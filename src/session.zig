//! WireGuard transport sessions (data messages with padding and replay
//! protection) and the protocol timers, driven by an injectable clock.

const std = @import("std");
const wireguard = @import("wireguard.zig");
const replay = @import("replay.zig");
const noise = @import("noise.zig");

pub const NS_PER_SEC: u64 = 1_000_000_000;

// WireGuard whitepaper Section 6.1 constants.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
pub const REJECT_AFTER_MESSAGES: u64 = replay.REJECT_AFTER_MESSAGES;
pub const REKEY_AFTER_TIME_NS: u64 = 120 * NS_PER_SEC;
pub const REJECT_AFTER_TIME_NS: u64 = 180 * NS_PER_SEC;
pub const REKEY_ATTEMPT_TIME_NS: u64 = 90 * NS_PER_SEC;
pub const REKEY_TIMEOUT_NS: u64 = 5 * NS_PER_SEC;
pub const KEEPALIVE_TIMEOUT_NS: u64 = 10 * NS_PER_SEC;
pub const MAX_JITTER_NS: u64 = 333 * std.time.ns_per_ms;

/// Source of monotonic nanoseconds. Production code wraps `std.Io`; tests
/// use `ManualClock` to step time deterministically.
pub const Clock = struct {
    ctx: *anyopaque,
    nowFn: *const fn (ctx: *anyopaque) u64,

    pub fn now(self: Clock) u64 {
        return self.nowFn(self.ctx);
    }
};

pub const ManualClock = struct {
    ns: u64 = 0,

    pub fn clock(self: *ManualClock) Clock {
        return .{ .ctx = self, .nowFn = nowImpl };
    }

    pub fn advance(self: *ManualClock, ns: u64) void {
        self.ns += ns;
    }

    fn nowImpl(ctx: *anyopaque) u64 {
        const self: *ManualClock = @ptrCast(@alignCast(ctx));
        return self.ns;
    }
};

pub const IoClock = struct {
    io: std.Io,

    pub fn clock(self: *IoClock) Clock {
        return .{ .ctx = self, .nowFn = nowImpl };
    }

    fn nowImpl(ctx: *anyopaque) u64 {
        const self: *IoClock = @ptrCast(@alignCast(ctx));
        const ts = std.Io.Clock.Timestamp.now(self.io, .awake);
        return @intCast(@max(ts.raw.nanoseconds, 0));
    }
};

/// Plaintext length after WireGuard padding: rounded up to a multiple of 16,
/// but never beyond `mtu` (when `mtu` is non-zero and the payload fits in it).
pub fn paddedLength(len: usize, mtu: usize) usize {
    const aligned = (len + 15) & ~@as(usize, 15);
    if (mtu == 0 or len > mtu) return aligned;
    return @min(aligned, mtu);
}

/// Length of the IP packet at the start of a decrypted, padded payload, taken
/// from the IPv4 total length or IPv6 payload length field. A zero-length
/// payload is a keepalive.
pub fn ipPacketLength(plaintext: []const u8) error{InvalidPacket}!usize {
    if (plaintext.len == 0) return 0;
    const version = plaintext[0] >> 4;
    const len: usize = switch (version) {
        4 => blk: {
            if (plaintext.len < 20) return error.InvalidPacket;
            const total = std.mem.readInt(u16, plaintext[2..4], .big);
            if (total < 20) return error.InvalidPacket;
            break :blk total;
        },
        6 => blk: {
            if (plaintext.len < 40) return error.InvalidPacket;
            break :blk @as(usize, std.mem.readInt(u16, plaintext[4..6], .big)) + 40;
        },
        else => return error.InvalidPacket,
    };
    if (len > plaintext.len) return error.InvalidPacket;
    return len;
}

pub const SessionError = error{
    SessionExpired,
    CounterExhausted,
    SessionNotConfirmed,
    BufferTooSmall,
    PacketTooShort,
    InvalidMessageType,
    ReceiverIndexMismatch,
    AuthenticationFailed,
    Replayed,
};

/// One keypair's transport state. The responder may not send until the
/// initiator's first data packet confirms the keys (whitepaper Section 5.4.7).
pub const Session = struct {
    keys: noise.SessionKeys,
    created_ns: u64,
    send_counter: u64 = 0,
    filter: replay.ReplayFilter = .{},
    confirmed: bool,
    mtu: usize = 0,

    pub fn init(keys: noise.SessionKeys, now_ns: u64) Session {
        return .{ .keys = keys, .created_ns = now_ns, .confirmed = keys.is_initiator };
    }

    pub fn age(self: *const Session, now_ns: u64) u64 {
        return now_ns -| self.created_ns;
    }

    pub fn expired(self: *const Session, now_ns: u64) bool {
        return self.age(now_ns) >= REJECT_AFTER_TIME_NS;
    }

    /// True when the session's initiator should start a new handshake before
    /// sending (REKEY_AFTER_TIME or REKEY_AFTER_MESSAGES reached).
    pub fn wantsRekeyOnSend(self: *const Session, now_ns: u64) bool {
        if (self.send_counter >= REKEY_AFTER_MESSAGES) return true;
        return self.keys.is_initiator and self.age(now_ns) >= REKEY_AFTER_TIME_NS;
    }

    /// True when the initiator should rekey after receiving data on an old
    /// session (REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT).
    pub fn wantsRekeyOnReceive(self: *const Session, now_ns: u64) bool {
        return self.keys.is_initiator and
            self.age(now_ns) >= REJECT_AFTER_TIME_NS - KEEPALIVE_TIMEOUT_NS - REKEY_TIMEOUT_NS;
    }

    /// Encrypts `payload` (an empty payload is a keepalive) into a type 4 data
    /// message, zero-padding the plaintext as WireGuard does.
    pub fn encrypt(self: *Session, payload: []const u8, out: []u8, now_ns: u64) SessionError!usize {
        if (!self.confirmed) return error.SessionNotConfirmed;
        if (self.expired(now_ns)) return error.SessionExpired;
        if (self.send_counter >= REJECT_AFTER_MESSAGES) return error.CounterExhausted;
        const plen = paddedLength(payload.len, self.mtu);
        const total = wireguard.TRANSPORT_OVERHEAD + plen;
        if (out.len < total) return error.BufferTooSmall;

        // Build the padded plaintext in place in the payload area of `out`.
        const body = out[wireguard.TRANSPORT_HEADER_SIZE..][0..plen];
        std.mem.copyForwards(u8, body[0..payload.len], payload);
        @memset(body[payload.len..], 0);
        const n = wireguard.WireGuardTunnel.encapsulateData(&self.keys.send_key, self.keys.remote_index, self.send_counter, body, out) catch
            return error.BufferTooSmall;
        self.send_counter += 1;
        return n;
    }

    /// Authenticates and decrypts a data message. The replay window is updated
    /// only after the tag verifies. Returns the padded plaintext length.
    pub fn decrypt(self: *Session, packet: []const u8, out: []u8, now_ns: u64) SessionError!usize {
        if (self.expired(now_ns)) return error.SessionExpired;
        if (packet.len < wireguard.TRANSPORT_OVERHEAD) return error.PacketTooShort;
        const counter = std.mem.readInt(u64, packet[8..16], .little);
        if (counter >= REJECT_AFTER_MESSAGES) return error.Replayed;
        const res = wireguard.WireGuardTunnel.decapsulateData(&self.keys.recv_key, self.keys.local_index, packet, out) catch |err| return switch (err) {
            error.PacketTooShort => error.PacketTooShort,
            error.InvalidMessageType => error.InvalidMessageType,
            error.ReceiverIndexMismatch => error.ReceiverIndexMismatch,
            error.BufferTooSmall => error.BufferTooSmall,
            error.AuthenticationFailed => error.AuthenticationFailed,
        };
        if (!self.filter.validate(res.counter, REJECT_AFTER_MESSAGES)) {
            std.crypto.secureZero(u8, out[0..res.payload_len]);
            return error.Replayed;
        }
        self.confirmed = true;
        return res.payload_len;
    }

    pub fn wipe(self: *Session) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.keys));
    }
};

/// Actions the timer state machine asks the caller to take.
pub const Actions = packed struct {
    send_keepalive: bool = false,
    initiate_handshake: bool = false,
    retransmit_handshake: bool = false,
    handshake_failed: bool = false,
    zero_keys: bool = false,

    pub fn any(self: Actions) bool {
        return self.send_keepalive or self.initiate_handshake or self.retransmit_handshake or
            self.handshake_failed or self.zero_keys;
    }
};

/// WireGuard timer state for one peer (whitepaper Section 6). Events are
/// reported with `on*`, and `poll` returns the actions that are due. All
/// times come from the injected clock; retransmission jitter is supplied by
/// the caller so tests stay deterministic.
pub const Timers = struct {
    clock: Clock,
    persistent_keepalive_ns: u64 = 0,

    last_data_sent_ns: ?u64 = null,
    last_data_received_ns: ?u64 = null,
    last_any_sent_ns: ?u64 = null,
    last_any_received_ns: ?u64 = null,
    keepalive_due_ns: ?u64 = null,
    new_handshake_due_ns: ?u64 = null,
    handshake_started_ns: ?u64 = null,
    handshake_retransmit_due_ns: ?u64 = null,
    session_created_ns: ?u64 = null,

    pub fn init(clock: Clock) Timers {
        return .{ .clock = clock };
    }

    /// An authenticated data packet with a non-empty payload was sent.
    pub fn onDataSent(self: *Timers) void {
        const now = self.clock.now();
        self.last_data_sent_ns = now;
        self.onAnySent(now);
        // Expect an answer; otherwise start a new handshake.
        if (self.new_handshake_due_ns == null)
            self.new_handshake_due_ns = now + KEEPALIVE_TIMEOUT_NS + REKEY_TIMEOUT_NS;
    }

    /// Any authenticated packet (data, keepalive, handshake) was sent.
    pub fn onKeepaliveSent(self: *Timers) void {
        self.onAnySent(self.clock.now());
    }

    fn onAnySent(self: *Timers, now: u64) void {
        self.last_any_sent_ns = now;
        self.keepalive_due_ns = null; // we just sent something
    }

    /// An authenticated data packet with a non-empty payload was received.
    pub fn onDataReceived(self: *Timers) void {
        const now = self.clock.now();
        self.last_data_received_ns = now;
        self.onAnyReceived(now);
        if (self.keepalive_due_ns == null) self.keepalive_due_ns = now + KEEPALIVE_TIMEOUT_NS;
    }

    /// Any authenticated packet (including keepalives) was received.
    pub fn onKeepaliveReceived(self: *Timers) void {
        self.onAnyReceived(self.clock.now());
    }

    fn onAnyReceived(self: *Timers, now: u64) void {
        self.last_any_received_ns = now;
        self.new_handshake_due_ns = null; // the peer is alive
    }

    /// A handshake initiation was sent; `jitter_ns` is in [0, MAX_JITTER_NS].
    pub fn onHandshakeInitiated(self: *Timers, jitter_ns: u64) void {
        const now = self.clock.now();
        if (self.handshake_started_ns == null) self.handshake_started_ns = now;
        self.handshake_retransmit_due_ns = now + REKEY_TIMEOUT_NS + @min(jitter_ns, MAX_JITTER_NS);
        self.onAnySent(now);
    }

    /// A handshake completed and a new session was installed.
    pub fn onSessionDerived(self: *Timers) void {
        const now = self.clock.now();
        self.session_created_ns = now;
        self.handshake_started_ns = null;
        self.handshake_retransmit_due_ns = null;
        self.new_handshake_due_ns = null;
    }

    pub fn poll(self: *Timers) Actions {
        const now = self.clock.now();
        var a = Actions{};

        if (self.handshake_retransmit_due_ns) |due| {
            if (now - self.handshake_started_ns.? >= REKEY_ATTEMPT_TIME_NS) {
                a.handshake_failed = true;
                self.handshake_started_ns = null;
                self.handshake_retransmit_due_ns = null;
            } else if (now >= due) {
                a.retransmit_handshake = true;
                self.handshake_retransmit_due_ns = null; // re-armed by onHandshakeInitiated
            }
        }

        if (self.keepalive_due_ns) |due| {
            if (now >= due) {
                a.send_keepalive = true;
                self.keepalive_due_ns = null;
            }
        }

        if (self.persistent_keepalive_ns != 0) {
            const last = self.last_any_sent_ns orelse self.session_created_ns;
            if (last) |l| if (now >= l + self.persistent_keepalive_ns) {
                a.send_keepalive = true;
            };
        }

        if (self.new_handshake_due_ns) |due| {
            if (now >= due and self.handshake_started_ns == null) {
                a.initiate_handshake = true;
                self.new_handshake_due_ns = null;
            }
        }

        if (self.session_created_ns) |created| {
            if (now - created >= 3 * REJECT_AFTER_TIME_NS) {
                a.zero_keys = true;
                self.session_created_ns = null;
            }
        }
        return a;
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn testKeys(is_initiator: bool) noise.SessionKeys {
    const a: [32]u8 = @splat(0xa1);
    const b: [32]u8 = @splat(0xb2);
    return .{
        .send_key = if (is_initiator) a else b,
        .recv_key = if (is_initiator) b else a,
        .local_index = if (is_initiator) 1 else 2,
        .remote_index = if (is_initiator) 2 else 1,
        .is_initiator = is_initiator,
    };
}

test "padding rules" {
    try testing.expectEqual(@as(usize, 0), paddedLength(0, 0));
    try testing.expectEqual(@as(usize, 16), paddedLength(1, 0));
    try testing.expectEqual(@as(usize, 16), paddedLength(16, 0));
    try testing.expectEqual(@as(usize, 32), paddedLength(17, 0));
    try testing.expectEqual(@as(usize, 1420), paddedLength(1419, 1420));
    try testing.expectEqual(@as(usize, 1424), paddedLength(1421, 1420)); // larger than MTU: plain alignment
    try testing.expectEqual(@as(usize, 1408), paddedLength(1401, 1420));
}

test "IP length recovery strips padding and rejects malformed headers" {
    var v4: [48]u8 = @splat(0);
    v4[0] = 0x45;
    std.mem.writeInt(u16, v4[2..4], 33, .big);
    try testing.expectEqual(@as(usize, 33), try ipPacketLength(&v4));
    std.mem.writeInt(u16, v4[2..4], 49, .big);
    try testing.expectError(error.InvalidPacket, ipPacketLength(&v4));
    std.mem.writeInt(u16, v4[2..4], 19, .big);
    try testing.expectError(error.InvalidPacket, ipPacketLength(&v4));
    var v6: [64]u8 = @splat(0);
    v6[0] = 0x60;
    std.mem.writeInt(u16, v6[4..6], 8, .big);
    try testing.expectEqual(@as(usize, 48), try ipPacketLength(&v6));
    try testing.expectError(error.InvalidPacket, ipPacketLength(v6[0..39]));
    try testing.expectError(error.InvalidPacket, ipPacketLength(&[_]u8{0x50}));
    try testing.expectEqual(@as(usize, 0), try ipPacketLength(&.{}));
}

test "session round trip, key confirmation, replay and tamper rejection" {
    var ini = Session.init(testKeys(true), 0);
    var rsp = Session.init(testKeys(false), 0);
    var pkt: [128]u8 = undefined;
    var out: [128]u8 = undefined;

    // Responder cannot send before receiving from the initiator.
    try testing.expectError(error.SessionNotConfirmed, rsp.encrypt("x", &pkt, 0));

    const n = try ini.encrypt("hello", &pkt, 1);
    try testing.expectEqual(@as(usize, 32 + 16), n);
    const m = try rsp.decrypt(pkt[0..n], &out, 1);
    try testing.expectEqual(@as(usize, 16), m);
    try testing.expectEqualStrings("hello", out[0..5]);
    try testing.expectEqualSlices(u8, &@as([11]u8, @splat(0)), out[5..16]);
    try testing.expectError(error.Replayed, rsp.decrypt(pkt[0..n], &out, 1));

    // Now confirmed: the responder may answer, including keepalives.
    const k = try rsp.encrypt("", &pkt, 2);
    try testing.expectEqual(@as(usize, 32), k);
    try testing.expectEqual(@as(usize, 0), try ini.decrypt(pkt[0..k], &out, 2));

    // A tampered packet fails before touching the replay window.
    const n2 = try ini.encrypt("again", &pkt, 3);
    var bad = pkt;
    bad[20] ^= 1;
    try testing.expectError(error.AuthenticationFailed, rsp.decrypt(bad[0..n2], &out, 3));
    _ = try rsp.decrypt(pkt[0..n2], &out, 3);

    // Out-of-order delivery inside the window is accepted once.
    var held: [4][64]u8 = undefined;
    var lens: [4]usize = undefined;
    for (0..4) |i| lens[i] = try ini.encrypt("ooo", &held[i], 4);
    for ([_]usize{ 3, 1, 0, 2 }) |i| _ = try rsp.decrypt(held[i][0..lens[i]], &out, 4);
    for (0..4) |i| try testing.expectError(error.Replayed, rsp.decrypt(held[i][0..lens[i]], &out, 4));

    // Wrong receiver index and truncated packets.
    try testing.expectError(error.ReceiverIndexMismatch, ini.decrypt(held[0][0..lens[0]], &out, 4));
    try testing.expectError(error.PacketTooShort, rsp.decrypt(pkt[0..31], &out, 4));
}

test "session limits: age and message counters" {
    var ini = Session.init(testKeys(true), 1000);
    var pkt: [64]u8 = undefined;
    try testing.expect(!ini.wantsRekeyOnSend(1000 + REKEY_AFTER_TIME_NS - 1));
    try testing.expect(ini.wantsRekeyOnSend(1000 + REKEY_AFTER_TIME_NS));
    try testing.expect(ini.wantsRekeyOnReceive(1000 + 165 * NS_PER_SEC));
    try testing.expect(!ini.wantsRekeyOnReceive(1000 + 165 * NS_PER_SEC - 1));
    try testing.expectError(error.SessionExpired, ini.encrypt("x", &pkt, 1000 + REJECT_AFTER_TIME_NS));
    var rsp = Session.init(testKeys(false), 0);
    try testing.expect(!rsp.wantsRekeyOnSend(REKEY_AFTER_TIME_NS)); // only the initiator rekeys on time

    ini = Session.init(testKeys(true), 0);
    ini.send_counter = REKEY_AFTER_MESSAGES;
    try testing.expect(ini.wantsRekeyOnSend(0));
    ini.send_counter = REJECT_AFTER_MESSAGES;
    try testing.expectError(error.CounterExhausted, ini.encrypt("x", &pkt, 0));

    // A packet claiming a counter at the reject limit is dropped unprocessed.
    var hdr: [32]u8 = @splat(0);
    hdr[0] = 4;
    std.mem.writeInt(u32, hdr[4..8], 2, .little);
    std.mem.writeInt(u64, hdr[8..16], REJECT_AFTER_MESSAGES, .little);
    var out: [16]u8 = undefined;
    try testing.expectError(error.Replayed, rsp.decrypt(&hdr, &out, 0));
}

test "timers: keepalive, new handshake, retransmit, give up, zero keys" {
    var mc = ManualClock{ .ns = 50 * NS_PER_SEC };
    var t = Timers.init(mc.clock());
    t.onSessionDerived();
    try testing.expect(!t.poll().any());

    // Received data and sent nothing back for 10 s: keepalive.
    t.onDataReceived();
    mc.advance(KEEPALIVE_TIMEOUT_NS - 1);
    try testing.expect(!t.poll().send_keepalive);
    mc.advance(1);
    try testing.expect(t.poll().send_keepalive);
    try testing.expect(!t.poll().send_keepalive); // fires once

    // Replying in time suppresses the keepalive.
    t.onDataReceived();
    mc.advance(NS_PER_SEC);
    t.onDataSent();
    mc.advance(KEEPALIVE_TIMEOUT_NS);
    try testing.expect(!t.poll().send_keepalive);

    // Sent data with no reply for 15 s: new handshake.
    mc.advance(KEEPALIVE_TIMEOUT_NS + REKEY_TIMEOUT_NS);
    var a = t.poll();
    try testing.expect(a.initiate_handshake);

    // Handshake retransmits every 5 s plus jitter, gives up after 90 s.
    t.onHandshakeInitiated(100);
    mc.advance(REKEY_TIMEOUT_NS);
    try testing.expect(!t.poll().retransmit_handshake);
    mc.advance(100);
    try testing.expect(t.poll().retransmit_handshake);
    var retries: usize = 1;
    while (true) {
        t.onHandshakeInitiated(0);
        mc.advance(REKEY_TIMEOUT_NS);
        a = t.poll();
        if (a.handshake_failed) break;
        try testing.expect(a.retransmit_handshake);
        retries += 1;
    }
    // 90 s / 5 s = 18 attempts: the initial initiation plus 17 retransmits.
    try testing.expectEqual(@as(usize, 17), retries);
    try testing.expect(!t.poll().any());

    // Keys are zeroed after 3 * REJECT_AFTER_TIME without a new session.
    var mc2 = ManualClock{};
    var t2 = Timers.init(mc2.clock());
    t2.onSessionDerived();
    mc2.advance(3 * REJECT_AFTER_TIME_NS - 1);
    try testing.expect(!t2.poll().zero_keys);
    mc2.advance(1);
    try testing.expect(t2.poll().zero_keys);
}

test "timers: persistent keepalive" {
    var mc = ManualClock{};
    var t = Timers.init(mc.clock());
    t.persistent_keepalive_ns = 25 * NS_PER_SEC;
    t.onSessionDerived();
    mc.advance(25 * NS_PER_SEC - 1);
    try testing.expect(!t.poll().send_keepalive);
    mc.advance(1);
    try testing.expect(t.poll().send_keepalive);
    t.onKeepaliveSent();
    mc.advance(24 * NS_PER_SEC);
    try testing.expect(!t.poll().send_keepalive);
}

test "end to end: handshake, sessions and timers on a manual clock" {
    var mc = ManualClock{ .ns = 1_700_000_000 * NS_PER_SEC };
    const clock = mc.clock();
    var prng = std.Random.DefaultPrng.init(42);
    const rnd = prng.random();
    var ka: [32]u8 = undefined;
    var kb: [32]u8 = undefined;
    rnd.bytes(&ka);
    rnd.bytes(&kb);
    const a = noise.LocalIdentity.init(&ka);
    const b = noise.LocalIdentity.init(&kb);
    var ap = [_]noise.Peer{noise.Peer.init(&a, &b.public_key, null)};
    var bp = [_]noise.Peer{noise.Peer.init(&b, &a.public_key, null)};

    var e: [32]u8 = undefined;
    rnd.bytes(&e);
    const m1 = try noise.createInitiation(&a, &ap[0], &e, &noise.handshakeTimestamp(clock.now()), 10, clock.now());
    const rp = try noise.consumeInitiation(&b, &bp, &m1, clock.now());
    rnd.bytes(&e);
    const m2 = try noise.createResponse(&b, rp, &e, 20, clock.now());
    const ip = try noise.consumeResponse(&a, &ap, &m2, clock.now());
    var sa = Session.init(try noise.deriveKeys(ip), clock.now());
    var sb = Session.init(try noise.deriveKeys(rp), clock.now());

    var pkt: [256]u8 = undefined;
    var out: [256]u8 = undefined;
    var ip4: [37]u8 = @splat(0x33);
    ip4[0] = 0x45;
    std.mem.writeInt(u16, ip4[2..4], ip4.len, .big);
    const n = try sa.encrypt(&ip4, &pkt, clock.now());
    const plen = try sb.decrypt(pkt[0..n], &out, clock.now());
    try testing.expectEqual(@as(usize, 48), plen);
    try testing.expectEqualSlices(u8, &ip4, out[0..try ipPacketLength(out[0..plen])]);

    mc.advance(REKEY_AFTER_TIME_NS);
    try testing.expect(sa.wantsRekeyOnSend(clock.now()));
    try testing.expect(!sb.wantsRekeyOnSend(clock.now()));
    mc.advance(REJECT_AFTER_TIME_NS - REKEY_AFTER_TIME_NS);
    try testing.expectError(error.SessionExpired, sa.encrypt("late", &pkt, clock.now()));
    try testing.expectError(error.SessionExpired, sb.decrypt(pkt[0..n], &out, clock.now()));
}
