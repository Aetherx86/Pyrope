//! WireGuard Noise_IKpsk2 handshake (initiator and responder) with MAC1/MAC2
//! cookie handling, following the WireGuard whitepaper Section 5.
//!
//! Every secret-dependent primitive (X25519, ChaCha20-Poly1305,
//! XChaCha20-Poly1305, BLAKE2s, HMAC) is constant time; MAC and tag checks use
//! constant-time comparisons. Randomness (ephemeral keys, indices, cookie
//! secrets, nonces) and time are passed in by the caller, so the whole state
//! machine is deterministic and testable.

const std = @import("std");
const blake = @import("blake2s.zig");
const aead = @import("aead.zig");
const curve = @import("curve25519.zig");

pub const CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com";
pub const LABEL_MAC1 = "mac1----";
pub const LABEL_COOKIE = "cookie--";

pub const INITIATION_SIZE: usize = 148;
pub const RESPONSE_SIZE: usize = 92;
pub const COOKIE_REPLY_SIZE: usize = 64;

pub const NS_PER_SEC: u64 = 1_000_000_000;
pub const REKEY_TIMEOUT_NS: u64 = 5 * NS_PER_SEC;
pub const COOKIE_SECRET_MAX_AGE_NS: u64 = 120 * NS_PER_SEC;
pub const COOKIE_SECRET_LATENCY_NS: u64 = 5 * NS_PER_SEC;
pub const INITIATIONS_PER_SECOND: u64 = 50;

pub const Error = error{
    InvalidMessage,
    InvalidMac1,
    AuthenticationFailed,
    IdentityElement,
    UnknownPeer,
    StaleTimestamp,
    HandshakeFlood,
    InvalidState,
};

const zero32: [32]u8 = @splat(0);
const zero16: [16]u8 = @splat(0);
const zero_nonce: [12]u8 = @splat(0);

fn ctEql(comptime n: usize, a: *const [n]u8, b: *const [n]u8) bool {
    var d: u8 = 0;
    for (a, b) |x, y| d |= x ^ y;
    return d == 0;
}

fn dh(private_key: *const [32]u8, public_key: *const [32]u8) Error![32]u8 {
    return curve.Curve25519.sharedSecret(private_key, public_key) catch error.IdentityElement;
}

fn seal(key: *const [32]u8, plaintext: []const u8, ad: []const u8, out: []u8) void {
    std.debug.assert(out.len == plaintext.len + 16);
    aead.ChaCha20Poly1305.encrypt(key, &zero_nonce, ad, plaintext, out[0..plaintext.len], out[plaintext.len..][0..16]);
}

fn open(key: *const [32]u8, sealed: []const u8, ad: []const u8, out: []u8) Error!void {
    const n = sealed.len - 16;
    aead.ChaCha20Poly1305.decrypt(key, &zero_nonce, ad, sealed[0..n], sealed[n..][0..16], out[0..n]) catch
        return error.AuthenticationFailed;
}

fn mixHash(h: *[32]u8, data: []const u8) void {
    h.* = blake.hash(&.{ h, data });
}

fn initialState(responder_static: *const [32]u8, ck: *[32]u8, h: *[32]u8) void {
    ck.* = blake.hash(&.{CONSTRUCTION});
    h.* = blake.hash(&.{ ck, IDENTIFIER });
    mixHash(h, responder_static);
}

fn checkType(msg: []const u8, comptime t: u8, comptime size: usize) Error!void {
    if (msg.len != size) return error.InvalidMessage;
    if (msg[0] != t or msg[1] != 0 or msg[2] != 0 or msg[3] != 0) return error.InvalidMessage;
}

/// TAI64N label: big-endian (2^62 + 10 + seconds) followed by big-endian nanoseconds.
pub fn tai64n(unix_seconds: u64, nanoseconds: u32) [12]u8 {
    var out: [12]u8 = undefined;
    std.mem.writeInt(u64, out[0..8], 0x400000000000000a + unix_seconds, .big);
    std.mem.writeInt(u32, out[8..12], nanoseconds, .big);
    return out;
}

/// Handshake timestamp for a Unix time in nanoseconds. Nanoseconds are rounded
/// down to a multiple of 2^24 (about 16.8 ms, the largest power of two below
/// 1 s / INITIATIONS_PER_SECOND) so the label does not leak a precise clock.
pub fn handshakeTimestamp(unix_ns: u64) [12]u8 {
    const nanos: u32 = @intCast(unix_ns % NS_PER_SEC);
    return tai64n(unix_ns / NS_PER_SEC, nanos & ~@as(u32, (1 << 24) - 1));
}

/// Encodes an IPv4 or IPv6 address and UDP port the way WireGuard feeds the
/// source address into the cookie MAC (address bytes, then big-endian port).
pub fn encodeSource(addr: []const u8, port: u16, out: *[18]u8) []const u8 {
    std.debug.assert(addr.len == 4 or addr.len == 16);
    @memcpy(out[0..addr.len], addr);
    std.mem.writeInt(u16, out[addr.len..][0..2], port, .big);
    return out[0 .. addr.len + 2];
}

pub const LocalIdentity = struct {
    private_key: [32]u8,
    public_key: [32]u8,
    /// Hash(LABEL_MAC1 || our public key): verifies mac1 on messages to us.
    mac1_key: [32]u8,
    /// Hash(LABEL_COOKIE || our public key): encrypts the cookie replies we send.
    cookie_key: [32]u8,

    pub fn init(private_key: *const [32]u8) LocalIdentity {
        var id: LocalIdentity = undefined;
        curve.Curve25519.clampScalar(private_key, &id.private_key);
        curve.Curve25519.getPublicKey(&id.private_key, &id.public_key);
        id.mac1_key = blake.hash(&.{ LABEL_MAC1, &id.public_key });
        id.cookie_key = blake.hash(&.{ LABEL_COOKIE, &id.public_key });
        return id;
    }
};

pub const HandshakeState = enum {
    zeroed,
    initiation_created,
    initiation_consumed,
    response_created,
    response_consumed,
};

/// Per-peer handshake and cookie state.
pub const Peer = struct {
    remote_static: [32]u8,
    preshared_key: [32]u8,
    remote_mac1_key: [32]u8,
    remote_cookie_key: [32]u8,
    /// DH(local static, remote static), precomputed; null if it is the
    /// identity element (the remote key is a small-order point).
    static_static: ?[32]u8,

    state: HandshakeState = .zeroed,
    hash: [32]u8 = zero32,
    chaining_key: [32]u8 = zero32,
    ephemeral_private: [32]u8 = zero32,
    remote_ephemeral: [32]u8 = zero32,
    local_index: u32 = 0,
    remote_index: u32 = 0,

    /// Greatest TAI64N timestamp accepted from this peer (replay protection).
    latest_timestamp: [12]u8 = @splat(0),
    last_initiation_consumed_ns: ?u64 = null,

    /// Cookie received from this peer, used for mac2 on what we send it.
    cookie: [16]u8 = zero16,
    cookie_birth_ns: ?u64 = null,
    last_mac1: [16]u8 = zero16,
    last_mac1_valid: bool = false,

    pub fn init(local: *const LocalIdentity, remote_static: *const [32]u8, preshared_key: ?*const [32]u8) Peer {
        return .{
            .remote_static = remote_static.*,
            .preshared_key = if (preshared_key) |p| p.* else zero32,
            .remote_mac1_key = blake.hash(&.{ LABEL_MAC1, remote_static }),
            .remote_cookie_key = blake.hash(&.{ LABEL_COOKIE, remote_static }),
            .static_static = dh(&local.private_key, remote_static) catch null,
        };
    }

    fn clearHandshake(self: *Peer) void {
        std.crypto.secureZero(u8, &self.hash);
        std.crypto.secureZero(u8, &self.chaining_key);
        std.crypto.secureZero(u8, &self.ephemeral_private);
        std.crypto.secureZero(u8, &self.remote_ephemeral);
        self.state = .zeroed;
    }

    fn cookieValid(self: *const Peer, now_ns: u64) bool {
        const birth = self.cookie_birth_ns orelse return false;
        return now_ns >= birth and now_ns - birth < COOKIE_SECRET_MAX_AGE_NS - COOKIE_SECRET_LATENCY_NS;
    }

    /// Fills mac1 and mac2 (the last 32 bytes of `msg`) for a message to this peer.
    fn addMacs(self: *Peer, msg: []u8, now_ns: u64) void {
        const n = msg.len;
        const mac1 = blake.mac(&self.remote_mac1_key, msg[0 .. n - 32]);
        @memcpy(msg[n - 32 .. n - 16], &mac1);
        self.last_mac1 = mac1;
        self.last_mac1_valid = true;
        const mac2 = if (self.cookieValid(now_ns)) blake.mac(&self.cookie, msg[0 .. n - 16]) else zero16;
        @memcpy(msg[n - 16 .. n], &mac2);
    }
};

fn verifyMac1(mac1_key: *const [32]u8, msg: []const u8) bool {
    const n = msg.len;
    const expected = blake.mac(mac1_key, msg[0 .. n - 32]);
    return ctEql(16, &expected, msg[n - 32 ..][0..16]);
}

/// Builds handshake initiation (message type 1) to `peer`.
pub fn createInitiation(
    local: *const LocalIdentity,
    peer: *Peer,
    ephemeral_private: *const [32]u8,
    timestamp: *const [12]u8,
    sender_index: u32,
    now_ns: u64,
) Error![INITIATION_SIZE]u8 {
    const ss = peer.static_static orelse return error.IdentityElement;
    var msg: [INITIATION_SIZE]u8 = @splat(0);
    msg[0] = 1;
    std.mem.writeInt(u32, msg[4..8], sender_index, .little);

    var ck: [32]u8 = undefined;
    var h: [32]u8 = undefined;
    initialState(&peer.remote_static, &ck, &h);

    var eph: [32]u8 = undefined;
    curve.Curve25519.clampScalar(ephemeral_private, &eph);
    curve.Curve25519.getPublicKey(&eph, msg[8..40]);
    ck = blake.kdf(1, &ck, msg[8..40])[0];
    mixHash(&h, msg[8..40]);

    var es = try dh(&eph, &peer.remote_static);
    defer std.crypto.secureZero(u8, &es);
    var k = blake.kdf(2, &ck, &es);
    ck = k[0];
    seal(&k[1], &local.public_key, &h, msg[40..88]);
    mixHash(&h, msg[40..88]);

    k = blake.kdf(2, &ck, &ss);
    ck = k[0];
    seal(&k[1], timestamp, &h, msg[88..116]);
    mixHash(&h, msg[88..116]);
    std.crypto.secureZero(u8, std.mem.asBytes(&k));

    peer.addMacs(&msg, now_ns);
    peer.chaining_key = ck;
    peer.hash = h;
    peer.ephemeral_private = eph;
    peer.local_index = sender_index;
    peer.state = .initiation_created;
    std.crypto.secureZero(u8, &eph);
    std.crypto.secureZero(u8, &ck);
    return msg;
}

/// Processes a handshake initiation addressed to `local`. Finds the sending
/// peer by its decrypted static key among `peers`. The peer is updated only
/// when every check passes.
pub fn consumeInitiation(local: *const LocalIdentity, peers: []Peer, msg: []const u8, now_ns: u64) Error!*Peer {
    try checkType(msg, 1, INITIATION_SIZE);
    if (!verifyMac1(&local.mac1_key, msg)) return error.InvalidMac1;

    var ck: [32]u8 = undefined;
    var h: [32]u8 = undefined;
    initialState(&local.public_key, &ck, &h);

    const e: *const [32]u8 = msg[8..40];
    ck = blake.kdf(1, &ck, e)[0];
    mixHash(&h, e);

    var es = try dh(&local.private_key, e);
    defer std.crypto.secureZero(u8, &es);
    var k = blake.kdf(2, &ck, &es);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&k));
    ck = k[0];
    var s_pub: [32]u8 = undefined;
    try open(&k[1], msg[40..88], &h, &s_pub);
    mixHash(&h, msg[40..88]);

    var peer: ?*Peer = null;
    for (peers) |*p| {
        if (ctEql(32, &p.remote_static, &s_pub)) peer = p;
    }
    const p = peer orelse return error.UnknownPeer;
    const ss = p.static_static orelse return error.IdentityElement;

    k = blake.kdf(2, &ck, &ss);
    ck = k[0];
    var ts: [12]u8 = undefined;
    try open(&k[1], msg[88..116], &h, &ts);
    mixHash(&h, msg[88..116]);

    if (std.mem.order(u8, &ts, &p.latest_timestamp) != .gt) return error.StaleTimestamp;
    if (p.last_initiation_consumed_ns) |last| {
        if (now_ns < last + NS_PER_SEC / INITIATIONS_PER_SECOND) return error.HandshakeFlood;
    }

    p.chaining_key = ck;
    p.hash = h;
    p.remote_ephemeral = e.*;
    p.remote_index = std.mem.readInt(u32, msg[4..8], .little);
    p.latest_timestamp = ts;
    p.last_initiation_consumed_ns = now_ns;
    p.state = .initiation_consumed;
    std.crypto.secureZero(u8, &ck);
    return p;
}

/// Builds the handshake response (message type 2) after `consumeInitiation`.
pub fn createResponse(
    local: *const LocalIdentity,
    peer: *Peer,
    ephemeral_private: *const [32]u8,
    sender_index: u32,
    now_ns: u64,
) Error![RESPONSE_SIZE]u8 {
    _ = local;
    if (peer.state != .initiation_consumed) return error.InvalidState;
    var msg: [RESPONSE_SIZE]u8 = @splat(0);
    msg[0] = 2;
    std.mem.writeInt(u32, msg[4..8], sender_index, .little);
    std.mem.writeInt(u32, msg[8..12], peer.remote_index, .little);

    var ck = peer.chaining_key;
    var h = peer.hash;

    var eph: [32]u8 = undefined;
    curve.Curve25519.clampScalar(ephemeral_private, &eph);
    defer std.crypto.secureZero(u8, &eph);
    curve.Curve25519.getPublicKey(&eph, msg[12..44]);
    ck = blake.kdf(1, &ck, msg[12..44])[0];
    mixHash(&h, msg[12..44]);

    var ee = try dh(&eph, &peer.remote_ephemeral);
    defer std.crypto.secureZero(u8, &ee);
    ck = blake.kdf(1, &ck, &ee)[0];
    var se = try dh(&eph, &peer.remote_static);
    defer std.crypto.secureZero(u8, &se);
    ck = blake.kdf(1, &ck, &se)[0];

    var k3 = blake.kdf(3, &ck, &peer.preshared_key);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&k3));
    ck = k3[0];
    mixHash(&h, &k3[1]);
    seal(&k3[2], "", &h, msg[44..60]);
    mixHash(&h, msg[44..60]);

    peer.addMacs(&msg, now_ns);
    peer.chaining_key = ck;
    peer.hash = h;
    peer.local_index = sender_index;
    peer.state = .response_created;
    std.crypto.secureZero(u8, &ck);
    return msg;
}

/// Processes a handshake response for an initiation we created. The peer is
/// found by the receiver index and must be waiting for a response.
pub fn consumeResponse(local: *const LocalIdentity, peers: []Peer, msg: []const u8, now_ns: u64) Error!*Peer {
    _ = now_ns;
    try checkType(msg, 2, RESPONSE_SIZE);
    if (!verifyMac1(&local.mac1_key, msg)) return error.InvalidMac1;

    const receiver = std.mem.readInt(u32, msg[8..12], .little);
    var peer: ?*Peer = null;
    for (peers) |*p| {
        if (p.state == .initiation_created and p.local_index == receiver) peer = p;
    }
    const p = peer orelse return error.UnknownPeer;

    var ck = p.chaining_key;
    var h = p.hash;
    const e: *const [32]u8 = msg[12..44];
    ck = blake.kdf(1, &ck, e)[0];
    mixHash(&h, e);

    var ee = try dh(&p.ephemeral_private, e);
    defer std.crypto.secureZero(u8, &ee);
    ck = blake.kdf(1, &ck, &ee)[0];
    var se = try dh(&local.private_key, e);
    defer std.crypto.secureZero(u8, &se);
    ck = blake.kdf(1, &ck, &se)[0];

    var k3 = blake.kdf(3, &ck, &p.preshared_key);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&k3));
    ck = k3[0];
    mixHash(&h, &k3[1]);
    var empty: [0]u8 = .{};
    try open(&k3[2], msg[44..60], &h, &empty);
    mixHash(&h, msg[44..60]);

    p.chaining_key = ck;
    p.hash = h;
    p.remote_index = std.mem.readInt(u32, msg[4..8], .little);
    p.state = .response_consumed;
    std.crypto.secureZero(u8, &ck);
    return p;
}

pub const SessionKeys = struct {
    send_key: [32]u8,
    recv_key: [32]u8,
    local_index: u32,
    remote_index: u32,
    is_initiator: bool,
};

/// Derives transport keys once the handshake is complete (the initiator after
/// consuming the response, the responder after creating it) and erases the
/// handshake secrets.
pub fn deriveKeys(peer: *Peer) Error!SessionKeys {
    const is_initiator = switch (peer.state) {
        .response_consumed => true,
        .response_created => false,
        else => return error.InvalidState,
    };
    var t = blake.kdf(2, &peer.chaining_key, "");
    defer std.crypto.secureZero(u8, std.mem.asBytes(&t));
    const keys = SessionKeys{
        .send_key = if (is_initiator) t[0] else t[1],
        .recv_key = if (is_initiator) t[1] else t[0],
        .local_index = peer.local_index,
        .remote_index = peer.remote_index,
        .is_initiator = is_initiator,
    };
    peer.clearHandshake();
    return keys;
}

/// Responder-side cookie logic: mac1/mac2 checks and cookie replies.
pub const CookieChecker = struct {
    mac1_key: [32]u8,
    cookie_key: [32]u8,
    secret: [32]u8,
    secret_birth_ns: u64,

    pub fn init(local: *const LocalIdentity, secret: *const [32]u8, now_ns: u64) CookieChecker {
        return .{
            .mac1_key = local.mac1_key,
            .cookie_key = local.cookie_key,
            .secret = secret.*,
            .secret_birth_ns = now_ns,
        };
    }

    /// The secret must be replaced (with fresh randomness) every two minutes.
    pub fn secretExpired(self: *const CookieChecker, now_ns: u64) bool {
        return now_ns < self.secret_birth_ns or now_ns - self.secret_birth_ns >= COOKIE_SECRET_MAX_AGE_NS;
    }

    pub fn rotate(self: *CookieChecker, secret: *const [32]u8, now_ns: u64) void {
        self.secret = secret.*;
        self.secret_birth_ns = now_ns;
    }

    fn sizeOk(msg: []const u8) bool {
        return msg.len == INITIATION_SIZE or msg.len == RESPONSE_SIZE;
    }

    pub fn checkMac1(self: *const CookieChecker, msg: []const u8) bool {
        if (!sizeOk(msg)) return false;
        return verifyMac1(&self.mac1_key, msg);
    }

    /// The cookie for a source address: MAC(secret, source).
    pub fn cookieFor(self: *const CookieChecker, source: []const u8) [16]u8 {
        return blake.mac(&self.secret, source);
    }

    /// True when mac2 carries a cookie this checker issued to `source`.
    pub fn checkMac2(self: *const CookieChecker, msg: []const u8, source: []const u8) bool {
        if (!sizeOk(msg)) return false;
        var cookie = self.cookieFor(source);
        defer std.crypto.secureZero(u8, &cookie);
        const n = msg.len;
        const expected = blake.mac(&cookie, msg[0 .. n - 16]);
        return ctEql(16, &expected, msg[n - 16 ..][0..16]);
    }

    /// Builds a cookie reply (message type 3) for a handshake message whose
    /// mac1 is valid. The cookie is encrypted with XChaCha20-Poly1305 under
    /// Hash(LABEL_COOKIE || our public key), bound to the message's mac1.
    pub fn createReply(self: *const CookieChecker, msg: []const u8, source: []const u8, nonce: *const [24]u8) Error![COOKIE_REPLY_SIZE]u8 {
        if (!self.checkMac1(msg)) return error.InvalidMac1;
        var out: [COOKIE_REPLY_SIZE]u8 = @splat(0);
        out[0] = 3;
        @memcpy(out[4..8], msg[4..8]); // receiver = the sender index of msg
        @memcpy(out[8..32], nonce);
        var cookie = self.cookieFor(source);
        defer std.crypto.secureZero(u8, &cookie);
        const n = msg.len;
        aead.XChaCha20Poly1305.encrypt(&self.cookie_key, nonce, msg[n - 32 .. n - 16], &cookie, out[32..48], out[48..64]);
        return out;
    }
};

/// Processes a cookie reply from a peer we sent a handshake message to and
/// stores the cookie so the next message to that peer carries mac2.
pub fn consumeCookieReply(peers: []Peer, msg: []const u8, now_ns: u64) Error!*Peer {
    try checkType(msg, 3, COOKIE_REPLY_SIZE);
    const receiver = std.mem.readInt(u32, msg[4..8], .little);
    var peer: ?*Peer = null;
    for (peers) |*p| {
        const waiting = p.state == .initiation_created or p.state == .response_created;
        if (waiting and p.last_mac1_valid and p.local_index == receiver) peer = p;
    }
    const p = peer orelse return error.UnknownPeer;

    var cookie: [16]u8 = undefined;
    aead.XChaCha20Poly1305.decrypt(&p.remote_cookie_key, msg[8..32], &p.last_mac1, msg[32..48], msg[48..64], &cookie) catch
        return error.AuthenticationFailed;
    p.cookie = cookie;
    p.cookie_birth_ns = now_ns;
    p.last_mac1_valid = false;
    std.crypto.secureZero(u8, &cookie);
    return p;
}

// ------------------------------------------------------------------ tests

const kat = @import("noise_kat.zig");
const wireguard = @import("wireguard.zig");
const testing = std.testing;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

const T0: u64 = 1_700_000_000 * NS_PER_SEC;

test "Noise_IKpsk2 known-answer transcript from the independent reference" {
    const i_id = LocalIdentity.init(&hex(kat.initiator_private_hex));
    const r_id = LocalIdentity.init(&hex(kat.responder_private_hex));
    try testing.expectEqualSlices(u8, &hex(kat.initiator_public_hex), &i_id.public_key);
    try testing.expectEqualSlices(u8, &hex(kat.responder_public_hex), &r_id.public_key);

    const psk = hex(kat.preshared_key_hex);
    var i_peers = [_]Peer{Peer.init(&i_id, &r_id.public_key, &psk)};
    var r_peers = [_]Peer{Peer.init(&r_id, &i_id.public_key, &psk)};

    const init_msg = try createInitiation(&i_id, &i_peers[0], &hex(kat.initiator_ephemeral_hex), &hex(kat.timestamp_hex), kat.initiator_index, T0);
    try testing.expectEqualSlices(u8, &hex(kat.initiation_hex), &init_msg);

    const rp = try consumeInitiation(&r_id, &r_peers, &init_msg, T0);
    try testing.expectEqual(&r_peers[0], rp);
    try testing.expectEqual(kat.initiator_index, rp.remote_index);
    try testing.expectEqualSlices(u8, &hex(kat.timestamp_hex), &rp.latest_timestamp);

    const resp = try createResponse(&r_id, rp, &hex(kat.responder_ephemeral_hex), kat.responder_index, T0);
    try testing.expectEqualSlices(u8, &hex(kat.response_hex), &resp);

    const ip = try consumeResponse(&i_id, &i_peers, &resp, T0);
    const ik = try deriveKeys(ip);
    const rk = try deriveKeys(rp);
    try testing.expectEqualSlices(u8, &hex(kat.initiator_send_key_hex), &ik.send_key);
    try testing.expectEqualSlices(u8, &hex(kat.initiator_recv_key_hex), &ik.recv_key);
    try testing.expectEqualSlices(u8, &ik.send_key, &rk.recv_key);
    try testing.expectEqualSlices(u8, &ik.recv_key, &rk.send_key);
    try testing.expect(ik.is_initiator and !rk.is_initiator);
    try testing.expectEqual(kat.responder_index, ik.remote_index);
    try testing.expectEqual(kat.initiator_index, rk.remote_index);
    try testing.expectEqual(HandshakeState.zeroed, i_peers[0].state);
    try testing.expectEqualSlices(u8, &zero32, &i_peers[0].chaining_key);

    // First transport packet (counter 0, payload zero-padded to 16 bytes).
    var padded: [16]u8 = @splat(0);
    @memcpy(padded[0..kat.data_payload.len], kat.data_payload);
    var pkt: [64]u8 = undefined;
    const n = try wireguard.WireGuardTunnel.encapsulateData(&ik.send_key, ik.remote_index, 0, &padded, &pkt);
    try testing.expectEqualSlices(u8, &hex(kat.data_packet_hex), pkt[0..n]);
}

test "cookie reply and mac2 known-answer transcript" {
    const i_id = LocalIdentity.init(&hex(kat.initiator_private_hex));
    const r_id = LocalIdentity.init(&hex(kat.responder_private_hex));
    const psk = hex(kat.preshared_key_hex);
    var i_peers = [_]Peer{Peer.init(&i_id, &r_id.public_key, &psk)};
    var r_peers = [_]Peer{Peer.init(&r_id, &i_id.public_key, &psk)};

    const init_msg = try createInitiation(&i_id, &i_peers[0], &hex(kat.initiator_ephemeral_hex), &hex(kat.timestamp_hex), kat.initiator_index, T0);
    var checker = CookieChecker.init(&r_id, &hex(kat.cookie_secret_hex), T0);
    const src = hex(kat.cookie_source_hex);
    try testing.expect(checker.checkMac1(&init_msg));
    try testing.expect(!checker.checkMac2(&init_msg, &src)); // no cookie yet
    try testing.expectEqualSlices(u8, &hex(kat.cookie_hex), &checker.cookieFor(&src));

    const reply = try checker.createReply(&init_msg, &src, &hex(kat.cookie_nonce_hex));
    try testing.expectEqualSlices(u8, &hex(kat.cookie_reply_hex), &reply);

    // A reply with a flipped bit or a replayed reply is rejected.
    var bad = reply;
    bad[40] ^= 1;
    try testing.expectError(error.AuthenticationFailed, consumeCookieReply(&i_peers, &bad, T0));
    _ = try consumeCookieReply(&i_peers, &reply, T0);
    try testing.expectEqualSlices(u8, &hex(kat.cookie_hex), &i_peers[0].cookie);
    try testing.expectError(error.UnknownPeer, consumeCookieReply(&i_peers, &reply, T0));

    const retry = try createInitiation(&i_id, &i_peers[0], &hex(kat.initiator_ephemeral_hex), &hex(kat.retry_timestamp_hex), kat.initiator_index, T0 + NS_PER_SEC);
    try testing.expectEqualSlices(u8, &hex(kat.retry_initiation_hex), &retry);
    try testing.expect(checker.checkMac2(&retry, &src));
    var other: [18]u8 = undefined;
    try testing.expect(!checker.checkMac2(&retry, encodeSource(&.{ 198, 51, 100, 8 }, 51820, &other)));
    _ = try consumeInitiation(&r_id, &r_peers, &retry, T0 + NS_PER_SEC);

    // The cookie expires after 120 s - 5 s; later messages carry a zero mac2.
    const late = T0 + NS_PER_SEC + COOKIE_SECRET_MAX_AGE_NS;
    const retry2 = try createInitiation(&i_id, &i_peers[0], &hex(kat.initiator_ephemeral_hex), &tai64n(1_700_000_200, 0), kat.initiator_index, late);
    try testing.expectEqualSlices(u8, &zero16, retry2[132..148]);

    // Secret rotation invalidates previously issued cookies.
    try testing.expect(checker.secretExpired(T0 + COOKIE_SECRET_MAX_AGE_NS));
    try testing.expect(!checker.secretExpired(T0 + COOKIE_SECRET_MAX_AGE_NS - 1));
    checker.rotate(&@as([32]u8, @splat(0xff)), T0 + COOKIE_SECRET_MAX_AGE_NS);
    try testing.expect(!checker.checkMac2(&retry, &src));
}

test "handshake rejects tampering, replays, floods, unknown peers and bad state" {
    const i_id = LocalIdentity.init(&hex(kat.initiator_private_hex));
    const r_id = LocalIdentity.init(&hex(kat.responder_private_hex));
    var i_peers = [_]Peer{Peer.init(&i_id, &r_id.public_key, null)};
    var r_peers = [_]Peer{Peer.init(&r_id, &i_id.public_key, null)};
    const eph = hex(kat.initiator_ephemeral_hex);

    const m1 = try createInitiation(&i_id, &i_peers[0], &eph, &tai64n(100, 0), 7, T0);

    // Wrong size or type.
    try testing.expectError(error.InvalidMessage, consumeInitiation(&r_id, &r_peers, m1[0..147], T0));
    var wrong_type = m1;
    wrong_type[0] = 2;
    try testing.expectError(error.InvalidMessage, consumeInitiation(&r_id, &r_peers, &wrong_type, T0));
    var reserved = m1;
    reserved[2] = 1;
    try testing.expectError(error.InvalidMessage, consumeInitiation(&r_id, &r_peers, &reserved, T0));

    // Any flipped bit before mac2 breaks mac1, which is checked before any DH.
    for (0..INITIATION_SIZE - 16) |i| {
        var t = m1;
        t[i] ^= 0x04;
        if (i < 4) continue; // type field covered above
        try testing.expectError(error.InvalidMac1, consumeInitiation(&r_id, &r_peers, &t, T0));
    }

    // A message encrypted to someone else, with a valid mac1 for us: the
    // static-key AEAD fails.
    var forged = m1;
    forged[50] ^= 0x01;
    @memcpy(forged[116..132], &blake.mac(&r_id.mac1_key, forged[0..116]));
    try testing.expectError(error.AuthenticationFailed, consumeInitiation(&r_id, &r_peers, &forged, T0));

    // A small-order ephemeral is rejected as an identity element.
    var low = m1;
    @memset(low[8..40], 0);
    @memcpy(low[116..132], &blake.mac(&r_id.mac1_key, low[0..116]));
    try testing.expectError(error.IdentityElement, consumeInitiation(&r_id, &r_peers, &low, T0));

    // Unknown peer: the responder does not know this initiator.
    var no_peers = [_]Peer{Peer.init(&r_id, &hex(kat.responder_public_hex), null)};
    try testing.expectError(error.UnknownPeer, consumeInitiation(&r_id, &no_peers, &m1, T0));

    // createResponse before any initiation is a state error.
    try testing.expectError(error.InvalidState, createResponse(&r_id, &r_peers[0], &eph, 9, T0));

    // Accept once, then the same initiation is a replay.
    _ = try consumeInitiation(&r_id, &r_peers, &m1, T0);
    try testing.expectError(error.StaleTimestamp, consumeInitiation(&r_id, &r_peers, &m1, T0 + NS_PER_SEC));

    // Newer timestamp but within 1/50 s of the last accepted one: flood.
    const m2 = try createInitiation(&i_id, &i_peers[0], &eph, &tai64n(101, 0), 8, T0);
    try testing.expectError(error.HandshakeFlood, consumeInitiation(&r_id, &r_peers, &m2, T0 + 10_000_000));
    // The rejected attempt did not consume the timestamp.
    _ = try consumeInitiation(&r_id, &r_peers, &m2, T0 + 20_000_000);

    // A response to an index we never used is unknown; tampered responses fail.
    const resp = try createResponse(&r_id, &r_peers[0], &hex(kat.responder_ephemeral_hex), 99, T0);
    var wrong_idx = resp;
    wrong_idx[8] ^= 0xff;
    @memcpy(wrong_idx[60..76], &blake.mac(&i_id.mac1_key, wrong_idx[0..60]));
    try testing.expectError(error.UnknownPeer, consumeResponse(&i_id, &i_peers, &wrong_idx, T0));
    var bad_tag = resp;
    bad_tag[50] ^= 0x01;
    @memcpy(bad_tag[60..76], &blake.mac(&i_id.mac1_key, bad_tag[0..60]));
    try testing.expectError(error.AuthenticationFailed, consumeResponse(&i_id, &i_peers, &bad_tag, T0));
    try testing.expectEqual(HandshakeState.initiation_created, i_peers[0].state);
    _ = try consumeResponse(&i_id, &i_peers, &resp, T0);
    // A second copy of the response no longer matches a pending initiation.
    try testing.expectError(error.UnknownPeer, consumeResponse(&i_id, &i_peers, &resp, T0));
    try testing.expectError(error.InvalidState, deriveKeys(&no_peers[0]));
}

test "mismatched preshared keys fail at the response" {
    const i_id = LocalIdentity.init(&hex(kat.initiator_private_hex));
    const r_id = LocalIdentity.init(&hex(kat.responder_private_hex));
    var i_peers = [_]Peer{Peer.init(&i_id, &r_id.public_key, &@as([32]u8, @splat(0x11)))};
    var r_peers = [_]Peer{Peer.init(&r_id, &i_id.public_key, &@as([32]u8, @splat(0x22)))};
    const m1 = try createInitiation(&i_id, &i_peers[0], &hex(kat.initiator_ephemeral_hex), &tai64n(5, 0), 1, T0);
    const rp = try consumeInitiation(&r_id, &r_peers, &m1, T0);
    const resp = try createResponse(&r_id, rp, &hex(kat.responder_ephemeral_hex), 2, T0);
    try testing.expectError(error.AuthenticationFailed, consumeResponse(&i_id, &i_peers, &resp, T0));
}

test "randomized handshakes between many peers derive matching keys" {
    var prng = std.Random.DefaultPrng.init(0x1c5);
    const rnd = prng.random();
    var priv: [4][32]u8 = undefined;
    for (&priv) |*p| rnd.bytes(p);
    var ids: [4]LocalIdentity = undefined;
    for (&ids, priv) |*id, p| id.* = LocalIdentity.init(&p);

    // Peer tables: every identity knows every other one.
    var tables: [4][3]Peer = undefined;
    for (0..4) |a| {
        var j: usize = 0;
        for (0..4) |b| {
            if (a == b) continue;
            tables[a][j] = Peer.init(&ids[a], &ids[b].public_key, null);
            j += 1;
        }
    }
    var now: u64 = T0;
    for (0..12) |round| {
        const a = rnd.uintLessThan(usize, 4);
        var b = rnd.uintLessThan(usize, 3);
        if (b >= a) b += 1;
        const slot_ab = if (b < a) b else b - 1;
        var e1: [32]u8 = undefined;
        var e2: [32]u8 = undefined;
        rnd.bytes(&e1);
        rnd.bytes(&e2);
        now += NS_PER_SEC;
        const ts = handshakeTimestamp(now + round);
        const m1 = try createInitiation(&ids[a], &tables[a][slot_ab], &e1, &ts, rnd.int(u32), now);
        const rp = try consumeInitiation(&ids[b], &tables[b], &m1, now);
        try testing.expectEqualSlices(u8, &ids[a].public_key, &rp.remote_static);
        const m2 = try createResponse(&ids[b], rp, &e2, rnd.int(u32), now);
        const ip = try consumeResponse(&ids[a], &tables[a], &m2, now);
        const ka = try deriveKeys(ip);
        const kb = try deriveKeys(rp);
        try testing.expectEqualSlices(u8, &ka.send_key, &kb.recv_key);
        try testing.expectEqualSlices(u8, &ka.recv_key, &kb.send_key);
        try testing.expect(!std.mem.eql(u8, &ka.send_key, &ka.recv_key));
    }
}

test "handshake timestamp and source encoding" {
    const ts = handshakeTimestamp(1_700_000_000 * NS_PER_SEC + 123_456_789);
    try testing.expectEqualSlices(u8, &tai64n(1_700_000_000, 117_440_512), &ts); // 7 * 2^24
    try testing.expectEqual(.lt, std.mem.order(u8, &tai64n(10, 999_999_999), &tai64n(11, 0)));
    var buf: [18]u8 = undefined;
    try testing.expectEqualSlices(u8, &hex(kat.cookie_source_hex), encodeSource(&.{ 198, 51, 100, 7 }, 51820, &buf));
    var v6: [16]u8 = @splat(0);
    v6[15] = 1;
    try testing.expectEqual(@as(usize, 18), encodeSource(&v6, 1, &buf).len);
}
