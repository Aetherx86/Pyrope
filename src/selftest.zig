//! In-memory loopback self-test: two peers run the full Noise_IKpsk2
//! handshake (including a cookie round trip under load), then exchange
//! transport data and check that replays and tampering are rejected.

const std = @import("std");
const noise = @import("noise.zig");
const session = @import("session.zig");

pub const Step = struct {
    name: []const u8,
    ok: bool,
};

pub const MAX_STEPS = 12;

pub const Report = struct {
    steps: [MAX_STEPS]Step = undefined,
    len: usize = 0,
    initiator_public: [32]u8 = @splat(0),
    responder_public: [32]u8 = @splat(0),

    fn add(self: *Report, name: []const u8, ok: bool) void {
        self.steps[self.len] = .{ .name = name, .ok = ok };
        self.len += 1;
    }

    pub fn passed(self: *const Report) bool {
        if (self.len == 0) return false;
        for (self.steps[0..self.len]) |s| if (!s.ok) return false;
        return true;
    }

    pub fn items(self: *const Report) []const Step {
        return self.steps[0..self.len];
    }
};

/// Runs the loopback scenario. `rnd` supplies keys, indices and nonces;
/// `start_ns` is the simulated wall-clock start time.
pub fn run(rnd: std.Random, start_ns: u64) Report {
    var r = Report{};
    var now = start_ns;

    var ki: [32]u8 = undefined;
    var kr: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    rnd.bytes(&ki);
    rnd.bytes(&kr);
    rnd.bytes(&psk);
    const ini = noise.LocalIdentity.init(&ki);
    const rsp = noise.LocalIdentity.init(&kr);
    std.crypto.secureZero(u8, &ki);
    std.crypto.secureZero(u8, &kr);
    r.initiator_public = ini.public_key;
    r.responder_public = rsp.public_key;
    var ip = [_]noise.Peer{noise.Peer.init(&ini, &rsp.public_key, &psk)};
    var rp = [_]noise.Peer{noise.Peer.init(&rsp, &ini.public_key, &psk)};

    var secret: [32]u8 = undefined;
    rnd.bytes(&secret);
    const checker = noise.CookieChecker.init(&rsp, &secret, now);
    var src_buf: [18]u8 = undefined;
    const source = noise.encodeSource(&.{ 192, 0, 2, 1 }, 51820, &src_buf);

    var eph: [32]u8 = undefined;
    rnd.bytes(&eph);
    const first = noise.createInitiation(&ini, &ip[0], &eph, &noise.handshakeTimestamp(now), rnd.int(u32), now) catch {
        r.add("initiation created", false);
        return r;
    };
    r.add("initiation created", true);
    r.add("mac1 valid, mac2 absent", checker.checkMac1(&first) and !checker.checkMac2(&first, source));

    // Responder is under load: answer with a cookie reply instead.
    var nonce: [24]u8 = undefined;
    rnd.bytes(&nonce);
    const reply_ok = blk: {
        const reply = checker.createReply(&first, source, &nonce) catch break :blk false;
        _ = noise.consumeCookieReply(&ip, &reply, now) catch break :blk false;
        break :blk true;
    };
    r.add("cookie reply consumed", reply_ok);

    now += noise.REKEY_TIMEOUT_NS;
    rnd.bytes(&eph);
    const retry = noise.createInitiation(&ini, &ip[0], &eph, &noise.handshakeTimestamp(now), rnd.int(u32), now) catch {
        r.add("retry carries valid mac2", false);
        return r;
    };
    r.add("retry carries valid mac2", checker.checkMac2(&retry, source));

    const peer = noise.consumeInitiation(&rsp, &rp, &retry, now) catch {
        r.add("initiation consumed", false);
        return r;
    };
    r.add("initiation consumed", std.mem.eql(u8, &peer.remote_static, &ini.public_key));

    rnd.bytes(&eph);
    const resp = noise.createResponse(&rsp, peer, &eph, rnd.int(u32), now) catch {
        r.add("response consumed", false);
        return r;
    };
    const ipeer = noise.consumeResponse(&ini, &ip, &resp, now) catch {
        r.add("response consumed", false);
        return r;
    };
    r.add("response consumed", true);
    std.crypto.secureZero(u8, &eph);

    const k_i = noise.deriveKeys(ipeer) catch unreachable;
    const k_r = noise.deriveKeys(peer) catch unreachable;
    r.add("transport keys agree", std.mem.eql(u8, &k_i.send_key, &k_r.recv_key) and
        std.mem.eql(u8, &k_i.recv_key, &k_r.send_key));

    var si = session.Session.init(k_i, now);
    var sr = session.Session.init(k_r, now);
    var pkt: [128]u8 = undefined;
    var out: [128]u8 = undefined;
    const msg = "loopback payload";
    const data_ok = blk: {
        const n = si.encrypt(msg, &pkt, now) catch break :blk false;
        const m = sr.decrypt(pkt[0..n], &out, now) catch break :blk false;
        if (!std.mem.eql(u8, out[0..msg.len], msg) or m != 16) break :blk false;
        const k = sr.encrypt("", out[0..32], now) catch break :blk false; // keepalive back
        var back: [16]u8 = undefined;
        const z = si.decrypt(out[0..k], &back, now) catch break :blk false;
        break :blk z == 0;
    };
    r.add("data and keepalive exchanged", data_ok);

    const n = si.encrypt(msg, &pkt, now) catch 0;
    _ = sr.decrypt(pkt[0..n], &out, now) catch {};
    r.add("replayed data rejected", if (sr.decrypt(pkt[0..n], &out, now)) |_| false else |e| e == error.Replayed);

    const n2 = si.encrypt(msg, &pkt, now) catch 0;
    pkt[n2 - 1] ^= 0x80;
    r.add("tampered data rejected", if (sr.decrypt(pkt[0..n2], &out, now)) |_| false else |e| e == error.AuthenticationFailed);

    now += noise.NS_PER_SEC;
    r.add("replayed initiation rejected", if (noise.consumeInitiation(&rsp, &rp, &retry, now)) |_| false else |e| e == error.StaleTimestamp);
    return r;
}

test "loopback self-test passes every step" {
    var prng = std.Random.DefaultPrng.init(7);
    const report = run(prng.random(), 1_700_000_000 * noise.NS_PER_SEC);
    for (report.items()) |s| {
        if (!s.ok) std.debug.print("step failed: {s}\n", .{s.name});
    }
    try std.testing.expect(report.passed());
    try std.testing.expectEqual(@as(usize, 11), report.len);
}
