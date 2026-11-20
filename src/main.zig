const std = @import("std");
pub const chacha = @import("chacha20.zig");
pub const poly = @import("poly1305.zig");
pub const aead = @import("aead.zig");
pub const curve = @import("curve25519.zig");
pub const wireguard = @import("wireguard.zig");
pub const blake2s = @import("blake2s.zig");
pub const replay = @import("replay.zig");
pub const noise = @import("noise.zig");
pub const session = @import("session.zig");
pub const selftest = @import("selftest.zig");

pub const VERSION = "0.2.0";

const Writer = std.Io.Writer;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var out_buf: [4096]u8 = undefined;
    var stdout_file = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const out = &stdout_file.interface;
    const code = run(init, out) catch |err| blk: {
        std.debug.print("pyrope: {s}\n", .{@errorName(err)});
        break :blk 1;
    };
    out.flush() catch {};
    if (code != 0) std.process.exit(code);
}

fn run(init: std.process.Init, out: *Writer) !u8 {
    const io = init.io;
    var args = init.minimal.args.iterate();
    _ = args.next(); // skip prog name

    const cmd = args.next() orelse {
        try printUsage(out);
        return 0;
    };

    if (eql(cmd, "--help") or eql(cmd, "-h") or eql(cmd, "help")) {
        try printUsage(out);
        return 0;
    }

    if (eql(cmd, "--version") or eql(cmd, "-v")) {
        try out.print("Pyrope v{s} (Constant-Time WireGuard / ChaCha20-Poly1305 Tunnel)\n", .{VERSION});
        return 0;
    }

    if (eql(cmd, "bench")) {
        var megabytes: usize = 10;
        var json = false;
        while (args.next()) |a| {
            if (eql(a, "--json")) {
                json = true;
            } else {
                megabytes = std.fmt.parseInt(usize, a, 10) catch {
                    std.debug.print("pyrope: bench expects a size in megabytes, got '{s}'\n", .{a});
                    return 2;
                };
                if (megabytes == 0 or megabytes > 1 << 20) {
                    std.debug.print("pyrope: bench size must be between 1 and 1048576 MB\n", .{});
                    return 2;
                }
            }
        }
        try runBenchmark(io, out, megabytes, json);
        return 0;
    }

    if (eql(cmd, "keygen")) {
        var priv = try randomPrivateKey(io);
        defer std.crypto.secureZero(u8, &priv);
        var pub_key: [32]u8 = undefined;
        curve.Curve25519.getPublicKey(&priv, &pub_key);
        const priv_hex = std.fmt.bytesToHex(priv, .lower);
        const pub_hex = std.fmt.bytesToHex(pub_key, .lower);
        try out.print("Curve25519 Keypair Generated:\nPrivate: {s}\nPublic:  {s}\n", .{ &priv_hex, &pub_hex });
        return 0;
    }

    if (eql(cmd, "genkey")) {
        var priv = try randomPrivateKey(io);
        defer std.crypto.secureZero(u8, &priv);
        try writeBase64Key(out, &priv);
        return 0;
    }

    if (eql(cmd, "pubkey")) {
        var in_buf: [512]u8 = undefined;
        var stdin_file = std.Io.File.stdin().readerStreaming(io, &in_buf);
        const line = (stdin_file.interface.takeDelimiter('\n') catch null) orelse "";
        var priv = decodeBase64Key(line) catch {
            std.debug.print("pyrope: pubkey expects a base64 X25519 private key (44 characters) on stdin\n", .{});
            return 1;
        };
        defer std.crypto.secureZero(u8, &priv);
        var pub_key: [32]u8 = undefined;
        curve.Curve25519.getPublicKey(&priv, &pub_key);
        try writeBase64Key(out, &pub_key);
        return 0;
    }

    if (eql(cmd, "selftest")) {
        var json = false;
        while (args.next()) |a| {
            if (eql(a, "--json")) json = true else {
                std.debug.print("pyrope: unknown selftest option '{s}'\n", .{a});
                return 2;
            }
        }
        var seed: [32]u8 = undefined;
        try io.randomSecure(&seed);
        var csprng = std.Random.DefaultCsprng.init(seed);
        std.crypto.secureZero(u8, &seed);
        const wall = std.Io.Clock.real.now(io).nanoseconds;
        const report = selftest.run(csprng.random(), @intCast(@max(wall, 0)));
        try printSelftest(out, &report, json);
        return if (report.passed()) 0 else 1;
    }

    std.debug.print("pyrope: unknown command '{s}'\n", .{cmd});
    try printUsage(out);
    return 2;
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn printUsage(out: *Writer) !void {
    try out.writeAll(
        \\Pyrope: Constant-Time WireGuard / ChaCha20-Poly1305 Tunnel
        \\Usage: pyrope <command> [options]
        \\
        \\Commands:
        \\  genkey                     Print a new base64 X25519 private key
        \\  pubkey                     Read a base64 private key on stdin, print its public key
        \\  keygen                     Print a new keypair in hex
        \\  selftest [--json]          Run a loopback handshake, cookie and transport self-test
        \\  bench [megabytes] [--json] Benchmark AEAD throughput and handshake rate
        \\  --version, -v              Print version
        \\  --help, -h                 Print this help message
        \\
    );
}

fn randomPrivateKey(io: std.Io) ![32]u8 {
    var raw: [32]u8 = undefined;
    try io.randomSecure(&raw);
    var priv: [32]u8 = undefined;
    curve.Curve25519.clampScalar(&raw, &priv);
    std.crypto.secureZero(u8, &raw);
    return priv;
}

fn writeBase64Key(out: *Writer, key: *const [32]u8) !void {
    var buf: [44]u8 = undefined;
    const enc = std.base64.standard.Encoder.encode(&buf, key);
    try out.print("{s}\n", .{enc});
    std.crypto.secureZero(u8, &buf);
}

pub fn decodeBase64Key(text: []const u8) ![32]u8 {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len != 44) return error.InvalidKey;
    const dec = std.base64.standard.Decoder;
    if ((dec.calcSizeForSlice(trimmed) catch return error.InvalidKey) != 32) return error.InvalidKey;
    var key: [32]u8 = undefined;
    dec.decode(&key, trimmed) catch return error.InvalidKey;
    return key;
}

fn printSelftest(out: *Writer, report: *const selftest.Report, json: bool) !void {
    const ipub = std.fmt.bytesToHex(report.initiator_public, .lower);
    const rpub = std.fmt.bytesToHex(report.responder_public, .lower);
    if (json) {
        try out.print("{{\"version\":\"{s}\",\"passed\":{},\"initiator_public\":\"{s}\",\"responder_public\":\"{s}\",\"steps\":[", .{ VERSION, report.passed(), &ipub, &rpub });
        for (report.items(), 0..) |s, i| {
            if (i > 0) try out.writeAll(",");
            try out.print("{{\"name\":\"{s}\",\"ok\":{}}}", .{ s.name, s.ok });
        }
        try out.writeAll("]}\n");
        return;
    }
    try out.print("Loopback self-test (initiator {s}..., responder {s}...)\n", .{ ipub[0..8], rpub[0..8] });
    for (report.items()) |s| {
        try out.print("  [{s}] {s}\n", .{ if (s.ok) "ok" else "FAIL", s.name });
    }
    try out.print("{s}\n", .{if (report.passed()) "PASS" else "FAIL"});
}

const BenchResult = struct {
    name: []const u8,
    bytes: u64,
    ns: u64,

    fn mbPerSec(self: BenchResult) f64 {
        if (self.ns == 0) return 0;
        return (@as(f64, @floatFromInt(self.bytes)) / (1024.0 * 1024.0)) / (@as(f64, @floatFromInt(self.ns)) / 1e9);
    }
};

fn nowNs(io: std.Io) i96 {
    return std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
}

fn elapsed(io: std.Io, t0: i96) u64 {
    return @intCast(@max(nowNs(io) - t0, 1));
}

fn runBenchmark(io: std.Io, out: *Writer, megabytes: usize, json: bool) !void {
    var key: [32]u8 = @splat(0x55);
    const nonce: [12]u8 = @splat(0x11);
    const xnonce: [24]u8 = @splat(0x22);
    var chunk: [65536]u8 = @splat(0xA5);
    var ct: [65536]u8 = undefined;
    var tag: [16]u8 = undefined;

    const iterations = @max((megabytes * 1024 * 1024) / chunk.len, 1);
    const total: u64 = iterations * chunk.len;

    var results: [4]BenchResult = undefined;

    var t0 = nowNs(io);
    for (0..iterations) |_| {
        aead.ChaCha20Poly1305.encrypt(&key, &nonce, "bench_aad", &chunk, &ct, &tag);
        key[0] ^= tag[0]; // keep the work observable
    }
    results[0] = .{ .name = "chacha20poly1305_seal", .bytes = total, .ns = elapsed(io, t0) };

    aead.ChaCha20Poly1305.encrypt(&key, &nonce, "bench_aad", &chunk, &ct, &tag);
    t0 = nowNs(io);
    for (0..iterations) |_| {
        try aead.ChaCha20Poly1305.decrypt(&key, &nonce, "bench_aad", &ct, &tag, &chunk);
    }
    results[1] = .{ .name = "chacha20poly1305_open", .bytes = total, .ns = elapsed(io, t0) };

    t0 = nowNs(io);
    for (0..iterations) |_| {
        aead.XChaCha20Poly1305.encrypt(&key, &xnonce, "bench_aad", &chunk, &ct, &tag);
        key[1] ^= tag[0];
    }
    results[2] = .{ .name = "xchacha20poly1305_seal", .bytes = total, .ns = elapsed(io, t0) };

    // Transport path: 1420-byte packets through a Session (padding + framing).
    var keys = noise.SessionKeys{ .send_key = key, .recv_key = key, .local_index = 1, .remote_index = 1, .is_initiator = true };
    var s = session.Session.init(keys, 0);
    var pkt: [session.paddedLength(1420, 0) + wireguard.TRANSPORT_OVERHEAD]u8 = undefined;
    const pkts = @max(total / 1420, 1);
    t0 = nowNs(io);
    for (0..pkts) |_| {
        _ = try s.encrypt(chunk[0..1420], &pkt, 0);
    }
    results[3] = .{ .name = "transport_encrypt_1420", .bytes = pkts * 1420, .ns = elapsed(io, t0) };
    keys.send_key = @splat(0);

    // Full handshakes per second (initiation + response + key derivation).
    var prng = std.Random.DefaultPrng.init(1);
    const rnd = prng.random();
    var ka: [32]u8 = undefined;
    var kb: [32]u8 = undefined;
    rnd.bytes(&ka);
    rnd.bytes(&kb);
    const a = noise.LocalIdentity.init(&ka);
    const b = noise.LocalIdentity.init(&kb);
    var ap = [_]noise.Peer{noise.Peer.init(&a, &b.public_key, null)};
    var bp = [_]noise.Peer{noise.Peer.init(&b, &a.public_key, null)};
    const handshakes: u64 = 200;
    t0 = nowNs(io);
    var i: u64 = 0;
    while (i < handshakes) : (i += 1) {
        var e: [32]u8 = undefined;
        rnd.bytes(&e);
        const now = (i + 1) * noise.NS_PER_SEC;
        const m1 = try noise.createInitiation(&a, &ap[0], &e, &noise.tai64n(i + 1, 0), @intCast(i), now);
        const rp = try noise.consumeInitiation(&b, &bp, &m1, now);
        rnd.bytes(&e);
        const m2 = try noise.createResponse(&b, rp, &e, @intCast(i), now);
        const ip = try noise.consumeResponse(&a, &ap, &m2, now);
        _ = try noise.deriveKeys(ip);
        _ = try noise.deriveKeys(rp);
    }
    const hs_ns = elapsed(io, t0);
    const hs_per_sec = @as(f64, @floatFromInt(handshakes)) / (@as(f64, @floatFromInt(hs_ns)) / 1e9);

    if (json) {
        try out.print("{{\"version\":\"{s}\",\"megabytes\":{d},\"results\":[", .{ VERSION, megabytes });
        for (results, 0..) |r, idx| {
            if (idx > 0) try out.writeAll(",");
            try out.print("{{\"name\":\"{s}\",\"bytes\":{d},\"ns\":{d},\"mb_per_s\":{d:.1}}}", .{ r.name, r.bytes, r.ns, r.mbPerSec() });
        }
        try out.print("],\"handshakes\":{{\"count\":{d},\"ns\":{d},\"per_s\":{d:.1}}}}}\n", .{ handshakes, hs_ns, hs_per_sec });
        return;
    }
    try out.print("AEAD throughput ({d} MB per run):\n", .{megabytes});
    for (results) |r| {
        try out.print("  {s:<24} {d:>10.1} MB/s\n", .{ r.name, r.mbPerSec() });
    }
    try out.print("Full handshakes: {d} in {d:.3} s ({d:.1}/s)\n", .{ handshakes, @as(f64, @floatFromInt(hs_ns)) / 1e9, hs_per_sec });
}

// C-ABI Export Symbols
pub export fn pyrope_x25519(scalar: [*]const u8, point: [*]const u8, out: [*]u8) void {
    const s: *const [32]u8 = @ptrCast(scalar);
    const p: *const [32]u8 = @ptrCast(point);
    const o: *[32]u8 = @ptrCast(out);
    curve.Curve25519.scalarMult(s, p, o);
}

pub export fn pyrope_aead_encrypt(
    key: [*]const u8,
    nonce: [*]const u8,
    aad_ptr: [*]const u8,
    aad_len: usize,
    pt_ptr: [*]const u8,
    pt_len: usize,
    out_ct: [*]u8,
    out_tag: [*]u8,
) void {
    const k: *const [32]u8 = @ptrCast(key);
    const n: *const [12]u8 = @ptrCast(nonce);
    const t: *[16]u8 = @ptrCast(out_tag);
    aead.ChaCha20Poly1305.encrypt(k, n, aad_ptr[0..aad_len], pt_ptr[0..pt_len], out_ct[0..pt_len], t);
}

pub export fn pyrope_aead_decrypt(
    key: [*]const u8,
    nonce: [*]const u8,
    aad_ptr: [*]const u8,
    aad_len: usize,
    ct_ptr: [*]const u8,
    ct_len: usize,
    tag: [*]const u8,
    out_pt: [*]u8,
) i32 {
    const k: *const [32]u8 = @ptrCast(key);
    const n: *const [12]u8 = @ptrCast(nonce);
    const t: *const [16]u8 = @ptrCast(tag);
    aead.ChaCha20Poly1305.decrypt(k, n, aad_ptr[0..aad_len], ct_ptr[0..ct_len], t, out_pt[0..ct_len]) catch {
        return -1; // Auth failure
    };
    return 0; // Success
}

/// XChaCha20-Poly1305 with a 24-byte nonce (draft-irtf-cfrg-xchacha).
pub export fn pyrope_xaead_encrypt(
    key: [*]const u8,
    nonce: [*]const u8,
    aad_ptr: [*]const u8,
    aad_len: usize,
    pt_ptr: [*]const u8,
    pt_len: usize,
    out_ct: [*]u8,
    out_tag: [*]u8,
) void {
    const k: *const [32]u8 = @ptrCast(key);
    const n: *const [24]u8 = @ptrCast(nonce);
    const t: *[16]u8 = @ptrCast(out_tag);
    aead.XChaCha20Poly1305.encrypt(k, n, aad_ptr[0..aad_len], pt_ptr[0..pt_len], out_ct[0..pt_len], t);
}

/// Returns 0 on success, -1 when authentication fails (nothing is written).
pub export fn pyrope_xaead_decrypt(
    key: [*]const u8,
    nonce: [*]const u8,
    aad_ptr: [*]const u8,
    aad_len: usize,
    ct_ptr: [*]const u8,
    ct_len: usize,
    tag: [*]const u8,
    out_pt: [*]u8,
) i32 {
    const k: *const [32]u8 = @ptrCast(key);
    const n: *const [24]u8 = @ptrCast(nonce);
    const t: *const [16]u8 = @ptrCast(tag);
    aead.XChaCha20Poly1305.decrypt(k, n, aad_ptr[0..aad_len], ct_ptr[0..ct_len], t, out_pt[0..ct_len]) catch return -1;
    return 0;
}

/// Derives the X25519 public key for a private key. Returns 0.
pub export fn pyrope_x25519_public_key(private_key: [*]const u8, out_public: [*]u8) i32 {
    const p: *const [32]u8 = @ptrCast(private_key);
    const o: *[32]u8 = @ptrCast(out_public);
    curve.Curve25519.getPublicKey(p, o);
    return 0;
}

test "base64 key decoding accepts wg-style keys and rejects malformed input" {
    const k = try decodeBase64Key("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=\n");
    try std.testing.expectEqual(@as(u8, 0x77), k[0]);
    try std.testing.expectEqual(@as(u8, 0x2a), k[31]);
    try std.testing.expectError(error.InvalidKey, decodeBase64Key(""));
    try std.testing.expectError(error.InvalidKey, decodeBase64Key("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LC=="));
    try std.testing.expectError(error.InvalidKey, decodeBase64Key("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo"));
    try std.testing.expectError(error.InvalidKey, decodeBase64Key("!wdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="));
}

test "C-ABI exports round trip" {
    const key: [32]u8 = @splat(7);
    const nonce: [24]u8 = @splat(9);
    const msg = "c-abi xchacha";
    var ct: [msg.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    pyrope_xaead_encrypt(&key, &nonce, "ad", 2, msg, msg.len, &ct, &tag);
    var pt: [msg.len]u8 = undefined;
    try std.testing.expectEqual(@as(i32, 0), pyrope_xaead_decrypt(&key, &nonce, "ad", 2, &ct, ct.len, &tag, &pt));
    try std.testing.expectEqualStrings(msg, &pt);
    tag[3] ^= 1;
    try std.testing.expectEqual(@as(i32, -1), pyrope_xaead_decrypt(&key, &nonce, "ad", 2, &ct, ct.len, &tag, &pt));

    var p1: [32]u8 = undefined;
    var p2: [32]u8 = undefined;
    _ = pyrope_x25519_public_key(&key, &p1);
    pyrope_x25519(&key, &curve.Curve25519.BASE_POINT, &p2);
    try std.testing.expectEqualSlices(u8, &p1, &p2);
}

test {
    _ = @import("chacha20.zig");
    _ = @import("poly1305.zig");
    _ = @import("aead.zig");
    _ = @import("curve25519.zig");
    _ = @import("wireguard.zig");
    _ = @import("blake2s.zig");
    _ = @import("replay.zig");
    _ = @import("noise.zig");
    _ = @import("session.zig");
    _ = @import("selftest.zig");
}
