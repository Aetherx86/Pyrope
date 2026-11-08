const std = @import("std");
pub const chacha = @import("chacha20.zig");
pub const poly = @import("poly1305.zig");
pub const aead = @import("aead.zig");
pub const curve = @import("curve25519.zig");
pub const wireguard = @import("wireguard.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    _ = allocator;

    var args = init.minimal.args.iterate();
    _ = args.next(); // skip prog name

    const cmd = args.next() orelse {
        printUsage();
        return;
    };

    if (std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h") or std.mem.eql(u8, cmd, "help")) {
        printUsage();
        return;
    }

    if (std.mem.eql(u8, cmd, "--version") or std.mem.eql(u8, cmd, "-v")) {
        std.debug.print("Pyrope v0.1.0 (Constant-Time WireGuard / ChaCha20-Poly1305 Tunnel)\n", .{});
        return;
    }

    if (std.mem.eql(u8, cmd, "bench")) {
        const mb_str = args.next() orelse "10";
        const mb = std.fmt.parseInt(usize, mb_str, 10) catch 10;
        try runBenchmark(init.io, mb);
        return;
    }

    if (std.mem.eql(u8, cmd, "keygen")) {
        var priv: [32]u8 = undefined;
        // Deterministic seed demonstration
        @memset(&priv, 0x42);
        priv[0] = 0x77;
        priv[31] = 0x2a;

        var pub_key: [32]u8 = undefined;
        curve.Curve25519.getPublicKey(&priv, &pub_key);

        std.debug.print("Curve25519 Keypair Generated:\n", .{});
        const priv_hex = std.fmt.bytesToHex(priv, .lower);
        const pub_hex = std.fmt.bytesToHex(pub_key, .lower);
        std.debug.print("Private: {s}\n", .{&priv_hex});
        std.debug.print("Public:  {s}\n", .{&pub_hex});
        return;
    }

    printUsage();
}

fn printUsage() void {
    std.debug.print(
        \\Pyrope: Constant-Time WireGuard / ChaCha20-Poly1305 Tunnel
        \\Usage: pyrope <command> [options]
        \\
        \\Commands:
        \\  bench <megabytes>   Benchmark ChaCha20-Poly1305 AEAD throughput
        \\  keygen              Generate Curve25519 public/private keypair
        \\  --version, -v       Print version
        \\  --help, -h          Print this help message
        \\
    , .{});
}

fn runBenchmark(io: std.Io, megabytes: usize) !void {
    std.debug.print("Benchmarking ChaCha20-Poly1305 AEAD throughput ({d} MB)...\n", .{megabytes});

    var key: [32]u8 = undefined;
    @memset(&key, 0x55);
    var nonce: [12]u8 = undefined;
    @memset(&nonce, 0x11);

    var chunk: [65536]u8 = undefined; // 64 KB blocks
    @memset(&chunk, 0xA5);

    var ct: [65536]u8 = undefined;
    var tag: [16]u8 = undefined;

    const total_bytes = megabytes * 1024 * 1024;
    const iterations = total_bytes / chunk.len;

    const t0 = std.Io.Clock.Timestamp.now(io, .awake);

    for (0..iterations) |_| {
        aead.ChaCha20Poly1305.encrypt(&key, &nonce, "bench_aad", &chunk, &ct, &tag);
    }

    const t1 = std.Io.Clock.Timestamp.now(io, .awake);
    const dur_ns = t0.durationTo(t1).raw.nanoseconds;
    const dur_sec = @as(f64, @floatFromInt(dur_ns)) / 1_000_000_000.0;
    const mb_sec = if (dur_sec > 0.0) @as(f64, @floatFromInt(megabytes)) / dur_sec else 0.0;

    std.debug.print("Processed {d} MB in {d:.3} s ({d:.1} MB/s)\n", .{ megabytes, dur_sec, mb_sec });
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

test {
    _ = @import("chacha20.zig");
    _ = @import("poly1305.zig");
    _ = @import("aead.zig");
    _ = @import("curve25519.zig");
    _ = @import("wireguard.zig");
}
