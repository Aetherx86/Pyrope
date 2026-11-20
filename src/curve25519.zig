const std = @import("std");

pub const POINT_SIZE: usize = 32;
pub const SCALAR_SIZE: usize = 32;

/// Field element of GF(2^255 - 19) in radix 2^51: five unsigned 64-bit limbs.
///
/// Every operation is a fixed sequence of 64x64->128 bit multiplications,
/// additions, shifts and masks. There are no divisions, no secret-dependent
/// branches and no secret-dependent memory indices.
const Fe = [5]u64;

const MASK51: u64 = (1 << 51) - 1;

const fe_zero: Fe = .{ 0, 0, 0, 0, 0 };
const fe_one: Fe = .{ 1, 0, 0, 0, 0 };

fn feFromBytes(s: *const [32]u8) Fe {
    // Bit 255 is ignored (RFC 7748 Section 5): limb 4 keeps bits 204..254 only.
    return .{
        std.mem.readInt(u64, s[0..8], .little) & MASK51,
        (std.mem.readInt(u64, s[6..14], .little) >> 3) & MASK51,
        (std.mem.readInt(u64, s[12..20], .little) >> 6) & MASK51,
        (std.mem.readInt(u64, s[19..27], .little) >> 1) & MASK51,
        (std.mem.readInt(u64, s[24..32], .little) >> 12) & MASK51,
    };
}

inline fn feCarry(h: *Fe) void {
    var c = h[0] >> 51;
    h[0] &= MASK51;
    h[1] += c;
    c = h[1] >> 51;
    h[1] &= MASK51;
    h[2] += c;
    c = h[2] >> 51;
    h[2] &= MASK51;
    h[3] += c;
    c = h[3] >> 51;
    h[3] &= MASK51;
    h[4] += c;
    c = h[4] >> 51;
    h[4] &= MASK51;
    h[0] += c * 19;
}

fn feToBytes(out: *[32]u8, a: Fe) void {
    var h = a;
    feCarry(&h);
    feCarry(&h);

    // q = 1 when h >= p, computed without branches.
    var q = (h[0] + 19) >> 51;
    q = (h[1] + q) >> 51;
    q = (h[2] + q) >> 51;
    q = (h[3] + q) >> 51;
    q = (h[4] + q) >> 51;

    h[0] += 19 * q;
    var c = h[0] >> 51;
    h[0] &= MASK51;
    h[1] += c;
    c = h[1] >> 51;
    h[1] &= MASK51;
    h[2] += c;
    c = h[2] >> 51;
    h[2] &= MASK51;
    h[3] += c;
    c = h[3] >> 51;
    h[3] &= MASK51;
    h[4] += c;
    h[4] &= MASK51;

    std.mem.writeInt(u64, out[0..8], h[0] | (h[1] << 51), .little);
    std.mem.writeInt(u64, out[8..16], (h[1] >> 13) | (h[2] << 38), .little);
    std.mem.writeInt(u64, out[16..24], (h[2] >> 26) | (h[3] << 25), .little);
    std.mem.writeInt(u64, out[24..32], (h[3] >> 39) | (h[4] << 12), .little);
}

inline fn feAdd(a: Fe, b: Fe) Fe {
    var h: Fe = .{ a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3], a[4] + b[4] };
    feCarry(&h);
    return h;
}

inline fn feSub(a: Fe, b: Fe) Fe {
    // Add 4p before subtracting so no limb can underflow for carried inputs.
    var h: Fe = .{
        (a[0] + 0x1fffffffffffb4) - b[0],
        (a[1] + 0x1ffffffffffffc) - b[1],
        (a[2] + 0x1ffffffffffffc) - b[2],
        (a[3] + 0x1ffffffffffffc) - b[3],
        (a[4] + 0x1ffffffffffffc) - b[4],
    };
    feCarry(&h);
    return h;
}

inline fn m(a: u64, b: u64) u128 {
    return @as(u128, a) * @as(u128, b);
}

fn feReduceWide(r: [5]u128) Fe {
    var t = r;
    var out: Fe = undefined;
    t[1] += t[0] >> 51;
    out[0] = @as(u64, @truncate(t[0])) & MASK51;
    t[2] += t[1] >> 51;
    out[1] = @as(u64, @truncate(t[1])) & MASK51;
    t[3] += t[2] >> 51;
    out[2] = @as(u64, @truncate(t[2])) & MASK51;
    t[4] += t[3] >> 51;
    out[3] = @as(u64, @truncate(t[3])) & MASK51;
    const c: u64 = @truncate(t[4] >> 51);
    out[4] = @as(u64, @truncate(t[4])) & MASK51;
    out[0] += c * 19;
    out[1] += out[0] >> 51;
    out[0] &= MASK51;
    return out;
}

fn feMul(a: Fe, b: Fe) Fe {
    const b1_19 = b[1] * 19;
    const b2_19 = b[2] * 19;
    const b3_19 = b[3] * 19;
    const b4_19 = b[4] * 19;
    return feReduceWide(.{
        m(a[0], b[0]) + m(a[1], b4_19) + m(a[2], b3_19) + m(a[3], b2_19) + m(a[4], b1_19),
        m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b4_19) + m(a[3], b3_19) + m(a[4], b2_19),
        m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b4_19) + m(a[4], b3_19),
        m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b4_19),
        m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]),
    });
}

inline fn feSq(a: Fe) Fe {
    return feMul(a, a);
}

fn feSqN(a: Fe, n: usize) Fe {
    var r = a;
    for (0..n) |_| r = feSq(r);
    return r;
}

fn feMulSmall(a: Fe, k: u64) Fe {
    return feReduceWide(.{ m(a[0], k), m(a[1], k), m(a[2], k), m(a[3], k), m(a[4], k) });
}

/// z^(p-2) with a fixed addition chain (public exponent, constant time).
fn feInvert(z: Fe) Fe {
    const z2 = feSq(z);
    const z9 = feMul(feSqN(z2, 2), z);
    const z11 = feMul(z9, z2);
    const z_5_0 = feMul(feSq(z11), z9);
    const z_10_0 = feMul(feSqN(z_5_0, 5), z_5_0);
    const z_20_0 = feMul(feSqN(z_10_0, 10), z_10_0);
    const z_40_0 = feMul(feSqN(z_20_0, 20), z_20_0);
    const z_50_0 = feMul(feSqN(z_40_0, 10), z_10_0);
    const z_100_0 = feMul(feSqN(z_50_0, 50), z_50_0);
    const z_200_0 = feMul(feSqN(z_100_0, 100), z_100_0);
    const z_250_0 = feMul(feSqN(z_200_0, 50), z_50_0);
    return feMul(feSqN(z_250_0, 5), z11);
}

inline fn feCswap(swap: u64, a: *Fe, b: *Fe) void {
    const mask = 0 -% swap;
    inline for (0..5) |i| {
        const x = mask & (a[i] ^ b[i]);
        a[i] ^= x;
        b[i] ^= x;
    }
}

pub const Curve25519 = struct {
    pub const BASE_POINT = [32]u8{
        9, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };

    pub fn clampScalar(k_in: *const [SCALAR_SIZE]u8, k_out: *[SCALAR_SIZE]u8) void {
        @memcpy(k_out, k_in);
        k_out[0] &= 248;
        k_out[31] &= 127;
        k_out[31] |= 64;
    }

    /// X25519(scalar, u) per RFC 7748 Section 5 using the constant-time
    /// Montgomery ladder. The most significant bit of `point` is ignored and
    /// non-canonical u-coordinates are reduced, as the RFC requires.
    pub fn scalarMult(scalar: *const [SCALAR_SIZE]u8, point: *const [POINT_SIZE]u8, out_point: *[POINT_SIZE]u8) void {
        var k: [SCALAR_SIZE]u8 = undefined;
        clampScalar(scalar, &k);

        const x1 = feFromBytes(point);
        var x2 = fe_one;
        var z2 = fe_zero;
        var x3 = x1;
        var z3 = fe_one;
        var swap: u64 = 0;

        var t: usize = 255;
        while (t > 0) {
            t -= 1;
            const k_t: u64 = (k[t >> 3] >> @as(u3, @intCast(t & 7))) & 1;
            swap ^= k_t;
            feCswap(swap, &x2, &x3);
            feCswap(swap, &z2, &z3);
            swap = k_t;

            const a = feAdd(x2, z2);
            const aa = feSq(a);
            const b = feSub(x2, z2);
            const bb = feSq(b);
            const e = feSub(aa, bb);
            const c = feAdd(x3, z3);
            const d = feSub(x3, z3);
            const da = feMul(d, a);
            const cb = feMul(c, b);
            x3 = feSq(feAdd(da, cb));
            z3 = feMul(x1, feSq(feSub(da, cb)));
            x2 = feMul(aa, bb);
            z2 = feMul(e, feAdd(aa, feMulSmall(e, 121665)));
        }

        feCswap(swap, &x2, &x3);
        feCswap(swap, &z2, &z3);

        feToBytes(out_point, feMul(x2, feInvert(z2)));
        std.crypto.secureZero(u8, &k);
    }

    pub fn getPublicKey(private_key: *const [SCALAR_SIZE]u8, out_public_key: *[POINT_SIZE]u8) void {
        scalarMult(private_key, &BASE_POINT, out_public_key);
    }

    /// X25519 Diffie-Hellman that rejects the all-zero output produced by
    /// small-order peer points (RFC 7748 Section 6.1). The zero check is a
    /// constant-time OR over all output bytes.
    pub fn sharedSecret(private_key: *const [SCALAR_SIZE]u8, peer_public: *const [POINT_SIZE]u8) error{IdentityElement}![32]u8 {
        var out: [32]u8 = undefined;
        scalarMult(private_key, peer_public, &out);
        var acc: u8 = 0;
        for (out) |b| acc |= b;
        if (acc == 0) return error.IdentityElement;
        return out;
    }
};

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "RFC 7748 Section 5.2 X25519 Test Vectors" {
    // Alice private key
    const alice_private = [32]u8{
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    };

    var alice_public: [32]u8 = undefined;
    Curve25519.getPublicKey(&alice_private, &alice_public);

    const expected_alice_public = [32]u8{
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
        0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
        0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
    };
    try std.testing.expectEqualSlices(u8, &expected_alice_public, &alice_public);

    // Bob private key
    const bob_private = [32]u8{
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
        0x79, 0xe1, 0x7f, 0x8a, 0xb3, 0x8e, 0x06, 0x99,
        0xbb, 0x80, 0x47, 0x86, 0x44, 0x13, 0x72, 0x44,
        0xea, 0x32, 0x14, 0x82, 0x60, 0xf7, 0x04, 0x9b,
    };

    var bob_public: [32]u8 = undefined;
    Curve25519.getPublicKey(&bob_private, &bob_public);

    const expected_bob_public = [32]u8{
        0x04, 0xb1, 0x04, 0x63, 0xab, 0xee, 0xbd, 0x8f,
        0x1b, 0x1a, 0x5c, 0x9f, 0x8e, 0xfe, 0xdf, 0xec,
        0x98, 0x46, 0xb4, 0x45, 0x60, 0xa6, 0x3f, 0x70,
        0xb0, 0x47, 0xff, 0xda, 0x18, 0xd3, 0xd5, 0x1b,
    };
    try std.testing.expectEqualSlices(u8, &expected_bob_public, &bob_public);

    // Mutual Diffie-Hellman Shared Secret: Alice(bob_public) == Bob(alice_public)
    var shared_alice: [32]u8 = undefined;
    var shared_bob: [32]u8 = undefined;

    Curve25519.scalarMult(&alice_private, &bob_public, &shared_alice);
    Curve25519.scalarMult(&bob_private, &alice_public, &shared_bob);

    const expected_shared = [32]u8{
        0x3a, 0xa9, 0x3b, 0xa8, 0x89, 0x03, 0x9e, 0x0d,
        0x1d, 0xf4, 0xd4, 0xfe, 0xc9, 0xf5, 0xbc, 0xa9,
        0xf6, 0x32, 0x7f, 0x8e, 0x99, 0x37, 0x62, 0xe1,
        0x02, 0x43, 0x1c, 0x48, 0xa5, 0x6d, 0xd1, 0x32,
    };
    try std.testing.expectEqualSlices(u8, &expected_shared, &shared_alice);
    try std.testing.expectEqualSlices(u8, &expected_shared, &shared_bob);
}

test "RFC 7748 Section 5.2 X25519 function vectors (incl. u-coordinate with bit 255 set)" {
    const cases = [_]struct { k: [32]u8, u: [32]u8, out: [32]u8 }{
        .{
            .k = hexToBytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            .u = hexToBytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
            .out = hexToBytes("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
        },
        .{
            .k = hexToBytes("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
            .u = hexToBytes("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
            .out = hexToBytes("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
        },
    };
    for (cases) |c| {
        var out: [32]u8 = undefined;
        Curve25519.scalarMult(&c.k, &c.u, &out);
        try std.testing.expectEqualSlices(u8, &c.out, &out);
    }
}

test "RFC 7748 Section 5.2 iterated X25519 (1 and 1000 iterations)" {
    var k = Curve25519.BASE_POINT;
    var u = Curve25519.BASE_POINT;
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        var r: [32]u8 = undefined;
        Curve25519.scalarMult(&k, &u, &r);
        u = k;
        k = r;
        if (i == 0) {
            try std.testing.expectEqualSlices(u8, &hexToBytes("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"), &k);
        }
    }
    try std.testing.expectEqualSlices(u8, &hexToBytes("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"), &k);
}

test "X25519 differential test against std.crypto, including non-canonical u" {
    var prng = std.Random.DefaultPrng.init(0x25519);
    const rnd = prng.random();
    var i: usize = 0;
    while (i < 300) : (i += 1) {
        var k: [32]u8 = undefined;
        var u: [32]u8 = undefined;
        rnd.bytes(&k);
        rnd.bytes(&u);
        // Non-canonical encodings: values in [p, 2^255) and the top bit set.
        if (i % 10 == 0) {
            @memset(&u, 0xff);
            u[0] = 0xed -% @as(u8, @intCast(i % 19));
        }
        var ours: [32]u8 = undefined;
        Curve25519.scalarMult(&k, &u, &ours);
        const theirs = std.crypto.dh.X25519.scalarmult(k, u) catch @as([32]u8, @splat(0));
        try std.testing.expectEqualSlices(u8, &theirs, &ours);
    }
}

test "X25519 sharedSecret rejects small-order points" {
    const k = hexToBytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    // Points of order 1, 2, 4 and 8 on Curve25519 and its twist.
    const small = [_][32]u8{
        @splat(0),
        hexToBytes("0100000000000000000000000000000000000000000000000000000000000000"),
        hexToBytes("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        hexToBytes("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        hexToBytes("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    };
    for (small) |p| {
        try std.testing.expectError(error.IdentityElement, Curve25519.sharedSecret(&k, &p));
    }
    const ok = try Curve25519.sharedSecret(&k, &Curve25519.BASE_POINT);
    var pk: [32]u8 = undefined;
    Curve25519.getPublicKey(&k, &pk);
    try std.testing.expectEqualSlices(u8, &pk, &ok);
}
