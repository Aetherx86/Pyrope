const std = @import("std");

pub const POINT_SIZE: usize = 32;
pub const SCALAR_SIZE: usize = 32;

const P: u512 = (@as(u512, 1) << 255) - 19;
const A24: u512 = 121665;

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

    inline fn cswap(swap: u1, a: *u512, b: *u512) void {
        const mask: u512 = if (swap == 1) ~@as(u512, 0) else 0;
        const dummy = mask & (a.* ^ b.*);
        a.* ^= dummy;
        b.* ^= dummy;
    }

    fn modPow(base: u512, exp: u512) u512 {
        var res: u512 = 1;
        var b = base % P;
        var e = exp;

        while (e > 0) {
            if ((e & 1) == 1) {
                res = (res * b) % P;
            }
            e >>= 1;
            b = (b * b) % P;
        }
        return res;
    }

    pub fn scalarMult(scalar: *const [SCALAR_SIZE]u8, point: *const [POINT_SIZE]u8, out_point: *[POINT_SIZE]u8) void {
        var clamped_k: [SCALAR_SIZE]u8 = undefined;
        clampScalar(scalar, &clamped_k);

        var k_int: u256 = 0;
        for (0..32) |i| {
            k_int |= @as(u256, clamped_k[i]) << @as(u8, @intCast(i * 8));
        }

        var u_int: u512 = 0;
        for (0..32) |i| {
            u_int |= @as(u512, point[i]) << @as(u8, @intCast(i * 8));
        }
        u_int %= P;

        const x1 = u_int;
        var x2: u512 = 1;
        var z2: u512 = 0;
        var x3: u512 = u_int;
        var z3: u512 = 1;
        var swap: u1 = 0;

        var t: i32 = 254;
        while (t >= 0) : (t -= 1) {
            const shift: u8 = @as(u8, @intCast(t));
            const k_t: u1 = @as(u1, @truncate((k_int >> shift) & 1));
            swap ^= k_t;
            cswap(swap, &x2, &x3);
            cswap(swap, &z2, &z3);
            swap = k_t;

            const A = (x2 + z2) % P;
            const AA = (A * A) % P;
            const B = (P + x2 - z2) % P;
            const BB = (B * B) % P;
            const E = (P + AA - BB) % P;
            const C = (x3 + z3) % P;
            const D = (P + x3 - z3) % P;
            const DA = (D * A) % P;
            const CB = (C * B) % P;
            x3 = ((DA + CB) * (DA + CB)) % P;
            z3 = (x1 * (((P + DA - CB) % P) * ((P + DA - CB) % P) % P)) % P;
            x2 = (AA * BB) % P;
            z2 = (E * ((AA + A24 * E) % P)) % P;
        }

        cswap(swap, &x2, &x3);
        cswap(swap, &z2, &z3);

        const z2_inv = modPow(z2, P - 2);
        const result = (x2 * z2_inv) % P;

        for (0..32) |i| {
            const shift: u8 = @as(u8, @intCast(i * 8));
            out_point[i] = @as(u8, @truncate((result >> shift) & 0xFF));
        }
    }

    pub fn getPublicKey(private_key: *const [SCALAR_SIZE]u8, out_public_key: *[POINT_SIZE]u8) void {
        scalarMult(private_key, &BASE_POINT, out_public_key);
    }
};

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
