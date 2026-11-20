const std = @import("std");

pub const CHACHA20_KEY_SIZE: usize = 32;
pub const CHACHA20_NONCE_SIZE: usize = 12;
pub const CHACHA20_BLOCK_SIZE: usize = 64;

const CONSTANTS = [4]u32{
    0x61707865, // "expa"
    0x3320646e, // "nd 3"
    0x79622d32, // "2-by"
    0x6b206574, // "te k"
};

pub inline fn quarterRound(a: *u32, b: *u32, c: *u32, d: *u32) void {
    a.* = a.* +% b.*;
    d.* ^= a.*;
    d.* = std.math.rotl(u32, d.*, 16);

    c.* = c.* +% d.*;
    b.* ^= c.*;
    b.* = std.math.rotl(u32, b.*, 12);

    a.* = a.* +% b.*;
    d.* ^= a.*;
    d.* = std.math.rotl(u32, d.*, 8);

    c.* = c.* +% d.*;
    b.* ^= c.*;
    b.* = std.math.rotl(u32, b.*, 7);
}

pub const ChaCha20 = struct {
    state: [16]u32,

    pub fn init(key: *const [CHACHA20_KEY_SIZE]u8, nonce: *const [CHACHA20_NONCE_SIZE]u8, counter: u32) ChaCha20 {
        var state: [16]u32 = undefined;
        state[0] = CONSTANTS[0];
        state[1] = CONSTANTS[1];
        state[2] = CONSTANTS[2];
        state[3] = CONSTANTS[3];

        for (0..8) |i| {
            state[4 + i] = std.mem.readInt(u32, key[i * 4 ..][0..4], .little);
        }

        state[12] = counter;

        for (0..3) |i| {
            state[13 + i] = std.mem.readInt(u32, nonce[i * 4 ..][0..4], .little);
        }

        return ChaCha20{ .state = state };
    }

    pub fn block(self: *const ChaCha20, out_block: *[CHACHA20_BLOCK_SIZE]u8) void {
        var working = self.state;

        // 10 double rounds = 20 rounds
        var round: usize = 0;
        while (round < 10) : (round += 1) {
            // Column round
            quarterRound(&working[0], &working[4], &working[8], &working[12]);
            quarterRound(&working[1], &working[5], &working[9], &working[13]);
            quarterRound(&working[2], &working[6], &working[10], &working[14]);
            quarterRound(&working[3], &working[7], &working[11], &working[15]);

            // Diagonal round
            quarterRound(&working[0], &working[5], &working[10], &working[15]);
            quarterRound(&working[1], &working[6], &working[11], &working[12]);
            quarterRound(&working[2], &working[7], &working[8], &working[13]);
            quarterRound(&working[3], &working[4], &working[9], &working[14]);
        }

        for (0..16) |i| {
            const val = working[i] +% self.state[i];
            std.mem.writeInt(u32, out_block[i * 4 ..][0..4], val, .little);
        }
    }

    pub fn xorStream(self: *ChaCha20, in: []const u8, out: []u8) void {
        std.debug.assert(in.len <= out.len);

        var key_block: [CHACHA20_BLOCK_SIZE]u8 = undefined;
        var offset: usize = 0;

        while (offset < in.len) {
            self.block(&key_block);
            self.state[12] +%= 1; // Increment counter

            const chunk_len = if (in.len - offset < CHACHA20_BLOCK_SIZE) in.len - offset else CHACHA20_BLOCK_SIZE;
            for (0..chunk_len) |i| {
                out[offset + i] = in[offset + i] ^ key_block[i];
            }
            offset += chunk_len;
        }
    }
};

/// HChaCha20 (draft-irtf-cfrg-xchacha Section 2.2): derives a 256-bit subkey
/// from a key and a 128-bit nonce. Same 20 rounds as ChaCha20, without the
/// final feed-forward addition; output is state words 0..3 and 12..15.
pub fn hchacha20(key: *const [CHACHA20_KEY_SIZE]u8, nonce16: *const [16]u8) [32]u8 {
    var w: [16]u32 = undefined;
    w[0] = CONSTANTS[0];
    w[1] = CONSTANTS[1];
    w[2] = CONSTANTS[2];
    w[3] = CONSTANTS[3];
    for (0..8) |i| w[4 + i] = std.mem.readInt(u32, key[i * 4 ..][0..4], .little);
    for (0..4) |i| w[12 + i] = std.mem.readInt(u32, nonce16[i * 4 ..][0..4], .little);

    var round: usize = 0;
    while (round < 10) : (round += 1) {
        quarterRound(&w[0], &w[4], &w[8], &w[12]);
        quarterRound(&w[1], &w[5], &w[9], &w[13]);
        quarterRound(&w[2], &w[6], &w[10], &w[14]);
        quarterRound(&w[3], &w[7], &w[11], &w[15]);
        quarterRound(&w[0], &w[5], &w[10], &w[15]);
        quarterRound(&w[1], &w[6], &w[11], &w[12]);
        quarterRound(&w[2], &w[7], &w[8], &w[13]);
        quarterRound(&w[3], &w[4], &w[9], &w[14]);
    }

    var out: [32]u8 = undefined;
    for (0..4) |i| {
        std.mem.writeInt(u32, out[i * 4 ..][0..4], w[i], .little);
        std.mem.writeInt(u32, out[16 + i * 4 ..][0..4], w[12 + i], .little);
    }
    std.crypto.secureZero(u32, &w);
    return out;
}

test "RFC 8439 Section 2.3.2 ChaCha20 Block Function Test Vector" {
    const key = [32]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const nonce = [12]u8{
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00,
    };
    const counter: u32 = 1;

    const ctx = ChaCha20.init(&key, &nonce, counter);
    var block_out: [64]u8 = undefined;
    ctx.block(&block_out);

    const expected_first_words = [16]u8{
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
        0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
    };
    try std.testing.expectEqualSlices(u8, &expected_first_words, block_out[0..16]);
}

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

const rfc_key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

test "RFC 8439 Section 2.3.2 full serialized block" {
    const ctx = ChaCha20.init(&rfc_key, &hexToBytes("000000090000004a00000000"), 1);
    var out: [64]u8 = undefined;
    ctx.block(&out);
    try std.testing.expectEqualSlices(u8, &hexToBytes(
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" ++
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
    ), &out);
}

test "RFC 8439 Section 2.4.2 ChaCha20 encryption of the sunscreen plaintext" {
    const plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    var ctx = ChaCha20.init(&rfc_key, &hexToBytes("000000000000004a00000000"), 1);
    var ct: [plaintext.len]u8 = undefined;
    ctx.xorStream(plaintext, &ct);
    try std.testing.expectEqualSlices(u8, &hexToBytes(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" ++
            "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" ++
            "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" ++
            "5af90bbf74a35be6b40b8eedf2785e42874d",
    ), &ct);
}

test "draft-irtf-cfrg-xchacha Section 2.2.1 HChaCha20 test vector" {
    const sub = hchacha20(&rfc_key, &hexToBytes("000000090000004a0000000031415927"));
    try std.testing.expectEqualSlices(u8, &hexToBytes("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"), &sub);
}

test "ChaCha20 differential test against std.crypto" {
    var prng = std.Random.DefaultPrng.init(0xc4ac4a20);
    const rnd = prng.random();
    var in: [1000]u8 = undefined;
    var ours: [1000]u8 = undefined;
    var theirs: [1000]u8 = undefined;
    for (0..100) |_| {
        var key: [32]u8 = undefined;
        var nonce: [12]u8 = undefined;
        rnd.bytes(&key);
        rnd.bytes(&nonce);
        const counter = rnd.int(u32) >> 8;
        const len = rnd.uintLessThan(usize, in.len + 1);
        rnd.bytes(in[0..len]);
        var ctx = ChaCha20.init(&key, &nonce, counter);
        ctx.xorStream(in[0..len], ours[0..len]);
        std.crypto.stream.chacha.ChaCha20IETF.xor(theirs[0..len], in[0..len], counter, key, nonce);
        try std.testing.expectEqualSlices(u8, theirs[0..len], ours[0..len]);
    }
}
