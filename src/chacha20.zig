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
