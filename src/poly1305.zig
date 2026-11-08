const std = @import("std");

pub const POLY1305_KEY_SIZE: usize = 32;
pub const POLY1305_TAG_SIZE: usize = 16;
pub const POLY1305_BLOCK_SIZE: usize = 16;

const P: u256 = (@as(u256, 1) << 130) - 5;

pub const Poly1305 = struct {
    r: u256,
    s: u128,
    accumulator: u256,
    buffer: [16]u8,
    buf_len: usize,

    pub fn init(key: *const [POLY1305_KEY_SIZE]u8) Poly1305 {
        var r_bytes: [16]u8 = undefined;
        @memcpy(&r_bytes, key[0..16]);

        // Clamp r
        r_bytes[3] &= 15;
        r_bytes[7] &= 15;
        r_bytes[11] &= 15;
        r_bytes[15] &= 15;
        r_bytes[4] &= 252;
        r_bytes[8] &= 252;
        r_bytes[12] &= 252;

        const r_val = std.mem.readInt(u128, &r_bytes, .little);
        const s_val = std.mem.readInt(u128, key[16..32][0..16], .little);

        var buf: [16]u8 = undefined;
        @memset(&buf, 0);

        return Poly1305{
            .r = @as(u256, r_val),
            .s = s_val,
            .accumulator = 0,
            .buffer = buf,
            .buf_len = 0,
        };
    }

    fn processBlock(self: *Poly1305, blk: []const u8) void {
        var block_bytes: [17]u8 = undefined;
        @memset(&block_bytes, 0);
        @memcpy(block_bytes[0..blk.len], blk);
        block_bytes[blk.len] = 1;

        var n: u256 = 0;
        for (0..blk.len + 1) |i| {
            n |= @as(u256, block_bytes[i]) << @as(u8, @intCast(i * 8));
        }

        self.accumulator = (self.accumulator + n) % P;
        self.accumulator = (self.accumulator * self.r) % P;
    }

    pub fn update(self: *Poly1305, msg: []const u8) void {
        var offset: usize = 0;
        while (offset < msg.len) {
            if (self.buf_len > 0 or msg.len - offset < 16) {
                const to_copy = if (16 - self.buf_len < msg.len - offset) 16 - self.buf_len else msg.len - offset;
                @memcpy(self.buffer[self.buf_len .. self.buf_len + to_copy], msg[offset .. offset + to_copy]);
                self.buf_len += to_copy;
                offset += to_copy;

                if (self.buf_len == 16) {
                    self.processBlock(&self.buffer);
                    self.buf_len = 0;
                }
            } else {
                self.processBlock(msg[offset .. offset + 16]);
                offset += 16;
            }
        }
    }

    pub fn final(self: *Poly1305, out_tag: *[POLY1305_TAG_SIZE]u8) void {
        if (self.buf_len > 0) {
            self.processBlock(self.buffer[0..self.buf_len]);
            self.buf_len = 0;
        }

        const a_mod = @as(u128, @truncate(self.accumulator));
        const final_val = a_mod +% self.s;
        std.mem.writeInt(u128, out_tag, final_val, .little);
    }

    pub fn authenticate(key: *const [POLY1305_KEY_SIZE]u8, msg: []const u8, out_tag: *[POLY1305_TAG_SIZE]u8) void {
        var p = Poly1305.init(key);
        p.update(msg);
        p.final(out_tag);
    }

    pub fn verify(tag_a: *const [POLY1305_TAG_SIZE]u8, tag_b: *const [POLY1305_TAG_SIZE]u8) bool {
        var diff: u8 = 0;
        for (0..POLY1305_TAG_SIZE) |i| {
            diff |= tag_a[i] ^ tag_b[i];
        }
        return diff == 0;
    }
};

test "RFC 8439 Section 2.5.2 Poly1305 Test Vector" {
    const key = [32]u8{
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
    };
    const msg = "Cryptographic Forum Research Group";

    var tag: [16]u8 = undefined;
    Poly1305.authenticate(&key, msg, &tag);

    const expected_tag = [16]u8{
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
    };
    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);
    try std.testing.expect(Poly1305.verify(&tag, &expected_tag));
}
