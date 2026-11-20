const std = @import("std");

pub const POLY1305_KEY_SIZE: usize = 32;
pub const POLY1305_TAG_SIZE: usize = 16;
pub const POLY1305_BLOCK_SIZE: usize = 16;

const MASK44: u64 = 0xfffffffffff;
const MASK42: u64 = 0x3ffffffffff;

/// Poly1305 one-time authenticator (RFC 8439 Section 2.5).
///
/// The accumulator is held in three limbs of 44/44/42 bits and every
/// multiplication is a fixed sequence of 64x64->128 bit products, carries and
/// masks. There is no division, no table lookup and no branch that depends on
/// the key, the message contents or the accumulator value, so the running time
/// depends only on the message length.
pub const Poly1305 = struct {
    r: [3]u64,
    s1: u64,
    s2: u64,
    h: [3]u64,
    pad: [2]u64,
    buffer: [16]u8,
    buf_len: usize,

    pub fn init(key: *const [POLY1305_KEY_SIZE]u8) Poly1305 {
        const t0 = std.mem.readInt(u64, key[0..8], .little);
        const t1 = std.mem.readInt(u64, key[8..16], .little);

        // Clamp r and split it into 44/44/42 bit limbs in one step.
        const r0 = t0 & 0xffc0fffffff;
        const r1 = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
        const r2 = (t1 >> 24) & 0x00ffffffc0f;

        return Poly1305{
            .r = .{ r0, r1, r2 },
            // 2^130 = 5 (mod p); limbs above bit 88 wrap with a factor 5 << 2.
            .s1 = r1 * (5 << 2),
            .s2 = r2 * (5 << 2),
            .h = .{ 0, 0, 0 },
            .pad = .{
                std.mem.readInt(u64, key[16..24], .little),
                std.mem.readInt(u64, key[24..32], .little),
            },
            .buffer = @as([16]u8, @splat(0)),
            .buf_len = 0,
        };
    }

    /// Absorbs one 16-byte block. `hibit` is 1 << 40 for full blocks (the
    /// appended 0x01 byte at bit 128) and 0 for the final, already padded block.
    fn processBlock(self: *Poly1305, blk: *const [16]u8, hibit: u64) void {
        const t0 = std.mem.readInt(u64, blk[0..8], .little);
        const t1 = std.mem.readInt(u64, blk[8..16], .little);

        var h0 = self.h[0] + (t0 & MASK44);
        var h1 = self.h[1] + (((t0 >> 44) | (t1 << 20)) & MASK44);
        var h2 = self.h[2] + (((t1 >> 24) & MASK42) | hibit);

        const r0 = self.r[0];
        const r1 = self.r[1];
        const r2 = self.r[2];

        const d0 = mul(h0, r0) + mul(h1, self.s2) + mul(h2, self.s1);
        var d1 = mul(h0, r1) + mul(h1, r0) + mul(h2, self.s2);
        var d2 = mul(h0, r2) + mul(h1, r1) + mul(h2, r0);

        var c: u64 = @truncate(d0 >> 44);
        h0 = @as(u64, @truncate(d0)) & MASK44;
        d1 += c;
        c = @truncate(d1 >> 44);
        h1 = @as(u64, @truncate(d1)) & MASK44;
        d2 += c;
        c = @truncate(d2 >> 42);
        h2 = @as(u64, @truncate(d2)) & MASK42;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= MASK44;
        h1 += c;

        self.h = .{ h0, h1, h2 };
    }

    inline fn mul(a: u64, b: u64) u128 {
        return @as(u128, a) * @as(u128, b);
    }

    pub fn update(self: *Poly1305, msg: []const u8) void {
        var offset: usize = 0;

        if (self.buf_len > 0) {
            const want = 16 - self.buf_len;
            const take = @min(want, msg.len);
            @memcpy(self.buffer[self.buf_len .. self.buf_len + take], msg[0..take]);
            self.buf_len += take;
            offset = take;
            if (self.buf_len < 16) return;
            self.processBlock(&self.buffer, 1 << 40);
            self.buf_len = 0;
        }

        while (msg.len - offset >= 16) : (offset += 16) {
            self.processBlock(msg[offset..][0..16], 1 << 40);
        }

        const rest = msg.len - offset;
        if (rest > 0) {
            @memcpy(self.buffer[0..rest], msg[offset..]);
            self.buf_len = rest;
        }
    }

    pub fn final(self: *Poly1305, out_tag: *[POLY1305_TAG_SIZE]u8) void {
        if (self.buf_len > 0) {
            var last = @as([16]u8, @splat(0));
            @memcpy(last[0..self.buf_len], self.buffer[0..self.buf_len]);
            last[self.buf_len] = 1;
            self.processBlock(&last, 0);
            self.buf_len = 0;
        }

        var h0 = self.h[0];
        var h1 = self.h[1];
        var h2 = self.h[2];

        // Fully carry h.
        var c = h1 >> 44;
        h1 &= MASK44;
        h2 += c;
        c = h2 >> 42;
        h2 &= MASK42;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= MASK44;
        h1 += c;
        c = h1 >> 44;
        h1 &= MASK44;
        h2 += c;
        c = h2 >> 42;
        h2 &= MASK42;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= MASK44;
        h1 += c;

        // g = h + 5 - 2^130; select g when it did not underflow (h >= p).
        var g0 = h0 + 5;
        c = g0 >> 44;
        g0 &= MASK44;
        var g1 = h1 + c;
        c = g1 >> 44;
        g1 &= MASK44;
        var g2 = h2 +% c -% (@as(u64, 1) << 42);

        var mask = (g2 >> 63) -% 1; // all ones when g2 is non-negative
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;

        // h = (h + s) mod 2^128
        const t0 = self.pad[0];
        const t1 = self.pad[1];
        h0 += t0 & MASK44;
        c = h0 >> 44;
        h0 &= MASK44;
        h1 += (((t0 >> 44) | (t1 << 20)) & MASK44) + c;
        c = h1 >> 44;
        h1 &= MASK44;
        h2 += ((t1 >> 24) & MASK42) + c;
        h2 &= MASK42;

        const lo = h0 | (h1 << 44);
        const hi = (h1 >> 20) | (h2 << 24);
        std.mem.writeInt(u64, out_tag[0..8], lo, .little);
        std.mem.writeInt(u64, out_tag[8..16], hi, .little);

        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    pub fn authenticate(key: *const [POLY1305_KEY_SIZE]u8, msg: []const u8, out_tag: *[POLY1305_TAG_SIZE]u8) void {
        var p = Poly1305.init(key);
        p.update(msg);
        p.final(out_tag);
    }

    /// Constant-time tag comparison.
    pub fn verify(tag_a: *const [POLY1305_TAG_SIZE]u8, tag_b: *const [POLY1305_TAG_SIZE]u8) bool {
        var diff: u8 = 0;
        for (0..POLY1305_TAG_SIZE) |i| {
            diff |= tag_a[i] ^ tag_b[i];
        }
        return diff == 0;
    }
};

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

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

const Vector = struct { key: []const u8, msg: []const u8, tag: []const u8 };

// RFC 8439 Appendix A.3 test vectors #1 to #11 (hex). Vectors #5 to #11
// exercise the carry propagation and the final reduction modulo 2^130 - 5.
const rfc8439_a3 = [_]Vector{
    .{ // #1
        .key = "0000000000000000000000000000000000000000000000000000000000000000",
        .msg = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        .tag = "00000000000000000000000000000000",
    },
    .{ // #2
        .key = "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
        .msg = "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
        .tag = "36e5f6b5c5e06070f0efca96227a863e",
    },
    .{ // #3
        .key = "36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000",
        .msg = "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
        .tag = "f3477e7cd95417af89a6b8794c310cf0",
    },
    .{ // #4
        .key = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        .msg = "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
        .tag = "4541669a7eaaee61e708dc7cbcc5eb62",
    },
    .{ // #5
        .key = "0200000000000000000000000000000000000000000000000000000000000000",
        .msg = "ffffffffffffffffffffffffffffffff",
        .tag = "03000000000000000000000000000000",
    },
    .{ // #6
        .key = "02000000000000000000000000000000ffffffffffffffffffffffffffffffff",
        .msg = "02000000000000000000000000000000",
        .tag = "03000000000000000000000000000000",
    },
    .{ // #7
        .key = "0100000000000000000000000000000000000000000000000000000000000000",
        .msg = "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000000000000",
        .tag = "05000000000000000000000000000000",
    },
    .{ // #8
        .key = "0100000000000000000000000000000000000000000000000000000000000000",
        .msg = "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe01010101010101010101010101010101",
        .tag = "00000000000000000000000000000000",
    },
    .{ // #9
        .key = "0200000000000000000000000000000000000000000000000000000000000000",
        .msg = "fdffffffffffffffffffffffffffffff",
        .tag = "faffffffffffffffffffffffffffffff",
    },
    .{ // #10
        .key = "0100000000000000040000000000000000000000000000000000000000000000",
        .msg = "e33594d7505e43b900000000000000003394d7505e4379cd01000000000000000000000000000000000000000000000001000000000000000000000000000000",
        .tag = "14000000000000005500000000000000",
    },
    .{ // #11
        .key = "0100000000000000040000000000000000000000000000000000000000000000",
        .msg = "e33594d7505e43b900000000000000003394d7505e4379cd010000000000000000000000000000000000000000000000",
        .tag = "13000000000000000000000000000000",
    },
};

test "RFC 8439 Appendix A.3 Poly1305 test vectors 1-11" {
    var msg_buf: [512]u8 = undefined;
    for (rfc8439_a3) |v| {
        var key: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&key, v.key);
        const msg = try std.fmt.hexToBytes(&msg_buf, v.msg);
        var expected: [16]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, v.tag);

        var tag: [16]u8 = undefined;
        Poly1305.authenticate(&key, msg, &tag);
        try std.testing.expectEqualSlices(u8, &expected, &tag);

        // Same input fed one byte at a time must produce the same tag.
        var p = Poly1305.init(&key);
        for (msg) |b| p.update(&[_]u8{b});
        var tag2: [16]u8 = undefined;
        p.final(&tag2);
        try std.testing.expectEqualSlices(u8, &expected, &tag2);
    }
}

test "Poly1305 differential test against std.crypto with random splits" {
    var prng = std.Random.DefaultPrng.init(0x9e3779b97f4a7c15);
    const rnd = prng.random();
    var msg: [700]u8 = undefined;
    var iter: usize = 0;
    while (iter < 400) : (iter += 1) {
        var key: [32]u8 = undefined;
        rnd.bytes(&key);
        // Bias some keys and messages to all-ones to hit the reduction edges.
        if (iter % 7 == 0) @memset(key[0..16], 0xff);
        const len = rnd.uintLessThan(usize, msg.len + 1);
        rnd.bytes(msg[0..len]);
        if (iter % 5 == 0) @memset(msg[0..len], 0xff);

        var expected: [16]u8 = undefined;
        std.crypto.onetimeauth.Poly1305.create(&expected, msg[0..len], &key);

        var p = Poly1305.init(&key);
        var off: usize = 0;
        while (off < len) {
            const step = @min(len - off, rnd.uintLessThan(usize, 40) + 1);
            p.update(msg[off .. off + step]);
            off += step;
        }
        var tag: [16]u8 = undefined;
        p.final(&tag);
        try std.testing.expectEqualSlices(u8, &expected, &tag);
    }
}

test "Poly1305 constant-time verify rejects every single-bit flip" {
    const a = hexToBytes("a8061dc1305136c6c22b8baf0c0127a9");
    for (0..16) |i| {
        for (0..8) |bit| {
            var b = a;
            b[i] ^= @as(u8, 1) << @intCast(bit);
            try std.testing.expect(!Poly1305.verify(&a, &b));
        }
    }
}
