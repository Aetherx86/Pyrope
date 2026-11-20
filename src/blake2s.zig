const std = @import("std");

pub const BLOCK_SIZE: usize = 64;
pub const MAX_OUT: usize = 32;
pub const MAX_KEY: usize = 32;

const IV = [8]u32{
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

const SIGMA = [10][16]u8{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    .{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    .{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

/// BLAKE2s (RFC 7693) with 1..32 byte digests and optional 0..32 byte key.
/// The message schedule indices are compile-time constants, so the
/// compression function has no data-dependent branches or memory accesses.
pub const Blake2s = struct {
    h: [8]u32,
    t: u64,
    buf: [BLOCK_SIZE]u8,
    buf_len: usize,
    out_len: usize,

    pub fn init(out_len: usize, key: []const u8) Blake2s {
        std.debug.assert(out_len >= 1 and out_len <= MAX_OUT);
        std.debug.assert(key.len <= MAX_KEY);
        var s = Blake2s{
            .h = IV,
            .t = 0,
            .buf = @splat(0),
            .buf_len = 0,
            .out_len = out_len,
        };
        s.h[0] ^= 0x01010000 ^ (@as(u32, @intCast(key.len)) << 8) ^ @as(u32, @intCast(out_len));
        if (key.len > 0) {
            @memcpy(s.buf[0..key.len], key);
            s.buf_len = BLOCK_SIZE;
        }
        return s;
    }

    inline fn g(v: *[16]u32, comptime a: usize, comptime b: usize, comptime c: usize, comptime d: usize, x: u32, y: u32) void {
        v[a] = v[a] +% v[b] +% x;
        v[d] = std.math.rotr(u32, v[d] ^ v[a], 16);
        v[c] = v[c] +% v[d];
        v[b] = std.math.rotr(u32, v[b] ^ v[c], 12);
        v[a] = v[a] +% v[b] +% y;
        v[d] = std.math.rotr(u32, v[d] ^ v[a], 8);
        v[c] = v[c] +% v[d];
        v[b] = std.math.rotr(u32, v[b] ^ v[c], 7);
    }

    fn compress(self: *Blake2s, block: *const [BLOCK_SIZE]u8, last: bool) void {
        var mw: [16]u32 = undefined;
        for (0..16) |i| mw[i] = std.mem.readInt(u32, block[i * 4 ..][0..4], .little);

        var v: [16]u32 = undefined;
        @memcpy(v[0..8], &self.h);
        @memcpy(v[8..16], &IV);
        v[12] ^= @truncate(self.t);
        v[13] ^= @truncate(self.t >> 32);
        if (last) v[14] = ~v[14];

        inline for (0..10) |r| {
            const s = SIGMA[r];
            g(&v, 0, 4, 8, 12, mw[s[0]], mw[s[1]]);
            g(&v, 1, 5, 9, 13, mw[s[2]], mw[s[3]]);
            g(&v, 2, 6, 10, 14, mw[s[4]], mw[s[5]]);
            g(&v, 3, 7, 11, 15, mw[s[6]], mw[s[7]]);
            g(&v, 0, 5, 10, 15, mw[s[8]], mw[s[9]]);
            g(&v, 1, 6, 11, 12, mw[s[10]], mw[s[11]]);
            g(&v, 2, 7, 8, 13, mw[s[12]], mw[s[13]]);
            g(&v, 3, 4, 9, 14, mw[s[14]], mw[s[15]]);
        }

        for (0..8) |i| self.h[i] ^= v[i] ^ v[i + 8];
    }

    pub fn update(self: *Blake2s, data: []const u8) void {
        var in = data;
        while (in.len > 0) {
            // Only compress a full buffer once more input is known to follow,
            // so the final block is always processed by `final`.
            if (self.buf_len == BLOCK_SIZE) {
                self.t += BLOCK_SIZE;
                self.compress(&self.buf, false);
                self.buf_len = 0;
            }
            const take = @min(BLOCK_SIZE - self.buf_len, in.len);
            @memcpy(self.buf[self.buf_len .. self.buf_len + take], in[0..take]);
            self.buf_len += take;
            in = in[take..];
        }
    }

    pub fn final(self: *Blake2s, out: []u8) void {
        std.debug.assert(out.len >= self.out_len);
        self.t += self.buf_len;
        @memset(self.buf[self.buf_len..], 0);
        self.compress(&self.buf, true);
        var full: [32]u8 = undefined;
        for (0..8) |i| std.mem.writeInt(u32, full[i * 4 ..][0..4], self.h[i], .little);
        @memcpy(out[0..self.out_len], full[0..self.out_len]);
        std.crypto.secureZero(u8, &full);
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    /// One-shot BLAKE2s with `out.len` digest bytes.
    pub fn hash(out: []u8, key: []const u8, data: []const u8) void {
        var s = init(out.len, key);
        s.update(data);
        s.final(out);
    }
};

/// WireGuard HASH(x): unkeyed BLAKE2s-256.
pub fn hash(parts: []const []const u8) [32]u8 {
    var s = Blake2s.init(32, "");
    for (parts) |p| s.update(p);
    var out: [32]u8 = undefined;
    s.final(&out);
    return out;
}

/// WireGuard MAC(key, input): keyed BLAKE2s with a 16-byte digest.
pub fn mac(key: []const u8, data: []const u8) [16]u8 {
    var out: [16]u8 = undefined;
    Blake2s.hash(&out, key, data);
    return out;
}

/// HMAC (RFC 2104) instantiated with BLAKE2s-256 and a 64-byte block.
pub fn hmac(key: []const u8, parts: []const []const u8) [32]u8 {
    var k: [BLOCK_SIZE]u8 = @splat(0);
    if (key.len > BLOCK_SIZE) {
        Blake2s.hash(k[0..32], "", key);
    } else {
        @memcpy(k[0..key.len], key);
    }
    var ipad: [BLOCK_SIZE]u8 = undefined;
    var opad: [BLOCK_SIZE]u8 = undefined;
    for (0..BLOCK_SIZE) |i| {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    var inner = Blake2s.init(32, "");
    inner.update(&ipad);
    for (parts) |p| inner.update(p);
    var ih: [32]u8 = undefined;
    inner.final(&ih);

    var outer = Blake2s.init(32, "");
    outer.update(&opad);
    outer.update(&ih);
    var out: [32]u8 = undefined;
    outer.final(&out);

    std.crypto.secureZero(u8, &k);
    std.crypto.secureZero(u8, &ipad);
    std.crypto.secureZero(u8, &opad);
    std.crypto.secureZero(u8, &ih);
    return out;
}

/// WireGuard KDF_n(key, input) for n = 1..3 (HKDF with HMAC-BLAKE2s).
pub fn kdf(comptime n: usize, key: *const [32]u8, input: []const u8) [n][32]u8 {
    comptime std.debug.assert(n >= 1 and n <= 3);
    var prk = hmac(key, &.{input});
    defer std.crypto.secureZero(u8, &prk);
    var out: [n][32]u8 = undefined;
    out[0] = hmac(&prk, &.{&[_]u8{1}});
    if (n >= 2) out[1] = hmac(&prk, &.{ &out[0], &[_]u8{2} });
    if (n >= 3) out[2] = hmac(&prk, &.{ &out[1], &[_]u8{3} });
    return out;
}

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "RFC 7693 Appendix B BLAKE2s-256(\"abc\")" {
    var out: [32]u8 = undefined;
    Blake2s.hash(&out, "", "abc");
    try std.testing.expectEqualSlices(u8, &hexToBytes("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"), &out);
}

fn selftestSeq(out: []u8, seed: u32) void {
    var a: u32 = 0xDEAD4BAD *% seed;
    var b: u32 = 1;
    for (out) |*o| {
        const t = a +% b;
        a = b;
        b = t;
        o.* = @truncate(t >> 24);
    }
}

test "RFC 7693 Appendix E BLAKE2s self-test grand hash (keyed and unkeyed)" {
    const md_lens = [_]usize{ 16, 20, 28, 32 };
    const in_lens = [_]usize{ 0, 3, 64, 65, 255, 1024 };
    var in: [1024]u8 = undefined;
    var md: [32]u8 = undefined;
    var key: [32]u8 = undefined;
    var grand = Blake2s.init(32, "");
    for (md_lens) |outlen| {
        for (in_lens) |inlen| {
            selftestSeq(in[0..inlen], @intCast(inlen));
            Blake2s.hash(md[0..outlen], "", in[0..inlen]);
            grand.update(md[0..outlen]);
            selftestSeq(key[0..outlen], @intCast(outlen));
            Blake2s.hash(md[0..outlen], key[0..outlen], in[0..inlen]);
            grand.update(md[0..outlen]);
        }
    }
    grand.final(&md);
    try std.testing.expectEqualSlices(u8, &hexToBytes("6a411f08ce25adcdfb02aba641451cec53c598b24f4fc787fbdc88797f4c1dfe"), &md);
}

test "BLAKE2s differential test against std.crypto with random keys, lengths and splits" {
    var prng = std.Random.DefaultPrng.init(0xb1a2e5);
    const rnd = prng.random();
    var data: [700]u8 = undefined;
    for (0..300) |_| {
        const outlen = rnd.intRangeAtMost(usize, 1, 32);
        const keylen = rnd.uintLessThan(usize, 33);
        const len = rnd.uintLessThan(usize, data.len + 1);
        var key: [32]u8 = undefined;
        rnd.bytes(&key);
        rnd.bytes(data[0..len]);

        var expected: [32]u8 = undefined;
        var ref = std.crypto.hash.blake2.Blake2s256.init(.{ .key = key[0..keylen], .expected_out_bits = outlen * 8 });
        ref.update(data[0..len]);
        ref.final(&expected);

        var s = Blake2s.init(outlen, key[0..keylen]);
        var off: usize = 0;
        while (off < len) {
            const step = @min(len - off, rnd.uintLessThan(usize, 130) + 1);
            s.update(data[off .. off + step]);
            off += step;
        }
        var out: [32]u8 = undefined;
        s.final(&out);
        try std.testing.expectEqualSlices(u8, expected[0..outlen], out[0..outlen]);
    }
}

test "HMAC-BLAKE2s differential test against std.crypto.auth.hmac" {
    const Ref = std.crypto.auth.hmac.Hmac(std.crypto.hash.blake2.Blake2s256);
    var prng = std.Random.DefaultPrng.init(0x4d4143);
    const rnd = prng.random();
    var key: [100]u8 = undefined;
    var msg: [300]u8 = undefined;
    for (0..100) |_| {
        const klen = rnd.uintLessThan(usize, key.len + 1);
        const mlen = rnd.uintLessThan(usize, msg.len + 1);
        rnd.bytes(key[0..klen]);
        rnd.bytes(msg[0..mlen]);
        var expected: [32]u8 = undefined;
        Ref.create(&expected, msg[0..mlen], key[0..klen]);
        const split = rnd.uintLessThan(usize, mlen + 1);
        const got = hmac(key[0..klen], &.{ msg[0..split], msg[split..mlen] });
        try std.testing.expectEqualSlices(u8, &expected, &got);
    }
}

test "WireGuard construction constants: initial chaining key and hash" {
    // Hash("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s") and
    // Hash(chaining_key || "WireGuard v1 zx2c4 Jason@zx2c4.com"), as hard-coded
    // in the Linux kernel and wireguard-go implementations.
    const ck = hash(&.{"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"});
    try std.testing.expectEqualSlices(u8, &hexToBytes("60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36"), &ck);
    const h = hash(&.{ &ck, "WireGuard v1 zx2c4 Jason@zx2c4.com" });
    try std.testing.expectEqualSlices(u8, &hexToBytes("2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3"), &h);
}

test "KDF chain is consistent with HMAC definition" {
    const key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const out = kdf(3, &key, "input");
    const prk = hmac(&key, &.{"input"});
    try std.testing.expectEqualSlices(u8, &hmac(&prk, &.{"\x01"}), &out[0]);
    try std.testing.expectEqualSlices(u8, &hmac(&prk, &.{ &out[0], "\x02" }), &out[1]);
    try std.testing.expectEqualSlices(u8, &hmac(&prk, &.{ &out[1], "\x03" }), &out[2]);
    const two = kdf(2, &key, "input");
    try std.testing.expectEqualSlices(u8, &out[0], &two[0]);
    try std.testing.expectEqualSlices(u8, &out[1], &two[1]);
}
