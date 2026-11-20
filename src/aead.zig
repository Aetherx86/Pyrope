const std = @import("std");
pub const chacha = @import("chacha20.zig");
pub const poly = @import("poly1305.zig");

pub const KEY_SIZE = chacha.CHACHA20_KEY_SIZE;
pub const NONCE_SIZE = chacha.CHACHA20_NONCE_SIZE;
pub const TAG_SIZE = poly.POLY1305_TAG_SIZE;

pub const XNONCE_SIZE: usize = 24;

/// Computes the RFC 8439 Section 2.8 Poly1305 tag over
/// aad || pad16 || ciphertext || pad16 || le64(aad.len) || le64(ct.len).
fn computeTag(
    key: *const [KEY_SIZE]u8,
    nonce: *const [NONCE_SIZE]u8,
    aad: []const u8,
    ciphertext: []const u8,
    out_tag: *[TAG_SIZE]u8,
) void {
    // One-time Poly1305 key from ChaCha20 block 0.
    const chacha_init = chacha.ChaCha20.init(key, nonce, 0);
    var first_block: [64]u8 = undefined;
    chacha_init.block(&first_block);
    var poly_key: [32]u8 = undefined;
    @memcpy(&poly_key, first_block[0..32]);
    std.crypto.secureZero(u8, &first_block);

    const zeros: [16]u8 = @splat(0);
    var p = poly.Poly1305.init(&poly_key);
    p.update(aad);
    p.update(zeros[0 .. (16 - (aad.len % 16)) % 16]);
    p.update(ciphertext);
    p.update(zeros[0 .. (16 - (ciphertext.len % 16)) % 16]);

    var len_buf: [16]u8 = undefined;
    std.mem.writeInt(u64, len_buf[0..8], @as(u64, @intCast(aad.len)), .little);
    std.mem.writeInt(u64, len_buf[8..16], @as(u64, @intCast(ciphertext.len)), .little);
    p.update(&len_buf);
    p.final(out_tag);
    std.crypto.secureZero(u8, &poly_key);
}

pub const ChaCha20Poly1305 = struct {
    pub fn encrypt(
        key: *const [KEY_SIZE]u8,
        nonce: *const [NONCE_SIZE]u8,
        aad: []const u8,
        plaintext: []const u8,
        out_ciphertext: []u8,
        out_tag: *[TAG_SIZE]u8,
    ) void {
        std.debug.assert(out_ciphertext.len >= plaintext.len);

        // Encrypt plaintext starting at counter = 1, then authenticate.
        var chacha_enc = chacha.ChaCha20.init(key, nonce, 1);
        chacha_enc.xorStream(plaintext, out_ciphertext[0..plaintext.len]);
        computeTag(key, nonce, aad, out_ciphertext[0..plaintext.len], out_tag);
    }

    pub fn decrypt(
        key: *const [KEY_SIZE]u8,
        nonce: *const [NONCE_SIZE]u8,
        aad: []const u8,
        ciphertext: []const u8,
        tag: *const [TAG_SIZE]u8,
        out_plaintext: []u8,
    ) !void {
        std.debug.assert(out_plaintext.len >= ciphertext.len);

        // Verify the tag (constant-time comparison) before decrypting.
        var computed_tag: [TAG_SIZE]u8 = undefined;
        computeTag(key, nonce, aad, ciphertext, &computed_tag);
        if (!poly.Poly1305.verify(&computed_tag, tag)) {
            return error.AuthenticationFailed;
        }

        var chacha_dec = chacha.ChaCha20.init(key, nonce, 1);
        chacha_dec.xorStream(ciphertext, out_plaintext[0..ciphertext.len]);
    }
};

/// XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03): a 24-byte nonce variant.
/// The subkey is HChaCha20(key, nonce[0..16]) and the inner ChaCha20-Poly1305
/// nonce is 4 zero bytes followed by nonce[16..24]. WireGuard uses it to
/// encrypt cookie replies.
pub const XChaCha20Poly1305 = struct {
    fn derive(key: *const [KEY_SIZE]u8, nonce: *const [XNONCE_SIZE]u8, subkey: *[KEY_SIZE]u8, inner: *[NONCE_SIZE]u8) void {
        subkey.* = chacha.hchacha20(key, nonce[0..16]);
        @memset(inner[0..4], 0);
        @memcpy(inner[4..12], nonce[16..24]);
    }

    pub fn encrypt(
        key: *const [KEY_SIZE]u8,
        nonce: *const [XNONCE_SIZE]u8,
        aad: []const u8,
        plaintext: []const u8,
        out_ciphertext: []u8,
        out_tag: *[TAG_SIZE]u8,
    ) void {
        var subkey: [KEY_SIZE]u8 = undefined;
        var inner: [NONCE_SIZE]u8 = undefined;
        derive(key, nonce, &subkey, &inner);
        defer std.crypto.secureZero(u8, &subkey);
        ChaCha20Poly1305.encrypt(&subkey, &inner, aad, plaintext, out_ciphertext, out_tag);
    }

    pub fn decrypt(
        key: *const [KEY_SIZE]u8,
        nonce: *const [XNONCE_SIZE]u8,
        aad: []const u8,
        ciphertext: []const u8,
        tag: *const [TAG_SIZE]u8,
        out_plaintext: []u8,
    ) !void {
        var subkey: [KEY_SIZE]u8 = undefined;
        var inner: [NONCE_SIZE]u8 = undefined;
        derive(key, nonce, &subkey, &inner);
        defer std.crypto.secureZero(u8, &subkey);
        try ChaCha20Poly1305.decrypt(&subkey, &inner, aad, ciphertext, tag, out_plaintext);
    }
};

test "RFC 8439 Section 2.8.2 AEAD Test Vector" {
    const key = [32]u8{
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    const nonce = [12]u8{
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47,
    };
    const aad = [12]u8{
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7,
    };
    const plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    var ct: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    ChaCha20Poly1305.encrypt(&key, &nonce, &aad, plaintext, &ct, &tag);

    const expected_tag = [16]u8{
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    };
    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);

    // Decrypt and verify
    var decrypted: [plaintext.len]u8 = undefined;
    try ChaCha20Poly1305.decrypt(&key, &nonce, &aad, &ct, &tag, &decrypted);
    try std.testing.expectEqualStrings(plaintext, &decrypted);

    // Tampered tag must fail authentication
    var bad_tag = tag;
    bad_tag[0] ^= 0x01;
    const err = ChaCha20Poly1305.decrypt(&key, &nonce, &aad, &ct, &bad_tag, &decrypted);
    try std.testing.expectError(error.AuthenticationFailed, err);
}

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

const sunscreen = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

test "RFC 8439 Section 2.8.2 AEAD full ciphertext" {
    const key = hexToBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const nonce = hexToBytes("070000004041424344454647");
    const aad = hexToBytes("50515253c0c1c2c3c4c5c6c7");
    var ct: [sunscreen.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    ChaCha20Poly1305.encrypt(&key, &nonce, &aad, sunscreen, &ct, &tag);
    try std.testing.expectEqualSlices(u8, &hexToBytes(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" ++
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" ++
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" ++
            "3ff4def08e4b7a9de576d26586cec64b6116",
    ), &ct);
    try std.testing.expectEqualSlices(u8, &hexToBytes("1ae10b594f09e26a7e902ecbd0600691"), &tag);
}

test "RFC 8439 Appendix A.5 AEAD decryption" {
    const key = hexToBytes("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");
    const nonce = hexToBytes("000000000102030405060708");
    const aad = hexToBytes("f33388860000000000004e91");
    const ct = hexToBytes(
        "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2" ++
            "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf" ++
            "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855" ++
            "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4" ++
            "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e" ++
            "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a" ++
            "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10" ++
            "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29" ++
            "a6ad5cb4022b02709b",
    );
    const tag = hexToBytes("eead9d67890cbb22392336fea1851f38");
    var pt: [ct.len]u8 = undefined;
    try ChaCha20Poly1305.decrypt(&key, &nonce, &aad, &ct, &tag, &pt);
    try std.testing.expect(std.mem.startsWith(u8, &pt, "Internet-Drafts are draft documents valid for a maximum of six months"));
    try std.testing.expect(std.mem.endsWith(u8, &pt, "/\xe2\x80\x9cwork in progress.\x2f\xe2\x80\x9d"));
}

test "draft-irtf-cfrg-xchacha Appendix A.3.1 XChaCha20-Poly1305 vector" {
    const key = hexToBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const nonce = hexToBytes("404142434445464748494a4b4c4d4e4f5051525354555657");
    const aad = hexToBytes("50515253c0c1c2c3c4c5c6c7");
    var ct: [sunscreen.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    XChaCha20Poly1305.encrypt(&key, &nonce, &aad, sunscreen, &ct, &tag);
    try std.testing.expectEqualSlices(u8, &hexToBytes(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" ++
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" ++
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" ++
            "21f9664c97637da9768812f615c68b13b52e",
    ), &ct);
    try std.testing.expectEqualSlices(u8, &hexToBytes("c0875924c1c7987947deafd8780acf49"), &tag);

    var pt: [sunscreen.len]u8 = undefined;
    try XChaCha20Poly1305.decrypt(&key, &nonce, &aad, &ct, &tag, &pt);
    try std.testing.expectEqualStrings(sunscreen, &pt);
    var bad_nonce = nonce;
    bad_nonce[23] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, XChaCha20Poly1305.decrypt(&key, &bad_nonce, &aad, &ct, &tag, &pt));
}

test "AEAD differential test against std.crypto (both variants) and tamper rejection" {
    var prng = std.Random.DefaultPrng.init(0xaead);
    const rnd = prng.random();
    var pt: [600]u8 = undefined;
    var aad: [80]u8 = undefined;
    var ct: [600]u8 = undefined;
    var ct2: [600]u8 = undefined;
    var back: [600]u8 = undefined;
    for (0..150) |i| {
        var key: [32]u8 = undefined;
        var nonce: [12]u8 = undefined;
        var xnonce: [24]u8 = undefined;
        rnd.bytes(&key);
        rnd.bytes(&nonce);
        rnd.bytes(&xnonce);
        const len = rnd.uintLessThan(usize, pt.len + 1);
        const alen = rnd.uintLessThan(usize, aad.len + 1);
        rnd.bytes(pt[0..len]);
        rnd.bytes(aad[0..alen]);

        var tag: [16]u8 = undefined;
        var tag2: [16]u8 = undefined;
        ChaCha20Poly1305.encrypt(&key, &nonce, aad[0..alen], pt[0..len], &ct, &tag);
        std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(ct2[0..len], &tag2, pt[0..len], aad[0..alen], nonce, key);
        try std.testing.expectEqualSlices(u8, ct2[0..len], ct[0..len]);
        try std.testing.expectEqualSlices(u8, &tag2, &tag);

        XChaCha20Poly1305.encrypt(&key, &xnonce, aad[0..alen], pt[0..len], &ct, &tag);
        std.crypto.aead.chacha_poly.XChaCha20Poly1305.encrypt(ct2[0..len], &tag2, pt[0..len], aad[0..alen], xnonce, key);
        try std.testing.expectEqualSlices(u8, ct2[0..len], ct[0..len]);
        try std.testing.expectEqualSlices(u8, &tag2, &tag);

        // Flip one bit of ciphertext, AAD or tag: decryption must fail.
        var bad_tag = tag;
        switch (i % 3) {
            0 => if (len > 0) {
                ct[rnd.uintLessThan(usize, len)] ^= 0x80;
            } else {
                bad_tag[0] ^= 1;
            },
            1 => if (alen > 0) {
                aad[rnd.uintLessThan(usize, alen)] ^= 0x01;
            } else {
                bad_tag[15] ^= 0x80;
            },
            else => bad_tag[rnd.uintLessThan(usize, 16)] ^= 0x10,
        }
        try std.testing.expectError(error.AuthenticationFailed, XChaCha20Poly1305.decrypt(&key, &xnonce, aad[0..alen], ct[0..len], &bad_tag, &back));
    }
}
