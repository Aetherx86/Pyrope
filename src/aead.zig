const std = @import("std");
pub const chacha = @import("chacha20.zig");
pub const poly = @import("poly1305.zig");

pub const KEY_SIZE = chacha.CHACHA20_KEY_SIZE;
pub const NONCE_SIZE = chacha.CHACHA20_NONCE_SIZE;
pub const TAG_SIZE = poly.POLY1305_TAG_SIZE;

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

        // 1. Generate one-time Poly1305 key from ChaCha20 block 0
        const chacha_init = chacha.ChaCha20.init(key, nonce, 0);
        var first_block: [64]u8 = undefined;
        chacha_init.block(&first_block);
        var poly_key: [32]u8 = undefined;
        @memcpy(&poly_key, first_block[0..32]);

        // 2. Encrypt plaintext starting at counter = 1
        var chacha_enc = chacha.ChaCha20.init(key, nonce, 1);
        chacha_enc.xorStream(plaintext, out_ciphertext[0..plaintext.len]);

        // 3. Authenticate AAD and Ciphertext
        var p = poly.Poly1305.init(&poly_key);

        // Feed AAD
        p.update(aad);
        const pad_aad_len = (16 - (aad.len % 16)) % 16;
        if (pad_aad_len > 0) {
            var zeros: [16]u8 = undefined;
            @memset(&zeros, 0);
            p.update(zeros[0..pad_aad_len]);
        }

        // Feed Ciphertext
        p.update(out_ciphertext[0..plaintext.len]);
        const pad_ct_len = (16 - (plaintext.len % 16)) % 16;
        if (pad_ct_len > 0) {
            var zeros: [16]u8 = undefined;
            @memset(&zeros, 0);
            p.update(zeros[0..pad_ct_len]);
        }

        // Feed lengths (u64 little-endian)
        var len_buf: [16]u8 = undefined;
        std.mem.writeInt(u64, len_buf[0..8], @as(u64, @intCast(aad.len)), .little);
        std.mem.writeInt(u64, len_buf[8..16], @as(u64, @intCast(plaintext.len)), .little);
        p.update(&len_buf);

        p.final(out_tag);
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

        // 1. Generate one-time Poly1305 key from ChaCha20 block 0
        const chacha_init = chacha.ChaCha20.init(key, nonce, 0);
        var first_block: [64]u8 = undefined;
        chacha_init.block(&first_block);
        var poly_key: [32]u8 = undefined;
        @memcpy(&poly_key, first_block[0..32]);

        // 2. Verify Tag before decryption
        var p = poly.Poly1305.init(&poly_key);

        p.update(aad);
        const pad_aad_len = (16 - (aad.len % 16)) % 16;
        if (pad_aad_len > 0) {
            var zeros: [16]u8 = undefined;
            @memset(&zeros, 0);
            p.update(zeros[0..pad_aad_len]);
        }

        p.update(ciphertext);
        const pad_ct_len = (16 - (ciphertext.len % 16)) % 16;
        if (pad_ct_len > 0) {
            var zeros: [16]u8 = undefined;
            @memset(&zeros, 0);
            p.update(zeros[0..pad_ct_len]);
        }

        var len_buf: [16]u8 = undefined;
        std.mem.writeInt(u64, len_buf[0..8], @as(u64, @intCast(aad.len)), .little);
        std.mem.writeInt(u64, len_buf[8..16], @as(u64, @intCast(ciphertext.len)), .little);
        p.update(&len_buf);

        var computed_tag: [TAG_SIZE]u8 = undefined;
        p.final(&computed_tag);

        if (!poly.Poly1305.verify(&computed_tag, tag)) {
            return error.AuthenticationFailed;
        }

        // 3. Decrypt ciphertext starting at counter = 1
        var chacha_dec = chacha.ChaCha20.init(key, nonce, 1);
        chacha_dec.xorStream(ciphertext, out_plaintext[0..ciphertext.len]);
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
