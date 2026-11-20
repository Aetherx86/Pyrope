# Pyrope

Constant-Time WireGuard / ChaCha20-Poly1305 Tunnel

A standalone, zero-dependency cryptographic tunneling engine implementing RFC 8439 ChaCha20-Poly1305 AEAD, XChaCha20-Poly1305, Curve25519 (X25519) ECDH, BLAKE2s, the WireGuard Noise_IKpsk2 handshake and WireGuard transport framing, written in Zig.

## Architecture

- Constant-Time Cryptography: Branchless quarter-round transformations and conditional field swaps (`cswap`) eliminate cache-timing side channels.
- Wrapping Arithmetic: Strict wrapping arithmetic operators (`+%`, `-%`, `*%`) guarantee standard modular operations without undefined behavior or compiler panics.
- Full RFC Test Vector Coverage: Validated bit-for-bit against official test vectors in RFC 8439 (ChaCha20, Poly1305, AEAD), RFC 7748 (X25519), RFC 7693 (BLAKE2s) and draft-irtf-cfrg-xchacha (HChaCha20, XChaCha20-Poly1305).
- WireGuard Handshake: Noise_IKpsk2 initiator and responder with MAC1/MAC2 cookie handling, RFC 6479 replay window and timer state machine.
- WireGuard Protocol Framing: Direct serialization and parsing of WireGuard Type 4 data transport packets with 64-bit nonce counters and 16-byte authentication tags.
- Zero Allocations: Operates entirely over stack-allocated buffers and caller-provided memory, making it suitable for bare-metal kernels and high-throughput userspace routers.

## WireGuard Transport Packet Layout

```
+-------------------------------------------------------------+
| Type (4B: 0x04) | Receiver Index (4B) | Counter Nonce (8B)  |
+-------------------------------------------------------------+
| Encrypted Payload (Plaintext size)                          |
+-------------------------------------------------------------+
| Poly1305 Authentication Tag (16B)                           |
+-------------------------------------------------------------+
```

## CLI Usage

```bash
# WireGuard-style base64 keys
pyrope genkey > private.key
pyrope pubkey < private.key

# Keypair in hex (random, clamped)
pyrope keygen

# Loopback handshake, cookie and transport self-test (exit status 0 on success)
pyrope selftest
pyrope selftest --json

# AEAD throughput and handshake rate, human-readable or JSON
pyrope bench 64
pyrope bench 16 --json
```

## C-ABI Export Symbols

```c
void pyrope_x25519(const uint8_t* scalar, const uint8_t* point, uint8_t* out);
void pyrope_aead_encrypt(const uint8_t* key, const uint8_t* nonce, const uint8_t* aad, size_t aad_len, const uint8_t* pt, size_t pt_len, uint8_t* out_ct, uint8_t* out_tag);
int32_t pyrope_aead_decrypt(const uint8_t* key, const uint8_t* nonce, const uint8_t* aad, size_t aad_len, const uint8_t* ct, size_t ct_len, const uint8_t* tag, uint8_t* out_pt);

/* Added in 0.2.0 */
int32_t pyrope_x25519_public_key(const uint8_t* private_key, uint8_t* out_public);
void pyrope_xaead_encrypt(const uint8_t* key, const uint8_t* nonce24, const uint8_t* aad, size_t aad_len, const uint8_t* pt, size_t pt_len, uint8_t* out_ct, uint8_t* out_tag);
int32_t pyrope_xaead_decrypt(const uint8_t* key, const uint8_t* nonce24, const uint8_t* aad, size_t aad_len, const uint8_t* ct, size_t ct_len, const uint8_t* tag, uint8_t* out_pt);
```

The decrypt functions return 0 on success and -1 when authentication fails, in which case no plaintext is written.

## 0.2.0: Handshake, Sessions and Hardened Field Arithmetic

### Constant-time Poly1305 and X25519

Version 0.1.0 computed Poly1305 and X25519 with `u256`/`u512` integers and the `%` operator, which compiles to a variable-time wide division. Both are now limb-based:

- Poly1305 uses 44/44/42-bit limbs with 64x64->128-bit products and a masked final reduction (poly1305-donna style).
- X25519 uses radix-2^51 field elements, a mask-based conditional swap, and inversion by a fixed addition chain. It also ignores bit 255 of the input u-coordinate as RFC 7748 requires; 0.1.0 did not, and so produced wrong results for the second RFC 7748 Section 5.2 vector.
- `Curve25519.sharedSecret` rejects the all-zero output from small-order points.

These primitives are checked against RFC 8439 Sections 2.3.2, 2.4.2, 2.5.2 and 2.8.2, Appendix A.3 vectors #1 to #11, and Appendix A.5. They are also checked against RFC 7748 Section 5.2 (both function vectors, and the 1- and 1000-iteration results) and Section 6.1, and against `std.crypto` in randomized differential tests. AEAD throughput rose from about 42 MB/s to about 565 MB/s on the development machine (Apple silicon, ReleaseFast).

### New modules

| Module | Contents |
|---|---|
| `src/blake2s.zig` | BLAKE2s (RFC 7693) with 1 to 32 byte digests and keys, HMAC-BLAKE2s, and the WireGuard `KDF1/2/3`. Verified with the RFC 7693 Appendix B vector and the Appendix E self-test grand hash. |
| `src/aead.zig` | `XChaCha20Poly1305` (HChaCha20 subkey plus 24-byte nonce), verified with the draft-irtf-cfrg-xchacha HChaCha20 and AEAD vectors. |
| `src/noise.zig` | Complete Noise_IKpsk2 initiator and responder: initiation (148 bytes), response (92 bytes), transport key derivation, optional pre-shared key, TAI64N replay protection, initiation flood limit (50 per second), mac1 checked before any Diffie-Hellman, and cookie replies (64 bytes, XChaCha20-Poly1305) with mac2 generation and verification. Randomness and time are passed in by the caller. |
| `src/replay.zig` | RFC 6479 sliding-window replay filter (128 x 64-bit ring, 8128-counter window), updated only after authentication. |
| `src/session.zig` | Transport sessions: zero-padding to 16 bytes (capped at the MTU), IPv4/IPv6 length recovery, a key-confirmation rule (the responder cannot send before it receives), and REKEY/REJECT limits on age and message count. Also WireGuard timers (keepalive, new handshake, retransmit with jitter, give up after 90 s, zero keys after 540 s, persistent keepalive) driven by an injectable `Clock` (`ManualClock` for tests, `IoClock` for real time). |
| `src/selftest.zig` | The in-memory loopback scenario behind `pyrope selftest`. |

### Handshake known-answer vectors

There are no official WireGuard handshake test vectors, so `tools/wireguard_kat.py` is an independent reference. It uses pure-Python X25519, ChaCha20-Poly1305 and HChaCha20 written from the RFC pseudocode, plus `hashlib` BLAKE2s and `hmac`, and validates those primitives against the published RFC vectors before it runs. It generates a fixed transcript in `src/noise_kat.zig`: initiation, response, transport keys, the first data packet, a cookie reply, and a retry that carries mac2. The Zig implementation must reproduce that transcript byte for byte. CI regenerates the transcript and fails if it differs:

```bash
python3 tools/wireguard_kat.py --check
```

Note that `keygen` printed a fixed private key in 0.1.0. It now uses the operating system's secure random source.

## Building and Testing

```bash
# Run test suite (46 tests)
zig build test

# Regenerate and compare the handshake known-answer transcript
python3 tools/wireguard_kat.py --check

# Compile optimized release binary and shared library
zig build -Doptimize=ReleaseFast
```

## License

MIT License - Copyright (c) 2026 Jeong Hoon Kim
