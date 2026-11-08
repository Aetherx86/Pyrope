# Pyrope

Constant-Time WireGuard / ChaCha20-Poly1305 Tunnel

A standalone, zero-dependency cryptographic tunneling engine implementing RFC 8439 ChaCha20-Poly1305 AEAD, Curve25519 (X25519) ECDH, and WireGuard protocol packet framing, written in Zig.

## Architecture

- Constant-Time Cryptography: Branchless quarter-round transformations and conditional field swaps (`cswap`) eliminate cache-timing side channels.
- Wrapping Arithmetic: Strict wrapping arithmetic operators (`+%`, `-%`, `*%`) guarantee standard modular operations without undefined behavior or compiler panics.
- Full RFC Test Vector Coverage: Validated bit-for-bit against official test vectors in RFC 8439 (ChaCha20, Poly1305, AEAD) and RFC 7748 (X25519).
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
# Generate Curve25519 keypair
pyrope keygen

# Run ChaCha20-Poly1305 AEAD throughput benchmark
pyrope bench 50
```

## C-ABI Export Symbols

```c
void pyrope_x25519(const uint8_t* scalar, const uint8_t* point, uint8_t* out);
void pyrope_aead_encrypt(const uint8_t* key, const uint8_t* nonce, const uint8_t* aad, size_t aad_len, const uint8_t* pt, size_t pt_len, uint8_t* out_ct, uint8_t* out_tag);
int32_t pyrope_aead_decrypt(const uint8_t* key, const uint8_t* nonce, const uint8_t* aad, size_t aad_len, const uint8_t* ct, size_t ct_len, const uint8_t* tag, uint8_t* out_pt);
```

## Building and Testing

```bash
# Run test suite
zig build test

# Compile optimized release binary and shared library
zig build -Doptimize=ReleaseFast
```

## License

MIT License - Copyright (c) 2026 Jeong Hoon Kim
