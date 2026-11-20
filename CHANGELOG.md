# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-11-21

### Security
- Poly1305 now uses 44-bit limb arithmetic and X25519 uses radix-2^51 field arithmetic. Both replace `u256`/`u512` modulo operations, which compiled to variable-time wide division. Neither has a secret-dependent branch or memory index.
- X25519 now ignores bit 255 of the u-coordinate (RFC 7748 Section 5). The previous version computed a wrong result for the second RFC 7748 Section 5.2 vector.
- `keygen` now draws its private key from the operating system's secure random source; it previously printed a fixed key.
- Intermediate secrets (one-time Poly1305 keys, HKDF state, ephemeral keys, handshake chaining keys) are wiped after use.

### Added
- BLAKE2s (RFC 7693), HMAC-BLAKE2s and the WireGuard KDF.
- HChaCha20 and XChaCha20-Poly1305, with C-ABI exports `pyrope_xaead_encrypt` and `pyrope_xaead_decrypt`, and `pyrope_x25519_public_key`.
- Complete WireGuard Noise_IKpsk2 initiator and responder (`src/noise.zig`): optional pre-shared key, TAI64N timestamp replay protection, initiation flood limit, mac1 checked before any Diffie-Hellman, and cookie replies with mac2.
- RFC 6479 sliding-window replay filter (`src/replay.zig`).
- Transport sessions with padding, key confirmation and REKEY/REJECT limits, plus WireGuard timers driven by an injectable clock (`src/session.zig`).
- CLI commands: `genkey`, `pubkey`, `selftest [--json]`, and `bench [megabytes] [--json]`. The benchmark now covers seal, open, XChaCha, transport encryption and full handshakes per second.
- `tools/wireguard_kat.py`: an independent Python reference that generates the handshake known-answer transcript in `src/noise_kat.zig`. CI checks that the transcript is reproducible.
- Tests grew from 6 to 46. New tests cover all RFC 8439 Appendix A.3 Poly1305 vectors, the A.5 decryption vector, the RFC 7748 1000-iteration vector, the RFC 7693 self-test, and differential tests against `std.crypto`.

### Changed
- CI pins `mlugg/setup-zig` to v2.2.1 by full commit SHA, and adds steps for the transcript check, `pyrope selftest` and `zig fmt --check`.
- CLI output now goes to stdout instead of stderr.

## 0.1.0 - 2026-11-08

### Added
- Initial release of Pyrope constant-time WireGuard and ChaCha20-Poly1305 tunneling engine.
- Constant-time ChaCha20 stream cipher with wrapping arithmetic (+%, -%, *%).
- Constant-time Poly1305 one-time MAC with 130-bit modular arithmetic (2^130 - 5).
- RFC 8439 ChaCha20-Poly1305 authenticated encryption with associated data (AEAD).
- Curve25519 (X25519) Montgomery ladder Diffie-Hellman key exchange with branchless conditional swaps.
- WireGuard Type 4 transport packet encapsulation and decapsulation framing with zero runtime allocations.
