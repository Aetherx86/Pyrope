# Changelog

All notable changes to this project will be documented in this file.

## 0.1.0 - 2026-11-08

### Added
- Initial release of Pyrope constant-time WireGuard and ChaCha20-Poly1305 tunneling engine.
- Constant-time ChaCha20 stream cipher with wrapping arithmetic (+%, -%, *%).
- Constant-time Poly1305 one-time MAC with 130-bit modular arithmetic (2^130 - 5).
- RFC 8439 ChaCha20-Poly1305 authenticated encryption with associated data (AEAD).
- Curve25519 (X25519) Montgomery ladder Diffie-Hellman key exchange with branchless conditional swaps.
- WireGuard Type 4 transport packet encapsulation and decapsulation framing with zero runtime allocations.
