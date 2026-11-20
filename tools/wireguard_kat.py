#!/usr/bin/env python3
"""Independent reference for the WireGuard Noise_IKpsk2 handshake.

Builds a deterministic handshake transcript (initiation, response, transport
keys, a data packet, a cookie reply and a mac2-bearing retry) with fixed keys,
ephemerals, timestamps and indices, and emits it as src/noise_kat.zig.

Primitives are written from the RFC pseudocode (RFC 7748 X25519, RFC 8439
ChaCha20-Poly1305, draft-irtf-cfrg-xchacha HChaCha20) using Python integers,
and BLAKE2s/HMAC come from hashlib/hmac, so nothing is shared with the Zig
implementation under test.

Usage:
    python3 tools/wireguard_kat.py            # print the Zig file
    python3 tools/wireguard_kat.py --write    # rewrite src/noise_kat.zig
    python3 tools/wireguard_kat.py --check    # fail if src/noise_kat.zig differs
"""

import hashlib
import hmac as hmaclib
import struct
import sys
from pathlib import Path

# ---------------------------------------------------------------- X25519
P = 2**255 - 19


def x25519(k: bytes, u: bytes) -> bytes:
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    kn = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (kn >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + 121665 * e) % P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def pubkey(priv: bytes) -> bytes:
    return x25519(priv, (9).to_bytes(32, "little"))


# ---------------------------------------------------------------- ChaCha20
def rotl(v, n):
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = rotl(s[b] ^ s[c], 7)


def rounds(s):
    for _ in range(10):
        qr(s, 0, 4, 8, 12); qr(s, 1, 5, 9, 13); qr(s, 2, 6, 10, 14); qr(s, 3, 7, 11, 15)
        qr(s, 0, 5, 10, 15); qr(s, 1, 6, 11, 12); qr(s, 2, 7, 8, 13); qr(s, 3, 4, 9, 14)


CONST = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]


def chacha_block(key, counter, nonce):
    init = CONST + list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    s = list(init)
    rounds(s)
    return struct.pack("<16I", *[(x + y) & 0xFFFFFFFF for x, y in zip(s, init)])


def chacha_xor(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha_block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], ks))
    return bytes(out)


def hchacha(key, n16):
    s = CONST + list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", n16))
    rounds(s)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    acc = 0
    p = (1 << 130) - 5
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i + 16] + b"\x01", "little")
        acc = (acc + n) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def pad16(b):
    return b"\x00" * (-len(b) % 16)


def aead_enc(key, nonce12, pt, aad):
    otk = chacha_block(key, 0, nonce12)[:32]
    ct = chacha_xor(key, 1, nonce12, pt)
    mac_data = aad + pad16(aad) + ct + pad16(ct) + struct.pack("<QQ", len(aad), len(ct))
    return ct + poly1305(otk, mac_data)


def wg_aead(key, counter, pt, aad):
    return aead_enc(key, b"\x00" * 4 + struct.pack("<Q", counter), pt, aad)


def xaead(key, nonce24, pt, aad):
    return aead_enc(hchacha(key, nonce24[:16]), b"\x00" * 4 + nonce24[16:], pt, aad)


# ---------------------------------------------------------------- WireGuard
def HASH(*parts):
    return hashlib.blake2s(b"".join(parts)).digest()


def MAC(key, data):
    return hashlib.blake2s(data, digest_size=16, key=key).digest()


def HMAC(key, data):
    return hmaclib.new(key, data, hashlib.blake2s).digest()


def KDF(n, key, data):
    t0 = HMAC(key, data)
    out, prev = [], b""
    for i in range(1, n + 1):
        prev = HMAC(t0, prev + bytes([i]))
        out.append(prev)
    return out


CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"


def tai64n(sec, nsec):
    return struct.pack(">QI", 0x400000000000000A + sec, nsec)


def transcript():
    i_priv = bytes(range(0x10, 0x30))
    r_priv = bytes(range(0x40, 0x60))
    i_eph = bytes(range(0x70, 0x90))
    r_eph = bytes(range(0xA0, 0xC0))
    psk = bytes(range(0xD0, 0xF0))
    i_pub, r_pub = pubkey(i_priv), pubkey(r_priv)
    i_index, r_index = 0x11223344, 0x55667788
    ts = tai64n(1_700_000_000, 0x07000000)

    def initiation(eph, stamp, cookie=None):
        c = HASH(CONSTRUCTION)
        h = HASH(c, IDENTIFIER)
        h = HASH(h, r_pub)
        e_pub = pubkey(eph)
        (c,) = KDF(1, c, e_pub)
        h = HASH(h, e_pub)
        c, k = KDF(2, c, x25519(eph, r_pub))
        enc_static = wg_aead(k, 0, i_pub, h)
        h = HASH(h, enc_static)
        c, k = KDF(2, c, x25519(i_priv, r_pub))
        enc_ts = wg_aead(k, 0, stamp, h)
        h = HASH(h, enc_ts)
        body = struct.pack("<II", 1, i_index) + e_pub + enc_static + enc_ts
        mac1 = MAC(HASH(b"mac1----", r_pub), body)
        mac2 = MAC(cookie, body + mac1) if cookie else b"\x00" * 16
        return body + mac1 + mac2, c, h

    init_msg, c, h = initiation(i_eph, ts)

    # Responder side (continues from the initiator's c, h which both derive).
    e_pub = pubkey(r_eph)
    (c,) = KDF(1, c, e_pub)
    h = HASH(h, e_pub)
    (c,) = KDF(1, c, x25519(r_eph, pubkey(i_eph)))
    (c,) = KDF(1, c, x25519(r_eph, i_pub))
    c, tau, k = KDF(3, c, psk)
    h = HASH(h, tau)
    enc_nothing = wg_aead(k, 0, b"", h)
    h = HASH(h, enc_nothing)
    body = struct.pack("<III", 2, r_index, i_index) + e_pub + enc_nothing
    mac1 = MAC(HASH(b"mac1----", i_pub), body)
    resp_msg = body + mac1 + b"\x00" * 16

    t_send_i, t_recv_i = KDF(2, c, b"")

    payload = b"pyrop"  # padded with zeros to 16 bytes
    padded = payload + pad16(payload)
    data_msg = struct.pack("<IIQ", 4, r_index, 0) + wg_aead(t_send_i, 0, padded, b"")

    # Cookie reply from the responder to the initiation, then a retry with mac2.
    secret = bytes(range(0x01, 0x21))
    src = bytes([198, 51, 100, 7]) + struct.pack(">H", 51820)
    cookie = MAC(secret, src)
    nonce = bytes(range(0x30, 0x48))
    cookie_key = HASH(b"cookie--", r_pub)
    cookie_msg = struct.pack("<II", 3, i_index) + nonce + xaead(cookie_key, nonce, cookie, init_msg[116:132])
    retry_msg, _, _ = initiation(i_eph, tai64n(1_700_000_001, 0), cookie)

    return {
        "initiator_private": i_priv,
        "responder_private": r_priv,
        "initiator_ephemeral": i_eph,
        "responder_ephemeral": r_eph,
        "preshared_key": psk,
        "initiator_public": i_pub,
        "responder_public": r_pub,
        "timestamp": ts,
        "initiation": init_msg,
        "response": resp_msg,
        "initiator_send_key": t_send_i,
        "initiator_recv_key": t_recv_i,
        "data_packet": data_msg,
        "cookie_secret": secret,
        "cookie_source": src,
        "cookie_nonce": nonce,
        "cookie": cookie,
        "cookie_reply": cookie_msg,
        "retry_timestamp": tai64n(1_700_000_001, 0),
        "retry_initiation": retry_msg,
    }


def render(t):
    lines = [
        "// Generated by tools/wireguard_kat.py from an independent Python reference",
        "// (pure-Python X25519 / ChaCha20-Poly1305 / XChaCha20, hashlib BLAKE2s/HMAC).",
        "// Do not edit by hand; run `python3 tools/wireguard_kat.py --write`.",
        "",
        "pub const initiator_index: u32 = 0x11223344;",
        "pub const responder_index: u32 = 0x55667788;",
        "pub const data_payload = \"pyrop\";",
        "",
    ]
    for name, value in t.items():
        lines.append(f'pub const {name}_hex = "{value.hex()}";')
    return "\n".join(lines) + "\n"


def selfcheck():
    """Validate the reference primitives against published vectors first."""
    h = bytes.fromhex
    assert x25519(h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                  h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")) == \
        h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    assert x25519(h("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
                  h("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")) == \
        h("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
    assert poly1305(h("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
                    b"Cryptographic Forum Research Group") == h("a8061dc1305136c6c22b8baf0c0127a9")
    sun = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
           b"for the future, sunscreen would be it.")
    key = bytes(range(0x80, 0xA0))
    aad = h("50515253c0c1c2c3c4c5c6c7")
    assert aead_enc(key, h("070000004041424344454647"), sun, aad)[-16:] == h("1ae10b594f09e26a7e902ecbd0600691")
    assert xaead(key, bytes(range(0x40, 0x58)), sun, aad)[-16:] == h("c0875924c1c7987947deafd8780acf49")
    assert hchacha(bytes(range(32)), h("000000090000004a0000000031415927")) == \
        h("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
    assert HASH(CONSTRUCTION) == h("60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36")


def main(argv):
    selfcheck()
    out = render(transcript())
    target = Path(__file__).resolve().parent.parent / "src" / "noise_kat.zig"
    if "--write" in argv:
        target.write_text(out)
        print(f"wrote {target}")
    elif "--check" in argv:
        if target.read_text() != out:
            print("src/noise_kat.zig does not match the reference transcript", file=sys.stderr)
            return 1
        print("src/noise_kat.zig matches the reference transcript")
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
