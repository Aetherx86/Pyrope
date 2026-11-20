# Pyrope

상수 시간 WireGuard / ChaCha20-Poly1305 터널 (Constant-Time WireGuard / ChaCha20-Poly1305 Tunnel)

RFC 8439 ChaCha20-Poly1305 AEAD, Curve25519 (X25519) ECDH 및 WireGuard 프로토콜 패킷 프레이밍을 구현한 무의존성 암호화 터널링 엔진으로, Zig로 작성되었습니다.

[English Documentation](README.md)

## 아키텍처

- 상수 시간 암호화 (Constant-Time Cryptography): 분기 없는 쿼터 라운드(quarter-round) 변환 및 조건부 필드 스왑(`cswap`)을 통해 캐시 타이밍 부채널 공격을 원천 차단합니다.
- 래핑 산술 연산: 엄격한 래핑 산술 연산자(`+%`, `-%`, `*%`)를 사용하여 정의되지 않은 동작이나 컴파일러 패닉 없이 표준 모듈러 연산을 수행합니다.
- RFC 표준 테스트 벡터 완벽 준수: RFC 8439(ChaCha20, Poly1305, AEAD) 및 RFC 7748(X25519) 공식 테스트 벡터와 비트 단위로 일치함을 검증했습니다.
- WireGuard 프로토콜 프레이밍: 64비트 논스 카운터와 16바이트 인증 태그를 포함한 WireGuard 타입 4 데이터 전송 패킷을 직접 직렬화 및 파싱합니다.
- 제로 할당 (Zero Allocations): 스택 할당 버퍼와 호출자가 제공한 메모리 상에서만 작동하므로 베어메탈 커널 및 고성능 유저스페이스 라우터에 이상적입니다.

## WireGuard 전송 패킷 레이아웃

```
+-------------------------------------------------------------+
| Type (4B: 0x04) | Receiver Index (4B) | Counter Nonce (8B)  |
+-------------------------------------------------------------+
| Encrypted Payload (Plaintext size)                          |
+-------------------------------------------------------------+
| Poly1305 Authentication Tag (16B)                           |
+-------------------------------------------------------------+
```

## 빌드 및 테스트

```bash
# 테스트 스위트 실행
zig build test

# 최적화된 릴리스 바이너리 및 공유 라이브러리 컴파일
zig build -Doptimize=ReleaseFast
```

## 0.2.0 변경 사항

- 상수 시간 강화: Poly1305는 44비트 림(limb) 연산으로, X25519는 2^51 기수 필드 연산으로 다시 구현했습니다. 이전 버전은 `u256`/`u512` 나머지 연산을 사용했는데, 이 연산은 가변 시간 나눗셈으로 컴파일됩니다. X25519는 이제 u 좌표의 최상위 비트(bit 255)를 RFC 7748 규정대로 무시합니다.
- BLAKE2s(RFC 7693), HMAC-BLAKE2s, WireGuard KDF, HChaCha20 및 XChaCha20-Poly1305를 추가했습니다.
- WireGuard Noise_IKpsk2 개시자(initiator)와 응답자(responder) 핸드셰이크를 완전하게 구현했습니다. MAC1/MAC2 쿠키 처리, TAI64N 재전송 방지, 사전 공유 키를 지원합니다.
- RFC 6479 슬라이딩 윈도 재전송 필터, 패딩을 포함한 전송 세션, 주입 가능한 시계로 구동되는 재키잉(rekey)/킵얼라이브 타이머를 추가했습니다.
- CLI 명령 `genkey`, `pubkey`, `selftest [--json]`, `bench [MB] [--json]`을 추가했습니다. `keygen`은 이제 고정 키 대신 보안 난수를 사용합니다.
- 핸드셰이크 기대값 벡터는 독립적인 Python 참조 구현(`tools/wireguard_kat.py`)으로 생성했으며, CI에서 재현성을 검사합니다. 테스트는 46개입니다.

```bash
pyrope genkey | pyrope pubkey
pyrope selftest
pyrope bench 16 --json
```

## 라이선스

MIT License - Copyright (c) 2026 Jeong Hoon Kim
