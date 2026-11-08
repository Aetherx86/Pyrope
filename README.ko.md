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

## 라이선스

MIT License - Copyright (c) 2026 Jeong Hoon Kim
