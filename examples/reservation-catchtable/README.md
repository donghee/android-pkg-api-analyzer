# reservation-catchtable

캐치테이블 앱의 실제 REST API(순수 `urllib` HTTP 요청, Waydroid/Frida/UI 자동화 불필요)를
그대로 재현해 줄서기예약(웨이팅)을 등록/취소/조회하는 CLI입니다. API는 `../../reports/catchtable_api_analysis.md`
(3.1절 로그인, 3.6절 등록, 3.7절 취소, 3.8절 목록 조회)에서 mitmproxy로 캡처/분석한 내용을 기반으로
구현했습니다.

## 준비

```bash
pip install cryptography   # 이미 설치돼 있다면 생략 가능
```

`.env` 파일 (이 디렉토리에 이미 있음, 필요 시 값 수정):

```
CATCHTABLE_ID=<휴대폰번호/이메일/닉네임>
CATCHTABLE_PASSWORD=<비밀번호>
```

## 사용법

```bash
# 조회만 (로그인 -> 매장검색 -> 시간대조회, 등록 안 함)
./reservation-catchtable.py --shop "오이지 연남" --date 2026-09-07 --dry-run

# 실제 등록 (확인 프롬프트 있음)
./reservation-catchtable.py --shop "오이지 연남" --date 2026-09-07

# 시간 지정 + 확인 없이 바로 등록
./reservation-catchtable.py --shop "오이지 연남" --date 2026-09-07 --time 11:30 --yes

# 인원 / 방문목적 지정
./reservation-catchtable.py --shop "오이지 연남" --date 2026-09-07 --person 2 --purpose TRAVEL

# 예약 취소 (등록 시 출력된 예약번호 사용, 확인 프롬프트 있음)
./reservation-catchtable.py --cancel <reservationRef>

# 확인 없이 바로 취소
./reservation-catchtable.py --cancel <reservationRef> --yes

# 내 예약 목록 (기본: 방문예정)
./reservation-catchtable.py --list

# 취소/노쇼 내역 조회
./reservation-catchtable.py --list --list-status CANCEL
```

`--time`을 지정하지 않으면 해당 날짜에 가능한 첫 시간대가 자동 선택됩니다.

## 동작 원리

1. **로그인** — `POST /api/user/v1/login-via-catchtable`. 비밀번호는 Login.js 번들에 하드코딩된
   RSA 공개키로 클라이언트 측 암호화(JSEncrypt 호환, PKCS1 v1.5) 후 전송. 세션은 `Set-Cookie`로
   내려오는 `x-ct-a` 쿠키 하나로 유지됩니다(별도 access/refresh 토큰 없음).
2. **매장 검색** — `POST /api/v5/autocomplete/_list` `{"query": "<매장명>"}` → `shopRef` 획득.
3. **시간대 조회** — `POST /api/reservation/v2/reserved-entry/time-slots?shopRef=...`
   `{"searchDate","personCount"}` → 시간대별 `tableId` 목록.
4. **검증 → 홀드 → 등록** — `validate-time-slot` → `holdings`(7분 임시 잠금) →
   `POST /api/reservation/v2/reserved-entries` 순서로 호출하면 실제 예약이 `CONFIRMED` 상태로 생성됩니다.
5. **방문 목적** (선택) — 등록 후 별도로 `PUT .../visit-purpose` 호출.
6. **취소** — `POST /api/reservation/v2/reserved-entries/{reservationRef}/cancel` (바디 없음)
   하나로 끝남. 응답에 `status: "CANCEL"`, `cancelReasonCode: "CANCEL_BY_CUSTOMER_DIRECT"` 포함.
   `--cancel`은 먼저 `GET .../reserved-entries/{ref}`로 현재 상태를 확인해, 이미 취소된 예약이면
   API를 다시 호출하지 않고 바로 안내만 합니다.
7. **목록 조회** — `GET /api/v4/user/reservations/_list?statusGroup={PLANNED|COMPLETE|CANCEL}`.
   마이다이닝 화면의 방문예정/방문완료/취소·노쇼 세 탭과 동일한 엔드포인트. 응답 아이템은
   `{reservationRef, reservation: {visitAt, totalPersonCount, reservedEntry: {reservedEntryStatus}}, shop: {shopName, ...}}`
   형태의 중첩 구조(3.6절 등록 응답의 평평한 구조와 다름).

## 검증 이력

2026-09-03 세션에서 다음을 모두 실제 API로 end-to-end 테스트 완료:
- `--dry-run`(로그인/검색/시간대조회)
- 실제 등록(`--yes`, 오이지 연남 2026-09-09 11:30 / 옥동식 2026-10-01 18:00)
- `--cancel`(옥동식 예약 취소, `cancelReasonCode: CANCEL_BY_CUSTOMER_DIRECT` 확인)
- `--list`(방문예정 0건, 취소/노쇼 4건 — 오이지 연남 x3, 옥동식 x1 — 정상 조회 확인)

상세 캡처 로그는 `../../logs/co_kr_catchtable_android_catchtable_app_mitm_waitlist_*.log`,
`../../logs/co_kr_catchtable_android_catchtable_app_mitm_cancel_*.log` 참고.

## 주의

- 등록 단계(`register`)가 완료되면 **실제 매장에 진짜 예약이 생성됩니다.** 무분별하게 반복 실행하지
  마세요 — 노쇼/반복 취소는 계정 페널티로 이어질 수 있습니다.
- 이 스크립트는 개인 계정으로 개인 소유 기기/데이터를 대상으로 한 자동화 목적으로만 사용하세요.
