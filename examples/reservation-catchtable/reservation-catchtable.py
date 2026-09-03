#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reservation-catchtable.py

캐치테이블 Android 앱(`co.kr.catchtable.android.catchtable_app`)이 실제로 호출하는
REST API를 그대로 재현하는 줄서기예약(웨이팅) 자동화 CLI입니다.

이 스크립트는 앱을 직접 조작하지 않고, Waydroid + Frida/mitmproxy로 앱 트래픽을
역공학해서 얻은 API를 순수 HTTP 요청으로 재현합니다. API 명세와 캡처 원본은
../../reports/catchtable_api_analysis.md (3.1절 로그인, 3.6절 줄서기예약) 참고.

[동작 순서]
1. 로그인            POST /api/user/v1/login-via-catchtable
                     비밀번호는 클라이언트에서 RSA(JSEncrypt 호환, PKCS1v1.5)로 암호화해서
                     전송하고, 서버가 Set-Cookie로 내려주는 x-ct-a 쿠키 하나로 세션을 유지합니다.
2. 매장 검색          POST /api/v5/autocomplete/_list           매장명 -> shopRef
3. 예약 가능 날짜 조회  GET  /api/reservation/v2/reserved-entry/day-slots
4. 특정 날짜 시간대 조회 POST /api/reservation/v2/reserved-entry/time-slots
5. 시간대 검증         POST /api/reservation/v2/reserved-entry/validate-time-slot
6. 홀드 생성(7분 임시 잠금) POST /api/reservation/v2/reserved-entry/shops/{shopRef}/holdings
7. 줄서기예약 등록      POST /api/reservation/v2/reserved-entries
8. 방문 목적 설정(선택)  PUT  /api/reservation/v1/RESERVED_ENTRY/{reservationRef}/visit-purpose

취소는 별도 API 한 번으로 끝납니다: POST /api/reservation/v2/reserved-entries/{reservationRef}/cancel
(바디 없음 `{}`, 응답에 `status: "CANCEL"`, `cancelReasonCode: "CANCEL_BY_CUSTOMER_DIRECT"` 포함)

[주의] 7번 단계가 완료되면 실제 매장에 진짜 줄서기예약이 등록됩니다(무료 이벤트가 아니면
노쇼/취소 페널티가 있을 수 있음). 기본적으로 실행 전 확인 프롬프트를 띄우며,
--yes를 주면 확인 없이 바로 등록/취소합니다. --dry-run을 주면 등록 직전(6단계까지)에서 멈춥니다.

[사용법]
  ./reservation-catchtable.py --shop "오이지 연남" --date 2026-09-07 --time 11:30
  ./reservation-catchtable.py --shop "오이지 연남" --date 2026-09-07              # 시간 미지정 시 첫 가능 시간대 자동 선택
  ./reservation-catchtable.py --shop "오이지 연남" --date 2026-09-07 --dry-run    # 조회만, 등록 안 함
  ./reservation-catchtable.py --shop "오이지 연남" --date 2026-09-07 --yes       # 확인 없이 바로 등록
  ./reservation-catchtable.py --cancel <reservationRef>                        # 기존 예약 취소 (확인 프롬프트 있음)
  ./reservation-catchtable.py --cancel <reservationRef> --yes                  # 확인 없이 바로 취소

[환경 변수] (이 스크립트와 같은 디렉토리의 .env 파일 또는 셸 환경 변수)
  CATCHTABLE_ID       로그인 ID (휴대폰번호/이메일/닉네임)
  CATCHTABLE_PASSWORD 비밀번호
"""

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("cryptography 패키지가 필요합니다: pip install cryptography", file=sys.stderr)
    sys.exit(1)


BASE_URL = "https://ct-api.catchtable.co.kr"
ORIGIN = "https://app.catchtable.co.kr"
USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 13; Pixel 5 Build/TQ3A.230901.001; wv) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/151.0.7922.199 Safari/537.36"
)

# app.catchtable.co.kr 이 서빙하는 Login.js 번들에 하드코딩된 RSA 공개키
# (VITE_LOGIN_PUBLIC_KEY). mitmproxy 캡처로 확인 — ../../reports/catchtable_api_analysis.md 3.1절 참고.
LOGIN_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDGRfDQbOBrD7CThAJ2VO9QQknaN9QEZbsRE1TnQP0E
853lHb++GuDM8l0NEReA1J6bkQEIZeU4tqiPdlNY/j8enB+7kpP88M0toFlKqWQMOdKd9VojrUAh06dK
0pcRS3ZMlRMCFIudp3m7rYv+5UwT0slaLkTo634NWSlQFBvI+QIDAQAB
-----END PUBLIC KEY-----"""

VISIT_PURPOSE_CODES = ("EAT_ALONE", "DRINK_ALONE", "TRAVEL", "ETC")  # 혼밥/혼술/여행/기타


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


SCRIPT_DIR = Path(__file__).resolve().parent
load_dotenv(SCRIPT_DIR / ".env")

DEFAULT_ID = os.environ.get("CATCHTABLE_ID") or os.environ.get("ID", "")
DEFAULT_PASSWORD = os.environ.get("CATCHTABLE_PASSWORD") or os.environ.get("PASSWORD", "")


def encrypt_password(password: str) -> str:
    """JSEncrypt(RSA/PKCS1 v1.5) 호환 암호화. WebView의 encryptPassword()와 동일 알고리즘."""
    public_key = serialization.load_pem_public_key(LOGIN_PUBLIC_KEY_PEM)
    ciphertext = public_key.encrypt(password.encode("utf-8"), padding.PKCS1v15())
    return base64.b64encode(ciphertext).decode("ascii")


class CatchTableApiError(RuntimeError):
    pass


class CatchTableClient:
    def __init__(self, device_id=None):
        self.device_id = device_id or str(uuid.uuid4())
        self.cookie = ""  # "x-ct-a=..."
        self._txn = 0

    def _headers(self):
        self._txn += 1
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "Origin": ORIGIN,
            "x-requested-with": "XMLHttpRequest",
            "x-device-id": self.device_id,
            "x-transaction-id": str(self._txn),
            "User-Agent": USER_AGENT,
        }
        if self.cookie:
            headers["Cookie"] = self.cookie
        return headers

    def _request(self, method, path, body=None, query=None):
        url = f"{BASE_URL}{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers=self._headers())
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                for set_cookie in resp.headers.get_all("Set-Cookie") or []:
                    if set_cookie.startswith("x-ct-a="):
                        self.cookie = set_cookie.split(";", 1)[0]
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                payload = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                payload = raw.decode("utf-8", "replace")
            raise CatchTableApiError(f"{method} {path} -> HTTP {e.code}: {payload}") from None

    # 1. 로그인
    def login(self, login_key: str, password: str) -> dict:
        body = {"loginKey": login_key, "encryptedPassword": encrypt_password(password)}
        data = self._request("POST", "/api/user/v1/login-via-catchtable", body)
        current_user = (data.get("data") or {}).get("currentUser") or {}
        if not current_user.get("loggedIn"):
            raise CatchTableApiError(f"로그인 실패: {data}")
        return current_user

    # 2. 매장 검색
    def search_shop(self, name: str) -> dict:
        data = self._request("POST", "/api/v5/autocomplete/_list", {"query": name})
        shops = (data.get("data") or {}).get("shops") or []
        if not shops:
            raise CatchTableApiError(f"'{name}' 매장을 찾을 수 없습니다")
        return shops[0]  # {"code", "label", "subLabel", "primaryCode" (shopRef), ...}

    # 3. 예약 가능 날짜 조회
    def day_slots(self, shop_ref: str, search_date: str, search_end_date: str) -> list:
        data = self._request(
            "GET",
            "/api/reservation/v2/reserved-entry/day-slots",
            query={
                "shopRef": shop_ref,
                "searchDate": search_date,
                "searchEndDate": search_end_date,
                "availableOnly": "true",
            },
        )
        return data.get("dailyAvailabilities") or []

    # 4. 특정 날짜의 시간대(테이블) 조회
    def time_slots(self, shop_ref: str, search_date: str, person_count: int) -> dict:
        return self._request(
            "POST",
            "/api/reservation/v2/reserved-entry/time-slots",
            {"searchDate": search_date, "personCount": person_count},
            query={"shopRef": shop_ref},
        )

    # 5. 시간대 검증
    def validate_time_slot(self, shop_ref: str, date_yymmdd: str, time_hhmm: str) -> dict:
        return self._request(
            "POST",
            "/api/reservation/v2/reserved-entry/validate-time-slot",
            {"shopRef": shop_ref, "date": date_yymmdd, "time": time_hhmm},
        )

    # 6. 홀드 생성 (7분간 유효한 임시 잠금)
    def create_holding(self, shop_ref: str, table_id: str, visit_date: str, visit_time: str) -> str:
        data = self._request(
            "POST",
            f"/api/reservation/v2/reserved-entry/shops/{shop_ref}/holdings",
            {"tableId": table_id, "visitDate": visit_date, "visitTime": visit_time},
        )
        return data["id"]

    # 7. 줄서기예약 등록 (실제 예약 확정)
    def register(self, shop_ref, holding_id, table_id, visit_date, visit_time, person_count) -> dict:
        return self._request(
            "POST",
            "/api/reservation/v2/reserved-entries",
            {
                "shopRef": shop_ref,
                "holdingId": holding_id,
                "tableId": table_id,
                "visitDate": visit_date,
                "visitTime": visit_time,
                "totalPersonCount": person_count,
                "personOptions": [],
            },
        )

    # 8. 방문 목적 설정 (선택 사항 — 등록 자체와는 별도 API)
    def set_visit_purpose(self, reservation_ref: str, codes: list) -> dict:
        return self._request(
            "PUT",
            f"/api/reservation/v1/RESERVED_ENTRY/{reservation_ref}/visit-purpose",
            {"visitPurposes": codes},
        )

    # 예약 조회
    def get_reservation(self, reservation_ref: str) -> dict:
        return self._request("GET", f"/api/reservation/v2/reserved-entries/{reservation_ref}")

    # 내 예약 목록 (마이다이닝 > 나의 예약 화면과 동일한 API)
    def list_reservations(self, status_group="PLANNED", sort_code="ASC", size=10) -> list:
        data = self._request(
            "GET", "/api/v4/user/reservations/_list",
            query={"statusGroup": status_group, "sortCode": sort_code, "size": size},
        )
        return (data.get("data") or {}).get("items") or []

    # 줄서기예약 취소
    def cancel_reservation(self, reservation_ref: str) -> dict:
        return self._request(
            "POST", f"/api/reservation/v2/reserved-entries/{reservation_ref}/cancel", {}
        )


def to_yymmdd(date_str: str) -> str:
    return date_str.replace("-", "")[2:]  # "2026-09-07" -> "260907"


def to_hhmm(time_str: str) -> str:
    return time_str.replace(":", "")  # "11:30" -> "1130"


def pick_time_slot(time_slots: dict, wanted_time: str | None) -> tuple:
    slots = time_slots.get("timeSlots") or []
    if not slots:
        reason = time_slots.get("notAvailableReason")
        raise CatchTableApiError(f"예약 가능한 시간대가 없습니다 (notAvailableReason={reason})")
    if wanted_time:
        for slot in slots:
            if slot["operationTime"] == wanted_time:
                return slot["operationTime"], slot["tableIds"][0]
        available = ", ".join(s["operationTime"] for s in slots)
        raise CatchTableApiError(f"'{wanted_time}' 시간대는 예약 불가합니다. 가능한 시간: {available}")
    first = slots[0]
    return first["operationTime"], first["tableIds"][0]


def main():
    parser = argparse.ArgumentParser(
        description="캐치테이블 줄서기예약(웨이팅) 자동화 CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--shop", help="매장명 (예: 오이지 연남). 신규 등록 시 필수")
    parser.add_argument("--date", help="방문 일자 (YYYY-MM-DD). 신규 등록 시 필수")
    parser.add_argument("--time", help="방문 시각 (HH:MM). 미지정 시 해당 날짜의 첫 가능 시간대 자동 선택")
    parser.add_argument("--person", type=int, default=1, help="방문 인원 (기본: 1)")
    parser.add_argument(
        "--purpose", choices=[*VISIT_PURPOSE_CODES, "none"], default="EAT_ALONE",
        help="방문 목적 코드 (기본: EAT_ALONE=혼밥). 'none'이면 방문 목적 설정을 건너뜀",
    )
    parser.add_argument("--cancel", metavar="RESERVATION_REF",
                         help="신규 등록 대신, 주어진 reservationRef의 예약을 취소하고 종료")
    parser.add_argument("--list", action="store_true",
                         help="신규 등록 대신, 내 예약 목록을 조회하고 종료 (마이다이닝 화면과 동일)")
    parser.add_argument("--list-status", default="PLANNED", choices=["PLANNED", "CANCEL", "COMPLETE"],
                         help="--list와 함께 사용. 조회할 상태 그룹 (기본: PLANNED=방문예정)")
    parser.add_argument("--id", default=DEFAULT_ID, help="로그인 ID (기본: .env의 CATCHTABLE_ID)")
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help="로그인 비밀번호 (기본: .env의 CATCHTABLE_PASSWORD)")
    parser.add_argument("--yes", action="store_true", help="확인 프롬프트 없이 바로 등록/취소")
    parser.add_argument("--dry-run", action="store_true", help="조회만 하고 실제 등록(홀드/등록)은 하지 않음")
    args = parser.parse_args()

    if not args.id or not args.password:
        print("CATCHTABLE_ID / CATCHTABLE_PASSWORD 가 설정되어 있지 않습니다 "
              "(.env 파일 또는 --id/--password 인자로 지정하세요)", file=sys.stderr)
        sys.exit(1)

    if not args.cancel and not args.list and (not args.shop or not args.date):
        print("--shop과 --date가 필요합니다 (--cancel RESERVATION_REF 또는 --list 단독 사용도 가능)", file=sys.stderr)
        sys.exit(1)

    client = CatchTableClient()

    print(f"🔐 로그인 중... ({args.id})", file=sys.stderr)
    user = client.login(args.id, args.password)
    print(f"✅ 로그인 성공: {user.get('displayName')} (ctUserIdentifier={user.get('ctUserIdentifier')})", file=sys.stderr)

    if args.list:
        items = client.list_reservations(status_group=args.list_status)
        if not items:
            print(f"[{args.list_status}] 상태의 예약이 없습니다.")
            return
        print(f"[{args.list_status}] 예약 {len(items)}건:")
        for item in items:
            shop = item.get("shop") or {}
            reservation = item.get("reservation") or {}
            status = (reservation.get("reservedEntry") or {}).get("reservedEntryStatus")
            print(f"  - {shop.get('shopName')} | {reservation.get('visitAt')} | "
                  f"{reservation.get('totalPersonCount')}명 | {status} | "
                  f"reservationRef={item.get('reservationRef')}")
        return

    if args.cancel:
        reservation = client.get_reservation(args.cancel)
        if reservation.get("status") == "CANCEL":
            print(f"이미 취소된 예약입니다 (cancelReasonCode={reservation.get('cancelReasonCode')}, "
                  f"canceledAt={reservation.get('canceledAt')})", file=sys.stderr)
            return
        print(f"매장: {reservation.get('shopName')} / 방문일시: {reservation.get('visitAt')} / "
              f"인원: {reservation.get('totalPersonCount')}명 / 상태: {reservation.get('status')}", file=sys.stderr)
        if not args.yes:
            answer = input("이 줄서기예약을 취소할까요? [y/N] ")
            if answer.strip().lower() != "y":
                print("취소하지 않았습니다.", file=sys.stderr)
                return
        result = client.cancel_reservation(args.cancel)
        print(f"🗑️  취소 완료: {result.get('shopName')} {result.get('visitAt')} "
              f"(status={result.get('status')}, cancelReasonCode={result.get('cancelReasonCode')})")
        return

    print(f"🔍 매장 검색: {args.shop}", file=sys.stderr)
    shop = client.search_shop(args.shop)
    shop_ref = shop["primaryCode"]
    print(f"✅ 매장 확인: {shop['label']} (shopRef={shop_ref}, {shop.get('subLabel', '')})", file=sys.stderr)

    print(f"📅 {args.date} 시간대 조회 중...", file=sys.stderr)
    slots = client.time_slots(shop_ref, args.date, args.person)
    if slots.get("notAvailableReason") and not (slots.get("timeSlots")):
        raise CatchTableApiError(f"{args.date}은 예약 불가: {slots.get('notAvailableReason')}")
    visit_time, table_id = pick_time_slot(slots, args.time)
    print(f"✅ 시간대 선택: {args.date} {visit_time} (잔여 {slots.get('remainingCount')}팀, tableId={table_id})", file=sys.stderr)

    if args.dry_run:
        print("🛑 --dry-run: 조회만 수행하고 종료합니다 (홀드/등록 없음)", file=sys.stderr)
        return

    if not args.yes:
        answer = input(f"'{shop['label']}' {args.date} {visit_time} {args.person}명으로 줄서기예약을 등록할까요? [y/N] ")
        if answer.strip().lower() != "y":
            print("취소했습니다.", file=sys.stderr)
            return

    date_yymmdd = to_yymmdd(args.date)
    time_hhmm = to_hhmm(visit_time)

    print("🔒 시간대 검증 중...", file=sys.stderr)
    client.validate_time_slot(shop_ref, date_yymmdd, time_hhmm)

    print("⏳ 임시 홀드(7분) 생성 중...", file=sys.stderr)
    holding_id = client.create_holding(shop_ref, table_id, args.date, visit_time)

    print("🚀 줄서기예약 등록 중...", file=sys.stderr)
    reservation = client.register(shop_ref, holding_id, table_id, args.date, visit_time, args.person)

    if args.purpose != "none":
        client.set_visit_purpose(reservation["reservationRef"], [args.purpose])

    print()
    print("=" * 60)
    print("🎉 줄서기예약이 등록되었습니다!")
    print("=" * 60)
    print(f"  매장       : {reservation.get('shopName')}")
    print(f"  방문일시    : {reservation.get('visitAt')}")
    print(f"  인원       : {reservation.get('totalPersonCount')}명")
    print(f"  방문유형    : {reservation.get('tableName')}")
    print(f"  상태       : {reservation.get('status')}")
    print(f"  예약번호    : {reservation.get('reservationRef')}")
    print(f"  도착인증 가능 시간: {reservation.get('checkInAvailablePeriod')}")
    print("=" * 60)
    print("💡 방문 당일 도착인증 가능 시간부터 앱에서 '도착했어요'를 눌러야 순서대로 호출됩니다.")


if __name__ == "__main__":
    try:
        main()
    except CatchTableApiError as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n중단되었습니다.", file=sys.stderr)
        sys.exit(130)
