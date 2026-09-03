# 캐치테이블 (CatchTable Android) API 프로토콜 상세 분석 보고서

본 문서는 안드로이드 캐치테이블 앱(`co.kr.catchtable.android.catchtable_app`)의 통신 패킷 캡처(TLS 복호화) 및
역공학 분석을 통해 규명된 캐치테이블 모바일 API 프로토콜 명세서입니다. Waydroid + Frida 기반 프로토콜
분석기(`analyze.sh`)와, 그 한계를 보완하기 위해 추가한 mitmproxy 기반 네트워크 레벨 캡처를 함께 사용했습니다.

---

## 1. 개요 및 통신 아키텍처

캐치테이블 앱은 **하이브리드(WebView 셸) 앱**입니다. 네이티브 레이어는 얇고(SDK 초기화, 푸시, 딥링크 정도),
실제 화면과 비즈니스 로직 대부분은 `android.webkit.WebView` 안에서 로드되는 SPA(들)로 구현되어 있습니다.

* **API 게이트웨이**: `https://ct-api.catchtable.co.kr` (Cloudflare 프록시, IP 예: `104.18.0.85`, `104.18.1.85`)
  * 경로 프리픽스로 여러 마이크로서비스를 라우팅하는 구조로 보입니다: `/api/v3/*`, `/api/v4/*`,
    `/api/display/v2/*`, `/api/user/v1/*`, `/api/user/v2/*`, `/api/review/v2/*`, `/api/payment/v2/*`,
    `/api/points/v2/*`, `/api/community/v1/*`, `/api/reservation/v1/*`, `/reservation-api/v1/*`,
    `/api/advertisement/v1/*`, `/api/in-app-message-campaigns/v1/*`, `/api/display/v2/main/*` 등.
* **프런트엔드/마이크로프런트엔드 호스트** (WebView가 로드하는 오리진들, 기능별로 분리된 서브도메인):
  `app.catchtable.co.kr`(메인), `shop-detail-app.`, `search-app.`, `search-map-app.`, `review-app.`,
  `payment-app.`, `dining-booking-app.`, `coupon-app.`, `bookmark-app.catchtable.co.kr`
* **정적 자산**: `ugc-images.catchtable.co.kr` (사용자 생성 콘텐츠 이미지)
* **전송 프로토콜**: HTTP/2 over TLS 1.3 (API), 일부 서드파티 SDK는 HTTP/1.1
* **데이터 포맷**: 요청/응답 모두 `application/json` (gzip 압축)
* **서드파티 SDK**: Amplitude(분석), AB180 Airbridge(어트리뷰션), Adjust, AppsFlyer, Google
  Analytics/Firebase, WadCorp(자체 이벤트 인프라로 추정), Instagram/Facebook SDK(공유), Admixer(광고)

### 1.1 왜 두 가지 캡처 방식을 병행했는가

Chromium 기반 WebView는 BoringSSL을 `libwebviewchromium.so`에 **정적으로, 심볼을 모두 스트립한 상태로**
내장합니다. 따라서 앱 프로세스에 붙어 `libssl.so`의 `SSL_write`/`SSL_read`를 후킹하는 일반적인 Frida
기법(`analyze.sh`)은 네이티브 SDK 트래픽(Amplitude, Airbridge 등)은 잡아내지만, **WebView 안에서 실행되는
실제 비즈니스 로직(ct-api 호출)은 볼 수 없습니다.** 이를 확인하기 위해 실행 중인 프로세스에 논스폰
(non-spawn) attach로 `libwebviewchromium.so`의 export(202개)/import(628개)/전체 심볼(855개)을 모두
덤프해봤지만 `SSL_*`/`TLS`/`BIO_`/`EVP_`/`CRYPTO` 계열 심볼은 전무했습니다(자세한 내용은
`WEBVIEW_HOOK_FINDINGS.md` 참고). 대신 **mitmproxy를 시스템 신뢰 CA로 설치 + 기기 전역 프록시 설정**하는
네트워크 레벨 MITM으로 전환했고, 이 방식으로 `ct-api.catchtable.co.kr` 트래픽 163건(엔드포인트 92종)을
완전한 평문으로 캡처했습니다(`MITM_CAPTURE_FINDINGS.md`). **인증서 피닝은 관찰되지 않았습니다** — 즉
mitmproxy 단독으로 충분합니다.

---

## 2. 인증 및 보안 체계

### 2.1 공통 요청 헤더 (WebView → ct-api, XHR/fetch 기반)

```http
GET /api/v4/user/reservations/upcoming HTTP/2
Host: ct-api.catchtable.co.kr
x-transaction-id: 9
x-device-id: 2e93c11d-6bc7-45eb-bdce-f526abe4ddcc
x-experiment-variants: 260820_autopay_benefit_type=B
x-requested-with: XMLHttpRequest
User-Agent: Mozilla/5.0 (Linux; Android 13; Pixel 5 Build/TQ3A.230901.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/151.0.7922.199 Safari/537.36
Accept: application/json, text/plain, */*
Origin: https://app.catchtable.co.kr
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate, br, zstd
Cookie: x-ct-a=AACsne2Zj-uVsOsAAAAKAG1u...(세션/인증 토큰, opaque binary-ish base64 형태); airbridge_user__catchtable=...; _ga=...; ...
```

### 2.2 인증 요소

1. **`x-ct-a` 쿠키**: 로그인 API(`/api/user/v1/login-via-catchtable`, 3.1절)가 `Set-Cookie`로 발급하는
   세션 토큰. `Max-Age=2592000`(30일), `HttpOnly`+`Secure`+`SameSite=None`. 이후 모든 `ct-api` 요청에
   쿠키로 자동 첨부됩니다. (자체 서명/암호화된 바이너리를 base64 유사 인코딩한 형태 — 평문 페이로드
   구조는 이번 분석 범위에서는 역공학하지 않았습니다.)
2. **`x-device-id`**: 기기 식별용 UUID (앱 최초 실행 시 생성, 이후 고정).
3. **`x-transaction-id`**: 요청별 증가하는 정수 카운터로 보이는 값 (요청 추적/재시도 판별용).
4. **`x-experiment-variants`**: 서버가 내려준 A/B 테스트 그룹을 요청 헤더로 되돌려 보내는 방식
   (예: `260820_autopay_benefit_type=B`).
5. **`Origin: https://app.catchtable.co.kr`**: WebView가 이 오리진에서 로드된 것으로 확인되며, ct-api는
   CORS로 `access-control-allow-origin`을 캐치테이블 서브도메인들에만 허용합니다 — 즉 API는 브라우저
   fetch/XHR 기반 same-site 정책을 그대로 따릅니다(네이티브 앱이라기보다 "WebView 안의 웹앱"에 가까운
   설계).
6. **로그인 방식**: `co.kr.catchtable.android.catchtable_app` MY 탭 → "휴대폰 번호로 시작" → 실제로는
   **휴대폰 번호(또는 이메일/닉네임) + 비밀번호**를 입력하는 화면으로 연결됩니다. 관찰된 바로는 OTP/SMS
   인증 단계가 없는 단순 ID+PW 로그인이며, 비밀번호는 클라이언트에서 RSA(JSEncrypt)로 암호화한 뒤
   전송됩니다. 로그인 성공 시 `x-ct-a` 쿠키가 발급되고 WebView의 로컬 스토리지/쿠키 저장소에
   영속화되어 **앱(프로세스) 재시작 후에도 세션이 유지**됩니다. API 상세는 3.1절 참고.

---

## 3. 핵심 API 프로토콜 상세 명세

### 3.1 로그인 (`/api/user/v1/login-via-catchtable`)

계정을 로그아웃한 뒤 mitmproxy 캡처를 붙인 상태에서 다시 로그인해 실제 로그인 API를 확인했습니다
(이전 버전 문서에서는 로그인이 mitmproxy 셋업 이전에 이뤄져 캡처가 없었음 — 이번에 보완).

* **Endpoint**: `POST /api/user/v1/login-via-catchtable` (선행 `OPTIONS` CORS preflight 있음)
* **역할**: 휴대폰번호/이메일/닉네임 + 비밀번호 기반 로그인 (ID+PW 로그인, OTP/SMS 인증 단계 없음)

#### 요청 헤더 (발췌 — 인증에 의미 있는 것만)

```http
POST /api/user/v1/login-via-catchtable HTTP/2
Host: ct-api.catchtable.co.kr
Content-Type: application/json
x-transaction-id: 16
x-device-id: 2e93c11d-6bc7-45eb-bdce-f526abe4ddcc
x-requested-with: XMLHttpRequest
Origin: https://app.catchtable.co.kr
```

#### 요청 바디

```json
{
  "loginKey": "<휴대폰번호/이메일/닉네임>",
  "encryptedPassword": "<RSA(JSEncrypt)로 암호화된 base64 문자열>"
}
```

| 파라미터 | 설명 |
|---|---|
| `loginKey` | 로그인 화면에 입력한 값 그대로 (휴대폰번호/이메일/닉네임 중 하나, 평문) |
| `encryptedPassword` | **비밀번호는 절대 평문으로 전송되지 않음.** WebView JS가 `Login.js` 번들에 포함된
  [JSEncrypt](https://github.com/travist/jsencrypt) 라이브러리로 클라이언트 측 RSA 암호화 후 base64로
  전송. 실제 소스(난독화된 변수명 그대로): `encryptPassword=(ne,re)=>{const ie=new JSEncrypt;ie.setPublicKey(ne);const oe=ie.encrypt(re);return oe===!1?...}` — `ne`가 RSA 공개키, `re`가 평문 비밀번호. 이번 캡처
  세션에서는 공개키가 어디서 오는지(하드코딩 vs 별도 API로 fetch)까지는 추적하지 않았음 — 로그인 화면
  진입~제출 사이에 별도의 키 조회 API 호출은 관찰되지 않았으므로 `Login.js` 번들에 공개키가 하드코딩돼
  있을 가능성이 높음(TLS 위에 추가로 RSA를 얹는 defense-in-depth로 추정). |

#### 응답

```http
HTTP/2 200
Set-Cookie: x-ct-a=AACsne2Zj-uVsOsAAAAKAG1u...(생략); Path=/; Domain=catchtable.co.kr; Max-Age=2592000; Secure; HttpOnly; SameSite=None
```

```json
{
  "resultCode": null,
  "displayMessage": null,
  "message": null,
  "data": {
    "isVerified": true,
    "currentUser": {
      "loginPhase": "real",
      "name": "<실명, 응답 원문에는 평문으로 포함됨>",
      "displayName": "똑똑한 개척가_51713",
      "authProvider": "B",
      "reservationSyncYn": "Y",
      "pushPopupReadYn": "Y",
      "catchtableAgreement": { "marketingAgreement": { "...": "..." }, "notiPushAgreement": { "...": "..." } },
      "agreementProvisionThirdPartyYn": "Y",
      "pushSetting": { "pushTokenList": ["...FCM 토큰들..."] },
      "ctUserIdentifier": "pgB-4pjWG3C4F7wFthIVvw",
      "loggedIn": true,
      "curOauthUser": false
    },
    "blockUsers": [],
    "blockUserIdentifiers": [],
    "followUsers": []
  }
}
```

* `data.isVerified` / `data.currentUser.loggedIn`이 로그인 성공 여부를 나타내는 실질적인 플래그.
* 세션은 서버가 `Set-Cookie`로 내려주는 **`x-ct-a`** 하나로 전부 처리됨 — `Max-Age=2592000`(30일),
  `HttpOnly`+`Secure`+`SameSite=None`. 이후 모든 `ct-api` 요청은 이 쿠키만 자동 첨부하면 인증됨(응답
  바디에 별도 access/refresh 토큰 필드는 없음 — 순수 쿠키 세션 방식).
* `authProvider: "B"`는 아이디/비번(자체 계정) 로그인을 뜻하는 것으로 추정됩니다(4.4절의 `kakaoLogin`/
  `naverLogin` 네이티브 브릿지 경로는 다른 `authProvider` 값을 쓸 것으로 보이나 이번 세션에서는
  ID+PW 로그인만 캡처했습니다).
* `ctUserIdentifier`가 사실상의 내부 유저 PK로, 3.1 이후 다른 응답들(예: `blockUserIdentifiers`,
  분석 SDK 쿠키의 `externalUserID`)에서도 동일 값이 재사용됩니다.
* 로그인 실패 시 표시되는 문구("비밀번호가 올바르지 않습니다.")는 `Login.js` 번들 안에 클라이언트
  문자열로 존재 — 서버가 세부 에러 코드를 내려주고 클라이언트가 매핑하는 방식인지, 클라이언트가 자체
  검증하는 방식인지는 이번 분석에서 확인하지 않았습니다.

### 3.2 알림 신규 여부 (`/api/v4/notifications/new`)

* **Endpoint**: `GET /api/v4/notifications/new?lastReadNoticeSeq={seq}`
* **역할**: 마지막으로 읽은 공지 시퀀스 이후 새 알림이 있는지 확인 (홈 화면 진입 시 자동 호출)

```http
GET /api/v4/notifications/new?lastReadNoticeSeq=2013 HTTP/2
Host: ct-api.catchtable.co.kr
```

응답:

```json
{"resultCode":null,"displayMessage":null,"message":null,"data":{"hasNotice":false,"hasCommunityNotification":false}}
```

응답 포맷은 `{resultCode, displayMessage, message, data}` 공통 래퍼를 사용합니다(대부분의 ct-api 엔드포인트
에서 동일하게 관찰됨).

### 3.3 다가오는 예약 조회 (`/api/v4/user/reservations/upcoming`)

* **Endpoint**: `GET /api/v4/user/reservations/upcoming`
* **역할**: 로그인한 사용자의 다가오는 (정규) 예약 목록 조회

응답 (본 세션에서는 빈 배열 — 아래 3.5의 줄서기예약과는 별도 데이터로 취급되는 것으로 보입니다):

```json
{"resultCode":null,"displayMessage":null,"message":null,"data":[]}
```

### 3.4 메인 화면 배너/섹션 (`/api/display/v2/main/*`)

* **Endpoints**:
  * `POST /api/display/v2/main/banners`
  * `POST /api/display/v2/main/shortcuts`
  * `POST /api/display/v2/main/section-layout`
* **역할**: 홈 화면 상단 배너, 바로가기 아이콘 그리드(줄서기예약/판교급상승/예약핫플/... ), 섹션 레이아웃을
  서버 주도 UI(server-driven UI) 방식으로 구성.

```json
// POST /api/display/v2/main/banners 요청 바디
{"position":"WHERE_TO_GO","interestRegionCodes":[],"shuffle":false}
```

### 3.5 줄서기예약 (웨이팅) 상태 (`/reservation-api/v1/waitings/statuses`)

* **Endpoint**: `GET /reservation-api/v1/waitings/statuses`
* **역할**: 현재 진행 중인(활성) 줄서기예약이 있는지 여부를 조회 — 홈 화면 배지 표시용으로 추정.

```json
{"resultCode":null,"displayMessage":null,"message":null,"data":false}
```

`data`가 boolean인 것으로 보아 이 엔드포인트는 "활성 웨이팅 존재 여부"만 나타내며, 예약 상세는 매장별
화면(`co_kr.../presentation` WebView 내 줄서기예약 플로우, 본 문서 3.6)에서 별도 호출로 조회되는 구조로
보입니다.

### 3.6 줄서기예약 등록 플로우 (전체 API 캡처 완료)

로그아웃 후 재로그인(3.1절)에 이어, 같은 mitmproxy 세션에서 매장 검색부터 실제 등록까지 전체
플로우를 다시 캡처했습니다(`오이지 연남`, 2026-09-07 예시). 화면 흐름은 다음과 같고, 각 단계에
대응하는 실제 API 호출을 그 아래에 정리합니다.

1. 매장 검색 → 매장 상세 페이지
2. "줄서기예약" 탭 선택 → 방문 가능 날짜 목록 표시
3. 날짜 + 인원 수 선택 → "다음"
4. 서버가 배정한 방문 시간 슬롯을 포함한 예약 확정 화면 — **7분 타이머**("예약 찜")가 표시되며 시간
   내 완료하지 않으면 슬롯이 풀리는 낙관적 잠금(optimistic hold) 방식
5. 방문 목적(복수 선택, 예: 혼밥/혼술/여행/기타) + "개인정보 제3자 제공 동의" 체크 → 등록 버튼 활성화
6. "방문 당일 매장 도착인증" 안내 + 필수 동의 체크박스 → "확인하고 다음" → **실제 등록 완료**
7. 이후 "방문 예정" 화면에서 `방문 전 → 도착인증 → 매장호출 → 입장` 4단계 진행 바가 노출되며, "도착
   인증은 방문일 오전 11:20부터 가능"이라는 안내가 표시됨 — 즉 도착인증은 방문 시각 10분 전부터
   활성화되는 시간 제한 액션입니다. (5~6단계에서 관찰되는 "개인정보 제3자 제공 동의"/"도착인증 하겠다"
   체크박스는 순수 클라이언트 측 UX 게이팅으로, 아래 API 호출 바디 어디에도 대응하는 필드가 없습니다 —
   즉 서버로는 전송되지 않고 버튼 활성화 조건으로만 쓰입니다.)

#### (2단계) 매장 검색: `POST /api/v5/autocomplete/_list`

```json
// 요청
{"query": "오이지 연남"}

// 응답 (data.shops[0])
{
  "correctedQuery": "ㅇㅗㅇㅣㅈㅣㅇㅕㄴㄴㅏㅁ",
  "suggestions": [],
  "shops": [{
    "code": "oiji_yeonnam",
    "label": "오이지 연남",
    "subLabel": "서울특별시 마포구 연희로1길 15 지층",
    "primaryCode": "QPBdjjRAZsW7iXlpkTE_Cg",
    "headImageUrl": "https://ugc-images.catchtable.co.kr/...",
    "status": "OPEN",
    "ad": null
  }]
}
```

`primaryCode`가 이후 모든 호출에서 쓰이는 **`shopRef`**, `code`가 매장 슬러그(URL/일부 엔드포인트의
경로 파라미터로 재사용, 예: `/api/user/v1/shop/oiji_yeonnam/viewed`)입니다.

#### (3단계) 예약 가능 날짜: `GET /api/reservation/v2/reserved-entry/day-slots`

쿼리: `shopRef`, `searchDate` (오늘), `searchEndDate` (오늘+30일), `availableOnly=true`

```json
{"dailyAvailabilities": [
  {"date": "2026-09-07", "remainingCount": 6, "availableStatus": "AVAILABLE", "available": true},
  {"date": "2026-09-08", "remainingCount": 6, "availableStatus": "AVAILABLE", "available": true},
  "... 최대 searchEndDate까지 ..."
]}
```

#### (3단계, 날짜 선택 후) 시간대 조회: `POST /api/reservation/v2/reserved-entry/time-slots?shopRef={shopRef}`

```json
// 요청
{"searchDate": "2026-09-07", "personCount": 1}

// 응답
{
  "operationDate": "2026-09-07",
  "notAvailableReason": null,
  "remainingCount": 6,
  "timeSlots": [
    {"operationTime": "11:30", "tableIds": ["7oqN4jesQuufPMCLmgVuug"]},
    {"operationTime": "12:30", "tableIds": ["7oqN4jesQuufPMCLmgVuug"]},
    {"operationTime": "13:30", "tableIds": ["7oqN4jesQuufPMCLmgVuug"]},
    {"operationTime": "18:00", "tableIds": ["7oqN4jesQuufPMCLmgVuug"]},
    {"operationTime": "19:00", "tableIds": ["7oqN4jesQuufPMCLmgVuug"]},
    {"operationTime": "20:00", "tableIds": ["7oqN4jesQuufPMCLmgVuug"]}
  ]
}
```

`tableId`(`7oqN4jesQuufPMCLmgVuug`)는 이 매장의 "매장 식사"라는 기본 테이블 그룹을 가리키는
고정 값으로, 매장의 좌석 구성(`tableSetting.tables[]`, 별도 매장 상세 API 응답에서 확인)에 따라
매장마다 다릅니다.

#### (4단계) 시간대 검증: `POST /api/reservation/v2/reserved-entry/validate-time-slot`

```json
// 요청
{"shopRef": "QPBdjjRAZsW7iXlpkTE_Cg", "date": "260907", "time": "1130"}   // date=YYMMDD, time=HHMM (구분자 없음)

// 응답
{"resultCode": "OK"}
```

#### (4단계) 홀드 생성(7분 타이머의 실체): `POST /api/reservation/v2/reserved-entry/shops/{shopRef}/holdings`

```json
// 요청
{"tableId": "7oqN4jesQuufPMCLmgVuug", "visitDate": "2026-09-07", "visitTime": "11:30"}

// 응답
{"id": "BOHZQKMUQWQXMSGOM7SZHQ"}
```

`id`가 곧 UI에 표시되는 "7분간 예약 찜"의 홀드 ID(`holdingId`)입니다. 서버가 이 홀드에 만료 시간을
관리하는 것으로 추정되며(정확한 TTL 값은 응답에 노출되지 않음), 이 시간 내에 등록을 완료해야 합니다.

#### (6단계) 실제 등록: `POST /api/reservation/v2/reserved-entries`

```json
// 요청
{
  "shopRef": "QPBdjjRAZsW7iXlpkTE_Cg",
  "holdingId": "BOHZQKMUQWQXMSGOM7SZHQ",
  "tableId": "7oqN4jesQuufPMCLmgVuug",
  "visitDate": "2026-09-07",
  "visitTime": "11:30",
  "totalPersonCount": 1,
  "personOptions": []
}

// 응답
{
  "shopName": "오이지 연남",
  "operationDate": "2026-09-07",
  "tableId": "7oqN4jesQuufPMCLmgVuug",
  "tableName": "매장 식사",
  "isTakeOut": false,
  "status": "CONFIRMED",
  "totalPersonCount": 1,
  "registeredAt": "2026-09-03 16:19:14",
  "confirmedAt": "2026-09-03 16:19:14",
  "visitAt": "2026-09-07 11:30:00",
  "eatingTerm": 60,
  "checkInAvailablePeriod": {"startDateTime": "2026-09-07 11:20:00", "endDateTime": "2026-09-07 12:20:00"},
  "registeredCustomerName": "<실명>",
  "reservationRef": "KqFQcAHguhj3RlWynR4G-g",
  "shopRef": "QPBdjjRAZsW7iXlpkTE_Cg"
}
```

이 호출이 성공하면 **`status: "CONFIRMED"`로 예약이 즉시 확정**됩니다(무료 이벤트 매장 기준 — 별도
결제 API 호출은 관찰되지 않음). `reservationRef`가 이후 예약 상세/취소/방문목적 API에서 쓰이는
예약 식별자입니다. `checkInAvailablePeriod`가 바로 7단계에서 언급한 "도착인증 가능 시간"(방문 시각
10분 전 ~ 방문 시각+50분)의 서버 측 근거입니다.

#### (선택) 방문 목적 설정: `PUT /api/reservation/v1/RESERVED_ENTRY/{reservationRef}/visit-purpose`

등록 자체와는 **별도의 후속 호출**입니다 (등록 응답에 방문 목적 필드가 없음 — UI에서 선택을
강제하는 것은 클라이언트 UX일 뿐, 서버는 등록과 방문 목적을 분리해서 처리).

```json
// 요청
{"visitPurposes": ["EAT_ALONE"]}   // GET /api/reservation/v1/visit-purpose 로 얻은 코드 중 선택 (3.4절 참고 위치 대신 아래 표)
```

방문 목적 코드는 `GET /api/reservation/v1/visit-purpose?reservationType=WAITING&personCount={N}`로
조회되며, 관찰된 값은 `EAT_ALONE`(혼밥) / `DRINK_ALONE`(혼술) / `TRAVEL`(여행) / `ETC`(기타) 4종입니다.

### 3.7 줄서기예약 취소

마이다이닝(`나의 예약`) → 해당 예약 상세 화면 → "줄서기예약 취소" → 확인 다이얼로그("줄서기예약을
취소할까요?") → "예약 취소"로 이어지는 플로우를 캡처했습니다(`옥동식`, 2026-10-01 11:30 예시).

`POST /api/reservation/v2/reserved-entries/{reservationRef}/cancel`

```json
// 요청 바디: 없음 (빈 객체)
{}

// 응답 — 등록 때와 동일한 예약 객체가 취소 상태로 갱신되어 돌아옴
{
  "shopName": "옥동식",
  "status": "CANCEL",
  "cancelReasonCode": "CANCEL_BY_CUSTOMER_DIRECT",
  "totalPersonCount": 1,
  "visitAt": "2026-10-01 18:00:00",
  "canceledAt": "2026-09-03 16:48:26",
  "reservationRef": "Kshlz-_jLPlrV_7BR9K6yQ",
  "shopRef": "_NcRqXWyoFy65jz7LUPCUg"
}
```

* 요청 바디가 완전히 빈 객체(`{}`)인 것으로 보아, 취소 사유 등 추가 입력 없이 단순 상태 전이만
  일으키는 엔드포인트입니다.
* `cancelReasonCode: "CANCEL_BY_CUSTOMER_DIRECT"` — 사용자가 앱에서 직접 취소했음을 나타내는 코드.
  이름 패턴상 무단취소(노쇼)나 매장측 취소 등 다른 사유 코드도 존재할 것으로 추정되지만, 이번
  분석에서는 관찰하지 못했습니다.
* 취소된 예약은 `GET /api/reservation/v2/reserved-entries/{reservationRef}`로 조회해도 동일하게
  `status: "CANCEL"`을 반환합니다 — 별도의 "취소 내역" 전용 API가 아니라 같은 리소스의 상태 필드로
  구분되는 구조입니다.

### 3.8 내 예약 목록 조회

마이다이닝(`나의 예약`) 탭의 "방문예정" / "방문완료" / "취소/노쇼" 세 하위 탭은 모두 같은 엔드포인트를
`statusGroup` 파라미터만 바꿔 호출합니다.

`GET /api/v4/user/reservations/_list?statusGroup={PLANNED|COMPLETE|CANCEL}&sortCode={ASC|DESC}&size={n}`

* `statusGroup=PLANNED` — "방문예정" (홈 화면에서는 `sortCode=ASC`로 관찰됨)
* `statusGroup=CANCEL` — "취소/노쇼" (`sortCode=DESC`로 관찰됨, 최근 취소 순)
* `size`는 페이지 크기(관찰값 10) — 응답의 `data.hasMore`/`data.scrollKey`로 다음 페이지를 이어받는
  커서 기반 페이지네이션으로 보입니다.

응답 `data.items[]`의 각 원소는 예약 상세(3.6절의 등록 응답)와는 다른, 좀 더 중첩된 구조입니다:

```json
{
  "reservationType": "RESERVED_ENTRY",
  "reservationRef": "J0NIoUReeim_si05G9Q0Jg",
  "reservation": {
    "totalPersonCount": 1,
    "isConfirmed": true,
    "isNoShow": false,
    "visitAt": "2026-09-07 11:30:00",
    "reservedEntry": { "reservedEntryStatus": "CANCEL", "tableName": "매장 식사", "eatingTerm": 60 }
  },
  "shop": { "shopRef": "...", "shopName": "오이지 연남", "catchtableUrlPath": "oiji_yeonnam", "...": "..." },
  "reviewStatus": { "validToWriteReview": false, "...": "..." },
  "reservationVisitPurposeResult": { "visitPurposes": ["EAT_ALONE"] },
  "reservationAvailability": { "waiting": false, "reservedEntry": true }
}
```

이 문서를 작성한 시점 기준 `statusGroup=CANCEL` 조회 결과, 이번 세션에서 만들었던 4건의 줄서기예약이
전부 확인됩니다 — 오이지 연남 2026-09-07 2건(동일 매장/시간에 두 번 등록·취소를 반복한 재현 테스트),
오이지 연남 2026-09-09 1건, 옥동식 2026-10-01 1건. 각각 `reservedEntryStatus: "CANCEL"`이며,
`statusGroup=PLANNED` 조회 결과는 0건(빈 배열) — 현재 활성 줄서기예약이 없는 상태입니다.

#### 재현 가능한 순수 API 클라이언트

이 전체 흐름(3.1절 로그인 포함)은 Waydroid/Frida/UI 자동화 없이 **순수 HTTP 요청만으로 재현**되며,
`examples/reservation-catchtable/reservation-catchtable.py`로 실제 검증했습니다(로그인 → 검색 →
시간대 조회 → 검증 → 홀드 → 등록 → 방문목적 → 취소 → **목록 조회**까지 전부 실제 API로 성공).
비밀번호 암호화(3.1절의 JSEncrypt/RSA)와 `x-ct-a` 쿠키 세션 유지만 올바르게 구현하면 WebView/앱
없이도 동일한 API를 그대로 호출할 수 있다는 뜻입니다.

---

## 4. 정적 분석 (jadx 디컴파일)

동적 캡처(Frida/mitmproxy)로 "무엇이 오가는지"를 확인한 뒤, `jadx 1.5.6`으로 `base.apk`를 디컴파일해
"왜 그렇게 동작하는지"를 코드 레벨에서 확인했습니다 (`decompile.sh`, 결과물은
`decompiled/co.kr.catchtable.android.catchtable_app/`). 총 7,042개 클래스, 11,220개 소스 파일.

### 4.1 빌드 특성

* `AndroidManifest.xml`: `versionName=1.0.10.07190`, `minSdkVersion=23`, `targetSdkVersion=35`,
  빌드 variant는 Kotlin 메타데이터에 `"app_realRelease"`로 남아있음 (R8 릴리스 빌드).
* **`android:networkSecurityConfig` 속성이 없고**, `res/xml/`에도 `network_security_config.xml`이
  존재하지 않음 → 커스텀 신뢰 앵커/인증서 피닝 설정이 없다는 뜻이며, mitmproxy가 시스템 CA만으로
  통했던 관찰(1.1절, `MITM_CAPTURE_FINDINGS.md`)과 정확히 일치합니다.
* `android:usesCleartextTraffic="true"` — 평문 HTTP 트래픽 자체는 매니페스트 레벨에서 막혀있지 않음
  (다만 실제 관찰된 API 트래픽은 전부 HTTPS).
* `WebSettings.setMixedContentMode(0)` (`MainActivity`) — `MIXED_CONTENT_ALWAYS_ALLOW`. WebView가
  HTTPS 페이지 안에서 HTTP 리소스 로드를 허용하도록 명시적으로 완화되어 있음.

### 4.2 왜 `analyze.sh`의 OkHttp 후킹도 걸리지 않았는가

이번 세션에서 `agent/agent.js`의 `libssl.so` 후킹은 성공했지만(TLS 평문 자체는 잡힘), Java 레벨
`okhttp3.Request$Builder`/`okhttp3.internal.connection.RealCall` 후킹은 한 번도 걸리지 않았습니다
(`[SYS] okhttp request hook installed` 로그는 찍히는데 실제 `[REQ]` 라인이 안 나옴). 디컴파일로 원인이
확인됩니다: R8 full-mode로 **OkHttp/Retrofit 라이브러리 클래스 자체가 전부 리패키징**되어 있습니다.
예를 들어 실제 Retrofit 클라이언트 빌더 코드(4.3절)는 `okhttp3.OkHttpClient$Builder`,
`retrofit2.Retrofit$Builder` 대신 `I9.E`, `T1.i` 같은 난독화된 이름으로 존재합니다. 유일하게 원래
경로/이름이 살아있는 OkHttp 클래스는 `okhttp3/internal/publicsuffix/PublicSuffixDatabase`
하나뿐이었는데, 이는 OkHttp가 배포하는 consumer ProGuard 규칙이 리소스 파일(`publicsuffixes.gz`) 로딩을
위해 이 클래스만 명시적으로 `-keep` 하기 때문으로 보입니다. **즉 클래스 이름으로 후킹하는 접근은 이런
앱에서는 원천적으로 깨지며, 심볼이 아니라 (a) 네이티브 레벨 `SSL_write`/`SSL_read` 후킹이나 (b)
`OkHttpClient$Builder`가 실제로 존재하는 모든 클래스를 순회하며 `addInterceptor` 메서드 시그니처로
찾는 식의 우회가 필요합니다.**

### 4.3 네이티브 Retrofit 클라이언트 (WebView와는 별개로 실제 존재함)

WebView가 비즈니스 로직 대부분을 처리하지만, **파일 업로드 · 배너 POST · 이벤트 로깅**용으로 순수
네이티브 Retrofit 클라이언트가 따로 있습니다 (`T1/c.java`, `T1/a.java`):

```java
// T1/c.java (정적 초기화 블록, 발췌) — Retrofit baseUrl이 코드에 직접 박혀 있음
i iVar = new i(17);                 // Retrofit.Builder
iVar.e("https://ct-api.catchtable.co.kr");   // .baseUrl(...)
((ArrayList) iVar.f1575d).add(new ea.a(new com.google.gson.j()));  // GsonConverterFactory
iVar.f1573b = e5;                   // .client(okHttpClient)  (connectTimeout 10s / readTimeout 15s / writeTimeout 15s)
f6648a = iVar.g();                  // .build()
```

```java
// T1/a.java — Retrofit 서비스 인터페이스 (실제 애노테이션이 살아있음: @f=@GET, @o=@POST, @p=@PUT, @y=@Url, @t=@Query, @a=@Body)
public interface a {
    @f("/image-upload/v1/upload-specs")
    Object a(@t("desiredCount") int i, @t("pathPrefix") String s, @t("contentType") String s2, ...);

    @p                                        // PUT, 업로드용 presigned URL로 파일 전송
    Object b(@y String url, @fa.a J files, ...);

    @f("/image-upload/v1/video-upload-specs")
    Object c(@t("desiredCount") int i, @t("pathPrefix") String s, @t("contentType") String s2, ...);

    @o("/api/v4/banners")                     // ← mitmproxy 캡처에서 관찰된 것과 동일 엔드포인트
    Object d(@fa.a RequestBannerVO body, ...);

    @o                                        // POST, 동적 URL — 이벤트 로그 전송
    Object e(@y String url, @fa.a RequestEventLog body, ...);
}
```

`POST /api/v4/banners`는 5.2절 mitmproxy 캡처에서도 실제로 관찰된 엔드포인트로, 이 네이티브 코드가
그 호출의 실제 소스임을 확인할 수 있습니다. 반대로 검색/예약/줄서기/리뷰/쿠폰 등 나머지 API는 이
네이티브 인터페이스에 없으므로 **전부 WebView 안의 JS `fetch`/`XHR`에서 직접 호출**되는 것으로
확정됩니다 — 이번 앱 아키텍처 이해의 핵심 포인트입니다.

### 4.4 WebView ↔ Native JS 브릿지 프로토콜 (`CtAppHost`)

`MainActivity`가 `lollipopFixedWebView.addJavascriptInterface(this.f12979l, "CtAppHost")`로 등록하는
`H0` 클래스(파일: `co/kr/catchtable/android/H0.java`)가 JS↔네이티브 브릿지의 본체입니다. JS는

```js
window.CtAppHost.postMessage(JSON.stringify({ action: "<name>", message: "<json-string>" }))
```

형태로 단일 진입점 `postMessage(String)`을 호출하고, 네이티브는 `action` 값으로 분기합니다. 코드에서
추출한 전체 액션 카탈로그 (35개):

| 카테고리 | action 값 |
|---|---|
| 소셜 로그인 | `kakaoLogin`, `naverLogin`, `loginSuccess`, `logout` |
| 기기/식별자 | `requestDeviceId`, `getTokenWithUUID`, `requestAdjustID`, `requestAmplitudeDeviceId`, `requestAppInfo` |
| 위치 | `requestGeolocation`, `requestGeolocationPermission`, `subscribeGeolocation`, `unsubscribeGeolocation`, `subscribeHeading`, `unsubscribeHeading` |
| 권한/설정 | `requestNotificationPermissions`, `requestOpenNotificationSetting`, `requestOpenSetting`, `checkFirstAppAccess` |
| 네비게이션/외부 연동 | `openApplicationURL`, `openExternalURL`, `shareToInstagram` |
| 로컬 저장 | `getStoreData`, `saveStoreData` |
| UI/라이프사이클 | `webAppInitialized`, `informWebappConfig`, `requestWebViewVisibility`, `requestWebViewLog`, `detectScreenCapture`, `showRatingPopup`, `reloadNotification` |
| 연락처 | `requestContactList` |
| 캘린더/방문 정보 | `calendar`, `reservation_visit_calendar`, `setShopVisitInfo` |
| 미디어 업로드 | `image`, `requestRecommendMediaList`, `uploadRecommendedMedia` |

`kakaoLogin`은 서버 API가 아니라 **카카오 SDK(`UserApiClient`)를 네이티브에서 직접 호출**하고 그 결과를
콜백으로 JS에 돌려주는 구조입니다 — 즉 카카오/네이버 소셜 로그인은 WebView 안에서 OAuth 리다이렉트를
직접 하는 게 아니라 네이티브 SDK가 처리합니다 (이번 세션에서 실제 로그인은 휴대폰번호+비밀번호 방식만
사용했으므로 이 경로는 캡처하지 못했습니다). `requestDeviceId`는 `SharedPreferences`에 저장된 UUID를
그대로 반환하는데, 이 값이 곧 API 요청의 `x-device-id` 헤더(2.2절)로 쓰이는 것으로 보입니다.

### 4.5 재현 방법

```bash
./decompile.sh co.kr.catchtable.android.catchtable_app
# apk/co.kr.catchtable.android.catchtable_app/*.apk (원본 APK)
# decompiled/co.kr.catchtable.android.catchtable_app/{sources,resources}/
```

---

## 5. 캐치테이블 API 카탈로그 (기능별 분류, mitmproxy 캡처 기준)

163건 요청 / 92개 엔드포인트 중 주요 항목 (메서드 + 경로, 쿼리 생략):

### 5.1 홈 / 알림 / 뱃지

| 메서드 | 경로 |
|---|---|
| GET | `/api/v4/notifications/new` |
| GET | `/api/v4/notifications/community/new` |
| GET | `/api/community/v1/notification/dock` |
| GET | `/api/user/v1/badges/notifications` |
| GET | `/api/v3/customer-support/get-main-popup-notice` |
| GET | `/api/in-app-message-campaigns/v1/active` |

### 5.2 홈 화면 구성 (server-driven UI)

| 메서드 | 경로 |
|---|---|
| POST | `/api/display/v2/main/banners` |
| POST | `/api/display/v2/main/shortcuts` |
| POST | `/api/display/v2/main/section-layout` |
| POST | `/api/v4/banners` |
| GET | `/api/advertisement/v1/inline-banner` |
| GET | `/api/v4/promotion/{slug}`, `/api/v4/exhibitions/{slug}` |

### 5.3 예약 / 줄서기(웨이팅)

| 메서드 | 경로 |
|---|---|
| GET | `/api/v4/user/reservations/upcoming` |
| GET | `/api/v3/main/futureReservationCnt` |
| GET | `/api/v3/main/confirmableReservationState` |
| GET | `/api/v3/reservation/review-notification-count` |
| GET | `/api/v3/reservation/un-written-review-count` |
| GET | `/reservation-api/v1/waitings/statuses` |
| GET | `/api/reservation/v1/dining/unpaid-charges-lite` |
| POST | `/api/v5/autocomplete/_list` (매장 검색, 3.6절) |
| GET | `/api/reservation/v2/reserved-entry/day-slots` (예약 가능 날짜, 3.6절) |
| POST | `/api/reservation/v2/reserved-entry/time-slots` (시간대 조회, 3.6절) |
| POST | `/api/reservation/v2/reserved-entry/validate-time-slot` (3.6절) |
| POST | `/api/reservation/v2/reserved-entry/shops/{shopRef}/holdings` (홀드 생성, 3.6절) |
| POST | `/api/reservation/v2/reserved-entries` (줄서기예약 등록, 3.6절) |
| GET | `/api/reservation/v2/reserved-entries/{reservationRef}` (예약 상세 조회) |
| POST | `/api/reservation/v2/reserved-entries/{reservationRef}/cancel` (취소, 3.7절) |
| GET | `/api/reservation/v1/visit-purpose` (방문 목적 코드 조회) |
| PUT | `/api/reservation/v1/RESERVED_ENTRY/{reservationRef}/visit-purpose` (방문 목적 설정) |
| GET | `/api/v4/user/reservations/_list?statusGroup=...` (내 예약 목록: 방문예정/방문완료/취소·노쇼, 3.8절) |

### 5.4 검색 / 필터

| 메서드 | 경로 |
|---|---|
| POST | `/api/v7/search/curation/list` |
| POST | `/api/v7/search/curation/list/aggregations` |
| GET / PUT | `/api/v4/filters/my-interest-region` |
| GET | `/api/v4/filters/ct-region-filter` |
| GET | `/api/v5/filters` |

### 5.5 회원 / 프로필 / 소셜

| 메서드 | 경로 |
|---|---|
| POST | `/api/user/v1/login-via-catchtable` (상세는 3.1절) |
| GET | `/api/user/v1/profile` |
| GET | `/api/v3/user/myMain` |
| GET | `/api/v3/user/logout` |
| POST | `/api/v3/user/lastLoginTime` |
| GET | `/api/v4/users/contacts/connections` |
| GET | `/api/v4/users/anniversary` |
| GET | `/api/v3/preference/getUserPreference` |
| POST | `/api/v3/fcm/register/uuid` |

`GET /api/v3/user/logout`은 최초 mitmproxy 캡처(3절 각 예시들의 타임스탬프)에서도 관찰됐던
엔드포인트인데, 실제로는 별도 로그아웃 조작 없이도 세션이 만료/무효화되면 앱이 자동으로 이 엔드포인트를
호출하고 로그인 화면으로 돌아가는 것으로 보입니다 — 실제로 이번 로그인 재현 세션에서도, mitmproxy용
전역 프록시를 걸고 앱을 재기동했을 때 명시적으로 로그아웃 조작을 하지 않았음에도 로그인 화면이 떠 있는
상태였습니다.

### 5.6 리뷰 / 북마크 / 쿠폰 / 포인트 / 결제

| 메서드 | 경로 |
|---|---|
| GET | `/api/review/v2/users/me/reviews`, `/api/review/v2/users/me/reviews/stats` |
| GET | `/api/v3/bookmark/savedAllShopBookmarkList`, `/api/v1/collections/count` |
| GET | `/api/user/v1/coupons/count`, `/api/user/v1/coupons/auto-pay-revisit/usable(-lite)/simple` |
| GET | `/api/points/v2/point-info-lite` |
| GET | `/api/payment/v2/membership`, `/api/payment/v2/valid-cards/latest` |
| POST | `/api/user/v2/visited-shops/reminder` |

### 5.7 시스템 / 초기화

| 메서드 | 경로 |
|---|---|
| GET | `/api/v3/init` |
| GET | `/api/v3/version/jsts` |
| `OPTIONS` | 위 대부분의 엔드포인트에 대해 CORS preflight로 선행 관찰됨 |

전체 목록은 다음 명령으로 원본 로그에서 재추출할 수 있습니다:

```bash
grep -a -oE '\[REQ\] [A-Z]+ https://ct-api\.catchtable\.co\.kr[^ ?]*' \
  logs/co_kr_catchtable_android_catchtable_app_mitm_20260903_152906.log \
  | sed 's#\[REQ\] ##; s#https://ct-api.catchtable.co.kr##' | sort | uniq -c | sort -rn
```

---

## 6. 알려진 한계 (Known Limitations)

* **네이티브(Frida) TLS 후킹으로는 WebView 트래픽을 볼 수 없음**: `libwebviewchromium.so`는 BoringSSL을
  정적/비공개 가시성(hidden visibility)으로 빌드해 `SSL_*` 심볼이 export/import/symbol table 어디에도
  존재하지 않습니다(202 exports / 628 imports / 855 symbols 전수 조사, 전부 bionic/ART/NDK 계열이거나
  `OPENSSL_memory_*` 알로케이터 셔임뿐). 이 결론은 실행 중인 프로세스에 직접 attach해서 라이브로 확인한
  것이며, 추가 시간 투자(바이너리 시그니처 스캐닝 등)로도 안정적으로 해결하기 어려운 구조적 한계로
  판단됩니다. 자세한 내용은 `WEBVIEW_HOOK_FINDINGS.md`.
* **Java 레벨 OkHttp 후킹(`okhttp3.Request$Builder` 등 클래스명 기반)도 이 앱에서는 통하지 않음**:
  4.2절에서 디컴파일로 확인했듯 R8이 OkHttp/Retrofit 라이브러리 클래스 자체를 리패키징해서, 원래
  이름으로 후킹을 걸면 그런 클래스가 애초에 존재하지 않습니다. `analyze.sh`가 네이티브 SDK
  (Amplitude/Airbridge/Adjust 등) 트래픽을 잡을 수 있었던 건 그 SDK들이 상대적으로 난독화가 덜 되어
  있었기 때문이지, OkHttp 후킹 자체가 일반적으로 신뢰할 수 있다는 뜻은 아닙니다 — `libssl.so` 레벨
  후킹(또는 안 되면 mitmproxy)이 이런 종류의 앱에는 더 안정적입니다.
* **`x-ct-a` 세션 토큰의 내부 구조는 역공학하지 않음**: opaque 값으로만 확인, 서명/암호화 방식은 범위
  밖입니다.
* **홀드(holdings)의 정확한 만료 시간(TTL)은 API 응답에 노출되지 않음**: UI에는 "7분"으로 표시되지만
  (3.6절), `holdings` 응답 바디(`{"id": "..."}`)에는 만료 시각/TTL 필드가 없어 서버가 실제로 정확히
  몇 초를 적용하는지는 확인하지 못했습니다.
* **`app.catchtable.co.kr` 등 프런트엔드 서브도메인 5종의 실제 페이지 소스는 캡처하지 않음**: 이번
  분석은 API 트래픽에 집중했고, 각 마이크로프런트엔드가 서빙하는 JS 번들 자체는 분석 대상이 아니었습니다.

---

## 7. API 분석에 사용한 도구

1. **`analyze.sh` + `agent/agent.js`** (이 저장소) — Waydroid 컨테이너 부팅, frida-server 배포, 앱 프로세스
   spawn 후 `libssl.so` SSL_write/read, DNS, TCP connect, OkHttp 요청/응답을 Frida로 후킹. 캐치테이블의
   네이티브 SDK 계층(Amplitude/Airbridge/Adjust/AppsFlyer/Crashlytics) 트래픽 확인에 사용.
   로그: `logs/co_kr_catchtable_android_catchtable_app_20260903_*.log`
2. **mitmproxy (CA-in-the-middle)** — `~/.local/mitmproxy/.venv`에 설치, 생성된 CA를 Waydroid 컨테이너의
   `/system/etc/security/cacerts/`에 root로 설치, 기기 전역 HTTP 프록시(`settings put global http_proxy`)로
   전체 트래픽을 우회시켜 WebView(Chromium) 내부 BoringSSL과 무관하게 네트워크 레벨에서 복호화. 캐치테이블
   ct-api 트래픽 확인에 사용. 로그: `logs/co_kr_catchtable_android_catchtable_app_mitm_20260903_152906.log`
   (일반 탐색), `logs/co_kr_catchtable_android_catchtable_app_mitm_login_20260903_155909.log`
   (로그아웃 후 재로그인, 3.1절 로그인 API 캡처), `logs/co_kr_catchtable_android_catchtable_app_mitm_waitlist_20260903_161233.log`
   (매장 검색부터 줄서기예약 등록까지 전체 흐름, 3.6절), `logs/co_kr_catchtable_android_catchtable_app_mitm_cancel_20260903_164604.log`
   (줄서기예약 취소, 3.7절). 애드온: `mitm/addon.py`, 상세: `MITM_CAPTURE_FINDINGS.md`
3. **ADBKeyboard** (`senzhk/ADBKeyBoard`) — `adb shell input text`가 한글(비 ASCII)을 입력하지 못하는 문제를
   우회하기 위해 설치한 headless IME. `am broadcast -a ADB_INPUT_B64 --es msg <base64>`로 한글 텍스트(매장
   검색어 등)를 WebView 입력 필드에 주입하는 데 사용.
4. **jadx 1.5.6 + `decompile.sh`** (이 저장소) — `base.apk`를 pull해 정적 디컴파일. 동적 캡처로는 안 보이는
   것(네이티브 Retrofit baseURL/엔드포인트, WebView JS↔Native 브릿지 프로토콜, R8이 OkHttp 클래스를
   리패키징해서 Java 후킹이 안 통하는 이유, `network_security_config.xml` 부재 확인)을 코드 레벨에서
   규명하는 데 사용. 결과: `decompiled/co.kr.catchtable.android.catchtable_app/`, 상세는 4절.
5. **`ui/dump.sh`** (이 저장소) — `adb shell uiautomator dump` + `screencap`으로 화면 계층과 스크린샷을
   동시에 저장, 좌표 기반 UI 자동화(로그인, 매장 검색, 줄서기예약 등록)에 사용.
6. **`examples/reservation-catchtable/reservation-catchtable.py`** (이 저장소) — 캡처한 API(로그인 ~
   줄서기예약 등록/취소)를 순수 Python `urllib` + `cryptography`(RSA 암호화)로 재구현한 CLI.
   Waydroid/Frida/UI 자동화 없이 API 분석 결과가 실제로 정확한지 검증하는 용도로 작성했으며, 실행해서
   실제 로그인, 줄서기예약 등록, `--cancel`을 통한 취소, `--list`를 통한 목록 조회까지 end-to-end로
   성공을 확인했습니다.
