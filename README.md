# android-pkg-api-analyzer

Waydroid에 설치된 임의의 Android 패키지와 API 서버 간 통신을 평문으로 캡처해
`reports/<pkg_name>_api_analysis.md` API 분석 문서로 정리하는 범용(패키지 비종속) 유틸리티.

전략: **동적 캡처(트래픽)는 Frida 우선, 실패하면 mitmproxy** + **정적 분석(코드)은 `decompile.sh`로 항상
병행**. 동적 캡처가 "무엇이 오가는지"를, 정적 분석이 "왜 그렇게 동작하는지"(base URL, 네이티브 REST
인터페이스, WebView JS 브릿지, 후킹이 막히는 이유)를 답한다.

## 0) 사전 준비

- Waydroid + adb가 호스트에 설치·구성되어 있어야 함(`sudo` 가능, `~/.android/adbkey.pub` 존재).
- **분석 대상 앱이 Waydroid에 이미 설치되어 있어야 함.** `analyze.sh`는 미설치 패키지면 즉시 중단됨.
  아직 없다면: `waydroid session start && waydroid show-full-ui`로 GUI를 띄워 Play Store에서 설치하거나,
  APK가 있으면 세션 부팅 후 `adb -s <ip>:5555 install <apk 경로>`로 사이드로드.
- 정확한 패키지명이 필요하면: `adb -s <ip>:5555 shell pm list packages | grep -i <검색어>`.

## TL;DR

```bash
# 1) Frida 캡처 (기본)
./analyze.sh <package.name>              # 앱을 정상 사용하다 Ctrl+C → logs/*.log + *.summary.txt
./ui/dump.sh <label>                     # (선택, 별도 터미널) UI 흐름 ↔ 트래픽 로그 대조용

# 2) logs/*.log 에 대상 API 호스트(SNI/DNS)가 안 잡히면 → WebView 앱, mitmproxy로 전환
./analyze.sh <package.name> --mitm       # 2절 — CA 설치/프록시 설정까지 자동화

# 3) 정적 분석은 항상 병행
./decompile.sh <package.name>            # apk/<pkg>/*.apk + decompiled/<pkg>/{sources,resources}

# 4) reports/<pkg_name>_api_analysis.md 작성 (reports/catchtable_api_analysis.md를 템플릿으로 참고)
```

## Frida vs mitmproxy

| 상황 | 방법 |
|---|---|
| 순수 네이티브 앱 (OkHttp/HttpURLConnection) | `analyze.sh` (Frida, `libssl.so` 후킹) |
| 하이브리드 앱, WebView가 기기 네트워크 스택에 편승 | `analyze.sh` — 자식 프로세스도 spawn-gating으로 자동 계측되어 대개 통함 |
| 하이브리드 앱, WebView가 자체 BoringSSL을 정적/스트립 상태로 내장 (최신 Chromium 다수) | **`analyze.sh <package.name> --mitm`** — `SSL_*` 심볼이 export/import 어디에도 없어 후킹 대상이 없음 |

판별법: `analyze.sh`로 앱을 몇 분 정상 사용한 뒤 `logs/*.log`에 대상 API 호스트가 `[SNI]`/`[DNS]`로
계속 잡히는지 확인. 최초 실행 시만 잡히고 이후 화면 전환/조회에서 전혀 안 잡히면(분석 SDK 트래픽만
보임) WebView가 별도 TLS 스택을 쓰는 것 — `--mitm`으로 전환.

## 1) Frida 캡처 (`analyze.sh`)

```bash
./analyze.sh <package.name>              # 기본 분석
./analyze.sh <package.name> --raw-tls    # TLS 원본 바이트 전체 덤프 (로그 커짐)
PKG_LOG_DIR=/other/path ./analyze.sh <package.name>   # 로그 저장 위치 변경 (기본: ./logs)
```

Waydroid 부팅 → frida-tools/frida-server 확보(`~/.local/frida`에 캐시) → `agent/agent.js` 번들링 →
adb 연결 → 대상 패키지 spawn+attach → TLS(`SSL_write`/`SSL_read`)/OkHttp/DNS/TCP 후킹. 앱을 정상
사용(로그인/검색/예약 등) 후 `Ctrl+C` → `logs/<pkg>_<timestamp>.log` + `.summary.txt` 생성. 이 단계가
`.device_ip`를 만들어 두므로 `decompile.sh`보다 먼저 최소 1회 실행해야 함.

일부 앱은 frida spawn 시점 후킹이 앱 초기화(네트워크 스택 등)와 충돌해 WebView 로드 실패 등으로
이어질 수 있음 — 그런 증상이면 2절 `--mitm` 모드로 전환.

## 2) mitmproxy 캡처 (`analyze.sh --mitm`, WebView 앱 대안)

네트워크 레벨 CA-in-the-middle이라 프로세스 내부 심볼 유무와 무관하게 동작. 아래 전체 절차를
`analyze.sh <package.name> --mitm` 한 번으로 자동화함(수동 절차는 참고용으로 아래에 남겨둠):

```bash
./analyze.sh <package.name> --mitm
```

내부 동작(`setup_adb` 이후):

1. **mitmproxy 설치**: `~/.local/mitmproxy/.venv`에 격리된 venv (없으면 자동 설치, 시스템 파이썬 안 건드림)
2. **CA 인증서 생성**: `~/.mitmproxy/mitmproxy-ca-cert.pem`이 없으면 `mitmdump`를 짧게 띄웠다 내려서 생성
3. **기기 시스템 신뢰 저장소에 CA 설치**: 해시(`openssl x509 -subject_hash_old`) 계산 → 이미 설치돼
   있으면 건너뜀 → 없으면 `/` 를 rw로 리마운트(이 Waydroid 이미지는 `/system`이 별도 마운트가 아니라
   루트 자체가 overlay라 `mount -o remount,rw /system`이 아니라 `/`를 리마운트해야 함) 후
   `/system/etc/security/cacerts/<hash>.0`로 설치
4. **기기 전역 프록시 설정**: `waydroid0` 브리지의 host측 IP를 자동 탐지해서
   `settings put global http_proxy <bridge-ip>:8888`(포트는 `MITM_PORT` 환경변수로 변경 가능 —
   8080은 host의 docker-proxy가 이미 점유하고 있을 수 있어 기본값을 8888로 씀)
5. **앱 재기동**: `am force-stop` 후 런처 액티비티로 재실행(새 프로세스가 CA/프록시를 인식하도록)
6. **`mitmdump -s mitm/addon.py` 구동** (analyze.sh와 동일한 로그 포맷): `logs/<pkg>_mitm_<timestamp>.log`

앱을 정상 사용(로그인/검색/예약 등) 후 `Ctrl+C` → mitmdump가 정상 종료됨.

**뒷정리는 스크립트가 항상 자동으로 함**: `analyze.sh`는 (Frida/`--mitm` 모드 무관하게) 종료 시
`trap ... EXIT`로 기기의 전역 프록시를 확인해서 지운다. `settings get global http_proxy`만으로는 안
잡히는 경우가 있었음(실제 겪은 문제) — Android가 프록시를 `global_http_proxy_host`/`_port` 개별 키에도
저장하는데 이게 남아있으면 `http_proxy` 조회는 `null`을 보여주면서도 ConnectivityService의
NetworkMonitor가 `generate_204` 검증을 죽은 프록시로 계속 시도하다 실패해서 **네트워크가 영영
VALIDATED되지 않고 기기 전체가 "인터넷 안 됨"으로 보이며 WebView 로드도 실패**한다. `analyze.sh`는
이제 이 개별 키까지 항상 확인해서 지우므로 정상적으로 스크립트를 통해 껐다 켜는 한 이 문제를 다시 겪지
않아야 함. 수동으로 디버깅해야 한다면:
```bash
adb -s <ip>:5555 shell settings list global | grep proxy   # http_proxy 말고 이 키들도 확인
adb -s <ip>:5555 shell settings put global http_proxy :0
adb -s <ip>:5555 shell settings delete global global_http_proxy_host
```

CA 설치를 검증할 때 기기의 **Chrome 앱**(`com.android.chrome`, WebView 컴포넌트와는 별개)으로 접속하면
"Your connection is not private" 경고가 뜰 수 있음 — Chrome은 Android 시스템 신뢰 저장소를 쓰지 않고
자체 Chrome Root Store만 신뢰하는 정책으로 전환했기 때문(구글 공식 정책, CA 설치가 잘못된 게 아님).
분석 대상 앱이 쓰는 시스템 WebView(`com.google.android.webview`)는 시스템 저장소를 그대로 신뢰하므로
영향 없음 — 캡처가 안 된다면 Chrome 창이 아니라 대상 앱 자체를 확인할 것.

인증서 피닝 앱이면 이 방식도 막힘 — `[ERR]` 라인이나 해당 호스트 연결 실패로 확인. 피닝 우회(Frida
`javax.net.ssl`/OkHttp `CertificatePinner` 후킹)는 이 프로젝트 범위 밖.

### 수동 절차 (참고용 — `--mitm`이 위 과정을 전부 대신함)

```bash
python3 -m venv ~/.local/mitmproxy/.venv && ~/.local/mitmproxy/.venv/bin/pip install -q mitmproxy
~/.local/mitmproxy/.venv/bin/mitmdump &  sleep 2; kill %1   # ~/.mitmproxy/mitmproxy-ca-cert.pem 생성

HASH=$(openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem | head -1)
sudo waydroid shell -- mount -o rw,remount /
adb -s <ip>:5555 push ~/.mitmproxy/mitmproxy-ca-cert.pem /data/local/tmp/$HASH.0
sudo waydroid shell -- cp /data/local/tmp/$HASH.0 /system/etc/security/cacerts/$HASH.0
sudo waydroid shell -- chmod 644 /system/etc/security/cacerts/$HASH.0

adb -s <ip>:5555 shell settings put global http_proxy 192.168.240.1:8888
~/.local/mitmproxy/.venv/bin/mitmdump -s mitm/addon.py \
  --set logfile=logs/<pkg>_mitm_$(date +%Y%m%d_%H%M%S).log \
  --listen-host 192.168.240.1 --listen-port 8888
# 새 프로세스가 CA/프록시를 인식하도록 앱 재기동 후 정상 사용, 끝나면 Ctrl+C

adb -s <ip>:5555 shell settings put global http_proxy :0   # 뒷정리
```

## 3) 정적 분석 (jadx 디컴파일, `decompile.sh`)

```bash
./decompile.sh <package.name>            # analyze.sh를 먼저 1회 실행해 .device_ip가 있어야 함
JADX_NO_RES=1 ./decompile.sh <package.name>   # 리소스 디코딩 생략(속도 우선)
```

기기에서 `base.apk`(+splits)를 pull해 [jadx](https://github.com/skylot/jadx)로 디컴파일(첫 실행 시
`~/.local/jadx`에 자동 설치). 결과: `apk/<pkg>/*.apk`, `decompiled/<pkg>/sources/`(Java),
`decompiled/<pkg>/resources/`(Manifest 등). 동적 캡처만으로 답하기 어려운 것들:

- **`AndroidManifest.xml`**: `networkSecurityConfig` 유무 → 없으면 시스템 CA만 신뢰, mitmproxy가 통할
  가능성 높음. `res/xml/network_security_config.xml`이 있으면 피닝 도메인 목록을 직접 확인.
- **네이티브 REST 클라이언트 존재 여부**: `grep -r "api.example.com" decompiled/<pkg>/sources`로 baseUrl이
  박힌 Retrofit/OkHttp 코드 탐색 — WebView 앱도 파일 업로드/로깅 등 일부는 네이티브 클라이언트를 쓰는
  경우가 많음.
- **WebView JS↔Native 브릿지**: `grep -rl JavascriptInterface decompiled/<pkg>/sources`로 JS가 호출 가능한
  네이티브 함수 전체 목록 확인(소셜 로그인/카메라/위치/공유 등 fetch로 안 잡히는 경로).
- **Java 레벨 Frida 후킹(`okhttp3.Request$Builder` 등)이 안 통하는 이유**: R8 full-mode 난독화 시 라이브러리
  클래스명까지 리패키징됨 — 클래스명이 아니라 `@GET(`/`retrofit2.http` 같은 애노테이션·문자열로 grep.

## UI 자동화 (`ui/dump.sh`)

```bash
./ui/dump.sh <label>     # ui/<label>_<timestamp>.xml (계층) + .png (스크린샷)
```

화면 흐름을 트래픽 로그와 대조하거나 좌표 기반 탭 자동화에 사용. 겪었던 함정:

- **탭 좌표는 매번 새 dump/screenshot에서 다시 구할 것** — Waydroid 창(freeform window) 위치가 세션마다
  바뀜. 이전 좌표 재사용 시 엉뚱한 곳을 탭함.
- **`enabled`/`checked` 속성이 화면과 다를 수 있음** — 같은 텍스트 노드가 enabled=true/false로 겹치는
  경우 있음(WebView 레이어링). 탭 후 반드시 재-dump로 상태 변화 확인.
- **`adb exec-out screencap -p`는 가끔 PNG가 깨짐**(다른 프로세스 stderr 혼입) — `screencap -p
  /sdcard/x.png && adb pull` 방식이 안전(`ui/dump.sh`는 이미 이렇게 구현됨).
- **WebView 화면은 접근성 트리가 비어 있을 수 있음** — 재시도하거나 스크린샷으로 좌표 눈대중.
- **비-ASCII 입력**: `adb shell input text`는 ASCII만 지원. [ADBKeyboard](https://github.com/senzhk/ADBKeyBoard)를
  기본 IME로 설정 → `adb shell settings put secure show_ime_with_hard_keyboard 1` → 필드 포커스 후
  `am broadcast -a ADB_INPUT_B64 --es msg <base64>`로 주입.

## 출력물 / 파일 맵

- `analyze.sh`, `agent/agent.js` — Frida 캡처 (메인 스크립트 + 패키지 비종속 에이전트). `--mitm`으로
  mitmproxy 캡처(2절)도 같은 스크립트가 처리.
- `mitm/addon.py` — mitmproxy 캡처 애드온 (`analyze.sh --mitm`이 구동)
- `decompile.sh` — jadx 정적 디컴파일
- `ui/dump.sh` — uiautomator UI 계층 + 스크린샷
- `logs/` — 캡처 원본 로그 (`_mitm_` 포함 파일명이 `--mitm` 캡처)
- `apk/<pkg>/`, `decompiled/<pkg>/` — pull한 APK / jadx 결과 (gitignored)
- `reports/<pkg_name>_api_analysis.md` — 패키지별 API 분석 문서. **분석이 끝나면 항상 이 디렉토리에 저장.**
- `examples/<pkg>/` — 분석한 API를 순수 HTTP 클라이언트로 재구현한 검증용 CLI 예제

## 분석 문서 구조 (`reports/<pkg_name>_api_analysis.md`)

`reports/catchtable_api_analysis.md`(하이브리드/WebView 앱, 92개 엔드포인트 캡처 사례)를 템플릿으로
아래 절 구성을 따를 것:

1. 개요 및 통신 아키텍처 (네이티브/WebView 여부, 캡처에 쓴 방법)
2. 인증 및 보안 체계 (공통 헤더, 토큰/세션, 피닝 여부)
3. 핵심 API 프로토콜 상세 명세 (엔드포인트별 요청/응답 예시)
4. 정적 분석 (`decompile.sh` 결과 — manifest, 네이티브 REST 클라이언트, JS 브릿지, 후킹이 막힌 이유)
5. API 카탈로그 (기능별 엔드포인트 목록)

순수 네이티브 앱(Frida만으로 충분한 경우)은 1)의 캡처 방법만 다르고 나머지 구조는 동일하게 적용.
