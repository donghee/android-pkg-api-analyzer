#!/bin/bash
#
# decompile.sh — android-pkg-api-analyzer
#
# Waydroid에 설치된 임의의 패키지의 APK(들)를 pull해서 jadx로 정적 디컴파일한다.
# 동적 캡처(analyze.sh / mitmproxy)로 "무엇이 오가는지"를 본 뒤, 이 스크립트로
# "왜 그렇게 동작하는지"(베이스 URL 상수, 네이티브 Retrofit/OkHttp 인터페이스,
# WebView JS↔Native 브릿지 프로토콜, network security config, 후킹이 왜 안 통하는지 등)를
# 코드 레벨에서 확인하는 용도.
#
# 사용법:
#   ./decompile.sh <package.name>
#   JADX_NO_RES=1 ./decompile.sh <package.name>   # 리소스 디코딩 생략(속도 우선, 코드만)
#
# 결과:
#   apk/<package.name>/*.apk           — pull한 원본 APK(들) (base + split)
#   decompiled/<package.name>/sources  — 디컴파일된 Java 소스
#   decompiled/<package.name>/resources/AndroidManifest.xml, res/xml/network_security_config.xml 등
#
# 분석 시 우선적으로 확인할 것 (자세한 예시는 reports/catchtable_api_analysis.md "정적 분석" 절 참고):
#   - AndroidManifest.xml: networkSecurityConfig, usesCleartextTraffic, 액티비티/서비스 목록
#   - res/xml/network_security_config.xml (있다면): 인증서 피닝 여부
#   - 소스 전역에서 API 베이스 URL 문자열 grep (예: 도메인명으로 grep)
#   - WebView 앱이면: JavascriptInterface 애노테이션이 붙은 클래스 (JS↔Native 브릿지 프로토콜)
#   - retrofit2.http.* / okhttp3.* 애노테이션이 붙은 인터페이스 (네이티브 REST 클라이언트가 있다면)
#   - 이 문자열들이 원래 패키지 경로로 안 잡히면 R8 obfuscation으로 리패키징된 것 — 클래스명이 아니라
#     애노테이션/문자열 리터럴로 grep해야 함 (예: "@GET(" 대신 클래스 짧은 이름 "@f(" 식으로 나타남)

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PKG="${1:-}"
if [ -z "$PKG" ]; then
  echo "usage: $0 <package.name>" >&2
  exit 1
fi

APK_DIR="$SCRIPT_DIR/apk/$PKG"
OUT_DIR="$SCRIPT_DIR/decompiled/$PKG"
JADX_HOME="${JADX_HOME:-$HOME/.local/jadx}"
JADX_BIN="$JADX_HOME/bin/jadx"

install_jadx() {
  [ -x "$JADX_BIN" ] && return 0
  echo "installing jadx into $JADX_HOME ..." >&2
  local ver
  ver=$(curl -s https://api.github.com/repos/skylot/jadx/releases/latest | grep -oE '"tag_name": *"v[^"]+"' | grep -oE 'v[0-9.]+')
  mkdir -p "$JADX_HOME"
  curl -fsSL -o /tmp/jadx.zip "https://github.com/skylot/jadx/releases/download/${ver}/jadx-${ver#v}.zip"
  unzip -q -o /tmp/jadx.zip -d "$JADX_HOME"
  chmod +x "$JADX_HOME/bin/jadx" "$JADX_HOME/bin/jadx-gui" 2>/dev/null
}

pull_apks() {
  set -e
  local ip
  ip=$(cat "$SCRIPT_DIR/.device_ip" 2>/dev/null)
  [ -z "$ip" ] && { echo "no $SCRIPT_DIR/.device_ip — run analyze.sh once first to establish device connectivity" >&2; exit 1; }
  local serial="$ip:5555"

  mkdir -p "$APK_DIR"
  local paths
  paths=$(adb -s "$serial" shell pm path "$PKG" 2>/dev/null | sed 's/^package://' | tr -d '\r')
  if [ -z "$paths" ]; then
    echo "package $PKG not installed (or device unreachable) — is Waydroid session running?" >&2
    exit 1
  fi
  while IFS= read -r remote; do
    [ -z "$remote" ] && continue
    local base
    base=$(basename "$remote")
    echo "pulling $base ..." >&2
    adb -s "$serial" pull "$remote" "$APK_DIR/$base" >/dev/null
  done <<< "$paths"
}

decompile() {
  set -e
  install_jadx
  local base_apk
  base_apk=$(ls "$APK_DIR"/base.apk 2>/dev/null || ls "$APK_DIR"/*.apk | head -1)

  local res_flag=""
  [ "${JADX_NO_RES:-0}" = "1" ] && res_flag="--no-res"

  echo "decompiling $base_apk -> $OUT_DIR (this can take a few minutes for large apps) ..." >&2
  "$JADX_BIN" -d "$OUT_DIR" $res_flag "$base_apk"

  echo >&2
  echo "== quick recon ==" >&2
  if [ -f "$OUT_DIR/resources/AndroidManifest.xml" ]; then
    echo "-- manifest security-relevant attributes --" >&2
    grep -oE 'android:networkSecurityConfig="[^"]*"|android:usesCleartextTraffic="[^"]*"' \
      "$OUT_DIR/resources/AndroidManifest.xml" >&2 || echo "(none found — no custom networkSecurityConfig, so system CA store is trusted; mitmproxy CA install should work)" >&2
  fi
  echo "-- candidate JS<->Native bridge classes (WebView apps) --" >&2
  grep -rl 'JavascriptInterface' "$OUT_DIR/sources" 2>/dev/null | grep -vE '/(com/google|com/facebook|co/ab180|org/chromium)/' | head -10 >&2
  echo "-- candidate native REST client annotations (retrofit2.http / okhttp3, possibly repackaged) --" >&2
  grep -rlE '@(GET|POST|PUT|DELETE)\(|retrofit2\.http' "$OUT_DIR/sources" 2>/dev/null | head -10 >&2
}

pull_apks
decompile
