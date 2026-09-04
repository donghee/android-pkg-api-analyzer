#!/bin/bash
#
# native_recon.sh — android-pkg-api-analyzer
#
# apk/<pkg>/*.apk 안의 네이티브 라이브러리(lib/*/*.so)를 rabin2(radare2)로 훑는다.
# decompile.sh(jadx)는 DEX 바이트코드만 보므로 .so는 전혀 다루지 않는데, 이 스크립트가 그 공백을
# 메운다 — 특히 아래 두 가지는 동적 캡처(analyze.sh)로도 못 잡는 트래픽 사각지대라 중요:
#
#   - raw BSD 소켓(socket/connect/send*)을 직접 쓰면서 libssl/libcrypto 링크도 dlopen도 없는 라이브러리
#     → analyze.sh의 SSL_write/SSL_read 훅도, agent.js의 java.net.Socket 훅도, --mitm의 전역 프록시도
#       안 잡는 트래픽 (raw socket은 Android의 global http_proxy 설정을 아예 참조하지 않음).
#   - libssl/libcrypto는 링크하지만 SSL_write/SSL_read 심볼을 안 쓰는(또는 스트립된) 라이브러리
#     → 참고: r2book "Signatures" 장 — 심볼 있는 레퍼런스 빌드에서 zignature를 뽑아(za/zg) 대상
#       바이너리에 매칭(z/)하면 심볼 없이도 함수 오프셋을 찾을 수 있음.
#
# 그 외에도 JNI Java_* export 심볼(decompile.sh가 찾은 JavascriptInterface 브릿지와 대조용)과
# 안티 후킹/디버깅 탐지 문자열(frida/ptrace/TracerPid/xposed 등, README에 적힌 "frida spawn 훅이
# 앱 초기화와 충돌"하는 원인일 수 있음)을 함께 보고한다.
#
# 사용법:
#   ./native_recon.sh <package.name>          # apk/<pkg>/*.apk 필요 — decompile.sh를 먼저 실행해둘 것
#
# 결과:
#   decompiled/<package.name>/native/<abi>/*.so  — 추출된 라이브러리
#   stdout                                        — 라이브러리별 recon 요약 + [!] 위험 신호

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PKG="${1:-}"
if [ -z "$PKG" ]; then
  echo "usage: $0 <package.name>" >&2
  exit 1
fi

APK_DIR="$SCRIPT_DIR/apk/$PKG"
OUT_DIR="$SCRIPT_DIR/decompiled/$PKG/native"

require_rabin2() {
  command -v rabin2 >/dev/null 2>&1 && return 0
  echo "rabin2 (radare2) not found on PATH — install it first, e.g.:" >&2
  echo "  sudo apt install radare2      # Debian/Ubuntu" >&2
  echo "  or see https://github.com/radareorg/radare2#installation" >&2
  exit 1
}

extract_libs() {
  set -e
  [ -d "$APK_DIR" ] || { echo "no $APK_DIR — run decompile.sh $PKG first to pull the APK(s)" >&2; exit 1; }
  rm -rf "$OUT_DIR"
  local any_apk=0
  for apk in "$APK_DIR"/*.apk; do
    [ -f "$apk" ] || continue
    any_apk=1
    local entries
    entries=$(unzip -Z1 "$apk" 2>/dev/null | grep -E '^lib/[^/]+/[^/]+\.so$' || true)
    [ -z "$entries" ] && continue
    while IFS= read -r entry; do
      [ -z "$entry" ] && continue
      local abi
      abi=$(echo "$entry" | cut -d/ -f2)
      mkdir -p "$OUT_DIR/$abi"
      unzip -o -q -j "$apk" "$entry" -d "$OUT_DIR/$abi"
    done <<< "$entries"
  done
  if [ "$any_apk" = 0 ]; then
    echo "no *.apk found in $APK_DIR — run decompile.sh $PKG first" >&2
    exit 1
  fi
  if [ ! -d "$OUT_DIR" ] || [ -z "$(find "$OUT_DIR" -name '*.so' 2>/dev/null)" ]; then
    echo "no native libraries (lib/*/*.so) found in $APK_DIR/*.apk — pure Java/Kotlin or WebView-only app, nothing for radare2 to add here" >&2
    exit 0
  fi
}

recon_one() {
  local so="$1" rel="$2"
  echo "======================================================================"
  echo "== $rel =="
  echo "======================================================================"

  local info libs imports exports strings_out
  info=$(rabin2 -I "$so" 2>/dev/null)
  libs=$(rabin2 -l "$so" 2>/dev/null)
  imports=$(rabin2 -i "$so" 2>/dev/null)
  exports=$(rabin2 -s "$so" 2>/dev/null)
  strings_out=$(rabin2 -zz "$so" 2>/dev/null)

  echo "-- header --"
  echo "$info" | grep -E '^(arch|bits|stripped|canary|nx|relro|pic|lang|compiler)\b' | sed 's/^/  /'

  echo "-- linked libraries --"
  if [ -n "$libs" ]; then echo "$libs" | sed 's/^/  /'; else echo "  (none)"; fi

  echo "-- JNI exports (Java_*) --"
  local jni_syms
  jni_syms=$(printf '%s\n' "$exports" | grep -oE 'Java_[A-Za-z0-9_]+' | sort -u)
  if [ -n "$jni_syms" ]; then echo "$jni_syms" | sed 's/^/  /'; else echo "  (none)"; fi

  echo "-- SSL/TLS symbols (import or export) --"
  local ssl_syms
  ssl_syms=$(printf '%s\n%s\n' "$imports" "$exports" | grep -oE 'SSL_[A-Za-z_]+' | sort -u)
  if [ -n "$ssl_syms" ]; then echo "$ssl_syms" | sed 's/^/  /'; else echo "  (none found)"; fi

  echo "-- raw socket imports --"
  local sock_imports
  sock_imports=$(printf '%s\n' "$imports" | grep -oE '\b(socket|connect|sendto|recvfrom|sendmsg|recvmsg)$' | sort -u)
  if [ -n "$sock_imports" ]; then echo "$sock_imports" | sed 's/^/  /'; else echo "  (none)"; fi

  echo "-- anti-hooking / anti-debug strings --"
  local anti_hits
  # note: deliberately excludes generic "/proc/self/maps" — legit crash reporters (cronet/crashpad,
  # ASan) read it too, so on its own it is too noisy a signal to flag.
  anti_hits=$(printf '%s\n' "$strings_out" | grep -iE '\bfrida\b|frida-server|frida-gadget|ptrace|tracerpid|\bxposed\b|substrate|magisk' | head -10)
  if [ -n "$anti_hits" ]; then echo "$anti_hits"; else echo "  (none found)"; fi

  echo
  echo "-- flags --"
  local has_ssl_link has_ssl_sym has_sock_import has_dlopen flagged
  has_ssl_link=0; printf '%s' "$libs" | grep -qiE 'libssl|libcrypto' && has_ssl_link=1
  has_ssl_sym=0; [ -n "$ssl_syms" ] && has_ssl_sym=1
  has_sock_import=0; [ -n "$sock_imports" ] && has_sock_import=1
  has_dlopen=0; printf '%s' "$imports" | grep -qE '\bdlopen$' && has_dlopen=1
  flagged=0

  if [ "$has_sock_import" = 1 ] && [ "$has_ssl_link" = 0 ] && [ "$has_ssl_sym" = 0 ] && [ "$has_dlopen" = 0 ]; then
    flagged=1
    cat <<EOF
  [!] raw BSD socket calls (socket/connect/send*) with NO libssl/libcrypto link, no SSL_* symbol,
      and no dlopen: this library talks to the network on its own. It bypasses analyze.sh's
      SSL_write/SSL_read hook, agent.js's java.net.Socket hook, AND --mitm's global HTTP proxy
      (raw sockets ignore Android's global http_proxy setting). If you need this traffic, add a
      libc connect/sendto Interceptor hook to agent/agent.js gated the same way as the SSL hooks.
EOF
  fi

  if [ "$has_ssl_link" = 1 ] && [ "$has_ssl_sym" = 0 ]; then
    flagged=1
    cat <<EOF
  [!] links libssl/libcrypto but no SSL_* symbol shows up here (likely called through a stripped
      internal wrapper). analyze.sh's hook is on libssl.so's own exports so it should still see this
      library's traffic — but if it doesn't, use a zignature match (r2book "Signatures": za/zg on a
      symbol-ed reference libssl.so, then z/ against this file) to find the real call site.
EOF
  fi

  if [ -n "$anti_hits" ]; then
    flagged=1
    cat <<EOF
  [!] anti-hooking/anti-debug strings present — if analyze.sh (Frida) fails to attach or the app
      crashes/misbehaves on spawn for this package, run:
        r2 -q -c 'aaa; axt @@= \$(rabin2 -zzq $so | grep -iE "frida|ptrace|tracerpid" | cut -d\  -f1)' $so
      to find the function(s) referencing these strings, then hook/neutralize them in agent.js.
EOF
  fi

  if [ "$flagged" = 0 ]; then
    echo "  (no networking/crypto/anti-hooking signal — likely unrelated to API traffic, e.g. codec/image/analytics helper)"
  fi
  echo
}

require_rabin2
extract_libs

find "$OUT_DIR" -name '*.so' | sort | while IFS= read -r so; do
  recon_one "$so" "${so#"$OUT_DIR"/}"
done
