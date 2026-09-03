#!/bin/bash
#
# analyze.sh — android-pkg-tls-analyzer
#
# Waydroid 컨테이너를 부팅하고 frida를 세팅한 뒤, 지정한 Android 패키지와
# API 서버 간의 통신 프로토콜을 상세하게 분석(로깅)한다. (TLS 복호화 후 평문)
#
# 캡처되는 내용:
#   [LOAD]    앱이 로드하는 네이티브 라이브러리 (암호/네트워크 스택 식별)
#   [DNS]     도메인 이름 해석 (호스트 -> IP)
#   [TCP]     소켓 연결 대상 (ip:port)
#   [SNI]     TLS SNI 호스트네임
#   [ALPN]    TLS에서 제시하는 프로토콜 (h2 / http/1.1)
#   [TLS-W/R] TLS 평문 바이트 (HTTP/2 프레임 자동 해석 주석)
#   [REQ]     OkHttp 요청: method, URL
#   [REQ-H]   요청 헤더 (인증, 세션 토큰 포함 전체)
#   [REQ-BODY] 요청 바디 (contentType, length) + 본문 텍스트
#   [RESP]    응답: 상태코드, 프로토콜(h2/http/1.1), method, URL
#   [RESP-H]  응답 헤더
#   [RESP-BODY] 응답 바디 (peek으로 비파괴적 읽기)
#   [JDK-*]   java.net.HttpURLConnection 사용 시 (OkHttp 이외 트래픽)
#
# 사용법:
#   ./analyze.sh <package.name>                    # 기본 분석 (TLS 원바이트 덤프는 생략)
#   ./analyze.sh <package.name> --raw-tls           # TLS 원본 바이트 전체 덤프 (로그 큼)
#   PKG_LOG_DIR=...  ./analyze.sh <package.name>    # 로그 저장 위치 변경 (기본: ./logs)
#
# 앱을 정상적으로 사용(로그인, 검색, 예약 등)하고 나서 Ctrl+C 로 종료하면
# 로그와 요약 리포트가 ./logs/ 에 남는다.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PKG="${1:-${PKG_NAME:-}}"
if [ -z "$PKG" ]; then
  echo "usage: $0 <package.name> [--raw-tls]" >&2
  exit 1
fi
shift || true

RAW_TLS="${PKG_RAW_TLS:-0}"
for arg in "$@"; do
  [ "$arg" = "--raw-tls" ] && RAW_TLS=1
done

LOG_DIR="${PKG_LOG_DIR:-$SCRIPT_DIR/logs}"
export PKG RAW_TLS LOG_DIR

# ---------- waydroid boot ----------
boot_waydroid() {
  set -e
  sudo systemctl disable waydroid-container 2>/dev/null || true
  sudo systemctl restart waydroid-container

  sudo iptables -P FORWARD ACCEPT

  waydroid session stop 2>/dev/null || true
  waydroid session start &
  waydroid show-full-ui &
}

# ---------- frida-tools (shared cache across projects) ----------
FRIDA_LOCAL=~/.local/frida
VENV=${FRIDA_LOCAL}/.venv

install_frida_tools() {
  [ -x "$VENV/bin/frida" ] || { python3 -m venv "$VENV"; "$VENV/bin/pip" install -q frida-tools; }
  FRIDA_VERSION=$("$VENV/bin/frida" --version)
}

fetch_frida_server() {
  local arch=android-x86_64
  FS_BIN="$FRIDA_LOCAL/frida-server-$FRIDA_VERSION-$arch"
  mkdir -p "$FRIDA_LOCAL"
  [ -s "$FS_BIN" ] && return 0

  local url="https://github.com/frida/frida/releases/download/$FRIDA_VERSION/frida-server-$FRIDA_VERSION-$arch.xz"
  local tmp
  tmp=$(mktemp -t frida-server-XXXXXX)
  if ! curl -fsSL "$url" | python3 -c "import sys,lzma;sys.stdout.buffer.write(lzma.decompress(sys.stdin.buffer.read()))" > "$tmp"; then
    rm -f "$tmp"
    echo "frida-server $FRIDA_VERSION download failed: $url" >&2
    return 1
  fi
  chmod 755 "$tmp"
  mv "$tmp" "$FS_BIN"

  find "$FRIDA_LOCAL" -maxdepth 1 -name "frida-server-*-$arch" ! -name "$(basename "$FS_BIN")" -delete
}

# ---------- device / adb / frida-server setup ----------
setup_device() {
  set -e
  install_frida_tools
  fetch_frida_server

  killall adb 2>/dev/null || true

  for i in $(seq 1 60); do sudo waydroid shell -- getprop sys.boot_completed 2>/dev/null | grep -q 1 && break; sleep 2; done

  IP_LINE=$(waydroid status 2>/dev/null | grep "IP address")
  IP=${IP_LINE##*:}
  IP=${IP//[[:space:]]/}
  sudo waydroid shell -- mkdir -p /data/misc/adb
  cat ~/.android/adbkey.pub | sudo waydroid shell -- sh -c 'cat > /data/misc/adb/adb_keys'
  sudo waydroid shell -- setprop ctl.restart adbd
  sleep 2
  for i in $(seq 1 15); do
    echo "Connecting to waydroid device via adb (attempt $i/15)..." >&2
    adb connect "$IP:5555" >/dev/null 2>&1
    sleep 1
    [ "$(adb -s "$IP:5555" get-state 2>/dev/null)" = "device" ] && break
    adb kill-server >/dev/null 2>&1
    adb start-server >/dev/null 2>&1
    sleep 1
  done
  adb -s "$IP:5555" forward tcp:27042 tcp:27042 >/dev/null
  echo "$IP" > "$SCRIPT_DIR/.device_ip"

  if ! sudo waydroid shell -- pm list packages 2>/dev/null | grep -q "^package:$PKG\$"; then
    echo "package $PKG not installed in waydroid, aborting" >&2
    exit 1
  fi

  RUNNING=""
  for i in $(seq 1 5); do
    echo "Starting frida-server on device (attempt $i/5)..." >&2
    RUNNING=$(sudo waydroid shell -- sh -c 'pgrep -f /data/local/tmp/frida-server' 2>/dev/null)
    [ -n "$RUNNING" ] && break
    adb -s "$IP:5555" push "$FS_BIN" /data/local/tmp/frida-server >/dev/null
    sudo waydroid shell -- chmod 755 /data/local/tmp/frida-server
    sudo waydroid shell -- sh -c '/data/local/tmp/frida-server -D'
    sleep 2
  done
  if [ -z "$RUNNING" ]; then
    echo "frida-server failed to start on device, aborting analysis" >&2
    exit 1
  fi
}

# ---------- agent build (package-agnostic, compiled once per RAW_TLS setting) ----------
AGENT_DIR="$SCRIPT_DIR/agent"
AGENT_SRC="$AGENT_DIR/agent.js"
AGENT_BUNDLE="$AGENT_DIR/agent.bundle.js"
export AGENT_BUNDLE

build_agent() {
  set -e
  [ -f "$AGENT_DIR/package.json" ] || printf '{"name":"android-pkg-tls-analyzer-agent","version":"1.0.0","private":true}\n' > "$AGENT_DIR/package.json"
  if [ ! -d "$AGENT_DIR/node_modules/frida-java-bridge" ]; then
    echo "Installing frida-java-bridge (first run only)..." >&2
    ( cd "$AGENT_DIR" && npm install --no-audit --no-fund frida-java-bridge )
  fi
  # substitute RAW_TLS flag into a throwaway copy so agent.js stays a clean template
  sed "s/__RAW_TLS__/${RAW_TLS}/" "$AGENT_SRC" > "$AGENT_DIR/.agent.generated.js"
  echo "Compiling agent bundle..." >&2
  ( cd "$AGENT_DIR" && "$VENV/bin/frida-compile" .agent.generated.js -o agent.bundle.js >/dev/null )
  rm -f "$AGENT_DIR/.agent.generated.js"
}

# ---------- protocol capture ----------
analyze_protocol() {
  build_agent
  setup_device
  mkdir -p "$LOG_DIR"

  "$VENV/bin/python3" - <<PY
import collections
import frida
import os
import signal
import sys
import time

PKG = "$PKG"
stamp = time.strftime("%Y%m%d_%H%M%S")
OUT_DIR = "$LOG_DIR"
os.makedirs(OUT_DIR, exist_ok=True)
base = PKG.replace(".", "_")
log_path = os.path.join(OUT_DIR, "%s_%s.log" % (base, stamp))
summary_path = os.path.join(OUT_DIR, "%s_%s.summary.txt" % (base, stamp))

dns_hosts = collections.Counter()
snis = collections.Counter()
tcp_endpoints = collections.Counter()
urls = collections.Counter()
statuses = collections.Counter()
protocols = collections.Counter()
err_count = 0

fh = open(log_path, "w", buffering=1)

def emit(line):
    global err_count
    print(line, flush=True)
    fh.write(line + "\n")
    if not line.startswith("["):
        return
    close = line.find("] ")
    if close < 1:
        return
    tag = line[1:close]
    rest = line[close + 2:]
    first = rest.splitlines()[0] if rest else ""
    if tag == "ERR":
        err_count += 1
    elif tag == "DNS":
        host, _, _ips = first.partition(" -> ")
        if host:
            dns_hosts[host] += 1
    elif tag == "SNI":
        snis[first.strip()] += 1
    elif tag == "TCP":
        tcp_endpoints[first.strip()] += 1
    elif tag == "REQ":
        m, _, url = first.partition(" ")
        if m and url:
            urls[m + " " + url.split("?")[0]] += 1
    elif tag == "RESP":
        p = first.split()
        if p:
            statuses[p[0]] += 1
        if len(p) > 1:
            protocols[p[1]] += 1

def write_summary():
    L = []
    def w(s=""):
        L.append(s)
    w("=" * 72)
    w("PROTOCOL ANALYSIS SUMMARY")
    w("package: %s   generated: %s" % (PKG, time.strftime("%Y-%m-%d %H:%M:%S")))
    w("=" * 72)
    w()
    w("## DNS lookups (count  domain)")
    for h, c in dns_hosts.most_common(60):
        w("  %5d  %s" % (c, h))
    w()
    w("## TLS SNI hosts (count  host)")
    for h, c in snis.most_common(60):
        w("  %5d  %s" % (c, h))
    w()
    w("## TCP endpoints (count  ip:port)")
    for ep, c in tcp_endpoints.most_common(60):
        w("  %5d  %s" % (c, ep))
    w()
    w("## Transport protocol per response (count  proto)")
    for p, c in protocols.most_common():
        w("  %5d  %s" % (c, p))
    w()
    w("## HTTP status codes (count  code)")
    for s, c in statuses.most_common():
        w("  %5d  %s" % (c, s))
    w()
    w("## Endpoints (count  METHOD path-without-query), top 100")
    for u, c in urls.most_common(100):
        w("  %5d  %s" % (c, u))
    w()
    w("hook errors logged: %d" % err_count)
    text = "\n".join(L)
    print()
    print(text)
    with open(summary_path, "w") as f:
        f.write(text + "\n")
    print("summary written to %s" % summary_path)

def on_message(message, data):
    if message.get("type") == "send":
        p = message.get("payload")
        emit(p if isinstance(p, str) else str(p))
    else:
        emit("[FRIDA-ERROR] %s" % message.get("description", message))

JS = open(os.environ["AGENT_BUNDLE"]).read()


instrumented = set()

def instrument(d, pid, label):
    if pid in instrumented:
        return
    try:
        session = d.attach(pid)
        script = session.create_script(JS)
        script.on("message", on_message)
        script.load()
        instrumented.add(pid)
        print("instrumented %s (pid %d)" % (label, pid), file=sys.stderr)
    except Exception as e:
        print("failed to instrument %s (pid %d): %s" % (label, pid, e), file=sys.stderr)

def main():
    d = frida.get_usb_device(timeout=30)

    # Many hybrid apps (WebView-shell apps in particular) push their real API
    # traffic through a separate sandboxed renderer/service process, not the
    # main app process. Spawn-gate so we catch and instrument those children
    # too (e.g. "<pkg>:sandboxed_process0", "<pkg>:webview_service").
    d.enable_spawn_gating()

    def on_child_added(child):
        label = child.identifier or ("pid-%d" % child.pid)
        print("child process spawned: %s (pid %d, parent %d)" % (label, child.pid, child.parent_pid), file=sys.stderr)
        instrument(d, child.pid, label)
        try:
            d.resume(child.pid)
        except Exception as e:
            print("failed to resume child pid %d: %s" % (child.pid, e), file=sys.stderr)

    d.on("child_added", on_child_added)

    try:
        pid = d.spawn([PKG])
    except Exception as e:
        print("failed to spawn %s: %s" % (PKG, e), file=sys.stderr)
        sys.exit(1)
    instrument(d, pid, PKG)
    d.resume(pid)

    print("== android-pkg-tls-analyzer ==", file=sys.stderr)
    print("package : %s (pid %d)" % (PKG, pid), file=sys.stderr)
    print("log     : %s" % log_path, file=sys.stderr)
    print("summary : %s  (written on Ctrl+C)" % summary_path, file=sys.stderr)
    print("use the app normally (login, search, booking...), then Ctrl+C", file=sys.stderr)
    print("watching for child/sandboxed processes (e.g. WebView renderer)...", file=sys.stderr)

    def on_sigint(signum, frame):
        write_summary()
        sys.exit(0)
    signal.signal(signal.SIGINT, on_sigint)

    while True:
        time.sleep(3600)

main()
PY
}

boot_waydroid
analyze_protocol
