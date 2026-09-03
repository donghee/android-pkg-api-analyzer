#!/bin/bash
#
# ui/dump.sh — adb uiautomator 기반 UI 계층 덤프 + 스크린샷 캡처
#
# 사용법:
#   ./ui/dump.sh <label>
#
# ./ui/<label>_<timestamp>.xml   — uiautomator UI 계층 (좌표, resource-id, text 등)
# ./ui/<label>_<timestamp>.png   — 동일 시점 스크린샷
#
# analyze.sh 로 프로토콜 캡처를 돌리는 동안, 화면 흐름을 단계별로 함께
# 남겨서 REQ/RESP 로그와 UI 상태를 나중에 대조할 수 있게 한다.

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABEL="${1:?usage: $0 <label>}"

DEVICE_IP_FILE="$SCRIPT_DIR/../.device_ip"
if [ -f "$DEVICE_IP_FILE" ]; then
  ADB_SERIAL="$(cat "$DEVICE_IP_FILE"):5555"
else
  ADB_SERIAL="$(adb devices | awk '/device$/{print $1; exit}')"
fi

STAMP=$(date +%Y%m%d_%H%M%S)
XML_OUT="$SCRIPT_DIR/${LABEL}_${STAMP}.xml"
PNG_OUT="$SCRIPT_DIR/${LABEL}_${STAMP}.png"

adb -s "$ADB_SERIAL" shell uiautomator dump /sdcard/window_dump.xml >/dev/null
adb -s "$ADB_SERIAL" pull /sdcard/window_dump.xml "$XML_OUT" >/dev/null

# exec-out can get corrupted by stray stdout writes from other processes (e.g.
# GPU driver warnings), so capture to a file on-device and pull it instead.
adb -s "$ADB_SERIAL" shell screencap -p /sdcard/screen_dump.png >/dev/null
adb -s "$ADB_SERIAL" pull /sdcard/screen_dump.png "$PNG_OUT" >/dev/null

echo "ui  : $XML_OUT"
echo "png : $PNG_OUT"
