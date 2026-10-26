#!/usr/bin/env bash
# One command that proves the whole product on this machine.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
DURATION="${1:-20}"
export PATH="/Applications/Wireshark.app/Contents/MacOS:$PATH"

echo "==> 1/4 the engine is the installed Wireshark"
if [ ! -x "/Applications/Wireshark.app/Contents/MacOS/tshark" ]; then
  echo "FAIL: Wireshark is not installed at /Applications/Wireshark.app" >&2
  exit 1
fi
/Applications/Wireshark.app/Contents/MacOS/tshark --version | head -1

echo
echo "==> 2/4 the package builds and every unit test passes"
swift build -c release 2>&1 | tail -1
swift test 2>&1 | grep -E "Test Suite '[A-Za-z]+Tests' (passed|failed)" -A1 \
  | awk '/Test Suite/{name=$3; gsub(/\x27/,"",name)} /Executed/{line=$0; sub(/^[ \t]+/,"",line); print "  " name ": " line}'
total=$(swift test 2>&1 | grep -oE "Executed [0-9]+ tests" | awk '{sum+=$2} END{print sum}')
echo "  total test cases executed: ${total:-unknown}"

echo
echo "==> 3/4 the app renders four panes in a real window"
bash scripts/verify-ui.sh "" 12 | tail -3

echo
echo "==> 4/4 live traffic is captured, identified, attributed and reported"
bash scripts/verify-live.sh "$DURATION" | tail -8

echo
echo "PASS: every claim above was checked on this machine."
