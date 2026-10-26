#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

TSHARK="/Applications/Wireshark.app/Contents/MacOS/tshark"
if [ ! -x "$TSHARK" ]; then
  echo "smoke-live: no executable tshark at $TSHARK" >&2
  exit 1
fi

interfaces="$("$TSHARK" -D 2>&1 || true)"
case "$interfaces" in
  *en0*) ;;
  *)
    echo "smoke-live: en0 is not offered by tshark -D" >&2
    exit 1
    ;;
esac

output="$(SENTINEL_LIVE_SMOKE=1 swift test --filter LiveCaptureTests 2>&1)" || {
  printf '%s\n' "$output"
  echo "smoke-live: FAIL, the live capture test did not pass" >&2
  exit 1
}
printf '%s\n' "$output"

case "$output" in
  *testLiveCaptureOnEn0YieldsParsedPackets*) ;;
  *)
    echo "smoke-live: FAIL, the live capture test did not run" >&2
    exit 1
    ;;
esac

if printf '%s' "$output" | grep -qi skipped; then
  echo "smoke-live: FAIL, the live capture test was skipped" >&2
  exit 1
fi

echo "smoke-live: PASS, en0 produced parsed packets"
