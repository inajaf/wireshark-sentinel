#!/usr/bin/env bash
# Launch the app, prove all four panes rendered, and keep a screenshot of the window.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
OUT="${1:-$ROOT/build/ui-evidence}"
case "$OUT" in /*) ;; *) OUT="$ROOT/$OUT" ;; esac

# A caller-supplied output directory is removed before the run. Refuse anything
# outside build/, so a typo cannot delete something that matters.
guard_output_dir() {
  case "$1" in
    "$ROOT"/build/*|"$ROOT"/build) ;;
    *) echo "refusing to remove $1: output must live under $ROOT/build" >&2; exit 2 ;;
  esac
}
SECONDS_TO_CAPTURE="${2:-12}"
BUNDLE="$ROOT/build/Wireshark Sentinel.app"
BINARY="$BUNDLE/Contents/MacOS/WiresharkSentinel"

bash "$ROOT/scripts/build-app.sh" >/dev/null

guard_output_dir "$OUT"
rm -rf "$OUT"
mkdir -p "$OUT"

"$BINARY" --selftest "$OUT" --seconds "$SECONDS_TO_CAPTURE" >"$OUT/app.log" 2>"$OUT/app.err" &
APP_PID=$!

WINDOW_ID=""
for _ in $(seq 1 40); do
  sleep 0.5
  WINDOW_ID=$(python3 - <<'PY'
import Quartz
windows = Quartz.CGWindowListCopyWindowInfo(
    Quartz.kCGWindowListOptionOnScreenOnly | Quartz.kCGWindowListExcludeDesktopElements,
    Quartz.kCGNullWindowID,
)
for window in windows:
    owner = window.get("kCGWindowOwnerName") or ""
    if "Sentinel" in owner and window.get("kCGWindowLayer") == 0:
        print(window.get("kCGWindowNumber"))
        break
PY
)
  [ -n "$WINDOW_ID" ] && break
  kill -0 "$APP_PID" 2>/dev/null || break
done

if [ -n "$WINDOW_ID" ]; then
  # The window exists before any packet arrives. Let traffic accumulate so the
  # screenshot shows a populated packet list rather than an empty one.
  sleep 5
  screencapture -x -o -l "$WINDOW_ID" "$OUT/window.png" 2>/dev/null || true
  echo "captured window $WINDOW_ID"
else
  echo "window not found; no screenshot taken"
fi

wait "$APP_PID" || true

echo "--- app stderr ---"
cat "$OUT/app.err" || true

if [ ! -f "$OUT/ui.json" ]; then
  echo "FAIL: the app did not write $OUT/ui.json"
  exit 1
fi

echo "--- ui.json ---"
cat "$OUT/ui.json"

python3 - "$OUT/ui.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
required = {"packet-list", "packet-details", "packet-bytes", "sentinel"}
panes = set(data.get("panes", []))
missing = required - panes
print("panes rendered:", sorted(panes))
print("window:", data.get("windowWidth"), "x", data.get("windowHeight"))
if missing:
    print("FAIL: panes missing:", sorted(missing))
    sys.exit(1)
if data.get("windowWidth", 0) < 800 or data.get("windowHeight", 0) < 400:
    print("FAIL: window too small, the panes did not lay out")
    sys.exit(1)
if data.get("packets", 0) < 1:
    print("FAIL: the panes rendered but no packet reached them")
    sys.exit(1)
print(f"PASS: four panes rendered in a real window showing {data['packets']} frames")
PY
