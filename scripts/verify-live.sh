#!/usr/bin/env bash
# Prove the whole thing on real traffic: capture live, identify, attribute, report.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
DURATION="${1:-20}"
OUT="${2:-$ROOT/build/live-evidence}"
INTERFACE="${3:-en0}"
BUNDLE="$ROOT/build/Wireshark Sentinel.app"
BINARY="$BUNDLE/Contents/MacOS/WiresharkSentinel"

bash "$ROOT/scripts/build-app.sh" >/dev/null

rm -rf "$OUT"
mkdir -p "$OUT"

echo "==> capturing $DURATION s on $INTERFACE through the installed Wireshark engine"
"$BINARY" --selftest "$OUT" --seconds "$DURATION" --interface "$INTERFACE" 2>&1 | tee "$OUT/app.err" || true

for f in sentinel-report.md sentinel-report.json ui.json; do
  if [ ! -s "$OUT/$f" ]; then
    echo "FAIL: $OUT/$f was not written"
    exit 1
  fi
done

echo
echo "==> report"
cat "$OUT/sentinel-report.md"

echo
echo "==> checks"
python3 - "$OUT" <<'PY'
import json, ipaddress, re, sys
out = sys.argv[1]
md = open(f"{out}/sentinel-report.md", encoding="utf-8").read()
data = json.load(open(f"{out}/sentinel-report.json", encoding="utf-8"))

failures = []

conversations = data.get("conversations") or data.get("assessments") or []
if not isinstance(conversations, list):
    conversations = []
if len(conversations) < 1:
    failures.append("the report carries no conversations")

def is_public(address):
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (parsed.is_private or parsed.is_loopback or parsed.is_multicast
                or parsed.is_link_local or parsed.is_unspecified)

public_seen = set()
for line in md.splitlines():
    for address in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line):
        if is_public(address):
            public_seen.add(address)
            if not re.search(r"Possibly spying|Not sure yet|Identified", line, re.I):
                failures.append(f"line names {address} with no verdict: {line.strip()[:120]}")

if not public_seen:
    failures.append("no remote public address appeared in the report; capture saw nothing off-host")

verdicts = {}
for entry in conversations:
    verdict = str(entry.get("verdict", "")).lower()
    verdicts[verdict] = verdicts.get(verdict, 0) + 1
    for key in ("endpoint", "remote"):
        value = entry.get(key)
        if isinstance(value, str) and not value:
            failures.append("a conversation carries an empty endpoint")

print(f"conversations: {len(conversations)}")
print(f"verdicts: {verdicts}")
print(f"public remotes identified in the report: {len(public_seen)}")

if failures:
    print("FAIL:")
    for item in failures:
        print(" -", item)
    sys.exit(1)
print("PASS: every remote resource in the report carries a verdict")
PY
