#!/usr/bin/env bash
# Regenerate the app icon from scripts/make-icon.swift.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
MASTER="$ROOT/Assets/AppIcon-1024.png"
ICONSET="$ROOT/build/AppIcon.iconset"
ICNS="$ROOT/Assets/AppIcon.icns"

mkdir -p "$ROOT/Assets" "$ROOT/build"
swift "$ROOT/scripts/make-icon.swift" "$MASTER"

rm -rf "$ICONSET"
mkdir -p "$ICONSET"

while read -r pixels name; do
  sips -z "$pixels" "$pixels" "$MASTER" --out "$ICONSET/$name.png" >/dev/null
done <<'SIZES'
16 icon_16x16
32 icon_16x16@2x
32 icon_32x32
64 icon_32x32@2x
128 icon_128x128
256 icon_128x128@2x
256 icon_256x256
512 icon_256x256@2x
512 icon_512x512
1024 icon_512x512@2x
SIZES

iconutil -c icns "$ICONSET" -o "$ICNS"
echo "==> wrote $ICNS"
sips -g pixelWidth -g pixelHeight "$ICNS" 2>/dev/null | tail -2 || true
