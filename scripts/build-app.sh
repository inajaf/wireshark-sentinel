#!/usr/bin/env bash
# Assemble a launchable macOS app bundle from the SwiftPM executable.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
APP_NAME="Wireshark Sentinel"
BUNDLE="$ROOT/build/$APP_NAME.app"
BINARY="WiresharkSentinel"

echo "==> building release binary"
swift build -c release --product "$BINARY"

rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/Contents/MacOS" "$BUNDLE/Contents/Resources"

cp "$ROOT/.build/release/$BINARY" "$BUNDLE/Contents/MacOS/$BINARY"

if [ ! -f "$ROOT/Assets/AppIcon.icns" ]; then
    echo "==> app icon missing; generating it"
    "$ROOT/scripts/make-icon.sh"
fi
cp "$ROOT/Assets/AppIcon.icns" "$BUNDLE/Contents/Resources/AppIcon.icns"

cat > "$BUNDLE/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key><string>en</string>
    <key>CFBundleExecutable</key><string>WiresharkSentinel</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundleIdentifier</key><string>local.sentinel.wireshark</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleName</key><string>Wireshark Sentinel</string>
    <key>CFBundleDisplayName</key><string>Wireshark Sentinel</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSPrincipalClass</key><string>NSApplication</string>
    <key>NSLocationWhenInUseUsageDescription</key>
    <string>Wireshark Sentinel uses Location access only to read the names of nearby Wi-Fi networks for the Wi-Fi diagnostics view. Scanning never joins a network or sends credentials.</string>
    <key>NSLocationUsageDescription</key>
    <string>Wireshark Sentinel uses Location access only to read the names of nearby Wi-Fi networks for the Wi-Fi diagnostics view. Scanning never joins a network or sends credentials.</string>
</dict>
</plist>
PLIST

echo "==> ad-hoc signing"
codesign --force --sign - "$BUNDLE" >/dev/null 2>&1 || echo "codesign skipped"

echo "==> built $BUNDLE"
ls -la "$BUNDLE/Contents/MacOS/"
