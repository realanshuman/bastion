#!/usr/bin/env bash
# build.sh — compile Bastion.app and package Bastion.dmg from source (Command Line Tools).
set -euo pipefail
CLT=/Library/Developer/CommandLineTools
SDK="$CLT/SDKs/MacOSX.sdk"
HERE="$(cd "$(dirname "$0")" && pwd)"
APP="$HOME/Applications/Bastion.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

echo "compiling app…"
"$CLT/usr/bin/swiftc" -parse-as-library -sdk "$SDK" -target arm64-apple-macosx14.0 -O \
  -o "$APP/Contents/MacOS/Bastion" "$HERE/app/SecurityGuard.swift"

echo "rendering icon…"
"$CLT/usr/bin/swiftc" -sdk "$SDK" -o "$HERE/app/icongen" "$HERE/app/icon.swift"
"$HERE/app/icongen" "$HERE/app/icon-1024.png"
IS="$HERE/app/AppIcon.iconset"; rm -rf "$IS"; mkdir -p "$IS"
for s in 16 32 128 256 512; do
  sips -z $s $s "$HERE/app/icon-1024.png" --out "$IS/icon_${s}x${s}.png" >/dev/null
  d=$((s*2)); sips -z $d $d "$HERE/app/icon-1024.png" --out "$IS/icon_${s}x${s}@2x.png" >/dev/null
done
cp "$HERE/app/icon-1024.png" "$IS/icon_512x512@2x.png"
iconutil -c icns "$IS" -o "$APP/Contents/Resources/AppIcon.icns"

cp "$HERE/app/Info.plist" "$APP/Contents/Info.plist"
codesign --force --deep -s - "$APP" || true
echo "built $APP"

echo "packaging dmg…"
STAGE=$(mktemp -d)/Bastion; mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"; ln -s /Applications "$STAGE/Applications"
hdiutil create -volname Bastion -srcfolder "$STAGE" -ov -format UDZO "$HOME/Bastion.dmg" >/dev/null
rm -rf "$(dirname "$STAGE")"
echo "built $HOME/Bastion.dmg"
