#!/usr/bin/env bash
# build.sh: compile Bastion.app + the `bastion` CLI and package Bastion.dmg from source (Command Line Tools).
set -euo pipefail
CLT=/Library/Developer/CommandLineTools
SDK="$CLT/SDKs/MacOSX.sdk"
SWIFTC="$CLT/usr/bin/swiftc"
export DEVELOPER_DIR="$CLT"
HERE="$(cd "$(dirname "$0")" && pwd)"
APP="$HOME/Applications/Bastion.app"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Helpers" "$HERE/bin"

# universal binary (Apple silicon + Intel); $1 output, $2 minimum macOS, rest: swiftc arguments
universal(){
  local out="$1" min="$2" name; shift 2; name=$(basename "$out")
  "$SWIFTC" -O -sdk "$SDK" -target "arm64-apple-macosx$min" "$@" -o "$TMP/$name.arm64"
  "$SWIFTC" -O -sdk "$SDK" -target "x86_64-apple-macosx$min" "$@" -o "$TMP/$name.x86_64"
  lipo -create "$TMP/$name.arm64" "$TMP/$name.x86_64" -output "$out"
}

echo "compiling app…"
universal "$APP/Contents/MacOS/Bastion" 14.0 -parse-as-library "$HERE/app/SecurityGuard.swift" "$HERE/app/Theme.swift" "$HERE/app/Window.swift" "$HERE/app/Agent.swift" "$HERE/app/Guide.swift"
echo "compiling cli…"
universal "$HERE/bin/bastion" 13.0 "$HERE"/cli/*.swift
cp "$HERE/bin/bastion" "$APP/Contents/Helpers/bastion"

echo "bundling engine…"   # the app installs this into ~/.security-guard on first launch
ENG="$APP/Contents/Resources/engine"; rm -rf "$ENG"; mkdir -p "$ENG/shims"
for f in lib.sh scanner.sh guard.sh watcher.sh git-guard harden.sh install.sh uninstall.sh README.md LICENSE VERSION \
         allowlist.txt blocklist.txt ignore.txt; do cp "$HERE/$f" "$ENG/"; done
cp "$HERE/shims/"* "$ENG/shims/"

echo "rendering icon…"
"$SWIFTC" -sdk "$SDK" -o "$HERE/app/icongen" "$HERE/app/icon.swift"
"$HERE/app/icongen" "$HERE/app/icon-1024.png"
IS="$HERE/app/AppIcon.iconset"; rm -rf "$IS"; mkdir -p "$IS"
for s in 16 32 128 256 512; do
  sips -z $s $s "$HERE/app/icon-1024.png" --out "$IS/icon_${s}x${s}.png" >/dev/null
  d=$((s*2)); sips -z $d $d "$HERE/app/icon-1024.png" --out "$IS/icon_${s}x${s}@2x.png" >/dev/null
done
cp "$HERE/app/icon-1024.png" "$IS/icon_512x512@2x.png"
iconutil -c icns "$IS" -o "$APP/Contents/Resources/AppIcon.icns"

cp "$HERE/app/Info.plist" "$APP/Contents/Info.plist"
codesign --force -s - "$APP/Contents/Helpers/bastion"
codesign --force --deep -s - "$APP" || true
echo "built $APP  (cli: $HERE/bin/bastion)"

echo "packaging dmg…"
STAGE="$TMP/dmg/Bastion"; mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"; ln -s /Applications "$STAGE/Applications"
hdiutil create -volname Bastion -srcfolder "$STAGE" -ov -format UDZO "$HOME/Bastion.dmg" >/dev/null
echo "built $HOME/Bastion.dmg"
