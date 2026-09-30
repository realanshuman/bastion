#!/bin/bash
# tools/snapshot/build.sh: builds two helpers from the app's own sources, into tools/snapshot/.build
#   snap <out dir> [home,needs,protection,…]   renders the real window and menu-bar panel offscreen, light and dark, at 2x
#                                              (run it with HOME set to a fake home; SNAP_H sets the window height)
#   sheettest                                  checks the command-line sheet is never clipped (fake HOME: it installs)
set -e
D="$(cd "$(dirname "$0")" && pwd)"; A="$(cd "$D/../../app" && pwd)"; B="$D/.build"
CLT=/Library/Developer/CommandLineTools; export DEVELOPER_DIR=$CLT
mkdir -p "$B"; sed 's/^@main$//' "$A/SecurityGuard.swift" > "$B/app_sg.swift"   # the app's own entry point would clash
APP=("$B/app_sg.swift" "$A/Theme.swift" "$A/Window.swift" "$A/Agent.swift" "$A/Guide.swift" "$A/Terminal.swift" "$A/Protection.swift")
build(){ "$CLT/usr/bin/swiftc" -sdk "$CLT/SDKs/MacOSX.sdk" -target "$(uname -m)-apple-macosx14.0" -parse-as-library "$D/$1.swift" "${APP[@]}" -o "$B/$1"; }
build snapshot & one=$!; build sheettest & two=$!; wait $one && wait $two   # either failing fails the build
echo "built $B/snapshot and $B/sheettest"
