#!/usr/bin/env bash
# install.sh — set up Security Guard for the CURRENT user on THIS Mac.
# Portable: generates launchd plists for whoever runs it (no hardcoded username).
# Usage:  bash install.sh            # scheduled scan + live watcher
#         bash install.sh --scan     # scheduled 6h scan only
#         bash install.sh --watch    # live watcher only
set -uo pipefail
DEST="$HOME/.security-guard"
SELF="$(cd "$(dirname "$0")" && pwd)"
LA="$HOME/Library/LaunchAgents"
mkdir -p "$DEST/logs" "$DEST/quarantine" "$LA"

# copy scripts here if installing from a different folder (e.g. a downloaded copy)
if [ "$SELF" != "$DEST" ]; then
  for f in scanner.sh guard.sh watcher.sh git-guard README.md; do
    [ -f "$SELF/$f" ] && cp "$SELF/$f" "$DEST/$f"
  done
  chmod +x "$DEST"/*.sh "$DEST/git-guard" 2>/dev/null || true
fi

want_scan=1; want_watch=1
case "${1:-}" in --scan) want_watch=0;; --watch) want_scan=0;; esac

gen_plist(){ # $1 label-suffix, $2 script, $3 extra-dict-xml
  cat > "$LA/com.$(id -un).securityguard$1.plist" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.$(id -un).securityguard$1</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$DEST/$2</string>$4</array>
  <key>StandardOutPath</key><string>$DEST/logs/launchd$1.out</string>
  <key>StandardErrorPath</key><string>$DEST/logs/launchd$1.err</string>
  <key>ProcessType</key><string>Background</string><key>LowPriorityIO</key><true/><key>Nice</key><integer>10</integer>
$3
</dict></plist>
PL
}

loaded=""
if [ "$want_scan" = 1 ]; then
  gen_plist "" "guard.sh" "  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>21600</integer>" "<string>$HOME</string>"
  launchctl unload "$LA/com.$(id -un).securityguard.plist" 2>/dev/null || true
  launchctl load "$LA/com.$(id -un).securityguard.plist" && loaded="$loaded scheduled-scan"
fi
if [ "$want_watch" = 1 ]; then
  gen_plist ".watcher" "watcher.sh" "  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>10</integer>" ""
  launchctl unload "$LA/com.$(id -un).securityguard.watcher.plist" 2>/dev/null || true
  launchctl load "$LA/com.$(id -un).securityguard.watcher.plist" && loaded="$loaded live-watcher"
fi
echo "Security Guard installed for $(id -un). Active:$loaded"
echo "Tool dir: $DEST   |   Uninstall: bash $DEST/uninstall.sh"
