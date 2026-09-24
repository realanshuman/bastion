#!/usr/bin/env bash
# install.sh — set up Bastion background agents for the current user (fixed labels).
# Usage:  install.sh            # scheduled scan + live watcher
#         install.sh --scan     # scheduled 6h scan only
#         install.sh --watch    # live watcher only
set -uo pipefail
DEST="$HOME/.security-guard"
SELF="$(cd "$(dirname "$0")" && pwd)"
LA="$HOME/Library/LaunchAgents"
SCAN_LABEL="com.bastion.guard.scan"
WATCH_LABEL="com.bastion.guard.watcher"
mkdir -p "$DEST/logs" "$DEST/quarantine" "$LA"

if [ "$SELF" != "$DEST" ]; then
  for f in scanner.sh guard.sh watcher.sh git-guard harden.sh allowlist.txt ignore.txt README.md; do
    [ -f "$SELF/$f" ] && cp "$SELF/$f" "$DEST/$f"
  done
  mkdir -p "$DEST/shims"; cp "$SELF/shims/"* "$DEST/shims/" 2>/dev/null || true
  chmod +x "$DEST"/*.sh "$DEST/git-guard" "$DEST/shims/"* 2>/dev/null || true
fi

want_scan=1; want_watch=1
case "${1:-}" in --scan) want_watch=0;; --watch) want_scan=0;; esac

plist(){ # $1 label, $2 script, $3 extra-keys, $4 extra-args
  cat > "$LA/$1.plist" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$1</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$DEST/$2</string>$4</array>
  <key>StandardOutPath</key><string>$DEST/logs/$1.out</string>
  <key>StandardErrorPath</key><string>$DEST/logs/$1.err</string>
  <key>ProcessType</key><string>Background</string><key>LowPriorityIO</key><true/><key>Nice</key><integer>10</integer>
$3
</dict></plist>
PL
}

loaded=""
if [ "$want_scan" = 1 ]; then
  plist "$SCAN_LABEL" "guard.sh" "  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>21600</integer>" "<string>$HOME</string>"
  launchctl unload "$LA/$SCAN_LABEL.plist" 2>/dev/null || true
  launchctl load "$LA/$SCAN_LABEL.plist" && loaded="$loaded scheduled-scan"
fi
if [ "$want_watch" = 1 ]; then
  plist "$WATCH_LABEL" "watcher.sh" "  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>10</integer>" ""
  launchctl unload "$LA/$WATCH_LABEL.plist" 2>/dev/null || true
  launchctl load "$LA/$WATCH_LABEL.plist" && loaded="$loaded live-watcher"
fi
echo "Bastion agents active:$loaded"
