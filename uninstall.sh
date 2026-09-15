#!/usr/bin/env bash
# uninstall.sh — stop and remove Security Guard's background agents for this user.
# Keeps the tool folder (scripts) unless you pass --purge.
LA="$HOME/Library/LaunchAgents"; U="$(id -un)"
for p in "$LA/com.$U.securityguard.plist" "$LA/com.$U.securityguard.watcher.plist"; do
  [ -f "$p" ] && { launchctl unload "$p" 2>/dev/null; rm -f "$p"; echo "removed $(basename "$p")"; }
done
pkill -f "$HOME/.security-guard/watcher.sh" 2>/dev/null || true
echo "background agents stopped."
[ "${1:-}" = "--purge" ] && { rm -rf "$HOME/.security-guard"; echo "tool folder purged."; } || echo "tool folder kept at ~/.security-guard (use --purge to remove)."
