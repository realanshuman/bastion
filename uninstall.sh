#!/usr/bin/env bash
# uninstall.sh — stop and remove Bastion background agents. --purge also deletes the tool folder.
LA="$HOME/Library/LaunchAgents"
for lbl in io.anshuman.bastion.scan io.anshuman.bastion.watcher; do
  p="$LA/$lbl.plist"
  [ -f "$p" ] && { launchctl unload "$p" 2>/dev/null; rm -f "$p"; echo "removed $lbl"; }
done
# migrate: clean any legacy-named agents from older builds
for p in "$LA"/com.*.securityguard*.plist; do
  [ -f "$p" ] && { launchctl unload "$p" 2>/dev/null; rm -f "$p"; echo "removed legacy $(basename "$p")"; }
done
pkill -f "$HOME/.security-guard/watcher.sh" 2>/dev/null || true
echo "Bastion agents stopped."
[ "${1:-}" = "--purge" ] && { rm -rf "$HOME/.security-guard"; echo "tool folder purged."; } || echo "tool folder kept at ~/.security-guard"
