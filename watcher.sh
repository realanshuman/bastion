#!/usr/bin/env bash
# watcher.sh — near-real-time watch for the fast-appearing runtime IOCs.
# Cheap: only shallow temp dirs, hidden ~/.node_module trees, loader process, C2 socket.
# (Full config-file scanning stays on the 6h scheduled guard.sh + the git-guard.)
# Quarantines unambiguous artifacts on sight; notifies; logs. Loop interval 15s.
set -uo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin
G="$HOME/.security-guard"
C2_IP='23.27.20.187'
INTERVAL="${SG_WATCH_INTERVAL:-15}"
notify(){ osascript -e "display notification \"$1\" with title \"🛡 Security Guard (live)\" sound name \"Basso\"" >/dev/null 2>&1 || true; }
qmove(){ # $1 path, $2 reason
  local stamp dest; stamp=$(date '+%Y%m%d-%H%M%S')
  dest="$G/quarantine/live-$stamp/$(echo "$1" | sed 's|^/||')"
  mkdir -p "$(dirname "$dest")" 2>/dev/null
  if mv "$1" "$dest" 2>/dev/null; then
    echo "$(date '+%F %T')  QUARANTINED [$2]: $1 -> $dest" >> "$G/ALERTS.txt"
    notify "Live: quarantined $2 — $(basename "$1")"
  else
    echo "$(date '+%F %T')  DETECTED [$2] (move failed): $1" >> "$G/ALERTS.txt"
    notify "Live: detected $2 (couldn't move) — $(basename "$1")"
  fi
}
alert(){ echo "$(date '+%F %T')  ALERT [$2]: $1" >> "$G/ALERTS.txt"; notify "Live ALERT: $2 — $1"; }

echo "$(date '+%F %T')  watcher started (interval ${INTERVAL}s)" >> "$G/logs/watcher.log"
while true; do
  # 1. temp staging dirs / fake npm cache / beacons / harvested loot
  for t in /tmp /var/tmp /private/tmp "${TMPDIR:-/nonexistent}"; do
    [ -d "$t" ] || continue
    while IFS= read -r -d '' d; do qmove "$d" "staging-dir"; done < <(find "$t" -maxdepth 3 -type d -name '*$*_2[0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9]' -print0 2>/dev/null)
    [ -d "$t/.npm" ] && qmove "$t/.npm" "fake-npm-cache"
    while IFS= read -r -d '' b; do grep -qE '^[0-9]{13}$' "$b" 2>/dev/null && qmove "$b" "beacon"; done < <(find "$t" -maxdepth 1 -type f -name '.*=' -print0 2>/dev/null)
    while IFS= read -r -d '' x; do qmove "$(dirname "$x")" "harvest-bundle"; done < <(find "$t" -maxdepth 5 -type f \( -name '_sysenv.json' -o -name '_sysenv.env' -o -name '_chromium_exts.txt' \) -print0 2>/dev/null)
  done
  # 2. hidden runtime-staging node dirs
  for d in "$HOME/.node_module" "$HOME/.node_modules"; do [ -d "$d" ] && qmove "$d" "hidden-node-dir"; done
  # 3. live loader process (alert only — killing is your call)
  P=$(ps -axo pid=,command= 2>/dev/null | grep -E "node([^[:space:]]*)?[[:space:]]+-e[[:space:]]+.*global\.[a-z]{1,2}[[:space:]]*=" | grep -v grep | awk '{print $1}' | tr '\n' ',')
  [ -n "$P" ] && alert "loader PID(s) $P (kill $P)" "loader-process"
  # 4. live C2 connection (alert only)
  command -v lsof >/dev/null 2>&1 && lsof -nP -i 2>/dev/null | grep -qF "$C2_IP" && alert "connection to $C2_IP" "c2-connection"
  sleep "$INTERVAL"
done
