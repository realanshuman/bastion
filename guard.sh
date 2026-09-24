#!/usr/bin/env bash
# guard.sh — runs scanner, auto-quarantines UNAMBIGUOUS artifacts, alerts on the rest.
# Safe-by-design: it QUARANTINES (moves, never deletes) only artifacts that are never
# legitimate (temp staging dirs, beacons, harvested loot, hidden ~/.node_module trees).
# It NEVER edits your repo/config files — those are ALERT-ONLY so uncommitted work is never lost.
set -uo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin
G="$HOME/.security-guard"
STAMP=$(date '+%Y%m%d-%H%M%S')
LOG="$G/logs/scan-$STAMP.log"
QDIR="$G/quarantine/$STAMP"
notify(){ osascript -e "display notification \"$1\" with title \"🛡 Security Guard\" sound name \"Basso\"" >/dev/null 2>&1 || true; }

OUT=$("$G/scanner.sh" "$@" 2>/dev/null); RC=$?
{
  echo "=== security-guard scan $STAMP ==="
  echo "roots: ${*:-$HOME}"
} > "$LOG"

if [ "$RC" -eq 0 ]; then
  echo "RESULT: CLEAN" >> "$LOG"
  # keep only last 30 clean logs tidy
  ls -1t "$G/logs"/scan-*.log 2>/dev/null | tail -n +60 | xargs rm -f 2>/dev/null || true
  exit 0
fi

echo "RESULT: $(echo "$OUT" | grep -c .) FINDING(S)" >> "$LOG"
echo "$OUT" | sed 's|^|  |' >> "$LOG"
QUARANTINED=0; ALERTED=0
while IFS='|' read -r kind path detail; do
  [ -z "$kind" ] && continue
  case "$kind" in
    STAGING|BEACON|HARVEST|HIDDENDEP)   # unambiguous → quarantine (move, preserve path)
      if [ -e "$path" ]; then
        dest="$QDIR/$(echo "$path" | sed 's|^/||')"
        mkdir -p "$(dirname "$dest")" 2>/dev/null
        if mv "$path" "$dest" 2>/dev/null; then
          echo "  QUARANTINED: $path -> $dest" >> "$LOG"; QUARANTINED=$((QUARANTINED+1))
        else
          echo "  QUARANTINE-FAILED (left in place): $path" >> "$LOG"
        fi
      fi ;;
    CONFIG|SOURCE)                      # repo files → ALERT ONLY (never auto-edit)
      echo "  ALERT (needs manual fix, not auto-touched): $path [$detail]" >> "$LOG"; ALERTED=$((ALERTED+1)) ;;
    PROCESS)
      echo "  ALERT: loader process PID(s) $path running — kill manually: kill $path" >> "$LOG"; ALERTED=$((ALERTED+1)) ;;
    NETWORK)
      echo "  ALERT: live C2 connection to $path" >> "$LOG"; ALERTED=$((ALERTED+1)) ;;
  esac
done <<< "$OUT"

MSG="$QUARANTINED quarantined, $ALERTED need your attention. See logs."
echo "SUMMARY: $MSG" >> "$LOG"
notify "$MSG"
# also drop a plain-text pointer the user will see
echo "$STAMP  $MSG  ($LOG)" >> "$G/ALERTS.txt"
exit 2
