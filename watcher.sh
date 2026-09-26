#!/usr/bin/env bash
# watcher.sh v3: real-time defense for the config-injection infostealer family.
# Every cycle: auto-kill loaders and malware processes talking to a blocklisted address,
# quarantine staging artifacts, and (every ~60s) check repo configs for fresh injection.
# `watcher.sh --once` runs one full cycle and exits (tests, on-demand checks).
set -uo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin
G="$HOME/.security-guard"
. "$G/lib.sh" || { echo "watcher: missing lib.sh" >&2; exit 1; }
INTERVAL="${SG_WATCH_INTERVAL:-12}"
ONCE=0; [ "${1:-}" = "--once" ] && ONCE=1
MALWARE_PROCS='^(node|next-server|npm|npx|pnpm|yarn|bun|deno)'
REPORTED="$G/logs/.config-alerts"   # configs already reported, as "path<TAB>mtime": one alert per file version
C2_SEEN=" "                         # "pid:ip" pairs already reported (processes we don't auto-kill)
allowed(){ bastion_list allowlist.txt | grep -qxF "$1"; }
notify(){ [ -n "${BASTION_NO_NOTIFY:-}" ] && return 0; osascript -e "display notification \"$1\" with title \"🛡 Bastion\" sound name \"Basso\"" >/dev/null 2>&1 || true; }
logline(){ echo "$(date '+%F %T')  $1" >> "$G/ALERTS.txt"; EVENT=1; }
LAST_RESPONSE=0
respond(){ # hand anything the reflexes caught to the responder (investigate, contain, report), at most once a minute
  local now; now=$(date +%s)
  [ -x "$G/bin/bastion" ] && [ $((now - LAST_RESPONSE)) -ge 60 ] || return 0
  LAST_RESPONSE=$now
  ( "$G/bin/bastion" respond --trigger watcher --quiet >/dev/null 2>&1 & )
}
qmove(){ # $1 path, $2 reason: moves (never deletes) into quarantine, with a manifest line for restore
  protected_path "$1" && { logline "SKIPPED quarantine of protected path $1 [$2]"; return; }
  local stamp dest; stamp=$(date '+%Y%m%d-%H%M%S')
  dest="$G/quarantine/live-$stamp/$(echo "$1" | sed 's|^/||')"; mkdir -p "$(dirname "$dest")" 2>/dev/null
  if mv "$1" "$dest" 2>/dev/null; then printf '%s\t%s\n' "$1" "$2" >> "$G/quarantine/live-$stamp/.manifest"
    logline "QUARANTINED [$2]: $1"; notify "Quarantined $2: $(basename "$1")"; fi; }

mkdir -p "$G/logs"
[ "$ONCE" = 1 ] || echo "$(date '+%F %T')  watcher v3 started (interval ${INTERVAL}s, blocklist: $(bastion_list blocklist.txt | tr '\n' ' '))" >> "$G/logs/watcher.log"
cycle=0
while true; do
  cycle=$((cycle+1))

  # 1) LOADER PROCESSES: auto-kill node started with inline code (-e/-p/--eval/--print) carrying a loader marker
  while read -r pid; do
    [ -n "$pid" ] || continue
    cmd=$(ps -o command= -p "$pid" 2>/dev/null | cut -c1-120)
    peers=$(lsof -nP -a -p "$pid" -i 2>/dev/null | awk '/->/ { split($0, a, "->"); r = a[2]; sub(/ .*/, "", r); sub(/:[0-9]+$/, "", r); print r }' | sort -u | tr '\n' ' ')
    kill -9 "$pid" 2>/dev/null && { logline "KILLED loader PID $pid : $cmd${peers:+ (connected to ${peers% })}"; notify "Killed loader (PID $pid)"; }
  done < <(loader_pids)

  # 2) C2 CONNECTIONS: exact remote-IP match with the blocklist (re-read every cycle; the allowlist wins).
  #    Malware-type processes are killed; anything else is reported once per process and address.
  if command -v lsof >/dev/null 2>&1; then
    BLOCKED=" $(bastion_list blocklist.txt | tr '\n' ' ') "
    while read -r pname pid rip; do
      [ -n "$rip" ] || continue
      case "$BLOCKED" in *" $rip "*) ;; *) continue;; esac
      allowed "$rip" && continue
      if echo "$pname" | grep -qE "$MALWARE_PROCS"; then
        kill -9 "$pid" 2>/dev/null && { logline "KILLED $pname PID $pid → C2 $rip"; notify "Killed $pname → C2 $rip"; }
      else
        case "$C2_SEEN" in *" $pid:$rip "*) continue;; esac
        C2_SEEN="$C2_SEEN$pid:$rip "
        logline "ALERT: $pname (PID $pid) → C2 $rip (not auto-killed, close it by hand)"; notify "$pname is talking to C2 $rip. Close it."
      fi
    done < <(remote_peers)
  fi

  # 3) STAGING / BEACON / HARVEST / HIDDEN DIRS: quarantine on sight
  for t in /tmp /var/tmp /private/tmp "${TMPDIR:-/nonexistent}"; do
    [ -d "$t" ] || continue
    while IFS= read -r -d '' d; do qmove "$d" "staging-dir"; done < <(find "$t" -maxdepth 3 -type d -name '*$*_2[0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9]' -print0 2>/dev/null)
    [ -d "$t/.npm" ] && qmove "$t/.npm" "fake-npm-cache"
    while IFS= read -r -d '' b; do grep -qE '^[0-9]{13}$' "$b" 2>/dev/null && qmove "$b" "beacon"; done < <(find "$t" -maxdepth 1 -type f -name '.*=' -print0 2>/dev/null)
    # a harvest file directly in a temp root is moved on its own, never the temp folder itself
    while IFS= read -r -d '' x; do
      d=$(dirname "$x")
      if protected_path "$d" || [ "${d%/}" = "${t%/}" ]; then qmove "$x" "harvest-file"; else qmove "$d" "harvest-bundle"; fi
    done < <(find "$t" -maxdepth 5 -type f \( -name '_sysenv.json' -o -name '_chromium_exts.txt' \) -print0 2>/dev/null)
  done
  for d in "$HOME/.node_module" "$HOME/.node_modules"; do [ -d "$d" ] && qmove "$d" "hidden-node-dir"; done

  # 4) CONFIG INJECTION (every ~60s): shared rule from lib.sh; one alert per file version
  if [ "$ONCE" = 1 ] || [ $((cycle % 5)) -eq 0 ]; then
    while IFS= read -r cfg; do
      is_ignored_exact "$cfg" && continue
      r=$(config_reasons "$cfg"); [ -n "$r" ] || continue
      key="$cfg"$'\t'"$(stat -f %m "$cfg" 2>/dev/null)"
      grep -qxF "$key" "$REPORTED" 2>/dev/null && continue
      echo "$key" >> "$REPORTED"
      logline "ALERT: injected config detected → $cfg [$r] (do NOT run dev/build here)"; notify "Injected config: $(basename "$cfg")"
    done < <(find "$HOME" -maxdepth 5 -type d -name .git -not -path '*/node_modules/*' -not -path '*/Library/*' 2>/dev/null | sed 's|/.git$||' | while read -r r; do find "$r" -maxdepth 2 -name '*.config.*' -not -path '*/node_modules/*' 2>/dev/null; done)
  fi

  [ "${EVENT:-0}" = 1 ] && respond; EVENT=0
  [ "$ONCE" = 1 ] && exit 0
  sleep "$INTERVAL"
done
