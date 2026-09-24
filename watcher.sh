#!/usr/bin/env bash
# watcher.sh v2 — active real-time defense for the config-injection infostealer family.
# Every cycle: detect + AUTO-KILL loaders and malware processes talking to a C2,
# quarantine staging artifacts, and (throttled) scan repo configs for fresh injection.
set -uo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin
G="$HOME/.security-guard"
INTERVAL="${SG_WATCH_INTERVAL:-12}"
# Known C2 infrastructure (extend as new indicators appear)
KNOWN_C2="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$HOME/.security-guard/blocklist.txt" 2>/dev/null | tr '\n' ' ')"
DEAD_DROPS="ethereum-rpc.publicnode.com eth.drpc.org eth-mainnet.public.blastapi.io"
is_ignored(){ [ -f "$G/ignore.txt" ] || return 1; while IFS= read -r pat; do case "$pat" in ""|\#*) continue;; esac; case "$1" in *"$pat"*) return 0;; esac; done < "$G/ignore.txt"; return 1; }
allowed(){ grep -qxF "$1" <(grep -vE "^\s*#|^\s*$" "$G/allowlist.txt" 2>/dev/null | awk "{print \$1}"); }
MALWARE_PROCS='^(node|next-server|npm|npx|pnpm|yarn|bun|deno)'
notify(){ osascript -e "display notification \"$1\" with title \"🛡 Bastion — live\" sound name \"Basso\"" >/dev/null 2>&1 || true; }
logline(){ echo "$(date '+%F %T')  $1" >> "$G/ALERTS.txt"; }
qmove(){ local stamp dest; stamp=$(date '+%Y%m%d-%H%M%S')
  dest="$G/quarantine/live-$stamp/$(echo "$1" | sed 's|^/||')"; mkdir -p "$(dirname "$dest")" 2>/dev/null
  if mv "$1" "$dest" 2>/dev/null; then logline "QUARANTINED [$2]: $1"; notify "Quarantined $2: $(basename "$1")"; fi; }

echo "$(date '+%F %T')  watcher v2 started (interval ${INTERVAL}s, C2 list: $KNOWN_C2)" >> "$G/logs/watcher.log"
cycle=0
while true; do
  cycle=$((cycle+1))

  # 1) LOADER PROCESSES — auto-kill. Exact marker OR any `node -e` with a huge/obfuscated arg.
  while read -r pid; do
    [ -n "$pid" ] || continue
    cmd=$(ps -o command= -p "$pid" 2>/dev/null | cut -c1-120)
    kill -9 "$pid" 2>/dev/null && { logline "KILLED loader PID $pid : $cmd"; notify "Killed loader (PID $pid)"; }
  done < <(ps -axo pid=,command= 2>/dev/null | grep -E "node([^ ]*)? +-e +.*(global\.[a-z]{1,2}=|_\\\$_[0-9a-f]{4}=|createRequire)" | grep -v grep | awk '{print $1}')

  # 2) C2 CONNECTIONS — any process to a known C2 IP. Auto-kill malware procs; alert on others.
  if command -v lsof >/dev/null 2>&1; then
    net=$(lsof -nP -i 2>/dev/null)
    for ip in $KNOWN_C2; do
      allowed "$ip" && continue
      while read -r pname pid; do
        [ -n "$pid" ] || continue
        if echo "$pname" | grep -qE "$MALWARE_PROCS"; then
          kill -9 "$pid" 2>/dev/null && { logline "KILLED $pname PID $pid → C2 $ip"; notify "Killed $pname → C2 $ip"; }
        else
          logline "ALERT: $pname (PID $pid) → C2 $ip — not auto-killed (close it manually)"; notify "$pname is talking to C2 $ip — close it"
        fi
      done < <(echo "$net" | grep -F "$ip" | grep ESTABLISHED | awk '{print $1" "$2}' | sort -u)
    done
    # dead-drop domains (resolved names in lsof)
    for dd in $DEAD_DROPS; do
      echo "$net" | grep -qi "$dd" && { logline "ALERT: connection to dead-drop $dd"; notify "Connection to $dd"; }
    done
  fi

  # 3) STAGING / BEACON / HIDDEN DIRS — quarantine on sight
  for t in /tmp /var/tmp /private/tmp "${TMPDIR:-/nonexistent}"; do
    [ -d "$t" ] || continue
    while IFS= read -r -d '' d; do qmove "$d" "staging-dir"; done < <(find "$t" -maxdepth 3 -type d -name '*$*_2[0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9]' -print0 2>/dev/null)
    [ -d "$t/.npm" ] && qmove "$t/.npm" "fake-npm-cache"
    while IFS= read -r -d '' b; do grep -qE '^[0-9]{13}$' "$b" 2>/dev/null && qmove "$b" "beacon"; done < <(find "$t" -maxdepth 1 -type f -name '.*=' -print0 2>/dev/null)
    while IFS= read -r -d '' x; do qmove "$(dirname "$x")" "harvest-bundle"; done < <(find "$t" -maxdepth 5 -type f \( -name '_sysenv.json' -o -name '_chromium_exts.txt' \) -print0 2>/dev/null)
  done
  for d in "$HOME/.node_module" "$HOME/.node_modules"; do [ -d "$d" ] && qmove "$d" "hidden-node-dir"; done

  # 4) CONFIG INJECTION (throttled ~ every 60s): scan git-repo configs for the structural signature
  if [ $((cycle % 5)) -eq 0 ]; then
    while IFS= read -r cfg; do
      is_ignored "$cfg" && continue
      L=$(awk '{if(length($0)>m)m=length($0)}END{print m+0}' "$cfg" 2>/dev/null)
      if [ "${L:-0}" -gt 500 ] || grep -qE "global\.[a-z]{1,2}='[0-9]+-|_\\\$_[0-9a-f]{4}=\(function" "$cfg" 2>/dev/null; then
        logline "ALERT: injected config detected → $cfg (do NOT run dev/build here)"; notify "Injected config: $(basename "$cfg")"
      fi
    done < <(find "$HOME" -maxdepth 5 -type d -name .git -not -path '*/node_modules/*' -not -path '*/Library/*' 2>/dev/null | sed 's|/.git$||' | while read -r r; do find "$r" -maxdepth 2 -name '*.config.*' -not -path '*/node_modules/*' 2>/dev/null; done)
  fi

  sleep "$INTERVAL"
done
