#!/usr/bin/env bash
# scanner.sh — structural + IOC scan for the config-injection supply-chain family.
# READ-ONLY. Prints findings; exit 0 = clean, 2 = findings. Never executes inspected files.
set -uo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin
ROOTS=("$@"); [ ${#ROOTS[@]} -eq 0 ] && ROOTS=("$HOME")
C2_IP='23.27.20.187'
FOUND=0
emit(){ printf '%s\n' "$*"; }              # a finding line, machine-parseable
PRUNE='( -name node_modules -o -name .git -o -name .next -o -name dist -o -name build -o -name .cache -o -name Caches -o -name .Trash -o -name .pnpm-store -o -name .npm -o -name .security-guard -o -name Library )'

# 1. config files: createRequire, >500-char line, global.X='N-...' marker, eval/atob, huge padding
while IFS= read -r -d '' f; do
  head -3 "$f" 2>/dev/null | grep -q 'config-injection-check\|scanner.sh' && continue
  L=$(awk '{if(length($0)>m)m=length($0)}END{print m+0}' "$f" 2>/dev/null)
  r=""
  grep -q 'createRequire' "$f" 2>/dev/null && r="${r}createRequire "
  [ "${L:-0}" -gt 500 ] && r="${r}longline:${L} "
  grep -qE "global\.[a-z]{1,2}[[:space:]]*=[[:space:]]*['\"][0-9]+-" "$f" 2>/dev/null && r="${r}campaign-marker "
  grep -qE '[[:space:]]{100,}[^[:space:]]' "$f" 2>/dev/null && r="${r}hidden-padding "
  [ -n "$r" ] && { emit "CONFIG|$f|$r"; FOUND=$((FOUND+1)); }
done < <(find "${ROOTS[@]}" -type d $PRUNE -prune -o -type f \
  \( -name '*.config.js' -o -name '*.config.mjs' -o -name '*.config.cjs' -o -name '*.config.ts' -o -name '*.config.mts' \
     -o -name '.*rc.js' -o -name '.*rc.cjs' -o -name '.*rc.mjs' -o -name 'vite.config.*' -o -name 'next.config.*' \
     -o -name 'postcss.config.*' -o -name 'tailwind.config.*' -o -name 'orval.config.*' \) -print0 2>/dev/null)

# 2. source payload body signatures (outside node_modules), skip docs/detectors
while IFS= read -r -d '' f; do emit "SOURCE|$f|payload-body"; FOUND=$((FOUND+1)); done < <(
  find "${ROOTS[@]}" -type d $PRUNE -prune -o -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' \) -print0 2>/dev/null \
  | xargs -0 grep -laE "_\\\$_[0-9a-f]{4}[[:space:]]*=[[:space:]]*\(function[[:space:]]*\(i,[[:space:]]*p\)|global\.[a-z]{1,2}='[0-9]+-[0-9]" 2>/dev/null | tr '\n' '\0')

# 3. temp staging dirs / fake npm cache / beacons
for t in /tmp /var/tmp /private/tmp "${TMPDIR:-/nonexistent}"; do
  [ -d "$t" ] || continue
  while IFS= read -r -d '' d; do emit "STAGING|$d|exfil-dir-naming"; FOUND=$((FOUND+1)); done < <(find "$t" -maxdepth 3 -type d -name '*$*_2[0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9]' -print0 2>/dev/null)
  [ -d "$t/.npm" ] && { emit "STAGING|$t/.npm|fake-npm-cache"; FOUND=$((FOUND+1)); }
  while IFS= read -r -d '' b; do grep -qE '^[0-9]{13}$' "$b" 2>/dev/null && { emit "BEACON|$b|timestamp-beacon"; FOUND=$((FOUND+1)); }; done < <(find "$t" -maxdepth 1 -type f -name '.*=' -print0 2>/dev/null)
  while IFS= read -r -d '' x; do emit "HARVEST|$x|staged-loot"; FOUND=$((FOUND+1)); done < <(find "$t" -maxdepth 5 -type f \( -name '_sysenv.json' -o -name '_sysenv.env' -o -name '_chromium_exts.txt' \) -print0 2>/dev/null)
done

# 4. hidden runtime-staging node dirs in $HOME root
for d in "$HOME/.node_module" "$HOME/.node_modules"; do
  [ -d "$d" ] && { emit "HIDDENDEP|$d|hidden-node-dir"; FOUND=$((FOUND+1)); }
done

# 5. live loader process
P=$(ps -axo pid=,command= 2>/dev/null | grep -E "node([^[:space:]]*)?[[:space:]]+-e[[:space:]]+.*global\.[a-z]{1,2}[[:space:]]*=" | grep -v grep || true)
[ -n "$P" ] && { emit "PROCESS|$(echo "$P" | awk '{print $1}' | tr '\n' ',')|loader-running"; FOUND=$((FOUND+1)); }

# 6. live C2 connection
if command -v lsof >/dev/null 2>&1; then
  lsof -nP -i 2>/dev/null | grep -qF "$C2_IP" && { emit "NETWORK|$C2_IP|c2-connection"; FOUND=$((FOUND+1)); }
fi

[ "$FOUND" -gt 0 ] && exit 2 || exit 0
