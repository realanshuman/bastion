#!/usr/bin/env bash
# scanner.sh — structural + IOC scan for the config-injection supply-chain family.
# READ-ONLY. Prints findings; exit 0 = clean, 2 = findings. Never executes inspected files.
set -uo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin
ROOTS=("$@"); [ ${#ROOTS[@]} -eq 0 ] && ROOTS=("$HOME")
KNOWN_C2="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$HOME/.security-guard/blocklist.txt" 2>/dev/null | tr '\n' ' ')"; C2_IP="${KNOWN_C2%% *}"
FOUND=0
emit(){ printf '%s\n' "$*"; }
IGNORE_FILE="$HOME/.security-guard/ignore.txt"
is_ignored(){ # true if path matches a benign-reference pattern
  [ -f "$IGNORE_FILE" ] || return 1
  local pat
  while IFS= read -r pat; do
    case "$pat" in ''|\#*) continue;; esac
    case "$1" in *"$pat"*) return 0;; esac
  done < "$IGNORE_FILE"
  return 1
}
              # a finding line, machine-parseable
PRUNE='( -name node_modules -o -name .git -o -name .next -o -name dist -o -name build -o -name .cache -o -name Caches -o -name .Trash -o -name .pnpm-store -o -name .npm -o -name .security-guard -o -name Library )'

# 1. config files: createRequire, >500-char line, global.X='N-...' marker, eval/atob, huge padding
while IFS= read -r -d '' f; do
  head -3 "$f" 2>/dev/null | grep -q 'config-injection-check\|scanner.sh' && continue
  L=$(awk '{if(length($0)>m)m=length($0)}END{print m+0}' "$f" 2>/dev/null)
  r=""
  grep -q "createRequire" "$f" 2>/dev/null && cr=1 || cr=0
  [ "${L:-0}" -gt 500 ] && r="${r}longline:${L} "
  grep -qE "global\.[a-z]{1,2}[[:space:]]*=[[:space:]]*['\"][0-9]+-" "$f" 2>/dev/null && r="${r}campaign-marker "
  grep -qE '[[:space:]]{100,}[^[:space:]]' "$f" 2>/dev/null && r="${r}hidden-padding "
  [ -n "$r" ] && [ "${cr:-0}" = "1" ] && r="${r}+createRequire"
  [ -n "$r" ] && { emit "CONFIG|$f|$r"; FOUND=$((FOUND+1)); }
done < <(find "${ROOTS[@]}" -type d $PRUNE -prune -o -type f \
  \( -name '*.config.js' -o -name '*.config.mjs' -o -name '*.config.cjs' -o -name '*.config.ts' -o -name '*.config.mts' \
     -o -name '.*rc.js' -o -name '.*rc.cjs' -o -name '.*rc.mjs' -o -name 'vite.config.*' -o -name 'next.config.*' \
     -o -name 'postcss.config.*' -o -name 'tailwind.config.*' -o -name 'orval.config.*' \) -print0 2>/dev/null)

# 2. source payload body signatures (outside node_modules), skip docs/detectors
while IFS= read -r -d '' f; do is_ignored "$f" && continue; emit "SOURCE|$f|payload-body"; FOUND=$((FOUND+1)); done < <(
  find "${ROOTS[@]}" -type d $PRUNE -prune -o -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' \) -print0 2>/dev/null \
  | xargs -0 grep -laE "_\\\$_[0-9a-f]{4}[[:space:]]*=[[:space:]]*\(function[[:space:]]*\(i,[[:space:]]*p\)|global\.[a-z]{1,2}='[0-9]+-[0-9]" 2>/dev/null | tr '\n' '\0')

# 2b. npm install hooks that fetch/decode code or call a raw IP (they run automatically on install)
HOOK_RE='(curl|wget)[^"]*\|[[:space:]]*(ba|z)?sh|https?://[0-9]{1,3}(\.[0-9]{1,3}){3}|node[[:space:]]+-e[[:space:]].{150,}|base64[[:space:]]+(-d|--decode)|eval\('
while IFS= read -r -d '' f; do
  is_ignored "$f" && continue
  grep -E '"(preinstall|install|postinstall|prepare|prepublish)"[[:space:]]*:' "$f" 2>/dev/null | grep -qE "$HOOK_RE" \
    && { emit "SCRIPT|$f|install-hook"; FOUND=$((FOUND+1)); }
done < <(find "${ROOTS[@]}" -type d $PRUNE -prune -o -type f -name package.json -print0 2>/dev/null)

# 2c. editor auto-run tasks: .vscode/tasks.json with runOn=folderOpen executes when the folder is opened
while IFS= read -r -d '' f; do
  is_ignored "$f" && continue
  grep -q '"folderOpen"' "$f" 2>/dev/null && { emit "AUTORUN|$f|runs-on-folder-open"; FOUND=$((FOUND+1)); }
done < <(find "${ROOTS[@]}" -type d $PRUNE -prune -o -type f -name tasks.json -path '*/.vscode/*' -print0 2>/dev/null)

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
  for _ip in ${KNOWN_C2:-$C2_IP}; do lsof -nP -i 2>/dev/null | grep -qwF "$_ip" && { emit "NETWORK|$_ip|c2-connection"; FOUND=$((FOUND+1)); }; done
fi

[ "$FOUND" -gt 0 ] && exit 2 || exit 0
