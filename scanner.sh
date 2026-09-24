#!/usr/bin/env bash
# scanner.sh — structural + IOC scan for the config-injection supply-chain family.
# READ-ONLY. Prints one finding per line (KIND|target|detail); exit 0 = clean, 2 = findings.
# Never executes inspected files.
set -uo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin
. "$HOME/.security-guard/lib.sh" || { echo "scanner: missing lib.sh" >&2; exit 1; }
ROOTS=("$@"); [ ${#ROOTS[@]} -eq 0 ] && ROOTS=("$HOME")
FOUND=0
emit(){ printf '%s\n' "$*"; }
PRUNE='( -name node_modules -o -name .git -o -name .next -o -name dist -o -name build -o -name .cache -o -name Caches -o -name .Trash -o -name .pnpm-store -o -name .npm -o -name .security-guard -o -name Library )'

CONFIG_HITS=$'\n'   # configs already reported, so section 2 doesn't report them again as source files
# 1. build configs carrying the payload (marker, string scrambler, hidden padding, obfuscated long line)
while IFS= read -r -d '' f; do
  is_ignored_exact "$f" && continue
  r=$(config_reasons "$f")
  [ -n "$r" ] && { emit "CONFIG|$f|$r"; FOUND=$((FOUND+1)); CONFIG_HITS="$CONFIG_HITS$f"$'\n'; }
done < <(find "${ROOTS[@]}" -type d $PRUNE -prune -o -type f \
  \( -name '*.config.js' -o -name '*.config.mjs' -o -name '*.config.cjs' -o -name '*.config.ts' -o -name '*.config.mts' \
     -o -name '.*rc.js' -o -name '.*rc.cjs' -o -name '.*rc.mjs' -o -name 'vite.config.*' -o -name 'next.config.*' \
     -o -name 'postcss.config.*' -o -name 'tailwind.config.*' -o -name 'orval.config.*' \) -print0 2>/dev/null)

# 2. payload body in source files (outside node_modules); docs/tests quoting it are on the ignore list
while IFS= read -r -d '' f; do
  case "$CONFIG_HITS" in *$'\n'"$f"$'\n'*) continue;; esac
  is_ignored "$f" && continue; emit "SOURCE|$f|payload-body"; FOUND=$((FOUND+1))
done < <(
  find "${ROOTS[@]}" -type d $PRUNE -prune -o -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' \) -print0 2>/dev/null \
  | xargs -0 grep -laE "$BASTION_SCRAMBLER_RE|$BASTION_MARKER_RE" 2>/dev/null | tr '\n' '\0')

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

# 3. temp staging dirs / fake npm cache / beacons / harvested data
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

# 5. live loader process (node -e / -p / --eval / --print with a loader marker)
P=$(loader_pids | tr '\n' ',')
[ -n "$P" ] && { emit "PROCESS|${P%,}|loader-running"; FOUND=$((FOUND+1)); }

# 6. live connection to a blocklisted address (exact remote-IP match; allowlist wins)
if command -v lsof >/dev/null 2>&1; then
  BLOCKED=" $(bastion_list blocklist.txt | tr '\n' ' ') "; ALLOWED=" $(bastion_list allowlist.txt | tr '\n' ' ') "
  for rip in $(remote_peers | awk '{ print $3 }' | sort -u); do
    case "$BLOCKED" in *" $rip "*) ;; *) continue;; esac
    case "$ALLOWED" in *" $rip "*) continue;; esac
    emit "NETWORK|$rip|c2-connection"; FOUND=$((FOUND+1))
  done
fi

[ "$FOUND" -gt 0 ] && exit 2 || exit 0
