# lib.sh — detection rules shared by scanner.sh, watcher.sh and the execution-guard shim.
# git-guard carries its own copy of the config rule (it is installed into repos); keep the two in sync.

# Strong signs of the config-injection payload. A long line on its own is NOT one:
# real configs carry long CSP strings, safelists and inlined data.
BASTION_MARKER_RE="global\\.[a-z]{1,2}[[:space:]]*=[[:space:]]*['\"][0-9]+-[0-9]+['\"]"            # global.i='1-183'
BASTION_SCRAMBLER_RE="_\\\$_[0-9a-f]{4}[[:space:]]*=[[:space:]]*\\(function[[:space:]]*\\("            # _\$_1a2b=(function(i,p)
BASTION_OBFUSCATION_RE="_0x[0-9a-f]{4,}|(\\\\x[0-9a-f]{2}){8,}|String\\.fromCharCode|(^|[^A-Za-z0-9_\$.])(eval|atob)\\(|new Function\\(|global\\[['\"]"
# node started with inline code (-e/-p/--eval/--print, separate or joined with =) that carries a loader marker
BASTION_LOADER_RE="(^|[[:space:]])(-e|-p|-pe|--eval|--print)([[:space:]]|=).*(global\\.[a-z]{1,2}[[:space:]]*=[[:space:]]*['\"]?[0-9]+-[0-9]+|_\\\$_[0-9a-f]{4}[[:space:]]*=|global\\.r[[:space:]]*=[[:space:]]*require)"

# config_reasons FILE → space-separated reasons; empty output means the file looks clean
config_reasons(){
  local f="$1" r="" L
  L=$(awk '{ if (length($0) > m) m = length($0) } END { print m + 0 }' "$f" 2>/dev/null)
  # fast path for the common case: no long line and no strong pattern → clean after two cheap reads
  if [ "${L:-0}" -le 500 ] && ! grep -qE "$BASTION_MARKER_RE|$BASTION_SCRAMBLER_RE|[[:space:]]{100,}[^[:space:]]" "$f" 2>/dev/null; then
    return 0
  fi
  grep -qE "$BASTION_MARKER_RE" "$f" 2>/dev/null && r="${r}campaign-marker "
  grep -qE "$BASTION_SCRAMBLER_RE" "$f" 2>/dev/null && r="${r}string-scrambler "
  grep -qE '[[:space:]]{100,}[^[:space:]]' "$f" 2>/dev/null && r="${r}hidden-padding "
  if [ "${L:-0}" -gt 500 ] && awk 'length($0) > 500' "$f" 2>/dev/null | grep -qE "$BASTION_OBFUSCATION_RE"; then
    r="${r}obfuscated-line:${L} "
  fi
  [ -n "$r" ] && grep -q 'createRequire' "$f" 2>/dev/null && r="${r}+createRequire"
  printf '%s' "${r% }"
}

# npm install hooks that fetch/decode code or call a raw IP (they run automatically on install)
BASTION_HOOK_RE='(curl|wget)[^"]*\|[[:space:]]*(ba|z)?sh|https?://[0-9]{1,3}(\.[0-9]{1,3}){3}|node[[:space:]]+-e[[:space:]].{150,}|base64[[:space:]]+(-d|--decode)|eval\('
install_hook_suspicious(){ grep -E '"(preinstall|install|postinstall|prepare|prepublish)"[[:space:]]*:' "$1" 2>/dev/null | grep -qE "$BASTION_HOOK_RE"; }
# .vscode/tasks.json with runOn=folderOpen runs a command the moment the folder is opened in VS Code or Cursor
autorun_task(){ grep -q '"folderOpen"' "$1" 2>/dev/null; }

BASTION_IGNORE="${BASTION_IGNORE:-$HOME/.security-guard/ignore.txt}"   # CI points this at the base branch's .bastionignore
# benign references (docs, tests, detectors quoting a signature): any path containing an entry
is_ignored(){
  [ -f "$BASTION_IGNORE" ] || return 1
  local pat
  while IFS= read -r pat; do
    case "$pat" in ''|\#*) continue;; esac
    case "$1" in *"$pat"*) return 0;; esac
  done < "$BASTION_IGNORE"
  return 1
}
# config files are skipped only when their exact full path is listed: a broad entry like /docs/
# must never hide the config of a docs site, which runs like any other build config
is_ignored_exact(){ [ -f "$BASTION_IGNORE" ] && grep -qxF "$1" "$BASTION_IGNORE"; }

# entries of allowlist.txt / blocklist.txt (first word of each non-comment line)
bastion_list(){ grep -vE '^[[:space:]]*(#|$)' "$HOME/.security-guard/$1" 2>/dev/null | awk '{ print $1 }'; }

# "<command> <pid> <remote-ip>" for connections that are up or being opened — exact IPs, no ports or brackets
remote_peers(){
  lsof -nP -i 2>/dev/null | awk '/ESTABLISHED|SYN_SENT/ {
    if (split($0, a, "->") < 2) next
    r = a[2]; sub(/ .*/, "", r); sub(/:[0-9]+$/, "", r); gsub(/\[/, "", r); gsub(/\]/, "", r)
    print $1, $2, r }' | sort -u
}

# --- dependencies and CI ---
# tells of the self-spreading npm worms (Shai-Hulud style) inside install-time code or CI workflows
BASTION_WORM_RE='shai-?hulud|sha1-?hulud|trufflehog|webhook\.site/|bun_environment\.js|setup_bun\.js'

# packages under DIR/node_modules whose install scripts look malicious → "DEPHOOK|<package.json>|<reasons>"
deps_modules_scan(){
  local nm="$1/node_modules" pj line f reason target
  [ -d "$nm" ] || return 0
  while IFS= read -r pj; do
    line=$(grep -E '"(preinstall|install|postinstall)"[[:space:]]*:' "$pj" 2>/dev/null) || continue
    reason=""
    printf '%s' "$line" | grep -qE "$BASTION_HOOK_RE" && reason="install-script"
    printf '%s' "$line" | grep -qiE "$BASTION_WORM_RE" && reason="${reason:+$reason,}worm-marker"
    # "node setup.js" → look inside the file the install script runs
    for target in $(printf '%s' "$line" | grep -oE '(node|bun)[[:space:]]+[./A-Za-z0-9_-]+\.[cm]?js' | awk '{ print $2 }' | sort -u); do
      f="$(dirname "$pj")/$target"
      [ -f "$f" ] || continue
      if grep -qE "$BASTION_MARKER_RE|$BASTION_SCRAMBLER_RE" "$f" 2>/dev/null; then reason="${reason:+$reason,}payload:$target"
      elif grep -qiE "$BASTION_WORM_RE" "$f" 2>/dev/null; then reason="${reason:+$reason,}worm:$target"
      elif [ "$(grep -oE '_0x[0-9a-f]{4,}' "$f" 2>/dev/null | head -300 | wc -l | tr -d ' ')" -ge 300 ]; then reason="${reason:+$reason,}obfuscated:$target"
      fi
    done
    [ -n "$reason" ] && printf 'DEPHOOK|%s|%s\n' "$pj" "$reason"
  done < <(find "$nm" -maxdepth 6 -type f -name package.json 2>/dev/null | tr '\n' '\0' | xargs -0 grep -lE '"(preinstall|install|postinstall)"[[:space:]]*:' 2>/dev/null)
  return 0
}

# lockfile entries downloaded over plain http or from a raw IP (a local registry on localhost is fine) → "DEPURL|<lockfile>|<url>"
deps_lock_scan(){
  grep -oE '(resolved|tarball)"?[[:space:]:]+"?(http://[^"[:space:],}]+|https?://[0-9]{1,3}(\.[0-9]{1,3}){3}[^"[:space:],}]*)' "$1" 2>/dev/null \
    | grep -oE 'https?://[^"[:space:],}]+' | grep -vE '^https?://(localhost|127\.0\.0\.1)(:[0-9]+)?/' | sort -u | head -5 \
    | while IFS= read -r url; do printf 'DEPURL|%s|%s\n' "$1" "$url"; done
  return 0
}

# a GitHub Actions workflow that ships the repo's secrets out (how recent npm worms steal CI tokens)
workflow_exfil(){
  grep -qiE "$BASTION_WORM_RE|SHA1HULUD" "$1" 2>/dev/null && return 0
  grep -qE 'toJSON\(secrets\)' "$1" 2>/dev/null && grep -qE 'curl|wget|Invoke-WebRequest|https?://' "$1" 2>/dev/null
}

# pids of node processes whose command line is an inline-code loader
loader_pids(){ ps -axo pid=,ucomm=,args= 2>/dev/null | awk '$2 ~ /^node[0-9.]*$/' | grep -E "$BASTION_LOADER_RE" | awk '{ print $1 }'; }

# never quarantine a temp root, the home folder or the disk root
protected_path(){
  case "${1%/}" in ""|/|/tmp|/private/tmp|/var/tmp|/private/var/tmp|"$HOME"|"${TMPDIR%/}") return 0;; esac
  return 1
}
