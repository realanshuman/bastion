set -u
S="${1:?usage: bash $0 <fixtures folder> <fake home folder>}"; FH="${2:?}"; REAL_ENGINE="${ROOT:-$HOME/.security-guard}"; export HOME="$FH" BASTION_NO_NOTIFY=1
E="$FH/.security-guard"; B="$E/bin/bastion"; pass=0; fail=0
ok(){ if [ "$1" = "$2" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $3: got [$1] want [$2]"; fi; }
has(){ case "$1" in *"$2"*) echo yes;; *) echo no;; esac; }
INF="$S/fixture-infected"; L600=$(printf 'x%.0s' $(seq 1 600))
# ---------- scanner ----------
out=$(bash "$E/scanner.sh" "$INF"); rc=$?
ok "$rc" 2 "scanner exit on infected"
ok "$(echo "$out" | cut -d'|' -f1 | sort | tr '\n' ' ')" "AUTORUN CONFIG SCRIPT SOURCE " "scanner kinds on infected"
ok "$(has "$out" 'CONFIG|'"$INF"'/postcss.config.mjs|campaign-marker string-scrambler +createRequire')" yes "CONFIG detail"
mkdir -p "$FH/legit"; printf '%s\n' 'import { createRequire } from "module";' 'const require = createRequire(import.meta.url);' "export default { headers: [{ value: \"default-src 'self' $L600\" }] };" > "$FH/legit/next.config.mjs"
bash "$E/scanner.sh" "$FH/legit" >/dev/null; ok "$?" 0 "legit long-line ESM config is clean"
mkdir -p "$FH/evasion"; printf '%s\n' "// scanner.sh" "export default {}; global.i='1-183';" > "$FH/evasion/vite.config.js"
ok "$(bash "$E/scanner.sh" "$FH/evasion" | cut -d'|' -f1)" CONFIG "comment mentioning scanner.sh no longer hides a config"
echo "/fixture-infected/" >> "$E/ignore.txt"
ok "$(bash "$E/scanner.sh" "$INF" | cut -d'|' -f1 | tr '\n' ' ')" "CONFIG " "broad ignore hides references but never the config"
echo "$INF/postcss.config.mjs" >> "$E/ignore.txt"
bash "$E/scanner.sh" "$INF" >/dev/null; ok "$?" 0 "exact-path ignore silences that config"
grep -vF -e "/fixture-infected/" -e "$INF/postcss.config.mjs" "$E/ignore.txt" > "$E/ig.tmp" && mv "$E/ig.tmp" "$E/ignore.txt"
# ---------- watcher --once ----------
export TMPDIR="$FH/tmp/"; echo keep > "$FH/tmp/keep.txt"; echo '{}' > "$FH/tmp/_sysenv.json"
mkdir -p "$FH/tmp/bundle"; echo x > "$FH/tmp/bundle/_chromium_exts.txt"
mkdir -p "$FH/proj/.git"; cp "$INF/postcss.config.mjs" "$FH/proj/postcss.config.mjs"
bash "$E/watcher.sh" --once
ok "$([ -f "$FH/tmp/keep.txt" ] && [ -d "$FH/tmp" ] && echo intact)" intact "temp folder itself never moved"
ok "$([ -e "$FH/tmp/_sysenv.json" ] && echo present || echo moved)" moved "harvest file in temp root quarantined alone"
ok "$([ -e "$FH/tmp/bundle" ] && echo present || echo moved)" moved "harvest bundle folder quarantined"
ok "$(grep -c 'injected config detected' "$E/ALERTS.txt")" 1 "config alert raised once"
bash "$E/watcher.sh" --once
ok "$(grep -c 'injected config detected' "$E/ALERTS.txt")" 1 "no repeat alert for the same file version"
ok "$(grep -c 'harvest-file\|harvest-bundle' "$E/ALERTS.txt")" 2 "two harvest quarantines logged"
ok "$("$B" quarantine --json | jq -r '[.items[].reason] | sort | join(",")')" "harvest-bundle,harvest-file" "quarantine manifest reasons"
unset TMPDIR
# ---------- shim ----------
for t in node npm; do printf '#!/bin/bash\necho "REAL %s $*"\n' "$t" > "$FH/fakebin/$t"; chmod +x "$FH/fakebin/$t"; done
P="$E/shims:$FH/fakebin:/usr/bin:/bin"
r=$(PATH="$P" node -e "global.i='1-183';global.r=require" 2>&1); ok "$(has "$r" blocked)" yes "shim blocks node -e loader"
r=$(PATH="$P" node "--eval=global.r=require;x()" 2>&1); ok "$(has "$r" blocked)" yes "shim blocks --eval= joined form"
r=$(PATH="$P" node --print "global.o='1-71'" 2>&1); ok "$(has "$r" blocked)" yes "shim blocks --print"
r=$(PATH="$P" node -p "1+1" 2>&1); ok "$r" "REAL node -p 1+1" "shim passes benign node -p"
r=$(cd "$INF" && PATH="$P" npm run dev 2>&1); ok "$(has "$r" 'injected config')" yes "shim blocks npm run dev in infected repo"
r=$(cd "$FH/legit" && PATH="$P" npm run dev 2>&1); ok "$r" "REAL npm run dev" "shim allows dev in legit long-line repo"
r=$(cd "$INF" && PATH="$P" npm install 2>&1); ok "$(has "$r" 'install hook')" yes "shim blocks install with malicious hook"
r=$(cd "$INF" && PATH="$P" npm install --ignore-scripts 2>&1); ok "$r" "REAL npm install --ignore-scripts" "--ignore-scripts bypasses hook check"
# ---------- git push guard ----------
R="$FH/gitrepo"; mkdir -p "$R"; cd "$R" && git init -q && git config user.email t@t && git config user.name t
cp "$FH/legit/next.config.mjs" . && git add -A && git commit -qm legit
push(){ echo "refs/heads/main $(git rev-parse HEAD) refs/heads/main 0000000000000000000000000000000000000000" | bash "$E/git-guard" 2>&1; echo "rc=$?"; }
ok "$(push | tail -1)" "rc=0" "hook allows legit createRequire config"
cp "$INF/postcss.config.mjs" . && git add -A && git commit -qm bad
git config core.fsmonitor "touch $FH/pwned"; rm -f "$FH/pwned"     # a hostile repo setting, planted after our own git use
r=$(push); ok "$(echo "$r" | tail -1)" "rc=1" "hook blocks injected config in pushed commit"
ok "$(has "$r" 'postcss.config.mjs')" yes "hook names the file"
ok "$([ -e "$FH/pwned" ] && echo EXECUTED || echo safe)" safe "repo core.fsmonitor never executed"
rm postcss.config.mjs && echo "clean worktree, still-bad commit" >/dev/null
ok "$(push | tail -1)" "rc=1" "hook checks the commit, not the worktree"
ok "$(echo "refs/heads/x 0000000000000000000000000000000000000000 refs/heads/x abc" | bash "$E/git-guard" >/dev/null 2>&1; echo $?)" 0 "branch deletion allowed"
# ---------- CLI git-guard upgrade ----------
for n in oldhook foreign nohook; do mkdir -p "$FH/r-$n" && (cd "$FH/r-$n" && git init -q); done
git -C "$REAL_ENGINE" show cde62eb:git-guard > "$FH/r-oldhook/.git/hooks/pre-push"; chmod +x "$FH/r-oldhook/.git/hooks/pre-push"
printf '#!/bin/sh\necho custom\n' > "$FH/r-foreign/.git/hooks/pre-push"; chmod +x "$FH/r-foreign/.git/hooks/pre-push"
j=$("$B" enable git-guard --json)
ok "$(echo "$j" | jq -r '.updated | map(split("/") | last) | join(",")')" "r-oldhook" "outdated Bastion hook upgraded"
ok "$(echo "$j" | jq -r '.skipped_custom_hooks | map(split("/") | last) | join(",")')" "r-foreign" "foreign hook left alone"
ok "$(echo "$j" | jq -r '.installed | map(split("/") | last) | sort | join(",")')" "gitrepo,proj,r-nohook" "hook added where none existed"
ok "$(cmp -s "$FH/r-oldhook/.git/hooks/pre-push" "$E/git-guard" && echo same)" same "upgraded hook is the new version"
ok "$(head -2 "$FH/r-foreign/.git/hooks/pre-push" | tail -1)" "echo custom" "foreign hook content untouched"
ok "$("$B" selftest --json | jq -r .ok)" true "cli selftest"
echo "passed $pass, failed $fail"
