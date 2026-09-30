F="${1:?usage: bash $0 <fake home folder>}"; export HOME="$F" BASTION_NO_NOTIFY=1; B="$F/.security-guard/bin/bastion"; pass=0; fail=0
ok(){ if [ "$1" = "$2" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $3: got [$1] want [$2]"; fi; }
A="$F/work/app"; CLEAN=$(cd "$A" && git show HEAD~1:postcss.config.mjs)
r=$("$B" respond --json)
ok "$(echo "$r" | jq -r .status)" contained "respond contains the attack"
ok "$(echo "$r" | jq -r '[.indicators[] | select(.value=="203.0.113.77") | .status][0]')" blocked "payload IP extracted from URL and blocked"
ok "$(grep -c '^203.0.113.77$' "$F/.security-guard/blocklist.txt")" 1 "blocklist gained the attacker IP"
ok "$(cat "$A/postcss.config.mjs")" "$CLEAN" "config restored exactly"
s=$("$B" status --fast --json)
ok "$(echo "$s" | jq -r .posture)" protected "status: protected after containment"
ok "$(echo "$s" | jq -r .incident.status)" contained "status: shows the contained incident"
ok "$(echo "$s" | jq -r '.last_scan.clean')" true "verify scan log says clean"
# undo puts the infected version back; a plan-only run changes nothing; a real run contains again
"$B" undo latest --yes --json >/dev/null
ok "$(grep -c "global.i='1-183'" "$A/postcss.config.mjs")" 1 "undo restored the infected version"
p=$("$B" respond --plan --json)
ok "$(echo "$p" | jq -r .mode)" observe "--plan runs in observe mode"
ok "$(grep -c "global.i='1-183'" "$A/postcss.config.mjs")" 1 "plan-only changed nothing"
ok "$(echo "$p" | jq -r '[.actions[] | select(.type=="restore_file")] | last | .status')" proposed "plan-only proposes the restore"
r2=$("$B" respond --json)
ok "$(echo "$r2" | jq -r .status)" contained "second real run contains again"
ok "$(echo "$r2" | jq -r .id)" "$(echo "$r" | jq -r .id)" "same incident continued, not a new one"
ok "$(cat "$A/postcss.config.mjs")" "$CLEAN" "restored again"
ok "$("$B" incident resolve latest --json | jq -r .status)" resolved "resolve"
ok "$("$B" status --fast --json | jq -r .incident)" null "no current incident after resolve"
# --- variant: payload on the same line as real code, pushed off-screen with padding ---
mkdir -p "$F/work/pad" && cd "$F/work/pad" && git init -q -b main
printf '%s\n' "const config = { plugins: {} };" "export default config;" > vite.config.js
GIT_AUTHOR_NAME=Dev GIT_AUTHOR_EMAIL=dev@example.com GIT_COMMITTER_NAME=Dev GIT_COMMITTER_EMAIL=dev@example.com git add -A >/dev/null && GIT_AUTHOR_NAME=Dev GIT_AUTHOR_EMAIL=dev@example.com GIT_COMMITTER_NAME=Dev GIT_COMMITTER_EMAIL=dev@example.com git commit -qm init
PADCLEAN=$(cat vite.config.js); printf '%s\n' "const config = { plugins: {} };" "export default config;$(printf ' %.0s' $(seq 1 160))eval(atob('Y29uc29sZS5sb2coMSk='))" > vite.config.js
r3=$("$B" respond "$F/work/pad" --json)
ok "$(echo "$r3" | jq -r .status)" contained "padding variant contained"
ok "$(cat vite.config.js)" "$PADCLEAN" "padding variant: legit start of the line kept, payload cut"
ok "$(echo "$r3" | jq -r '.repos[] | select(.path|endswith("/pad")) | .files[0].introduced_by // "on-disk"')" on-disk "uncommitted injection flagged as written on disk"
"$B" incident resolve latest >/dev/null
# --- variant: developer has their own uncommitted edits in the same file → never auto-rewritten ---
mkdir -p "$F/work/edits" && cd "$F/work/edits" && git init -q -b main && printf '%s\n' "export default { a: 1 };" > next.config.mjs
GIT_AUTHOR_NAME=Dev GIT_AUTHOR_EMAIL=dev@example.com GIT_COMMITTER_NAME=Dev GIT_COMMITTER_EMAIL=dev@example.com git add -A >/dev/null && GIT_AUTHOR_NAME=Dev GIT_AUTHOR_EMAIL=dev@example.com GIT_COMMITTER_NAME=Dev GIT_COMMITTER_EMAIL=dev@example.com git commit -qm init
printf '%s\n' "export default { a: 2, b: 'my new work' };" "global.o='1-71';" > next.config.mjs; BEFORE=$(cat next.config.mjs)
r4=$("$B" respond "$F/work/edits" --json)
ok "$(cat next.config.mjs)" "$BEFORE" "file with the developer's own edits left untouched"
ok "$(echo "$r4" | jq -r '[.actions[] | select(.type=="restore_file")] | last | .status')" proposed "restore proposed for review instead"
ok "$(echo "$r4" | jq -r .status)" open "incident stays open"
"$B" incident resolve latest >/dev/null
# --- variant: untracked infected config → cleaned copy suggested, original untouched ---
mkdir -p "$F/work/loose" && printf '%s\n' "export default {};" "global.i='1-9';" > "$F/work/loose/postcss.config.js"; LBEFORE=$(cat "$F/work/loose/postcss.config.js")
r5=$("$B" respond "$F/work/loose" --json)
ok "$(cat "$F/work/loose/postcss.config.js")" "$LBEFORE" "untracked file untouched"
sug=$(echo "$r5" | jq -r '[.actions[] | select(.type=="clean_file")] | last | .suggested_copy')
ok "$(cat "$sug" 2>/dev/null)" "export default {};" "cleaned copy suggested"
ok "$([ -e "$F/pwned" ] && echo EXECUTED || echo safe)" safe "hostile fsmonitor never executed"
echo "passed $pass, failed $fail"
