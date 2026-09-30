F="${1:?usage: bash $0 <fake home folder>}"; export HOME="$F" BASTION_NO_NOTIFY=1; B="$F/.security-guard/bin/bastion"; pass=0; fail=0
ok(){ if [ "$1" = "$2" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $3: got [$1] want [$2]"; fi; }
export GIT_AUTHOR_NAME=Dev GIT_AUTHOR_EMAIL=dev@example.com GIT_COMMITTER_NAME=Dev GIT_COMMITTER_EMAIL=dev@example.com
g(){ git -C "$R" "$@" >/dev/null 2>&1; }
PAD=$(printf '%*s' 2000 '')
infect(){ printf 'export default { plugins: {} };%sglobal.o='"'"'1-183'"'"';var _$_ab12=(function(i,p){return i})();\n' "$PAD" > "$1"; }
O="$F/work/origin.git"; git init -q --bare -b main "$O"
R="$F/work/app"; git clone -q "$O" "$R" 2>/dev/null; g checkout -b main
echo 'export default { plugins: {} };' > "$R/postcss.config.mjs"; g add -A; g commit -m init; g push -u origin main
# a leftover infected branch on the server
g checkout -b old; infect "$R/postcss.config.mjs"; g commit -am bad; g push -u origin old; g checkout main; g branch -D old
"$B" scan "$F/work" --json >/dev/null
# 1. the live list and the one status
t=$("$B" todos --json --offline)
ok "$(echo "$t" | jq -r .state)" clean_up "state: something to clean up, nothing running"
ok "$(echo "$t" | jq -r '.items[0].danger')" dormant "the branch is dormant"
ok "$(echo "$t" | jq -r '.items[0].fix.button')" "Delete branch…" "fix button says what it does"
ok "$("$B" status --json | jq -r '.state + " " + (.needs_you|tostring)')" "clean_up 1" "status carries the same state and count"
id=$(echo "$t" | jq -r '.items[0].id')
# 2. risky fixes need --yes; with it the branch goes and the list empties
ok "$("$B" fix "$id" --json | jq -r '.error' | grep -c 'Run it with --yes')" 1 "deleting a server branch needs --yes"
r=$("$B" fix "$id" --yes --json)
ok "$(echo "$r" | jq -r .ok)" true "fix ran and Bastion sees it fixed"
ok "$(git -C "$O" branch --list old | wc -l | tr -d ' ')" 0 "the branch is gone from the server"
ok "$("$B" todos --json --offline | jq -r .state)" all_clear "all clear right after the fix (no rescan)"
ok "$("$B" repos --json | jq -r '.repos[] | select(.name=="app") | .infected_branches')" 0 "repositories agree at once"
ok "$(grep -c 'FIXED: Delete the old branch old' "$F/.security-guard/ALERTS.txt")" 1 "the fix is in the activity log"
# 3. incidents keep up: a fixed branch moves to done; ticking the rest makes it all done
g checkout -b old2; infect "$R/postcss.config.mjs"; g commit -am bad2; g push -u origin old2; g checkout main; g branch -D old2
"$B" scan "$F/work" --json >/dev/null
inc=$("$B" incident latest --json); iid=$(echo "$inc" | jq -r .id)
ok "$(echo "$inc" | jq -r '[.todos[] | select(.key | startswith("branch:"))] | length')" 1 "incident has the branch to-do"
ok "$(echo "$inc" | jq -r '.branch_details[0].proof[0].evidence.column')" 2032 "incident shows the proof for the branch"
bid=$("$B" todos --json --offline | jq -r '.items[] | select(.type=="branch") | .id')
"$B" fix "$bid" --yes --json >/dev/null
inc=$("$B" incident "$iid" --json)
ok "$(echo "$inc" | jq -r '[.done[] | select(.how=="fixed")] | length')" 1 "the branch to-do moved to done by itself"
key=$(echo "$inc" | jq -r '[.todos[] | select(.key != "resolve")][0].key')
if [ -n "$key" ] && [ "$key" != "null" ]; then
  ok "$("$B" incident "$iid" tick "$key" --json | jq -r .all_done)" true "ticking the last to-do makes the incident all done"
else
  ok "$(echo "$inc" | jq -r .all_done)" true "incident all done"
fi
# 4. an injected config in the working copy: act now, and "Contain it now" cleans it (auto-respond only observes)
"$B" autonomy observe --yes --json >/dev/null
cp "$R/postcss.config.mjs" "$F/clean.mjs"; infect "$R/postcss.config.mjs"; cat "$F/clean.mjs" > /dev/null
git -C "$R" checkout -q -- postcss.config.mjs; infect "$R/postcss.config.mjs"
"$B" scan "$F/work" --json >/dev/null
t=$("$B" todos --json --offline)
ok "$(echo "$t" | jq -r .state)" act_now "an infected working copy means act now"
tid=$(echo "$t" | jq -r '.items[] | select(.danger=="now") | .id' | head -1)
ok "$("$B" fix "$tid" --json | jq -r .ok)" true "Contain it now cleans it even though auto-respond only observes"
ok "$(cat "$R/postcss.config.mjs")" "export default { plugins: {} };" "file is back to its clean commit"
# 5. husky repos get Bastion's check in .husky/pre-push, and it's a no-op without Bastion
H="$F/work/hus"; git init -q -b main "$H"; mkdir -p "$H/.husky/_"; printf 'npm test\n' > "$H/.husky/pre-push"; git -C "$H" config core.hooksPath .husky/_
ok "$("$B" next --json | jq -r '[.steps[] | select(.id | startswith("husky:"))] | length')" 1 "husky repo shows up in next steps"
"$B" enable git-guard --husky "$H" --json >/dev/null
ok "$(grep -c 'security-guard/git-guard' "$H/.husky/pre-push")" 1 "check added to .husky/pre-push"
ok "$(head -1 "$H/.husky/pre-push")" "npm test" "existing hook kept"
ok "$("$B" repos --json | jq -r '.repos[] | select(.name=="hus") | .git_guard')" protected "husky repo now counts as protected"
ok "$(cd "$H" && HOME=/nonexistent sh -e .husky/pre-push origin x </dev/null >/dev/null 2>&1; [ $? -ne 0 ] && echo ran)" ran "(sanity) the existing hook line still runs first"
printf '# only bastion\n' > "$F/only"; sed -n '/Bastion/,$p' "$H/.husky/pre-push" > "$F/tail.sh"
ok "$(HOME=/nonexistent sh -e "$F/tail.sh" origin x </dev/null; echo $?)" 0 "no-op where Bastion isn't installed"
# 6. connecting an agent writes its config with a backup, and refuses broken JSON
mkdir -p "$F/.cursor"; echo '{"mcpServers":{"other":{"command":"x"}}}' > "$F/.cursor/mcp.json"
"$B" connect cursor --write --json >/dev/null
ok "$(jq -r '.mcpServers | keys | join(",")' "$F/.cursor/mcp.json")" "bastion,other" "cursor config gains bastion, keeps others"
ok "$([ -f "$F/.cursor/mcp.json.bastion-backup" ] && echo yes)" yes "backup kept"
ok "$("$B" agents --json | jq -r '.agents[] | select(.id=="cursor") | .connected')" true "agents report sees it connected"
mkdir -p "$F/.codeium/windsurf"; echo '{broken' > "$F/.codeium/windsurf/mcp_config.json"
ok "$("$B" connect windsurf --write --json | jq -r .error | grep -c 'valid JSON')" 1 "broken JSON is left alone"
echo "passed $pass, failed $fail"
