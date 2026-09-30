F="${1:?usage: bash $0 <fake home folder>}"; export HOME="$F" BASTION_NO_NOTIFY=1; B="$F/.security-guard/bin/bastion"; pass=0; fail=0
ok(){ if [ "$1" = "$2" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $3: got [$1] want [$2]"; fi; }
g(){ GIT_AUTHOR_NAME=Dev GIT_AUTHOR_EMAIL=dev@example.com GIT_COMMITTER_NAME=Dev GIT_COMMITTER_EMAIL=dev@example.com git -C "$R" "$@" >/dev/null 2>&1; }
PAY="$(printf 'export default {};%*s' 300 '')global.o='1-183';var _\$_1a2b=(function(){return 1})();"
R="$F/work/shop"; mkdir -p "$R"; git -C "$R" init -q -b main
echo 'export default { plugins: {} };' > "$R/postcss.config.mjs"; g add -A; g commit -m init
g branch feature
# 1. cache: warm it on clean branches, then infect one: it must still be found
ok "$("$B" branches --json | jq -r .clean)" true "clean repo: no infected branches"
ok "$(ls "$F/.security-guard/cache/" | grep -c 'branch-trees-\|blob-verdicts-')" 2 "cache files written"
g checkout feature; printf '%s\n' "$PAY" > "$R/postcss.config.mjs"; g commit -am "feature work"; g checkout main
ok "$("$B" branches --json | jq -r '[.infected_branches[].ref] | join(",")')" feature "newly infected branch found with a warm cache"
ok "$("$B" branches --json | jq -r '[.infected_branches[].ref] | join(",")')" feature "second run (all cached) gives the same answer"
# 2. rule change invalidates cached verdicts
echo "# tweak" >> "$F/.security-guard/lib.sh"
ok "$("$B" branches --json | jq -r '[.infected_branches[].ref] | join(",")')" feature "still found after the rules change"
ok "$(ls "$F/.security-guard/cache/" | grep -c 'blob-verdicts-')" 1 "old verdicts dropped when rules change"
# 3. scan runs the response inline and returns the incident
r=$("$B" scan "$F/work" --json)
ok "$(echo "$r" | jq -r '.response.id // empty' | cut -c1-4)" INC- "scan returns the incident it opened"
ok "$(echo "$r" | jq -r '.response.summary' | grep -ci 'nothing is running')" 1 "branch-only incident says nothing is running"
id=$(echo "$r" | jq -r .response.id)
ok "$(ls "$F/.security-guard/incidents" | wc -l | tr -d ' ')" 1 "one incident"
# 4. resolved + unchanged branch → no new incident on the next scan
"$B" incident resolve "$id" --json >/dev/null
r=$("$B" scan "$F/work" --json)
ok "$(echo "$r" | jq -r '.response.status')" known "unchanged infected branch doesn't reopen"
ok "$(ls "$F/.security-guard/incidents" | wc -l | tr -d ' ')" 1 "still one incident"
# 5. the branch changes (new infected commit) → a new incident
g checkout feature; echo "// more" >> "$R/postcss.config.mjs"; g commit -am "more"; g checkout main
r=$("$B" scan "$F/work" --json)
ok "$(echo "$r" | jq -r '.response.status')" contained "changed infected branch opens a new incident"
ok "$(ls "$F/.security-guard/incidents" | wc -l | tr -d ' ')" 2 "two incidents"
# 6. background path (scheduled scan): guard.sh hands its log to the responder, no second scan
"$B" incident resolve latest --json >/dev/null
printf '%s\n' "$PAY" > "$R/vite.config.js"
bash "$F/.security-guard/guard.sh" "$F/work" >/dev/null 2>&1
for i in $(seq 1 40); do [ -d "$F/.security-guard/respond.lock" ] || [ "$(ls "$F/.security-guard/incidents" | wc -l | tr -d ' ')" = 3 ] && break; sleep 0.25; done
for i in $(seq 1 40); do [ -d "$F/.security-guard/respond.lock" ] || break; sleep 0.25; done
ok "$(ls "$F/.security-guard/incidents" | wc -l | tr -d ' ')" 3 "scheduled scan's background response opened an incident"
ok "$("$B" status --json | jq -r '.responding')" false "no response running afterwards"
echo "passed $pass, failed $fail"
