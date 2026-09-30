F="${1:?usage: bash $0 <fake home folder>}"; export HOME="$F" BASTION_NO_NOTIFY=1; B="$F/.security-guard/bin/bastion"; pass=0; fail=0
ok(){ if [ "$1" = "$2" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $3: got [$1] want [$2]"; fi; }
export GIT_AUTHOR_NAME=Dev GIT_AUTHOR_EMAIL=dev@example.com GIT_COMMITTER_NAME=Dev GIT_COMMITTER_EMAIL=dev@example.com
g(){ git -C "$R" "$@" >/dev/null 2>&1; }
PAD=$(printf '%*s' 2000 '')
infect(){ printf 'export default { plugins: {} };%sglobal.o='"'"'1-183'"'"';var _$_ab12=(function(i,p){return i})();\n' "$PAD" > "$1"; }
fix_of(){ "$B" branches "$R" --json | jq -r --arg ref "$1" '.branches[] | select(.ref == $ref) | .fix.title'; }
# origin + clone
O="$F/work/origin.git"; git init -q --bare -b main "$O"
R="$F/work/app"; git clone -q "$O" "$R" 2>/dev/null; g checkout -b main
echo 'export default { plugins: {} };' > "$R/postcss.config.mjs"; g add -A; g commit -m init; g push -u origin main
# 1. a leftover branch on the server; main is clean → delete it
g checkout -b old-feature; infect "$R/postcss.config.mjs"; g commit -am "feature"; g push -u origin old-feature; g checkout main; g branch -D old-feature
ok "$(fix_of origin/old-feature | cut -c1-21)" "Delete the old branch" "leftover server branch → delete it"
ev=$("$B" branches "$R" --json | jq -r '.branches[] | select(.ref=="origin/old-feature") | .proof[0].evidence | "\(.line) \(.padding) \(.column)"')
ok "$ev" "1 2000 2032" "evidence: line, blank run and column of the hidden code"
see=$("$B" branches "$R" --json | jq -r '.branches[] | select(.ref=="origin/old-feature") | .proof[0].see_it')
ok "$(eval "$see" | cut -c1-17)" "global.o='1-183';" "the see-it command shows the hidden code"
g push origin --delete old-feature; g fetch --prune origin
# 2. a stale local branch whose server copy is clean → update it
g checkout -b stale; infect "$R/postcss.config.mjs"; g commit -am "bad"; g push -u origin stale
echo 'export default { plugins: { a: {} } };' > "$R/postcss.config.mjs"; g commit -am "clean again"; g push; g reset --hard HEAD~1; g checkout main
ok "$(fix_of stale | cut -c1-22)" "Update your local stal" "stale local branch behind a clean server copy → update it"
g branch -D stale; g push origin --delete stale; g fetch --prune origin
# 3. server has the infected commit, local has the same work without it → push the clean copy
g checkout -b amended; echo "// work" >> "$R/postcss.config.mjs"; cp "$R/postcss.config.mjs" "$F/clean.mjs"; infect "$R/postcss.config.mjs"; g commit -am "work"; g push -u origin amended
cp "$F/clean.mjs" "$R/postcss.config.mjs"; g commit --amend -am "work"; g checkout main
ok "$(fix_of origin/amended | cut -c1-22)" "Push your clean copy o" "amended clean local vs infected server → push the clean copy"
ok "$("$B" branches "$R" --json | jq -r '.branches[] | select(.ref=="origin/amended") | .fix.commands[0]' | grep -c 'force-with-lease=amended:')" 1 "push uses --force-with-lease pinned to the infected commit"
# 4. a local-only branch → delete or fix it
g checkout -b mine; infect "$R/postcss.config.mjs"; g commit -am "mine"; g checkout main
ok "$(fix_of mine | cut -c1-25)" "Delete or fix your local " "local-only branch → delete or fix"
# 5. the incident to-do carries proof, the exact command and a link
"$B" scan "$F/work" --json >/dev/null
t=$("$B" incident latest --json)
ok "$(echo "$t" | jq -r '[.todos[] | select(.title | test("Push your clean copy"))] | length')" 1 "incident to-do per branch with the fitting fix"
ok "$(echo "$t" | jq -r '[.todos[].cmd // "" | select(test("<branch>|<remote>"))] | length')" 0 "no placeholder commands"
ok "$(echo "$t" | jq -r '[.todos[].why // "" | select(test("blank characters push hidden code"))] | length' | awk '{print ($1>0)}')" 1 "to-dos explain where the code hides"
echo "passed $pass, failed $fail"
