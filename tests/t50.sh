# t50: `bastion ask`. Plain questions in, plain answers out; protection only ever goes up without a button press
F="${1:?usage: bash $0 <fake home folder>}"; export HOME="$F" BASTION_NO_NOTIFY=1; B="$F/.security-guard/bin/bastion"; pass=0; fail=0
ok(){ if [ "$1" = "$2" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $3: got [$1] want [$2]"; fi; }
ask(){ "$B" ask "$1" --json; }
export GIT_AUTHOR_NAME=Dev GIT_AUTHOR_EMAIL=dev@example.com GIT_COMMITTER_NAME=Dev GIT_COMMITTER_EMAIL=dev@example.com
g(){ git -C "$R" "$@" >/dev/null 2>&1; }
PAD=$(printf '%*s' 2000 '')
infect(){ printf 'export default { plugins: {} };%sglobal.o='"'"'1-183'"'"';var _$_ab12=(function(i,p){return i})();\n' "$PAD" > "$1"; }
O="$F/work/origin.git"; git init -q --bare -b main "$O"
R="$F/work/shop-web"; git clone -q "$O" "$R" 2>/dev/null; g checkout -b main
echo 'export default { plugins: {} };' > "$R/postcss.config.mjs"; g add -A; g commit -m init; g push -u origin main
g checkout -b promo; infect "$R/postcss.config.mjs"; g commit -am promo; g push -u origin promo; g checkout main
git init -q -b main "$F/work/billing-api"; echo '{}' > "$F/work/billing-api/package.json"; git -C "$F/work/billing-api" add -A; git -C "$F/work/billing-api" commit -qm init
"$B" scan "$F/work" --json >/dev/null
# questions about one repo: by name, by a name with spaces, by a loose part of it, by path
r=$(ask "is shop-web safe?")
ok "$(echo "$r" | jq -r .intent)" check "a repo by name is checked"
ok "$(echo "$r" | jq -r .tone)" warn "safe where you are, but a branch carries malware"
ok "$(echo "$r" | jq -r '.answer | test("safe to run on main, but 2 other branches carry malware")')" true "says both halves"
ok "$(echo "$r" | jq -r '[.actions[] | select(.kind=="fix")] | length')" 2 "offers each branch fix as a button"
ok "$(echo "$r" | jq -r '[.points[] | select(startswith("Proof:"))] | length')" 1 "the same proof on two branches is shown once"
ok "$(ask "can i run npm in shop web" | jq -r .repo)" "$F/work/shop-web" "a name typed with a space still finds it"
ok "$(ask "check billing" | jq -r '.intent + " " + .tone')" "check good" "a unique part of a name is enough"
ok "$(ask "is ~/work/billing-api ok" | jq -r '.repo | endswith("/work/billing-api")')" true "a path works"
ok "$(ask "hunt the history of shop-web" | jq -r '.auto.kind + " " + .auto.args[0]')" "present history" "history is shown, not guessed"
# what needs me, in plain words, and the words explained
r=$(ask "what needs me?")
ok "$(echo "$r" | jq -r '.intent + " " + .tone')" "needs warn" "needs: one thing, nothing running"
ok "$(echo "$r" | jq -r '.points[0] | startswith("Dormant: ")')" true "each item says how dangerous it is"
ok "$(echo "$r" | jq -r '.suggestions[0]')" "What does dormant mean?" "suggests the explanation it needs"
ok "$(ask "what does dormant mean" | jq -r '.intent + " " + (.answer | test("branch you don.t have checked out") | tostring)')" "explain true" "dormant explained"
ok "$(ask "whats hidden code?" | jq -r .intent)" explain "contractions are understood"
ok "$(ask "hello" | jq -r '.intent + " " + (.answer | test("2 things need you") | tostring)')" "greeting true" "a greeting gets the status in one line"
ok "$(ask "" | jq -r .intent)" status "an empty question is a status check"
ok "$(ask "am i safe" | jq -r '.points[0] | test("^I.m watching 2 repositories")')" true "status speaks in first person"
ok "$(ask "fnord zzyzx" | jq -r .intent)" unknown "nonsense is admitted, not guessed"
# actions: scanning is handed to the app (so it can show progress); nothing runs in --json mode
logs=$(ls "$F/.security-guard/logs" | wc -l)
ok "$(ask "scan everything" | jq -r .auto.kind)" scan "scan is an automatic step"
ok "$(ls "$F/.security-guard/logs" | wc -l)" "$logs" "…that --json leaves to the caller"
ok "$(ask "switch to dark mode" | jq -r '.auto.kind + " " + .auto.value')" "appearance dark" "appearance is an app step"
# turning protection ON happens; turning it OFF is only ever a button that asks
ok "$(ask "turn on the execution guard" | jq -r .tone)" good "turn on does it"
ok "$(grep -c '>>> bastion execution guard >>>' "$F/.zshrc")" 1 "…the execution guard really is on"
r=$(ask "turn off the execution guard")
ok "$(echo "$r" | jq -r '.intent + " " + .actions[0].kind')" "turn_off feature_off" "turn off is a button"
ok "$(grep -c '>>> bastion execution guard >>>' "$F/.zshrc")" 1 "…and nothing was turned off"
# agents: never edits another app's settings on its own
ok "$(ask "connect cursor" | jq -r '.answer | test("isn.t installed")')" true "an agent that isn't installed is refused"
ok "$([ -e "$F/.cursor" ] && echo created || echo absent)" absent "…and nothing was created for it"
mkdir -p "$F/.cursor"
r=$(ask "connect cursor")
ok "$(echo "$r" | jq -r '.actions[0].kind + " " + .actions[0].agent')" "connect cursor" "an installed agent gets a Connect button"
ok "$([ -e "$F/.cursor/mcp.json" ] && echo written || echo untouched)" untouched "…and its config is untouched until you press it"
# activity lines come in Bastion's own words
ok "$("$B" activity --json | jq -r '[.events[] | select(.said | length > 0)] | length > 0')" true "activity carries a plain sentence"
ok "$(ask "what happened today" | jq -r '.intent')" activity "what happened"
echo "passed $pass, failed $fail"
