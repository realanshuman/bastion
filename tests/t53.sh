# t53: protection levels and the scan schedule. Basic, Recommended and Maximum set exactly what they list; going down
# or sending data asks first; the push guard is never removed; nothing touches this Mac's real launchd.
F="${1:?usage: bash $0 <fake home folder>}"; S="$(cd "$(dirname "$0")" && pwd)"
export HOME="$F" BASTION_NO_NOTIFY=1 SHELL=/bin/zsh BASTION_LAUNCHCTL="$S/fakebin/launchctl"; B="$F/.security-guard/bin/bastion"; pass=0; fail=0
ok(){ if [ "$1" = "$2" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $3: got [$1] want [$2]"; fi; }
export GIT_AUTHOR_NAME=Dev GIT_AUTHOR_EMAIL=dev@example.com GIT_COMMITTER_NAME=Dev GIT_COMMITTER_EMAIL=dev@example.com
real_before=$(/bin/launchctl list 2>/dev/null | grep -c com.bastion)
level(){ "$B" status --json | jq -r .level; }
git init -q -b main "$F/work/app"; echo '{}' > "$F/work/app/package.json"; git -C "$F/work/app" add -A; git -C "$F/work/app" commit -qm init
mkdir -p "$F/.claude"   # Claude Code is "installed": Maximum hard-guards it

ok "$(level)" off "nothing running: off"
r=$("$B" protect --json)
ok "$(echo "$r" | jq -r '[.levels[].id] | join(" ")')" "basic recommended maximum" "three levels"
ok "$(echo "$r" | jq -r '.levels[1].changes | length > 0')" true "each level lists what it would change"

# up to Basic: only raises, so no yes needed
ok "$("$B" protect basic --json | jq -r '.ok, .level' | tr '\n' ' ')" "true basic " "basic: applied without asking"
ok "$(grep -c . "$F/.fake-launchd")" 2 "…the watcher and the scheduled scan are 'loaded' (in the stand-in)"
ok "$(grep -c 'bastion execution guard' "$F/.zshrc" 2>/dev/null || echo 0)" 0 "…and the shell is untouched"
ok "$(grep -A0 StartInterval "$F/Library/LaunchAgents/com.bastion.guard.scan.plist" | grep -o '[0-9]*' | tail -1)" 21600 "scan every 6 hours by default"

# up to Recommended: guards the repos, turns on the execution guard
ok "$("$B" protect recommended --json | jq -r .level)" recommended "recommended: applied without asking"
ok "$(grep -c '>>> bastion execution guard >>>' "$F/.zshrc")" 1 "…execution guard on"
ok "$([ -x "$F/work/app/.git/hooks/pre-push" ] && echo guarded || echo open)" guarded "…push guard on"

# Maximum sends package names to osv.dev: that needs a yes
ok "$("$B" protect maximum --json | jq -r '.error | test("has to confirm")')" true "maximum asks first (osv.dev)"
ok "$(level)" recommended "…and nothing changed"
ok "$("$B" protect maximum --yes --json | jq -r .level)" maximum "maximum with a yes"
ok "$("$B" status --json | jq -r .osv)" true "…online check on"
ok "$("$B" hooks status --json | jq -r .claude)" true "…Claude Code hard-guarded"

# down again: asks, and never removes the push guard or the hard-guard
ok "$("$B" protect recommended --json | jq -r '.error | test("has to confirm")')" true "going down asks first"
ok "$("$B" protect recommended --yes --json | jq -r .level)" recommended "back to recommended"
ok "$("$B" status --json | jq -r .osv) $("$B" hooks status --json | jq -r .claude)" "false true" "…online check off, hard-guard kept"
ok "$("$B" protect basic --yes --json | jq -r .level)" basic "down to basic"
ok "$(grep -c 'bastion execution guard' "$F/.zshrc") $([ -x "$F/work/app/.git/hooks/pre-push" ] && echo kept || echo removed)" "0 kept" "…execution guard off, push guard kept"
ok "$("$B" protect basic --json | jq -r .message)" "Basic is already on. Nothing changed." "choosing the current level changes nothing"

# a mix of your own is custom; nothing running is off
"$B" disable schedule --yes --json >/dev/null
ok "$(level)" custom "watcher without the schedule: custom"
"$B" disable watcher --yes --json >/dev/null
ok "$(level)" off "nothing running: off"

# the schedule: 1 hour, 6 hours or a day; a running schedule is reloaded with it
"$B" enable schedule --json >/dev/null
ok "$("$B" schedule 1h --json | jq -r '.scan_every_hours, .running' | tr '\n' ' ')" "1 true " "every hour"
ok "$(sed -n 's:.*<key>StartInterval</key><integer>\([0-9]*\)</integer>.*:\1:p' "$F/Library/LaunchAgents/com.bastion.guard.scan.plist")" 3600 "…the agent runs hourly"
ok "$("$B" status --json | jq -r .protection.scan_every_hours)" 1 "…status says so"
ok "$("$B" schedule daily --json | jq -r .scan_every_hours)" 24 "daily"
ok "$("$B" schedule weekly --json | jq -r '.error | test("Usage")')" true "an interval it doesn't offer is refused"
ok "$("$B" activity --json | jq -r '[.events[].said | select(test("Scheduled scan set to run once a day"))] | length')" 1 "activity records the schedule"
ok "$("$B" activity --json | jq -r '[.events[].said | select(test("Protection level set to Maximum"))] | length')" 1 "…and each level change"

# the real launchd was never touched
ok "$(/bin/launchctl list 2>/dev/null | grep -c com.bastion)" "$real_before" "this Mac's own agents are exactly as they were"
echo "passed $pass, failed $fail"
