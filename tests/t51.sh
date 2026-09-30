# t51: honest status. "checked" is never, stale or recent, and nothing the engine prints carries an em dash (old logs included)
F="${1:?usage: bash $0 <fake home folder>}"; export HOME="$F" BASTION_NO_NOTIFY=1; B="$F/.security-guard/bin/bastion"; pass=0; fail=0
ok(){ if [ "$1" = "$2" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $3: got [$1] want [$2]"; fi; }
export GIT_AUTHOR_NAME=Dev GIT_AUTHOR_EMAIL=dev@example.com GIT_COMMITTER_NAME=Dev GIT_COMMITTER_EMAIL=dev@example.com
L="$F/.security-guard/logs"; ED=$(printf '\xe2\x80\x94')
# never: nothing has been looked at, and status says so instead of "protected"
r=$("$B" status --json)
ok "$(echo "$r" | jq -r .checked)" never "no scan yet"
ok "$(echo "$r" | jq -r .last_scan)" null "no last scan"
ok "$(echo "$r" | jq -r '.summary | test("No scan has run yet, so nothing has been checked")')" true "the summary says nothing was checked"
ok "$("$B" status | grep -c 'never (run: bastion scan)')" 1 "the terminal says it too"
# stale: one clean scan, 9 days old
printf 'RESULT: CLEAN\n' > "$L/scan-$(date -v-9d +%Y%m%d-%H%M%S).log"
r=$("$B" status --json)
ok "$(echo "$r" | jq -r .checked)" stale "a 9 day old scan is stale"
ok "$(echo "$r" | jq -r '(.last_scan_age_hours / 24 | floor)')" 9 "its age, in hours"
ok "$(echo "$r" | jq -r '.summary | test("The last scan was 9 days ago")')" true "the summary gives the age"
# 2 days old is still recent
rm -f "$L"/scan-*.log; printf 'RESULT: CLEAN\n' > "$L/scan-$(date -v-2d +%Y%m%d-%H%M%S).log"
ok "$("$B" status --json | jq -r .checked)" recent "2 days old is recent"
# recent: a real scan
rm -f "$L"/scan-*.log
git init -q -b main "$F/work/app"; echo '{}' > "$F/work/app/package.json"; git -C "$F/work/app" add -A; git -C "$F/work/app" commit -qm init
"$B" scan "$F/work" --json >/dev/null
r=$("$B" status --json)
ok "$(echo "$r" | jq -r .checked)" recent "after a scan"
ok "$(echo "$r" | jq -r '.last_scan_age_hours')" 0 "age 0"
ok "$(echo "$r" | jq -r '.summary | test("days ago|No scan")')" false "the summary drops the warning"
# lines written by earlier versions still have em dashes; the engine never passes one on
printf '%s  ALERT %s hidden code in %s %s do not run npm there\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$ED" "$F/work/app/postcss.config.mjs" "$ED" >> "$F/.security-guard/ALERTS.txt"
a=$("$B" activity --json)
ok "$(echo "$a" | grep -c "$ED")" 0 "no em dash in activity JSON"
ok "$(echo "$a" | jq -r '.events[0].message')" "ALERT. Hidden code in $F/work/app/postcss.config.mjs. Do not run npm there" "a spaced dash becomes a sentence break"
ok "$("$B" activity | grep -c "$ED")" 0 "no em dash in the terminal either"
# an old incident report: its words are cleaned, its paths are not touched
D="$F/.security-guard/incidents/INC-20260101-000000"; mkdir -p "$D"
printf '{"id":"INC-20260101-000000","status":"resolved","opened":"2026-01-01T00:00:00Z","summary":"Contained %s nothing is running","findings":[{"path":"/tmp/odd%sname/x.js","title":"Hidden code %s obfuscated"}]}' "$ED" "$ED" "$ED" > "$D/incident.json"
i=$("$B" incident INC-20260101-000000 --json)
ok "$(echo "$i" | jq -r '.summary // .incident.summary')" "Contained. Nothing is running" "old summary cleaned"
ok "$(echo "$i" | jq -r '[.. | strings | select(startswith("/tmp/odd"))][0]')" "/tmp/odd${ED}name/x.js" "a path is left exactly as it is"
ok "$("$B" incidents --json | grep -c "$ED")" 0 "the incident list has none"
ok "$("$B" incident INC-20260101-000000 | grep -v '/tmp/odd' | grep -c "$ED")" 0 "the terminal report has none outside the path"
# MCP answers are plain too
m=$(printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bastion_activity","arguments":{}}}' | "$B" mcp 2>/dev/null)
ok "$(echo "$m" | grep -c "$ED")" 0 "no em dash over MCP"
echo "passed $pass, failed $fail"
