#!/bin/bash
# tests/run.sh [cli]: every suite, each in a fake home folder of its own under a temporary folder. Nothing touches your
# real home folder, shell setup or launchd agents: BASTION_LAUNCHCTL points at a stand-in (fakebin/launchctl).
# [cli]: test this build of bastion instead of bin/bastion.
T="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$T/.." && pwd)"
# a temporary folder of its own, removed at the end, and only ever that folder
W="$(mktemp -d "${TMPDIR:-/tmp}/bastion-tests.XXXXXX")" || exit 1
W="$(cd "$W" && pwd -P)" || exit 1
case "$W" in */bastion-tests.??????) trap 'rm -rf "$W"' EXIT ;; *) echo "unexpected temporary folder: $W"; exit 1 ;; esac
export ROOT BASTION_NO_NOTIFY=1 BASTION_LAUNCHCTL="$T/fakebin/launchctl" DEVELOPER_DIR=/Library/Developer/CommandLineTools
CLI="${1:-$ROOT/bin/bastion}"
[ -x "$CLI" ] || { echo "no bastion CLI at $CLI (run ./build.sh, or pass a build)"; exit 1; }
fresh(){ F="$W/$1"; rm -rf "$F"; mkdir -p "$F/.security-guard/logs" "$F/.security-guard/quarantine" "$F/.security-guard/bin" "$F/work" "$F/tmp" "$F/fakebin"
  (cd "$ROOT" && cp -a lib.sh scanner.sh guard.sh watcher.sh git-guard harden.sh install.sh uninstall.sh allowlist.txt blocklist.txt ignore.txt VERSION shims "$F/.security-guard/") \
    && touch "$F/.security-guard/ALERTS.txt" && cp "$CLI" "$F/.security-guard/bin/bastion"; }
bash "$T/fixtures.sh" "$W"
echo "== rules";     fresh fhR && mkdir -p "$W/rules" && S="$W" HOME="$W/fhR" bash "$T/rules.sh" "$W/rules" 2>&1 | tail -1
echo "== battery";   fresh fhA && bash "$T/battery.sh" "$W" "$W/fhA" 2>&1 | tail -1
echo "== lifecycle"; fresh fhB && bash "$T/stage.sh" "$W/fhB" >/dev/null 2>&1 && bash "$T/lifecycle.sh" "$W/fhB" 2>&1 | tail -1
for t in t41 t411 t413 t414 t50 t51 t52 t53; do echo "== $t"; fresh "fh$t" && bash "$T/$t.sh" "$W/fh$t" 2>&1 | grep -E "FAIL|passed"; done
echo "== mcp"; fresh fhm; out=$(sed "s#\$S/#$W/#g" "$T/mcp-in.jsonl" | HOME="$W/fhm" "$W/fhm/.security-guard/bin/bastion" mcp 2>/dev/null)
echo "responses $(echo "$out" | grep -c '"jsonrpc"') · tools $(echo "$out" | jq -r 'if type=="array" then .[] else . end | select(.result.tools) | .result.tools | length') · expected refusals (disable, unknown method, bad JSON) $(echo "$out" | jq -c 'if type=="array" then .[] else . end | select(.error)' | wc -l | tr -d ' ')"
