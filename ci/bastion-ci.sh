#!/usr/bin/env bash
# Bastion in GitHub Actions: scans the checked-out repository (repo checks only, no machine checks) and fails the
# job on findings, with an annotation on each file and a summary table.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "${1:-.}" && pwd)"
# the ignore list comes from the base branch, so a pull request can't silence its own findings
IGNORE="$(mktemp)"
if [ -n "${GITHUB_BASE_REF:-}" ] && git -C "$ROOT" fetch -q --depth=1 origin "$GITHUB_BASE_REF" 2>/dev/null; then
  git -C "$ROOT" show FETCH_HEAD:.bastionignore > "$IGNORE" 2>/dev/null || : > "$IGNORE"
elif [ -f "$ROOT/.bastionignore" ]; then cp "$ROOT/.bastionignore" "$IGNORE"; fi
export SCAN_REPO_ONLY=1 BASTION_IGNORE="$IGNORE"
out=$(bash "$HERE/scanner.sh" "$ROOT" 2>/dev/null)
title(){ case "$1" in
  CONFIG) echo "Injected build config";; SOURCE) echo "Malware code in a source file";; SCRIPT) echo "Suspicious npm install hook";;
  AUTORUN) echo "Editor auto-run task";; DEPHOOK) echo "Malicious install script in a dependency";;
  DEPURL) echo "Dependency downloaded from an untrusted address";; WORKFLOW) echo "CI workflow that ships secrets out";; *) echo "$1";; esac; }
count=0; rows=""
while IFS='|' read -r kind path detail; do
  [ -n "$kind" ] || continue
  rel="${path#"$ROOT"/}"; count=$((count + 1))
  echo "::error file=$rel,title=Bastion: $(title "$kind")::$(title "$kind") ($detail). Don't merge until it's removed. https://github.com/realanshuman/bastion"
  rows="$rows| $(title "$kind") | \`$rel\` | $detail |"$'\n'
done <<< "$out"
{
  echo "## 🛡 Bastion"
  if [ "$count" -eq 0 ]; then echo "No hidden malware in build configs, install hooks, dependencies, editor tasks or CI workflows."
  else printf '**%s finding(s). Do not merge.**\n\n| What | File | Signs |\n| --- | --- | --- |\n%s' "$count" "$rows"; fi
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
[ "$count" -eq 0 ] && echo "Bastion: clean." && exit 0
echo "Bastion: $count finding(s)." && exit 1
