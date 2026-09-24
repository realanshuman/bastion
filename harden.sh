#!/usr/bin/env bash
# harden.sh — turn Bastion's execution guard on/off by putting the shims first on PATH.
set -uo pipefail
SHIMS="$HOME/.security-guard/shims"
RC="$HOME/.zshrc"
MARK_A="# >>> bastion execution guard >>>"
MARK_B="# <<< bastion execution guard <<<"
case "${1:-status}" in
  install)
    [ -f "$RC" ] || touch "$RC"
    if ! grep -qF "$MARK_A" "$RC"; then
      printf '\n%s\nexport PATH="%s:$PATH"\n%s\n' "$MARK_A" "$SHIMS" "$MARK_B" >> "$RC"
    fi
    echo "installed" ;;
  remove)
    [ -f "$RC" ] && awk -v a="$MARK_A" -v b="$MARK_B" '$0==a{s=1} !s{print} $0==b{s=0}' "$RC" > "$RC.tmp" && mv "$RC.tmp" "$RC"
    echo "removed" ;;
  status)
    grep -qF "$MARK_A" "$RC" 2>/dev/null && echo "on" || echo "off" ;;
esac
