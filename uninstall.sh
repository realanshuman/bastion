#!/usr/bin/env bash
# uninstall.sh: stop and remove Bastion background agents. --purge also deletes the tool folder.
LA="$HOME/Library/LaunchAgents"
LAUNCHCTL="${BASTION_LAUNCHCTL:-launchctl}"
for lbl in com.bastion.guard.scan com.bastion.guard.watcher; do
  p="$LA/$lbl.plist"
  [ -f "$p" ] && { "$LAUNCHCTL" unload "$p" 2>/dev/null; rm -f "$p"; echo "removed $lbl"; }
done
# migrate: clean any legacy-named agents from older builds
for p in "$LA"/com.*.securityguard*.plist; do
  [ -f "$p" ] && { "$LAUNCHCTL" unload "$p" 2>/dev/null; rm -f "$p"; echo "removed legacy $(basename "$p")"; }
done
pkill -f "$HOME/.security-guard/watcher.sh" 2>/dev/null || true
[ -f "$HOME/.security-guard/harden.sh" ] && bash "$HOME/.security-guard/harden.sh" remove >/dev/null 2>&1 && echo "execution guard removed from ~/.zshrc"
# the bastion command in terminal windows: only the lines and the link Bastion added
if [ -x "$HOME/.security-guard/bin/bastion" ]; then
  msg=$("$HOME/.security-guard/bin/bastion" path remove --yes 2>/dev/null); case "$msg" in *Removed*) echo "bastion command removed from your terminal setup";; esac
else
  MA="# >>> bastion command line >>>"; MB="# <<< bastion command line <<<"
  for rc in "$HOME/.zshrc" "$HOME/.bash_profile" "$HOME/.bash_login" "$HOME/.profile"; do
    [ -f "$rc" ] && grep -qxF "$MA" "$rc" || continue
    awk -v a="$MA" -v b="$MB" '$0==a{s=1} !s{print} $0==b{s=0}' "$rc" > "$rc.bastion-tmp" && cat "$rc.bastion-tmp" > "$rc"; rm -f "$rc.bastion-tmp"
    echo "bastion command removed from ${rc/#$HOME/~}"
  done
  f="$HOME/.config/fish/conf.d/bastion.fish"; [ -f "$f" ] && grep -qxF "$MA" "$f" && rm -f "$f" && echo "bastion command removed from ${f/#$HOME/~}"
  for l in "$HOME/.local/bin/bastion" "$HOME/bin/bastion"; do
    [ -L "$l" ] && case "$(readlink "$l")" in *"/.security-guard/bin/bastion") rm -f "$l"; echo "bastion command link removed from ${l/#$HOME/~}";; esac
  done
fi
echo "Bastion agents stopped."
[ "${1:-}" = "--purge" ] && { rm -rf "$HOME/.security-guard"; echo "tool folder purged."; } || echo "tool folder kept at ~/.security-guard"
