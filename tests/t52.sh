# t52: `bastion path`. Puts the bastion command in new terminal windows only after a yes, shows the exact change first,
# and takes out exactly what it added (a file it changed ends up byte for byte as it was)
F="${1:?usage: bash $0 <fake home folder>}"; export HOME="$F" BASTION_NO_NOTIFY=1 SHELL=/bin/zsh; B="$F/.security-guard/bin/bastion"; pass=0; fail=0
ok(){ if [ "$1" = "$2" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $3: got [$1] want [$2]"; fi; }
finds(){ "$1" -ilc 'command -v bastion' </dev/null 2>/dev/null | tail -1; }   # what a new terminal window finds
OURS="$F/.security-guard/bin/bastion"
same(){ [ "$(canon "$1")" = "$(canon "$2")" ] && echo same || echo "different ($1)"; }
canon(){ python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1"; }
reset(){ rm -rf "$F/.zshrc" "$F/.zprofile" "$F/.bash_profile" "$F/.profile" "$F/.local" "$F/bin" "$F/.config"; "$B" path remove --yes --json >/dev/null 2>&1; rm -f "$F/.zshrc"; }

# zsh, no ~/.zshrc yet: the plan creates it; nothing happens without a yes
r=$("$B" path --json)
ok "$(echo "$r" | jq -r '.action + " " + (.creates_file|tostring) + " " + (.file | sub(".*/"; ""))')" "shell true .zshrc" "plan: create ~/.zshrc"
ok "$(echo "$r" | jq -r '.lines[1]')" 'export PATH="$PATH:$HOME/.security-guard/bin"' "the folder goes last on PATH"
ok "$("$B" path install --json | jq -r '.error | test("has to confirm")')" true "no yes, no change"
ok "$([ -e "$F/.zshrc" ] && echo exists || echo absent)" absent "…~/.zshrc wasn't created"
r=$("$B" path install --yes --json)
ok "$(echo "$r" | jq -r '[.ok, .changed, .how, .verified] | map(tostring) | join(" ")')" "true true shell true" "installed and checked in a new shell"
ok "$(same "$(finds zsh)" "$OURS")" same "a new zsh window finds bastion"
ok "$("$B" path install --yes --json | jq -r '.changed')" false "installing twice changes nothing"
ok "$(grep -c '>>> bastion command line >>>' "$F/.zshrc")" 1 "…one block"
ok "$("$B" status --json | jq -r '.command_line | .how + " " + (.installed|tostring)')" "shell true" "status knows"
ok "$("$B" activity --json | jq -r '[.events[] | select(.said | test("bastion command"))][0].said')" "Added the bastion command to ~/.zshrc" "activity says what changed"
ok "$("$B" path remove --json | jq -r '.error | test("has to confirm")')" true "removing asks too"
r=$("$B" path remove --yes --json)
ok "$(echo "$r" | jq -r '[.ok, .changed, .still_works] | map(tostring) | join(" ")')" "true true false" "removed"
ok "$([ -e "$F/.zshrc" ] && echo exists || echo absent)" absent "the ~/.zshrc it created is gone again"
ok "$(finds zsh)" "" "a new window doesn't find it"

# an existing ~/.zshrc (and the execution guard's block) come back exactly as they were
printf 'export EDITOR=vim\nalias ll="ls -l"\n' > "$F/.zshrc"; "$B" enable exec-guard --json >/dev/null
before=$(shasum < "$F/.zshrc")
"$B" path install --yes --json >/dev/null
ok "$(grep -c 'bastion execution guard >>>' "$F/.zshrc") $(grep -c 'bastion command line >>>' "$F/.zshrc")" "1 1" "both blocks live side by side"
ok "$(head -2 "$F/.zshrc" | tail -1)" 'alias ll="ls -l"' "the file's own lines are untouched"
"$B" path remove --yes --json >/dev/null
ok "$(shasum < "$F/.zshrc")" "$before" "remove leaves ~/.zshrc byte for byte as it was"
ok "$(grep -c 'bastion execution guard >>>' "$F/.zshrc")" 1 "…the execution guard is still there"
"$B" disable exec-guard --yes --json >/dev/null

# a symlinked ~/.zshrc (dotfiles) stays a symlink
mkdir -p "$F/dotfiles"; printf 'export A=1\n' > "$F/dotfiles/zshrc"; rm -f "$F/.zshrc"; ln -s "$F/dotfiles/zshrc" "$F/.zshrc"
"$B" path install --yes --json >/dev/null
ok "$([ -L "$F/.zshrc" ] && echo link || echo file) $(grep -c 'bastion command line >>>' "$F/dotfiles/zshrc")" "link 1" "writes through a symlinked ~/.zshrc"
"$B" path remove --yes --json >/dev/null
ok "$([ -L "$F/.zshrc" ] && echo link || echo file) $(cat "$F/dotfiles/zshrc")" "link export A=1" "…and removes through it"
rm -rf "$F/.zshrc" "$F/dotfiles"

# ~/.local/bin already on PATH: a link there, and the shell setup isn't touched at all
mkdir -p "$F/.local/bin"; printf 'export PATH="$HOME/.local/bin:$PATH"\n' > "$F/.zshrc"; before=$(shasum < "$F/.zshrc")
r=$("$B" path --json)
ok "$(echo "$r" | jq -r '.action + " " + (.link | sub(".*/\\.local"; "~/.local"))')" "link ~/.local/bin/bastion" "plan: a link in ~/.local/bin"
ok "$(echo "$r" | jq -r '.summary | test("shell setup doesn.t change")')" true "…and it says the setup doesn't change"
r=$("$B" path install --yes --json)
ok "$(echo "$r" | jq -r '[.how, .verified] | map(tostring) | join(" ")')" "link true" "linked and checked"
ok "$(same "$(readlink "$F/.local/bin/bastion")" "$OURS")" same "the link points at Bastion's command"
ok "$(shasum < "$F/.zshrc")" "$before" "~/.zshrc untouched"
ok "$(same "$(finds zsh)" "$F/.local/bin/bastion")" same "a new window finds it through the link"
"$B" path remove --yes --json >/dev/null
ok "$(if [ -e "$F/.local/bin/bastion" ] || [ -L "$F/.local/bin/bastion" ]; then echo there; else echo gone; fi)" gone "remove deletes the link, and leaves nothing in its place"
ok "$("$B" --version)" "$(cat "$F/.security-guard/VERSION")" "Bastion's own command is untouched"
ok "$("$B" status --json | jq -r '.command_line | (.ours | length | tostring) + " " + .how')" "0 none" "status: nothing left"

# something else called bastion comes first: nothing changes
printf '#!/bin/sh\necho other\n' > "$F/.local/bin/bastion"; chmod +x "$F/.local/bin/bastion"
r=$("$B" path install --yes --json)
ok "$(echo "$r" | jq -r '[.ok, .changed, .plan.action] | map(tostring) | join(" ")')" "false false conflict" "another bastion: refused"
ok "$(cat "$F/.local/bin/bastion" | tail -1) $(shasum < "$F/.zshrc" | cut -c1-8)" "echo other ${before:0:8}" "…nothing was touched"
rm -f "$F/.local/bin/bastion"

# set up by hand: status knows, remove leaves it alone
rm -rf "$F/.local" "$F/.zshrc"; printf 'export PATH="$PATH:$HOME/.security-guard/bin"\n' > "$F/.zprofile"
ok "$("$B" status --json | jq -r '.command_line.how')" manual "a PATH line of your own counts"
ok "$("$B" path --json | jq -r .action)" none "…and already works"
ok "$("$B" path remove --yes --json | jq -r '[.ok, .changed] | map(tostring) | join(" ")')" "false false" "remove won't touch your own line"
ok "$(cat "$F/.zprofile")" 'export PATH="$PATH:$HOME/.security-guard/bin"' "…it's still there"
rm -f "$F/.zprofile"

# bash reads the first of .bash_profile, .bash_login, .profile: with only .profile, that's the one, and no .bash_profile appears
export SHELL=/bin/bash; printf 'export B=1\n' > "$F/.profile"; before=$(shasum < "$F/.profile")
ok "$("$B" path --json | jq -r '.file | sub(".*/"; "")')" .profile "bash: .profile when it's the only one"
"$B" path install --yes --json >/dev/null
ok "$([ -e "$F/.bash_profile" ] && echo created || echo absent)" absent "no .bash_profile to hide .profile"
ok "$(same "$(finds bash)" "$OURS")" same "a new bash window finds bastion"
"$B" path remove --yes --json >/dev/null
ok "$(shasum < "$F/.profile")" "$before" ".profile back as it was"
rm -f "$F/.profile"
ok "$("$B" path --json | jq -r '.file | sub(".*/"; "")')" .bash_profile "bash with no startup file: .bash_profile"

# fish: a file of its own in conf.d, deleted again on remove (works even where fish isn't installed)
export SHELL=/usr/local/bin/fish
r=$("$B" path --json)
ok "$(echo "$r" | jq -r '.file | sub(".*/\\.config"; "~/.config")')" "~/.config/fish/conf.d/bastion.fish" "fish: its own conf.d file"
"$B" path install --yes --json >/dev/null
ok "$(sed -n 3p "$F/.config/fish/conf.d/bastion.fish")" '    set -gx PATH $PATH $HOME/.security-guard/bin' "fish syntax"
"$B" path remove --yes --json >/dev/null
ok "$([ -e "$F/.config/fish/conf.d/bastion.fish" ] && echo there || echo gone)" gone "remove deletes the fish file"

# a shell Bastion doesn't know: nothing changes, and it says what to add yourself
export SHELL=/bin/tcsh
ok "$("$B" path install --yes --json | jq -r '[.ok, .changed, .plan.action] | map(tostring) | join(" ")')" "false false unsupported" "tcsh: refused, not guessed"
# Ask offers the button (it never changes anything itself), and other questions still go where they did
export SHELL=/bin/zsh; rm -rf "$F/.config" "$F/.local" "$F/.zshrc"
ok "$("$B" ask "install the command line tool" --json | jq -r '.intent + " " + .actions[0].kind')" "command_line cli_install" "ask: install is a button"
ok "$([ -e "$F/.zshrc" ] && echo changed || echo untouched)" untouched "…and asking changed nothing"
ok "$("$B" ask "how do i use bastion in my terminal" --json | jq -r .intent)" command_line "ask: in my terminal"
ok "$("$B" ask "turn on the execution guard" --json | jq -r .intent)" turn_on "the execution guard still goes to turn_on"
"$B" path install --yes --json >/dev/null
ok "$("$B" ask "remove the cli" --json | jq -r '.actions[0].kind')" cli_remove "ask: remove is a button too"
"$B" path remove --yes --json >/dev/null

# uninstalling Bastion takes the lines out too: through the CLI, and without it
export SHELL=/bin/zsh; rm -rf "$F/.config" "$F/.local"; printf 'export EDITOR=vim\n' > "$F/.zshrc"; before=$(shasum < "$F/.zshrc")
"$B" path install --yes --json >/dev/null
ok "$(bash "$F/.security-guard/uninstall.sh" 2>/dev/null | grep -c 'bastion command removed')" 1 "uninstall.sh removes the command"
ok "$(shasum < "$F/.zshrc")" "$before" "…leaving ~/.zshrc as it was"
"$B" path install --yes --json >/dev/null; mv "$B" "$B.away"
ok "$(bash "$F/.security-guard/uninstall.sh" 2>/dev/null | grep -c 'bastion command removed from ~/.zshrc')" 1 "…and without the CLI"
ok "$(grep -c 'bastion command line' "$F/.zshrc")" 0 "…no block left"
mv "$B.away" "$B"
echo "passed $pass, failed $fail"
