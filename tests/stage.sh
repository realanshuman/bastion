set -e; F="${1:?usage: bash $0 <fake home folder>}"; export HOME="$F"
dev(){ GIT_AUTHOR_NAME=Dev GIT_AUTHOR_EMAIL=dev@example.com GIT_COMMITTER_NAME=Dev GIT_COMMITTER_EMAIL=dev@example.com git "$@"; }
evil(){ GIT_AUTHOR_NAME=www GIT_AUTHOR_EMAIL=attacker@example.test GIT_COMMITTER_NAME=www GIT_COMMITTER_EMAIL=attacker@example.test git "$@"; }
PAD=$(printf 'A%.0s' $(seq 1 300))
git init -q --bare "$F/remote/app.git"
mkdir -p "$F/work/app" && cd "$F/work/app" && git init -q -b main
printf '%s\n' "export default {" "  plugins: { tailwindcss: {}, autoprefixer: {} },"  "};" > postcss.config.mjs
printf '{ "name": "app", "scripts": { "dev": "next dev" } }\n' > package.json; echo "API_KEY=test-not-real" > .env; echo ".env" > .gitignore
dev add -A && dev commit -qm "init" && git remote add origin "$F/remote/app.git" && git push -q origin main
printf '%s\n' "global.i='1-183';var _\$_1a2b=(function(i,p){return 'http://203.0.113.77:1244/j/x'})('$PAD');" >> postcss.config.mjs
evil add -A && evil commit -qm "update postcss config" && git push -q origin main
git checkout -q -b feature/x && dev commit -q --allow-empty -m "wip" && git push -q origin feature/x && git checkout -q main
git config core.fsmonitor "touch $F/pwned"
mkdir -p "$F/work/lib" && cd "$F/work/lib" && git init -q -b main && echo "export const x = 1" > index.js && evil add -A && evil commit -qm "add helper"
mkdir -p "$F/work/other" && cd "$F/work/other" && git init -q -b main && echo ok > README.md && dev add -A && dev commit -qm init
echo staged
