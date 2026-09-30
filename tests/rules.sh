. "$HOME/.security-guard/lib.sh"
T="${1:?usage: bash $0 <scratch folder>}"; pass=0; fail=0
ok(){ if [ "$1" = "$2" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $3: got [$1] want [$2]"; fi; }
L600=$(printf 'x%.0s' $(seq 1 600))
# --- configs that MUST stay clean ---
printf '%s\n' 'import { createRequire } from "module";' 'const require = createRequire(import.meta.url);' "export default { headers: [{ key: 'Content-Security-Policy', value: \"default-src 'self'; script-src 'self' $L600\" }] };" > "$T/next.config.mjs"
ok "$(config_reasons "$T/next.config.mjs")" "" "legit ESM config: createRequire + long CSP line"
printf '%s\n' "module.exports = { theme: { extend: { backgroundImage: { hero: 'url(data:image/png;base64,$(head -c 900 /dev/zero | base64 | tr -d '\n'))' } } } };" > "$T/tailwind.config.js"
ok "$(config_reasons "$T/tailwind.config.js")" "" "long base64 data-URI line"
printf '%s\n' "export default { safelist: ['$(printf 'text-red-%s ' $(seq 1 150))'] };" > "$T/safelist.config.js"
ok "$(config_reasons "$T/safelist.config.js")" "" "long safelist line"
printf '%s\n' "export default { plugins: [retrieval(), isFunction(x), evaluate()], note: '$L600' };" > "$T/words.config.js"
ok "$(config_reasons "$T/words.config.js")" "" "long line with retrieval(/isFunction(/evaluate("
# --- configs that MUST be flagged ---
ok "$(config_reasons "$S/fixture-infected/postcss.config.mjs")" "campaign-marker string-scrambler +createRequire" "campaign sample"
printf '%s\n' "export default {}; var _0x3fa1=['\\x68\\x74\\x74\\x70']; (function(_0x1b2c){ $L600 })();" > "$T/obf.config.js"
ok "$(config_reasons "$T/obf.config.js" | sed 's/:[0-9]*//')" "obfuscated-line" "javascript-obfuscator style long line"
printf 'module.exports = {};%150s%s\n' '' "eval(atob('ZG9jdW1lbnQ='))" > "$T/pad.config.js"
ok "$(config_reasons "$T/pad.config.js")" "hidden-padding" "payload pushed off-screen with padding"
printf '%s\n' "export default {}; global.o = \"1-71\";" > "$T/marker.config.js"
ok "$(config_reasons "$T/marker.config.js")" "campaign-marker" "marker with spaces and double quotes"
# --- loader command lines ---
m(){ printf '%s' "$1" | grep -qE "$BASTION_LOADER_RE" && echo hit || echo miss; }
ok "$(m "node -e global.i='1-183';global.r=require;global.m=module;")" hit "node -e marker"
ok "$(m "/usr/local/bin/node --eval=global.i = '1-183';x()")" hit "--eval= joined, spaced marker"
ok "$(m "node -p global.r=require;require('x')")" hit "-p with global.r=require"
ok "$(m "node --print global.o='1-71'")" hit "--print"
ok "$(m "node -pe _\$_2b1f=(function(i,p){})")" hit "-pe scrambler"
ok "$(m "node -e console.log(process.version)")" miss "benign node -e"
ok "$(m "node server.js --eval-mode global.i='1-2'")" miss "--eval-mode is not --eval"
ok "$(m "node dist/index.js")" miss "plain node"
# --- remote peer parsing ---
printf '%s\n' 'COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME' \
 'node     4242 me   23u  IPv4 0x1      0t0  TCP 192.168.1.5:50123->23.27.20.187:443 (ESTABLISHED)' \
 'curl     4343 me   5u   IPv4 0x2      0t0  TCP 192.168.1.5:50124->123.27.20.187:443 (ESTABLISHED)' \
 'node     4444 me   7u   IPv6 0x3      0t0  TCP [2001:db8::5]:50125->[2001:db8::1]:8080 (SYN_SENT)' \
 'node     4545 me   8u   IPv4 0x4      0t0  TCP *:3000 (LISTEN)' > "$T/lsof.txt"
lsof(){ cat "$T/lsof.txt"; }
ok "$(remote_peers | tr '\n' '|')" "curl 4343 123.27.20.187|node 4242 23.27.20.187|node 4444 2001:db8::1|" "remote peer parsing (exact IPs)"
# --- protected paths ---
p(){ protected_path "$1" && echo protected || echo ok; }
ok "$(p /tmp)" protected "/tmp"; ok "$(p "$HOME")" protected "HOME"; ok "$(p "${TMPDIR}")" protected "TMPDIR (trailing slash)"
ok "$(p "${TMPDIR%/}/x")" ok "subdir of TMPDIR"; ok "$(p /private/tmp/.npm)" ok "/private/tmp/.npm"
echo "passed $pass, failed $fail"
