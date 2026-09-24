<div align="center">

<img src="assets/icon.png" width="120" alt="Bastion"/>

# Bastion

**Stops hidden malware in your JavaScript projects before it runs — for you and for your AI coding agent.**

A tiny macOS menu-bar app, a command-line tool and an MCP server, in one download.

![Platform](https://img.shields.io/badge/platform-macOS%2014%2B-blue)
![Swift](https://img.shields.io/badge/Swift-6-orange)
![MCP](https://img.shields.io/badge/MCP-server-8A2BE2)
![License](https://img.shields.io/badge/license-MIT-green)

<img src="assets/panel-preview.png" width="360" alt="Bastion panel"/>

</div>

## What is it?

Attackers have started hiding malware in the ordinary files of npm/JavaScript projects:

- **config files** like `postcss.config.js` or `vite.config.ts` — the code runs the moment you type `npm run dev`, `build` or `test`
- **install hooks** in `package.json` — the code runs during `npm install`
- **editor tasks** in `.vscode/tasks.json` — the code runs as soon as you open the folder

Once it runs, it quietly steals your tokens, browser sessions and saved passwords, then phones home.

**Bastion is a small, always-on guard for developers that catches this.** It lives in your menu bar as a
shield: **green means you're safe, orange means something needs your attention.** It also plugs straight
into AI coding agents like Claude Code, Cursor and Codex, so they check a project *before* they run anything in it.

It doesn't chase one exact virus, because attackers change the code constantly. It spots the *shape* of the
trick, so it catches new variants too.

## Why you'd want it

- 🛡️ **Blocks it before it runs** — refuses to start a dev server or an install when a project has been tampered with.
- 🤖 **Keeps your AI agent safe too** — agents ask Bastion "is this repo safe to run?" before `npm install` or `npm run dev`.
- ⚡ **Catches it in real time** — a background watcher kills malicious processes and connections within seconds.
- 🔒 **Cleans up safely** — quarantines the junk it finds (you can put it back). It never edits your code; it tells you what to fix.
- 🧠 **Doesn't cry wolf** — an allowlist for your own servers and an ignore list for docs and tests keep false alarms away.
- 🙈 **Stays out of your way** — no Dock icon, no window, just a shield in the menu bar.

## Install

**Easiest:** download `Bastion.dmg` from the [latest release](https://github.com/realanshuman/bastion/releases),
open it, drag **Bastion** to Applications and launch it. On first open, right-click the app → **Open**
(it's open-source and self-signed). The first launch sets everything up in `~/.security-guard`,
including the `bastion` command.

**From source:**
```bash
git clone https://github.com/realanshuman/bastion.git
cd bastion
bash build.sh      # builds Bastion.app, the bastion CLI and a .dmg
bash install.sh    # turns on the background protection
```
Want just one part? `install.sh --scan` (periodic scan only) or `install.sh --watch` (live watcher only).

**Where to find it afterwards**

- The 🛡 shield sits in your menu bar, at the top-right of the screen.
- The `bastion` command lives at `~/.security-guard/bin/bastion`. To type just `bastion`, add it to your PATH once:
  ```bash
  echo 'export PATH="$HOME/.security-guard/bin:$PATH"' >> ~/.zshrc
  ```

## Use it with AI agents

Bastion is an [MCP](https://modelcontextprotocol.io) server, so any agent that speaks MCP can use it.

**Claude Code** — run this once, or click **copy cmd** under *ai agents* in the panel:
```bash
claude mcp add --scope user bastion -- ~/.security-guard/bin/bastion mcp
```

**Cursor, Claude Desktop, Windsurf** — add Bastion to the `mcpServers` section of the app's MCP config
(for Cursor that's `~/.cursor/mcp.json`). Use your full home path; `bastion connect` prints it for you:
```json
{ "mcpServers": { "bastion": { "command": "/Users/you/.security-guard/bin/bastion", "args": ["mcp"] } } }
```

**Codex CLI** — in `~/.codex/config.toml`:
```toml
[mcp_servers.bastion]
command = "/Users/you/.security-guard/bin/bastion"
args = ["mcp"]
```

Once it's connected, your agent is told to check a repository before running `install`, `dev`, `build`,
`test` or codegen in it, and to stop and show you the problem if the project isn't safe.

**What your agent gets**

| Tool | What it does |
| --- | --- |
| `bastion_check_path` | "Is it safe to run npm here?" — checks one project, usually in under a second |
| `bastion_status` | Is this Mac protected right now? Active threats and which protections are on |
| `bastion_scan` | Sweeps all your repos plus temp folders, processes and network; quarantines known junk |
| `bastion_findings` | The last scan's findings, each with a plain explanation and the exact fix |
| `bastion_activity` | What Bastion caught or changed recently |
| `bastion_quarantine` | What's locked away, and where it came from |
| `bastion_lists` | Your allowlist, blocklist and ignore list |
| `bastion_enable` | Turns a protection **on**: watcher, scheduled scan, execution guard or git push guard |

**Agents can make you safer, never less safe.** There's no tool to switch protection off, trust a host,
ignore a path, edit the blocklist or restore quarantined files, so a confused or tricked agent can't do
those things either. They're yours, from the command line, and they ask you to confirm. Every change is
written to the activity log and shows a notification.

> Honest note: an agent that can run shell commands has your permissions and could, in principle, remove
> Bastion itself. Bastion makes lowering protection explicit and loud rather than impossible.

## Command line

```bash
bastion status                  # is this Mac protected right now?
bastion check                   # is it safe to run install/dev/build in this folder?
bastion scan                    # scan all your git repos (--full scans your whole home folder)
bastion findings                # details and fixes from the last scan
bastion activity                # what Bastion caught or changed recently
bastion quarantine              # what's locked away (quarantine restore <id> puts a batch back)
bastion enable watcher          # or schedule, exec-guard, git-guard; "disable" turns one off
bastion allow add api.mycompany.com   # trust your own server
bastion connect                 # setup snippets for Claude Code, Cursor, Codex and others
```

Add `--json` to any command for machine-readable output. Exit codes: `0` all good · `2` threats found ·
`1` error, so `bastion check && npm install` works in scripts and CI.

## The menu-bar panel

Click the shield to open it:

- **Status card** — safe or not, and when it last scanned.
- **Repos / Configs / Locked** — how much it's watching, and what it has quarantined.
- **Scan now** — check everything on demand (tick *git repos only* for a faster pass).
- **Protection** — switches for the real-time watcher, the scheduled scan and the execution guard, plus
  one-click "protect my repos" (adds a git hook that blocks pushing infected configs).
- **AI agents** — copies the command that connects Bastion to Claude Code.
- **Activity** — a log of everything it has caught or changed.
- **Quarantine** — the suspicious items it has isolated, with a Reveal button.

## Make it yours

Bastion reads three small text files in `~/.security-guard/`. Edit them directly, or use the commands:

- **`allowlist.txt`** — your own servers and APIs, so their traffic is never mistaken for a threat (`bastion allow add …`).
- **`blocklist.txt`** — known-bad IP addresses; ships with known attacker servers (`bastion block add …`).
- **`ignore.txt`** — files that only *mention* malware signatures, like security docs or tests (`bastion ignore add …`).

One entry per line; `#` starts a comment. Updates never overwrite your lists; new known-bad addresses are merged in.

## How it works (three layers)

1. **Prevent** — command guards refuse to run `dev`, `build` or `install` in a tampered project, and a git
   hook blocks pushing an infected config.
2. **Detect & stop** — a watcher checks every ~12 seconds, kills malware loaders and connections to known
   attacker servers, and quarantines what they leave behind.
3. **Scan** — a structural scan of your projects (config files, source files, `package.json` install hooks
   and `.vscode` auto-run tasks) on demand, at login and every few hours.

## Honest limits

- It's a **focused guard** for this family of supply-chain attacks and the mess they leave, not a full
  antivirus. Keep a general scanner around too.
- It checks **your project's own** install hooks, not the hooks of every dependency deep in `node_modules`.
  `npm install --ignore-scripts` is the belt-and-braces option.
- It protects **your machine**. If malicious code keeps arriving in a shared repo, fix it at the source
  (revoke the bad access, rotate credentials).
- It's **self-signed**, so the first launch shows an "unidentified developer" prompt (right-click → Open gets past it).

## Uninstall

```bash
bash ~/.security-guard/uninstall.sh            # stop the background guard, keep the app
bash ~/.security-guard/uninstall.sh --purge    # remove everything
```

If you connected an agent, remove it there too (Claude Code: `claude mcp remove bastion`).

## License

MIT — see [LICENSE](LICENSE). Contributions welcome.
