<div align="center">

<img src="assets/icon.png" width="120" alt="Bastion"/>

# Bastion

**A tiny macOS menu-bar app that stops hidden malware in your dev projects — before it runs.**

![Platform](https://img.shields.io/badge/platform-macOS%2014%2B-blue)
![Swift](https://img.shields.io/badge/Swift-6-orange)
![UI](https://img.shields.io/badge/UI-SwiftUI-purple)
![License](https://img.shields.io/badge/license-MIT-green)

<img src="assets/panel-preview.png" width="360" alt="Bastion panel"/>

</div>

## What is it?

Attackers have started hiding malware inside the ordinary config files of npm/JavaScript
projects (`postcss.config.js`, `vite.config.ts`, and friends). The moment you run
`npm run dev`, `build`, or `test`, the hidden code executes — quietly stealing your
tokens, browser sessions, and password-manager data, then phoning home.

**Bastion is a small, always-on guard for developers** that catches this. It lives in your
menu bar as a shield: **green means you're safe, orange means something needs your attention.**

It doesn't chase one exact virus — attackers change the code constantly. Instead it spots the
*shape* of the trick, so it catches new variants too.

## Why you'd want it

- 🛡️ **Blocks it before it runs** — refuses to start a dev server or execute a loader when a
  project config has been tampered with.
- ⚡ **Catches it in real time** — a background watcher spots and kills malicious processes and
  connections within seconds.
- 🔒 **Cleans up safely** — quarantines the junk it finds (it never edits your own code — it
  warns you instead, so nothing you wrote is lost).
- 🧠 **Doesn't cry wolf** — an allowlist for your own servers and an ignore-list for docs/tests
  keep false alarms away.
- 🙈 **Stays out of your way** — no Dock icon, no window; just a shield in the menu bar.

## Install

**Easiest:** download `Bastion.dmg` from the [latest release](https://github.com/realanshuman/bastion/releases),
open it, drag **Bastion** to Applications, and launch it. On first open, right-click the app →
**Open** (it's open-source and self-signed).

**From source:**
```bash
git clone https://github.com/realanshuman/bastion.git
cd bastion
bash build.sh      # builds Bastion.app and a .dmg
bash install.sh    # turns on the background protection
```
Want just one part? `install.sh --scan` (periodic scan only) or `install.sh --watch` (live watcher only).

## The menu-bar panel

Click the shield to open it:

- **Status card** — safe or not, and when it last scanned.
- **Repos / Configs / Quarantine** — how much it's watching, and what it has locked away.
- **Scan Now** — check everything on demand (tick *Git repos only* for a faster pass).
- **Overview** — switches for the real-time watcher, the scheduled scan, and one-click
  "protect my repos" (adds a git hook that blocks infected commits).
- **Activity** — a log of everything it has caught or done.
- **Quarantine** — the suspicious items it has isolated, with a Reveal button.

## Make it yours

Bastion reads two simple text files in `~/.security-guard/`:

- **`allowlist.txt`** — your own servers/APIs, so their traffic is never mistaken for a threat.
- **`blocklist.txt`** — known-bad addresses to block (ships with sensible defaults).

One IP or hostname per line; `#` for comments.

## How it works (three layers)

1. **Prevent** — command guards refuse to run a dev/build when a config is tampered with.
2. **Detect & stop** — a ~12s watcher auto-kills malicious processes and blocked connections.
3. **Scan** — a structural scan of your project configs on login and every few hours.

## Honest limits

- It's a **focused guard** for this family of supply-chain attacks plus the mess they leave —
  not a full antivirus. Keep a general scanner around too.
- It protects **your machine**. If malicious code keeps arriving in a shared repo, that has to
  be fixed at the source (revoke the bad access, rotate credentials).
- It's **self-signed**, so the first launch shows an "unidentified developer" prompt
  (right-click → Open gets past it).

## Uninstall

```bash
bash ~/.security-guard/uninstall.sh            # stop the background guard, keep the app
bash ~/.security-guard/uninstall.sh --purge    # remove everything
```

## License

MIT — see [LICENSE](LICENSE). Contributions welcome.
