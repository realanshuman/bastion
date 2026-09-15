<div align="center">

<img src="assets/icon.png" width="120" alt="Bastion"/>

# Bastion

**Supply-chain injection guard for macOS**

![Platform](https://img.shields.io/badge/platform-macOS%2014%2B-blue)
![Swift](https://img.shields.io/badge/Swift-6-orange)
![UI](https://img.shields.io/badge/UI-SwiftUI%20MenuBarExtra-purple)
![Scope](https://img.shields.io/badge/scope-targeted%20guard-informational)
![License](https://img.shields.io/badge/license-MIT-green)

A native menu-bar app that watches for the config-injection supply-chain payload
family — the obfuscated loader that hides in `postcss.config.*` / `orval.config.*`,
stages stolen data in `/tmp`, and beacons to a C2. Detects **structurally**, so it
catches new variants that signature scanners miss.

<img src="assets/panel-preview.png" width="340" alt="Bastion panel"/>

</div>

## What it does

- **Real-time watcher** — every ~15s, catches runtime artifacts the moment they appear:
  `/tmp` staging dirs, beacons, harvested loot, hidden `~/.node_module` trees, a live
  loader process, or a connection to the known C2.
- **Scheduled deep scan** — at login + every 6h, walks every build-config file across
  your repos for the injection payload.
- **Auto-quarantine** — moves unambiguous artifacts (never legitimate) to a quarantine
  folder. **Never edits your repo files** — those are alert-only, so uncommitted work is safe.
- **git-guard** — blocks committing or pushing an infected config file.
- **Menu-bar UI** — shield icon (green = clean, orange = threat) with a click-down panel
  for status, Scan Now, and toggles.

## New in 2.0

- **Redesigned panel** — hero status card, live stat tiles (repos / configs / quarantine),
  and a segmented **Overview · Activity · Quarantine** view.
- **In-app quarantine viewer** — see every contained artifact with a Reveal-in-Finder action.
- **Activity log** — the full threat/quarantine history, in the panel.
- **Scan scope selector** — full-home scan, or "Git repos only" for a fast pass.
- **One-click git-guard install** — protect every unprotected repo (blocks infected commits)
  straight from the panel.
- **Live stats** — repos and config files under watch, at a glance.

## Why "structural" detection

The payload changes its campaign marker each run — `global.i='1-project'`, `'1-183'`,
`global.o='1-71'`, ... A string-matching scanner misses the next variant. Bastion flags
the *shape* instead: a `createRequire` in a config file, a single line over 500 chars,
code hidden behind a wall of whitespace, the `global.X='N-...'` pattern. Those don't occur
in legitimate config files, whatever marker the attacker picks.

## Install

**From the DMG** — open `Bastion.dmg`, drag Bastion to Applications, launch. (First open:
right-click -> Open, since it's self-signed, not notarized.)

**From source:**
```bash
git clone https://github.com/realanshuman/bastion.git
cd bastion && bash build.sh          # builds Bastion.app + Bastion.dmg
bash install.sh                       # sets up the background agents for your user
```

Install options: `install.sh --scan` (scheduled only) or `install.sh --watch` (watcher only).

## Where it shows up after installing

Bastion is a **menu-bar app** — it has **no Dock icon and no app window**. After you
launch it (from Applications, or it auto-starts at login once the scheduled agent is on),
look at the **top-right of your macOS menu bar** for a **shield icon**:

- 🛡️ **green shield** = clean / protected
- 🛡️ **orange shield** = a threat was found

**Click the shield** to open the control panel (status, Scan Now, and the watcher /
scheduled-scan toggles). If you don't see it, the menu bar may be full — widen it by
removing another icon, or relaunch from `~/Applications/Bastion.app`.

To confirm it's running from a terminal: `pgrep -x Bastion`.

## Uninstall

```bash
bash uninstall.sh            # stop the background agents, keep the files
bash uninstall.sh --purge    # stop and remove everything
```

## Layout

| File | Role |
|------|------|
| `app/SecurityGuard.swift` | SwiftUI MenuBarExtra UI |
| `scanner.sh` | read-only structural detector (exit 0 clean / 2 findings) |
| `guard.sh` | scan -> quarantine -> alert |
| `watcher.sh` | ~15s real-time watch |
| `git-guard` | blocks infected commits/pushes |
| `install.sh` / `uninstall.sh` | portable per-user launchd setup |
| `build.sh` | compiles the app + dmg via Command Line Tools |

## Honest limits

- **Targeted, not antivirus.** It defends against this specific supply-chain family and
  the hygiene artifacts around it — pair it with a general scanner for broad coverage.
- **Detection + containment, not root cause.** It can't stop a payload reappearing from a
  compromised repo account; that needs credential rotation and access cleanup upstream.
- **Self-signed.** Fine for personal/team use; App Store distribution needs a Developer ID.
