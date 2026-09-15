<div align="center">

<img src="assets/icon.png" width="120" alt="Bastion"/>

# Bastion

**Supply-chain injection guard for macOS**

![Platform](https://img.shields.io/badge/platform-macOS%2014%2B-blue)
![Swift](https://img.shields.io/badge/Swift-6-orange)
![UI](https://img.shields.io/badge/UI-SwiftUI%20MenuBarExtra-purple)
![Scope](https://img.shields.io/badge/scope-targeted%20guard-informational)
![License](https://img.shields.io/badge/license-private-lightgrey)

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
