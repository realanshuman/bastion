<div align="center">

<img src="assets/icon.png" width="120" alt="Bastion"/>

# Bastion

**A tiny macOS app that guards your dev machine from sneaky, hidden malware in code config files.**

![Platform](https://img.shields.io/badge/platform-macOS%2014%2B-blue)
![Swift](https://img.shields.io/badge/Swift-6-orange)
![UI](https://img.shields.io/badge/UI-SwiftUI%20MenuBarExtra-purple)
![License](https://img.shields.io/badge/license-MIT-green)

<img src="assets/panel-preview.png" width="340" alt="Bastion panel"/>

</div>

## What is this?

Bastion lives in your **menu bar** (the strip at the top-right of your Mac). It quietly
watches for a nasty kind of attack that has been hitting developers: someone hides malware
inside an innocent-looking build file (like `postcss.config.js`), and it runs the moment you
type `npm run dev` or `npm test`. It steals passwords, tokens, and browser data, then phones
home — all without you noticing.

Bastion catches that. Green shield = you're safe. Orange shield = something's wrong, come look.

## The problem, in plain terms

- A teammate's laptop or account gets compromised.
- Their commits secretly add a few hidden lines to a config file in your shared repo.
- You pull the code and run it — the hidden code runs on **your** machine and steals your stuff.
- Regular antivirus misses it, because the attackers change the code slightly every time.

Bastion doesn't chase the exact code — it notices the **shape** of the trick (a config file
that suddenly has weird `require` calls, a giant one-line blob, or code hidden behind a wall
of spaces). That way it catches new variants too.

## What it does

- **Watches in real time** — every ~15 seconds it checks for the tell-tale signs: hidden
  staging folders in `/tmp`, sneaky hidden dependency folders, a malicious process running,
  or a connection to a known bad server.
- **Deep scan** — on login and every 6 hours, it reads all your build-config files and flags
  anything that looks injected.
- **Quarantines automatically** — if it finds obvious malware junk, it moves it somewhere safe
  (it never deletes your own code — it only warns you about that, so nothing you wrote is lost).
- **Blocks bad commits** — an optional git hook stops you from committing or pushing an
  infected config file by accident.

## The menu-bar panel, button by button

Click the shield in the menu bar to open it.

**Top row**
- **Shield icon + "Bastion"** — the app, and its version.
- **PROTECTED / N ALERTS** — quick status. A number means that many things need your attention.

**Status card** — big line tells you if you're clean or not, and when the last scan ran.

**Three tiles**
- **Repos** — how many code projects Bastion is watching.
- **Configs** — how many build-config files it checks.
- **Quarantine** — how many suspicious items it has locked away (0 is good).

**Scan Now** — runs a full check right now. Tick **"Git repos only (faster)"** to check just
your code projects for a quicker scan.

**Tabs**
- **Overview** — the on/off switches:
  - **Real-time watcher** — the always-on 15-second guard.
  - **Scheduled scan** — the every-6-hours + login deep scan.
  - **Protect N repos** — one click adds the "block bad commits" hook to your projects.
- **Activity** — a running list of everything Bastion has caught or done.
- **Quarantine** — the suspicious items it locked away, each with a **Reveal** button to see it
  in Finder.

**Bottom row**
- **Logs** — open the scan history folder. **GitHub** — the project page.
  **Refresh** — update the numbers now. **Quit** — close the app.
  (Quitting the app does **not** turn off protection — the watcher and scan run on their own.
  Use the switches to actually turn them off.)

## Where does it show up?

Bastion has **no Dock icon and no window** — it's a menu-bar app. After you open it, look at
the **top-right of your menu bar** for the shield:

- green shield = clean
- orange shield = a threat was found — click it

Can't see it? The menu bar might be full; remove another icon, or reopen it from
`~/Applications/Bastion.app`.

## Install

**Easy way:** download **Bastion.dmg** from
[Releases](https://github.com/realanshuman/bastion/releases), open it, drag Bastion into
Applications, and launch it. First time, right-click the app → **Open** (it's self-signed).

**From source:**
```bash
git clone https://github.com/realanshuman/bastion.git
cd bastion && bash build.sh     # builds the app + a .dmg
bash install.sh                  # turns on the background protection
```
Only want one part? `install.sh --scan` (deep scan only) or `install.sh --watch` (watcher only).

## Turn it off / remove it

```bash
bash uninstall.sh            # stop the background protection, keep the app
bash uninstall.sh --purge    # remove everything
```

## What it can't do (honest limits)

- It's a **specialist**, not a full antivirus — it's built for this one family of attacks plus
  the mess they leave behind. Keep a general scanner around too.
- It **cleans your machine**, but it can't fix the root cause if the bad code keeps coming from
  a compromised repo account — that needs you to rotate credentials and remove bad access.
- It's **self-signed**, so the first launch shows an "unidentified developer" warning
  (right-click → Open gets past it). App Store distribution would need an Apple Developer account.

## Files in this repo

| File | What it is |
|------|-----------|
| `app/SecurityGuard.swift` | the menu-bar app (SwiftUI) |
| `scanner.sh` | the detector that finds the malware |
| `guard.sh` | runs a scan, quarantines junk, alerts you |
| `watcher.sh` | the real-time 15-second guard |
| `git-guard` | blocks infected commits |
| `install.sh` / `uninstall.sh` | turn the background protection on/off |
| `build.sh` | builds the app and the .dmg |
