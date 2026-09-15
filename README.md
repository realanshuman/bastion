# Security Guard — targeted supply-chain injection defense

Protects against the config-injection payload family (postcss/orval `createRequire`
+ obfuscated loader, `/tmp` staging dirs, hidden `~/.node_module` trees, C2 23.27.20.187).
NOT a general antivirus.

## Parts
- `scanner.sh`  — read-only detector. `bash scanner.sh [dir...]` → exit 0 clean / 2 findings.
- `guard.sh`    — runs scanner, QUARANTINES unambiguous artifacts (moves to quarantine/),
                  ALERTS on repo config files (never auto-edits them), macOS notification + logs.
- `git-guard`   — blocks committing/pushing an infected config file.
- `com.anshuman.securityguard.plist` — scheduled runner (login + every 6h). NOT auto-installed.

## What it does automatically vs. asks you
- AUTO-QUARANTINE (safe, never legitimate): /tmp staging dirs, beacons, harvested loot, ~/.node_module(s).
- ALERT ONLY (you decide): infected repo config files, live loader process, live C2 connection.
  (Auto-editing repo files could destroy uncommitted work, so it won't.)

## Logs & alerts
- `logs/scan-<stamp>.log` per run; `ALERTS.txt` one line per detection; quarantined files in `quarantine/<stamp>/`.

## Run manually any time
    bash ~/.security-guard/guard.sh ~

## Giving this to someone else (e.g. a teammate)
The scripts are portable; only the launchd schedule needs each person's own paths,
so use the installer instead of copying plists.

1. Send them the folder (zip it):
       cd ~ && zip -r security-guard.zip .security-guard -x '.security-guard/logs/*' -x '.security-guard/quarantine/*'
2. They unzip anywhere and run:
       bash install.sh            # scheduled scan + live watcher (default)
       bash install.sh --scan     # 6-hourly scan only
       bash install.sh --watch    # real-time watcher only
3. To remove:
       bash ~/.security-guard/uninstall.sh          # stop agents, keep scripts
       bash ~/.security-guard/uninstall.sh --purge  # stop agents + delete everything

The installer auto-detects their username, generates their plists, and loads them.
Nothing is hardcoded to the original author's account.
