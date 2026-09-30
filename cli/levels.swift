// levels.swift: protection levels. Most people pick one of three and never look further: Basic watches and warns,
// Recommended also stops malware before it runs or spreads, Maximum adds the online check and locks down AI agents.
// Each level sets only the protections it cares about; any other mix is "custom". Moving down a level, or turning on
// something that sends data, asks first. The push guard is never removed by a level (that's a file in each repo).
import Foundation

struct ProtectionLevel { let id, title, summary: String; let includes: [String] }

let PROTECTION_LEVELS: [ProtectionLevel] = [
    ProtectionLevel(id: "basic", title: "Basic",
                    summary: "Watches this Mac and checks your code on a schedule. Nothing changes in your terminal or your repositories.",
                    includes: ["Real-time watcher", "Scheduled scan", "Warns you about anything it finds"]),
    ProtectionLevel(id: "recommended", title: "Recommended",
                    summary: "Also stops malware before it can run or spread, and cleans up what it can prove, with undo.",
                    includes: ["Everything in Basic", "npm and node won't start in an infected project", "Checks each push before it leaves your Mac",
                               "Contains attacks on its own"]),
    ProtectionLevel(id: "maximum", title: "Maximum",
                    summary: "Also checks your packages against a public list of known malware, and stops AI agents from running npm in an unsafe project.",
                    includes: ["Everything in Recommended", "Online check with osv.dev (package names and versions only)", "Hard-guard for your AI agents"]),
]

/// What a level wants. nil: the level leaves it as it is.
struct LevelTarget { var watcher, schedule, execGuard: Bool?; var contain: Bool?; var osv, gitGuard, hardGuard: Bool? }

func levelTarget(_ id: String) -> LevelTarget? {
    switch id {
    case "basic": return LevelTarget(watcher: true, schedule: true, execGuard: false, contain: nil, osv: false, gitGuard: nil, hardGuard: nil)
    case "recommended": return LevelTarget(watcher: true, schedule: true, execGuard: true, contain: true, osv: false, gitGuard: true, hardGuard: nil)
    case "maximum": return LevelTarget(watcher: true, schedule: true, execGuard: true, contain: true, osv: true, gitGuard: true, hardGuard: true)
    default: return nil
    }
}

/// How things stand right now, in the terms levels use
struct ProtectionNow {
    let watcher, schedule, execGuard: Bool
    let autonomy: String
    let osv: Bool
    let unguardedRepos: Int
    let unguardedAgents: [(id: String, name: String)]
    var contain: Bool { autonomy == "contain" }
    var gitGuard: Bool { unguardedRepos == 0 }
    var hardGuard: Bool { unguardedAgents.isEmpty }
}

/// `loaded`: launchctl's list when the caller already has it
func protectionNow(loaded list: String? = nil) -> ProtectionNow {
    let loaded = list ?? run(LAUNCHCTL, ["list"], timeout: 10).out
    let open = agentsReport().filter { $0["installed"] as? Bool == true && $0["hard_guard"] as? Bool == false }
    return ProtectionNow(watcher: loaded.contains(WATCH_LABEL), schedule: loaded.contains(SCAN_LABEL), execGuard: execGuardOn(),
                         autonomy: autonomy(), osv: osvEnabled(),
                         unguardedRepos: repoRoots().filter { gitGuardState($0) == "unprotected" }.count,
                         unguardedAgents: open.map { ($0["id"] as? String ?? "", $0["name"] as? String ?? "") })
}

private func meets(_ t: LevelTarget, _ n: ProtectionNow) -> Bool {
    func ok(_ want: Bool?, _ have: Bool) -> Bool { want == nil || want == have }
    // "guard every repo / agent" is met when there's none left to guard; a level never asks to remove them
    return ok(t.watcher, n.watcher) && ok(t.schedule, n.schedule) && ok(t.execGuard, n.execGuard) && ok(t.contain, n.contain)
        && ok(t.osv, n.osv) && (t.gitGuard != true || n.gitGuard) && (t.hardGuard != true || n.hardGuard)
}

/// maximum · recommended · basic · custom (some other mix) · off (nothing watching)
func protectionLevel(_ n: ProtectionNow = protectionNow()) -> String {
    for id in ["maximum", "recommended", "basic"] where meets(levelTarget(id)!, n) { return id }
    return !n.watcher && !n.schedule && !n.execGuard ? "off" : "custom"
}

/// Each step that takes things from `n` to `level`: what it does, in plain words, and whether it lowers protection or
/// sends data (either one needs a person's yes)
func levelChanges(to level: String, from n: ProtectionNow) -> [[String: Any]] {
    guard let t = levelTarget(level) else { return [] }
    var out: [[String: Any]] = []
    func step(_ id: String, _ title: String, lowers: Bool = false, consent: String? = nil) {
        var s: [String: Any] = ["id": id, "title": title, "lowers": lowers]
        if let consent { s["consent"] = consent }
        out.append(s)
    }
    if let w = t.watcher, w != n.watcher { step(w ? "watcher:on" : "watcher:off", w ? "Turn on the real-time watcher" : "Turn off the real-time watcher", lowers: !w) }
    if let s = t.schedule, s != n.schedule { step(s ? "schedule:on" : "schedule:off", s ? "Turn on the scheduled scan" : "Turn off the scheduled scan", lowers: !s) }
    if let e = t.execGuard, e != n.execGuard {
        step(e ? "exec_guard:on" : "exec_guard:off", e ? "Turn on the execution guard (adds 3 lines to ~/.zshrc)" : "Turn off the execution guard", lowers: !e)
    }
    if let c = t.contain, c != n.contain { step(c ? "contain:on" : "contain:off", c ? "Contain attacks on its own, with undo" : "Only report what it finds", lowers: !c) }
    if t.gitGuard == true, !n.gitGuard {
        step("git_guard:on", "Guard \(n.unguardedRepos) \(n.unguardedRepos == 1 ? "repository" : "repositories") on push")
    }
    if let o = t.osv, o != n.osv {
        step(o ? "osv:on" : "osv:off", o ? "Check packages against osv.dev" : "Stop checking packages online", lowers: !o,
             consent: o ? "Sends package names and versions, never your code, to osv.dev." : nil)
    }
    if t.hardGuard == true { for a in n.unguardedAgents { step("hard_guard:" + a.id, "Hard-guard \(a.name)") } }
    return out
}

/// `bastion protect`: every level, which one you're on, and what choosing each would change
func levelsReport() -> [String: Any] {
    let n = protectionNow()
    let current = protectionLevel(n)
    return ["level": current,
            "levels": PROTECTION_LEVELS.map { l -> [String: Any] in
                ["id": l.id, "title": l.title, "summary": l.summary, "includes": l.includes, "current": l.id == current,
                 "changes": levelChanges(to: l.id, from: n)]
            }]
}

/// `bastion protect <level>`: makes exactly the listed changes. Lowering protection or sending data needs a yes.
func applyLevel(_ id: String) throws -> [String: Any] {
    guard let level = PROTECTION_LEVELS.first(where: { $0.id == id }) else { throw Failure("Levels: basic, recommended, maximum.") }
    try requireEngine()
    let steps = levelChanges(to: id, from: protectionNow())
    if steps.isEmpty { return ["ok": true, "level": protectionLevel(), "done": [String](), "message": "\(level.title) is already on. Nothing changed."] }
    if !wantJSON {
        print("Switching to \(level.title):")
        for s in steps { print("  · " + (s["title"] as? String ?? "") + ((s["consent"] as? String).map { "  (\($0))" } ?? "")) }
    }
    if steps.contains(where: { $0["lowers"] as? Bool == true || $0["consent"] != nil }) {
        try confirmWeakening("Switch to \(level.title)?", why: "This lowers protection or sends data to osv.dev, so a person has to confirm it.")
    }
    var done: [String] = [], failed: [String] = []
    for s in steps {
        let sid = s["id"] as? String ?? "", title = s["title"] as? String ?? ""
        let parts = sid.split(separator: ":", maxSplits: 1).map(String.init)
        let on = parts.count > 1 && parts[1] == "on"
        do {
            switch parts[0] {
            case "watcher": _ = try on ? enable(.watcher) : disable(.watcher)
            case "schedule": _ = try on ? enable(.schedule) : disable(.schedule)
            case "exec_guard": _ = try on ? enable(.execGuard) : disable(.execGuard)
            case "contain": _ = try on ? enable(.autoRespond) : disable(.autoRespond)
            case "git_guard": _ = try enable(.gitGuard)
            case "osv":
                updateSettings { $0["osv"] = on }
                logEvent("CHANGED: online malware check (osv.dev) turned \(on ? "ON" : "OFF")")
            case "hard_guard": _ = try setHook(parts[1], on: true)
            default: continue
            }
            done.append(title)
        } catch { failed.append(title) }
    }
    let now = protectionLevel()
    logEvent("CHANGED: protection level set to \(level.title)")
    var r: [String: Any] = ["ok": now == id, "level": now, "done": done]
    if !failed.isEmpty { r["failed"] = failed }
    r["message"] = now == id ? "Protection is now \(level.title)."
        : "Some changes didn't go through (\(failed.isEmpty ? "the setting didn't stick" : failed.joined(separator: ", "))). Protection is \(now)."
    return r
}

// MARK: - The last 7 days

/// scans (every scan log, clean ones too) · caught (stopped, quarantined, blocked or flagged) · fixed · changed (settings)
func weekSummary() -> [String: Any] {
    let since = Date().addingTimeInterval(-7 * 86400)
    let scans = scanLogPaths().filter { ((parseScanLog($0)["time"]).flatMap(parseISO) ?? .distantPast) >= since }.count
    let recent = activity(limit: 2000).filter { (($0["time"] as? String).flatMap(parseActivityTime) ?? .distantPast) >= since }
    func count(_ types: Set<String>) -> Int { recent.filter { types.contains($0["type"] as? String ?? "") }.count }
    return ["days": 7, "scans": scans, "caught": count(["killed", "quarantined", "blocked", "alert"]), "fixed": count(["fixed"]),
            "changed": count(["setting_changed"])]
}

/// Activity lines are stamped "yyyy-MM-dd HH:mm:ss" in local time
func parseActivityTime(_ s: String) -> Date? {
    let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.dateFormat = "yyyy-MM-dd HH:mm:ss"
    return f.date(from: String(s.prefix(19)))
}

// MARK: - How often the scheduled scan runs

let SCAN_INTERVALS = [1, 6, 24]

func scanEveryHours() -> Int {
    let h = settings()["scan_every_hours"] as? Int ?? 6
    return SCAN_INTERVALS.contains(h) ? h : 6
}

/// `bastion schedule 1h|6h|24h`: saved in settings.json, where install.sh reads it; a running schedule is reloaded
func setScanInterval(_ raw: String) throws -> [String: Any] {
    let s = raw.lowercased()
    let hours: Int? = ["1", "1h", "hourly", "hour", "every hour"].contains(s) ? 1
        : ["6", "6h", "6 hours"].contains(s) ? 6
        : ["24", "24h", "daily", "day", "every day", "1d"].contains(s) ? 24 : nil
    guard let hours else { throw Failure("Usage: bastion schedule 1h|6h|24h") }
    try requireEngine()
    let before = scanEveryHours()
    updateSettings { $0["scan_every_hours"] = hours }
    let running = agentLoaded(SCAN_LABEL)
    if running { _ = run("/bin/bash", [engine("install.sh"), "--scan"], timeout: 60) }
    let words = hours == 1 ? "every hour" : hours == 24 ? "once a day" : "every \(hours) hours"
    if before != hours { logEvent("CHANGED: scheduled scan set to run \(words)") }
    return ["ok": true, "changed": before != hours, "scan_every_hours": hours, "running": running,
            "message": "The scheduled scan runs at login and \(words)." + (running ? "" : " It's off right now; turn it on to use it.")]
}
