// bastion — command-line and MCP interface to the Bastion engine in ~/.security-guard.
//   People: bastion status | check [dir] | scan [dirs…] | findings | activity | quarantine | lists | enable/disable …
//   Agents: add --json to any command, or run `bastion mcp` (Model Context Protocol server over stdio).
// Agents can inspect and strengthen protection. Anything that lowers it needs a person at a terminal.
import Foundation

let VERSION = "3.1.0"
let HOME: String = {
    if let h = ProcessInfo.processInfo.environment["HOME"], !h.isEmpty { return h }
    return NSHomeDirectory()
}()
let ENGINE = HOME + "/.security-guard"
let LAUNCH_AGENTS = HOME + "/Library/LaunchAgents"
let WATCH_LABEL = "com.bastion.guard.watcher"
let SCAN_LABEL = "com.bastion.guard.scan"
let fm = FileManager.default

struct Failure: Error { let message: String; init(_ m: String) { message = m } }

extension StringProtocol {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
    func has(_ regex: String) -> Bool { range(of: regex, options: .regularExpression) != nil }
}

func engine(_ file: String) -> String { file.isEmpty ? ENGINE : ENGINE + "/" + file }

func readText(_ path: String) -> String {
    guard let d = fm.contents(atPath: path) else { return "" }
    return String(decoding: d, as: UTF8.self)
}

func requireEngine() throws {
    guard fm.fileExists(atPath: engine("scanner.sh")) else {
        throw Failure("Bastion's engine isn't installed at \(ENGINE). Open Bastion.app once (it sets itself up), or run ./install.sh from the source folder.")
    }
}

// MARK: - Running programs

final class Flag: @unchecked Sendable { var value = false }

/// Runs a program with an argument vector — untrusted text never goes through a shell.
/// stdin is closed so children can't read MCP traffic, and the whole tree is killed on timeout.
func run(_ exe: String, _ args: [String], timeout: TimeInterval = 120) -> (out: String, code: Int32, timedOut: Bool) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: exe)
    p.arguments = args
    var env = ProcessInfo.processInfo.environment
    env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin"
    env["HOME"] = HOME
    p.environment = env
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = FileHandle.nullDevice
    p.standardInput = FileHandle.nullDevice
    do { try p.run() } catch { return ("", 127, false) }
    let expired = Flag()
    let pid = p.processIdentifier
    let killer = DispatchWorkItem {
        guard p.isRunning else { return }
        expired.value = true
        for child in descendants(of: pid) { kill(child, SIGKILL) }
        kill(pid, SIGKILL)
    }
    DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: killer)
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    killer.cancel()
    return (String(decoding: data, as: UTF8.self), p.terminationStatus, expired.value)
}

func descendants(of root: pid_t) -> [pid_t] {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/ps")
    p.arguments = ["-axo", "pid=,ppid="]
    let pipe = Pipe()
    p.standardOutput = pipe; p.standardError = FileHandle.nullDevice; p.standardInput = FileHandle.nullDevice
    guard (try? p.run()) != nil else { return [] }
    let text = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    p.waitUntilExit()
    var kids: [pid_t: [pid_t]] = [:]
    for line in text.split(separator: "\n") {
        let n = line.split(separator: " ").compactMap { pid_t($0) }
        if n.count == 2 { kids[n[1], default: []].append(n[0]) }
    }
    var out: [pid_t] = [], stack = [root]
    while let x = stack.popLast() { for k in kids[x] ?? [] { out.append(k); stack.append(k) } }
    return out
}

// MARK: - JSON and time

func jsonText(_ obj: Any, pretty: Bool = false) -> String {
    var o: JSONSerialization.WritingOptions = [.sortedKeys, .withoutEscapingSlashes]
    if pretty { o.insert(.prettyPrinted) }
    guard JSONSerialization.isValidJSONObject(obj),
          let d = try? JSONSerialization.data(withJSONObject: obj, options: o) else { return "{}" }
    return String(decoding: d, as: UTF8.self)
}

func isoTime(_ d: Date) -> String {
    let f = ISO8601DateFormatter(); f.timeZone = .current; f.formatOptions = [.withInternetDateTime]
    return f.string(from: d)
}

func stampDate(_ stamp: String) -> Date? {
    let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.dateFormat = "yyyyMMdd-HHmmss"
    return f.date(from: stamp.replacingOccurrences(of: "live-", with: ""))
}

func friendly(_ iso: Any?) -> String {
    guard let s = iso as? String, let d = ISO8601DateFormatter().date(from: s) else { return "—" }
    let f = DateFormatter(); f.dateFormat = "MMM d, HH:mm"
    return f.string(from: d)
}

// MARK: - What each finding means

struct Kind { let id, title, severity, scope, why, fix: String; let autoHandled: Bool }

let KINDS: [String: Kind] = [
    "CONFIG": Kind(id: "injected_config", title: "Injected build config", severity: "critical", scope: "project",
        why: "A build config file (postcss, vite, next, tailwind, orval…) carries an obfuscated payload. Build tools execute their config files, so running dev, build, test or codegen here would run the malware.",
        fix: "Don't run install/dev/build/test in this repo. `git log -p -- <target>` shows who changed the file; `git checkout <good-commit> -- <target>` restores the clean version. Then run `bastion check` again.",
        autoHandled: false),
    "SOURCE": Kind(id: "source_payload", title: "Malware code in a source file", severity: "high", scope: "project",
        why: "A JavaScript/TypeScript file contains the obfuscation signature this malware family uses.",
        fix: "Remove the injected code or restore the file from git. If it's documentation or a test that only quotes the signature, the user can mark it benign with `bastion ignore add <pattern>`.",
        autoHandled: false),
    "SCRIPT": Kind(id: "install_hook", title: "Suspicious npm install hook", severity: "high", scope: "project",
        why: "package.json runs a command automatically during install (preinstall/install/postinstall/prepare) that downloads or decodes code, or contacts a raw IP address.",
        fix: "Don't run npm/pnpm/yarn/bun install here until the hook has been reviewed. If it isn't expected, remove it and check the commit that added it. `npm install --ignore-scripts` installs without running hooks.",
        autoHandled: false),
    "AUTORUN": Kind(id: "editor_autorun", title: "Editor auto-run task", severity: "medium", scope: "project",
        why: ".vscode/tasks.json has a task that runs automatically when the folder is opened in VS Code or Cursor — a known way malicious repositories run code the moment they're opened.",
        fix: "Read the task's command before opening this folder in an editor. If nobody on the team added it, delete the task and check the commit that added it. Keep the editor's automatic-tasks setting off.",
        autoHandled: false),
    "STAGING": Kind(id: "staging_folder", title: "Malware staging folder", severity: "high", scope: "machine",
        why: "A temporary folder this stealer uses to collect data before uploading it. It means the payload has run on this Mac.",
        fix: "A normal scan (`bastion scan`) moves it to quarantine. Because the payload ran, change passwords, tokens and API keys that were on this Mac — from a different, clean device.",
        autoHandled: true),
    "BEACON": Kind(id: "beacon_file", title: "Infection marker file", severity: "high", scope: "machine",
        why: "A small timestamp file the malware writes to mark this machine as infected.",
        fix: "A normal scan (`bastion scan`) moves it to quarantine. Treat this Mac as compromised and rotate credentials from a clean device.",
        autoHandled: true),
    "HARVEST": Kind(id: "stolen_data", title: "Stolen-data bundle", severity: "critical", scope: "machine",
        why: "System details, environment variables and browser-extension data collected and staged for upload.",
        fix: "A normal scan (`bastion scan`) moves it to quarantine. Assume everything in .env files and browser profiles on this Mac was exposed: rotate credentials and move any crypto-wallet funds, from a clean device.",
        autoHandled: true),
    "HIDDENDEP": Kind(id: "hidden_runtime", title: "Hidden malware runtime", severity: "high", scope: "machine",
        why: "A hidden ~/.node_module(s) folder where the malware installs its own network libraries.",
        fix: "A normal scan (`bastion scan`) moves it to quarantine.",
        autoHandled: true),
    "PROCESS": Kind(id: "loader_process", title: "Malware loader running", severity: "critical", scope: "machine",
        why: "A `node -e` process carrying this campaign's loader marker is running right now.",
        fix: "Stop it now: kill -9 <target>. Turn on the real-time watcher (`bastion enable watcher`) so loaders are killed automatically.",
        autoHandled: false),
    "NETWORK": Kind(id: "c2_connection", title: "Connection to a known attacker server", severity: "critical", scope: "machine",
        why: "A process is connected to an address on the blocklist (a known command-and-control server).",
        fix: "Find it with `lsof -nP -i | grep <target>` and quit that process. The real-time watcher kills node-based processes that do this automatically.",
        autoHandled: false),
]

func makeFinding(_ code: String, _ target: String, _ detail: String) -> [String: Any] {
    let k = KINDS[code] ?? Kind(id: code.lowercased(), title: code, severity: "high", scope: "project", why: "", fix: "", autoHandled: false)
    var f: [String: Any] = ["kind": k.id, "title": k.title, "severity": k.severity, "scope": k.scope,
                            "detail": detail, "explanation": k.why, "auto_handled": k.autoHandled]
    var shown = target
    switch code {
    case "PROCESS":
        let pids = target.split(separator: ",").compactMap { Int($0.trimmed) }
        f["pids"] = pids; shown = pids.map(String.init).joined(separator: " ")
    case "NETWORK": f["ip"] = target
    default: f["path"] = target
    }
    f["remediation"] = k.fix.replacingOccurrences(of: "<target>", with: shown)
    return f
}

/// Engine output is one finding per line: KIND|target|detail
func parseFindings(_ text: String) -> [[String: Any]] {
    var out: [[String: Any]] = []
    for raw in text.split(separator: "\n") {
        let line = raw.trimmed
        guard let a = line.firstIndex(of: "|"), let b = line.lastIndex(of: "|"), a < b else { continue }
        let code = String(line[..<a])
        guard KINDS[code] != nil else { continue }
        out.append(makeFinding(code, String(line[line.index(after: a)..<b]), String(line[line.index(after: b)...])))
    }
    let configs = Set(out.filter { $0["kind"] as? String == "injected_config" }.compactMap { $0["path"] as? String })
    return out.filter { !($0["kind"] as? String == "source_payload" && configs.contains($0["path"] as? String ?? "")) }
}

// MARK: - Paths and repos

func resolveDir(_ raw: String) throws -> String {
    var s = raw.trimmed
    guard !s.isEmpty else { throw Failure("No path given.") }
    if s == "~" { s = HOME } else if s.hasPrefix("~/") { s = HOME + s.dropFirst(1) }
    if !s.hasPrefix("/") { s = fm.currentDirectoryPath + "/" + s }
    var path = URL(fileURLWithPath: s).standardizedFileURL.path
    var isDir: ObjCBool = false
    guard fm.fileExists(atPath: path, isDirectory: &isDir) else { throw Failure("Path not found: \(path)") }
    if !isDir.boolValue { path = (path as NSString).deletingLastPathComponent }
    guard path != "/" else { throw Failure("Refusing to scan the whole disk — pass a project folder.") }
    return path
}

func repoRoots() -> [String] {
    run("/usr/bin/find", [HOME, "-maxdepth", "4", "-type", "d", "-name", ".git",
                          "-not", "-path", "*/node_modules/*", "-not", "-path", "*/Library/*"], timeout: 90).out
        .split(separator: "\n").map(String.init).filter { $0.hasSuffix("/.git") }.map { String($0.dropLast(5)) }.sorted()
}

let globalHooksPath = (readText(HOME + "/.gitconfig") + readText(HOME + "/.config/git/config")).lowercased().contains("hookspath")

/// protected · unprotected · custom_hooks (the repo manages its own hooks; Bastion won't touch them)
func gitGuardState(_ repo: String) -> String {
    if globalHooksPath || readText(repo + "/.git/config").lowercased().contains("hookspath") { return "custom_hooks" }
    let hook = repo + "/.git/hooks/pre-push"
    guard fm.fileExists(atPath: hook) else { return "unprotected" }
    let body = readText(hook)
    return body.contains("security-guard") || body.contains("Bastion") ? "protected" : "custom_hooks"
}

// MARK: - Live checks

func entries(_ text: String, wholeLine: Bool = false) -> [String] {
    text.split(separator: "\n").compactMap { raw -> String? in
        let s = raw.trimmed
        if s.isEmpty || s.hasPrefix("#") { return nil }
        return wholeLine ? s : s.split(whereSeparator: { $0 == " " || $0 == "\t" }).first.map(String.init)
    }
}
func listEntries(_ file: String) -> [String] { entries(readText(engine(file)), wholeLine: file == "ignore.txt") }

/// grep -w semantics: 23.27.20.187 must not match inside 123.27.20.187
func containsWord(_ hay: String, _ needle: String) -> Bool {
    func wordy(_ c: Character?) -> Bool { guard let c else { return false }; return c.isLetter || c.isNumber || c == "_" }
    var from = hay.startIndex
    while from < hay.endIndex, let r = hay.range(of: needle, range: from..<hay.endIndex) {
        let before: Character? = r.lowerBound == hay.startIndex ? nil : hay[hay.index(before: r.lowerBound)]
        let after: Character? = r.upperBound == hay.endIndex ? nil : hay[r.upperBound]
        if !wordy(before) && !wordy(after) { return true }
        from = hay.index(after: r.lowerBound)
    }
    return false
}

func liveLoaders() -> [[String: Any]] {
    var hits: [[String: Any]] = []
    for line in run("/bin/ps", ["-axo", "pid=,args="], timeout: 15).out.split(separator: "\n") {
        let s = line.trimmed
        guard let sp = s.firstIndex(of: " "), let pid = Int(s[..<sp]) else { continue }
        let args = s[sp...].trimmed
        guard let exe = args.split(separator: " ").first,
              (String(exe) as NSString).lastPathComponent.hasPrefix("node") else { continue }
        if args.has(#"\s(-e|--eval)\s.*(global\.[a-z]{1,2}\s*=|_\$_[0-9a-f]{4}\s*=|createRequire)"#) {
            hits.append(["pid": pid, "command": String(args.prefix(160))])
        }
    }
    return hits
}

func liveC2() -> [[String: Any]] {
    let allow = Set(listEntries("allowlist.txt"))
    let block = listEntries("blocklist.txt").filter { !allow.contains($0) }
    guard !block.isEmpty else { return [] }
    var hits: [[String: Any]] = []
    for line in run("/usr/sbin/lsof", ["-nP", "-i"], timeout: 20).out.split(separator: "\n") where line.contains("ESTABLISHED") {
        let l = String(line)
        for ip in block where containsWord(l, ip) {
            let cols = l.split(separator: " ")
            hits.append(["ip": ip, "process": cols.first.map(String.init) ?? "?", "pid": cols.count > 1 ? Int(cols[1]) ?? 0 : 0])
        }
    }
    return hits
}

func agentLoaded(_ label: String) -> Bool { run("/bin/launchctl", ["list"], timeout: 10).out.contains(label) }
func execGuardOn() -> Bool { readText(HOME + "/.zshrc").contains("# >>> bastion execution guard >>>") }

// MARK: - Scan logs, quarantine, activity

func scanLogPaths() -> [String] {
    ((try? fm.contentsOfDirectory(atPath: engine("logs"))) ?? [])
        .filter { $0.hasPrefix("scan-") && $0.hasSuffix(".log") }.sorted().map { engine("logs/" + $0) }
}

func parseScanLog(_ path: String) -> [String: Any] {
    let text = readText(path)
    let stamp = ((path as NSString).lastPathComponent as NSString).deletingPathExtension.replacingOccurrences(of: "scan-", with: "")
    var result = "unknown"
    var quarantined: [[String: Any]] = []
    for line in text.split(separator: "\n").map(String.init) {
        if line.hasPrefix("RESULT:") { result = line.dropFirst(7).trimmed }
        if line.hasPrefix("  QUARANTINED: "), let arrow = line.range(of: " -> ") {
            let from = String(line[line.index(line.startIndex, offsetBy: 15)..<arrow.lowerBound])
            quarantined.append(["from": from, "to": String(line[arrow.upperBound...])])
        }
    }
    let moved = Set(quarantined.compactMap { $0["from"] as? String })
    let findings = parseFindings(text).map { f -> [String: Any] in
        var f = f
        if let p = f["path"] as? String, moved.contains(p) { f["handled"] = "quarantined" }
        return f
    }
    var out: [String: Any] = ["clean": result == "CLEAN", "result": result, "finding_count": findings.count,
                              "findings": findings, "quarantined": quarantined, "log": path]
    if let d = stampDate(stamp) { out["time"] = isoTime(d) }
    return out
}

/// Still a problem right now? Files: still on disk. Loaders: pid alive. (Connections are re-checked live.)
func stillPresent(_ f: [String: Any]) -> Bool {
    if f["handled"] != nil { return false }
    if let p = f["path"] as? String { return fm.fileExists(atPath: p) }
    if let pids = f["pids"] as? [Int] { return pids.contains { kill(pid_t($0), 0) == 0 } }
    return false
}

func quarantineItems() -> [[String: Any]] {
    let qdir = engine("quarantine")
    var items: [[String: Any]] = []
    for batch in ((try? fm.contentsOfDirectory(atPath: qdir)) ?? []).filter({ !$0.hasPrefix(".") }).sorted(by: >) {
        let base = qdir + "/" + batch
        var item: [String: Any] = ["id": batch]
        if let d = stampDate(batch) { item["time"] = isoTime(d) }
        let manifest = entries(readText(base + "/.manifest"), wholeLine: true)
        if manifest.isEmpty {
            item["stored_at"] = base; item["reason"] = "unknown"; items.append(item)   // batch from an older version
            continue
        }
        for line in manifest {
            let parts = line.split(separator: "\t", maxSplits: 1).map(String.init)
            guard fm.fileExists(atPath: base + parts[0]) else { continue }   // already restored
            var one = item
            one["original_path"] = parts[0]; one["stored_at"] = base + parts[0]
            one["reason"] = parts.count > 1 ? parts[1].lowercased() : "unknown"
            items.append(one)
        }
    }
    return items
}

func activity(limit: Int) -> [[String: Any]] {
    let lines = readText(engine("ALERTS.txt")).split(separator: "\n").map(String.init).filter { !$0.trimmed.isEmpty }
    return lines.suffix(max(1, limit)).reversed().map { line -> [String: Any] in
        let type: String
        if line.contains("KILLED") { type = "killed" }
        else if line.contains("QUARANTINED") || line.contains("quarantined,") { type = "quarantined" }
        else if line.contains("BLOCKED") { type = "blocked" }
        else if line.contains("CHANGED") { type = "setting_changed" }
        else if line.contains("ALERT") || line.contains("need your attention") { type = "alert" }
        else { type = "event" }
        let parts = line.components(separatedBy: "  ")
        let message = parts.dropFirst().joined(separator: "  ").trimmed
        return ["time": parts.first?.trimmed ?? "", "type": type, "message": message.isEmpty ? line : message]
    }
}

func logEvent(_ message: String) {
    let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.dateFormat = "yyyy-MM-dd HH:mm:ss"
    let line = "\(f.string(from: Date()))  \(message)\n"
    if let h = FileHandle(forWritingAtPath: engine("ALERTS.txt")) {
        h.seekToEndOfFile(); h.write(Data(line.utf8)); h.closeFile()
    } else { try? line.write(toFile: engine("ALERTS.txt"), atomically: true, encoding: .utf8) }
}

func notify(_ message: String) {
    if ProcessInfo.processInfo.environment["BASTION_NO_NOTIFY"] != nil { return }   // tests / CI
    _ = run("/usr/bin/osascript", ["-e", "display notification \"\(message)\" with title \"🛡 Bastion\""], timeout: 10)
}

// MARK: - Reports

final class RepoScan: @unchecked Sendable { var repos: [String] = []; var states: [String] = [] }

func statusReport(includeRepos: Bool) -> [String: Any] {
    let rs = RepoScan()
    let group = DispatchGroup()
    if includeRepos {
        DispatchQueue.global().async(group: group) { rs.repos = repoRoots(); rs.states = rs.repos.map(gitGuardState) }
    }
    let agents = run("/bin/launchctl", ["list"], timeout: 10).out
    let loaders = liveLoaders(), c2 = liveC2()
    let last = scanLogPaths().last.map(parseScanLog)
    let quarantine = quarantineItems()
    group.wait()

    var threats: [[String: Any]] = []
    for l in loaders {
        var f = makeFinding("PROCESS", "\(l["pid"] as? Int ?? 0)", "loader-running"); f["command"] = l["command"]; threats.append(f)
    }
    for c in c2 {
        var f = makeFinding("NETWORK", c["ip"] as? String ?? "", "c2-connection"); f["process"] = c["process"]; f["pid"] = c["pid"]; threats.append(f)
    }
    for f in (last?["findings"] as? [[String: Any]] ?? []) where f["path"] != nil && stillPresent(f) { threats.append(f) }

    let protection: [String: Any] = ["watcher": agents.contains(WATCH_LABEL), "scheduled_scan": agents.contains(SCAN_LABEL),
                                     "exec_guard": execGuardOn()]
    var out: [String: Any] = ["version": VERSION, "engine": ENGINE, "posture": threats.isEmpty ? "protected" : "at_risk",
                              "active_threats": threats, "protection": protection, "quarantine_count": quarantine.count]
    if let last {
        var ls: [String: Any] = ["result": last["result"] ?? "unknown", "clean": last["clean"] ?? false, "log": last["log"] ?? ""]
        if let t = last["time"] { ls["time"] = t }
        out["last_scan"] = ls
    } else { out["last_scan"] = NSNull() }
    if includeRepos {
        out["git_guard"] = ["repos": rs.repos.count,
                            "protected": rs.states.filter { $0 == "protected" }.count,
                            "unprotected": rs.states.filter { $0 == "unprotected" }.count,
                            "custom_hooks": rs.states.filter { $0 == "custom_hooks" }.count]
    }
    var summary = threats.isEmpty ? "Protected." : "\(threats.count) active threat\(threats.count == 1 ? "" : "s") — see active_threats[].remediation."
    if threats.isEmpty && !(protection["watcher"] as? Bool ?? false) { summary += " The real-time watcher is off (bastion_enable watcher turns it on)." }
    if last == nil { summary += " No scan has run yet." }
    out["summary"] = summary
    return out
}

func checkPath(_ raw: String) throws -> [String: Any] {
    try requireEngine()
    let dir = try resolveDir(raw)
    let started = Date()
    let r = run("/bin/bash", [engine("scanner.sh"), dir], timeout: 300)
    if r.timedOut { throw Failure("The check timed out after 5 minutes. Is \(dir) a single project folder?") }
    let all = parseFindings(r.out)
    let project = all.filter { ($0["scope"] as? String) == "project" }
    let machine = all.filter { ($0["scope"] as? String) == "machine" }
    var out: [String: Any] = [
        "path": dir, "safe_to_run": project.isEmpty, "findings": project, "machine_threats": machine,
        "checked": ["build configs", "source files", "npm install hooks", "editor auto-run tasks"],
        "duration_ms": Int(Date().timeIntervalSince(started) * 1000),
    ]
    out["advice"] = project.isEmpty
        ? "Nothing suspicious in this project. OK to run install, dev, build and test here."
        : "Do not run install, dev, build, test or codegen here until these findings are fixed. Show the user each finding's remediation."
    if !machine.isEmpty { out["machine_advice"] = "This Mac itself shows signs of infection. Run a full scan (bastion_scan / `bastion scan`) and tell the user." }
    return out
}

func scan(paths: [String], fullHome: Bool, readOnly: Bool) throws -> [String: Any] {
    try requireEngine()
    var roots: [String], scope: String
    if !paths.isEmpty { roots = try paths.map(resolveDir); scope = "paths" }
    else if fullHome { roots = [HOME]; scope = "home" }
    else { roots = repoRoots(); scope = "git_repos"; if roots.isEmpty { roots = [HOME]; scope = "home" } }
    let started = Date()
    var out: [String: Any] = ["scope": scope, "roots": roots.count, "read_only": readOnly]
    let r = run("/bin/bash", [engine(readOnly ? "scanner.sh" : "guard.sh")] + roots, timeout: 1800)
    if r.timedOut { throw Failure("The scan timed out after 30 minutes.") }
    if readOnly {
        let fs = parseFindings(r.out)
        out["clean"] = fs.isEmpty; out["findings"] = fs; out["quarantined"] = [[String: Any]]()
    } else {
        let logPath = r.out.split(separator: "\n").last(where: { $0.hasPrefix("LOG: ") }).map { String($0.dropFirst(5)) }
            ?? scanLogPaths().last ?? ""
        let parsed = parseScanLog(logPath)
        out["clean"] = parsed["clean"]; out["findings"] = parsed["findings"]; out["quarantined"] = parsed["quarantined"]; out["log"] = logPath
    }
    out["duration_ms"] = Int(Date().timeIntervalSince(started) * 1000)
    let n = (out["findings"] as? [Any])?.count ?? 0
    out["summary"] = n == 0 ? "Clean — nothing found." : "\(n) finding\(n == 1 ? "" : "s"). Each has an explanation and remediation; known-malicious leftovers were quarantined unless read_only."
    return out
}

func findingsReport() -> [String: Any] {
    guard let path = scanLogPaths().last else {
        return ["ran": false, "findings": [[String: Any]](), "message": "No scan has run yet. Run bastion_scan (or `bastion scan`)."]
    }
    var r = parseScanLog(path); r["ran"] = true
    let liveIPs = Set(liveC2().compactMap { $0["ip"] as? String })
    r["findings"] = (r["findings"] as? [[String: Any]] ?? []).map { f -> [String: Any] in
        var f = f
        f["still_present"] = (f["ip"] as? String).map { liveIPs.contains($0) } ?? stillPresent(f)
        return f
    }
    return r
}

func listsReport() -> [String: Any] {
    ["allowlist": listEntries("allowlist.txt"), "blocklist": listEntries("blocklist.txt"), "ignore": listEntries("ignore.txt"),
     "files": ["allowlist": engine("allowlist.txt"), "blocklist": engine("blocklist.txt"), "ignore": engine("ignore.txt")],
     "note": "Editing these lists is left to the user: bastion allow|block|ignore add|remove <value>."]
}

// MARK: - Protections

enum Feature: String {
    case watcher, schedule = "scheduled_scan", execGuard = "exec_guard", gitGuard = "git_guard"
    var title: String {
        switch self {
        case .watcher: return "real-time watcher"
        case .schedule: return "scheduled scan"
        case .execGuard: return "execution guard"
        case .gitGuard: return "git push guard"
        }
    }
    init?(_ s: String) {
        switch s.lowercased().replacingOccurrences(of: "-", with: "_") {
        case "watcher", "real_time_watcher", "realtime", "live": self = .watcher
        case "schedule", "scheduled_scan", "scheduled", "scan_schedule": self = .schedule
        case "exec_guard", "execution_guard", "exec": self = .execGuard
        case "git_guard", "git", "pre_push", "git_hook": self = .gitGuard
        default: return nil
        }
    }
}

func enable(_ f: Feature) throws -> [String: Any] {
    try requireEngine()
    switch f {
    case .watcher, .schedule:
        let label = f == .watcher ? WATCH_LABEL : SCAN_LABEL
        if agentLoaded(label) { return ["feature": f.rawValue, "enabled": true, "changed": false, "message": "The \(f.title) is already on."] }
        _ = run("/bin/bash", [engine("install.sh"), f == .watcher ? "--watch" : "--scan"], timeout: 60)
        let on = agentLoaded(label)
        if on { logEvent("CHANGED: \(f.title) turned ON") }
        return ["feature": f.rawValue, "enabled": on, "changed": on,
                "message": on ? "The \(f.title) is on." : "Couldn't start the \(f.title) — try its switch in the Bastion menu-bar app."]
    case .execGuard:
        if execGuardOn() { return ["feature": f.rawValue, "enabled": true, "changed": false, "message": "The execution guard is already on."] }
        _ = run("/bin/bash", [engine("harden.sh"), "install"], timeout: 20)
        let on = execGuardOn()
        if on { logEvent("CHANGED: execution guard turned ON") }
        return ["feature": f.rawValue, "enabled": on, "changed": on,
                "message": on ? "Execution guard is on for new terminal windows: node/npm/npx/pnpm/yarn/bun refuse to run in infected projects." : "Couldn't update ~/.zshrc."]
    case .gitGuard:
        var installed: [String] = [], skipped: [String] = [], already = 0
        for repo in repoRoots() {
            switch gitGuardState(repo) {
            case "protected": already += 1
            case "unprotected":
                let hooks = repo + "/.git/hooks", dst = hooks + "/pre-push"
                try? fm.createDirectory(atPath: hooks, withIntermediateDirectories: true)
                if (try? fm.copyItem(atPath: engine("git-guard"), toPath: dst)) != nil { chmod(dst, 0o755); installed.append(repo) }
            default: skipped.append(repo)
            }
        }
        if !installed.isEmpty { logEvent("CHANGED: git push guard added to \(installed.count) repo(s)") }
        return ["feature": f.rawValue, "enabled": true, "changed": !installed.isEmpty, "installed": installed,
                "already_protected": already, "skipped_custom_hooks": skipped,
                "message": "Push guard added to \(installed.count) repo(s); \(already) already had it. Repos with their own hook setup were left alone."]
    }
}

func disable(_ f: Feature) throws -> [String: Any] {
    switch f {
    case .watcher, .schedule:
        let label = f == .watcher ? WATCH_LABEL : SCAN_LABEL
        let plist = LAUNCH_AGENTS + "/\(label).plist"
        _ = run("/bin/launchctl", ["unload", plist], timeout: 20)
        try? fm.removeItem(atPath: plist)
        if f == .watcher { _ = run("/usr/bin/pkill", ["-f", engine("watcher.sh")], timeout: 10) }
    case .execGuard:
        _ = run("/bin/bash", [engine("harden.sh"), "remove"], timeout: 20)
    case .gitGuard:
        throw Failure("To drop the push guard from a repo, delete .git/hooks/pre-push in that repo.")
    }
    logEvent("CHANGED: \(f.title) turned OFF (bastion CLI)")
    notify("The \(f.title) was turned off.")
    return ["feature": f.rawValue, "enabled": false, "changed": true, "message": "The \(f.title) is off."]
}

// MARK: - Lists (people only)

func ipFamily(_ s: String) -> Int32? {
    var v4 = in_addr(), v6 = in6_addr()
    if inet_pton(AF_INET, s, &v4) == 1 { return AF_INET }
    if inet_pton(AF_INET6, s, &v6) == 1 { return AF_INET6 }
    return nil
}

func isLocalAddress(_ s: String) -> Bool {
    if ipFamily(s) == AF_INET {
        let o = s.split(separator: ".").compactMap { Int($0) }
        guard o.count == 4 else { return true }
        switch (o[0], o[1]) {
        case (0, _), (10, _), (127, _), (169, 254), (192, 168), (172, 16...31), (100, 64...127), (224...255, _): return true
        default: return false
        }
    }
    let l = s.lowercased()
    return l == "::" || l == "::1" || l.hasPrefix("fe8") || l.hasPrefix("fe9") || l.hasPrefix("fea") || l.hasPrefix("feb") || l.hasPrefix("fc") || l.hasPrefix("fd")
}

func validHost(_ s: String) -> Bool {
    ipFamily(s) != nil || (s.count <= 253 && s.has(#"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$"#))
}

func addEntry(_ file: String, _ value: String, note: String?) throws -> Bool {
    if listEntries(file).contains(value) { return false }
    var text = readText(engine(file))
    if !text.isEmpty && !text.hasSuffix("\n") { text += "\n" }
    if let note, !note.isEmpty { text += "# \(note)\n" }
    text += value + "\n"
    try text.write(toFile: engine(file), atomically: true, encoding: .utf8)
    return true
}

func removeEntry(_ file: String, _ value: String) throws -> Bool {
    var removed = false
    let kept = readText(engine(file)).components(separatedBy: "\n").filter { line in
        let s = line.trimmed
        if s.isEmpty || s.hasPrefix("#") { return true }
        let key = file == "ignore.txt" ? s : (s.split(whereSeparator: { $0 == " " || $0 == "\t" }).first.map(String.init) ?? s)
        if key == value { removed = true; return false }
        return true
    }
    if removed { try kept.joined(separator: "\n").write(toFile: engine(file), atomically: true, encoding: .utf8) }
    return removed
}

func restore(_ id: String) throws -> [String: Any] {
    guard !id.isEmpty, !id.contains("/"), !id.hasPrefix(".") else { throw Failure("Not a quarantine id: \(id)") }
    let base = engine("quarantine/" + id)
    guard fm.fileExists(atPath: base) else { throw Failure("No quarantine batch named \(id). List them with `bastion quarantine`.") }
    let manifest = entries(readText(base + "/.manifest"), wholeLine: true)
    guard !manifest.isEmpty else { throw Failure("This batch is from an older version without a manifest. Move files back by hand from \(base).") }
    var restored: [String] = [], skipped: [String] = []
    for line in manifest {
        let original = String(line.split(separator: "\t").first ?? "")
        guard original.hasPrefix("/") else { continue }
        let stored = base + original
        guard !fm.fileExists(atPath: original), fm.fileExists(atPath: stored) else { skipped.append(original); continue }
        try? fm.createDirectory(atPath: (original as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        if (try? fm.moveItem(atPath: stored, toPath: original)) != nil { restored.append(original) } else { skipped.append(original) }
    }
    if !restored.isEmpty { logEvent("CHANGED: restored \(restored.count) item(s) from quarantine batch \(id) (bastion CLI)") }
    let left = manifest.filter { fm.fileExists(atPath: base + String($0.split(separator: "\t").first ?? "")) }
    if left.isEmpty { try? fm.removeItem(atPath: base) }   // batch fully restored
    return ["id": id, "restored": restored, "skipped": skipped]
}

// MARK: - Engine setup (used by Bastion.app on launch)

let ENGINE_FILES = ["scanner.sh", "guard.sh", "watcher.sh", "git-guard", "harden.sh", "install.sh", "uninstall.sh", "README.md", "LICENSE", "VERSION"]

func bootstrap() -> [String: Any] {
    let exe = URL(fileURLWithPath: Bundle.main.executablePath ?? CommandLine.arguments[0]).resolvingSymlinksInPath()
    let src = exe.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Resources/engine").path
    guard fm.fileExists(atPath: src + "/scanner.sh") else { return ["ok": false, "action": "none", "reason": "no bundled engine next to this binary"] }
    if fm.fileExists(atPath: engine(".git")) { return ["ok": true, "action": "skipped", "reason": "\(ENGINE) is a source checkout"] }
    let want = readText(src + "/VERSION").trimmed, have = readText(engine("VERSION")).trimmed
    if have == want && fm.isExecutableFile(atPath: engine("bin/bastion")) { return ["ok": true, "action": "up_to_date", "version": have] }

    for d in ["", "logs", "quarantine", "shims", "bin"] { try? fm.createDirectory(atPath: engine(d), withIntermediateDirectories: true) }
    var written: [String] = []
    func put(_ from: String, _ to: String) {
        try? fm.removeItem(atPath: to)
        if (try? fm.copyItem(atPath: from, toPath: to)) != nil { removexattr(to, "com.apple.quarantine", 0); written.append(to) }
    }
    for f in ENGINE_FILES where fm.fileExists(atPath: src + "/" + f) { put(src + "/" + f, engine(f)) }
    for f in (try? fm.contentsOfDirectory(atPath: src + "/shims")) ?? [] { put(src + "/shims/" + f, engine("shims/" + f)) }
    for f in ["allowlist.txt", "ignore.txt"] where !fm.fileExists(atPath: engine(f)) { put(src + "/" + f, engine(f)) }
    if fm.fileExists(atPath: engine("blocklist.txt")) {   // your list stays yours; new known-bad entries are merged in
        for ip in entries(readText(src + "/blocklist.txt")) { _ = try? addEntry("blocklist.txt", ip, note: nil) }
    } else { put(src + "/blocklist.txt", engine("blocklist.txt")) }
    put(exe.path, engine("bin/bastion"))
    for f in written where f.hasSuffix(".sh") || f.hasSuffix("git-guard") || f.contains("/shims/") || f.hasSuffix("/bin/bastion") { chmod(f, 0o755) }
    // a running watcher keeps old code until restarted
    if fm.fileExists(atPath: LAUNCH_AGENTS + "/\(WATCH_LABEL).plist") && agentLoaded(WATCH_LABEL) {
        _ = run("/bin/launchctl", ["kickstart", "-k", "gui/\(getuid())/\(WATCH_LABEL)"], timeout: 20)
    }
    return ["ok": true, "action": have.isEmpty ? "installed" : "updated", "from": have, "to": want, "engine": ENGINE]
}

// MARK: - MCP server (stdio, newline-delimited JSON-RPC 2.0)

let MCP_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]

let MCP_INSTRUCTIONS = """
Bastion guards this Mac against supply-chain malware in JavaScript/npm projects: obfuscated payloads injected into build config files (postcss, vite, next, tailwind, orval…), npm install hooks that download code, and editor tasks that run when a folder is opened.
- Before running install, dev, build, test or codegen commands in a repository for the first time in a session, or after pulling or checking out changes you did not write, call bastion_check_path on it. If safe_to_run is false, do not run those commands; show the user the findings and their remediation.
- Use bastion_status when the user asks whether their machine is safe, and bastion_scan for a full sweep.
- You can inspect and strengthen protection. Turning protection off, allowlisting hosts, ignoring paths, editing the blocklist and restoring quarantined files are reserved for the user: tell them the matching `bastion` command instead.
"""

func schema(_ props: [String: Any] = [:], required: [String] = []) -> [String: Any] {
    var s: [String: Any] = ["type": "object", "properties": props, "additionalProperties": false]
    if !required.isEmpty { s["required"] = required }
    return s
}

func annotations(_ title: String, readOnly: Bool) -> [String: Any] {
    ["title": title, "readOnlyHint": readOnly, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false]
}

let TOOLS: [[String: Any]] = [
    ["name": "bastion_status", "title": "Security status",
     "description": "Is this Mac protected right now? Returns posture (protected / at_risk), active threats with fixes, which protections are on, git push-guard coverage, the last scan result and quarantine count. Read-only, a few seconds.",
     "inputSchema": schema(), "annotations": annotations("Security status", readOnly: true)],
    ["name": "bastion_check_path", "title": "Preflight a project",
     "description": "Check a project folder before running npm/pnpm/yarn/bun install, dev, build, test or codegen in it. Looks for injected build configs, malware code in source files, suspicious npm install hooks and editor auto-run tasks. Read-only, usually a few seconds. safe_to_run=false means: do not run those commands.",
     "inputSchema": schema(["path": ["type": "string", "description": "Absolute path of the project folder (~ is allowed)."]], required: ["path"]),
     "annotations": annotations("Preflight a project", readOnly: true)],
    ["name": "bastion_scan", "title": "Scan for malware",
     "description": "Sweep every git repository under the home folder (or the given paths, or the whole home folder) plus temp folders, running processes and network connections. Known-malicious leftovers (staging folders, beacon files, hidden runtimes) are moved to quarantine, which is reversible; project files are never modified. Can take a minute.",
     "inputSchema": schema([
        "paths": ["type": "array", "items": ["type": "string"], "description": "Folders to scan instead of all git repositories."] as [String: Any],
        "full_home": ["type": "boolean", "description": "Scan the entire home folder (slower). Ignored when paths are given."],
        "read_only": ["type": "boolean", "description": "Report only: don't quarantine anything or write a scan log."],
     ]),
     "annotations": annotations("Scan for malware", readOnly: false)],
    ["name": "bastion_findings", "title": "Last scan findings",
     "description": "Findings from the most recent scan, each with severity, a plain-language explanation, exact remediation steps, and whether it is still present or was quarantined. Read-only.",
     "inputSchema": schema(), "annotations": annotations("Last scan findings", readOnly: true)],
    ["name": "bastion_activity", "title": "Recent activity",
     "description": "Recent security events, newest first: loaders killed, attacker connections cut, items quarantined, commands blocked, settings changed. Read-only.",
     "inputSchema": schema(["limit": ["type": "integer", "minimum": 1, "maximum": 200, "description": "How many events (default 20)."] as [String: Any]]),
     "annotations": annotations("Recent activity", readOnly: true)],
    ["name": "bastion_quarantine", "title": "Quarantined items",
     "description": "Items Bastion has quarantined, with original location, reason and time. Restoring is left to the user (`bastion quarantine restore <id>`). Read-only.",
     "inputSchema": schema(), "annotations": annotations("Quarantined items", readOnly: true)],
    ["name": "bastion_lists", "title": "Allow, block and ignore lists",
     "description": "The allowlist (trusted hosts), blocklist (known attacker IPs) and ignore list (benign files that only quote malware signatures). Editing them is left to the user. Read-only.",
     "inputSchema": schema(), "annotations": annotations("Allow, block and ignore lists", readOnly: true)],
    ["name": "bastion_enable", "title": "Turn on a protection",
     "description": "Turn ON a protection. watcher: real-time guard that kills malware loaders and attacker connections within seconds. scheduled_scan: scan at login and every 6 hours. exec_guard: node/npm/npx/pnpm/yarn/bun refuse to run in infected projects (new terminals). git_guard: pre-push hook in every git repo without its own hook setup. Agents can only turn protections on.",
     "inputSchema": schema(["feature": ["type": "string", "enum": ["watcher", "scheduled_scan", "exec_guard", "git_guard"]] as [String: Any]], required: ["feature"]),
     "annotations": annotations("Turn on a protection", readOnly: false)],
]

func callTool(_ name: String, _ a: [String: Any]) throws -> [String: Any] {
    switch name {
    case "bastion_status": return statusReport(includeRepos: true)
    case "bastion_check_path":
        guard let p = a["path"] as? String else { throw Failure("`path` is required: the project folder to check.") }
        return try checkPath(p)
    case "bastion_scan":
        let paths = (a["paths"] as? [Any])?.compactMap { $0 as? String } ?? []
        return try scan(paths: paths, fullHome: a["full_home"] as? Bool ?? false, readOnly: a["read_only"] as? Bool ?? false)
    case "bastion_findings": return findingsReport()
    case "bastion_activity": return ["events": activity(limit: min(max(a["limit"] as? Int ?? 20, 1), 200))]
    case "bastion_quarantine":
        return ["items": quarantineItems(), "note": "Restoring is left to the user: bastion quarantine restore <id>"]
    case "bastion_lists": return listsReport()
    case "bastion_enable":
        guard let s = a["feature"] as? String, let f = Feature(s) else {
            throw Failure("`feature` must be one of: watcher, scheduled_scan, exec_guard, git_guard.")
        }
        return try enable(f)
    default: throw Failure("Unknown tool: \(name)")
    }
}

func rpcResult(_ id: Any, _ result: [String: Any]) -> [String: Any] { ["jsonrpc": "2.0", "id": id, "result": result] }
func rpcError(_ id: Any, _ code: Int, _ message: String) -> [String: Any] {
    ["jsonrpc": "2.0", "id": id, "error": ["code": code, "message": message] as [String: Any]]
}

func handle(_ raw: Any) -> [String: Any]? {
    guard let msg = raw as? [String: Any] else { return rpcError(NSNull(), -32600, "Invalid Request") }
    guard let method = msg["method"] as? String else { return nil }   // a response to us, or noise
    guard let id = msg["id"] else { return nil }                      // notification: nothing to answer
    let params = msg["params"] as? [String: Any] ?? [:]
    switch method {
    case "initialize":
        let asked = params["protocolVersion"] as? String ?? ""
        return rpcResult(id, ["protocolVersion": MCP_VERSIONS.contains(asked) ? asked : "2025-06-18",
                              "capabilities": ["tools": ["listChanged": false]],
                              "serverInfo": ["name": "bastion", "title": "Bastion", "version": VERSION],
                              "instructions": MCP_INSTRUCTIONS])
    case "ping":
        return rpcResult(id, [:])
    case "tools/list":
        return rpcResult(id, ["tools": TOOLS])
    case "tools/call":
        let name = params["name"] as? String ?? ""
        guard TOOLS.contains(where: { $0["name"] as? String == name }) else { return rpcError(id, -32602, "Unknown tool: \(name)") }
        do {
            let result = try callTool(name, params["arguments"] as? [String: Any] ?? [:])
            return rpcResult(id, ["content": [["type": "text", "text": jsonText(result)]], "structuredContent": result, "isError": false])
        } catch let f as Failure {
            return rpcResult(id, ["content": [["type": "text", "text": f.message]], "isError": true])
        } catch {
            return rpcResult(id, ["content": [["type": "text", "text": "\(error)"]], "isError": true])
        }
    default:
        return rpcError(id, -32601, "Method not found: \(method)")
    }
}

func serveMCP() -> Never {
    func send(_ obj: Any) { FileHandle.standardOutput.write(Data((jsonText(obj) + "\n").utf8)) }
    while let line = readLine(strippingNewline: true) {
        let text = line.trimmed
        if text.isEmpty { continue }
        guard let msg = try? JSONSerialization.jsonObject(with: Data(text.utf8)) else {
            send(rpcError(NSNull(), -32700, "Parse error")); continue
        }
        if let batch = msg as? [Any] {
            let replies = batch.compactMap(handle)
            if !replies.isEmpty { send(replies) }
        } else if let reply = handle(msg) { send(reply) }
    }
    exit(0)
}

// MARK: - Human output

let TTY = isatty(STDOUT_FILENO) != 0
func paint(_ s: String, _ code: String) -> String { TTY ? "\u{1B}[\(code)m\(s)\u{1B}[0m" : s }
func good(_ s: String) -> String { paint(s, "32") }
func bad(_ s: String) -> String { paint(s, "31") }
func warn(_ s: String) -> String { paint(s, "33") }
func faint(_ s: String) -> String { paint(s, "2") }
func strong(_ s: String) -> String { paint(s, "1") }
func onOff(_ v: Any?) -> String { (v as? Bool ?? false) ? good("on") : faint("off") }

func seconds(_ r: [String: Any]) -> String { String(format: "%.1f", Double(r["duration_ms"] as? Int ?? 0) / 1000) }

/// ~/… for humans; relative to the project when it's inside the checked folder.
func shortPath(_ p: String, under root: String? = nil) -> String {
    if let root, p.hasPrefix(root + "/") { return String(p.dropFirst(root.count + 1)) }
    return p.hasPrefix(HOME + "/") ? "~/" + p.dropFirst(HOME.count + 1) : p
}

func printFindings(_ fs: [[String: Any]], under root: String? = nil) {
    for f in fs {
        let sev = f["severity"] as? String ?? "high"
        let tag = sev == "critical" ? bad("[critical]") : sev == "high" ? warn("[high]") : faint("[\(sev)]")
        var target = ""
        if let p = f["path"] as? String { target = shortPath(p, under: root) }
        else if let ip = f["ip"] as? String { target = ip }
        else if let pids = f["pids"] as? [Int] { target = "pid " + pids.map(String.init).joined(separator: " ") }
        let handled = (f["handled"] as? String).map { faint("  (\($0))") } ?? ""
        print("  \(bad("✗")) \(tag) \(strong(f["title"] as? String ?? ""))\(handled)")
        print("    \(target)  \(faint(f["detail"] as? String ?? ""))")
        print("    \(faint("why:")) \(f["explanation"] as? String ?? "")")
        print("    \(faint("fix:")) \(f["remediation"] as? String ?? "")")
    }
}

func humanStatus(_ s: [String: Any]) {
    let threats = s["active_threats"] as? [[String: Any]] ?? []
    let p = s["protection"] as? [String: Any] ?? [:]
    print("\(strong("bastion \(VERSION)")) · " + (threats.isEmpty ? good("protected ✓") : bad("\(threats.count) active threat\(threats.count == 1 ? "" : "s") ✗")))
    if !threats.isEmpty { printFindings(threats); print("") }
    print("  real-time watcher   \(onOff(p["watcher"]))")
    print("  scheduled scan      \(onOff(p["scheduled_scan"]))")
    print("  execution guard     \(onOff(p["exec_guard"]))")
    if let g = s["git_guard"] as? [String: Any] {
        let repos = g["repos"] as? Int ?? 0, prot = g["protected"] as? Int ?? 0, open = g["unprotected"] as? Int ?? 0
        print("  git push guard      \(prot) of \(repos) repos" + (open > 0 ? faint("   (bastion enable git-guard)") : ""))
    }
    if let l = s["last_scan"] as? [String: Any] {
        let clean = l["clean"] as? Bool ?? false
        print("  last scan           \(friendly(l["time"])) · " + (clean ? good("clean") : warn((l["result"] as? String ?? "").lowercased())))
    } else { print("  last scan           " + faint("never — run: bastion scan")) }
    let q = s["quarantine_count"] as? Int ?? 0
    print("  quarantine          " + (q == 0 ? faint("empty") : warn("\(q) item\(q == 1 ? "" : "s")")))
}

func connectInfo() -> [String: Any] {
    let bin = fm.isExecutableFile(atPath: engine("bin/bastion")) ? engine("bin/bastion")
        : URL(fileURLWithPath: Bundle.main.executablePath ?? CommandLine.arguments[0]).resolvingSymlinksInPath().path
    let server: [String: Any] = ["command": bin, "args": ["mcp"]]
    return ["command": bin, "args": ["mcp"],
            "claude_code": "claude mcp add --scope user bastion -- \"\(bin)\" mcp",
            "json": ["mcpServers": ["bastion": server]],
            "codex_toml": "[mcp_servers.bastion]\ncommand = \"\(bin)\"\nargs = [\"mcp\"]"]
}

func humanConnect(_ c: [String: Any]) {
    let bin = c["command"] as? String ?? "bastion"
    print(strong("Connect Bastion to your AI agent") + faint("  — it runs as a local MCP server: \(bin) mcp"))
    print("\n" + strong("Claude Code"))
    print("  \(c["claude_code"] as? String ?? "")")
    print("\n" + strong("Cursor") + faint("  (~/.cursor/mcp.json)") + ", " + strong("Claude Desktop") + ", " + strong("Windsurf") + faint("  — add to mcpServers:"))
    print("  \"bastion\": { \"command\": \"\(bin)\", \"args\": [\"mcp\"] }")
    print("\n" + strong("Codex CLI") + faint("  (~/.codex/config.toml)"))
    print((c["codex_toml"] as? String ?? "").split(separator: "\n").map { "  " + $0 }.joined(separator: "\n"))
    print("\n" + faint("Any other MCP client: a stdio server with command \"\(bin)\" and argument \"mcp\"."))
}

let HELP = """
bastion \(VERSION) — guard for supply-chain malware in JavaScript projects

  bastion status                  is this Mac protected right now?
  bastion check [dir]             safe to run install/dev/build here? (default: current folder)
  bastion scan [dirs…]            scan your git repos, or the given folders (--full: whole home folder,
                                  --read-only: report without quarantining)
  bastion findings                details and fixes from the last scan
  bastion activity [-n 20]        what Bastion caught or changed recently
  bastion quarantine              what's locked away  ·  quarantine restore <id>
  bastion lists                   allowlist, blocklist and ignore list
  bastion allow|block|ignore add|remove <value>
  bastion enable|disable watcher|schedule|exec-guard|git-guard
  bastion connect                 plug Bastion into Claude Code, Cursor, Codex…
  bastion mcp                     run as an MCP server over stdio (for AI agents)

Add --json to any command for machine-readable output.
Exit codes: 0 ok · 2 threats found · 1 error. Lowering protection asks for confirmation (--yes skips it).
"""

// MARK: - Main

let argv = Array(CommandLine.arguments.dropFirst())
if argv.contains("--version") { print(VERSION); exit(0) }
if argv.isEmpty || argv.contains("--help") || argv.contains("-h") { print(HELP); exit(0) }

let wantJSON = argv.contains("--json")
let assumeYes = argv.contains("--yes") || argv.contains("-y")
var limit = 20
var positional: [String] = []
var skipNext = false
for (i, a) in argv.enumerated() {
    if skipNext { skipNext = false; continue }
    if a == "-n" || a == "--limit" { if i + 1 < argv.count, let n = Int(argv[i + 1]) { limit = n }; skipNext = true; continue }
    if a.hasPrefix("-") { continue }
    positional.append(a)
}
let command = positional.first ?? "help"
let rest = Array(positional.dropFirst())

func output(_ obj: [String: Any], code: Int32 = 0, human: () -> Void) -> Never {
    if wantJSON { print(jsonText(obj, pretty: true)) } else { human() }
    exit(code)
}

/// Lowering protection needs a person: an interactive "y", or an explicit --yes.
func confirmWeakening(_ question: String) throws {
    if assumeYes { return }
    guard isatty(STDIN_FILENO) != 0 else {
        throw Failure("This lowers protection, so a person has to confirm it. Run it in a terminal, or add --yes.")
    }
    FileHandle.standardError.write(Data("\(question) [y/N] ".utf8))
    let answer = (readLine() ?? "").trimmed.lowercased()
    guard answer == "y" || answer == "yes" else { throw Failure("Cancelled — nothing changed.") }
}

do {
    switch command {
    case "mcp":
        serveMCP()

    case "version":
        output(["version": VERSION, "engine": ENGINE]) { print(VERSION) }

    case "help":
        print(HELP)

    case "status":
        try requireEngine()
        let s = statusReport(includeRepos: !argv.contains("--fast"))
        output(s, code: (s["posture"] as? String) == "protected" ? 0 : 2) { humanStatus(s) }

    case "check":
        let r = try checkPath(rest.first ?? ".")
        let safe = r["safe_to_run"] as? Bool ?? false
        output(r, code: safe ? 0 : 2) {
            let dir = r["path"] as? String ?? ""
            if safe { print(good("✓ safe to run") + faint("  — no injected configs, install hooks or auto-run tasks in \(shortPath(dir))")) }
            else { print(bad("✗ not safe to run install/dev/build in \(shortPath(dir))")); printFindings(r["findings"] as? [[String: Any]] ?? [], under: dir) }
            let machine = r["machine_threats"] as? [[String: Any]] ?? []
            if !machine.isEmpty { print("\n" + warn("! this Mac shows signs of infection:")); printFindings(machine) }
        }

    case "scan":
        if !wantJSON {
            let what = !rest.isEmpty ? "\(rest.count) folder\(rest.count == 1 ? "" : "s")" : argv.contains("--full") ? "your home folder" : "your git repos"
            FileHandle.standardError.write(Data(faint("scanning \(what) + temp folders, processes, network…\n").utf8))
        }
        let r = try scan(paths: rest, fullHome: argv.contains("--full"), readOnly: argv.contains("--read-only") || argv.contains("--dry-run"))
        let fs = r["findings"] as? [[String: Any]] ?? []
        output(r, code: fs.isEmpty ? 0 : 2) {
            if fs.isEmpty { print(good("✓ clean") + faint("  — nothing found (\(seconds(r))s)")) }
            else {
                print(bad("✗ \(fs.count) finding\(fs.count == 1 ? "" : "s")") + faint("  (\(seconds(r))s)")); printFindings(fs)
                let q = (r["quarantined"] as? [Any])?.count ?? 0
                if q > 0 { print("\n" + warn("quarantined \(q) known-malicious item\(q == 1 ? "" : "s")") + faint("  (bastion quarantine)")) }
            }
        }

    case "findings":
        let r = findingsReport()
        output(r) {
            guard r["ran"] as? Bool ?? false else { print(faint("No scan has run yet — run: bastion scan")); return }
            let fs = r["findings"] as? [[String: Any]] ?? []
            print(strong("last scan") + " \(friendly(r["time"])) · " + (fs.isEmpty ? good("clean") : bad("\(fs.count) finding\(fs.count == 1 ? "" : "s")")))
            printFindings(fs)
        }

    case "activity":
        let events = activity(limit: limit)
        output(["events": events]) {
            if events.isEmpty { print(faint("No activity yet — all quiet.")) }
            for e in events { print(faint(e["time"] as? String ?? "") + "  " + (e["message"] as? String ?? "")) }
        }

    case "quarantine":
        if rest.first == "restore" {
            guard rest.count > 1 else { throw Failure("Usage: bastion quarantine restore <id>   (ids: bastion quarantine)") }
            try confirmWeakening("Put the items from quarantine batch \(rest[1]) back where they were?")
            let r = try restore(rest[1])
            notify("Items were restored from quarantine.")
            output(r) { print("restored \((r["restored"] as? [Any])?.count ?? 0) item(s)" + faint("; skipped \((r["skipped"] as? [Any])?.count ?? 0)")) }
        }
        let items = quarantineItems()
        output(["items": items]) {
            if items.isEmpty { print(faint("Quarantine is empty.")) }
            for i in items {
                print(warn("■") + " \(i["original_path"] as? String ?? i["stored_at"] as? String ?? "")" + faint("  \(i["reason"] as? String ?? "") · \(friendly(i["time"])) · id \(i["id"] as? String ?? "")"))
            }
        }

    case "lists":
        let l = listsReport()
        output(l) {
            for (name, key) in [("allowlist", "allowlist"), ("blocklist", "blocklist"), ("ignore list", "ignore")] {
                let v = l[key] as? [String] ?? []
                print(strong(name) + faint("  \(engine(key == "ignore" ? "ignore.txt" : key + ".txt"))"))
                print(v.isEmpty ? faint("  (empty)") : v.map { "  " + $0 }.joined(separator: "\n"))
            }
        }

    case "allow", "block", "ignore":
        guard rest.count >= 2, ["add", "remove"].contains(rest[0]) else {
            throw Failure("Usage: bastion \(command) add|remove <value>")
        }
        let file = command == "allow" ? "allowlist.txt" : command == "block" ? "blocklist.txt" : "ignore.txt"
        let value = rest[1].trimmed
        let note = rest.count > 2 ? rest[2...].joined(separator: " ") : nil
        let adding = rest[0] == "add"
        if adding {
            switch command {
            case "allow":
                guard validHost(value) else { throw Failure("\(value) isn't a hostname or IP address.") }
                try confirmWeakening("Trust \(value)? Connections to it will never be treated as a threat.")
            case "block":
                guard ipFamily(value) != nil else { throw Failure("The blocklist takes IP addresses (e.g. 203.0.113.7), not \(value).") }
                guard !isLocalAddress(value) || argv.contains("--force") else {
                    throw Failure("\(value) is a local/private address — blocking it would kill your own dev servers. Add --force if you really mean it.")
                }
                guard !listEntries("allowlist.txt").contains(value) else { throw Failure("\(value) is on your allowlist. Remove it there first.") }
                try confirmWeakening("Block \(value)? The watcher will kill node processes that connect to it.")
            default:
                guard value.count >= 5, !value.has(#"^\.[A-Za-z]{1,5}$"#), !HOME.hasPrefix(value), !value.contains("\t") else {
                    throw Failure("That pattern is too broad — it would hide real findings. Use a specific path fragment, like /docs/security-notes/.")
                }
                try confirmWeakening("Ignore findings in any path containing \"\(value)\"?")
            }
        } else if command == "block" {
            try confirmWeakening("Remove \(value) from the blocklist? Connections to it will no longer be stopped.")
        }
        let changed = try (adding ? addEntry(file, value, note: note) : removeEntry(file, value))
        if changed {
            logEvent("CHANGED: \(command) list — \(adding ? "added" : "removed") \(command == "ignore" ? "a pattern" : value) (bastion CLI)")
            if (adding && command != "block") || (!adding && command == "block") { notify("Your \(command) list was changed.") }
        }
        output(["list": command, "action": rest[0], "value": value, "changed": changed]) {
            print(changed ? good("✓ \(adding ? "added to" : "removed from") \(command) list: \(value)") : faint("no change — \(value) was \(adding ? "already there" : "not on the list")"))
        }

    case "enable", "disable":
        guard let name = rest.first, let f = Feature(name) else { throw Failure("Usage: bastion \(command) watcher|schedule|exec-guard|git-guard") }
        if command == "disable" { try confirmWeakening("Turn off the \(f.title)?") }
        let r = try (command == "enable" ? enable(f) : disable(f))
        output(r) { print(((r["enabled"] as? Bool ?? false) == (command == "enable") ? good("✓ ") : warn("! ")) + (r["message"] as? String ?? "")) }

    case "connect":
        let c = connectInfo()
        output(c) { humanConnect(c) }

    case "bootstrap":
        let r = bootstrap()
        output(r, code: r["ok"] as? Bool ?? false ? 0 : 1) { print(jsonText(r, pretty: true)) }

    default:
        throw Failure("Unknown command: \(command). Run `bastion help`.")
    }
} catch let f as Failure {
    if wantJSON { print(jsonText(["error": f.message], pretty: true)) } else { FileHandle.standardError.write(Data((bad("error: ") + f.message + "\n").utf8)) }
    exit(1)
} catch {
    if wantJSON { print(jsonText(["error": "\(error)"], pretty: true)) } else { FileHandle.standardError.write(Data("error: \(error)\n".utf8)) }
    exit(1)
}
