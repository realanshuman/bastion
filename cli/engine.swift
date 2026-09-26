// engine.swift: shared core of the `bastion` CLI (the Bastion engine in ~/.security-guard).
// Agents can inspect and strengthen protection. Anything that lowers it needs a person at a terminal.
import Foundation

let VERSION = "5.0.0"
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

/// Runs a program with an argument vector: untrusted text never goes through a shell.
/// stdin is closed so children can't read MCP traffic, and the whole tree is killed on timeout.
func run(_ exe: String, _ args: [String], timeout: TimeInterval = 120, env extra: [String: String] = [:]) -> (out: String, code: Int32, timedOut: Bool) {
    let r = runData(exe, args, timeout: timeout, env: extra)
    return (String(decoding: r.data, as: UTF8.self), r.code, r.timedOut)
}

/// Same as run(), but returns stdout as raw bytes (file contents must round-trip exactly).
func runData(_ exe: String, _ args: [String], timeout: TimeInterval = 120, env extra: [String: String] = [:]) -> (data: Data, code: Int32, timedOut: Bool) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: exe)
    p.arguments = args
    var env = ProcessInfo.processInfo.environment
    env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin"
    env["HOME"] = HOME
    env.merge(extra) { $1 }
    p.environment = env
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = FileHandle.nullDevice
    p.standardInput = FileHandle.nullDevice
    do { try p.run() } catch { return (Data(), 127, false) }
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
    return (data, p.terminationStatus, expired.value)
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
    guard let s = iso as? String, let d = ISO8601DateFormatter().date(from: s) else { return "unknown" }
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
        why: ".vscode/tasks.json has a task that runs automatically when the folder is opened in VS Code or Cursor. It's a known way malicious repositories run code the moment they're opened.",
        fix: "Read the task's command before opening this folder in an editor. If nobody on the team added it, delete the task and check the commit that added it. Keep the editor's automatic-tasks setting off.",
        autoHandled: false),
    "STAGING": Kind(id: "staging_folder", title: "Malware staging folder", severity: "high", scope: "machine",
        why: "A temporary folder this stealer uses to collect data before uploading it. It means the payload has run on this Mac.",
        fix: "A normal scan (`bastion scan`) moves it to quarantine. Because the payload ran, change passwords, tokens and API keys that were on this Mac, from a different, clean device.",
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
    "DEPHOOK": Kind(id: "malicious_dependency", title: "Malicious install script in a dependency", severity: "critical", scope: "project",
        why: "A package in node_modules runs code during install that downloads or decodes code, contacts a raw IP, or carries a known npm-worm marker. Install scripts run automatically on npm install.",
        fix: "Assume it already ran: rotate the secrets that were on this Mac, from a clean device. Remove or pin the package to a safe version, delete node_modules and reinstall with --ignore-scripts.",
        autoHandled: false),
    "DEPMAL": Kind(id: "known_malicious_package", title: "Known malicious package version", severity: "critical", scope: "project",
        why: "osv.dev lists this exact package version as malicious (a published compromise).",
        fix: "Pin the package to a version osv.dev doesn't flag, delete node_modules and reinstall. If it was installed with scripts, rotate the secrets that were on this Mac.",
        autoHandled: false),
    "DEPURL": Kind(id: "untrusted_dependency_source", title: "Dependency downloaded from an untrusted address", severity: "high", scope: "project",
        why: "The lockfile downloads a package over plain http or from a raw IP address, so whoever controls that address can swap the code.",
        fix: "Remove that entry from the lockfile and reinstall from the registry, then check the commit that added it.",
        autoHandled: false),
    "WORKFLOW": Kind(id: "ci_secret_exfiltration", title: "CI workflow that ships secrets out", severity: "critical", scope: "project",
        why: "A GitHub Actions workflow dumps the repository's secrets or posts to a data-collection endpoint. That's how recent npm worms steal CI tokens and spread.",
        fix: "Delete the workflow, check who pushed it, and rotate every secret the repository has.",
        autoHandled: false),
    "BRANCH": Kind(id: "infected_branch", title: "Payload on a branch", severity: "high", scope: "project",
        why: "A branch carries an injected build config. Checking it out and running dev, build or test would run the malware.",
        fix: "Don't check out or merge <target> until it's cleaned. Delete it (and its copy on the remote) if you don't need it; otherwise restore the file from a clean commit on that branch.",
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
    case "BRANCH":   // target = repo, detail = "<ref> <file> <commit>"
        let parts = detail.split(separator: " ").map(String.init)
        f["path"] = target
        if parts.count >= 2 { f["ref"] = parts[0]; f["file"] = parts[1]; shown = parts[0] }
        if parts.count >= 3 { f["commit"] = parts[2] }
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
    guard path != "/" else { throw Failure("Refusing to scan the whole disk. Pass a project folder.") }
    return path
}

/// A value worth reusing for a few seconds (one command often needs it several times; the MCP server lives longer, so it expires).
final class Memo<T>: @unchecked Sendable {
    private var value: T?, made = Date.distantPast
    private let lock = NSLock(), ttl: TimeInterval
    init(ttl: TimeInterval) { self.ttl = ttl }
    func reset() { lock.lock(); value = nil; lock.unlock() }
    func get(_ make: () -> T) -> T {
        lock.lock(); defer { lock.unlock() }
        if let value, Date().timeIntervalSince(made) < ttl { return value }
        let v = make(); value = v; made = Date(); return v
    }
}

let REPO_ROOTS = Memo<[String]>(ttl: 5)
func repoRoots() -> [String] {
    REPO_ROOTS.get {
        run("/usr/bin/find", [HOME, "-maxdepth", "4", "-type", "d", "-name", ".git",
                              "-not", "-path", "*/node_modules/*", "-not", "-path", "*/Library/*"], timeout: 90).out
            .split(separator: "\n").map(String.init).filter { $0.hasSuffix("/.git") }.map { String($0.dropLast(5)) }.sorted()
    }
}

/// Every git repo with its branch, remote, push-guard state and open findings (cheap: no scanning, no git calls).
func reposReport() -> [String: Any] {
    let last = scanLogPaths().last.map(parseScanLog)
    let open = (last?["findings"] as? [[String: Any]] ?? []).filter { $0["path"] != nil && $0["kind"] as? String != "infected_branch" && stillPresent($0) }
    let liveBranches = liveBranchFindings()
    let repos = repoRoots().map { repo -> [String: Any] in
        let head = readText(repo + "/.git/HEAD").trimmed
        let branch = head.hasPrefix("ref: refs/heads/") ? String(head.dropFirst(16)) : String(head.prefix(8))
        var remote: Any = NSNull()
        if let line = readText(repo + "/.git/config").split(separator: "\n").first(where: { $0.trimmed.hasPrefix("url = ") }) {
            // never show credentials embedded in a remote URL
            remote = line.trimmed.dropFirst(6).replacingOccurrences(of: #"://[^/@\s]+@"#, with: "://", options: .regularExpression)
        }
        let mine = open.filter { ($0["path"] as? String ?? "").hasPrefix(repo + "/") }
        let branches = liveBranches.filter { $0["path"] as? String == repo }
        return ["path": repo, "name": (repo as NSString).lastPathComponent, "branch": branch, "remote": remote,
                "git_guard": gitGuardState(repo), "findings": mine.count, "infected_branches": Set(branches.compactMap { $0["ref"] as? String }).count,
                "infected_branch_files": branches.count, "pr_guard": prGuardInstalled(repo)]
    }
    return ["repos": repos, "last_scan": last?["time"] ?? NSNull()]
}

let globalHooksPath = (readText(HOME + "/.gitconfig") + readText(HOME + "/.config/git/config")).lowercased().contains("hookspath")

/// protected · unprotected · custom_hooks (the repo manages its own hooks; Bastion won't touch them)
func gitGuardState(_ repo: String) -> String {
    if globalHooksPath || readText(repo + "/.git/config").lowercased().contains("hookspath") {
        // husky keeps hooks in the repo (.husky/pre-push); Bastion can add its check there
        if huskyRepo(repo) { return huskyGuarded(repo) ? "protected" : "husky" }
        return "custom_hooks"
    }
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

/// Remote IP of an lsof line ("… 10.0.0.2:5123->23.27.20.187:443 (ESTABLISHED)" → 23.27.20.187), exact, no port or brackets.
func remoteAddress(_ line: String) -> String? {
    guard let arrow = line.range(of: "->") else { return nil }
    var r = String(line[arrow.upperBound...].split(separator: " ").first ?? "")
    if let colon = r.lastIndex(of: ":"), r[r.index(after: colon)...].allSatisfy(\.isNumber) { r = String(r[..<colon]) }
    return r.replacingOccurrences(of: "[", with: "").replacingOccurrences(of: "]", with: "")
}

/// pid → the rest of the line, for one `ps` column
func processColumn(_ field: String) -> [Int: String] {
    var table: [Int: String] = [:]
    for line in run("/bin/ps", ["-axo", "pid=,\(field)="], timeout: 15).out.split(separator: "\n") {
        let s = line.trimmed
        guard let sp = s.firstIndex(of: " "), let pid = Int(s[..<sp]) else { continue }
        table[pid] = s[sp...].trimmed
    }
    return table
}

/// node started with inline code (-e/-p/--eval/--print, separate or joined with =) carrying a loader marker.
/// Same rule as BASTION_LOADER_RE in lib.sh.
let LOADER_RE = #"(^|\s)(-e|-p|-pe|--eval|--print)(\s|=).*(global\.[a-z]{1,2}\s*=\s*['"]?[0-9]+-[0-9]+|_\$_[0-9a-f]{4}\s*=|global\.r\s*=\s*require)"#

func liveLoaders() -> [[String: Any]] {
    let names = processColumn("ucomm"), commands = processColumn("args")
    return names.keys.sorted().compactMap { pid -> [String: Any]? in
        guard let name = names[pid], name.has(#"^node[0-9.]*$"#), let cmd = commands[pid], cmd.has(LOADER_RE) else { return nil }
        return ["pid": pid, "command": String(cmd.prefix(160))]
    }
}

func liveC2() -> [[String: Any]] {
    let allow = Set(listEntries("allowlist.txt"))
    let block = listEntries("blocklist.txt").filter { !allow.contains($0) }
    guard !block.isEmpty else { return [] }
    var hits: [[String: Any]] = []
    let blocked = Set(block)
    for line in run("/usr/sbin/lsof", ["-nP", "-i"], timeout: 20).out.split(separator: "\n")
    where line.contains("ESTABLISHED") || line.contains("SYN_SENT") {
        let l = String(line)
        guard let ip = remoteAddress(l), blocked.contains(ip) else { continue }
        let cols = l.split(separator: " ")
        hits.append(["ip": ip, "process": cols.first.map(String.init) ?? "?", "pid": cols.count > 1 ? Int(cols[1]) ?? 0 : 0])
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
    if f["path"] != nil { return findingStillThere(f) }
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
        else if line.contains("FIXED:") { type = "fixed" }
        else if line.contains("ALERT") || line.contains("need your attention") { type = "alert" }
        else { type = "event" }
        let parts = line.components(separatedBy: "  ")
        let message = parts.dropFirst().joined(separator: "  ").trimmed
        var e: [String: Any] = ["time": parts.first?.trimmed ?? "", "type": type, "message": message.isEmpty ? line : message]
        // a scan's summary line: "N quarantined, M need your attention. See logs.  (/path/to/scan.log)"
        if let m = try? NSRegularExpression(pattern: #"^(\d+) quarantined, (\d+) need your attention\. See logs\.\s*\((.+)\)$"#)
            .firstMatch(in: message, range: NSRange(message.startIndex..., in: message)), m.numberOfRanges == 4,
           let q = Range(m.range(at: 1), in: message), let n = Range(m.range(at: 2), in: message), let l = Range(m.range(at: 3), in: message) {
            e["type"] = "scan"; e["quarantined"] = Int(message[q]) ?? 0; e["attention"] = Int(message[n]) ?? 0; e["log"] = String(message[l])
        }
        if let r = message.range(of: #"^INCIDENT INC-[0-9-]+"#, options: .regularExpression) { e["incident"] = String(message[r].dropFirst(9)) }
        e["said"] = sayEvent(e)
        return e
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
    // a payload on a branch that isn't checked out is latent: it's reported and becomes a to-do, not an active threat
    for f in (last?["findings"] as? [[String: Any]] ?? []) where f["path"] != nil && f["kind"] as? String != "infected_branch" && stillPresent(f) { threats.append(f) }
    if let i = currentIncident() { refreshIncident(i) }
    let attention = needsYou(threats: threats, detail: false)

    let protection: [String: Any] = ["watcher": agents.contains(WATCH_LABEL), "scheduled_scan": agents.contains(SCAN_LABEL),
                                     "exec_guard": execGuardOn()]
    let setup = nextSteps().filter { $0["optional"] as? Bool != true }
    var out: [String: Any] = ["version": VERSION, "engine": ENGINE, "posture": threats.isEmpty ? "protected" : "at_risk", "responding": responseRunning(),
                              "state": overallState(attention), "needs_you": attention.count,
                              "setup": ["done": setup.filter { $0["done"] as? Bool == true }.count, "total": setup.count],
                              "active_threats": threats, "protection": protection, "quarantine_count": quarantine.count]
    if let last {
        // infected branches are latent (reported as to-dos), so they don't make the last scan "not clean"
        let found = last["findings"] as? [[String: Any]] ?? []
        let branches = Set(attention.filter { $0["type"] as? String == "branch" }.compactMap { $0["id"] as? String }).count
        let clean = (last["clean"] as? Bool ?? false) || (!found.isEmpty && found.allSatisfy { $0["kind"] as? String == "infected_branch" })
        var ls: [String: Any] = ["result": clean && branches > 0 ? "CLEAN, \(branches) INFECTED BRANCH\(branches == 1 ? "" : "ES")" : last["result"] ?? "unknown",
                                 "clean": clean, "infected_branches": branches, "log": last["log"] ?? ""]
        if let t = last["time"] { ls["time"] = t }
        out["last_scan"] = ls
    } else { out["last_scan"] = NSNull() }
    if includeRepos {
        out["git_guard"] = ["repos": rs.repos.count,
                            "protected": rs.states.filter { $0 == "protected" }.count,
                            "unprotected": rs.states.filter { $0 == "unprotected" }.count,
                            "husky": rs.states.filter { $0 == "husky" }.count,
                            "custom_hooks": rs.states.filter { $0 == "custom_hooks" }.count]
    }
    var summary = threats.isEmpty ? "Protected." : "\(threats.count) active threat\(threats.count == 1 ? "" : "s"). See active_threats[].remediation."
    if threats.isEmpty && !(protection["watcher"] as? Bool ?? false) { summary += " The real-time watcher is off (bastion_enable watcher turns it on)." }
    if last == nil { summary += " No scan has run yet." }
    out["autonomy"] = autonomy()
    out["osv"] = osvEnabled()
    if let i = currentIncident() {
        let brief = incidentBrief(i)
        out["incident"] = brief
        summary += " Incident \(brief["id"] ?? "") is \(brief["status"] ?? "open") with \(brief["todos"] ?? 0) to-do(s). bastion_incident has the report."
    } else { out["incident"] = NSNull() }
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
    let project = all.filter { ($0["scope"] as? String) == "project" && $0["kind"] as? String != "infected_branch" }
    let branches = all.filter { $0["kind"] as? String == "infected_branch" }
    let machine = all.filter { ($0["scope"] as? String) == "machine" }
    var out: [String: Any] = [
        "path": dir, "safe_to_run": project.isEmpty, "findings": project, "machine_threats": machine, "infected_branches": branches,
        "checked": ["build configs", "source files", "npm install hooks", "editor auto-run tasks", "CI workflows", "other branches",
                    "dependencies (install scripts, lockfile sources" + (osvEnabled() ? ", osv.dev)" : ")")],
        "duration_ms": Int(Date().timeIntervalSince(started) * 1000),
    ]
    var refs: [String] = []
    for b in branches { if let r = b["ref"] as? String, !refs.contains(r) { refs.append(r) } }
    let current = git(dir, ["symbolic-ref", "-q", "--short", "HEAD"])?.trimmed ?? ""
    if !current.isEmpty { out["current_branch"] = current }
    let refList = refs.joined(separator: ", ")
    if !refs.isEmpty {
        out["infected_branch_refs"] = refs
        out["branch_details"] = branchContexts(branches)
        out["branch_advice"] = "Don't check out or merge \(refs.count == 1 ? "this branch" : "these branches") until \(refs.count == 1 ? "it's" : "they're") cleaned: \(refList)."
    }
    out["advice"] = !project.isEmpty
        ? "Do not run install, dev, build, test or codegen here until these findings are fixed. Show the user each finding's remediation."
        : refs.isEmpty ? "Nothing suspicious in this project. OK to run install, dev, build and test here."
        : "The checked-out code\(current.isEmpty ? "" : " (\(current))") is clean, so install, dev, build and test are OK here. But \(refList) \(refs.count == 1 ? "carries" : "carry") malware: don't check \(refs.count == 1 ? "it" : "them") out or merge \(refs.count == 1 ? "it" : "them"), and tell the user."
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
    // guard.sh leaves the response to us (BASTION_RESPOND=inline), so the incident is ready when the scan returns
    let r = run("/bin/bash", [engine(readOnly ? "scanner.sh" : "guard.sh")] + roots, timeout: 1800, env: readOnly ? [:] : ["BASTION_RESPOND": "inline"])
    if r.timedOut { throw Failure("The scan timed out after 30 minutes.") }
    if readOnly {
        let fs = parseFindings(r.out)
        out["clean"] = fs.isEmpty; out["findings"] = fs; out["quarantined"] = [[String: Any]]()
    } else {
        let logPath = r.out.split(separator: "\n").last(where: { $0.hasPrefix("LOG: ") }).map { String($0.dropFirst(5)) }
            ?? scanLogPaths().last ?? ""
        let parsed = parseScanLog(logPath)
        out["clean"] = parsed["clean"]; out["findings"] = parsed["findings"]; out["quarantined"] = parsed["quarantined"]; out["log"] = logPath
        if !(parsed["findings"] as? [Any] ?? []).isEmpty, let resp = try? respond(paths: [], planOnly: false, trigger: "scan", wait: true, fromLog: logPath),
           resp["status"] as? String != "skipped" {
            out["response"] = ["status": resp["status"] ?? "", "id": resp["id"] ?? resp["incident"] ?? NSNull(), "summary": resp["summary"] ?? ""]
        }
    }
    out["duration_ms"] = Int(Date().timeIntervalSince(started) * 1000)
    let n = (out["findings"] as? [Any])?.count ?? 0
    out["summary"] = n == 0 ? "Clean. Nothing found." : "\(n) finding\(n == 1 ? "" : "s"). Each has an explanation and remediation; known-malicious leftovers were quarantined unless read_only."
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
    case watcher, schedule = "scheduled_scan", execGuard = "exec_guard", gitGuard = "git_guard", autoRespond = "auto_respond"
    var title: String {
        switch self {
        case .watcher: return "real-time watcher"
        case .schedule: return "scheduled scan"
        case .execGuard: return "execution guard"
        case .gitGuard: return "git push guard"
        case .autoRespond: return "auto-respond"
        }
    }
    init?(_ s: String) {
        switch s.lowercased().replacingOccurrences(of: "-", with: "_") {
        case "watcher", "real_time_watcher", "realtime", "live": self = .watcher
        case "schedule", "scheduled_scan", "scheduled", "scan_schedule": self = .schedule
        case "exec_guard", "execution_guard", "exec": self = .execGuard
        case "git_guard", "git", "pre_push", "git_hook": self = .gitGuard
        case "auto_respond", "respond", "autonomy", "responder": self = .autoRespond
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
                "message": on ? "The \(f.title) is on." : "Couldn't start the \(f.title). Try its switch in the Bastion menu-bar app."]
    case .execGuard:
        if execGuardOn() { return ["feature": f.rawValue, "enabled": true, "changed": false, "message": "The execution guard is already on."] }
        _ = run("/bin/bash", [engine("harden.sh"), "install"], timeout: 20)
        let on = execGuardOn()
        if on { logEvent("CHANGED: execution guard turned ON") }
        return ["feature": f.rawValue, "enabled": on, "changed": on,
                "message": on ? "Execution guard is on for new terminal windows: node/npm/npx/pnpm/yarn/bun refuse to run in infected projects." : "Couldn't update ~/.zshrc."]
    case .autoRespond:
        if autonomy() == "contain" { return ["feature": f.rawValue, "enabled": true, "changed": false, "message": "Auto-respond is already on."] }
        updateSettings { $0["autonomy"] = "contain" }
        logEvent("CHANGED: auto-respond turned ON (contain)")
        return ["feature": f.rawValue, "enabled": true, "changed": true,
                "message": "Auto-respond is on: Bastion investigates what it finds, takes the proven and reversible steps, and writes an incident report."]
    case .gitGuard:
        var installed: [String] = [], updated: [String] = [], skipped: [String] = [], already = 0
        let current = readText(engine("git-guard"))
        for repo in repoRoots() {
            switch gitGuardState(repo) {
            case "protected":
                let hook = repo + "/.git/hooks/pre-push"
                if !current.isEmpty && readText(hook) != current, (try? current.write(toFile: hook, atomically: true, encoding: .utf8)) != nil {
                    chmod(hook, 0o755); updated.append(repo)
                } else { already += 1 }
            case "unprotected":
                let hooks = repo + "/.git/hooks", dst = hooks + "/pre-push"
                try? fm.createDirectory(atPath: hooks, withIntermediateDirectories: true)
                if (try? fm.copyItem(atPath: engine("git-guard"), toPath: dst)) != nil { chmod(dst, 0o755); installed.append(repo) }
            default: skipped.append(repo)
            }
        }
        if !installed.isEmpty || !updated.isEmpty {
            logEvent("CHANGED: " + [installed.isEmpty ? nil : "push guard added to \(installed.count) repo\(installed.count == 1 ? "" : "s")",
                                    updated.isEmpty ? nil : "push guard updated in \(updated.count) repo\(updated.count == 1 ? "" : "s")"].compactMap { $0 }.joined(separator: ", "))
        }
        return ["feature": f.rawValue, "enabled": true, "changed": !installed.isEmpty || !updated.isEmpty, "installed": installed,
                "updated": updated, "already_protected": already, "skipped_custom_hooks": skipped,
                "message": "Push guard added to \(installed.count) repo(s) and updated in \(updated.count); \(already) were already current. Repos with their own hook setup were left alone."]
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
    case .autoRespond:
        updateSettings { $0["autonomy"] = "observe" }
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

let ENGINE_FILES = ["lib.sh", "scanner.sh", "guard.sh", "watcher.sh", "git-guard", "harden.sh", "install.sh", "uninstall.sh", "README.md", "LICENSE", "VERSION"]

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

// MARK: - Self-test of the CLI's own detection rules (mirrors the lib.sh cases)

func selfTest() -> [String: Any] {
    var failures: [String] = []
    func expect(_ ok: Bool, _ name: String) { if !ok { failures.append(name) } }
    for l in ["node -e global.i='1-183';global.r=require;", "/usr/local/bin/node --eval=global.i = '1-183';x()",
              "node -p global.r=require;require('x')", "node --print global.o='1-71'", "node -pe _$_2b1f=(function(i,p){})"] {
        expect(l.has(LOADER_RE), "should catch loader: \(l)")
    }
    for l in ["node -e console.log(process.version)", "node server.js --eval-mode global.i='1-2'", "node dist/index.js"] {
        expect(!l.has(LOADER_RE), "should ignore: \(l)")
    }
    expect(remoteAddress("node 42 me 23u IPv4 0x1 0t0 TCP 10.0.0.5:50123->23.27.20.187:443 (ESTABLISHED)") == "23.27.20.187", "remote IPv4")
    expect(remoteAddress("curl 43 me 5u IPv4 0x2 0t0 TCP 10.0.0.5:50124->123.27.20.187:443 (ESTABLISHED)") != "23.27.20.187", "no substring IP match")
    expect(remoteAddress("node 44 me 7u IPv6 0x3 0t0 TCP [2001:db8::5]:50125->[2001:db8::1]:8080 (SYN_SENT)") == "2001:db8::1", "remote IPv6")
    expect(remoteAddress("node 45 me 8u IPv4 0x4 0t0 TCP *:3000 (LISTEN)") == nil, "listening socket has no remote")
    expect(isLocalAddress("192.168.1.10") && isLocalAddress("127.0.0.1") && isLocalAddress("::1") && isLocalAddress("169.254.1.1"), "local ranges refused")
    expect(!isLocalAddress("23.27.20.187"), "public address allowed")
    return ["ok": failures.isEmpty, "failures": failures]
}

/// A response is running right now (its lock is held and fresh).
func responseRunning() -> Bool {
    guard let m = (try? fm.attributesOfItem(atPath: engine("respond.lock")))?[.modificationDate] as? Date else { return false }
    return Date().timeIntervalSince(m) < 900
}
