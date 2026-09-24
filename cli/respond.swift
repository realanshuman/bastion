// respond.swift — Bastion's autonomous responder: investigate → decide → act → verify → report.
// It only changes what it can prove: attacker code is removed from a file only when the result is
// byte-identical to that file's last clean commit, and every change keeps an undo copy. Anything that
// reaches beyond this Mac (commits, pushes, access, credential rotation) becomes a to-do for the developer.
import Foundation

let POSIX = Locale(identifier: "en_US_POSIX")

// MARK: - Autonomy

/// off: never acts on its own · observe: investigates and reports · contain: also takes the proven, reversible steps
let AUTONOMY_LEVELS = ["off", "observe", "contain"]

func settings() -> [String: Any] {
    guard let d = fm.contents(atPath: engine("settings.json")),
          let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { return [:] }
    return o
}

func updateSettings(_ change: (inout [String: Any]) -> Void) {
    var s = settings()
    change(&s)
    try? jsonText(s, pretty: true).write(toFile: engine("settings.json"), atomically: true, encoding: .utf8)
}

func autonomy() -> String {
    let level = settings()["autonomy"] as? String ?? "contain"
    return AUTONOMY_LEVELS.contains(level) ? level : "contain"
}

// MARK: - Git, hardened: nothing in a (possibly hostile) repo's config may run code through these calls

let GIT_BIN: String? = ["/opt/homebrew/bin/git", "/usr/local/bin/git", "/Library/Developer/CommandLineTools/usr/bin/git",
                        "/Applications/Xcode.app/Contents/Developer/usr/bin/git"].first { fm.isExecutableFile(atPath: $0) }
let GIT_ENV = ["GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"]

func gitData(_ repo: String, _ args: [String]) -> Data? {
    guard let bin = GIT_BIN else { return nil }
    let r = runData(bin, ["--no-pager", "-C", repo, "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                          "-c", "log.showSignature=false"] + args, timeout: 30, env: GIT_ENV)
    return r.code == 0 && !r.timedOut ? r.data : nil
}

func git(_ repo: String, _ args: [String]) -> String? { gitData(repo, args).map { String(decoding: $0, as: UTF8.self) } }

struct Commit {
    let sha, author, authorEmail, committer, committerEmail, date, subject: String
    var short: String { String(sha.prefix(8)) }
    var json: [String: Any] {
        ["sha": sha, "short": short, "author": author, "author_email": authorEmail,
         "committer": committer, "committer_email": committerEmail, "date": date, "subject": subject]
    }
}

func commits(_ repo: String, _ args: [String]) -> [Commit] {
    (git(repo, ["log", "--no-show-signature", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%cI%x1f%s"] + args) ?? "")
        .split(separator: "\n").compactMap { line in
            let f = line.split(separator: "\u{1f}", omittingEmptySubsequences: false).map(String.init)
            guard f.count >= 7 else { return nil }
            return Commit(sha: f[0], author: f[1], authorEmail: f[2], committer: f[3], committerEmail: f[4], date: f[5], subject: f[6])
        }
}

func ownGitEmail() -> String {
    for line in (readText(HOME + "/.gitconfig") + "\n" + readText(HOME + "/.config/git/config")).split(separator: "\n") {
        let t = line.trimmed
        if t.lowercased().hasPrefix("email"), let eq = t.firstIndex(of: "=") { return t[t.index(after: eq)...].trimmed.lowercased() }
    }
    return ""
}

// MARK: - The rule, and removing exactly what the attacker added

/// lib.sh's rule (shared with the scanner, watcher and shim). "" only when the rule ran and found nothing.
func payloadReasons(_ content: Data, config: Bool) -> String {
    let tmp = NSTemporaryDirectory() + "bastion-check-" + UUID().uuidString
    guard fm.createFile(atPath: tmp, contents: content) else { return "unreadable" }
    defer { try? fm.removeItem(atPath: tmp) }
    let rule = config ? #"config_reasons "$1""#
                      : #"grep -qE "$BASTION_SCRAMBLER_RE|$BASTION_MARKER_RE" "$1" && printf payload-body; exit 0"#
    let r = run("/bin/bash", ["-c", #". "$HOME/.security-guard/lib.sh" || exit 3; "# + rule, "bastion", tmp], timeout: 20)
    return r.code == 3 || r.timedOut ? "rule-unavailable" : r.out.trimmed
}

/// Is a finding still there right now? Files are re-checked against the rule, so a fixed file stops counting.
func findingStillThere(_ f: [String: Any]) -> Bool {
    guard let path = f["path"] as? String, fm.fileExists(atPath: path) else { return false }
    let check: String
    switch f["kind"] as? String ?? "" {
    case "injected_config": return !payloadReasons(fm.contents(atPath: path) ?? Data(), config: true).isEmpty
    case "source_payload": return !payloadReasons(fm.contents(atPath: path) ?? Data(), config: false).isEmpty
    case "install_hook": check = "install_hook_suspicious"
    case "editor_autorun": check = "autorun_task"
    default: return true
    }
    return run("/bin/bash", ["-c", #". "$HOME/.security-guard/lib.sh" && "$0" "$1""#, check, path], timeout: 20).code == 0
}

// Swift copies of lib.sh's line rules. They only choose lines to drop: the result is re-checked with lib.sh
// and must equal the last clean commit before anything is written, so a mismatch can never cause damage.
let PAYLOAD_LINE_PATTERNS = [#"global\.[a-z]{1,2}\s*=\s*['"][0-9]+-[0-9]+['"]"#, #"_\$_[0-9a-f]{4}\s*=\s*\(function\s*\("#]
let OBFUSCATED_PATTERN = #"_0x[0-9a-f]{4,}|(\\x[0-9a-f]{2}){8,}|String\.fromCharCode|(^|[^A-Za-z0-9_$.])(eval|atob)\(|new Function\(|global\[['"]"#
let PADDING_PATTERN = #"\s{100,}\S"#

func isPayloadLine(_ line: String) -> Bool {
    PAYLOAD_LINE_PATTERNS.contains { line.has($0) } || (line.utf8.count > 500 && line.has(OBFUSCATED_PATTERN))
}

/// A line pushed far right behind padding keeps only its legitimate start; payload lines are dropped.
func stripPayload(_ text: String) -> (text: String, removed: [String]) {
    var kept: [String] = [], removed: [String] = []
    for line in text.components(separatedBy: "\n") {
        if let pad = line.range(of: PADDING_PATTERN, options: .regularExpression) {
            let head = String(line[..<pad.lowerBound])
            removed.append(String(line[pad.lowerBound...]).trimmed)
            if head.trimmed.isEmpty { continue }
            if isPayloadLine(head) { removed.append(head) } else { kept.append(head) }
            continue
        }
        if isPayloadLine(line) { removed.append(line) } else { kept.append(line) }
    }
    return (kept.joined(separator: "\n"), removed)
}

func trailingTrimmed(_ s: String) -> Substring {
    var end = s.endIndex
    while end > s.startIndex, s[s.index(before: end)].isWhitespace { end = s.index(before: end) }
    return s[..<end]
}

/// IPv4 addresses and URL hosts written in plain text (version strings like Chrome/120.0.0.0 are skipped).
func indicatorsIn(_ text: String) -> (ips: [String], domains: [String]) {
    var ips: [String] = [], domains: [String] = []
    let ns = text as NSString, all = NSRange(location: 0, length: ns.length)
    if let re = try? NSRegularExpression(pattern: #"(?<![0-9A-Za-z./])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9A-Za-z.])"#) {
        for m in re.matches(in: text, range: all) {
            let ip = ns.substring(with: m.range)
            let octets = ip.split(separator: ".")
            guard ipFamily(ip) == AF_INET, !ip.hasSuffix(".0"), !octets.contains(where: { $0.count > 1 && $0.hasPrefix("0") }),
                  !ips.contains(ip) else { continue }
            ips.append(ip)
        }
    }
    // URL hosts: an IP host is an address to block, a name is a domain to report
    if let re = try? NSRegularExpression(pattern: #"(?:https?|wss?)://([A-Za-z0-9.-]+)"#) {
        for m in re.matches(in: text, range: all) {
            let host = ns.substring(with: m.range(at: 1)).lowercased()
            if ipFamily(host) == AF_INET { if !ips.contains(host) { ips.append(host) } }
            else if host.has(#"\.[a-z]{2,}$"#), !domains.contains(host) { domains.append(host) }
        }
    }
    return (ips, domains)
}

// MARK: - Small helpers

func tilde(_ p: String) -> String { p.hasPrefix(HOME + "/") ? "~/" + p.dropFirst(HOME.count + 1) : p }

/// A path for commands the developer will paste: "$HOME/…" stays short and still survives spaces.
func shellPath(_ p: String) -> String { p.hasPrefix(HOME + "/") ? "\"$HOME/\(p.dropFirst(HOME.count + 1))\"" : "\"\(p)\"" }

func stamp(_ d: Date) -> String {
    let f = DateFormatter(); f.locale = POSIX; f.dateFormat = "yyyyMMdd-HHmmss"
    return f.string(from: d)
}

func parseISO(_ s: Any?) -> Date? {
    guard let s = s as? String else { return nil }
    let f = ISO8601DateFormatter()
    if let d = f.date(from: s) { return d }
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f.date(from: s)
}

func humanTime(_ s: Any?) -> String {
    guard let d = parseISO(s) else { return (s as? String) ?? "—" }
    let f = DateFormatter(); f.dateFormat = "MMM d, HH:mm"
    return f.string(from: d)
}

func appendLine(_ file: String, _ line: String) {
    let data = Data((line + "\n").utf8)
    if let h = FileHandle(forWritingAtPath: file) { h.seekToEndOfFile(); h.write(data); h.closeFile() }
    else { fm.createFile(atPath: file, contents: data) }
}

func repoRoot(of path: String) -> String {
    var dir = (path as NSString).deletingLastPathComponent
    while dir.count > 1 {
        if fm.fileExists(atPath: dir + "/.git") { return dir }
        dir = (dir as NSString).deletingLastPathComponent
    }
    return (path as NSString).deletingLastPathComponent
}

func isProtectedPath(_ p: String) -> Bool {
    func clean(_ s: String) -> String { s.count > 1 && s.hasSuffix("/") ? String(s.dropLast()) : s }
    let tmp = clean(ProcessInfo.processInfo.environment["TMPDIR"] ?? "/nonexistent")
    return ["", "/", "/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", HOME, tmp].contains(clean(p))
}

/// Copies (or moves) an item into quarantine/<batch>/<original path>, with a manifest line for restore.
func quarantine(_ path: String, reason: String, batch: String, keepOriginal: Bool) -> String? {
    guard !isProtectedPath(path), fm.fileExists(atPath: path) else { return nil }
    let base = engine("quarantine/" + batch), dest = base + path
    try? fm.createDirectory(atPath: (dest as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
    try? fm.removeItem(atPath: dest)
    let ok = keepOriginal ? (try? fm.copyItem(atPath: path, toPath: dest)) != nil : (try? fm.moveItem(atPath: path, toPath: dest)) != nil
    guard ok else { return nil }
    appendLine(base + "/.manifest", "\(path)\t\(reason)")
    return dest
}

/// node/next processes whose working folder is inside `repo`, with their start time
func processesIn(_ repo: String) -> [(pid: Int, name: String, started: Date?)] {
    var out: [(Int, String, Date?)] = []
    var pid = 0, name = ""
    for line in run("/usr/sbin/lsof", ["-a", "-d", "cwd", "-c", "node", "-c", "next", "-Fpcn"], timeout: 15).out.split(separator: "\n") {
        guard let tag = line.first else { continue }
        let value = String(line.dropFirst())
        switch tag {
        case "p": pid = Int(value) ?? 0
        case "c": name = value
        case "n": if pid > 0, value == repo || value.hasPrefix(repo + "/") { out.append((pid, name, processStart(pid))) }
        default: break
        }
    }
    return out
}

func processStart(_ pid: Int) -> Date? {
    let s = run("/bin/ps", ["-o", "lstart=", "-p", "\(pid)"], timeout: 5).out.trimmed
    let f = DateFormatter(); f.locale = POSIX; f.dateFormat = "EEE MMM d HH:mm:ss yyyy"
    return f.date(from: s.split(separator: " ").joined(separator: " "))
}

/// Remote addresses that something other than node/package-manager processes is talking to right now
func ipsInUseByOthers() -> Set<String> {
    var s = Set<String>()
    for line in run("/usr/sbin/lsof", ["-nP", "-i"], timeout: 20).out.split(separator: "\n") where line.contains("ESTABLISHED") {
        let l = String(line), name = l.split(separator: " ").first.map(String.init) ?? ""
        if name.has(#"^(node|next|npm|npx|pnpm|yarn|bun|deno)"#) { continue }
        if let ip = remoteAddress(l) { s.insert(ip) }
    }
    return s
}

/// The payload inside a repo's build cache means a dev server compiled it (docs quoting it can too, hence "possibly").
func buildCacheHit(_ repo: String) -> String? {
    let script = #". "$HOME/.security-guard/lib.sh" || exit 3; for d in "$1/.next" "$1/node_modules/.vite" "$1/.turbo"; do [ -d "$d" ] || continue; find "$d" -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' \) -size -8M 2>/dev/null | head -3000 | tr '\n' '\0' | xargs -0 grep -lE "$BASTION_SCRAMBLER_RE|$BASTION_MARKER_RE" 2>/dev/null | head -1; done | head -1"#
    let hit = run("/bin/bash", ["-c", script, "bastion", repo], timeout: 60).out.trimmed
    return hit.isEmpty ? nil : hit
}

/// What the stealer goes after, as names only — Bastion never reads secret values.
func secretsAtRisk(_ repos: [String]) -> [[String: String]] {
    var out: [[String: String]] = []
    for repo in repos {
        let envs = run("/usr/bin/find", [repo, "-maxdepth", "3", "-type", "f", "-name", ".env*", "-not", "-name", "*.example",
                                         "-not", "-name", "*.sample", "-not", "-name", "*.template", "-not", "-path", "*/node_modules/*"], timeout: 20).out
            .split(separator: "\n").map { String($0.dropFirst(repo.count + 1)) }.sorted()
        if !envs.isEmpty {
            out.append(["what": "Secrets in \(envs.prefix(6).joined(separator: ", "))\(envs.count > 6 ? " …" : "") (\(tilde(repo)))",
                        "how": "Rotate each key at its provider (cloud, database, payments, email…) and update the file."])
        }
    }
    let homeFiles: [(String, String, String)] = [
        (".npmrc", "npm token (~/.npmrc)", "Revoke it on npmjs.com → Access Tokens, then create a new one."),
        (".config/gh/hosts.yml", "GitHub CLI login (~/.config/gh)", "Revoke it on GitHub → Settings → Applications, then gh auth login again."),
        (".git-credentials", "Saved git tokens (~/.git-credentials)", "Revoke those tokens on your git host and delete the file."),
        (".aws/credentials", "AWS access keys (~/.aws/credentials)", "Deactivate and replace them in AWS IAM."),
        (".docker/config.json", "Docker registry logins (~/.docker/config.json)", "docker logout, then change the registry password or token."),
        (".kube/config", "Kubernetes credentials (~/.kube/config)", "Rotate the cluster credentials."),
        (".netrc", "Saved logins (~/.netrc)", "Change those passwords."),
    ]
    for (rel, what, how) in homeFiles where fm.fileExists(atPath: HOME + "/" + rel) {
        if rel == ".npmrc" && !readText(HOME + "/.npmrc").contains("_authToken") { continue }
        out.append(["what": what, "how": how])
    }
    let ssh = ((try? fm.contentsOfDirectory(atPath: HOME + "/.ssh")) ?? []).filter { $0.hasPrefix("id_") && !$0.hasSuffix(".pub") }
    if !ssh.isEmpty {
        out.append(["what": "SSH keys (\(ssh.sorted().joined(separator: ", ")))", "how": "Create new keys, add them to GitHub and your servers, then remove the old ones there."])
    }
    let browsers = [("Google/Chrome", "Chrome"), ("Arc", "Arc"), ("BraveSoftware/Brave-Browser", "Brave"), ("Microsoft Edge", "Edge"),
                    ("Firefox", "Firefox"), ("com.operasoftware.Opera", "Opera"), ("Vivaldi", "Vivaldi")]
        .filter { fm.fileExists(atPath: HOME + "/Library/Application Support/" + $0.0) }.map { $0.1 }
    if !browsers.isEmpty {
        out.append(["what": "Saved passwords, sign-in cookies and wallet extensions in \(browsers.joined(separator: ", "))",
                    "how": "From a clean device: change important passwords, sign out of all sessions (Google, GitHub, email, cloud), and move any crypto from browser wallets to a new wallet."])
    }
    return out
}

/// Other commits by the identity that planted the payload, across every local repo
func huntIdentity(_ email: String) -> [[String: Any]] {
    guard !email.isEmpty, GIT_BIN != nil else { return [] }
    var found: [[String: Any]] = []
    for repo in repoRoots() {
        var seen = Set<String>(), list: [Commit] = []
        for field in ["--committer=\(email)", "--author=\(email)"] {
            for c in commits(repo, ["--all", "-F", field, "-n", "40"]) where seen.insert(c.sha).inserted { list.append(c) }
        }
        if !list.isEmpty {
            found.append(["repo": repo, "count": list.count,
                          "commits": list.prefix(8).map { ["short": $0.short, "date": $0.date, "subject": $0.subject] as [String: Any] }])
        }
    }
    return found
}

/// Watcher and guard actions since the last response (they are evidence the payload ran)
func reflexEvents(since: Date?) -> [[String: String]] {
    let f = DateFormatter(); f.locale = POSIX; f.dateFormat = "yyyy-MM-dd HH:mm:ss"
    var out: [[String: String]] = []
    for line in readText(engine("ALERTS.txt")).split(separator: "\n").map(String.init) {
        guard line.contains("KILLED") || line.contains("QUARANTINED") || line.contains("BLOCKED [") else { continue }
        guard let d = f.date(from: String(line.prefix(19))) else { continue }
        if let since, d <= since { continue }
        out.append(["time": isoTime(d), "event": line.dropFirst(19).trimmed])
    }
    return out
}

// MARK: - Incidents on disk

func incidentDirs() -> [String] {
    ((try? fm.contentsOfDirectory(atPath: engine("incidents"))) ?? []).filter { $0.hasPrefix("INC-") }.sorted(by: >).map { engine("incidents/" + $0) }
}

func allIncidents() -> [[String: Any]] {
    incidentDirs().compactMap { dir in
        fm.contents(atPath: dir + "/incident.json").flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    }
}

func findIncident(_ id: String) -> [String: Any]? {
    id == "latest" ? allIncidents().first : allIncidents().first { ($0["id"] as? String) == id }
}

func currentIncident() -> [String: Any]? { allIncidents().first { ($0["status"] as? String) != "resolved" } }

func newIncident(_ now: Date) -> [String: Any] {
    var id = "INC-" + stamp(now), n = 2
    while fm.fileExists(atPath: engine("incidents/" + id)) { id = "INC-\(stamp(now))-\(n)"; n += 1 }
    return ["id": id, "status": "open", "opened": isoTime(now)]
}

@discardableResult
func saveIncident(_ inc: [String: Any]) -> String {
    let dir = engine("incidents/" + (inc["id"] as? String ?? "INC-unknown"))
    try? fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
    try? jsonText(inc, pretty: true).write(toFile: dir + "/incident.json", atomically: true, encoding: .utf8)
    try? reportMarkdown(inc).write(toFile: dir + "/report.md", atomically: true, encoding: .utf8)
    return dir + "/report.md"
}

func incidentBrief(_ i: [String: Any]) -> [String: Any] {
    let id = i["id"] as? String ?? ""
    let repos = (i["repos"] as? [[String: Any]] ?? []).compactMap { ($0["path"] as? String).map { ($0 as NSString).lastPathComponent } }
    return ["id": id, "status": i["status"] ?? "open", "summary": i["summary"] ?? "", "opened": i["opened"] ?? "", "repos": repos,
            "updated": i["updated"] ?? "", "todos": max(((i["todos"] as? [Any])?.count ?? 1) - 1, 0),
            "report": engine("incidents/\(id)/report.md")]
}

// MARK: - The response loop

func respond(paths: [String], planOnly: Bool, trigger: String, wait: Bool) throws -> [String: Any] {
    try requireEngine()
    let level = autonomy()
    if (trigger == "watcher" || trigger == "scan") && level == "off" {
        return ["status": "skipped", "reason": "Auto-respond is off (bastion autonomy contain turns it on)."]
    }
    let mode = planOnly || level != "contain" ? "observe" : "contain"
    let lock = engine("respond.lock")
    guard acquireLock(lock, wait: wait) else { return ["status": "skipped", "reason": "Another response is already running."] }
    defer { try? fm.removeItem(atPath: lock) }

    let now = Date()
    let lastRun = parseISO(settings()["last_respond"])
    let roots = paths.isEmpty ? repoRoots() : try paths.map(resolveDir)

    // 1. OBSERVE — fresh read-only scan, plus what the watcher did since the last response
    let found = parseFindings(run("/bin/bash", [engine("scanner.sh")] + (roots.isEmpty ? [HOME] : roots), timeout: 1800).out)
    let reflexes = reflexEvents(since: lastRun)
    updateSettings { $0["last_respond"] = isoTime(now) }
    if found.isEmpty && reflexes.isEmpty {
        return ["status": "clear", "mode": mode, "summary": "Nothing to respond to: no findings and no new automatic actions."]
    }

    var inc = currentIncident() ?? newIncident(now)
    let id = inc["id"] as? String ?? ""
    let batch = "respond-" + stamp(now)
    var actions = inc["actions"] as? [[String: Any]] ?? []
    var timeline = inc["timeline"] as? [[String: Any]] ?? []
    var indicators = inc["indicators"] as? [[String: Any]] ?? []
    var repoCases = inc["repos"] as? [[String: Any]] ?? []
    var machine = inc["machine"] as? [[String: Any]] ?? []
    var signs = inc["ran_signs"] as? [String] ?? []

    func act(_ type: String, _ target: String, _ status: String, _ detail: String, _ extra: [String: Any] = [:]) {
        var a: [String: Any] = ["n": actions.count + 1, "type": type, "target": target, "status": status, "detail": detail, "time": isoTime(Date())]
        a.merge(extra) { $1 }
        actions.append(a)
        if status == "done" { timeline.append(["time": isoTime(Date()), "event": detail]) }
    }
    func addIndicator(_ value: String, _ type: String, _ source: String) {
        guard !indicators.contains(where: { $0["value"] as? String == value }) else { return }
        indicators.append(["value": value, "type": type, "source": source])
    }
    let who = ["watcher": "the real-time watcher", "scan": "a scan", "agent": "an AI agent", "manual": "you"][trigger] ?? trigger
    timeline.append(["time": isoTime(now), "event": "Response started by \(who) (mode: \(mode))."])
    for r in reflexes { timeline.append(["time": r["time"] ?? "", "event": "Watcher: " + (r["event"] ?? "")]) }

    // 2. INVESTIGATE + CONTAIN — repo by repo
    var grouped: [String: [[String: Any]]] = [:]
    for f in found where f["scope"] as? String == "project" {
        if let p = f["path"] as? String { grouped[repoRoot(of: p), default: []].append(f) }
    }
    for (repo, fs) in grouped.sorted(by: { $0.key < $1.key }) {
        var files: [[String: Any]] = [], hooks: [[String: Any]] = []
        var infectedSince: Double? = nil
        for f in fs {
            let kind = f["kind"] as? String ?? ""
            guard kind == "injected_config" || kind == "source_payload", let path = f["path"] as? String else { hooks.append(f); continue }
            let rel = path.hasPrefix(repo + "/") ? String(path.dropFirst(repo.count + 1)) : path
            let isConfig = kind == "injected_config"
            var info: [String: Any] = ["path": path, "rel": rel, "kind": kind, "title": f["title"] ?? "", "detail": f["detail"] ?? ""]
            let worktree = fm.contents(atPath: path) ?? Data()
            if let m = (try? fm.attributesOfItem(atPath: path))?[.modificationDate] as? Date {
                infectedSince = min(infectedSince ?? m.timeIntervalSince1970, m.timeIntervalSince1970)
            }
            let stripped = stripPayload(String(decoding: worktree, as: UTF8.self))
            for line in stripped.removed {
                let found = indicatorsIn(line)
                found.ips.forEach { addIndicator($0, "ip", "payload in \(rel)") }
                found.domains.forEach { addIndicator($0, "domain", "payload in \(rel)") }
            }

            // history: the last clean version, and the commit that brought the payload in
            var lastClean: (commit: Commit, blob: Data)? = nil, introduced: Commit? = nil
            let tracked = gitData(repo, ["ls-files", "--error-unmatch", "--", rel]) != nil
            info["tracked"] = tracked
            if tracked {
                for c in commits(repo, ["-n", "200", "--", rel]) {
                    guard let blob = gitData(repo, ["cat-file", "-p", "\(c.sha):\(rel)"]) else { break }
                    if payloadReasons(blob, config: isConfig).isEmpty { lastClean = (c, blob); break }
                    introduced = c
                }
                let head = git(repo, ["rev-parse", "--verify", "-q", "HEAD:\(rel)"])?.trimmed
                let onDisk = git(repo, ["hash-object", "--no-filters", "--", rel])?.trimmed
                info["worktree"] = head != nil && head == onDisk ? "committed" : "uncommitted"
            }
            if let lc = lastClean { info["last_clean"] = lc.commit.json }
            if let c = introduced {
                info["introduced_by"] = c.json
                let refs = (git(repo, ["branch", "-a", "--contains", c.sha, "--format=%(refname:short)"]) ?? "")
                    .split(separator: "\n").map(String.init).filter { !$0.isEmpty && !$0.hasSuffix("/HEAD") }
                let remotes = (git(repo, ["remote"]) ?? "").split(separator: "\n").map(String.init)
                let isRemote: (String) -> Bool = { r in remotes.contains { r == $0 || r.hasPrefix($0 + "/") } }
                info["branches"] = refs.filter { !isRemote($0) }
                info["remote_branches"] = refs.filter { isRemote($0) && !remotes.contains($0) }
            }

            // decide: remove the payload only when the result is exactly the last clean commit
            if let lc = lastClean, trailingTrimmed(stripped.text) == trailingTrimmed(String(decoding: lc.blob, as: UTF8.self)) {
                if mode == "contain" {
                    let perms = (try? fm.attributesOfItem(atPath: path))?[.posixPermissions]
                    if let kept = quarantine(path, reason: "infected-version", batch: batch, keepOriginal: true),
                       (try? lc.blob.write(to: URL(fileURLWithPath: path), options: .atomic)) != nil {
                        if let perms { try? fm.setAttributes([.posixPermissions: perms], ofItemAtPath: path) }
                        info["action"] = "restored"
                        act("restore_file", path, "done",
                            "Removed the injected code from \(rel) — it now matches commit \(lc.commit.short) byte for byte (infected copy kept for undo).",
                            ["quarantined_copy": kept, "clean_commit": lc.commit.sha])
                    } else {
                        info["action"] = "proposed"
                        act("restore_file", path, "failed", "Couldn't rewrite \(rel); restore it from commit \(lc.commit.short).",
                            ["how": "git -C \(shellPath(repo)) checkout \(lc.commit.sha) -- \"\(rel)\""])
                    }
                } else {
                    info["action"] = "proposed"
                    act("restore_file", path, "proposed", "Remove the injected code from \(rel) (the result matches commit \(lc.commit.short) exactly).",
                        ["how": "# let Bastion do it (auto-respond on), or restore it yourself\nbastion respond \(shellPath(repo))\ngit -C \(shellPath(repo)) checkout \(lc.commit.sha) -- \"\(rel)\""])
                }
            } else if let lc = lastClean {
                info["action"] = "proposed"
                act("restore_file", path, "proposed",
                    "Restore \(rel) from commit \(lc.commit.short) — review first: the file has other changes besides the injected code.",
                    ["how": "git -C \(shellPath(repo)) diff \(lc.commit.sha) -- \"\(rel)\"\ngit -C \(shellPath(repo)) checkout \(lc.commit.sha) -- \"\(rel)\""])
            } else {
                info["action"] = "proposed"
                var extra: [String: Any] = [:]
                if payloadReasons(Data(stripped.text.utf8), config: isConfig).isEmpty {
                    let dir = engine("incidents/\(id)/suggested")
                    try? fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
                    let copy = dir + "/" + rel.replacingOccurrences(of: "/", with: "__")
                    if (try? stripped.text.write(toFile: copy, atomically: true, encoding: .utf8)) != nil { extra["suggested_copy"] = copy }
                }
                act("clean_file", path, "proposed",
                    "Clean \(rel) by hand — git has no clean version of it." + (extra["suggested_copy"] != nil ? " Bastion saved a cleaned copy to compare with." : ""),
                    extra.merging(["how": "diff \(shellPath(path)) \(shellPath(extra["suggested_copy"] as? String ?? "<cleaned copy>"))"]) { a, _ in a })
            }
            files.append(info)
        }

        // anything already running from this repo may have loaded the payload
        if let since = infectedSince {
            for p in processesIn(repo) {
                let started = p.started?.timeIntervalSince1970 ?? 0
                if mode == "contain", started >= since, kill(pid_t(p.pid), SIGKILL) == 0 {
                    act("stop_process", "\(p.name) pid \(p.pid)", "done",
                        "Stopped \(p.name) (pid \(p.pid)) — it started in \(tilde(repo)) after the payload arrived, so it may have been running it.")
                } else {
                    act("stop_process", "\(p.name) pid \(p.pid)", "proposed",
                        "Restart \(p.name) (pid \(p.pid)) in \(tilde(repo)) once the fix is in — " +
                        (started >= since ? "it may be running the payload." : "it started before the payload arrived, but restart it to be safe."),
                        ["how": "kill \(p.pid)   # then start your dev server again"])
                }
            }
        }

        var entry: [String: Any] = ["path": repo, "hooks": hooks]
        let previous = repoCases.first { $0["path"] as? String == repo }
        let newPaths = Set(files.compactMap { $0["path"] as? String })
        entry["files"] = ((previous?["files"] as? [[String: Any]]) ?? []).filter { !newPaths.contains($0["path"] as? String ?? "") } + files
        if let hit = buildCacheHit(repo) {
            entry["build_cache"] = hit
            signs.append("The payload is in the build cache of \(tilde(repo)) (\(tilde(hit))) — a dev server may have compiled it.")
        }
        repoCases.removeAll { $0["path"] as? String == repo }
        repoCases.append(entry)
    }

    // 3. MACHINE — leftovers, loaders and live connections
    let machineFindings = found.filter { $0["scope"] as? String == "machine" }
    let commandLines = processColumn("args"), processNames = processColumn("ucomm")
    for f in machineFindings {
        machine.append(f)
        let kind = f["kind"] as? String ?? "", title = f["title"] as? String ?? kind
        signs.append("\(title): \(tilde(f["path"] as? String ?? (f["ip"] as? String) ?? ""))")
        switch kind {
        case "staging_folder", "beacon_file", "stolen_data", "hidden_runtime":
            guard let p = f["path"] as? String else { continue }
            if mode == "contain", let q = quarantine(p, reason: kind, batch: batch, keepOriginal: false) {
                act("quarantine", p, "done", "Quarantined the \(title.lowercased()) at \(tilde(p)).", ["stored_at": q])
            } else {
                act("quarantine", p, mode == "contain" ? "failed" : "proposed", "Quarantine the \(title.lowercased()) at \(tilde(p)).",
                    ["how": "bastion scan   # moves known-malicious leftovers into quarantine"])
            }
        case "loader_process":
            for pid in f["pids"] as? [Int] ?? [] {
                let cmd = commandLines[pid] ?? ""
                let seen = indicatorsIn(cmd)
                seen.ips.forEach { addIndicator($0, "ip", "loader command line") }
                seen.domains.forEach { addIndicator($0, "domain", "loader command line") }
                let stillLoader = processNames[pid]?.has(#"^node[0-9.]*$"#) == true && cmd.has(LOADER_RE)
                if mode == "contain", stillLoader, kill(pid_t(pid), SIGKILL) == 0 {
                    act("kill", "pid \(pid)", "done", "Killed the malware loader (pid \(pid)).")
                } else if stillLoader {
                    act("kill", "pid \(pid)", "proposed", "Kill the malware loader (pid \(pid)).", ["how": "kill -9 \(pid)"])
                }
            }
        case "c2_connection":
            guard let ip = f["ip"] as? String else { continue }
            for peer in liveC2() where peer["ip"] as? String == ip {
                let pid = peer["pid"] as? Int ?? 0, name = peer["process"] as? String ?? "?"
                if mode == "contain", name.has(#"^(node|next|npm|npx|pnpm|yarn|bun|deno)"#), pid > 0, kill(pid_t(pid), SIGKILL) == 0 {
                    act("kill", "\(name) pid \(pid)", "done", "Killed \(name) (pid \(pid)) — it was connected to the attacker server \(ip).")
                } else {
                    act("kill", "\(name) pid \(pid)", "proposed", "Quit \(name) (pid \(pid)) — it is connected to the attacker server \(ip).",
                        ["how": "kill \(pid)"])
                }
            }
        default: break
        }
    }
    for r in reflexes where (r["event"] ?? "").contains("KILLED") || (r["event"] ?? "").contains("QUARANTINED") {
        signs.append("Watcher, \(humanTime(r["time"])): \(r["event"] ?? "")")
    }

    // 4. INDICATORS — block addresses found in the payload itself; anything doubtful stays a proposal
    let blocked = Set(listEntries("blocklist.txt")), allowed = Set(listEntries("allowlist.txt")), busy = ipsInUseByOthers()
    for i in indicators.indices where indicators[i]["status"] == nil {
        let v = indicators[i]["value"] as? String ?? "", source = indicators[i]["source"] as? String ?? ""
        guard indicators[i]["type"] as? String == "ip" else { indicators[i]["status"] = "reported"; continue }
        if blocked.contains(v) { indicators[i]["status"] = "already_blocked" }
        else if allowed.contains(v) { indicators[i]["status"] = "skipped"; indicators[i]["note"] = "on your allowlist" }
        else if isLocalAddress(v) { indicators[i]["status"] = "skipped"; indicators[i]["note"] = "local or private address" }
        else if busy.contains(v) {
            indicators[i]["status"] = "proposed"; indicators[i]["note"] = "another app is connected to it — check before blocking"
            act("block", v, "proposed", "Block \(v) (\(source)) — another app is connected to it, so check first.", ["how": "bastion block add \(v)"])
        } else if mode == "contain", (try? addEntry("blocklist.txt", v, note: "auto-blocked by Bastion — \(id), \(source)")) == true {
            indicators[i]["status"] = "blocked"
            act("block", v, "done", "Blocked \(v) — found in the \(source).")
        } else {
            indicators[i]["status"] = "proposed"
            act("block", v, "proposed", "Block \(v) (\(source)).", ["how": "bastion block add \(v)"])
        }
    }

    // 5. WHO — the identity that planted it, and what else it touched
    let own = ownGitEmail()
    var hunt = inc["hunt"] as? [[String: Any]] ?? []
    for r in repoCases {
        for f in r["files"] as? [[String: Any]] ?? [] {
            guard let c = f["introduced_by"] as? [String: Any], let email = (c["committer_email"] as? String)?.lowercased(), !email.isEmpty else { continue }
            let identity = "\(c["committer"] as? String ?? "") <\(email)>"
            if hunt.contains(where: { $0["identity"] as? String == identity }) { continue }
            hunt.append(["identity": identity, "email": email, "own": email == own, "repos": email == own ? [] : huntIdentity(email)])
        }
    }

    // 6. VERIFY — scan again and record the result as a scan log, so every view agrees
    let affected = repoCases.compactMap { $0["path"] as? String }.filter { fm.fileExists(atPath: $0) }
    let remaining = parseFindings(run("/bin/bash", [engine("scanner.sh")] + (affected.isEmpty ? [engine("")] : affected), timeout: 1800).out)
    let verifyLog = engine("logs/scan-\(stamp(Date())).log")
    var logText = "=== bastion response \(id) (verify) ===\nroots: \(affected.joined(separator: " "))\n"
    logText += remaining.isEmpty ? "RESULT: CLEAN\n" : "RESULT: \(remaining.count) FINDING(S)\n"
    for f in remaining {
        let code = KINDS.first { $0.value.id == f["kind"] as? String }?.key ?? "CONFIG"
        logText += "  \(code)|\(f["path"] as? String ?? (f["ip"] as? String) ?? "")|\(f["detail"] as? String ?? "")\n"
    }
    try? logText.write(toFile: verifyLog, atomically: true, encoding: .utf8)
    timeline.append(["time": isoTime(Date()), "event": remaining.isEmpty ? "Verified: a fresh scan is clean." : "Verified: \(remaining.count) problem(s) still need you."])

    // 7. REPORT
    let ranLevel: String = !machineFindings.isEmpty || reflexes.contains(where: { ($0["event"] ?? "").contains("KILLED") || ($0["event"] ?? "").contains("QUARANTINED") })
        ? "yes" : (signs.isEmpty ? (inc["ran"] as? String ?? "no sign") : (inc["ran"] as? String == "yes" ? "yes" : "possibly"))
    var uniqueSigns: [String] = []
    for s in signs where !uniqueSigns.contains(s) { uniqueSigns.append(s) }
    inc["mode"] = mode
    inc["updated"] = isoTime(Date())
    inc["status"] = remaining.isEmpty ? "contained" : "open"
    inc["repos"] = repoCases
    inc["machine"] = machine
    inc["indicators"] = indicators
    inc["actions"] = actions
    inc["timeline"] = timeline
    inc["hunt"] = hunt
    inc["ran"] = ranLevel
    inc["ran_signs"] = uniqueSigns
    inc["secrets"] = secretsAtRisk(affected)
    inc["remaining"] = remaining
    inc["todos"] = buildTodos(inc)
    inc["summary"] = buildSummary(inc)
    let report = saveIncident(inc)

    let todoCount = max(((inc["todos"] as? [Any])?.count ?? 1) - 1, 0)
    logEvent("INCIDENT \(id) [\(inc["status"] ?? "")]: \(inc["summary"] as? String ?? "")")
    notify(inc["status"] as? String == "contained"
           ? "Contained an attack — \(todoCount) thing\(todoCount == 1 ? "" : "s") for you to do. Open Bastion for the report."
           : "Found an attack that needs you. Open Bastion for the report.")
    var out = inc
    out["report"] = report
    return out
}

func acquireLock(_ lock: String, wait: Bool) -> Bool {
    let deadline = Date().addingTimeInterval(wait ? 120 : 0)
    while true {
        if (try? fm.createDirectory(atPath: lock, withIntermediateDirectories: false)) != nil { return true }
        if let m = (try? fm.attributesOfItem(atPath: lock))?[.modificationDate] as? Date, Date().timeIntervalSince(m) > 900 {
            guard (try? fm.removeItem(atPath: lock)) != nil else { return false }   // a crashed run left it behind
            continue
        }
        if Date() >= deadline { return false }
        Thread.sleep(forTimeInterval: 0.5)
    }
}

// MARK: - To-dos, summary, report

func buildTodos(_ inc: [String: Any]) -> [[String: String]] {
    let id = inc["id"] as? String ?? ""
    var todos: [[String: String]] = []
    for r in inc["repos"] as? [[String: Any]] ?? [] {
        let repo = r["path"] as? String ?? "", name = (repo as NSString).lastPathComponent
        let files = r["files"] as? [[String: Any]] ?? []
        let restored = files.filter { $0["action"] as? String == "restored" }.compactMap { $0["rel"] as? String }
        if !restored.isEmpty {
            todos.append(["title": "Commit the cleaned file\(restored.count == 1 ? "" : "s") in \(name)",
                          "why": "Bastion fixed your working copy; git doesn't have the fix yet.",
                          "cmd": "git -C \(shellPath(repo)) add -- \(restored.map { "\"\($0)\"" }.joined(separator: " "))\ngit -C \(shellPath(repo)) commit -m \"Remove injected payload (Bastion \(id))\""])
        }
        var pushed: [String] = []
        for f in files { for b in f["remote_branches"] as? [String] ?? [] where !pushed.contains(b) { pushed.append(b) } }
        if !pushed.isEmpty {
            todos.append(["title": "Clean the pushed branches of \(name)",
                          "why": "\(pushed.joined(separator: ", ")) still carr\(pushed.count == 1 ? "ies" : "y") the bad commit — anyone who pulls \(pushed.count == 1 ? "it" : "them") gets the malware.",
                          "cmd": "# after committing the fix, push each branch you use\ngit -C \(shellPath(repo)) push\n# and delete the ones you don't\ngit -C \(shellPath(repo)) push <remote> --delete <branch>"])
        }
        for h in r["hooks"] as? [[String: Any]] ?? [] {
            todos.append(["title": "\(h["title"] as? String ?? "Fix") in \(tilde(h["path"] as? String ?? ""))",
                          "why": h["explanation"] as? String ?? "", "how": h["remediation"] as? String ?? ""])
        }
    }
    let actions = inc["actions"] as? [[String: Any]] ?? []
    for (i, a) in actions.enumerated() where ["proposed", "failed"].contains(a["status"] as? String ?? "") {
        if !proposalStillOpen(a, later: actions.dropFirst(i + 1)) { continue }
        var t = ["title": a["detail"] as? String ?? "", "why": a["status"] as? String == "failed" ? "Bastion tried and couldn't." : "Bastion didn't do this on its own."]
        if let how = a["how"] as? String { t["cmd"] = how }
        todos.append(t)
    }
    for h in inc["hunt"] as? [[String: Any]] ?? [] {
        let identity = h["identity"] as? String ?? ""
        if h["own"] as? Bool == true {
            todos.append(["title": "Check how your own git identity committed the payload",
                          "why": "The bad commit is under your name (\(identity)) — someone used your machine, account or token, or copied your name.",
                          "how": "Review recent pushes in your git host's audit log and rotate your git credentials."])
            continue
        }
        todos.append(["title": "Remove access for \(identity)",
                      "why": "This identity committed the malware. Names and emails in commits can be faked, so confirm who actually pushed it.",
                      "how": "GitHub → repository Settings → Collaborators and teams. For organizations, Settings → Audit log shows who pushed."])
        let repos = h["repos"] as? [[String: Any]] ?? []
        let total = repos.reduce(0) { $0 + ($1["count"] as? Int ?? 0) }
        if total > 0 {
            let cmds = repos.flatMap { r in
                (r["commits"] as? [[String: Any]] ?? []).map { "git -C \(shellPath(r["repo"] as? String ?? "")) show \($0["short"] as? String ?? "")   # \($0["subject"] as? String ?? "")" }
            }
            todos.append(["title": "Review \(total) commit\(total == 1 ? "" : "s") by this identity",
                          "why": "It committed to: \(repos.map { tilde($0["repo"] as? String ?? "") }.joined(separator: ", ")).",
                          "cmd": cmds.prefix(12).joined(separator: "\n")])
        }
    }
    let secrets = inc["secrets"] as? [[String: String]] ?? []
    if !secrets.isEmpty {
        let list = secrets.map { "• \($0["what"] ?? "") — \($0["how"] ?? "")" }.joined(separator: "\n")
        switch inc["ran"] as? String ?? "no sign" {
        case "yes": todos.append(["title": "Rotate the secrets that were on this Mac — from a clean device",
                                  "why": "The payload ran here, and these are exactly what it steals.", "how": list])
        case "possibly": todos.append(["title": "Rotate the secrets that were on this Mac — from a clean device",
                                       "why": "The payload may have run here.", "how": list])
        default: todos.append(["title": "If you ran dev, build or test in an affected repo, rotate these secrets",
                               "why": "Bastion found no sign the payload ran, but it runs the moment a dev server loads the file.", "how": list])
        }
    }
    todos.append(["title": "Mark this incident resolved when you're done", "why": "It clears the incident from Bastion.", "cmd": "bastion incident resolve \(id)"])
    return todos
}

/// A proposal stays on the list only while it still applies and nothing later has already done it.
func proposalStillOpen(_ a: [String: Any], later: ArraySlice<[String: Any]>) -> Bool {
    let type = a["type"] as? String ?? "", target = a["target"] as? String ?? ""
    if later.contains(where: { $0["type"] as? String == type && $0["target"] as? String == target && $0["status"] as? String == "done" }) { return false }
    switch type {
    case "restore_file", "clean_file":
        guard let data = fm.contents(atPath: target) else { return false }
        return !payloadReasons(data, config: true).isEmpty || !payloadReasons(data, config: false).isEmpty
    case "kill", "stop_process":
        guard let pid = target.split(separator: " ").last.flatMap({ Int($0) }) else { return true }
        return kill(pid_t(pid), 0) == 0
    case "block": return !listEntries("blocklist.txt").contains(target)
    case "quarantine": return fm.fileExists(atPath: target)
    default: return true
    }
}

func buildSummary(_ inc: [String: Any]) -> String {
    let actions = inc["actions"] as? [[String: Any]] ?? []
    func done(_ types: String...) -> Int { actions.filter { types.contains($0["type"] as? String ?? "") && $0["status"] as? String == "done" }.count }
    var did: [String] = []
    let r = done("restore_file"); if r > 0 { did.append("removed injected code from \(r) file\(r == 1 ? "" : "s")") }
    let k = done("kill", "stop_process"); if k > 0 { did.append("stopped \(k) process\(k == 1 ? "" : "es")") }
    let q = done("quarantine"); if q > 0 { did.append("quarantined \(q) item\(q == 1 ? "" : "s")") }
    let b = done("block"); if b > 0 { did.append("blocked \(b) address\(b == 1 ? "" : "es")") }
    let repos = (inc["repos"] as? [Any])?.count ?? 0
    let scope = repos > 0 ? "an attack on \(repos) repo\(repos == 1 ? "" : "s")" : "signs of malware on this Mac"
    let todos = max(((inc["todos"] as? [Any])?.count ?? 1) - 1, 0)
    let head: String
    switch inc["status"] as? String ?? "open" {
    case "contained": head = "Contained \(scope)"
    case "resolved": head = "Resolved \(scope)"
    default: head = "Found \(scope)"
    }
    return head + (did.isEmpty ? "" : " — " + did.joined(separator: ", ")) + "." +
        (inc["status"] as? String == "resolved" || todos == 0 ? "" : " \(todos) thing\(todos == 1 ? "" : "s") for you to do.")
}

func reportMarkdown(_ inc: [String: Any]) -> String {
    let id = inc["id"] as? String ?? ""
    let status = (inc["status"] as? String ?? "open").uppercased()
    var md = "# Bastion incident \(id)\n\n**\(status)** · opened \(humanTime(inc["opened"])) · updated \(humanTime(inc["updated"])) · mode: \(inc["mode"] as? String ?? "")\n\n"
    md += (inc["summary"] as? String ?? "") + "\n\n## What happened\n\n"
    for r in inc["repos"] as? [[String: Any]] ?? [] {
        let repo = tilde(r["path"] as? String ?? "")
        for f in r["files"] as? [[String: Any]] ?? [] {
            md += "- `\(f["rel"] as? String ?? "")` in `\(repo)` carries the payload (\(f["detail"] as? String ?? "")). "
            if let c = f["introduced_by"] as? [String: Any] {
                md += "It arrived in commit `\(c["short"] as? String ?? "")` by **\(c["committer"] as? String ?? "") <\(c["committer_email"] as? String ?? "")>** on \(humanTime(c["date"])) — “\(c["subject"] as? String ?? "")”."
                let branches = (f["branches"] as? [String] ?? []) + (f["remote_branches"] as? [String] ?? [])
                if !branches.isEmpty { md += " Branches with it: \(branches.map { "`\($0)`" }.joined(separator: ", "))." }
            } else if f["tracked"] as? Bool == true {
                md += "The change isn't committed — something on this Mac wrote it straight to disk."
            } else { md += "The file isn't tracked by git." }
            md += "\n"
        }
        for h in r["hooks"] as? [[String: Any]] ?? [] { md += "- \(h["title"] as? String ?? ""): `\(tilde(h["path"] as? String ?? ""))`.\n" }
    }
    for f in inc["machine"] as? [[String: Any]] ?? [] {
        md += "- \(f["title"] as? String ?? ""): `\(tilde(f["path"] as? String ?? (f["ip"] as? String) ?? ""))`.\n"
    }
    md += "\n## Did it run on this Mac?\n\n"
    switch inc["ran"] as? String ?? "no sign" {
    case "yes": md += "**Yes.**"
    case "possibly": md += "**Possibly.**"
    default: md += "**No sign it ran.** It runs the moment a dev server, build or test loads the file, so think back to whether you ran one here."
    }
    md += "\n"
    for s in inc["ran_signs"] as? [String] ?? [] { md += "- \(s)\n" }
    md += "\n## What Bastion did\n\n"
    let actions = inc["actions"] as? [[String: Any]] ?? []
    let done = actions.filter { ["done", "undone"].contains($0["status"] as? String ?? "") }
    if done.isEmpty {
        md += inc["mode"] as? String == "observe" ? "Nothing yet — Bastion is set to observe, so it only investigates and reports.\n"
                                                  : "Nothing automatic was safe to do here.\n"
    }
    for a in done { md += "- \(a["status"] as? String == "undone" ? "↩︎ Undone:" : "✅") \(a["detail"] as? String ?? "")\n" }
    if actions.contains(where: { $0["type"] as? String == "restore_file" && $0["status"] as? String == "done" }) {
        md += "\nUndo Bastion's file changes with `bastion undo \(id)`.\n"
    }
    let resolved = inc["status"] as? String == "resolved"
    md += resolved ? "\n## Resolved\n\nMarked resolved on \(humanTime(inc["resolved"])).\n" : "\n## What you need to do\n\n"
    for (n, t) in (resolved ? [] : inc["todos"] as? [[String: String]] ?? []).enumerated() {
        md += "\(n + 1). **\(t["title"] ?? "")** — \(t["why"] ?? "")\n"
        if let how = t["how"], !how.isEmpty { md += how.split(separator: "\n").map { "   \($0)" }.joined(separator: "\n") + "\n" }
        if let cmd = t["cmd"], !cmd.isEmpty { md += "   ```\n" + cmd.split(separator: "\n").map { "   \($0)" }.joined(separator: "\n") + "\n   ```\n" }
    }
    let indicators = inc["indicators"] as? [[String: Any]] ?? []
    if !indicators.isEmpty {
        md += "\n## Indicators\n\n| Indicator | Found in | Status |\n| --- | --- | --- |\n"
        for i in indicators {
            md += "| `\(i["value"] as? String ?? "")` | \(i["source"] as? String ?? "") | \((i["status"] as? String ?? "").replacingOccurrences(of: "_", with: " "))\(i["note"].map { " — \($0)" } ?? "") |\n"
        }
    }
    let hunt = (inc["hunt"] as? [[String: Any]] ?? []).filter { !(($0["repos"] as? [Any]) ?? []).isEmpty }
    if !hunt.isEmpty {
        md += "\n## Everything else this identity touched\n\n"
        for h in hunt {
            md += "**\(h["identity"] as? String ?? "")**\n"
            for r in h["repos"] as? [[String: Any]] ?? [] {
                md += "- `\(tilde(r["repo"] as? String ?? ""))` — \(r["count"] as? Int ?? 0) commit(s): " +
                    (r["commits"] as? [[String: Any]] ?? []).prefix(4).map { "`\($0["short"] as? String ?? "")` \($0["subject"] as? String ?? "")" }.joined(separator: "; ") + "\n"
            }
        }
    }
    md += "\n## Timeline\n\n"
    for e in inc["timeline"] as? [[String: Any]] ?? [] { md += "- \(humanTime(e["time"])) — \(e["event"] as? String ?? "")\n" }
    return md
}

// MARK: - People-only follow-ups

func resolveIncident(_ id: String) throws -> [String: Any] {
    guard var inc = findIncident(id) else { throw Failure("No incident \(id). List them with `bastion incidents`.") }
    inc["status"] = "resolved"
    inc["resolved"] = isoTime(Date())
    inc["updated"] = isoTime(Date())
    inc["timeline"] = (inc["timeline"] as? [[String: Any]] ?? []) + [["time": isoTime(Date()), "event": "Marked resolved."]]
    inc["todos"] = []
    inc["summary"] = buildSummary(inc)
    saveIncident(inc)
    logEvent("INCIDENT \(inc["id"] as? String ?? id): marked resolved")
    return incidentBrief(inc)
}

func undoIncident(_ id: String) throws -> [String: Any] {
    guard var inc = findIncident(id) else { throw Failure("No incident \(id). List them with `bastion incidents`.") }
    var actions = inc["actions"] as? [[String: Any]] ?? []
    var undone: [String] = []
    for i in actions.indices where actions[i]["type"] as? String == "restore_file" && actions[i]["status"] as? String == "done" {
        guard let target = actions[i]["target"] as? String, let copy = actions[i]["quarantined_copy"] as? String,
              fm.fileExists(atPath: copy) else { continue }
        let staged = target + ".bastion-undo"
        try? fm.removeItem(atPath: staged)
        guard (try? fm.copyItem(atPath: copy, toPath: staged)) != nil,
              (try? fm.replaceItemAt(URL(fileURLWithPath: target), withItemAt: URL(fileURLWithPath: staged))) != nil else { continue }
        actions[i]["status"] = "undone"
        undone.append(target)
    }
    inc["actions"] = actions
    inc["status"] = "open"
    inc["updated"] = isoTime(Date())
    inc["timeline"] = (inc["timeline"] as? [[String: Any]] ?? []) + [["time": isoTime(Date()), "event": "Undid \(undone.count) file fix(es) by request."]]
    inc["todos"] = buildTodos(inc)
    inc["summary"] = buildSummary(inc)
    saveIncident(inc)
    if !undone.isEmpty { logEvent("CHANGED: undid \(undone.count) file fix(es) from incident \(inc["id"] as? String ?? id) (bastion CLI)") }
    return ["id": inc["id"] ?? id, "undone": undone]
}

/// Agents may block an address only when an incident ties it to malware on this Mac.
func blockIndicator(_ ip: String, incident: String?) throws -> [String: Any] {
    guard ipFamily(ip) != nil else { throw Failure("\(ip) isn't an IP address.") }
    guard !isLocalAddress(ip) else { throw Failure("\(ip) is a local or private address — blocking it would break local development.") }
    guard !listEntries("allowlist.txt").contains(ip) else { throw Failure("\(ip) is on the user's allowlist; only they can change that.") }
    let pool = incident.flatMap(findIncident).map { [$0] } ?? allIncidents().filter { ($0["status"] as? String) != "resolved" }
    guard var inc = pool.first(where: { ($0["indicators"] as? [[String: Any]] ?? []).contains { $0["value"] as? String == ip } }) else {
        throw Failure("No incident ties \(ip) to malware on this Mac, so Bastion won't block it for an agent. The user can: bastion block add \(ip)")
    }
    let id = inc["id"] as? String ?? ""
    if listEntries("blocklist.txt").contains(ip) { return ["ip": ip, "blocked": true, "changed": false, "evidence": id] }
    _ = try addEntry("blocklist.txt", ip, note: "blocked by an AI agent — evidence: \(id)")
    var indicators = inc["indicators"] as? [[String: Any]] ?? []
    for i in indicators.indices where indicators[i]["value"] as? String == ip { indicators[i]["status"] = "blocked" }
    inc["indicators"] = indicators
    inc["timeline"] = (inc["timeline"] as? [[String: Any]] ?? []) + [["time": isoTime(Date()), "event": "An AI agent blocked \(ip)."]]
    saveIncident(inc)
    logEvent("CHANGED: blocklist — added \(ip) (AI agent, evidence \(id))")
    notify("An AI agent blocked \(ip) — evidence: \(id).")
    return ["ip": ip, "blocked": true, "changed": true, "evidence": id]
}
