// attention.swift: what needs the user right now, and how to get it done.
// One live list (threats, infected branches, open to-dos) that every view reads, fixes that run with one click,
// the setup steps that are still open, and which AI agents are connected.
import Foundation

// MARK: - GitHub: is a branch still on the server? (via the gh CLI when it's there; cached for 10 minutes)

let GH_BIN: String? = ["/opt/homebrew/bin/gh", "/usr/local/bin/gh", "/usr/bin/gh"].first { fm.isExecutableFile(atPath: $0) }

/// true = the branch was deleted on GitHub · false = it's there · nil = can't tell (no gh, not GitHub, offline)
func serverBranchGone(repo: String, branch: String, network: Bool) -> Bool? {
    guard let gh = githubURL(repo) else { return nil }
    let slug = gh.replacingOccurrences(of: "https://github.com/", with: "")
    let key = slug + "|" + branch
    let cacheFile = engine("cache/server-branches.json")
    var cache = (fm.contents(atPath: cacheFile).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: [String: Any]] }) ?? [:]
    if let hit = cache[key], let t = parseISO(hit["checked"]), Date().timeIntervalSince(t) < 600 { return hit["gone"] as? Bool }
    guard network, let bin = GH_BIN else { return nil }
    let r = run(bin, ["api", "repos/\(slug)/git/ref/heads/\(branch)"], timeout: 10)
    let gone: Bool?
    if r.code == 0, r.out.contains("\"refs/heads/\(branch)\"") { gone = false }
    else if r.out.contains("\"Not Found\"") { gone = true }
    else { gone = nil }
    if let gone {
        cache[key] = ["gone": gone, "checked": isoTime(Date())]
        try? fm.createDirectory(atPath: engine("cache"), withIntermediateDirectories: true)
        try? jsonText(cache).write(toFile: cacheFile, atomically: true, encoding: .utf8)
    }
    return gone
}

// MARK: - The live list

/// Infected branches as they are right now: the repos the last scan flagged, checked again (fast: verdicts are cached).
let LIVE_BRANCHES = Memo<[[String: Any]]>(ttl: 5)
func liveBranchFindings() -> [[String: Any]] { LIVE_BRANCHES.get(computeLiveBranches) }
private func computeLiveBranches() -> [[String: Any]] {
    let last = scanLogPaths().last.map(parseScanLog)
    let repos = Set((last?["findings"] as? [[String: Any]] ?? []).filter { $0["kind"] as? String == "infected_branch" }.compactMap { $0["path"] as? String })
    guard !repos.isEmpty else { return [] }
    return branchFindings(repos: repos.sorted()).map { ["kind": "infected_branch", "path": $0.repo, "ref": $0.ref, "file": $0.file, "commit": $0.commit] }
}

/// Active threats right now: live loaders and attacker connections, and last-scan findings that are still on disk.
func liveThreats() -> [[String: Any]] {
    var threats: [[String: Any]] = []
    for l in liveLoaders() {
        var f = makeFinding("PROCESS", "\(l["pid"] as? Int ?? 0)", "loader-running"); f["command"] = l["command"]; threats.append(f)
    }
    for c in liveC2() {
        var f = makeFinding("NETWORK", c["ip"] as? String ?? "", "c2-connection"); f["process"] = c["process"]; f["pid"] = c["pid"]; threats.append(f)
    }
    let last = scanLogPaths().last.map(parseScanLog)
    for f in (last?["findings"] as? [[String: Any]] ?? []) where f["path"] != nil && f["kind"] as? String != "infected_branch" && stillPresent(f) { threats.append(f) }
    return threats
}

func stableID(_ s: String) -> String {
    var h: UInt64 = 0xcbf29ce484222325
    for b in s.utf8 { h ^= UInt64(b); h = h &* 0x100000001b3 }
    return String(String(h, radix: 36).prefix(8))
}

/// Everything that needs the user, most urgent first. Each item says what it is, how dangerous it is now, and the fix.
/// danger: "now" (running or will run as soon as npm runs here) · "dormant" (on a branch; nothing runs unless someone
/// switches to it) · "leftover" (already gone from GitHub; only an old pointer on this Mac) · "check" (a step to confirm)
func needsYou(threats given: [[String: Any]]? = nil, network: Bool = false, detail: Bool = true) -> [[String: Any]] {
    var items: [[String: Any]] = []
    let open = allIncidents().filter { ($0["status"] as? String) != "resolved" }
    func incidentFor(_ repo: String?) -> String? {
        guard let repo else { return open.first?["id"] as? String }
        return open.first { (($0["repos"] as? [[String: Any]]) ?? []).contains { $0["path"] as? String == repo } }?["id"] as? String
    }

    // 1. threats: act now
    for f in given ?? liveThreats() {
        let path = f["path"] as? String ?? f["ip"] as? String ?? ""
        let kind = f["kind"] as? String ?? ""
        let project = f["scope"] as? String == "project"
        let repo = project ? repoRoot(of: path) : nil
        var item: [String: Any] = ["id": stableID("threat|\(kind)|\(path)|\(f["detail"] ?? "")"), "type": "threat", "danger": "now",
                                   "title": f["title"] ?? "Threat", "what": f["explanation"] ?? "", "where": tilde(path), "finding": f]
        if let repo { item["repo"] = repo; item["repo_name"] = (repo as NSString).lastPathComponent }
        if (kind == "injected_config" || kind == "source_payload"), let data = fm.contents(atPath: path) {
            let ev = hiddenCodeEvidence(data)
            item["proof"] = [["file": tilde(path), "text": evidenceSentence(ev)]]
        }
        let contain = ["injected_config", "source_payload", "loader_process", "c2_connection", "staging_folder", "beacon_file", "stolen_data",
                       "hidden_runtime", "malicious_dependency", "known_malicious_package"].contains(kind)
        item["fix"] = ["title": contain ? "Let Bastion contain it" : "Fix it by hand", "button": "Contain it now",
                       "why": (contain ? "Bastion removes injected code only when the file then matches its last clean commit exactly (with undo), stops loaders and quarantines leftovers. " : "")
                              + (f["remediation"] as? String ?? ""),
                       "commands": contain ? ["bastion respond --contain"] : [String](), "risk": "safe", "runnable": contain]
        if let id = incidentFor(repo) { item["incident"] = id }
        items.append(item)
    }

    // 2. infected branches: dormant, or leftovers already gone from GitHub
    if !detail {   // counts only (status): no proof or fix analysis
        var seen = Set<String>()
        var remotes: [String: [String]] = [:]
        for f in liveBranchFindings() {
            let repo = f["path"] as? String ?? "", ref = f["ref"] as? String ?? ""
            guard seen.insert(repo + "|" + ref).inserted else { continue }
            if remotes[repo] == nil { remotes[repo] = (git(repo, ["remote"]) ?? "").split(separator: "\n").map(String.init) }
            let remote = remotes[repo]?.first { ref.hasPrefix($0 + "/") }
            let branch = remote.map { String(ref.dropFirst($0.count + 1)) } ?? ref
            let gone = remote != nil && serverBranchGone(repo: repo, branch: branch, network: false) == true
            items.append(["id": stableID("branch|\(repo)|\(ref)"), "type": "branch", "danger": gone ? "leftover" : "dormant", "title": "Clean \(branch)",
                          "repo": repo, "repo_name": (repo as NSString).lastPathComponent])
        }
    }
    for c in detail ? branchContexts(liveBranchFindings()) : [] {
        let repo = c["repo"] as? String ?? "", ref = c["ref"] as? String ?? "", branch = c["branch"] as? String ?? ref
        let files = c["files"] as? [String] ?? []
        var fix = c["fix"] as? [String: Any] ?? [:]
        var danger = "dormant"
        var what = "An old copy of \(files.joined(separator: " and ")) with hidden malware is on the branch \(branch). Nothing runs unless someone switches to it and runs npm (dev, build, test or install)."
        if c["on_server"] as? Bool == true, serverBranchGone(repo: repo, branch: branch, network: network) == true {
            danger = "leftover"
            what = "\(branch) was already deleted on GitHub. This Mac still keeps an old pointer to it, which is all Bastion sees."
            let remote = String(ref.prefix(ref.count - branch.count - 1))
            fix = ["title": "Clear the old pointer to \(branch)", "why": "It's already gone from GitHub; this only tidies up this Mac. Nothing is deleted on the server.",
                   "commands": ["git -C \(shellPath(repo)) fetch --prune \(remote)"], "risk": "safe", "button": "Clear it"]
        }
        fix["runnable"] = !(fix["risk"] as? String == "rewrites-nothing")
        switch fix["risk"] as? String ?? "" {
        case "commit": what = "Bastion already cleaned \(files.joined(separator: " and ")) in your working copy, but the infected version is still committed on \(branch)."
        case "push": what = "\(ref) on the server still has the infected \(files.joined(separator: " and ")). Anyone who pulls it gets the malware."
        default: break
        }
        var item: [String: Any] = ["id": stableID("branch|\(repo)|\(ref)"), "type": "branch", "danger": danger, "title": fix["title"] ?? "Clean \(branch)",
                                   "what": what, "where": "\(ref) · \(files.joined(separator: ", "))", "repo": repo,
                                   "repo_name": (repo as NSString).lastPathComponent, "branch": c, "proof": c["proof"] ?? [], "fix": fix]
        if let id = incidentFor(repo) { item["incident"] = id }
        items.append(item)
    }

    // 3. what an open incident still asks of you that Bastion can't check for you (rotate secrets, remove access…);
    //    committing and pushing fixes are already live items above, so they aren't repeated
    let branchRepos = Set(items.filter { $0["type"] as? String == "branch" }.compactMap { $0["repo"] as? String })
    for inc in open {
        let id = inc["id"] as? String ?? ""
        let ticked = Set(inc["ticked"] as? [String] ?? [])
        for t in inc["todos"] as? [[String: Any]] ?? [] {
            let key = t["key"] as? String ?? ""
            guard !key.hasPrefix("branch:"), !key.hasPrefix("resolve"), !ticked.contains(key),
                  !((t["cmd"] as? String) ?? "").hasPrefix("bastion incident resolve") else { continue }
            let title = t["title"] as? String ?? ""
            if (title.hasPrefix("Commit the cleaned file") || title.hasPrefix("Clean the pushed branches")),
               branchRepos.contains(where: { title.hasSuffix(" " + ($0 as NSString).lastPathComponent) }) { continue }
            items.append(["id": stableID("todo|\(id)|\(key)"), "type": "todo", "danger": "check", "title": t["title"] ?? "", "what": t["why"] ?? "",
                          "incident": id, "todo_key": key,
                          "fix": ["title": t["title"] ?? "", "why": t["how"] ?? "", "commands": (t["cmd"] as? String).map { [$0] } ?? [], "risk": "manual", "runnable": false]])
        }
    }
    let rank = ["now": 0, "dormant": 1, "check": 2, "leftover": 3]
    return items.enumerated().sorted { (rank[$0.element["danger"] as? String ?? ""] ?? 9, $0.offset) < (rank[$1.element["danger"] as? String ?? ""] ?? 9, $1.offset) }.map(\.element)
}

/// act_now · clean_up · all_clear: the one answer every view shows
func overallState(_ items: [[String: Any]]) -> String {
    items.contains { $0["danger"] as? String == "now" } ? "act_now" : items.isEmpty ? "all_clear" : "clean_up"
}

func todosReport(network: Bool) -> [String: Any] {
    let items = needsYou(network: network)
    let state = overallState(items)
    let summary: String
    switch state {
    case "act_now": summary = "Act now: \(items.filter { $0["danger"] as? String == "now" }.count) active threat(s)."
    case "clean_up": summary = "\(items.count) thing\(items.count == 1 ? "" : "s") to clean up. Nothing is running."
    default: summary = "All clear. Nothing needs you."
    }
    return ["state": state, "count": items.count, "items": items, "summary": summary]
}

// MARK: - Fixing an item

/// Runs an item's fix: exactly the commands it shows. Anything beyond this Mac (GitHub) or that deletes needs --yes.
func runFix(_ id: String, yes: Bool) throws -> [String: Any] {
    let items = needsYou()
    guard let item = items.first(where: { $0["id"] as? String == id }) else {
        throw Failure("Nothing with id \(id) needs fixing. It may already be done. `bastion todos` shows what's left.")
    }
    let fix = item["fix"] as? [String: Any] ?? [:]
    let cmds = (fix["commands"] as? [String] ?? []).filter { !$0.hasPrefix("#") }
    guard fix["runnable"] as? Bool == true, !cmds.isEmpty else { throw Failure("This one needs you to do it by hand: \(fix["title"] ?? "")") }
    let risk = fix["risk"] as? String ?? "safe"
    if risk != "safe" && !yes {
        throw Failure("This changes more than this Mac (\(risk.replacingOccurrences(of: "-", with: " "))). Run it with --yes, or yourself:\n" + cmds.joined(separator: "\n"))
    }
    var output = "", ok = true
    for cmd in cmds {
        let line = cmd.hasPrefix("bastion ") ? "\"\(engine("bin/bastion"))\" " + cmd.dropFirst(8) : cmd
        let r = run("/bin/bash", ["-c", line + " 2>&1"], timeout: 300,
                    env: ["GIT_TERMINAL_PROMPT": "0", "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"])
        output += "$ \(cmd)\n\(r.out)"
        if r.code != 0 || r.timedOut { ok = false; break }
    }
    let title = fix["title"] as? String ?? item["title"] as? String ?? "fix"
    logEvent(ok ? "FIXED: \(title)" : "FIX FAILED: \(title)")
    LIVE_BRANCHES.reset()   // look again, not at what this process saw before the fix
    let still = needsYou().contains { $0["id"] as? String == id }
    return ["id": id, "ok": ok && !still, "ran": cmds, "output": output, "title": title,
            "message": ok ? (still ? "Ran it, but Bastion still sees the problem. See the output." : "Done: \(title).") : "It didn't work. See the output."]
}

// MARK: - Setup that's still open

let AGENT_DIRS: [(id: String, name: String, dir: String, mcp: String)] = [
    ("claude", "Claude Code", HOME + "/.claude", HOME + "/.claude.json"),
    ("cursor", "Cursor", HOME + "/.cursor", HOME + "/.cursor/mcp.json"),
    ("claude_desktop", "Claude Desktop", HOME + "/Library/Application Support/Claude", HOME + "/Library/Application Support/Claude/claude_desktop_config.json"),
    ("windsurf", "Windsurf", HOME + "/.codeium/windsurf", HOME + "/.codeium/windsurf/mcp_config.json"),
    ("codex", "Codex CLI", HOME + "/.codex", HOME + "/.codex/config.toml"),
]

func mcpConnected(_ id: String) -> Bool {
    guard let a = AGENT_DIRS.first(where: { $0.id == id }) else { return false }
    if id == "codex" { return readText(a.mcp).contains("[mcp_servers.bastion]") }
    guard let data = fm.contents(atPath: a.mcp), let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
    if (root["mcpServers"] as? [String: Any])?["bastion"] != nil { return true }
    // Claude Code also keeps servers per project
    return ((root["projects"] as? [String: Any]) ?? [:]).values.contains { (($0 as? [String: Any])?["mcpServers"] as? [String: Any])?["bastion"] != nil }
}

func agentsReport() -> [[String: Any]] {
    let bin = engine("bin/bastion")
    return AGENT_DIRS.map { a in
        var out: [String: Any] = ["id": a.id, "name": a.name, "installed": fm.fileExists(atPath: a.dir), "connected": mcpConnected(a.id),
                                  "config": tilde(a.mcp), "can_connect": a.id != "claude"]
        if a.id == "claude" || a.id == "cursor" { out["hard_guard"] = hookInstalled(a.id) }
        if a.id == "claude" { out["connect_command"] = "claude mcp add --scope user bastion -- \"\(bin)\" mcp" }
        return out
    }
}

/// Adds Bastion to an agent's MCP config (a backup is kept). Claude Code rewrites its own config file, so it's connected with its CLI instead.
func connectAgent(_ id: String) throws -> [String: Any] {
    guard let a = AGENT_DIRS.first(where: { $0.id == id }) else { throw Failure("Unknown agent \(id). Try: \(AGENT_DIRS.map(\.id).joined(separator: ", ")).") }
    guard id != "claude" else { throw Failure("Claude Code keeps its MCP servers in a file it rewrites itself. Connect it with: claude mcp add --scope user bastion -- \"\(engine("bin/bastion"))\" mcp") }
    if mcpConnected(id) { return ["agent": id, "changed": false, "message": "\(a.name) is already connected."] }
    let bin = engine("bin/bastion")
    try? fm.createDirectory(atPath: (a.mcp as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
    if fm.fileExists(atPath: a.mcp) { try? fm.removeItem(atPath: a.mcp + ".bastion-backup"); try? fm.copyItem(atPath: a.mcp, toPath: a.mcp + ".bastion-backup") }
    if id == "codex" {
        let block = "\n[mcp_servers.bastion]\ncommand = \"\(bin)\"\nargs = [\"mcp\"]\n"
        let text = readText(a.mcp)
        try (text + (text.isEmpty || text.hasSuffix("\n") ? "" : "\n") + block).write(toFile: a.mcp, atomically: true, encoding: .utf8)
    } else {
        var root: [String: Any] = [:]
        if let data = fm.contents(atPath: a.mcp), !data.isEmpty {
            guard let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw Failure("\(tilde(a.mcp)) isn't valid JSON, so Bastion left it alone.")
            }
            root = parsed
        }
        var servers = root["mcpServers"] as? [String: Any] ?? [:]
        servers["bastion"] = ["command": bin, "args": ["mcp"]]
        root["mcpServers"] = servers
        try jsonText(root, pretty: true).write(toFile: a.mcp, atomically: true, encoding: .utf8)
    }
    logEvent("CHANGED: \(a.name) connected to Bastion (MCP)")
    return ["agent": id, "changed": true, "config": tilde(a.mcp), "message": "\(a.name) is connected. Restart it to load Bastion."]
}

/// husky manages git hooks through a committed .husky/pre-push; Bastion's check goes at its end (a no-op where Bastion isn't installed)
let HUSKY_MARK = "security-guard/git-guard"
func huskyRepo(_ repo: String) -> Bool { fm.fileExists(atPath: repo + "/.husky") }
func huskyGuarded(_ repo: String) -> Bool { readText(repo + "/.husky/pre-push").contains(HUSKY_MARK) }

func guardHusky(_ repo: String) throws -> [String: Any] {
    let dir = try resolveDir(repo)
    guard huskyRepo(dir) else { throw Failure("\(tilde(dir)) doesn't use husky.") }
    let name = (dir as NSString).lastPathComponent
    if huskyGuarded(dir) { return ["repo": dir, "changed": false, "message": "\(name) is already protected on push."] }
    let hook = dir + "/.husky/pre-push"
    let block = "# Bastion: refuse to push injected build configs (does nothing where Bastion isn't installed)\n" +
                "if [ -x \"$HOME/.security-guard/git-guard\" ]; then \"$HOME/.security-guard/git-guard\" \"$@\" || exit 1; fi\n"
    let body = readText(hook)
    try (body.isEmpty ? block : body + (body.hasSuffix("\n") ? "\n" : "\n\n") + block).write(toFile: hook, atomically: true, encoding: .utf8)
    chmod(hook, 0o755)
    logEvent("CHANGED: push guard added to \(name)'s .husky/pre-push")
    return ["repo": dir, "changed": true, "file": tilde(hook),
            "message": "Added Bastion's check to \(name)/.husky/pre-push. Commit that change so it stays part of the repo."]
}

/// The setup steps that make Bastion fully effective, with the action that completes each.
func nextSteps() -> [[String: Any]] {
    var steps: [[String: Any]] = []
    let agents = run("/bin/launchctl", ["list"], timeout: 10).out
    func add(_ id: String, _ title: String, _ why: String, done: Bool, action: [String]?, confirm: String? = nil, optional: Bool = false, page: String? = nil, bulk: Bool = false) {
        // bulk: safe to do together with one click (turning protections on); the rest are individual choices
        var s: [String: Any] = ["id": id, "title": title, "why": why, "done": done, "optional": optional, "bulk": bulk]
        if let action { s["action"] = action }
        if let confirm { s["confirm"] = confirm }
        if let page { s["page"] = page }
        steps.append(s)
    }
    add("watcher", "Turn on the real-time watcher", "Stops malware loaders and attacker connections within seconds.",
        done: agents.contains(WATCH_LABEL), action: ["enable", "watcher"], bulk: true)
    add("schedule", "Turn on the scheduled scan", "Scans your repos at login and every 6 hours, so new infections don't wait for you.",
        done: agents.contains(SCAN_LABEL), action: ["enable", "schedule"], bulk: true)
    add("exec_guard", "Turn on the execution guard", "npm, node, pnpm, yarn and bun refuse to start in an infected project, in any terminal.",
        done: execGuardOn(), action: ["enable", "exec-guard"], bulk: true)
    add("auto_respond", "Let Bastion contain attacks on its own", "When it finds something, it takes the proven, reversible steps right away (with undo) instead of only reporting.",
        done: autonomy() == "contain", action: ["enable", "auto-respond"])
    let repos = repoRoots()
    let plain = repos.filter { gitGuardState($0) == "unprotected" }
    add("git_guard", plain.isEmpty ? "Protect every repo on push" : "Protect \(plain.count) repo\(plain.count == 1 ? "" : "s") on push",
        "A git hook refuses to push a commit that carries the payload.", done: plain.isEmpty, action: ["enable", "git-guard"], bulk: true)
    for repo in repos where gitGuardState(repo) == "husky" {
        let name = (repo as NSString).lastPathComponent
        add("husky:" + repo, "Protect \(name) on push", "It uses husky for its git hooks, so Bastion adds its check to .husky/pre-push. You commit that change.",
            done: false, action: ["enable", "git-guard", "--husky", repo],
            confirm: "Bastion adds 2 lines to \(name)/.husky/pre-push. Commit the change so the check stays part of the repo.")
    }
    for a in agentsReport() where a["installed"] as? Bool == true {
        let id = a["id"] as? String ?? "", name = a["name"] as? String ?? ""
        if let hg = a["hard_guard"] as? Bool {
            add("guard:" + id, "Hard-guard \(name)", "Blocks the agent's install, dev, build and test commands in an unsafe repo. Enforced, not just asked.",
                done: hg, action: ["hooks", "install", id])
        }
        add("mcp:" + id, "Connect \(name) to Bastion", "The agent checks a repo with Bastion before it runs npm there, and can hand problems to Bastion.",
            done: a["connected"] as? Bool ?? false, action: a["can_connect"] as? Bool == true ? ["connect", id, "--write"] : nil,
            optional: id == "claude_desktop" || id == "windsurf", page: "agents")
    }
    add("osv", "Check dependencies against known malware", "Compares your exact package versions with osv.dev's list of malicious packages. Sends package names and versions only.",
        done: osvEnabled(), action: ["osv", "on", "--yes"], confirm: "Bastion will send package names and versions (never your code) to osv.dev.", optional: true)
    return steps
}
