// guards.swift — the dependency guard (lockfiles, node_modules, osv.dev), payloads on branches and in git history,
// the agent hard-guard hooks for Claude Code and Cursor, and the Team PR guard workflow.
import Foundation

// MARK: - Dependency guard

struct Package: Hashable { let name: String; let version: String }

/// "name@range" / "@scope/name@npm:range" → name
func packageName(fromSpec spec: String) -> String? {
    guard spec.count > 1, let at = spec.dropFirst().lastIndex(of: "@") else { return nil }
    return String(spec[..<at])
}

/// pnpm keys: "name@1.2.3", "@scope/name@1.2.3", older "name/1.2.3"
func packageVersion(fromKey key: String) -> Package? {
    if key.count > 1, let at = key.dropFirst().lastIndex(of: "@") {
        let version = String(key[key.index(after: at)...])
        if version.first?.isNumber == true { return Package(name: String(key[..<at]), version: version) }
    }
    if let slash = key.lastIndex(of: "/") {
        let name = String(key[..<slash]), version = String(key[key.index(after: slash)...])
        if version.first?.isNumber == true, !name.isEmpty { return Package(name: name, version: version) }
    }
    return nil
}

/// The packages a project pins, from whichever lockfile it has (npm, yarn classic or berry, pnpm, bun).
func lockedPackages(_ dir: String) -> (lockfile: String?, packages: Set<Package>) {
    for name in ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"] {
        let path = dir + "/" + name
        guard fm.fileExists(atPath: path) else { continue }
        let text = readText(path)
        var out = Set<Package>()
        switch name {
        case "package-lock.json", "npm-shrinkwrap.json":
            guard let obj = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { break }
            if let packages = obj["packages"] as? [String: Any] {
                for (key, value) in packages {
                    guard let r = key.range(of: "node_modules/", options: .backwards), let v = value as? [String: Any],
                          v["link"] as? Bool != true, let version = v["version"] as? String else { continue }
                    out.insert(Package(name: String(key[r.upperBound...]), version: version))
                }
            } else if let deps = obj["dependencies"] as? [String: Any] {
                var stack: [[String: Any]] = [deps]
                while let d = stack.popLast() {
                    for (n, v) in d {
                        guard let v = v as? [String: Any] else { continue }
                        if let version = v["version"] as? String, version.first?.isNumber == true { out.insert(Package(name: n, version: version)) }
                        if let sub = v["dependencies"] as? [String: Any] { stack.append(sub) }
                    }
                }
            }
        case "yarn.lock":
            var current: String?
            for line in text.components(separatedBy: "\n") {
                if !line.hasPrefix(" "), !line.hasPrefix("#"), line.hasSuffix(":") {
                    let first = line.dropLast().split(separator: ",").first.map { $0.trimmed.trimmingCharacters(in: CharacterSet(charactersIn: "\"")) } ?? ""
                    current = packageName(fromSpec: first)
                } else if let name = current, line.trimmed.hasPrefix("version") {
                    let version = line.trimmed.dropFirst("version".count).trimmingCharacters(in: CharacterSet(charactersIn: " :\""))
                    if version.first?.isNumber == true { out.insert(Package(name: name, version: version)) }
                    current = nil
                }
            }
        case "pnpm-lock.yaml":
            var inPackages = false
            for line in text.components(separatedBy: "\n") {
                if !line.hasPrefix(" ") { inPackages = line.hasPrefix("packages:") || line.hasPrefix("snapshots:"); continue }
                guard inPackages, line.hasPrefix("  "), !line.hasPrefix("   "), line.hasSuffix(":") else { continue }
                var key = line.trimmed.dropLast().trimmingCharacters(in: CharacterSet(charactersIn: "'\""))
                if key.hasPrefix("/") { key.removeFirst() }
                if let paren = key.firstIndex(of: "(") { key = String(key[..<paren]) }
                if let pkg = packageVersion(fromKey: key) { out.insert(pkg) }
            }
        default:
            if let re = try? NSRegularExpression(pattern: #""((?:@[^/"\s]+/)?[^@"\s/]+)@(\d+\.\d+\.\d+[^"\s]*)""#) {
                let ns = text as NSString
                for m in re.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
                    out.insert(Package(name: ns.substring(with: m.range(at: 1)), version: ns.substring(with: m.range(at: 2))))
                }
            }
        }
        return (path, out)
    }
    return (nil, [])
}

/// Installed packages (name + version from each node_modules package.json) — for projects without a lockfile.
func installedPackages(_ dir: String) -> Set<Package> {
    var out = Set<Package>()
    let list = run("/usr/bin/find", [dir + "/node_modules", "-maxdepth", "6", "-type", "f", "-name", "package.json"], timeout: 60).out
    for path in list.split(separator: "\n").prefix(20000) {
        guard let d = fm.contents(atPath: String(path)), d.count < 1_000_000,
              let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
              let name = o["name"] as? String, let version = o["version"] as? String else { continue }
        out.insert(Package(name: name, version: version))
    }
    return out
}

final class Holder<T>: @unchecked Sendable { var value: T; init(_ v: T) { value = v } }

func fetchSync(_ request: URLRequest) throws -> (Data, Int) {
    let done = DispatchSemaphore(value: 0)
    let result = Holder<(Data?, Int, Error?)>((nil, 0, nil))
    URLSession.shared.dataTask(with: request) { data, response, error in
        result.value = (data, (response as? HTTPURLResponse)?.statusCode ?? 0, error)
        done.signal()
    }.resume()
    done.wait()
    if let error = result.value.2 { throw Failure("osv.dev couldn't be reached: \(error.localizedDescription)") }
    return (result.value.0 ?? Data(), result.value.1)
}

/// Package versions osv.dev lists as malicious (MAL- advisories). Sends only names and versions.
func osvMalicious(_ packages: [Package]) throws -> [Package: [String]] {
    var hits: [Package: [String]] = [:]
    for start in stride(from: 0, to: packages.count, by: 1000) {
        let chunk = Array(packages[start..<min(start + 1000, packages.count)])
        let queries: [[String: Any]] = chunk.map { ["package": ["name": $0.name, "ecosystem": "npm"], "version": $0.version] }
        var request = URLRequest(url: URL(string: "https://api.osv.dev/v1/querybatch")!, timeoutInterval: 25)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: ["queries": queries])
        let (data, status) = try fetchSync(request)
        guard status == 200, let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let results = obj["results"] as? [[String: Any]] else { throw Failure("osv.dev answered with status \(status).") }
        for (i, r) in results.enumerated() where i < chunk.count {
            let ids = (r["vulns"] as? [[String: Any]] ?? []).compactMap { $0["id"] as? String }.filter { $0.hasPrefix("MAL-") }
            if !ids.isEmpty { hits[chunk[i]] = ids }
        }
    }
    return hits
}

func osvEnabled() -> Bool { settings()["osv"] as? Bool ?? false }

/// Dependency report for one project: install scripts in node_modules, lockfile sources, and (opt-in) osv.dev.
func depsReport(_ raw: String, online: Bool?, preinstall: Bool) throws -> [String: Any] {
    try requireEngine()
    let dir = try resolveDir(raw)
    let locks = "for l in package-lock.json npm-shrinkwrap.json yarn.lock pnpm-lock.yaml bun.lock; do [ -f \"$1/$l\" ] && deps_lock_scan \"$1/$l\"; done; exit 0"
    let script = #". "$HOME/.security-guard/lib.sh" || exit 3; "# + (preinstall ? "" : #"deps_modules_scan "$1"; "#) + locks
    var findings = parseFindings(run("/bin/bash", ["-c", script, "bastion", dir], timeout: 180).out)
    let (lockfile, locked) = lockedPackages(dir)
    var packages = locked
    if packages.isEmpty && !preinstall && fm.fileExists(atPath: dir + "/node_modules") { packages = installedPackages(dir) }
    let useOnline = online ?? osvEnabled()
    var out: [String: Any] = ["path": dir, "lockfile": lockfile ?? NSNull(), "packages": packages.count, "online": useOnline]
    if useOnline && !packages.isEmpty {
        do {
            for (pkg, ids) in try osvMalicious(packages.sorted { $0.name < $1.name }) {
                findings.append(makeFinding("DEPMAL", lockfile ?? dir + "/node_modules", "\(pkg.name)@\(pkg.version) \(ids.joined(separator: ","))"))
            }
            out["osv_checked"] = packages.count
        } catch let f as Failure { out["online_error"] = f.message }
    }
    out["findings"] = findings
    out["safe"] = findings.isEmpty
    out["summary"] = findings.isEmpty
        ? "\(packages.count) packages — nothing suspicious" + (useOnline ? " (checked against osv.dev)." : ". Turn on the online check to compare exact versions with osv.dev.")
        : "\(findings.count) dependency problem\(findings.count == 1 ? "" : "s") — see findings[].remediation."
    return out
}

/// Known-malicious versions for every project under the given roots, as scanner lines (only when the user opted in).
func depsEmit(_ roots: [String]) -> [String] {
    guard osvEnabled() else { return [] }
    var lines: [String] = []
    for root in roots {
        let found = run("/usr/bin/find", [root, "-maxdepth", "4", "(", "-name", "node_modules", "-o", "-name", ".git", "-o", "-name", ".next", ")", "-prune",
                                          "-o", "-type", "f", "(", "-name", "package-lock.json", "-o", "-name", "yarn.lock", "-o", "-name", "pnpm-lock.yaml",
                                          "-o", "-name", "npm-shrinkwrap.json", "-o", "-name", "bun.lock", ")", "-print"], timeout: 60).out
        for dir in Set(found.split(separator: "\n").map { (String($0) as NSString).deletingLastPathComponent }) {
            let (lockfile, packages) = lockedPackages(dir)
            guard let lockfile, !packages.isEmpty, let hits = try? osvMalicious(Array(packages)) else { continue }
            for (pkg, ids) in hits { lines.append("DEPMAL|\(lockfile)|\(pkg.name)@\(pkg.version) \(ids.joined(separator: ","))") }
        }
    }
    return lines
}

// MARK: - Payloads on branches and in history

let CONFIG_NAME_RE = #"(^|/)([^/]+\.config\.(js|mjs|cjs|ts|mts)|\.[^/]+rc\.(js|cjs|mjs))$"#

/// Git repos at or under a root
func reposUnder(_ root: String) -> [String] {
    if fm.fileExists(atPath: root + "/.git") { return [root] }
    return run("/usr/bin/find", [root, "-maxdepth", "4", "-type", "d", "-name", ".git", "-not", "-path", "*/node_modules/*", "-not", "-path", "*/Library/*"], timeout: 60).out
        .split(separator: "\n").map(String.init).filter { $0.hasSuffix("/.git") }.map { String($0.dropLast(5)) }
}

/// Branch tips (local and remote-tracking) whose build configs carry the payload.
/// The checked-out branch is skipped when the working copy already shows the same payload (the scan reports that file).
func branchFindings(_ repo: String) -> [(ref: String, file: String, commit: String)] {
    guard GIT_BIN != nil, fm.fileExists(atPath: repo + "/.git") else { return [] }
    let current = git(repo, ["symbolic-ref", "-q", "--short", "HEAD"])?.trimmed ?? ""
    let remotes = Set((git(repo, ["remote"]) ?? "").split(separator: "\n").map(String.init))
    var verdict: [String: Bool] = [:]
    var out: [(String, String, String)] = []
    for line in (git(repo, ["for-each-ref", "--format=%(objectname) %(refname:short)", "refs/heads", "refs/remotes"]) ?? "").split(separator: "\n") {
        let parts = line.split(separator: " ", maxSplits: 1).map(String.init)
        guard parts.count == 2, !parts[1].hasSuffix("/HEAD"), !remotes.contains(parts[1]) else { continue }
        let (sha, ref) = (parts[0], parts[1])
        for entry in (git(repo, ["ls-tree", "-r", sha], timeout: 60) ?? "").split(separator: "\n") {
            guard let tab = entry.firstIndex(of: "\t") else { continue }
            let path = String(entry[entry.index(after: tab)...])
            guard path.has(CONFIG_NAME_RE), !path.contains("node_modules/") else { continue }
            let meta = entry[..<tab].split(separator: " ")
            guard meta.count == 3, meta[1] == "blob" else { continue }
            let blob = String(meta[2])
            if verdict[blob] == nil { verdict[blob] = gitData(repo, ["cat-file", "-p", blob]).map { !payloadReasons($0, config: true).isEmpty } ?? false }
            guard verdict[blob] == true else { continue }
            if ref == current, let disk = fm.contents(atPath: repo + "/" + path), !payloadReasons(disk, config: true).isEmpty { continue }
            out.append((ref, path, String(sha.prefix(8))))
        }
    }
    return out
}

/// Every payload git still remembers: commits on any branch, tag, stash or reflog that brought one in or took one out,
/// branch tips carrying one, and commits left over from deleted branches.
func historyHunt(_ raw: String) throws -> [String: Any] {
    try requireEngine()
    let repo = try resolveDir(raw)
    guard fm.fileExists(atPath: repo + "/.git") else { throw Failure("\(repo) isn't a git repository.") }
    guard GIT_BIN != nil else { throw Failure("git isn't installed, so history can't be searched.") }
    let started = Date()
    let pattern = #"global\.[a-z]{1,2}[[:space:]]*=[[:space:]]*['"][0-9]+-[0-9]+['"]|_\$_[0-9a-f]{4}[[:space:]]*=[[:space:]]*\(function"#
    let log = git(repo, ["log", "--all", "--reflog", "--no-show-signature", "-E", "-G", pattern, "--name-only",
                         "--format=\u{1e}%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%cI%x1f%s", "-n", "300"], timeout: 240) ?? ""
    var events: [[String: Any]] = []
    var identities: [String: Int] = [:]
    for record in log.components(separatedBy: "\u{1e}") where !record.trimmed.isEmpty {
        let lines = record.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
        let f = lines[0].split(separator: "\u{1f}", omittingEmptySubsequences: false).map(String.init)
        guard f.count >= 7 else { continue }
        let c = Commit(sha: f[0], author: f[1], authorEmail: f[2], committer: f[3], committerEmail: f[4], date: f[5], subject: f[6])
        for file in lines.dropFirst().prefix(50) {
            let isConfig = file.has(CONFIG_NAME_RE)
            let now = gitData(repo, ["cat-file", "-p", "\(c.sha):\(file)"]).map { !payloadReasons($0, config: isConfig).isEmpty } ?? false
            let before = gitData(repo, ["cat-file", "-p", "\(c.sha)^:\(file)"]).map { !payloadReasons($0, config: isConfig).isEmpty } ?? false
            guard now != before else { continue }
            var e = c.json
            e["file"] = file
            e["change"] = now ? "added" : "removed"
            if now {
                let refs = (git(repo, ["branch", "-a", "--contains", c.sha, "--format=%(refname:short)"]) ?? "") + (git(repo, ["tag", "--contains", c.sha]) ?? "")
                e["refs"] = refs.split(separator: "\n").map(String.init).filter { !$0.isEmpty && !$0.hasSuffix("/HEAD") }
                identities["\(c.committer) <\(c.committerEmail)>", default: 0] += 1
            }
            events.append(e)
        }
    }
    // commits no branch points to any more (deleted branches, dropped stashes)
    var orphans: [[String: Any]] = []
    let fsck = git(repo, ["fsck", "--unreachable", "--no-reflogs", "--no-progress"], timeout: 180) ?? ""
    for line in fsck.split(separator: "\n") where line.hasPrefix("unreachable commit ") {
        let sha = String(line.dropFirst("unreachable commit ".count))
        for entry in (git(repo, ["ls-tree", "-r", sha]) ?? "").split(separator: "\n") {
            guard let tab = entry.firstIndex(of: "\t") else { continue }
            let path = String(entry[entry.index(after: tab)...])
            guard path.has(CONFIG_NAME_RE), let blob = entry[..<tab].split(separator: " ").last,
                  let data = gitData(repo, ["cat-file", "-p", String(blob)]), !payloadReasons(data, config: true).isEmpty else { continue }
            var o = commits(repo, ["-1", sha]).first?.json ?? ["sha": sha, "short": String(sha.prefix(8))]
            o["file"] = path
            orphans.append(o)
        }
        if orphans.count >= 50 { break }
    }
    let tips = branchFindings(repo).map { ["ref": $0.ref, "file": $0.file, "commit": $0.commit] as [String: Any] }
    let fetchHead = (try? fm.attributesOfItem(atPath: repo + "/.git/FETCH_HEAD"))?[.modificationDate] as? Date
    let added = events.filter { $0["change"] as? String == "added" }
    let clean = added.isEmpty && orphans.isEmpty && tips.isEmpty
    return ["repo": repo, "clean": clean, "introduced": added, "removed": events.filter { $0["change"] as? String == "removed" },
            "infected_branches": tips, "unreachable": orphans,
            "identities": identities.sorted { $0.value > $1.value }.map { ["identity": $0.key, "commits": $0.value] as [String: Any] },
            "last_fetch": fetchHead.map(isoTime) ?? NSNull(), "duration_ms": Int(Date().timeIntervalSince(started) * 1000),
            "summary": clean ? "No payload anywhere in this repository's history."
                : "\(added.count) commit\(added.count == 1 ? "" : "s") brought a payload in; \(tips.count) branch tip\(tips.count == 1 ? "" : "s") still carr\(tips.count == 1 ? "ies" : "y") one; \(orphans.count) left over from deleted branches.",
            "note": "Remote branches are as of your last fetch. Run git fetch --all first to see the server's current state."]
}

// MARK: - Agent hard-guard (Claude Code and Cursor hooks)

/// Directories a shell command would run package or build tooling in (after following cd and --prefix/-C/--cwd).
func projectDirsToCheck(_ command: String, cwd: String) -> [String] {
    let tools: Set<String> = ["npm", "pnpm", "yarn", "bun", "npx", "pnpx", "bunx", "next", "vite", "nuxt", "astro", "webpack",
                              "rollup", "tsx", "jest", "vitest", "turbo", "nx", "eslint", "node", "deno"]
    let quiet: Set<String> = ["-v", "--version", "-h", "--help", "help", "version", "config", "whoami", "login", "logout", "view", "info", "outdated", "ls", "list", "why"]
    var dir = cwd, dirs: [String] = []
    let segments = command.replacingOccurrences(of: "&&", with: "\n").replacingOccurrences(of: "||", with: "\n")
        .replacingOccurrences(of: ";", with: "\n").replacingOccurrences(of: "|", with: "\n").split(separator: "\n")
    for segment in segments {
        var words = segment.split(whereSeparator: { $0 == " " || $0 == "\t" }).map { String($0).trimmingCharacters(in: CharacterSet(charactersIn: "\"'()")) }
        while let first = words.first, first.contains("="), !first.hasPrefix("-") { words.removeFirst() }   // FOO=1 npm run dev
        guard let first = words.first else { continue }
        func resolve(_ p: String) -> String {
            let expanded = p == "~" ? HOME : p.hasPrefix("~/") ? HOME + p.dropFirst(1) : p
            return URL(fileURLWithPath: expanded, relativeTo: URL(fileURLWithPath: dir, isDirectory: true)).standardizedFileURL.path
        }
        if first == "cd", words.count > 1 { dir = resolve(words[1]); continue }
        let tool = (first as NSString).lastPathComponent
        guard tools.contains(tool) else { continue }
        let rest = Array(words.dropFirst())
        if let sub = rest.first(where: { !$0.hasPrefix("-") }), quiet.contains(sub) { continue }
        if rest.isEmpty && !["yarn", "bun"].contains(tool) { continue }
        var target = dir
        for (i, w) in rest.enumerated() where ["--prefix", "-C", "--cwd", "--dir"].contains(w) && i + 1 < rest.count { target = resolve(rest[i + 1]) }
        dirs.append(target)
    }
    // check the whole project, not just a subfolder
    return Array(Set(dirs.map { d -> String in
        var p = d
        while p.count > 1 {
            if fm.fileExists(atPath: p + "/.git") { return p }
            p = (p as NSString).deletingLastPathComponent
        }
        return d
    }))
}

/// A cached preflight check (one minute) so a busy agent doesn't pay for the same repo on every command.
func cachedCheck(_ dir: String) -> [String: Any]? {
    let cacheDir = engine("cache/hook"), key = cacheDir + "/" + String(dir.utf8.reduce(5381) { ($0 << 5) &+ $0 &+ UInt64($1) }, radix: 16) + ".json"
    if let attrs = try? fm.attributesOfItem(atPath: key), let m = attrs[.modificationDate] as? Date, Date().timeIntervalSince(m) < 60,
       let d = fm.contents(atPath: key), let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] { return o }
    guard let r = try? checkPath(dir) else { return nil }
    try? fm.createDirectory(atPath: cacheDir, withIntermediateDirectories: true)
    try? jsonText(r).write(toFile: key, atomically: true, encoding: .utf8)
    return r
}

/// Why a command must not run, or nil. Fails open: if Bastion can't check, the agent's normal flow continues.
func hookVerdict(command: String, cwd: String) -> String? {
    for dir in projectDirsToCheck(command, cwd: cwd) {
        guard let r = cachedCheck(dir), r["safe_to_run"] as? Bool == false else { continue }
        let problems = (r["findings"] as? [[String: Any]] ?? []).compactMap { f -> String? in
            guard let title = f["title"] as? String else { return nil }
            return "\(title) — \(tilde(f["path"] as? String ?? ""))"
        }
        return "Bastion blocked this command: \(tilde(dir)) is not safe to run.\n" + problems.prefix(5).map { "• " + $0 }.joined(separator: "\n") +
            "\nDon't run install, dev, build or test here. Tell the user, and suggest `bastion respond \(shellPath(dir))` (or the bastion_respond tool) to investigate and contain it."
    }
    return nil
}

/// The hook entry point. Claude Code: exit 2 + stderr blocks; exit 0 with no output leaves the normal flow alone.
/// Cursor: always answer with JSON — "allow" (which never skips the user's approval) or "deny" with reasons.
func runHook(_ agent: String) -> Never {
    let input = FileHandle.standardInput.readDataToEndOfFile()
    let obj = (try? JSONSerialization.jsonObject(with: input) as? [String: Any]) ?? [:]
    switch agent {
    case "cursor":
        let command = obj["command"] as? String ?? "", cwd = obj["cwd"] as? String ?? ((obj["workspace_roots"] as? [String])?.first ?? fm.currentDirectoryPath)
        if let reason = hookVerdict(command: command, cwd: cwd) {
            print(jsonText(["permission": "deny", "user_message": reason, "agent_message": reason]))
        } else { print(jsonText(["permission": "allow"])) }
        exit(0)
    default:
        guard (obj["tool_name"] as? String) == "Bash", let command = (obj["tool_input"] as? [String: Any])?["command"] as? String else { exit(0) }
        if let reason = hookVerdict(command: command, cwd: obj["cwd"] as? String ?? fm.currentDirectoryPath) {
            FileHandle.standardError.write(Data((reason + "\n").utf8))
            exit(2)
        }
        exit(0)
    }
}

func hookFile(_ agent: String) -> String { agent == "cursor" ? HOME + "/.cursor/hooks.json" : HOME + "/.claude/settings.json" }

func hookInstalled(_ agent: String) -> Bool { readText(hookFile(agent)).contains("hook \(agent)") && readText(hookFile(agent)).contains("bastion") }

/// Adds or removes Bastion's hook in the agent's own config (a backup is kept next to it).
func setHook(_ agent: String, on: Bool) throws -> [String: Any] {
    guard ["claude", "cursor"].contains(agent) else { throw Failure("Hard-guard supports claude and cursor.") }
    let path = hookFile(agent), bin = engine("bin/bastion")
    var root: [String: Any] = [:]
    if let d = fm.contents(atPath: path), !d.isEmpty {
        guard let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else {
            throw Failure("\(tilde(path)) isn't plain JSON, so Bastion won't touch it. Add the hook by hand — see the AI agents page.")
        }
        root = o
    }
    let key = agent == "cursor" ? "beforeShellExecution" : "PreToolUse"
    var hooks = root["hooks"] as? [String: Any] ?? [:]
    var entries = hooks[key] as? [[String: Any]] ?? []
    let ours: ([String: Any]) -> Bool = { jsonText($0).contains("hook \(agent)") && jsonText($0).contains("bastion") }
    let had = entries.contains(where: ours)
    entries.removeAll(where: ours)
    if on {
        entries.append(agent == "cursor"
            ? ["command": "\"\(bin)\" hook cursor", "timeout": 60]
            : ["matcher": "Bash", "hooks": [["type": "command", "command": "\"\(bin)\" hook claude", "timeout": 60] as [String: Any]]])
    }
    if on == had { return ["agent": agent, "installed": on, "changed": false, "file": path] }
    if entries.isEmpty { hooks.removeValue(forKey: key) } else { hooks[key] = entries }
    if hooks.isEmpty { root.removeValue(forKey: "hooks") } else { root["hooks"] = hooks }
    if agent == "cursor" && root["version"] == nil { root["version"] = 1 }
    try? fm.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
    if fm.fileExists(atPath: path) { try? fm.removeItem(atPath: path + ".bastion-backup"); try? fm.copyItem(atPath: path, toPath: path + ".bastion-backup") }
    try jsonText(root, pretty: true).write(toFile: path, atomically: true, encoding: .utf8)
    logEvent("CHANGED: \(agent == "cursor" ? "Cursor" : "Claude Code") hard-guard turned \(on ? "ON" : "OFF")")
    return ["agent": agent, "installed": on, "changed": true, "file": path, "backup": path + ".bastion-backup"]
}

// MARK: - Team PR guard

let PR_GUARD_WORKFLOW = """
# Bastion — fails a pull request that adds hidden malware to build configs, install hooks,
# editor tasks, dependencies or CI workflows. https://github.com/realanshuman/bastion
name: Bastion
on:
  pull_request:
  push:
    branches: [main, master]
permissions:
  contents: read
jobs:
  bastion:
    name: Supply-chain guard
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: realanshuman/bastion@v4

"""

func prGuardInstalled(_ repo: String) -> Bool {
    let dir = repo + "/.github/workflows"
    return ((try? fm.contentsOfDirectory(atPath: dir)) ?? []).contains { readText(dir + "/" + $0).contains("realanshuman/bastion") }
}

func ciSetup(_ raw: String, write: Bool) throws -> [String: Any] {
    let repo = try resolveDir(raw)
    guard fm.fileExists(atPath: repo + "/.git") else { throw Failure("\(tilde(repo)) isn't a git repository.") }
    let path = repo + "/.github/workflows/bastion.yml"
    let already = prGuardInstalled(repo)
    var written = false
    if write && !already {
        try fm.createDirectory(atPath: repo + "/.github/workflows", withIntermediateDirectories: true)
        try PR_GUARD_WORKFLOW.write(toFile: path, atomically: true, encoding: .utf8)
        written = true
        logEvent("CHANGED: PR guard workflow added to \(tilde(repo))")
    }
    return ["repo": repo, "workflow": path, "installed": already || written, "written": written, "yaml": PR_GUARD_WORKFLOW,
            "next": already || written ? "Commit and push .github/workflows/bastion.yml — every pull request is checked from then on."
                                       : "Run with --write to add .github/workflows/bastion.yml."]
}
