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

// MARK: - Branch scanning (cached: a commit's files and a blob's verdict never change)

/// Cached verdicts are thrown away when the rules (lib.sh) or Bastion itself change.
let RULES_ID: String = {
    var h: UInt64 = 0xcbf29ce484222325
    for b in (fm.contents(atPath: engine("lib.sh")) ?? Data()) + Data(VERSION.utf8) { h ^= UInt64(b); h = h &* 0x100000001b3 }
    return String(h, radix: 16)
}()

final class ScanCache: @unchecked Sendable {
    let lock = NSLock()
    var trees: [String: [(path: String, blob: String)]] = [:]   // commit → its build configs
    var verdicts: [String: String] = [:]                         // blob → payload reasons ("" = clean)
    var dirty = false
    private let dir = engine("cache")
    private var treeFile: String { dir + "/branch-trees-\(RULES_ID).tsv" }
    private var verdictFile: String { dir + "/blob-verdicts-\(RULES_ID).tsv" }

    init() {
        for line in readText(treeFile).split(separator: "\n") {
            let p = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
            guard p.count == 3 else { continue }
            trees[p[0], default: []] += p[1].isEmpty ? [] : [(p[1], p[2])]
        }
        for line in readText(verdictFile).split(separator: "\n") {
            let p = line.split(separator: "\t", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
            if p.count == 2, !p[0].isEmpty { verdicts[p[0]] = p[1] }
        }
    }

    func verdict(_ blob: String) -> String? { lock.lock(); defer { lock.unlock() }; return verdicts[blob] }

    func save() {
        lock.lock(); defer { lock.unlock() }
        guard dirty else { return }
        try? fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
        for f in (try? fm.contentsOfDirectory(atPath: dir)) ?? [] where (f.hasPrefix("branch-trees-") || f.hasPrefix("blob-verdicts-")) && !f.contains(RULES_ID) {
            try? fm.removeItem(atPath: dir + "/" + f)   // verdicts from older rules
        }
        var t = "", v = ""
        for (c, entries) in trees { t += entries.isEmpty ? "\(c)\t\t\n" : entries.map { "\(c)\t\($0.path)\t\($0.blob)\n" }.joined() }
        for (b, r) in verdicts { v += "\(b)\t\(r)\n" }
        try? t.write(toFile: treeFile, atomically: true, encoding: .utf8)
        try? v.write(toFile: verdictFile, atomically: true, encoding: .utf8)
        dirty = false
    }
}

let SCAN_CACHE = ScanCache()

final class Collected<T>: @unchecked Sendable {
    private var items: [T?]; private let lock = NSLock()
    init(_ n: Int) { items = Array(repeating: nil, count: n) }
    func set(_ i: Int, _ v: T) { lock.lock(); items[i] = v; lock.unlock() }
    var all: [T] { items.compactMap { $0 } }
}

/// Verdicts for blobs Bastion hasn't judged before: one `git cat-file --batch` reads them all, one run of the lib.sh rule judges them all.
/// nil when the rule couldn't run, so the caller can fail closed.
func judgeBlobs(_ repo: String, _ blobs: [String]) -> [String: String]? {
    guard let bin = GIT_BIN, !blobs.isEmpty else { return [:] }
    let tmp = NSTemporaryDirectory() + "bastion-blobs-" + UUID().uuidString
    try? fm.createDirectory(atPath: tmp, withIntermediateDirectories: true)
    defer { try? fm.removeItem(atPath: tmp) }
    try? (blobs.joined(separator: "\n") + "\n").write(toFile: tmp + "/.list", atomically: true, encoding: .utf8)
    let d = runData("/bin/bash", ["-c", #"exec "$0" --no-pager -C "$1" -c core.fsmonitor=false cat-file --batch < "$2""#, bin, repo, tmp + "/.list"],
                    timeout: 120, env: GIT_ENV).data
    var i = d.startIndex
    while i < d.endIndex, let nl = d[i...].firstIndex(of: 0x0A) {   // "<sha> blob <size>\n<content>\n"
        let header = String(decoding: d[i..<nl], as: UTF8.self).split(separator: " ")
        i = d.index(after: nl)
        guard header.count == 3, header[1] == "blob", let size = Int(header[2]) else { continue }
        let end = d.index(i, offsetBy: size, limitedBy: d.endIndex) ?? d.endIndex
        fm.createFile(atPath: tmp + "/" + header[0], contents: d[i..<end])
        i = end < d.endIndex ? d.index(after: end) : end
    }
    let r = run("/bin/bash", ["-c", #". "$HOME/.security-guard/lib.sh" || exit 3; for f in "$0"/*; do [ -f "$f" ] && printf '%s\t%s\n' "${f##*/}" "$(config_reasons "$f")"; done"#, tmp], timeout: 300)
    guard r.code != 3, !r.timedOut else { return nil }
    var out: [String: String] = [:]
    for line in r.out.split(separator: "\n") {
        let p = line.split(separator: "\t", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
        if !p[0].isEmpty { out[p[0]] = p.count == 2 ? p[1] : "" }
    }
    return out
}

/// Branch tips (local and remote-tracking) whose build configs carry the payload, for many repos at once (in parallel).
/// The checked-out branch is skipped when the working copy already shows the same payload (the scan reports that file).
func branchFindings(repos: [String]) -> [(repo: String, ref: String, file: String, commit: String)] {
    guard GIT_BIN != nil, !repos.isEmpty else { return [] }
    let results = Collected<[(repo: String, ref: String, file: String, commit: String)]>(repos.count)
    DispatchQueue.concurrentPerform(iterations: repos.count) { i in results.set(i, repoBranchFindings(repos[i])) }
    SCAN_CACHE.save()
    return results.all.flatMap { $0 }
}

func branchFindings(_ repo: String) -> [(ref: String, file: String, commit: String)] {
    branchFindings(repos: [repo]).map { ($0.ref, $0.file, $0.commit) }
}

private func repoBranchFindings(_ repo: String) -> [(repo: String, ref: String, file: String, commit: String)] {
    guard fm.fileExists(atPath: repo + "/.git") else { return [] }
    let cache = SCAN_CACHE
    let current = git(repo, ["symbolic-ref", "-q", "--short", "HEAD"])?.trimmed ?? ""
    let remotes = Set((git(repo, ["remote"]) ?? "").split(separator: "\n").map(String.init))
    var tips: [(sha: String, ref: String)] = []
    for line in (git(repo, ["for-each-ref", "--format=%(objectname) %(objecttype) %(refname:short)", "refs/heads", "refs/remotes"]) ?? "").split(separator: "\n") {
        let p = line.split(separator: " ", maxSplits: 2).map(String.init)
        guard p.count == 3, p[1] == "commit", !p[2].hasSuffix("/HEAD"), !remotes.contains(p[2]) else { continue }
        tips.append((p[0], p[2]))
    }
    // commit → its build configs: cached, or one ls-tree per commit Bastion hasn't seen
    var configs: [String: [(path: String, blob: String)]] = [:]
    for sha in Set(tips.map(\.sha)) {
        cache.lock.lock(); let known = cache.trees[sha]; cache.lock.unlock()
        if let known { configs[sha] = known; continue }
        guard let data = gitData(repo, ["ls-tree", "-r", "-z", sha], timeout: 60) else { continue }
        var entries: [(path: String, blob: String)] = []
        for rec in data.split(separator: 0) {
            let s = String(decoding: rec, as: UTF8.self)
            guard let tab = s.firstIndex(of: "\t") else { continue }
            let path = String(s[s.index(after: tab)...])
            let meta = s[..<tab].split(separator: " ")
            guard meta.count == 3, meta[1] == "blob", path.has(CONFIG_NAME_RE), !path.contains("node_modules/") else { continue }
            entries.append((path, String(meta[2])))
        }
        configs[sha] = entries
        if !entries.contains(where: { $0.path.contains("\t") || $0.path.contains("\n") }) {
            cache.lock.lock(); cache.trees[sha] = entries; cache.dirty = true; cache.lock.unlock()
        }
    }
    // blob → verdict: cached, or judged in one batch
    var verdicts: [String: String] = [:]
    var unknown: [String] = []
    for blob in Set(configs.values.flatMap { $0.map(\.blob) }) {
        if let v = cache.verdict(blob) { verdicts[blob] = v } else { unknown.append(blob) }
    }
    if !unknown.isEmpty {
        if let judged = judgeBlobs(repo, unknown) {
            cache.lock.lock(); for (b, r) in judged { cache.verdicts[b] = r }; cache.dirty = true; cache.lock.unlock()
            verdicts.merge(judged) { $1 }
        } else {
            for b in unknown { verdicts[b] = "rule-unavailable" }   // fail closed, and don't cache it
        }
    }
    var out: [(repo: String, ref: String, file: String, commit: String)] = []
    for tip in tips.sorted(by: { $0.ref < $1.ref }) {
        for e in configs[tip.sha] ?? [] where !(verdicts[e.blob] ?? "").isEmpty {
            if tip.ref == current, let disk = fm.contents(atPath: repo + "/" + e.path), !payloadReasons(disk, config: true).isEmpty { continue }
            out.append((repo, tip.ref, e.path, String(tip.sha.prefix(8))))
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

// MARK: - Proof and the right fix for an infected branch (so a developer can see it for themselves)

let PAYLOAD_MARKER_RE = #"global\.[a-z]{1,2}\s*=\s*['"][0-9]+-[0-9]+['"]"#

/// Where the payload hides in a file: the line, how much blank space pushes it off-screen, where it starts, how it begins.
func hiddenCodeEvidence(_ data: Data) -> [String: Any] {
    let lines = String(decoding: data, as: UTF8.self).components(separatedBy: "\n")
    guard !lines.isEmpty else { return [:] }
    let i = lines.firstIndex { $0.range(of: PAYLOAD_MARKER_RE, options: .regularExpression) != nil }
        ?? lines.indices.max { lines[$0].count < lines[$1].count } ?? 0
    let line = lines[i]
    var out: [String: Any] = ["line": i + 1, "line_length": line.count, "lines": lines.count]
    if let pad = line.range(of: #"[ \t]{40,}"#, options: .regularExpression), pad.upperBound < line.endIndex {
        out["padding"] = line.distance(from: pad.lowerBound, to: pad.upperBound)
        out["column"] = line.distance(from: line.startIndex, to: pad.upperBound) + 1
        out["visible"] = String(line[..<pad.lowerBound]).trimmed
        out["snippet"] = String(line[pad.upperBound...].prefix(64))
    } else if let m = line.range(of: PAYLOAD_MARKER_RE, options: .regularExpression) {
        out["column"] = line.distance(from: line.startIndex, to: m.lowerBound) + 1
        out["snippet"] = String(line[m.lowerBound...].prefix(64))
    }
    return out
}

/// "Line 8 looks like “};”, but 2,000 spaces hide code off-screen — it starts at column 2003: global.o='1-183';…"
func evidenceSentence(_ ev: [String: Any]) -> String {
    guard let line = ev["line"] as? Int else { return "" }
    let snippet = (ev["snippet"] as? String).map { $0 + "…" } ?? ""
    if let pad = ev["padding"] as? Int, let col = ev["column"] as? Int {
        let visible = (ev["visible"] as? String ?? "").isEmpty ? "" : " looks like “\((ev["visible"] as? String ?? "").prefix(40))”, but"
        return "Line \(line)\(visible) \(pad.formatted()) blank characters push hidden code off-screen — it starts at column \(col.formatted()): \(snippet)"
    }
    if let col = ev["column"] as? Int { return "Line \(line), column \(col.formatted()): \(snippet)" }
    return "Line \(line) is \((ev["line_length"] as? Int ?? 0).formatted()) characters of obfuscated code."
}

func defaultBranch(_ repo: String) -> String? {
    if let r = git(repo, ["symbolic-ref", "-q", "--short", "refs/remotes/origin/HEAD"])?.trimmed, !r.isEmpty { return r }
    return ["origin/main", "origin/master", "main", "master"].first { git(repo, ["rev-parse", "-q", "--verify", $0 + "^{commit}"]) != nil }
}

func githubURL(_ repo: String) -> String? {
    guard let u = git(repo, ["remote", "get-url", "origin"])?.trimmed else { return nil }
    let s = u.replacingOccurrences(of: #"^git@github\.com:"#, with: "https://github.com/", options: .regularExpression)
        .replacingOccurrences(of: #"^https://[^@/]+@github\.com/"#, with: "https://github.com/", options: .regularExpression)
        .replacingOccurrences(of: #"\.git$"#, with: "", options: .regularExpression)
    return s.hasPrefix("https://github.com/") ? s : nil
}

private func blobClean(_ repo: String, _ spec: String) -> Bool? {   // nil = no such file there
    guard let blob = git(repo, ["rev-parse", "-q", "--verify", spec])?.trimmed, !blob.isEmpty else { return nil }
    if let v = SCAN_CACHE.verdict(blob) { return v.isEmpty }
    return gitData(repo, ["cat-file", "-p", blob]).map { payloadReasons($0, config: true).isEmpty } ?? true
}

/// Everything about one infected branch: proof, how to see it, whether the main branch is clean, and the fix that fits.
func branchContext(repo: String, ref: String, files: [String]) -> [String: Any] {
    let remotes = (git(repo, ["remote"]) ?? "").split(separator: "\n").map(String.init)
    let remote = remotes.first { ref.hasPrefix($0 + "/") }
    let branch = remote.map { String(ref.dropFirst($0.count + 1)) } ?? ref
    let current = git(repo, ["symbolic-ref", "-q", "--short", "HEAD"])?.trimmed ?? ""
    let r = shellPath(repo)
    var out: [String: Any] = ["repo": repo, "ref": ref, "branch": branch, "on_server": remote != nil, "files": files]
    var proofs: [[String: Any]] = []
    for f in files {
        var p: [String: Any] = ["file": f]
        if let data = gitData(repo, ["cat-file", "-p", "\(ref):\(f)"]) {
            let ev = hiddenCodeEvidence(data)
            p["evidence"] = ev; p["text"] = evidenceSentence(ev)
            if let line = ev["line"] as? Int, let col = ev["column"] as? Int {
                p["see_it"] = "git -C \(r) show \(ref):\(f) | sed -n \(line)p | cut -c\(col)-\(col + 80)"
            }
            if remote != nil, let gh = githubURL(repo) { p["github_url"] = "\(gh)/blob/\(branch)/\(f)" + ((ev["line"] as? Int).map { "#L\($0)" } ?? "") }
        }
        proofs.append(p)
    }
    out["proof"] = proofs
    let tip = (git(repo, ["log", "-1", "--format=%h%x1f%an%x1f%cI%x1f%s", ref])?.trimmed ?? "").components(separatedBy: "\u{1f}")
    if tip.count == 4 { out["last_commit"] = ["short": tip[0], "author": tip[1], "date": tip[2], "subject": tip[3]] }
    let def = defaultBranch(repo)
    if let def, def != ref, !(remote == nil && def.hasSuffix("/" + branch)) {
        out["default_branch"] = def
        let states = files.map { blobClean(repo, "\(def):\($0)") }
        out["default_clean"] = states.allSatisfy { $0 != false }
        out["default_has_files"] = states.contains { $0 != nil }
        out["behind_default"] = Int(git(repo, ["rev-list", "--count", "\(ref)..\(def)"])?.trimmed ?? "")
    }
    let defName = (out["default_branch"] as? String).map { $0.split(separator: "/").last.map(String.init) ?? $0 } ?? "main"
    // the fix that fits this branch
    var title = "", why = "", cmds: [String] = [], risk = "safe"
    let localExists = git(repo, ["rev-parse", "-q", "--verify", "refs/heads/\(branch)"]) != nil
    let localClean = localExists && files.allSatisfy { blobClean(repo, "refs/heads/\(branch):\($0)") != false }
    let onlyInfectedDiffer: Bool = {
        guard remote != nil, localExists else { return false }
        let changed = Set((git(repo, ["diff", "--name-only", ref, "refs/heads/\(branch)"]) ?? "").split(separator: "\n").map(String.init))
        return !changed.isEmpty && changed.isSubset(of: Set(files))
    }()
    let worktreeClean = branch == current && files.allSatisfy { f in
        fm.contents(atPath: repo + "/" + f).map { payloadReasons($0, config: true).isEmpty } ?? true }
    let upstreamIsCurrent = remote != nil && branch == current && worktreeClean
    if remote == nil && worktreeClean {
        title = "Commit the fix on \(branch)"
        why = "Your working copy is already clean — Bastion removed the injected code. \(branch) still has the infected commit until you commit the fix."
        cmds = ["git -C \(r) add -- " + files.map { "\"\($0)\"" }.joined(separator: " "), "git -C \(r) commit -m \"Remove injected code\""]
        risk = "commit"
    } else if upstreamIsCurrent, let remote {
        title = "Push the fix to \(ref)"
        why = "Commit the cleaned file on your local \(branch) first, then push it — everyone who pulls \(ref) still gets the infected version until you do."
        cmds = ["git -C \(r) push \(remote) \(branch)"]
        risk = "push"
    } else if let remote, localClean, onlyInfectedDiffer {
        title = "Push your clean copy of \(branch)"
        why = "Your local \(branch) is the same work without the injected code — it differs from the server only in the infected file\(files.count == 1 ? "" : "s"). Pushing it replaces the infected commit (rewrites \(branch)'s history on the server)."
        cmds = ["git -C \(r) push --force-with-lease=\(branch):\(git(repo, ["rev-parse", "--short=12", ref])?.trimmed ?? ref) \(remote) \(branch)"]
        risk = "rewrites-history"
    } else if remote == nil, let up = git(repo, ["rev-parse", "-q", "--abbrev-ref", "\(branch)@{upstream}"])?.trimmed, !up.isEmpty,
              files.allSatisfy({ blobClean(repo, "\(up):\($0)") != false }),
              git(repo, ["merge-base", "--is-ancestor", "refs/heads/\(branch)", up]) != nil {
        title = "Update your local \(branch) — the server copy is clean"
        why = "Your local \(branch) is just behind \(up), which no longer has the injected code. Updating it doesn't switch branches or run anything."
        let parts = up.split(separator: "/", maxSplits: 1).map(String.init)
        cmds = [branch == current ? "git -C \(r) pull --ff-only" : "git -C \(r) fetch \(parts.first ?? "origin") \(parts.count == 2 ? parts[1] : branch):\(branch)"]
    } else if let remote, out["default_clean"] as? Bool == true {
        title = "Delete the old branch \(branch) — \(defName) is clean"
        why = "\(defName) doesn't have the injected code\((out["default_has_files"] as? Bool) == false ? " (the file isn't there at all)" : ""); only this branch still carries an old copy. If you still need the branch, fix the file on it instead."
        cmds = ["git -C \(r) push \(remote) --delete \(branch)"] + (localExists && branch != current ? ["git -C \(r) branch -D \(branch)"] : [])
        risk = "deletes-branch"
    } else if remote == nil {
        title = "Delete or fix your local branch \(branch)"
        why = "It's only on this Mac. Delete it if you don't need it; otherwise switch to it (that alone runs nothing) and restore the file\(files.count == 1 ? "" : "s") from \(defName)."
        cmds = ["git -C \(r) branch -D \(branch)"]
        risk = "deletes-branch"
    } else {
        title = "Remove the injected code from \(branch)"
        why = "The code sits at the end of the line shown above, after the long run of blank space. Remove it (or restore the file from its last clean commit), then commit and push."
        cmds = ["git -C \(r) switch \(branch)   # switching runs nothing; don't run npm until it's fixed"] +
               files.map { "# edit \($0): delete everything after the long run of spaces on the line shown above" } +
               ["git -C \(r) commit -am \"Remove injected code\" && git -C \(r) push"]
        risk = "rewrites-nothing"
    }
    let button = risk == "rewrites-history" ? "Push clean copy…" : risk == "deletes-branch" ? (remote == nil ? "Delete local branch…" : "Delete branch…")
        : risk == "commit" ? "Commit fix…" : risk == "push" ? "Push fix…" : title.hasPrefix("Update") ? "Update branch" : "Fix it"
    out["fix"] = ["title": title, "why": why, "commands": cmds, "risk": risk, "button": button]
    return out
}

/// Group branch findings by (repo, ref) and add proof + fix to each.
func branchContexts(_ findings: [[String: Any]]) -> [[String: Any]] {
    var order: [String] = [], files: [String: [String]] = [:], repoOf: [String: String] = [:], refOf: [String: String] = [:]
    for f in findings {
        let repo = f["path"] as? String ?? f["repo"] as? String ?? "", ref = f["ref"] as? String ?? ""
        let key = repo + "|" + ref
        if files[key] == nil { order.append(key); repoOf[key] = repo; refOf[key] = ref }
        if let file = f["file"] as? String, !(files[key] ?? []).contains(file) { files[key, default: []].append(file) }
    }
    return order.map { branchContext(repo: repoOf[$0] ?? "", ref: refOf[$0] ?? "", files: files[$0] ?? []) }
}
