// main.swift — `bastion` command-line entry point: argument parsing, human output, dispatch.
import Foundation

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
        let br = l["infected_branches"] as? Int ?? 0
        print("  last scan           \(friendly(l["time"])) · " + (clean ? good("clean") : warn((l["result"] as? String ?? "").lowercased()))
              + (clean && br > 0 ? warn(" · \(br) infected branch\(br == 1 ? "" : "es")") + faint("   (bastion branches)") : ""))
    } else { print("  last scan           " + faint("never — run: bastion scan")) }
    let q = s["quarantine_count"] as? Int ?? 0
    print("  quarantine          " + (q == 0 ? faint("empty") : warn("\(q) item\(q == 1 ? "" : "s")")))
    let level = s["autonomy"] as? String ?? "contain"
    print("  auto-respond        " + (level == "contain" ? good("contain") : level == "observe" ? warn("observe (report only)") : faint("off")))
    if let i = s["incident"] as? [String: Any] {
        print("\n" + (i["status"] as? String == "contained" ? good("● ") : warn("● ")) + strong("incident \(i["id"] as? String ?? "")") + faint("  \(i["status"] as? String ?? "") · \(i["todos"] as? Int ?? 0) to-do(s) · bastion incident"))
        print("  " + (i["summary"] as? String ?? ""))
    }
}

func humanIncident(_ r: [String: Any]) {
    switch r["status"] as? String ?? "" {
    case "clear": print(good("✓ nothing to respond to") + faint("  — no findings and no new automatic actions")); return
    case "skipped": print(faint("skipped — \(r["reason"] as? String ?? "")")); return
    default: break
    }
    let status = r["status"] as? String ?? "open"
    let head = status == "contained" ? good("✓ contained") : status == "resolved" ? good("✓ resolved") : warn("! needs you")
    print(head + "  " + (r["summary"] as? String ?? ""))
    for a in (r["actions"] as? [[String: Any]] ?? []) where a["status"] as? String == "done" {
        print("  " + good("✓") + " " + (a["detail"] as? String ?? ""))
    }
    let todos = r["todos"] as? [[String: Any]] ?? []
    if !todos.isEmpty { print("\n" + strong("your to-dos")) }
    for (n, t) in todos.enumerated() {
        print("  \(n + 1). " + strong(t["title"] as? String ?? "") + faint(" — \(t["why"] as? String ?? "")"))
        for l in ((t["cmd"] as? String) ?? "").split(separator: "\n") { print("       " + paint(String(l), "36")) }
        for l in ((t["how"] as? String) ?? "").split(separator: "\n") { print("       " + faint(String(l))) }
    }
    let id = r["id"] as? String ?? ""
    print("\n" + faint("report: \(tilde(engine("incidents/\(id)/report.md")))   ·   bastion incident \(id)"))
}

func connectInfo() -> [String: Any] {
    let bin = fm.isExecutableFile(atPath: engine("bin/bastion")) ? engine("bin/bastion")
        : URL(fileURLWithPath: Bundle.main.executablePath ?? CommandLine.arguments[0]).resolvingSymlinksInPath().path
    let server: [String: Any] = ["command": bin, "args": ["mcp"]]
    return ["command": bin, "args": ["mcp"],
            "claude_code": "claude mcp add --scope user bastion -- \(bin.hasPrefix(HOME + "/") && !bin.contains(" ") ? "~/" + bin.dropFirst(HOME.count + 1) : "\"\(bin)\"") mcp",
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
  bastion repos                   your git repos: branch, push guard, open findings
  bastion lists                   allowlist, blocklist and ignore list
  bastion allow|block|ignore add|remove <value>
  bastion enable|disable watcher|schedule|exec-guard|git-guard|auto-respond
  bastion respond [dirs…]         investigate and contain an attack, then write an incident report
                                  (--plan: investigate only, change nothing)
  bastion incidents               incident history  ·  incident [id] shows the report  ·  incident resolve [id]
  bastion undo [id]               put back files Bastion cleaned, if it got one wrong
  bastion autonomy [level]        contain (default) · observe (report only) · off
  bastion deps [dir]              dependencies: install scripts, lockfile sources (--online: also osv.dev)
  bastion history [repo]          every payload git remembers: commits, branches, deleted branches
  bastion branches [dirs…]        payloads on branches you haven't checked out
  bastion hooks install|remove claude|cursor|all   the agent hard-guard
  bastion ci-setup [repo] [--write]   the Team PR guard GitHub Action
  bastion osv on|off              online malware check against osv.dev (sends package names + versions)
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
var trigger = "manual"
var fromLog: String? = nil
var positional: [String] = []
var skipNext = false
for (i, a) in argv.enumerated() {
    if skipNext { skipNext = false; continue }
    if a == "-n" || a == "--limit" { if i + 1 < argv.count, let n = Int(argv[i + 1]) { limit = n }; skipNext = true; continue }
    if a == "--trigger" { if i + 1 < argv.count { trigger = argv[i + 1] }; skipNext = true; continue }
    if a == "--from-log" { if i + 1 < argv.count { fromLog = argv[i + 1] }; skipNext = true; continue }
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
func confirmWeakening(_ question: String, why: String = "This lowers protection, so a person has to confirm it.") throws {
    if assumeYes { return }
    guard isatty(STDIN_FILENO) != 0 else {
        throw Failure("\(why) Run it in a terminal, or add --yes.")
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
                if let resp = r["response"] as? [String: Any] {
                    print("\n" + strong("→ ") + (resp["summary"] as? String ?? "") + ((resp["id"] as? String).map { faint("  (bastion incident \($0))") } ?? ""))
                }
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
        guard let name = rest.first, let f = Feature(name) else { throw Failure("Usage: bastion \(command) watcher|schedule|exec-guard|git-guard|auto-respond") }
        if command == "disable" { try confirmWeakening("Turn off the \(f.title)?") }
        let r = try (command == "enable" ? enable(f) : disable(f))
        output(r) { print(((r["enabled"] as? Bool ?? false) == (command == "enable") ? good("✓ ") : warn("! ")) + (r["message"] as? String ?? "")) }

    case "respond":
        if !wantJSON && !argv.contains("--quiet") {
            FileHandle.standardError.write(Data(faint("investigating — scan, git history, processes, network…\n").utf8))
        }
        let r = try respond(paths: rest, planOnly: argv.contains("--plan"), trigger: trigger, wait: trigger == "manual" || trigger == "agent", fromLog: fromLog)
        let code: Int32 = (r["status"] as? String) == "open" ? 2 : 0
        if argv.contains("--quiet") { exit(code) }
        output(r, code: code) { humanIncident(r) }

    case "repos":
        let r = reposReport()
        output(r) {
            for repo in r["repos"] as? [[String: Any]] ?? [] {
                let guardState = repo["git_guard"] as? String ?? ""
                let f = repo["findings"] as? Int ?? 0
                print((f > 0 ? bad("✗") : good("✓")) + " " + strong(repo["name"] as? String ?? "") + faint("  \(repo["branch"] as? String ?? "") · push guard: \(guardState.replacingOccurrences(of: "_", with: " ")) · \(tilde(repo["path"] as? String ?? ""))") + (f > 0 ? bad("  \(f) finding(s)") : ""))
            }
        }

    case "incidents":
        let list = allIncidents().map(incidentBrief)
        output(["incidents": list]) {
            if list.isEmpty { print(faint("No incidents yet.")) }
            for i in list {
                let st = i["status"] as? String ?? ""
                print((st == "resolved" ? faint("resolved ") : st == "contained" ? good("contained") : warn("open     ")) + "  " +
                      strong(i["id"] as? String ?? "") + faint("  \(humanTime(i["opened"]))  ") + (i["summary"] as? String ?? ""))
            }
        }

    case "incident":
        if rest.first == "resolve" {
            let r = try resolveIncident(rest.count > 1 ? rest[1] : "latest")
            output(r) { print(good("✓ resolved ") + (r["id"] as? String ?? "")) }
        }
        let id = rest.first ?? "latest"
        guard let inc = findIncident(id) else { throw Failure(id == "latest" ? "No incidents yet." : "No incident \(id). List them with `bastion incidents`.") }
        var full = inc
        full["report"] = engine("incidents/\(inc["id"] as? String ?? "")/report.md")
        output(full) { print(reportMarkdown(inc)) }

    case "undo":
        let id = rest.first ?? "latest"
        try confirmWeakening("Put back the infected version of every file Bastion cleaned in incident \(id)? Only do this if Bastion got it wrong.")
        let r = try undoIncident(id)
        notify("Files from incident \(r["id"] as? String ?? id) were put back.")
        output(r) { print(good("✓ ") + "put back \((r["undone"] as? [Any])?.count ?? 0) file(s)") }

    case "autonomy":
        let current = autonomy()
        guard let level = rest.first?.lowercased() else {
            output(["autonomy": current]) { print("auto-respond: " + strong(current) + faint("   (contain · observe · off)")) }
        }
        guard let target = AUTONOMY_LEVELS.firstIndex(of: level), let now = AUTONOMY_LEVELS.firstIndex(of: current) else {
            throw Failure("Autonomy is one of: contain (take proven, reversible steps), observe (investigate and report only), off.")
        }
        if target < now { try confirmWeakening("Lower auto-respond from \(current) to \(level)?") }
        updateSettings { $0["autonomy"] = level }
        if level != current {
            logEvent("CHANGED: auto-respond set to \(level) (bastion CLI)")
            if target < now { notify("Auto-respond was lowered to \(level).") }
        }
        output(["autonomy": level, "changed": level != current]) { print(good("✓ ") + "auto-respond: " + strong(level)) }

    case "branches":
        let list: [[String: Any]] = branchFindings(repos: (rest.isEmpty ? repoRoots() : rest).flatMap(reposUnder))
            .map { ["repo": $0.repo, "ref": $0.ref, "file": $0.file, "commit": $0.commit] }
        if argv.contains("--emit") {   // scanner lines
            for b in list { print("BRANCH|\(b["repo"] ?? "")|\(b["ref"] ?? "") \(b["file"] ?? "") \(b["commit"] ?? "")") }
            exit(0)
        }
        output(["infected_branches": list, "clean": list.isEmpty], code: list.isEmpty ? 0 : 2) {
            if list.isEmpty { print(good("✓ no payload on any branch")) }
            for b in list { print(bad("✗ ") + strong(b["ref"] as? String ?? "") + "  \(b["file"] ?? "")" + faint("  \(tilde(b["repo"] as? String ?? "")) · \(b["commit"] ?? "")")) }
        }

    case "history":
        if !wantJSON { FileHandle.standardError.write(Data(faint("searching every branch, tag, stash and deleted branch…\n").utf8)) }
        let r = try historyHunt(rest.first ?? ".")
        output(r, code: r["clean"] as? Bool == true ? 0 : 2) {
            print((r["clean"] as? Bool == true ? good("✓ ") : bad("✗ ")) + (r["summary"] as? String ?? ""))
            for e in r["introduced"] as? [[String: Any]] ?? [] {
                print("  " + bad("+") + " \(e["short"] ?? "") " + strong("\(e["file"] ?? "")") + faint("  by \(e["committer"] ?? "") <\(e["committer_email"] ?? "")> · \(humanTime(e["date"])) · in \((e["refs"] as? [String] ?? []).joined(separator: ", "))"))
            }
            for b in r["infected_branches"] as? [[String: Any]] ?? [] { print("  " + warn("⎇") + " \(b["ref"] ?? ""): \(b["file"] ?? "")") }
            for o in r["unreachable"] as? [[String: Any]] ?? [] { print("  " + faint("◌ \(o["short"] ?? "") \(o["file"] ?? "") — left over from a deleted branch")) }
            print(faint(r["note"] as? String ?? ""))
        }

    case "deps":
        if argv.contains("--emit") { depsEmit(rest).forEach { print($0) }; exit(0) }
        let r = try depsReport(rest.first ?? ".", online: argv.contains("--online") ? true : nil, preinstall: argv.contains("--preinstall"))
        let code: Int32 = (r["findings"] as? [Any] ?? []).isEmpty ? 0 : 2
        if argv.contains("--quiet") { exit(code) }
        output(r, code: code) {
            print((code == 0 ? good("✓ ") : bad("✗ ")) + (r["summary"] as? String ?? ""))
            printFindings(r["findings"] as? [[String: Any]] ?? [], under: r["path"] as? String)
            if let e = r["online_error"] as? String { print(warn("! ") + e) }
        }

    case "hook":
        runHook(rest.first ?? "claude")

    case "hooks":
        let action = rest.first ?? "status"
        let agents = rest.count > 1 && rest[1] != "all" ? [rest[1]] : ["claude", "cursor"]
        if action == "status" {
            let st: [String: Any] = ["claude": hookInstalled("claude"), "cursor": hookInstalled("cursor")]
            output(st) { for a in ["claude", "cursor"] { print("\(a == "claude" ? "Claude Code" : "Cursor")  " + ((st[a] as? Bool ?? false) ? good("guarded") : faint("not guarded"))) } }
        }
        guard ["install", "remove"].contains(action) else { throw Failure("Usage: bastion hooks install|remove|status claude|cursor|all") }
        if action == "remove" { try confirmWeakening("Remove Bastion's hard-guard from \(agents.joined(separator: " and "))?") }
        let results = try agents.map { try setHook($0, on: action == "install") }
        output(["results": results]) {
            for r in results {
                print(good("✓ ") + "\(r["agent"] as? String == "cursor" ? "Cursor" : "Claude Code"): " + ((r["installed"] as? Bool ?? false) ? "hard-guard on" : "hard-guard off") + faint((r["changed"] as? Bool ?? false) ? "  (\(tilde(r["file"] as? String ?? "")))" : "  (no change)"))
            }
        }

    case "ci-setup":
        let r = try ciSetup(rest.first ?? ".", write: argv.contains("--write"))
        output(r) {
            if r["written"] as? Bool == true { print(good("✓ ") + "added \(tilde(r["workflow"] as? String ?? ""))") }
            else if r["installed"] as? Bool == true { print(good("✓ ") + "PR guard already set up in \(tilde(r["repo"] as? String ?? ""))") }
            else { print(r["yaml"] as? String ?? "") }
            print(faint(r["next"] as? String ?? ""))
        }

    case "osv":
        let action = rest.first ?? "status"
        if action == "on" {
            try confirmWeakening("Check dependencies against osv.dev? Bastion sends package names and versions — never your code.",
                                 why: "This sends package names and versions to osv.dev, so a person has to confirm it.")
            updateSettings { $0["osv"] = true }
            logEvent("CHANGED: online malware check (osv.dev) turned ON")
        } else if action == "off" {
            updateSettings { $0["osv"] = false }
            logEvent("CHANGED: online malware check (osv.dev) turned OFF")
        }
        output(["osv": osvEnabled()]) { print("online malware check (osv.dev): " + (osvEnabled() ? good("on") : faint("off"))) }

    case "connect":
        let c = connectInfo()
        output(c) { humanConnect(c) }

    case "selftest":
        let r = selfTest()
        output(r, code: r["ok"] as? Bool ?? false ? 0 : 1) {
            let f = r["failures"] as? [String] ?? []
            print(f.isEmpty ? good("✓ detection rules pass") : bad("✗ \(f.count) rule check(s) failed:\n  ") + f.joined(separator: "\n  "))
        }

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
