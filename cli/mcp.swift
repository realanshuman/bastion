import Foundation

// MARK: - MCP server (stdio, newline-delimited JSON-RPC 2.0)

let MCP_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]

let MCP_INSTRUCTIONS = """
Bastion guards this Mac against supply-chain malware in JavaScript/npm projects: obfuscated payloads injected into build config files (postcss, vite, next, tailwind, orval…), npm install hooks that download code, and editor tasks that run when a folder is opened.
- Before running install, dev, build, test or codegen commands in a repository for the first time in a session, or after pulling or checking out changes you did not write, call bastion_check_path on it. If safe_to_run is false, do not run those commands; show the user the findings and their remediation.
- Use bastion_status when the user asks whether their machine is safe, and bastion_scan for a full sweep.
- When a check or scan finds problems, call bastion_respond. Bastion investigates (which commit and identity planted the payload, whether it ran, what else it touched), takes only proven and reversible steps, and returns an incident report. Relay its to-do list to the user; don't redo its work.
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
     "description": "Check a project folder before running npm/pnpm/yarn/bun install, dev, build, test or codegen in it. Looks for injected build configs, malware code in source files, suspicious npm install hooks, malicious dependencies, CI workflows that leak secrets and editor auto-run tasks, and lists other branches that carry a payload. Read-only, usually a few seconds. safe_to_run=false means: do not run those commands.",
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
    ["name": "bastion_todos", "title": "What needs the user",
     "description": "Everything that needs the user right now, most urgent first: active threats, infected branches (with proof: the exact line and column where the code hides) and open incident steps. Each item has a danger level (now, dormant, leftover, check) and the fix. Fixes are the user's to run: show them, don't run git commands that change the server yourself.",
     "inputSchema": ["type": "object", "properties": [String: Any](), "additionalProperties": false], "annotations": ["readOnlyHint": true]],
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
     "inputSchema": schema(["feature": ["type": "string", "enum": ["watcher", "scheduled_scan", "exec_guard", "git_guard", "auto_respond"]] as [String: Any]], required: ["feature"]),
     "annotations": annotations("Turn on a protection", readOnly: false)],
    ["name": "bastion_respond", "title": "Respond to an attack",
     "description": "Run Bastion's responder: a fresh scan, then an investigation of every finding (which commit and identity planted it, whether it ran, which branches carry it, what else that identity touched). It contains what it can prove. It removes injected code only when the file then matches its last clean commit byte for byte (with undo), kills loaders, quarantines leftovers, blocks attacker addresses found in the payload, and returns an incident with the developer's to-do list. Respects the user's autonomy setting; plan_only=true investigates without changing anything. Can take a minute.",
     "inputSchema": schema([
        "paths": ["type": "array", "items": ["type": "string"], "description": "Project folders to respond in (default: every git repository)."] as [String: Any],
        "plan_only": ["type": "boolean", "description": "Investigate and report only; change nothing."],
     ]),
     "annotations": annotations("Respond to an attack", readOnly: false)],
    ["name": "bastion_incidents", "title": "Incidents",
     "description": "Bastion's incidents, newest first: id, status (open / contained / resolved), summary and how many to-dos are left. Read-only.",
     "inputSchema": schema(), "annotations": annotations("Incidents", readOnly: true)],
    ["name": "bastion_incident", "title": "Incident report",
     "description": "One incident in full: evidence, what Bastion did, the to-do list and the Markdown report. Defaults to the latest. Read-only.",
     "inputSchema": schema(["id": ["type": "string", "description": "Incident id, e.g. INC-20260924-203512 (default: latest)."]]),
     "annotations": annotations("Incident report", readOnly: true)],
    ["name": "bastion_deps", "title": "Check dependencies",
     "description": "Dependency guard for one project: install scripts in node_modules that fetch, decode or obfuscate code (npm-worm patterns), lockfile entries downloaded over http or from raw IPs, and (only if the user turned it on) exact versions that osv.dev lists as malicious. Read-only.",
     "inputSchema": schema(["path": ["type": "string", "description": "Absolute path of the project folder."]], required: ["path"]),
     "annotations": annotations("Check dependencies", readOnly: true)],
    ["name": "bastion_history", "title": "Hunt git history",
     "description": "Every payload a repository's git history remembers: commits on any branch, tag, stash or reflog that brought one in (with the identity), branch tips that still carry one, and commits left over from deleted branches. Read-only; can take a minute on big repos.",
     "inputSchema": schema(["path": ["type": "string", "description": "Absolute path of the git repository."]], required: ["path"]),
     "annotations": annotations("Hunt git history", readOnly: true)],
    ["name": "bastion_block_indicator", "title": "Block an attacker address",
     "description": "Add an IP address to the blocklist, only when a Bastion incident found it in malware evidence on this Mac. Local, private and allowlisted addresses are refused. The user can block anything else themselves.",
     "inputSchema": schema(["ip": ["type": "string"], "incident": ["type": "string", "description": "Incident id holding the evidence (default: any open incident)."]], required: ["ip"]),
     "annotations": annotations("Block an attacker address", readOnly: false)],
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
    case "bastion_todos": return todosReport(network: true)
    case "bastion_activity": return ["events": activity(limit: min(max(a["limit"] as? Int ?? 20, 1), 200))]
    case "bastion_quarantine":
        return ["items": quarantineItems(), "note": "Restoring is left to the user: bastion quarantine restore <id>"]
    case "bastion_lists": return listsReport()
    case "bastion_enable":
        guard let s = a["feature"] as? String, let f = Feature(s) else {
            throw Failure("`feature` must be one of: watcher, scheduled_scan, exec_guard, git_guard, auto_respond.")
        }
        return try enable(f)
    case "bastion_respond":
        let paths = (a["paths"] as? [Any])?.compactMap { $0 as? String } ?? []
        return try respond(paths: paths, planOnly: a["plan_only"] as? Bool ?? false, trigger: "agent", wait: true)
    case "bastion_incidents": return ["incidents": allIncidents().map(incidentBrief)]
    case "bastion_incident":
        let id = a["id"] as? String ?? "latest"
        guard let inc = findIncident(id) else { throw Failure("No incident \(id). bastion_incidents lists them.") }
        var out = inc
        out["report_markdown"] = reportMarkdown(inc)
        return out
    case "bastion_deps":
        guard let p = a["path"] as? String else { throw Failure("`path` is required.") }
        return try depsReport(p, online: nil, preinstall: false)
    case "bastion_history":
        guard let p = a["path"] as? String else { throw Failure("`path` is required.") }
        return try historyHunt(p)
    case "bastion_block_indicator":
        guard let ip = a["ip"] as? String else { throw Failure("`ip` is required.") }
        return try blockIndicator(ip.trimmed, incident: a["incident"] as? String)
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
