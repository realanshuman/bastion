// ask.swift: `bastion ask "<question>"`: a plain question in, a short plain answer out, with the next steps as buttons.
// No AI model, and nothing leaves this Mac: the question is matched to what Bastion already knows (its status, what needs
// you, your repositories, activity and incidents) and answered in its own words. The app's Ask box and the terminal get
// the same answer.
import Foundation

// MARK: - Reading the question

struct Question {
    let raw: String
    let words: [String]          // lowercased, contractions opened up, punctuation dropped
    let typed: [String]          // as typed, for anything that looks like a path
    private let spaced: String

    init(_ raw: String) {
        self.raw = raw.trimmed
        typed = raw.split(whereSeparator: \.isWhitespace).map { String($0).trimmingCharacters(in: CharacterSet(charactersIn: "?!,;\"'“”‘’")) }
        var s = raw.lowercased().replacingOccurrences(of: "’", with: "'")
        for (a, b) in [("what's", "what is"), ("whats", "what is"), ("how's", "how is"), ("it's", "it is"), ("i'm", "i am"),
                       ("isn't", "is not"), ("don't", "do not"), ("doesn't", "does not"), ("can't", "can not"), ("there's", "there is"),
                       ("that's", "that is"), ("who's", "who is"), ("where's", "where is"), ("what're", "what are")] {
            s = s.replacingOccurrences(of: #"\b"# + NSRegularExpression.escapedPattern(for: a) + #"(?![a-z'])"#, with: b, options: .regularExpression)
        }
        s = s.replacingOccurrences(of: #"[^a-z0-9~/._\-\s]"#, with: " ", options: .regularExpression)
        words = s.split(whereSeparator: \.isWhitespace).map { w -> String in
            var w = String(w)
            while let last = w.last, ".,-".contains(last) { w.removeLast() }
            return w
        }.filter { !$0.isEmpty }
        spaced = " " + words.joined(separator: " ") + " "
    }

    /// A word or phrase, matched on word boundaries: has("push guard")
    func has(_ phrase: String) -> Bool { spaced.contains(" " + phrase + " ") }
    func any(_ phrases: [String]) -> Bool { phrases.contains(where: has) }
    /// "What is…", "what does … mean", "explain…": asking for a meaning, not for an action
    var explaining: Bool {
        any(["what is", "what are", "what does", "what do", "explain", "define", "meaning", "mean", "means", "why", "how does", "how do", "tell me about", "whats"])
    }
}

private let GREETINGS: Set<String> = ["hi", "hello", "hey", "yo", "hola", "thanks", "thank", "you", "thx", "ty", "good", "morning", "evening",
                                      "afternoon", "bastion", "there", "cheers", "great", "nice", "cool", "ok", "okay"]

/// Words that never name a repository on their own
private let COMMON: Set<String> = ["the", "and", "for", "you", "your", "are", "was", "what", "why", "how", "who", "when", "where", "which", "this",
    "that", "there", "here", "with", "from", "into", "about", "does", "did", "doing", "done", "can", "could", "should", "would", "will", "have",
    "has", "had", "not", "any", "all", "every", "everything", "anything", "something", "nothing", "safe", "check", "scan", "run", "running",
    "npm", "install", "repo", "repos", "repository", "repositories", "project", "projects", "folder", "code", "please", "now", "today", "tell",
    "show", "look", "open", "need", "needs", "fix", "fixed", "clean", "cleaned", "branch", "branches", "history", "deps", "dependencies",
    "malware", "hidden", "guard", "push", "watcher", "security", "protect", "protected", "protection", "turn", "on", "off", "enable", "disable",
    "status", "happened", "incident", "incidents", "activity", "quarantine", "agent", "agents", "mine", "my", "our", "its", "it", "is", "in",
    "me", "to", "of", "a", "an", "be", "do", "i", "if", "or", "so", "up", "out", "dev", "build", "test", "tests", "main", "master", "git",
    "github", "file", "files", "config", "configs", "server", "app", "mac", "computer", "again", "right", "just", "still", "yet", "ever"]

// MARK: - Plain explanations

private let GLOSSARY: [(id: String, terms: [String], text: String)] = [
    ("hidden", ["hidden code", "hidden", "payload", "payloads", "injected", "injected config", "injected code", "padding", "invisible", "obfuscated"],
     "Hidden code is malware tucked into a normal-looking file, usually a build config like postcss.config.js or tailwind.config.js. It's pushed hundreds of spaces to the right, so you won't see it in your editor or in a code review. It runs the moment a dev server, build or test loads that file. I find it by its fingerprint, not by how the file looks."),
    ("dormant", ["dormant", "sleeping", "inactive"],
     "Dormant means the malware is on a branch you don't have checked out. Nothing runs unless someone switches to that branch and runs npm (install, dev, build or test). It's still worth cleaning up, so nobody does that by accident."),
    ("leftover", ["leftover", "leftovers", "left over", "old pointer", "pointer", "stale branch"],
     "A leftover is an old pointer on this Mac to a branch that was already deleted on GitHub. The server doesn't have the malware any more. Clearing the pointer just tidies up this Mac."),
    ("act_now", ["act now", "active threat", "active threats", "urgent"],
     "Act now means something is running, or will run as soon as npm runs in that folder: a live malware process, a connection to an attacker, or an infected file in the code you have checked out. Those always come first."),
    ("safe_to_run", ["safe to run"],
     "Safe to run means the code you have checked out has no injected configs, install hooks or auto-run tasks, so npm install, dev, build and test are fine there. Other branches can still carry malware, and I tell you when they do."),
    ("watcher", ["real-time watcher", "real time watcher", "watcher", "real time", "realtime", "real-time"],
     "The real-time watcher runs quietly in the background. It stops malware loaders and cuts connections to attacker servers within seconds, and quarantines known malicious leftovers."),
    ("schedule", ["scheduled scan", "scheduled scans", "schedule", "scheduled"],
     "The scheduled scan checks all your repositories at login and every 6 hours, so a new infection doesn't wait for you to notice."),
    ("exec_guard", ["execution guard", "exec guard", "exec-guard"],
     "The execution guard makes npm, node, pnpm, yarn and bun refuse to start inside an infected project, in any terminal, even if you forget to check first."),
    ("push_guard", ["push guard", "git guard", "git-guard", "pre-push", "pre push", "git hook", "git hooks", "husky"],
     "The push guard is a git hook. It refuses to push a commit that carries the payload, so malware can't travel from your Mac to GitHub. Repos that use husky get the same check in .husky/pre-push."),
    ("pr_guard", ["pr guard", "team pr guard", "github action", "pull request"],
     "The Team PR guard is a GitHub Action I can add to a repository. Every pull request gets checked, so teammates who don't run Bastion are covered too."),
    ("auto_respond", ["auto-respond", "auto respond", "autorespond", "contain", "containment", "observe", "autonomy"],
     "Auto-respond is how much I do on my own. Contain: I take the proven, reversible steps right away. I remove injected code (with undo), stop loaders, quarantine leftovers and block attacker addresses. Observe: I investigate and report, but change nothing. Off: I only act when you ask."),
    ("quarantine", ["quarantine", "quarantined"],
     "Quarantine is where I move known-malicious files and infected copies. Nothing is deleted. You can look at anything there, or put it back if I got it wrong."),
    ("incident", ["incident", "incidents"],
     "An incident is my report on one attack: what I found, what I already did, and what's left for you. It stays open until everything on its list is done."),
    ("proof", ["proof", "evidence"],
     "Proof is exactly where I found the hidden code: the file, the line and the column. You can see it for yourself on GitHub, or with the command I give you."),
    ("loader", ["loader", "loaders"],
     "A loader is a node process started with malware in its command line. It downloads and runs more malware. The watcher stops loaders within seconds."),
    ("c2", ["c2", "command and control", "attacker server", "attacker servers", "attacker address"],
     "A C2 (command-and-control) server is the attacker's machine the malware talks to. I cut connections to known ones, and can block new ones I find inside malware."),
    ("mcp", ["mcp", "ai agent", "ai agents", "hard-guard", "hard guard", "coding agent"],
     "Your coding agent (Claude Code, Cursor, Codex and others) can talk to me over MCP. Once connected, it checks a repository with me before it runs npm there. The hard-guard goes further: it blocks the command in an unsafe repo."),
    ("osv", ["osv", "osv.dev", "online check", "online malware check"],
     "The online malware check compares your exact package versions with osv.dev's list of malicious packages. It sends package names and versions, never your code, and stays off until you turn it on."),
    ("supply_chain", ["supply chain", "supply-chain", "supply chain attack", "malware", "attack"],
     "A supply-chain attack hides malware in code you pull in: an npm package, a teammate's branch, a build config. It runs on your Mac as soon as you install, build or start a dev server, and usually goes after passwords, keys and crypto wallets. I stop it before it runs."),
    ("bastion", ["bastion"],
     "I'm Bastion, a security agent that runs on your Mac. I keep supply-chain malware out of your code: I watch your repositories, stop malware before it runs, fix what I can prove, and tell you in plain words what's left for you."),
]

private let RELATED: [String: [String]] = [
    "hidden": ["What does dormant mean?", "What is proof?", "What needs me?"],
    "dormant": ["What is a leftover?", "What is hidden code?", "What needs me?"],
    "leftover": ["What does dormant mean?", "What needs me?", "Scan everything"],
    "act_now": ["What needs me?", "What is a loader?", "What is hidden code?"],
    "auto_respond": ["What is quarantine?", "What happened today?", "Turn on auto-respond"],
    "supply_chain": ["What is hidden code?", "Scan everything", "What can you do?"],
    "bastion": ["What can you do?", "Am I safe?", "Scan everything"],
]

private func glossaryTerm(_ q: Question) -> String? {
    GLOSSARY.first { $0.id != "bastion" && q.any($0.terms) }?.id
}

// MARK: - Small helpers

func plural(_ n: Int, _ one: String, _ many: String? = nil) -> String { "\(n) \(n == 1 ? one : (many ?? one + "s"))" }

/// "a, b and c", or "a, b or c"
func spoken(_ items: [String], or: Bool = false) -> String {
    items.count <= 1 ? items.joined() : items.dropLast().joined(separator: ", ") + (or ? " or " : " and ") + items.last!
}

/// One spelling per folder (macOS also writes /tmp as /private/tmp)
func canon(_ p: String) -> String { URL(fileURLWithPath: p).resolvingSymlinksInPath().path }

/// The git repository a folder belongs to (the folder itself counts), or nil
func repoContaining(_ dir: String) -> String? {
    var d = dir
    while d.count > 1 {
        if fm.fileExists(atPath: d + "/.git") { return d }
        d = (d as NSString).deletingLastPathComponent
    }
    return nil
}

/// The activity log's "2026-09-26 06:05:19", a scan log's "20260925-025440", or ISO 8601
func eventDate(_ any: Any?) -> Date? {
    guard let s = (any as? String)?.trimmed, !s.isEmpty else { return nil }
    if let d = parseISO(s) { return d }
    let f = DateFormatter(); f.locale = POSIX
    for format in ["yyyy-MM-dd HH:mm:ss", "yyyyMMdd-HHmmss"] { f.dateFormat = format; if let d = f.date(from: s) { return d } }
    return nil
}

/// "just now", "4 minutes ago", "yesterday", "on Sep 24"
func agoText(_ d: Date?) -> String {
    guard let d else { return "a while ago" }
    let s = Int(Date().timeIntervalSince(d))
    if s < 60 { return "just now" }
    if s < 3600 { return plural(s / 60, "minute") + " ago" }
    if s < 86400 { return plural(s / 3600, "hour") + " ago" }
    if Calendar.current.isDateInYesterday(d) { return "yesterday" }
    if s < 7 * 86400 { return plural(s / 86400, "day") + " ago" }
    let f = DateFormatter(); f.dateFormat = "MMM d"
    return "on " + f.string(from: d)
}

/// An activity line in Bastion's own words: "Scanned your repositories: all clean".
func sayEvent(_ e: [String: Any]) -> String {
    var m = (e["message"] as? String ?? "").replacingOccurrences(of: #"\s*\(/[^)]*\)\s*$"#, with: "", options: .regularExpression)
    func cap(_ s: String) -> String { s.prefix(1).uppercased() + s.dropFirst() }
    switch e["type"] as? String ?? "" {
    case "scan":
        let n = e["attention"] as? Int ?? 0, q = e["quarantined"] as? Int ?? 0
        let found = [n > 0 ? plural(n, "thing") + " to look at" : nil, q > 0 ? "\(q) quarantined" : nil].compactMap { $0 }
        return found.isEmpty ? "Scanned your repositories: all clean" : "Scanned your repositories: " + found.joined(separator: ", ")
    case "fixed":
        return "Fixed: " + m.replacingOccurrences(of: "FIXED: ", with: "")
    case "killed":
        if let r = m.range(of: #"C2 \S+"#, options: .regularExpression) { return "Cut a connection to an attacker server (\(m[r].dropFirst(3)))" }
        return m.contains("loader") ? "Stopped a malware loader" : "Stopped a malware process"
    case "quarantined":
        if let r = m.range(of: #"^QUARANTINED \[[^\]]+\]: "#, options: .regularExpression) {
            return "Quarantined " + ((String(m[r.upperBound...]) as NSString).lastPathComponent)
        }
        return cap(m)
    case "blocked":
        return cap(m.replacingOccurrences(of: #"^BLOCKED \[([^\]]+)\]: "#, with: "Blocked $1: ", options: .regularExpression))
    case "setting_changed":
        m = m.replacingOccurrences(of: "CHANGED: ", with: "")
            .replacingOccurrences(of: #"\s*\((bastion CLI|AI agent[^)]*)\)$"#, with: "", options: .regularExpression)
            .replacingOccurrences(of: " turned ON", with: " turned on").replacingOccurrences(of: " turned OFF", with: " turned off")
        return cap(m)
    case "alert":
        if let r = m.range(of: #"injected config detected → \S+"#, options: .regularExpression) {
            return "Found an injected config: " + ((String(m[r].dropFirst(28))) as NSString).lastPathComponent
        }
        if let r = m.range(of: #"C2 \S+"#, options: .regularExpression) { return "Saw a process talking to an attacker server (\(m[r].dropFirst(3)))" }
        return cap(m.replacingOccurrences(of: "ALERT: ", with: ""))
    default:
        if m.hasPrefix("INCIDENT "), m.hasSuffix(": marked resolved") {
            return "Closed incident " + m.dropFirst(9).replacingOccurrences(of: ": marked resolved", with: "")
        }
        if let r = m.range(of: #"^INCIDENT \S+ \[\w+\]: "#, options: .regularExpression) {
            return String(m[r.upperBound...]).replacingOccurrences(of: #"\s*\d+ things? for you to do\.$"#, with: "", options: .regularExpression)
        }
        if m.hasPrefix("FIX FAILED: ") { return "Couldn't fix: " + m.dropFirst(12) }
        return cap(m)
    }
}

/// A repo to use in example questions: one with something on it, else the one used most recently
func exampleRepo() -> String? {
    let roots = repoRoots()
    if let hot = liveBranchFindings().compactMap({ $0["path"] as? String }).first { return (hot as NSString).lastPathComponent }
    let visible = roots.filter { !$0.dropFirst(HOME.count).split(separator: "/").contains { $0.hasPrefix(".") } }
    func used(_ r: String) -> Date { ((try? fm.attributesOfItem(atPath: r + "/.git/index"))?[.modificationDate] as? Date) ?? .distantPast }
    return (visible.max { used($0) < used($1) } ?? roots.first).map { ($0 as NSString).lastPathComponent }
}

// MARK: - Answers

private func reply(_ intent: String, _ answer: String, tone: String = "info", points: [String] = [], actions: [[String: Any]] = [],
                   auto: [String: Any]? = nil, suggest: [String] = []) -> [String: Any] {
    var r: [String: Any] = ["intent": intent, "answer": answer, "tone": tone, "points": points, "actions": actions, "suggestions": suggest]
    if let auto { r["auto"] = auto }
    return r
}

/// A next step. `kind` is what the app does (scan · check · fix · steps · step · run · open · ask · connect · copy · present ·
/// feature_off · appearance); `command` is the same step for a terminal.
private func act(_ label: String, _ kind: String, _ extra: [String: Any] = [:], command: String? = nil) -> [String: Any] {
    var a: [String: Any] = ["label": label, "kind": kind]
    for (k, v) in extra { a[k] = v }
    if let command { a["command"] = command }
    return a
}

private func fixAction(_ item: [String: Any]) -> [String: Any] {
    let fix = item["fix"] as? [String: Any] ?? [:]
    let risk = fix["risk"] as? String ?? "safe", id = item["id"] as? String ?? ""
    return act(fix["button"] as? String ?? "Fix it", "fix", ["id": id, "risk": risk, "title": fix["title"] ?? ""],
               command: "bastion fix \(id)" + (risk == "safe" ? "" : " --yes"))
}

private func dangerWord(_ item: [String: Any]) -> String {
    switch item["danger"] as? String ?? "" {
    case "now": return "Act now"
    case "dormant": return "Dormant"
    case "leftover": return "Leftover"
    default: return "To check"
    }
}

/// "Turn on 3 protections": every open step that's safe to do together
private func bulkAction(_ steps: [[String: Any]]) -> [[String: Any]] {
    let bulk = steps.filter { $0["done"] as? Bool != true && $0["bulk"] as? Bool == true }
    guard !bulk.isEmpty else { return [] }
    return [act("Turn on \(plural(bulk.count, "protection"))", "steps", command: "bastion ask \"turn on protection\"")]
}

func askBastion(_ raw: String) -> [String: Any] {
    let q = Question(raw)
    var r = route(q)
    r["question"] = q.raw
    if (r["suggestions"] as? [String] ?? []).isEmpty { r["suggestions"] = suggestions(except: r["intent"] as? String ?? "") }
    return r
}

private func suggestions(except intent: String) -> [String] {
    var all: [(String, String)] = [("needs", "What needs me?"), ("scan", "Scan everything")]
    if let repo = exampleRepo() { all.append(("check", "Is \(repo) safe?")) }
    all += [("activity", "What happened today?"), ("turn_on", "Turn on protection"), ("help", "What can you do?")]
    return all.filter { $0.0 != intent }.prefix(4).map(\.1)
}

private func route(_ q: Question) -> [String: Any] {
    if q.words.isEmpty { return answerStatus() }
    if q.words.allSatisfy(GREETINGS.contains) { return answerGreeting() }
    if q.any(["help", "what can you do", "what do you do", "how do i use", "commands", "what can i ask", "how do you work", "how does this work"]) || q.raw == "?" {
        return answerHelp()
    }
    if let mode = appearanceMode(q) {
        return reply("appearance", mode == "system" ? "Done. I'll match your Mac's appearance." : "Done. Switched to \(mode) mode.", tone: "good",
                     auto: ["kind": "appearance", "value": mode], suggest: ["What needs me?", "Am I safe?"])
    }
    if let r = answerToggle(q) { return r }
    if q.any(["who are you", "what are you", "what is bastion", "about bastion", "about you", "what does bastion do", "what do you do"]) {
        return explain("bastion")
    }
    let named = mentionedRepo(q, partial: false)
    if let path = named.path { return answerRepo(q, path) }
    if !named.choices.isEmpty { return answerWhich(named.choices) }
    if q.any(["am i safe", "am i protected", "are we safe", "are we good", "is my mac safe", "is everything ok", "is everything okay",
              "is everything safe", "how are things", "how is it going", "status"]) { return answerStatus() }
    if isScanAll(q) { return answerScan(full: q.any(["full", "home folder", "whole mac", "entire mac", "whole computer", "everything on my mac"])) }
    if q.explaining, let term = glossaryTerm(q) { return explain(term) }
    if q.any(["needs me", "need me", "needs you", "needs attention", "to do", "todo", "todos", "to-do", "to-dos", "what should i do", "what do i do",
              "what do i need", "what now", "next step", "next steps", "what is left", "anything left", "left to do", "fix", "fix it", "fix everything",
              "fix all", "clean up", "cleanup", "problems", "problem", "issues", "issue", "wrong", "attention", "pending"]) { return answerNeeds() }
    if q.any(["what happened", "happened", "what did you do", "what have you done", "what did you find", "what have you found", "did you find",
              "recent", "recently", "lately", "today", "yesterday", "this week", "activity", "log", "logs", "history", "incident", "incidents",
              "last scan", "report", "summary", "news", "updates", "what changed", "changes"]) { return answerActivity() }
    if q.any(["quarantine", "quarantined", "locked away", "locked up"]) { return answerQuarantine() }
    if let r = answerAgents(q) { return r }
    let loose = mentionedRepo(q, partial: true)
    let checkish = q.any(["check", "safe", "scan", "run", "npm", "install", "audit", "inspect", "look at", "look into", "is", "can i",
                          "history", "deps", "dependencies", "packages", "branch", "branches", "clean", "infected"])
    if checkish, let path = loose.path { return answerRepo(q, path) }
    if checkish, !loose.choices.isEmpty { return answerWhich(loose.choices) }
    if let term = glossaryTerm(q) { return explain(term) }
    if q.any(["safe", "protected", "secure", "ok", "okay", "good", "fine", "how are", "how is", "am i", "are we", "anything", "infected",
              "virus", "hacked", "compromised", "risk", "at risk", "clean", "health", "healthy", "state"]) { return answerStatus() }
    if let path = loose.path { return answerRepo(q, path) }
    if !loose.choices.isEmpty { return answerWhich(loose.choices) }
    return reply("unknown", "I'm not sure what you mean by “\(q.raw)”.",
                 points: ["I can check a repository, scan everything, tell you what needs you, explain anything I've said, or turn on protection."])
}

// MARK: Status

private func answerStatus() -> [String: Any] {
    let s = statusReport(includeRepos: true)
    let n = s["needs_you"] as? Int ?? 0, threats = (s["active_threats"] as? [Any])?.count ?? 0
    let g = s["git_guard"] as? [String: Any] ?? [:], p = s["protection"] as? [String: Any] ?? [:]
    let head: String, tone: String
    switch s["state"] as? String ?? "all_clear" {
    case "act_now": head = "Act now: \(plural(max(threats, 1), "active threat")). Don't run npm in the affected project until it's handled."; tone = "bad"
    case "clean_up": head = "\(plural(n, "thing")) need\(n == 1 ? "s" : "") you, but nothing is running."; tone = "warn"
    default: head = "You're protected. Nothing needs you."; tone = "good"
    }
    let repos = g["repos"] as? Int ?? 0, guarded = g["protected"] as? Int ?? 0
    var points = ["I'm watching \(plural(repos, "repository", "repositories")); \(guarded) \(guarded == 1 ? "is" : "are") protected on push."]
    let switches = [("real-time watcher", p["watcher"]), ("scheduled scan", p["scheduled_scan"]), ("execution guard", p["exec_guard"])]
    let on = switches.filter { $0.1 as? Bool == true }.map(\.0), off = switches.filter { $0.1 as? Bool != true }.map(\.0)
    points.append(off.isEmpty ? "The real-time watcher, scheduled scan and execution guard are all on."
                  : on.isEmpty ? "The \(spoken(off)) are off."
                  : "The \(spoken(on)) \(on.count == 1 ? "is" : "are") on; the \(spoken(off)) \(off.count == 1 ? "is" : "are") off.")
    if let ls = s["last_scan"] as? [String: Any] {
        points.append("Last scan \(agoText(parseISO(ls["time"]))): \(ls["clean"] as? Bool == true ? "clean" : "it found things to look at").")
    } else { points.append("I haven't scanned yet.") }
    switch s["autonomy"] as? String ?? "contain" {
    case "contain": points.append("Auto-respond is on: I contain proven threats on my own, with undo.")
    case "observe": points.append("Auto-respond is set to observe: I investigate and report, but don't change anything.")
    default: points.append("Auto-respond is off: I only act when you ask.")
    }
    var actions: [[String: Any]] = []
    if n > 0 { actions.append(act("See what needs you", "open", ["page": "needs"], command: "bastion todos")) }
    actions += bulkAction(nextSteps())
    actions.append(act("Scan now", "scan", command: "bastion scan"))
    return reply("status", head, tone: tone, points: points, actions: actions,
                 suggest: n > 0 ? ["What needs me?", "What does dormant mean?", "What happened today?"] : [])
}

private func answerGreeting() -> [String: Any] {
    let items = needsYou(detail: false)
    let state = overallState(items)
    let head = state == "act_now" ? "Hi. Something needs you right now: malware can run on this Mac."
        : state == "clean_up" ? "Hi! \(plural(items.count, "thing")) need\(items.count == 1 ? "s" : "") you, but nothing is running."
        : "Hi! All clear, nothing needs you. What can I do for you?"
    return reply("greeting", head, tone: state == "act_now" ? "bad" : state == "clean_up" ? "warn" : "good",
                 actions: items.isEmpty ? [] : [act("See what needs you", "open", ["page": "needs"], command: "bastion todos")])
}

private func answerHelp() -> [String: Any] {
    let repo = exampleRepo() ?? "my-app"
    return reply("help", "I'm Bastion. I keep supply-chain malware out of your code. Ask me anything in your own words.", points: [
        "“Is \(repo) safe?” I check one repository in a couple of seconds.",
        "“Scan everything.” I check every repository on this Mac.",
        "“What needs me?” What's left for you, each with a one-click fix.",
        "“What happened today?” What I found and what I did about it.",
        "“What does dormant mean?” A plain explanation of anything I say.",
        "“Turn on protection.” I switch on every protection that's off.",
    ], suggest: ["What needs me?", "Is \(repo) safe?", "What happened today?"])
}

private func explain(_ id: String) -> [String: Any] {
    let entry = GLOSSARY.first { $0.id == id }
    var actions: [[String: Any]] = []
    switch id {
    case "watcher", "schedule", "exec_guard", "push_guard":
        let feature: Feature = id == "watcher" ? .watcher : id == "schedule" ? .schedule : id == "exec_guard" ? .execGuard : .gitGuard
        if !featureOn(feature) {
            actions.append(act("Turn on the \(feature.title)", "run", ["args": ["enable", cliName(feature)]], command: "bastion enable \(cliName(feature))"))
        }
    case "auto_respond":
        if autonomy() != "contain" { actions.append(act("Turn on auto-respond", "run", ["args": ["enable", "auto-respond"]], command: "bastion enable auto-respond")) }
    case "mcp": actions.append(act("Connect your agent", "open", ["page": "agents"], command: "bastion connect"))
    case "quarantine": actions.append(act("Open quarantine", "open", ["page": "quarantine"], command: "bastion quarantine"))
    default: break
    }
    return reply("explain", entry?.text ?? "", actions: actions, suggest: RELATED[id] ?? ["What needs me?", "Am I safe?", "What can you do?"])
}

// MARK: Protection on and off

private let FEATURE_WORDS: [(Feature, [String])] = [
    (.watcher, ["watcher", "real time", "realtime", "real-time", "real time watcher"]),
    (.schedule, ["scheduled scan", "scheduled scans", "schedule", "scheduled", "scan schedule"]),
    (.execGuard, ["execution guard", "exec guard", "exec-guard"]),
    (.gitGuard, ["push guard", "git guard", "git-guard", "pre-push", "pre push", "git hook", "git hooks"]),
    (.autoRespond, ["auto-respond", "auto respond", "autorespond", "auto response", "contain mode", "containment"]),
]

private func cliName(_ f: Feature) -> String {
    switch f {
    case .watcher: return "watcher"
    case .schedule: return "schedule"
    case .execGuard: return "exec-guard"
    case .gitGuard: return "git-guard"
    case .autoRespond: return "auto-respond"
    }
}

private func featureOn(_ f: Feature) -> Bool {
    switch f {
    case .watcher: return agentLoaded(WATCH_LABEL)
    case .schedule: return agentLoaded(SCAN_LABEL)
    case .execGuard: return execGuardOn()
    case .gitGuard: return !repoRoots().contains { gitGuardState($0) == "unprotected" }
    case .autoRespond: return autonomy() == "contain"
    }
}

private func appearanceMode(_ q: Question) -> String? {
    if q.any(["dark mode", "dark theme", "night mode", "go dark", "switch to dark", "use dark", "dark appearance"]) { return "dark" }
    if q.any(["light mode", "light theme", "day mode", "go light", "switch to light", "use light", "light appearance"]) { return "light" }
    if q.any(["system theme", "system appearance", "match system", "follow system", "match my mac", "automatic theme", "auto theme"]) { return "system" }
    return nil
}

/// "Turn on the watcher" does it: protection only ever goes up without a question. "Turn off…" hands the switch back to you.
private func answerToggle(_ q: Question) -> [String: Any]? {
    let off = q.any(["turn off", "switch off", "disable", "deactivate", "pause"])
    let on = !off && q.any(["turn on", "switch on", "enable", "activate", "start", "set up", "setup", "protect me", "protect my", "protect everything", "protect all"])
    guard on || off else { return nil }
    let named = FEATURE_WORDS.filter { q.any($0.1) }.map(\.0)
    if off {
        guard let f = named.first else { return nil }
        guard featureOn(f) else { return reply("turn_off", "The \(f.title) is already off.") }
        guard f != .gitGuard else {
            return reply("turn_off", "The push guard lives in each repo's .git/hooks/pre-push. Delete that file in a repo to drop it there.", tone: "info")
        }
        return reply("turn_off", "Turning protection off stays with you.", points: ["Use the button if you're sure. I'll ask you to confirm first, and I'll log the change."],
                     actions: [act("Turn off the \(f.title)", "feature_off", ["feature": f.rawValue, "title": f.title], command: "bastion disable \(cliName(f))")])
    }
    if !named.isEmpty {
        var said: [String] = []
        for f in named {
            let r = (try? enable(f)) ?? ["message": "Couldn't turn on the \(f.title)."]
            said.append(r["message"] as? String ?? "")
        }
        return reply("turn_on", said.count == 1 ? said[0] : "Done.", tone: "good", points: said.count == 1 ? [] : said,
                     suggest: ["Am I safe?", "What needs me?", "Turn on protection"])
    }
    guard !q.any(["cursor", "claude", "codex", "windsurf", "agent", "agents", "mcp"]),
          q.any(["everything", "all", "protection", "protections", "all protections", "protect me", "protect my", "protect everything",
                 "protect all", "set up", "setup", "bastion"]) else { return nil }
    let steps = nextSteps()
    let bulk = steps.filter { $0["done"] as? Bool != true && $0["bulk"] as? Bool == true }
    var turned: [String] = []
    for s in bulk {
        guard let a = s["action"] as? [String], a.count >= 2, a[0] == "enable", let f = Feature(a[1]),
              let r = try? enable(f), r["enabled"] as? Bool == true else { continue }
        turned.append(f == .gitGuard ? "the push guard" : "the \(f.title)")
    }
    let rest = nextSteps().filter { $0["done"] as? Bool != true && $0["optional"] as? Bool != true }
    var actions: [[String: Any]] = []
    for s in rest.prefix(3) {
        let id = s["id"] as? String ?? "", title = s["title"] as? String ?? ""
        if s["page"] as? String == "agents" && s["action"] == nil { actions.append(act(title, "open", ["page": "agents"], command: "bastion connect")) }
        else { actions.append(act(title, "step", ["id": id], command: "bastion " + ((s["action"] as? [String]) ?? []).joined(separator: " "))) }
    }
    let head = turned.isEmpty ? (rest.isEmpty ? "Everything is already on." : "Everything I can turn on in one go is already on.")
        : "Done. I turned on \(spoken(turned))."
    return reply("turn_on", head, tone: "good",
                 points: rest.isEmpty ? [] : ["\(plural(rest.count, "step")) left that need\(rest.count == 1 ? "s" : "") your say, because each changes something you might want to review first."],
                 actions: actions, suggest: ["Am I safe?", "What needs me?", "What is the push guard?"])
}

// MARK: Repositories

/// A repository the question names: a path, "this"/"here" (the folder you're in), a repo's name, or loosely a unique part of one.
private func mentionedRepo(_ q: Question, partial: Bool) -> (path: String?, choices: [String]) {
    for t in q.typed where t.hasPrefix("~/") || t.hasPrefix("/") {
        if let d = try? resolveDir(t) { return (repoContaining(d) ?? d, []) }
    }
    let roots = repoRoots()
    let cwd = fm.currentDirectoryPath
    if q.any(["this", "here", "this repo", "this folder", "this project", "current folder"]), cwd != "/", cwd != HOME,
       let r = roots.filter({ cwd == $0 || cwd.hasPrefix($0 + "/") }).max(by: { $0.count < $1.count }) { return (r, []) }
    let named = roots.map { ($0, ($0 as NSString).lastPathComponent.lowercased()) }
    let exact = named.filter { n in
        q.has(n.1) || q.has(n.1.trimmingCharacters(in: CharacterSet(charactersIn: "."))) ||
            (n.1.contains("-") || n.1.contains("_")) && q.has(n.1.replacingOccurrences(of: #"[-_.]+"#, with: " ", options: .regularExpression).trimmed)
    }
    if exact.count == 1 { return (exact[0].0, []) }
    if exact.count > 1 {   // "my app" names both my-app and app: take the longer name when it contains the others, else ask
        let best = exact.max { $0.1.count < $1.1.count }!
        let unique = exact.filter { $0.1 == best.1 }.count == 1 && exact.allSatisfy { best.1.contains($0.1) }
        return unique ? (best.0, []) : (nil, exact.map(\.0))
    }
    guard partial else { return (nil, []) }
    let words = Set(q.words.filter { $0.count >= 3 && !COMMON.contains($0) })
    guard !words.isEmpty else { return (nil, []) }
    let loose = named.filter { n in
        let parts = Set(n.1.split(whereSeparator: { "-_. ".contains($0) }).map(String.init))
        return !words.isDisjoint(with: parts) || words.contains { $0.count >= 5 && n.1.contains($0) }
    }
    if loose.count == 1 { return (loose[0].0, []) }
    return (nil, loose.count <= 6 ? loose.map(\.0) : [])
}

private func answerWhich(_ choices: [String]) -> [String: Any] {
    reply("which", "Which one do you mean?", points: choices.map(tilde),
          actions: choices.prefix(4).map { act(($0 as NSString).lastPathComponent, "ask", ["question": "is \(tilde($0)) safe?"]) })
}

private func answerRepo(_ q: Question, _ path: String) -> [String: Any] {
    let name = (path as NSString).lastPathComponent
    if q.any(["history", "hunt", "who added", "who planted", "who put", "planted", "when was", "git log", "commits", "commit"]) {
        var r = reply("history", "Searching every branch, tag, stash and deleted branch of \(name) for malware…",
                      auto: ["kind": "present", "title": "History · \(name)", "args": ["history", path]],
                      suggest: ["Is \(name) safe?", "Check \(name)'s dependencies", "What needs me?"])
        r["repo"] = path
        return r
    }
    if q.any(["dependencies", "dependency", "deps", "packages", "package", "node_modules", "lockfile", "npm packages"]) {
        var r = reply("deps", "Checking \(name)'s dependencies: install scripts, and where each package comes from…",
                      auto: ["kind": "present", "title": "Dependencies · \(name)", "args": ["deps", path]],
                      suggest: ["Is \(name) safe?", "Hunt git history in \(name)", "What needs me?"])
        r["repo"] = path
        return r
    }
    return answerCheck(path)
}

func answerCheck(_ path: String) -> [String: Any] {
    let name = (path as NSString).lastPathComponent
    guard let r = try? checkPath(path) else { return reply("check", "I couldn't check \(tilde(path)).", tone: "warn") }
    let on = (r["current_branch"] as? String).map { " on \($0)" } ?? ""
    let findings = r["findings"] as? [[String: Any]] ?? []
    let refs = r["infected_branch_refs"] as? [String] ?? []
    let machine = r["machine_threats"] as? [[String: Any]] ?? []
    let items = needsYou().filter { canon($0["repo"] as? String ?? "") == canon(path) }
    let secs = String(format: "%.1f", Double(r["duration_ms"] as? Int ?? 0) / 1000)
    var points: [String] = [], actions: [[String: Any]] = [], head: String, tone: String
    if !findings.isEmpty {
        head = "Don't run npm in \(name) yet. It has \(plural(findings.count, "problem"))."; tone = "bad"
        for f in findings.prefix(4) { points.append("\(f["title"] as? String ?? "Problem"): \(shortPath(f["path"] as? String ?? "", under: path))") }
        points.append("Install, dev, build and test would run the malware here. Everything else on your Mac is unaffected.")
        for i in items where (i["fix"] as? [String: Any])?["runnable"] as? Bool == true { actions.append(fixAction(i)); break }
        actions.append(act("See the proof", "open", ["page": "needs"], command: "bastion todos"))
    } else if !refs.isEmpty {
        head = "\(name) is safe to run\(on), but \(refs.count == 1 ? "one other branch carries" : "\(refs.count) other branches carry") malware."; tone = "warn"
        points.append("Don't check out or merge \(spoken(refs, or: true)).")
        let details = r["branch_details"] as? [[String: Any]] ?? []
        if let d = details.first(where: { $0["default_clean"] as? Bool == true })?["default_branch"] as? String {
            points.append("\(d) is clean. Only \(refs.count == 1 ? refs[0] + " carries" : "these branches carry") it.")
        }
        var proofs = Set<String>()   // the same file on two branches is one proof
        for p in details.flatMap({ $0["proof"] as? [[String: Any]] ?? [] }) where proofs.count < 2 {
            let line = "Proof: \(p["file"] as? String ?? ""): \(p["text"] as? String ?? "")"
            if proofs.insert(line).inserted { points.append(line) }
        }
        for i in items where (i["fix"] as? [String: Any])?["runnable"] as? Bool == true { actions.append(fixAction(i)); if actions.count == 2 { break } }
        actions.append(act("See the proof", "open", ["page": "needs"], command: "bastion branches \(shellPath(path))"))
    } else {
        head = "\(name) is safe to run\(on)."; tone = "good"
        points.append("I checked build configs, source files, npm install hooks, editor auto-run tasks, CI workflows, other branches and dependencies in \(secs)s. Nothing suspicious.")
        if gitGuardState(path) == "unprotected" {
            points.append("It isn't protected on push yet.")
            actions.append(act("Protect it on push", "run", ["args": ["enable", "git-guard"]], command: "bastion enable git-guard"))
        }
        actions.append(act("Hunt git history", "present", ["title": "History · \(name)", "args": ["history", path]], command: "bastion history \(shellPath(path))"))
    }
    if !machine.isEmpty {
        points.append("This Mac itself shows signs of infection. Scan everything next.")
        actions.insert(act("Scan everything", "scan", command: "bastion scan"), at: 0)
    }
    let offered = Set(actions.compactMap { $0["kind"] as? String })
    var out = reply("check", head, tone: tone, points: points, actions: Array(actions.prefix(3)),
                    suggest: (offered.contains("present") ? [] : ["Hunt git history in \(name)"]) + ["Check \(name)'s dependencies", "What needs me?", "Scan everything"])
    out["repo"] = path
    return out
}

// MARK: Scanning, to-dos, activity

private func isScanAll(_ q: Question) -> Bool {
    q.any(["scan", "rescan", "re-scan", "sweep", "scan now", "scan again", "check again", "run a scan", "full scan"])
        || q.any(["check", "look at", "look through", "go through"]) && q.any(["everything", "all", "all repos", "every repo", "all my repos", "my repos",
                                                                               "my code", "all repositories", "my repositories", "every repository", "my projects", "all projects"])
}

private func answerScan(full: Bool) -> [String: Any] {
    let n = repoRoots().count
    return reply("scan", full ? "Scanning your whole home folder now. This can take a few minutes." : "Scanning your \(plural(n, "repository", "repositories")) now…",
                 auto: ["kind": "scan", "full": full], suggest: ["What needs me?", "What happened today?"])
}

private func answerNeeds() -> [String: Any] {
    let items = needsYou()
    guard !items.isEmpty else {
        let open = nextSteps().filter { $0["optional"] as? Bool != true }
        let left = open.filter { $0["done"] as? Bool != true }
        return reply("needs", "Nothing needs you right now.", tone: "good",
                     points: left.isEmpty ? ["Every protection I offer is on."]
                        : ["\(open.count - left.count) of \(open.count) protections \(open.count - left.count == 1 ? "is" : "are") on. Turning on the rest takes one click."],
                     actions: bulkAction(left), suggest: ["Scan everything", "What happened today?", "Am I safe?"])
    }
    let now = items.filter { $0["danger"] as? String == "now" }
    let head = now.isEmpty ? "\(plural(items.count, "thing")) need\(items.count == 1 ? "s" : "") you. Nothing is running."
        : "Act now: \(plural(now.count, "active threat"))." + (now.count < items.count ? " Then \(items.count - now.count) more." : "")
    let points = items.prefix(5).map { i in "\(dangerWord(i)): \(i["title"] as? String ?? "")" + ((i["repo_name"] as? String).map { " in \($0)" } ?? "") }
    var actions: [[String: Any]] = []
    for i in items where (i["fix"] as? [String: Any])?["runnable"] as? Bool == true { actions.append(fixAction(i)); if actions.count == 2 { break } }
    actions.append(act("See every detail", "open", ["page": "needs"], command: "bastion todos"))
    let kinds = Set(items.compactMap { $0["danger"] as? String })
    return reply("needs", head, tone: now.isEmpty ? "warn" : "bad", points: points + (items.count > 5 ? ["…and \(items.count - 5) more."] : []), actions: actions,
                 suggest: (kinds.contains("dormant") ? ["What does dormant mean?"] : kinds.contains("leftover") ? ["What is a leftover?"] : ["What is hidden code?"])
                    + ["What happened today?", "Scan everything"])
}

private func answerActivity() -> [String: Any] {
    let events = activity(limit: 40)
    let recent = events.filter { eventDate($0["time"]).map { Date().timeIntervalSince($0) < 86400 } ?? false }
    let shown = recent.isEmpty ? Array(events.prefix(3)) : Array(recent.prefix(6))
    var points = shown.map { "\($0["said"] as? String ?? sayEvent($0)) · \(agoText(eventDate($0["time"])))" }
    if let last = scanLogPaths().last.map(parseScanLog), !shown.contains(where: { $0["type"] as? String == "scan" }) {
        points.insert("Last scan \(agoText(parseISO(last["time"]))): \(last["clean"] as? Bool == true ? "all clean" : "it found things to look at")", at: 0)
    }
    var head = events.isEmpty ? "Nothing has happened yet. All quiet."
        : recent.isEmpty ? "Quiet lately. The last thing happened \(agoText(eventDate(events.first?["time"])))." : "Here's the last 24 hours."
    var actions: [[String: Any]] = []
    if let inc = allIncidents().first {
        let b = incidentBrief(inc), id = b["id"] as? String ?? ""
        if b["status"] as? String != "resolved" {
            head += " Incident \(id) is still open."
            actions.append(act("Open the incident", "open", ["page": "incident", "id": id], command: "bastion incident \(id)"))
        } else if recent.contains(where: { $0["incident"] as? String == id }) {
            actions.append(act("Open the incident report", "open", ["page": "incident", "id": id], command: "bastion incident \(id)"))
        }
    }
    actions.append(act("All activity", "open", ["page": "activity"], command: "bastion activity"))
    return reply("activity", head, points: points, actions: actions, suggest: ["What needs me?", "Scan everything", "Am I safe?"])
}

private func answerQuarantine() -> [String: Any] {
    let items = quarantineItems()
    guard !items.isEmpty else {
        return reply("quarantine", "Nothing is in quarantine.", tone: "good", points: ["When I find known-malicious leftovers, I move them there. I never delete them."])
    }
    return reply("quarantine", "\(plural(items.count, "item")) in quarantine. Nothing was deleted.",
                 points: items.prefix(4).map { "\(tilde($0["original_path"] as? String ?? $0["stored_at"] as? String ?? "")) · \(($0["reason"] as? String ?? "").replacingOccurrences(of: "_", with: " "))" },
                 actions: [act("Open quarantine", "open", ["page": "quarantine"], command: "bastion quarantine")])
}

private func answerAgents(_ q: Question) -> [String: Any]? {
    guard q.any(["agent", "agents", "ai agent", "mcp", "claude", "claude code", "claude desktop", "cursor", "codex", "windsurf", "connect", "connected"]) else { return nil }
    let all = agentsReport(), found = all.filter { $0["installed"] as? Bool == true }
    if q.any(["connect", "set up", "setup", "hook up", "link"]), let a = all.first(where: { q.has(($0["name"] as? String ?? "").lowercased()) }) ?? all.first(where: { q.has($0["id"] as? String ?? "") }) {
        let id = a["id"] as? String ?? "", name = a["name"] as? String ?? id
        if a["connected"] as? Bool == true { return reply("agents", "\(name) is already connected.", tone: "good") }
        guard a["installed"] as? Bool == true else {
            return reply("agents", "\(name) isn't installed on this Mac. Once it is, I can connect to it in one click.",
                         actions: [act("Open AI agents", "open", ["page": "agents"], command: "bastion connect")])
        }
        if a["can_connect"] as? Bool == true {   // it edits another app's settings, so it stays a button you press
            return reply("agents", "I can connect \(name). I'll add myself to \(a["config"] as? String ?? "its MCP settings") and keep a backup of the old file.",
                         actions: [act("Connect \(name)", "connect", ["agent": id], command: "bastion connect \(id) --write")],
                         suggest: ["What is the hard-guard?", "Am I safe?"])
        }
        if let cmd = a["connect_command"] as? String {
            return reply("agents", "\(name) connects with one command in its own terminal:", points: [cmd],
                         actions: [act("Copy the command", "copy", ["text": cmd], command: cmd)])
        }
    }
    let on = found.filter { $0["connected"] as? Bool == true }.compactMap { $0["name"] as? String }
    let off = found.filter { $0["connected"] as? Bool != true }
    guard !found.isEmpty else {
        return reply("agents", "I don't see a coding agent on this Mac yet. When you install Claude Code, Cursor or Codex, I can connect to it.",
                     actions: [act("Open AI agents", "open", ["page": "agents"], command: "bastion connect")])
    }
    var actions: [[String: Any]] = []
    for a in off.prefix(2) {
        let id = a["id"] as? String ?? "", name = a["name"] as? String ?? id
        if a["can_connect"] as? Bool == true { actions.append(act("Connect \(name)", "connect", ["agent": id], command: "bastion connect \(id) --write")) }
        else if let cmd = a["connect_command"] as? String { actions.append(act("Copy \(name)'s command", "copy", ["text": cmd], command: cmd)) }
    }
    actions.append(act("Open AI agents", "open", ["page": "agents"], command: "bastion connect"))
    let head = off.isEmpty ? "All your agents are connected: \(spoken(on))."
        : on.isEmpty ? "None of your agents are connected yet." : "\(spoken(on)) \(on.count == 1 ? "is" : "are") connected."
    return reply("agents", head, tone: off.isEmpty ? "good" : "info",
                 points: off.isEmpty ? [] : ["Not connected: \(spoken(off.compactMap { $0["name"] as? String })). Connected agents check a repo with me before they run npm in it."],
                 actions: Array(actions.prefix(3)), suggest: ["What is MCP?", "Am I safe?"])
}

// MARK: - Terminal

func humanAnswer(_ r: [String: Any]) {
    let tone = r["tone"] as? String ?? "info"
    let mark = tone == "good" ? good("✓") : tone == "bad" ? bad("✗") : tone == "warn" ? warn("!") : strong("◆")
    print(mark + " " + strong(r["answer"] as? String ?? ""))
    for p in r["points"] as? [String] ?? [] { print("  " + faint("·") + " " + p) }
    let next = (r["actions"] as? [[String: Any]] ?? []).compactMap { a -> String? in
        (a["command"] as? String).map { faint("  → \(a["label"] as? String ?? ""): ") + $0 }
    }
    if !next.isEmpty { print(""); next.forEach { print($0) } }
    let s = (r["suggestions"] as? [String] ?? []).prefix(3)
    if !s.isEmpty { print("\n" + faint("ask: " + s.map { "“\($0)”" }.joined(separator: " · "))) }
}
