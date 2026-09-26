// Window.swift: Bastion's main window, laid out like a browser. A tinted sidebar holds back, forward, "Search or ask"
// and the pages; the page floats beside it. Home is the agent itself (Agent.swift). Every page reads `bastion … --json`,
// so the window, the terminal and AI agents always see the same thing.
import SwiftUI
import AppKit

typealias JSON = [String: Any]

/// Same home the CLI uses ($HOME first), so the window and the CLI always look at the same engine.
let HOME_DIR = ProcessInfo.processInfo.environment["HOME"].flatMap { $0.isEmpty ? nil : $0 } ?? NSHomeDirectory()
let BASTION_CLI = HOME_DIR + "/.security-guard/bin/bastion"

struct Box: @unchecked Sendable { let json: JSON }

/// Runs several bastion calls at once and returns their answers in order.
func bastionAll(_ calls: [[String]]) -> [Box] {
    final class Slots: @unchecked Sendable { var items: [Box]; let lock = NSLock(); init(_ n: Int) { items = Array(repeating: Box(json: [:]), count: n) } }
    let slots = Slots(calls.count)
    DispatchQueue.concurrentPerform(iterations: calls.count) { i in
        let b = Box(json: bastion(calls[i]))
        slots.lock.lock(); slots.items[i] = b; slots.lock.unlock()
    }
    return slots.items
}

/// `bastion <args> --json`, decoded. The window is a person, so after it asks, it passes --yes for actions that lower protection.
func bastion(_ args: [String]) -> JSON {
    guard FileManager.default.isExecutableFile(atPath: BASTION_CLI) else {
        return ["error": "Bastion's engine isn't installed yet. Quit and reopen the app to set it up."]
    }
    let out = runTool(BASTION_CLI, args + ["--json"])
    return (try? JSONSerialization.jsonObject(with: Data(out.utf8)) as? JSON) ?? ["error": out.isEmpty ? "No answer from bastion." : String(out.prefix(300))]
}

func tildePath(_ p: String) -> String { p.hasPrefix(HOME_DIR + "/") ? "~/" + p.dropFirst(HOME_DIR.count + 1) : p }

/// ISO 8601, the watcher's "yyyy-MM-dd HH:mm:ss" and the scan logs' "yyyyMMdd-HHmmss"
func parseDate(_ any: Any?) -> Date? {
    guard let s = (any as? String)?.trimmingCharacters(in: .whitespaces), !s.isEmpty else { return nil }
    let iso = ISO8601DateFormatter()
    if let d = iso.date(from: s) { return d }
    iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let d = iso.date(from: s) { return d }
    let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX")
    for format in ["yyyy-MM-dd HH:mm:ss", "yyyyMMdd-HHmmss"] {
        f.dateFormat = format
        if let d = f.date(from: String(s.prefix(format.count + 2)).trimmingCharacters(in: .whitespaces)) { return d }
    }
    return nil
}

func shortTime(_ any: Any?) -> String {
    guard let d = parseDate(any) else { return "" }
    let o = DateFormatter(); o.dateFormat = Calendar.current.isDateInToday(d) ? "'Today' HH:mm" : "MMM d, HH:mm"
    return o.string(from: d)
}

/// Compact age: now, 4m, 3h, 2d, Sep 24
func ago(_ any: Any?) -> String {
    guard let d = parseDate(any) else { return "" }
    let s = Int(Date().timeIntervalSince(d))
    if s < 60 { return "now" }
    if s < 3600 { return "\(s / 60)m" }
    if s < 86400 { return "\(s / 3600)h" }
    if s < 7 * 86400 { return "\(s / 86400)d" }
    let o = DateFormatter(); o.dateFormat = "MMM d"
    return o.string(from: d)
}

/// Spoken age: "just now", "4 minutes ago", "yesterday"
func agoWords(_ any: Any?) -> String? {
    guard let d = parseDate(any) else { return nil }
    let s = Int(Date().timeIntervalSince(d))
    func n(_ v: Int, _ unit: String) -> String { "\(v) \(unit)\(v == 1 ? "" : "s") ago" }
    if s < 60 { return "just now" }
    if s < 3600 { return n(s / 60, "minute") }
    if s < 86400 { return n(s / 3600, "hour") }
    if Calendar.current.isDateInYesterday(d) { return "yesterday" }
    if s < 7 * 86400 { return n(s / 86400, "day") }
    let o = DateFormatter(); o.dateFormat = "MMM d"
    return "on " + o.string(from: d)
}

/// Summaries end with "N things for you to do." Lists show that count on their own.
func withoutTodoCount(_ s: Any?) -> String {
    ((s as? String) ?? "").replacingOccurrences(of: #"\s*\d+ things? for you to do\.$"#, with: "", options: .regularExpression)
}

/// Log lines into sentences (the CLI's own wording, `said`, is used when it's there)
func humanizeEvent(_ message: String) -> String {
    var s = message
    if let re = try? NSRegularExpression(pattern: #"^(\d+) quarantined, (\d+) need your attention\. See logs\."#),
       let m = re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)),
       let q = Range(m.range(at: 1), in: s).flatMap({ Int(s[$0]) }), let n = Range(m.range(at: 2), in: s).flatMap({ Int(s[$0]) }) {
        let parts = [n > 0 ? "\(n) to look at" : nil, q > 0 ? "\(q) quarantined" : nil].compactMap { $0 }
        return parts.isEmpty ? "Scanned your repositories: all clean" : "Scanned your repositories: " + parts.joined(separator: ", ")
    }
    if let r = s.range(of: #"^INCIDENT \S+ \[\w+\]: "#, options: .regularExpression) { s = String(s[r.upperBound...]) }
    else if s.hasPrefix("INCIDENT ") { s = String(s.dropFirst(9)).replacingOccurrences(of: ": ", with: " ", options: [], range: nil) }
    for (pattern, template) in [(#"^CHANGED: "#, ""), (#"^ALERT: "#, ""), (#"^FIXED: "#, "Fixed: "), (#"^FIX FAILED: "#, "Couldn't fix: "), (#"^QUARANTINED \[([^\]]+)\]: "#, "Quarantined ($1): "),
                                (#"^BLOCKED \[([^\]]+)\]: "#, "Blocked $1: "), (#"^KILLED "#, "Stopped ")] {
        s = s.replacingOccurrences(of: pattern, with: template, options: .regularExpression)
    }
    return s.prefix(1).uppercased() + s.dropFirst()
}

/// An activity event in Bastion's own words
func said(_ e: JSON) -> String { (e["said"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? humanizeEvent(e["message"] as? String ?? "") }

// MARK: - Navigation

enum Pane: String, CaseIterable, Identifiable {
    case home, incidents, repos, activity, quarantine, agents, settings, guide
    var id: String { rawValue }
    var title: String {
        switch self {
        case .home: return "Home"
        case .incidents: return "Incidents"
        case .repos: return "Repositories"
        case .activity: return "Activity"
        case .quarantine: return "Quarantine"
        case .agents: return "AI agents"
        case .settings: return "Settings"
        case .guide: return "How it works"
        }
    }
    var icon: String {
        switch self {
        case .home: return "house"
        case .incidents: return "exclamationmark.shield"
        case .repos: return "folder"
        case .activity: return "clock.arrow.circlepath"
        case .quarantine: return "archivebox"
        case .agents: return "sparkles"
        case .settings: return "gearshape"
        case .guide: return "book.closed"
        }
    }
    var key: Character { Character("\((Pane.allCases.firstIndex(of: self) ?? 0) + 1)") }
}

/// Where you are, with a browser's back and forward
@MainActor
final class Router: ObservableObject {
    static let shared = Router()
    struct Place: Equatable { let pane: Pane; let incident: String?; let tab: String }
    @Published var pane: Pane = .home
    @Published var incident: String?          // an open incident page (Incidents / INC-…)
    @Published var palette = false
    @Published var incidentsTab = "needs"      // "needs" (Needs you) or "all" (every incident)
    @Published var focusAsk = 0                // bumped to put the cursor in Home's Ask box
    @Published private(set) var backStack: [Place] = []
    @Published private(set) var forwardStack: [Place] = []

    private var here: Place { Place(pane: pane, incident: incident, tab: incidentsTab) }
    private func visit(_ p: Place) {
        palette = false
        guard p != here else { return }
        backStack.append(here); forwardStack.removeAll()
        if backStack.count > 60 { backStack.removeFirst() }
        show(p)
    }
    private func show(_ p: Place) { pane = p.pane; incident = p.incident; incidentsTab = p.tab }

    func go(_ p: Pane) { visit(Place(pane: p, incident: nil, tab: incidentsTab)) }
    func openNeedsYou() { visit(Place(pane: .incidents, incident: nil, tab: "needs")) }
    func open(incident id: String) { visit(Place(pane: .incidents, incident: id, tab: incidentsTab)) }
    func askHome() { go(.home); focusAsk += 1 }
    var canGoBack: Bool { !backStack.isEmpty }
    var canGoForward: Bool { !forwardStack.isEmpty }
    func back() { guard let p = backStack.popLast() else { return }; forwardStack.append(here); show(p); palette = false }
    func forward() { guard let p = forwardStack.popLast() else { return }; backStack.append(here); show(p); palette = false }
}

struct ToastAction {
    let title: String
    let run: () -> Void
}

struct Confirm: Identifiable {
    let id = UUID()
    let title: String, message: String, button: String
    let run: () -> Void
}

/// One question to Bastion and its answer. An empty question is Bastion speaking up on its own (a follow-up).
struct Exchange: Identifiable {
    let id = UUID()
    let question: String
    var answer: JSON? = nil          // nil while Bastion is working on it
    var note: String? = nil          // what happened after (a scan finishing…)
    var noteTone = "info"
}

// MARK: - Store

@MainActor
final class AppStore: ObservableObject {
    static let shared = AppStore()             // one window, one store: the menu-bar panel can hand it questions
    @Published var status: JSON = [:]
    @Published var incidents: [JSON] = []
    @Published var details: [String: JSON] = [:]
    @Published var repos: [JSON] = []
    @Published var activity: [JSON] = []
    @Published var quarantine: [JSON] = []
    @Published var lists: JSON = [:]
    @Published var connect: JSON = [:]
    @Published var checks: [String: JSON] = [:]
    @Published var busy: Set<String> = []
    @Published var toast: String?
    @Published var toastAction: ToastAction?
    @Published var confirm: Confirm?
    @Published var loaded = false
    @Published var hooks: JSON = [:]
    @Published var sheet: ResultSheetContent?
    @Published var todos: [JSON] = []          // everything that needs the user, live (bastion todos)
    @Published var steps: [JSON] = []          // setup still open (bastion next)
    @Published var agents: [JSON] = []         // which AI agents are connected (bastion agents)
    @Published var chat: [Exchange] = []       // questions and answers on Home
    @Published var sampleRepo: String?         // a repo to use in example questions

    /// One with something on it, else the one used most recently
    static func pickSample(_ repos: [JSON]) -> String? {
        if let hot = repos.first(where: { ($0["infected_branches"] as? Int ?? 0) > 0 || ($0["findings"] as? Int ?? 0) > 0 }) { return hot["name"] as? String }
        let visible = repos.filter { r in !((r["path"] as? String ?? "").dropFirst(HOME_DIR.count).split(separator: "/").contains { $0.hasPrefix(".") }) }
        func used(_ r: JSON) -> Date {
            ((try? FileManager.default.attributesOfItem(atPath: (r["path"] as? String ?? "") + "/.git/index"))?[.modificationDate] as? Date) ?? .distantPast
        }
        return (visible.max { used($0) < used($1) } ?? repos.first)?["name"] as? String
    }

    func refresh() {
        Task {
            let r = await Task.detached(priority: .userInitiated) { () -> [Box] in
                bastionAll([["status"], ["incidents"], ["repos"], ["activity", "-n", "300"], ["quarantine"], ["lists"], ["connect"], ["hooks", "status"],
                            ["todos"], ["next"], ["agents"]])
            }.value
            hooks = r[7].json
            todos = r[8].json["items"] as? [JSON] ?? []
            steps = r[9].json["steps"] as? [JSON] ?? []
            agents = r[10].json["agents"] as? [JSON] ?? []
            status = r[0].json
            incidents = r[1].json["incidents"] as? [JSON] ?? []
            repos = r[2].json["repos"] as? [JSON] ?? []
            sampleRepo = Self.pickSample(repos)
            activity = r[3].json["events"] as? [JSON] ?? []
            quarantine = r[4].json["items"] as? [JSON] ?? []
            lists = r[5].json
            connect = r[6].json
            loaded = true
            for id in details.keys { load(incident: id) }
        }
    }

    func load(incident id: String) {
        Task {
            let r = await Task.detached(priority: .userInitiated) { Box(json: bastion(["incident", id])) }.value
            details[id] = r.json
        }
    }

    /// Runs a bastion command, shows its answer, then refreshes every page.
    func run(_ key: String, _ args: [String], done: String? = nil, after: ((JSON) -> Void)? = nil) {
        busy.insert(key)
        Task {
            let r = await Task.detached(priority: .userInitiated) { Box(json: bastion(args)) }.value.json
            busy.remove(key)
            flash((r["error"] as? String) ?? done ?? (r["summary"] as? String) ?? (r["message"] as? String) ?? "Done.")
            after?(r)
            refresh()
        }
    }

    func check(_ path: String) {
        busy.insert("check:" + path)
        Task {
            let r = await Task.detached(priority: .userInitiated) { Box(json: bastion(["check", path])) }.value.json
            busy.remove("check:" + path)
            checks[path] = r
            let name = (path as NSString).lastPathComponent
            let refs = r["infected_branch_refs"] as? [String] ?? []
            let on = (r["current_branch"] as? String).map { " on \($0)" } ?? ""
            if r["safe_to_run"] as? Bool != true {
                let n = (r["findings"] as? [Any])?.count ?? 0
                flash("\(name) isn't safe to run: \(n) problem\(n == 1 ? "" : "s"). Don't run npm there until it's fixed.",
                      action: ToastAction(title: "Review") { Router.shared.openNeedsYou() })
            } else if refs.isEmpty {
                flash("\(name) is safe to run\(on).")
            } else {
                flash("\(name) is safe to run\(on), but \(refs.joined(separator: ", ")) \(refs.count == 1 ? "carries" : "carry") malware. Don't check \(refs.count == 1 ? "it" : "them") out or merge \(refs.count == 1 ? "it" : "them").",
                      action: ToastAction(title: "Review") { Router.shared.openNeedsYou() })
            }
        }
    }

    /// Runs a read-only tool (history hunt, dependency check…) and shows the answer in a sheet.
    func present(_ title: String, _ key: String, _ args: [String]) {
        busy.insert(key)
        Task {
            let r = await Task.detached(priority: .userInitiated) { Box(json: bastion(args)) }.value.json
            busy.remove(key)
            sheet = ResultSheetContent(title: title, json: r)
        }
    }

    func respond() {
        run("respond", ["respond"]) { r in if let id = r["id"] as? String { Router.shared.open(incident: id) } }
    }

    func flash(_ text: String, action: ToastAction? = nil) {
        withAnimation(.easeOut(duration: 0.18)) { toast = text; toastAction = action }
        Task {
            try? await Task.sleep(nanoseconds: action == nil ? 4_000_000_000 : 9_000_000_000)
            if toast == text { withAnimation { toast = nil; toastAction = nil } }
        }
    }

    /// Scan every repo. The response runs as part of the scan, so the result (and the incident, if there is one) shows at once.
    /// `then` gets the result in words instead of a toast (the Ask box shows it with the answer).
    func scan(full: Bool = false, then report: ((String, String) -> Void)? = nil) {
        busy.insert("scan")
        Task {
            let r = await Task.detached(priority: .userInitiated) { Box(json: bastion(full ? ["scan", "--full"] : ["scan"])) }.value.json
            busy.remove("scan")
            refresh()
            if let error = r["error"] as? String { if let report { report(error, "warn") } else { flash(error) }; return }
            let n = (r["findings"] as? [Any])?.count ?? 0
            let secs = max(1, (r["duration_ms"] as? Int ?? 0) / 1000)
            guard n > 0 else {
                let s = "Scan finished in \(secs)s. All clean."
                if let report { report(s, "good") } else { flash(s) }
                return
            }
            let resp = r["response"] as? JSON
            if let id = resp?["id"] as? String {
                let s = "Scan finished in \(secs)s. \(withoutTodoCount(resp?["summary"]))"
                if let report { report(s, "warn") } else { flash(s, action: ToastAction(title: "Open incident") { Router.shared.open(incident: id) }) }
            } else {
                let s = "Scan finished in \(secs)s. \(n) thing\(n == 1 ? "" : "s") to look at."
                if let report { report(s, "warn") } else { flash(s, action: ToastAction(title: "Review") { Router.shared.openNeedsYou() }) }
            }
        }
    }

    /// Asks the person before doing something that lowers protection, deletes or reaches GitHub.
    func ask(_ title: String, _ message: String, button: String, _ run: @escaping () -> Void) {
        confirm = Confirm(title: title, message: message, button: button, run: run)
    }

    /// act_now, clean_up or all_clear: one answer, shown the same way everywhere
    var state: String { status["state"] as? String ?? (protected ? "all_clear" : "act_now") }
    var needsYouCount: Int { loaded ? todos.count : (status["needs_you"] as? Int ?? 0) }

    /// Runs an item's fix: the same commands it shows. Anything that reaches GitHub or deletes something asks first.
    func fix(_ item: JSON) {
        guard let id = item["id"] as? String, let fix = item["fix"] as? JSON else { return }
        let risk = fix["risk"] as? String ?? "safe"
        let title = fix["title"] as? String ?? "Fix"
        let cmds = (fix["commands"] as? [String] ?? []).joined(separator: "\n")
        let go = {
            self.busy.insert("fix:" + id)
            Task {
                let r = await Task.detached(priority: .userInitiated) { Box(json: bastion(["fix", id] + (risk == "safe" ? [] : ["--yes"]))) }.value.json
                self.busy.remove("fix:" + id)
                self.flash((r["error"] as? String) ?? (r["message"] as? String) ?? "Done.")
                if r["ok"] as? Bool != true, let out = r["output"] as? String, !out.isEmpty {
                    self.sheet = ResultSheetContent(title: title, json: ["summary": r["message"] ?? "It didn't work.", "output": out])
                }
                self.refresh()
                for incident in self.details.keys { self.load(incident: incident) }
            }
        }
        switch risk {
        case "safe": go()
        case "rewrites-history":
            ask("\(title)?", "This replaces the branch on GitHub with your clean copy. It only goes through if GitHub still has the infected commit. Anyone who already pulled that commit will need to reset their copy.\n\n\(cmds)", button: "Push clean copy", go)
        case "deletes-branch":
            ask("\(title)?", "This deletes the branch. Bastion can't bring it back.\n\n\(cmds)", button: "Delete branch", go)
        case "commit":
            ask("\(title)?", "Bastion commits the cleaned file for you. Nothing is pushed.\n\n\(cmds)", button: "Commit", go)
        case "push":
            ask("\(title)?", "This pushes your branch to GitHub. Commit the fix first.\n\n\(cmds)", button: "Push", go)
        default:
            ask("\(title)?", cmds, button: "Run", go)
        }
    }

    /// Completes a setup step (turn a protection on, add a hook, connect an agent). Steps that change shared files ask first.
    func doStep(_ step: JSON) {
        guard let action = step["action"] as? [String] else {
            if step["page"] as? String == "agents" { Router.shared.go(.agents) }
            return
        }
        let id = step["id"] as? String ?? ""
        let go = { self.run("step:" + id, action) }
        if let c = step["confirm"] as? String { ask("\(step["title"] as? String ?? "Continue")?", c, button: "Continue", go) } else { go() }
    }

    /// Every recommended step that needs no extra decision, one after another.
    func doRecommended() {
        let todo = bulkSteps
        guard !todo.isEmpty else { return }
        busy.insert("steps")
        Task {
            for s in todo {
                let a = s["action"] as? [String] ?? []
                _ = await Task.detached(priority: .userInitiated) { Box(json: bastion(a)) }.value
            }
            busy.remove("steps")
            flash("Turned on \(todo.count) protection\(todo.count == 1 ? "" : "s").")
            refresh()
        }
    }

    /// The user says a to-do Bastion can't check (rotating secrets…) is done.
    func tick(_ incident: String, _ key: String) {
        run("tick:" + key, ["incident", incident, "tick", key], done: "Marked done.") { _ in self.load(incident: incident) }
    }

    var protection: JSON { status["protection"] as? JSON ?? [:] }
    var autonomy: String { status["autonomy"] as? String ?? "contain" }
    var protected: Bool { (status["active_threats"] as? [Any] ?? []).isEmpty }
    var openIncidents: Int { incidents.filter { ($0["status"] as? String) != "resolved" }.count }
    var bulkSteps: [JSON] { steps.filter { $0["done"] as? Bool != true && $0["bulk"] as? Bool == true } }

    /// Turning a protection on is instant; turning it off asks first.
    func setFeature(_ feature: String, title: String, on: Bool) {
        if on { run("feature:" + feature, ["enable", feature]); return }
        ask("Turn off the \(title)?", "Bastion logs the change and shows a notification.", button: "Turn off") {
            self.run("feature:" + feature, ["disable", feature, "--yes"])
        }
    }

    func setAutonomy(_ level: String) {
        let order = ["off", "observe", "contain"]
        guard level != autonomy else { return }
        if (order.firstIndex(of: level) ?? 0) < (order.firstIndex(of: autonomy) ?? 2) {
            ask("Lower auto-respond to \(level)?", level == "off" ? "Bastion will stop responding on its own." : "Bastion will investigate and report, but won't change anything.", button: "Lower") {
                self.run("autonomy", ["autonomy", level, "--yes"])
            }
        } else { run("autonomy", ["autonomy", level]) }
    }
}

// MARK: - Window

struct MainWindow: View {
    @ObservedObject private var store = AppStore.shared
    @ObservedObject private var router = Router.shared
    private let ticker = Timer.publish(every: 20, on: .main, in: .common).autoconnect()

    var body: some View {
        HStack(spacing: 0) {
            Sidebar(store: store)
            content
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(DT.panel)
                .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(DT.border))
                .shadow(color: DT.shadow, radius: 4, y: 1)
                .padding(.vertical, 8).padding(.trailing, 8)
        }
        .background(DT.chrome)
        .overlay { if router.palette { CommandPalette(store: store).transition(.opacity) } }
        .overlay(alignment: .bottom) { toast }
        .background(shortcuts)
        .frame(minWidth: 1000, minHeight: 660)
        .confirmationDialog(store.confirm?.title ?? "", isPresented: Binding(get: { store.confirm != nil }, set: { if !$0 { store.confirm = nil } }),
                            presenting: store.confirm) { c in
            Button(c.button, role: .destructive) { c.run() }
            Button("Cancel", role: .cancel) {}
        } message: { c in Text(c.message) }
        .sheet(item: $store.sheet) { ResultSheet(content: $0) { store.sheet = nil } }
        .onAppear {
            Appearance.shared.apply()
            store.refresh()
            // a Dock icon while the window is open, back to menu-bar-only when it closes
            if NSApp.activationPolicy() != .prohibited { NSApp.setActivationPolicy(.regular); NSApp.activate(ignoringOtherApps: true) }
        }
        .onDisappear { if NSApp.activationPolicy() != .prohibited { NSApp.setActivationPolicy(.accessory) } }
        .onReceive(ticker) { _ in store.refresh() }
    }

    @ViewBuilder private var content: some View {
        switch router.pane {
        case .home: HomePage(store: store)
        case .incidents:
            if let id = router.incident { IncidentPage(store: store, id: id) } else { IncidentsPage(store: store) }
        case .repos: ReposPage(store: store)
        case .activity: ActivityPage(store: store)
        case .quarantine: QuarantinePage(store: store)
        case .agents: AgentsPage(store: store)
        case .settings: SettingsPage(store: store)
        case .guide: GuidePage(store: store)
        }
    }

    /// ⌘K or ⌘L search or ask · ⌘1 to ⌘7 pages · ⌘[ and ⌘] back and forward · ⌘R refresh · Esc closes or goes back
    private var shortcuts: some View {
        ZStack {
            Button("Search or ask") { withAnimation(.easeOut(duration: 0.12)) { router.palette.toggle() } }.keyboardShortcut("k", modifiers: .command)
            Button("Search or ask") { withAnimation(.easeOut(duration: 0.12)) { router.palette = true } }.keyboardShortcut("l", modifiers: .command)
            ForEach(Pane.allCases) { p in Button(p.title) { router.go(p) }.keyboardShortcut(KeyEquivalent(p.key), modifiers: .command) }
            Button("Back") { router.back() }.keyboardShortcut("[", modifiers: .command)
            Button("Forward") { router.forward() }.keyboardShortcut("]", modifiers: .command)
            Button("Refresh") { store.refresh() }.keyboardShortcut("r", modifiers: .command)
            Button("Close") {
                if router.palette { withAnimation(.easeOut(duration: 0.12)) { router.palette = false } }
                else if router.incident != nil { router.go(.incidents) }
            }.keyboardShortcut(.escape, modifiers: [])
        }.opacity(0).frame(width: 0, height: 0).accessibilityHidden(true)
    }

    @ViewBuilder private var toast: some View {
        if let t = store.toast {
            HStack(spacing: 12) {
                Text(t).font(uiFont(13, .medium)).foregroundStyle(DT.text).lineLimit(3).fixedSize(horizontal: false, vertical: true)
                if let a = store.toastAction {
                    Button(a.title) { withAnimation { store.toast = nil; store.toastAction = nil }; a.run() }.buttonStyle(PrimaryButton())
                }
            }
            .padding(.leading, 16).padding(.trailing, store.toastAction == nil ? 16 : 8).padding(.vertical, 10)
            .background(DT.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(DT.border))
            .shadow(color: DT.shadow, radius: 16, y: 6)
            .padding(.bottom, 24).padding(.leading, 240).frame(maxWidth: 820)
            .transition(.move(edge: .bottom).combined(with: .opacity))
        }
    }
}

// MARK: - Sidebar

struct Sidebar: View {
    @ObservedObject var store: AppStore
    @ObservedObject private var router = Router.shared
    var body: some View {
        let look = stateLook(store)
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 0) {   // the traffic lights sit to the left of these, as in a browser
                Spacer()
                IconButton(icon: "chevron.left", help: "Back  ⌘[", enabled: router.canGoBack) { router.back() }
                IconButton(icon: "chevron.right", help: "Forward  ⌘]", enabled: router.canGoForward) { router.forward() }
                IconButton(icon: "arrow.clockwise", help: "Refresh  ⌘R") { store.refresh() }
            }.frame(height: 28).padding(.top, 10)
            HStack(spacing: 8) {
                BrandMark(size: 18)
                Text("Bastion").font(uiFont(15, .semibold)).foregroundStyle(DT.text)
                Spacer()
                HStack(spacing: 5) {
                    Circle().fill(look.tint).frame(width: 6, height: 6)
                    Text(look.short).font(uiFont(12, .medium)).foregroundStyle(DT.dim)
                }.help(look.title)
            }.padding(.horizontal, 8).padding(.top, 12).padding(.bottom, 16)
            omnibox
            VStack(spacing: 2) {
                SideItem(pane: .home, selected: router.pane == .home) { router.go(.home) }
                SideItem(pane: .incidents, selected: router.pane == .incidents, count: store.needsYouCount, tint: look.tint) { router.go(.incidents) }
                header("Your code")
                SideItem(pane: .repos, selected: router.pane == .repos) { router.go(.repos) }
                SideItem(pane: .activity, selected: router.pane == .activity) { router.go(.activity) }
                SideItem(pane: .quarantine, selected: router.pane == .quarantine, count: store.quarantine.count) { router.go(.quarantine) }
                header("Connect")
                SideItem(pane: .agents, selected: router.pane == .agents) { router.go(.agents) }
                SideItem(pane: .settings, selected: router.pane == .settings) { router.go(.settings) }
                header("Learn")
                SideItem(pane: .guide, selected: router.pane == .guide) { router.go(.guide) }
            }.padding(.top, 16)
            Spacer(minLength: 16)
            callout
            HStack {
                AppearanceSwitch()
                Spacer()
                Text("v\(store.status["version"] as? String ?? "")").font(uiFont(11)).foregroundStyle(DT.faint)
            }.padding(.horizontal, 4).padding(.top, 12).padding(.bottom, 12)
        }
        .padding(.horizontal, 10)
        .frame(width: 240)
    }

    private var omnibox: some View {
        Button { withAnimation(.easeOut(duration: 0.12)) { router.palette = true } } label: {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").font(.system(size: 12, weight: .medium)).foregroundStyle(DT.dim)
                Text("Search or ask").font(uiFont(13)).foregroundStyle(DT.dim)
                Spacer()
                KeyCap(key: "⌘K")
            }
            .padding(.leading, 10).padding(.trailing, 7).frame(height: 32)
            .background(DT.panel, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(DT.border))
            .contentShape(Rectangle())
        }.buttonStyle(.plain).help("Ask Bastion a question, or jump to anything")
    }

    private func header(_ title: String) -> some View {
        Text(title).font(uiFont(11, .medium)).foregroundStyle(DT.faint)
            .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 10).padding(.top, 18).padding(.bottom, 6)
    }

    /// Like Vercel's "Action required" box: what needs you, or the rest of setup
    @ViewBuilder private var callout: some View {
        let setup = store.status["setup"] as? JSON ?? [:]
        let done = setup["done"] as? Int ?? 0, total = setup["total"] as? Int ?? 0
        let n = store.needsYouCount
        if n > 0 {
            let now = store.state == "act_now"
            SideCallout(icon: now ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill", tint: now ? DT.red : DT.orange,
                        title: now ? "Act now" : "\(n) thing\(n == 1 ? "" : "s") to clean up",
                        text: now ? "Malware is running, or will run as soon as npm runs there." : "Nothing is running. Each one has a one-click fix.",
                        button: "Review") { router.openNeedsYou() }
        } else if total > 0 && done < total {
            let bulk = store.bulkSteps.count
            SideCallout(icon: "shield.lefthalf.filled", tint: DT.green, title: "Finish setting up",
                        text: "\(done) of \(total) protections \(done == 1 ? "is" : "are") on.", progress: Double(done) / Double(total),
                        button: store.busy.contains("steps") ? "Turning on" : bulk > 0 ? "Turn on \(bulk) more" : "Show me") {
                if bulk > 0 { store.doRecommended() } else { router.go(.home) }
            }
        }
    }
}

struct SideItem: View {
    let pane: Pane
    let selected: Bool
    var count = 0
    var tint: Color? = nil
    let action: () -> Void
    @State private var hover = false
    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: pane.icon).font(.system(size: 13, weight: .medium)).foregroundStyle(selected ? DT.text : DT.dim).frame(width: 18)
                Text(pane.title).font(uiFont(13, selected ? .semibold : .regular)).foregroundStyle(selected ? DT.text : DT.text2)
                Spacer()
                if count > 0 {
                    Text("\(count)").font(uiFont(11, .semibold)).foregroundStyle(tint ?? DT.dim).monospacedDigit()
                        .padding(.horizontal, 6).frame(minWidth: 20, minHeight: 18).background((tint ?? DT.dim).opacity(0.12), in: Capsule())
                }
            }
            .padding(.horizontal, 10).frame(height: 30).contentShape(Rectangle())
            .background {   // the selected page looks like the active tab in a browser
                if selected {
                    RoundedRectangle(cornerRadius: 8, style: .continuous).fill(DT.panel)
                        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(DT.border))
                        .shadow(color: DT.shadow, radius: 2, y: 1)
                } else if hover {
                    RoundedRectangle(cornerRadius: 8, style: .continuous).fill(DT.sideHover)
                }
            }
        }
        .buttonStyle(.plain).onHover { hover = $0 }
        .help(pane.title + "  ⌘" + String(pane.key))
    }
}

struct SideCallout: View {
    let icon: String, tint: Color, title: String, text: String
    var progress: Double? = nil
    let button: String
    let action: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Text(title).font(uiFont(13, .semibold)).foregroundStyle(DT.text)
                Spacer()
                Image(systemName: icon).font(.system(size: 12)).foregroundStyle(tint)
            }
            Text(text).font(uiFont(12)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true)
            if let progress { ProgressBar(value: progress, tint: tint) }
            Button(action: action) { Text(button).frame(maxWidth: .infinity) }.buttonStyle(SecondaryButton())
        }
        .padding(12)
        .background(DT.panel, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(tint.opacity(0.35)))
    }
}

// MARK: - Page chrome

/// The breadcrumb bar at the top of the page
struct TopBar<Trailing: View>: View {
    let crumbs: [String]
    var back: (() -> Void)? = nil
    @ViewBuilder var trailing: Trailing
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                ForEach(Array(crumbs.enumerated()), id: \.offset) { i, c in
                    if i > 0 { Text("/").font(uiFont(13)).foregroundStyle(DT.faint) }
                    if i == 0, crumbs.count > 1, let back {
                        Button(c, action: back).buttonStyle(.plain).font(uiFont(13, .medium)).foregroundStyle(DT.dim)
                    } else {
                        Text(c).font(i == crumbs.count - 1 && crumbs.count > 1 ? codeFont(12, .medium) : uiFont(13, .semibold))
                            .foregroundStyle(DT.text).lineLimit(1)
                    }
                }
                Spacer()
                trailing
            }.padding(.horizontal, 20).frame(height: 48)
            Hairline()
        }
    }
}
extension TopBar where Trailing == EmptyView {
    init(crumbs: [String], back: (() -> Void)? = nil) { self.init(crumbs: crumbs, back: back) { EmptyView() } }
}

/// Scrolling page body with a comfortable reading width
struct PageBody<Content: View>: View {
    var width: CGFloat = 860
    @ViewBuilder var content: Content
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 36) { content }
                .padding(.horizontal, 40).padding(.top, 32).padding(.bottom, 44)
                .frame(maxWidth: width, alignment: .leading).frame(maxWidth: .infinity)
        }
    }
}

/// Segmented tabs
struct Segmented: View {
    let items: [(id: String, title: String, count: Int)]
    @Binding var selection: String
    var body: some View {
        HStack(spacing: 2) {
            ForEach(items, id: \.id) { item in
                let on = selection == item.id
                Button { selection = item.id } label: {
                    HStack(spacing: 6) {
                        Text(item.title).font(uiFont(13, .medium)).foregroundStyle(on ? DT.text : DT.dim)
                        if item.count > 0 { Text("\(item.count)").font(uiFont(12, .medium)).foregroundStyle(DT.dim).monospacedDigit() }
                    }
                    .padding(.horizontal, 12).frame(height: 28)
                    .background {
                        if on {
                            RoundedRectangle(cornerRadius: 7, style: .continuous).fill(DT.panel)
                                .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous).strokeBorder(DT.border))
                                .shadow(color: DT.shadow, radius: 1.5, y: 1)
                        }
                    }
                    .contentShape(Rectangle())
                }.buttonStyle(.plain)
            }
        }
        .padding(2).background(DT.surface2, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
    }
}

// MARK: - Danger, in one place

func dangerStyle(_ d: String) -> (icon: String, tint: Color, label: String) {
    switch d {
    case "now": return ("exclamationmark.octagon.fill", DT.red, "Act now")
    case "dormant": return ("moon.zzz.fill", DT.orange, "Dormant")
    case "leftover": return ("clock.arrow.circlepath", DT.dim, "Leftover")
    default: return ("checklist", DT.accent, "To check")
    }
}

struct DangerIcon: View {
    let danger: String
    var size: CGFloat = 28
    var body: some View {
        let s = dangerStyle(danger)
        Image(systemName: s.icon).font(.system(size: size * 0.42, weight: .semibold)).foregroundStyle(s.tint)
            .frame(width: size, height: size).background(s.tint.opacity(0.11), in: RoundedRectangle(cornerRadius: size * 0.28, style: .continuous))
    }
}

struct DangerPill: View {
    let danger: String
    var body: some View {
        let s = dangerStyle(danger)
        Tag(text: danger == "dormant" ? "Dormant, not running" : s.label, tint: s.tint)
    }
}

// MARK: - Protection switches (Settings; Home's Protection rows link here)

struct ProtectionGroup: View {
    @ObservedObject var store: AppStore
    var body: some View {
        RowGroup {
            row("bolt", "Real-time watcher", "Stops malware loaders and attacker connections within seconds.", "watcher", store.protection["watcher"] as? Bool ?? false)
            Hairline()
            row("clock", "Scheduled scan", "Checks every repository at login and every 6 hours.", "scheduled_scan", store.protection["scheduled_scan"] as? Bool ?? false)
            Hairline()
            row("lock.shield", "Execution guard", "npm, node, pnpm, yarn and bun refuse to run in an infected project.", "exec_guard", store.protection["exec_guard"] as? Bool ?? false)
        }
    }
    private func row(_ icon: String, _ title: String, _ detail: String, _ feature: String, _ on: Bool) -> some View {
        HStack(spacing: 12) {
            Image(systemName: icon).font(.system(size: 13)).foregroundStyle(DT.dim).frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(uiFont(13, .medium)).foregroundStyle(DT.text)
                Text(detail).font(uiFont(12)).foregroundStyle(DT.dim)
            }
            Spacer()
            if store.busy.contains("feature:" + feature) { ProgressView().controlSize(.small).scaleEffect(0.7) }
            Toggle(title, isOn: Binding(get: { on }, set: { store.setFeature(feature, title: title.lowercased(), on: $0) }))
                .labelsHidden().toggleStyle(ThemeSwitch())
        }.padding(.horizontal, 16).padding(.vertical, 12)
    }
}

/// Where an activity row leads: its incident; for a scan, the incident it opened or updated; the quarantine; settings.
@MainActor func activityTarget(_ e: JSON, in events: [JSON]) -> (() -> Void)? {
    if let id = e["incident"] as? String { return { Router.shared.open(incident: id) } }
    switch e["type"] as? String ?? "" {
    case "scan":
        guard let t = parseDate(e["time"]) else { return nil }
        let next = events.first { ($0["incident"] as? String) != nil && (parseDate($0["time"]).map { $0 >= t && $0.timeIntervalSince(t) < 600 } ?? false) }
        if let id = next?["incident"] as? String { return { Router.shared.open(incident: id) } }
        return { Router.shared.go(.repos) }
    case "quarantined": return { Router.shared.go(.quarantine) }
    case "setting_changed": return { Router.shared.go(.settings) }
    case "fixed": return { Router.shared.openNeedsYou() }
    default: return nil
    }
}

func eventStyle(_ e: JSON) -> (icon: String, tint: Color) {
    let raw = e["message"] as? String ?? ""
    switch e["type"] as? String ?? "" {
    case "killed": return ("bolt.fill", DT.red)
    case "quarantined": return ("archivebox.fill", DT.orange)
    case "blocked": return ("hand.raised.fill", DT.orange)
    case "alert": return ("exclamationmark.triangle.fill", DT.orange)
    case "setting_changed": return ("slider.horizontal.3", DT.blue)
    case "fixed": return ("checkmark", DT.green)
    case "scan": return (e["attention"] as? Int ?? 0 > 0 ? "magnifyingglass" : "checkmark", e["attention"] as? Int ?? 0 > 0 ? DT.orange : DT.green)
    default:
        if raw.contains("marked resolved") { return ("checkmark.seal.fill", DT.green) }
        return raw.hasPrefix("INCIDENT") ? ("exclamationmark.shield.fill", DT.accent) : ("circle.fill", DT.faint)
    }
}

struct ActivityRow: View {
    let event: JSON
    var open: (() -> Void)? = nil
    var body: some View {
        if let open {
            Button(action: open) { row(chevron: true) }.buttonStyle(.plain).hoverRow(radius: 0)
        } else {
            row(chevron: false)
        }
    }
    private func row(chevron: Bool) -> some View {
        let message = said(event)
        let s = eventStyle(event)
        return HStack(spacing: 12) {
            Image(systemName: s.icon).font(.system(size: s.icon == "circle.fill" ? 5 : 10, weight: .bold)).foregroundStyle(s.tint)
                .frame(width: 24, height: 24).background(s.icon == "circle.fill" ? .clear : s.tint.opacity(0.11), in: RoundedRectangle(cornerRadius: 7, style: .continuous))
            Text(message).font(uiFont(13)).foregroundStyle(DT.text).lineLimit(1).truncationMode(.tail)
            Spacer(minLength: 12)
            Text(shortTime(event["time"])).font(uiFont(12)).foregroundStyle(DT.faint).monospacedDigit()
            if chevron { Image(systemName: "chevron.right").font(.system(size: 9, weight: .semibold)).foregroundStyle(DT.faint) }
        }.padding(.horizontal, 16).frame(height: 44).contentShape(Rectangle()).help(message)
    }
}

// MARK: - Incidents

struct IncidentsPage: View {
    @ObservedObject var store: AppStore
    @ObservedObject private var router = Router.shared
    var body: some View {
        VStack(spacing: 0) {
            TopBar(crumbs: ["Incidents"]) {
                Button { store.scan() } label: { Label(store.busy.contains("scan") ? "Scanning" : "Scan now", systemImage: "magnifyingglass") }
                    .buttonStyle(SecondaryButton()).disabled(store.busy.contains("scan"))
            }
            HStack(spacing: 12) {
                Segmented(items: [("needs", "Needs you", store.needsYouCount), ("all", "All incidents", store.incidents.count)], selection: $router.incidentsTab)
                Spacer()
                Text(router.incidentsTab == "needs" ? "Updates on its own. Fixed items leave the list." : "Every attack Bastion handled, newest first.")
                    .font(uiFont(12)).foregroundStyle(DT.faint)
            }.padding(.horizontal, 20).frame(height: 52)
            Hairline()
            if router.incidentsTab == "needs" { NeedsYouList(store: store) } else { IncidentList(store: store) }
        }
    }
}

/// Every incident, grouped: still needs you (open to-dos), contained, resolved
struct IncidentList: View {
    @ObservedObject var store: AppStore
    var body: some View {
        let needs = store.incidents.filter { ($0["status"] as? String) != "resolved" && (($0["todos"] as? Int ?? 0) > 0 || ($0["status"] as? String) == "open") }
        let contained = store.incidents.filter { ($0["status"] as? String) == "contained" && ($0["todos"] as? Int ?? 0) == 0 }
        let resolved = store.incidents.filter { ($0["status"] as? String) == "resolved" }
        let groups: [(String, String, [JSON])] = [("open", "Needs you", needs), ("contained", "Contained", contained), ("resolved", "Resolved", resolved)].filter { !$0.2.isEmpty }
        if store.incidents.isEmpty {
            EmptyState(icon: "checkmark.shield", title: "No incidents yet",
                       text: "When Bastion finds an attack, it investigates, contains what it can prove and writes it up here: what happened, what it did and what's left for you.", tint: DT.green)
        } else {
            ScrollView {
                VStack(alignment: .leading, spacing: 28) {
                    ForEach(groups, id: \.0) { g in
                        VStack(alignment: .leading, spacing: 10) {
                            HStack(spacing: 8) {
                                StatusIcon(status: g.0, size: 13)
                                Text(g.1).font(uiFont(13, .semibold)).foregroundStyle(DT.text)
                                Text("\(g.2.count)").font(uiFont(12)).foregroundStyle(DT.dim).monospacedDigit()
                            }.padding(.leading, 2)
                            RowGroup {
                                ForEach(g.2.indices, id: \.self) { i in
                                    if i > 0 { Hairline() }
                                    IncidentRow(inc: g.2[i])
                                }
                            }
                        }
                    }
                }
                .padding(.horizontal, 32).padding(.vertical, 28).frame(maxWidth: 980).frame(maxWidth: .infinity)
            }
        }
    }
}

struct IncidentRow: View {
    let inc: JSON
    var body: some View {
        let status = inc["status"] as? String ?? "open"
        let repos = inc["repos"] as? [String] ?? []
        return Button { if let id = inc["id"] as? String { Router.shared.open(incident: id) } } label: {
            HStack(spacing: 12) {
                StatusIcon(status: status)
                VStack(alignment: .leading, spacing: 2) {
                    Text(withoutTodoCount(inc["summary"])).font(uiFont(13, .medium)).foregroundStyle(DT.text).lineLimit(1)
                    Text("\(inc["id"] as? String ?? "") · opened \(shortTime(inc["opened"]))").font(uiFont(12)).foregroundStyle(DT.faint)
                }
                Spacer(minLength: 12)
                ForEach(Array(repos.prefix(2).enumerated()), id: \.offset) { _, r in Pill(text: r, icon: "folder") }
                if repos.count > 2 { Text("+\(repos.count - 2)").font(uiFont(12)).foregroundStyle(DT.dim) }
                if let todos = inc["todos"] as? Int, todos > 0, status != "resolved" { Tag(text: "\(todos) to-do\(todos == 1 ? "" : "s")", tint: DT.orange) }
                Image(systemName: "chevron.right").font(.system(size: 9, weight: .semibold)).foregroundStyle(DT.faint)
            }.padding(.horizontal, 16).frame(height: 56).contentShape(Rectangle())
        }.buttonStyle(.plain).hoverRow(radius: 0)
    }
}

/// The live list: everything that needs the user, grouped by repo, each with what it is, how dangerous it is now, proof and the fix
struct NeedsYouList: View {
    @ObservedObject var store: AppStore
    var body: some View {
        if store.todos.isEmpty {
            EmptyState(icon: "checkmark.shield", title: "Nothing needs you",
                       text: "When Bastion finds something, it shows up here with what it is, how dangerous it is right now, the proof and a one-click fix.", tint: DT.green)
        } else {
            let now = store.todos.filter { $0["danger"] as? String == "now" }.count
            ScrollView {
                VStack(alignment: .leading, spacing: 28) {
                    Text(now > 0 ? "Start with the red ones. They're running, or will run as soon as npm runs in that folder."
                                 : "Nothing here is running. Clean these up so nobody runs them by accident.")
                        .font(uiFont(13)).foregroundStyle(DT.text2).fixedSize(horizontal: false, vertical: true)
                    ForEach(groups, id: \.0) { g in
                        VStack(alignment: .leading, spacing: 10) {
                            HStack(spacing: 8) {
                                Image(systemName: g.0.isEmpty ? "desktopcomputer" : "folder").font(.system(size: 12, weight: .medium)).foregroundStyle(DT.dim)
                                Text(g.0.isEmpty ? "This Mac" : (g.0 as NSString).lastPathComponent).font(uiFont(13, .semibold)).foregroundStyle(DT.text)
                                if !g.0.isEmpty { Text(tildePath(g.0)).font(codeFont(12)).foregroundStyle(DT.faint).lineLimit(1).truncationMode(.middle) }
                                Spacer()
                            }.padding(.leading, 2)
                            ForEach(g.1.indices, id: \.self) { i in TodoCard(store: store, item: g.1[i]) }
                        }
                    }
                }
                .padding(.horizontal, 32).padding(.vertical, 28).frame(maxWidth: 900, alignment: .leading).frame(maxWidth: .infinity)
            }
        }
    }
    private var groups: [(String, [JSON])] {
        var out: [(String, [JSON])] = []
        for item in store.todos {
            let repo = item["repo"] as? String ?? ""
            if let i = out.firstIndex(where: { $0.0 == repo }) { out[i].1.append(item) } else { out.append((repo, [item])) }
        }
        return out
    }
}

struct TodoCard: View {
    @ObservedObject var store: AppStore
    let item: JSON
    @State private var showFix = false
    var body: some View {
        let fix = item["fix"] as? JSON ?? [:]
        let danger = item["danger"] as? String ?? ""
        let proofs = item["proof"] as? [JSON] ?? []
        let cmds = fix["commands"] as? [String] ?? []
        let isTodo = item["type"] as? String == "todo"
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 12) {
                DangerIcon(danger: danger)
                VStack(alignment: .leading, spacing: 6) {
                    Text(item["title"] as? String ?? "").font(uiFont(15, .semibold)).foregroundStyle(DT.text).fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 6) {
                        DangerPill(danger: danger)
                        if let place = item["where"] as? String, !place.isEmpty, !isTodo {
                            Text(place).font(codeFont(12)).foregroundStyle(DT.dim).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                        }
                    }
                    if let what = item["what"] as? String, !what.isEmpty {
                        Text(what).font(uiFont(13)).foregroundStyle(DT.text2).lineSpacing(1.5).fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                            .padding(.top, 2)
                    }
                }
                Spacer(minLength: 12)
                actionButton(fix: fix, danger: danger)
            }
            if !proofs.isEmpty { proofBox(proofs).padding(.leading, 40) }
            if !isTodo, (fix["why"] as? String).map({ !$0.isEmpty }) == true || !cmds.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Button { withAnimation(.easeOut(duration: 0.15)) { showFix.toggle() } } label: {
                        HStack(spacing: 6) {
                            Image(systemName: showFix ? "chevron.down" : "chevron.right").font(.system(size: 9, weight: .bold)).foregroundStyle(DT.faint)
                            Text("How the fix works").font(uiFont(12, .medium)).foregroundStyle(DT.dim)
                        }.contentShape(Rectangle())
                    }.buttonStyle(.plain)
                    if showFix {
                        if let why = fix["why"] as? String, !why.isEmpty {
                            Text(why).font(uiFont(13)).foregroundStyle(DT.text2).fixedSize(horizontal: false, vertical: true)
                        }
                        if !cmds.isEmpty && !(cmds.count == 1 && cmds[0].hasPrefix("bastion ")) { CommandBlock(text: cmds.joined(separator: "\n")) }
                    }
                }.padding(.leading, 40)
            } else if isTodo, !cmds.isEmpty {
                CommandBlock(text: cmds.joined(separator: "\n")).padding(.leading, 40)
            }
            if let inc = item["incident"] as? String {
                Button { Router.shared.open(incident: inc) } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "doc.text").font(.system(size: 10))
                        Text("Part of \(inc)").font(uiFont(12))
                    }.foregroundStyle(DT.dim)
                }.buttonStyle(.plain).padding(.leading, 40).help("Open the incident report")
            }
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(DT.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(danger == "now" ? DT.red.opacity(0.5) : DT.border))
    }

    @ViewBuilder private func actionButton(fix: JSON, danger: String) -> some View {
        let id = item["id"] as? String ?? ""
        let busy = store.busy.contains("fix:" + id)
        if fix["runnable"] as? Bool == true {
            Button { store.fix(item) } label: {
                HStack(spacing: 6) {
                    if busy { ProgressView().controlSize(.small).scaleEffect(0.6).frame(width: 12, height: 12) }
                    Text(busy ? "Working" : fix["button"] as? String ?? "Fix it")
                }
            }.buttonStyle(PrimaryButton(tint: danger == "now" ? DT.red : nil)).disabled(busy)
        } else if item["type"] as? String == "todo", let inc = item["incident"] as? String, let key = item["todo_key"] as? String {
            Button { store.tick(inc, key) } label: { Label("Mark done", systemImage: "checkmark") }.buttonStyle(SecondaryButton())
        }
    }

    private func proofBox(_ proofs: [JSON]) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: "eye").font(.system(size: 10, weight: .semibold))
                Text("Proof: where the hidden code is").font(uiFont(12, .semibold))
            }.foregroundStyle(DT.dim)
            ForEach(proofs.indices, id: \.self) { i in
                let p = proofs[i]
                VStack(alignment: .leading, spacing: 8) {
                    Text("\(p["file"] as? String ?? ""): \(p["text"] as? String ?? "")").font(codeFont(12)).foregroundStyle(DT.text2)
                        .textSelection(.enabled).fixedSize(horizontal: false, vertical: true).lineSpacing(2)
                    HStack(spacing: 8) {
                        if let link = p["github_url"] as? String, let url = URL(string: link) {
                            Button { NSWorkspace.shared.open(url) } label: { Label("See it on GitHub", systemImage: "arrow.up.right") }.buttonStyle(SecondaryButton())
                        }
                        if let see = p["see_it"] as? String {
                            Button {
                                NSPasteboard.general.clearContents(); NSPasteboard.general.setString(see, forType: .string)
                                store.flash("Copied. Paste it in a terminal to see the hidden code for yourself.")
                            } label: { Label("Copy command to see it", systemImage: "doc.on.doc") }.buttonStyle(SecondaryButton())
                        }
                    }
                }
            }
        }
        .padding(12).frame(maxWidth: .infinity, alignment: .leading)
        .background(DT.sunken, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(DT.border))
    }
}

// MARK: - One incident, as a story: in short, what's left, what Bastion did, the evidence, the timeline

struct IncidentPage: View {
    @ObservedObject var store: AppStore
    let id: String
    var body: some View {
        let inc = store.details[id]
        VStack(spacing: 0) {
            TopBar(crumbs: ["Incidents", id], back: { Router.shared.go(.incidents) }) {
                if let inc { actions(inc) }
            }
            if let inc, inc["error"] == nil {
                IncidentStory(store: store, inc: inc)
            } else if let inc, let error = inc["error"] as? String {
                EmptyState(icon: "questionmark.circle", title: "Couldn't load \(id)", text: error)
            } else {
                ProgressView().controlSize(.small).frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .onAppear { store.load(incident: id) }
        .onChange(of: id) { store.load(incident: id) }
    }

    @ViewBuilder private func actions(_ inc: JSON) -> some View {
        let status = inc["status"] as? String ?? "open"
        HStack(spacing: 8) {
            if (inc["actions"] as? [JSON] ?? []).contains(where: { $0["type"] as? String == "restore_file" && $0["status"] as? String == "done" }) {
                Button("Undo file fixes") {
                    store.ask("Put back the infected files?", "Only do this if Bastion cleaned a file it shouldn't have. The infected versions go back in place.", button: "Put back") {
                        store.run("undo", ["undo", id, "--yes"])
                    }
                }.buttonStyle(SecondaryButton())
            }
            IconButton(icon: "doc.text", help: "Open the Markdown report") { NSWorkspace.shared.open(URL(fileURLWithPath: inc["report"] as? String ?? "")) }
            if status != "resolved" {
                Button { store.run("resolve", ["incident", "resolve", id], done: "\(id) marked resolved.") } label: { Label("Mark resolved", systemImage: "checkmark") }
                    .buttonStyle(inc["all_done"] as? Bool == true ? AnyButtonStyle(PrimaryButton()) : AnyButtonStyle(SecondaryButton()))
                    .help("Closes the incident. Anything still unfixed stays in Needs you until Bastion sees it fixed.")
            }
        }
    }
}

/// Lets a view pick a button style at run time
struct AnyButtonStyle: ButtonStyle {
    private let make: (Configuration) -> AnyView
    init<S: ButtonStyle>(_ style: S) { make = { AnyView(style.makeBody(configuration: $0)) } }
    func makeBody(configuration: Configuration) -> some View { make(configuration) }
}

struct IncidentStory: View {
    @ObservedObject var store: AppStore
    let inc: JSON
    private var actions: [JSON] { inc["actions"] as? [JSON] ?? [] }
    private var status: String {
        let s = inc["status"] as? String ?? "open"
        return s != "resolved" && (inc["open_todos"] as? Int ?? 0) > 0 ? "open" : s
    }
    var body: some View {
        PageBody(width: 820) {
            header
            inShort
            if inc["status"] as? String != "resolved", inc["all_done"] as? Bool == true { allDone }
            if inc["status"] as? String != "resolved" { todos }
            did
            evidence
            if !(inc["done"] as? [JSON] ?? []).isEmpty { doneList }
            details
            timeline
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Tag(text: status == "open" ? "Needs you" : status.capitalized, tint: status == "open" ? DT.orange : status == "contained" ? DT.accent : DT.green)
                Text("Opened \(shortTime(inc["opened"]))").font(uiFont(12)).foregroundStyle(DT.dim)
                Text("·").font(uiFont(12)).foregroundStyle(DT.faint)
                Text("Updated \(shortTime(inc["updated"]))").font(uiFont(12)).foregroundStyle(DT.dim)
            }
            Text(withoutTodoCount(inc["summary"])).font(.system(size: 20, weight: .semibold)).tracking(-0.3).foregroundStyle(DT.text)
                .fixedSize(horizontal: false, vertical: true)
            FlowRow(spacing: 8) {
                let ran = inc["ran"] as? String ?? "no sign"
                prop("Ran on this Mac", ran == "yes" ? "Yes" : ran == "possibly" ? "Possibly" : "No sign", tint: ran == "no sign" ? nil : DT.orange)
                prop("Auto-respond", inc["mode"] as? String == "observe" ? "Report only" : "Contain")
                ForEach((inc["repos"] as? [JSON] ?? []).compactMap { ($0["path"] as? String).map { ($0 as NSString).lastPathComponent } }, id: \.self) { Pill(text: $0, icon: "folder") }
            }
        }
    }

    private func prop(_ label: String, _ value: String, tint: Color? = nil) -> some View {
        HStack(spacing: 5) {
            Text(label).font(uiFont(11, .medium)).foregroundStyle(DT.dim)
            Text(value).font(uiFont(11, .semibold)).foregroundStyle(tint ?? DT.text)
        }
        .padding(.horizontal, 8).frame(height: 20)
        .background(DT.surface2, in: RoundedRectangle(cornerRadius: 5, style: .continuous))
    }

    private var inShort: some View {
        let ran = inc["ran"] as? String ?? "no sign"
        let observe = inc["mode"] as? String == "observe"
        let did = observe ? "Auto-respond is set to report only, so I investigated and changed nothing." : "I contained what I could prove."
        let text: String = {
            switch ran {
            case "yes": return "The malware ran on this Mac. \(did) Here's what's left for you."
            case "possibly": return "The malware may have run on this Mac. \(did) Here's what's left for you."
            default: return "No sign it ran on this Mac. It would run the moment a dev server, build or test loads the infected file, so clean it up before anyone does."
            }
        }()
        return HStack(alignment: .top, spacing: 14) {
            RoundedRectangle(cornerRadius: 1.5).fill(ran == "no sign" ? DT.green : DT.orange).frame(width: 3)
            VStack(alignment: .leading, spacing: 4) {
                Text("In short").font(uiFont(12, .semibold)).foregroundStyle(DT.dim)
                Text(text).font(uiFont(15)).foregroundStyle(DT.text).lineSpacing(2).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }.fixedSize(horizontal: false, vertical: true)
    }

    private var allDone: some View {
        HStack(spacing: 12) {
            Image(systemName: "checkmark.circle.fill").font(.system(size: 18)).foregroundStyle(DT.green)
            VStack(alignment: .leading, spacing: 2) {
                Text("Everything on the list is done").font(uiFont(13, .semibold)).foregroundStyle(DT.text)
                Text("I checked again. Nothing from this incident is left.").font(uiFont(12)).foregroundStyle(DT.dim)
            }
            Spacer()
            if let id = inc["id"] as? String {
                Button { store.run("resolve", ["incident", "resolve", id], done: "\(id) marked resolved.") } label: { Label("Mark resolved", systemImage: "checkmark") }
                    .buttonStyle(PrimaryButton())
            }
        }
        .padding(16)
        .background(DT.green.opacity(0.07), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(DT.green.opacity(0.3)))
    }

    private var todos: some View {
        let ticked = Set(inc["ticked"] as? [String] ?? [])
        let list = (inc["todos"] as? [JSON] ?? []).filter {
            !(($0["cmd"] as? String) ?? "").hasPrefix("bastion incident resolve") && !ticked.contains($0["key"] as? String ?? "")
        }
        return PageSection(title: "What's left for you", count: list.isEmpty ? nil : "\(list.count)") {
            if list.isEmpty {
                Text("Nothing. Mark the incident resolved when you're ready.").font(uiFont(13)).foregroundStyle(DT.dim)
            } else {
                RowGroup {
                    ForEach(Array(list.enumerated()), id: \.offset) { n, t in
                        if n > 0 { Hairline() }
                        todoRow(t)
                    }
                }
            }
        }
    }

    private func todoRow(_ t: JSON) -> some View {
        let key = t["key"] as? String ?? ""
        let live = store.todos.first { $0["id"] as? String == t["item_id"] as? String }
        return HStack(alignment: .top, spacing: 12) {
            Button { if !key.hasPrefix("branch:"), let id = inc["id"] as? String { store.tick(id, key) } } label: {
                Circle().strokeBorder(DT.dim, lineWidth: 1.5).frame(width: 16, height: 16)
            }.buttonStyle(.plain).padding(.top, 1)
                .help(key.hasPrefix("branch:") ? "Ticks itself once Bastion sees the branch fixed" : "Mark done")
            VStack(alignment: .leading, spacing: 6) {
                Text(t["title"] as? String ?? "").font(uiFont(13, .semibold)).foregroundStyle(DT.text).fixedSize(horizontal: false, vertical: true)
                if let why = t["why"] as? String, !why.isEmpty { Text(why).font(uiFont(13)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true) }
                if let how = t["how"] as? String, !how.isEmpty { Text(how).font(uiFont(13)).foregroundStyle(DT.text2).fixedSize(horizontal: false, vertical: true) }
                if let cmd = t["cmd"] as? String, !cmd.isEmpty { CommandBlock(text: cmd).padding(.top, 2) }
                HStack(spacing: 8) {
                    if let live, (live["fix"] as? JSON)?["runnable"] as? Bool == true {
                        let busy = store.busy.contains("fix:" + (live["id"] as? String ?? ""))
                        Button { store.fix(live) } label: { Text(busy ? "Working" : ((live["fix"] as? JSON)?["button"] as? String ?? "Fix it")) }
                            .buttonStyle(PrimaryButton()).disabled(busy)
                    }
                    if let link = t["link"] as? String, let url = URL(string: link) {
                        Button { NSWorkspace.shared.open(url) } label: { Label("See it on GitHub", systemImage: "arrow.up.right") }.buttonStyle(SecondaryButton())
                    }
                    if !key.hasPrefix("branch:"), let id = inc["id"] as? String {
                        Button { store.tick(id, key) } label: { Label("Mark done", systemImage: "checkmark") }.buttonStyle(SecondaryButton())
                    }
                }.padding(.top, 2)
            }
            Spacer(minLength: 0)
        }.padding(16)
    }

    private var did: some View {
        let done = actions.filter { ["done", "undone"].contains($0["status"] as? String ?? "") }
        return PageSection(title: "What I did") {
            if done.isEmpty {
                Text(inc["mode"] as? String == "observe" ? "Nothing yet. Auto-respond is set to report only, so I investigated and changed nothing." : "Nothing automatic was safe to do here.")
                    .font(uiFont(13)).foregroundStyle(DT.dim)
            } else {
                Steps(items: done.map { a in (a["status"] as? String == "undone" ? "Undone: " : "") + (a["detail"] as? String ?? "") }, tint: DT.green)
            }
        }
    }

    private var evidence: some View {
        PageSection(title: "The evidence") {
            VStack(alignment: .leading, spacing: 10) {
                ForEach(Array((inc["branch_details"] as? [JSON] ?? []).enumerated()), id: \.offset) { _, b in branchBlock(b) }
                ForEach(Array((inc["repos"] as? [JSON] ?? []).enumerated()), id: \.offset) { _, repo in
                    ForEach(Array((repo["files"] as? [JSON] ?? []).enumerated()), id: \.offset) { _, f in fileBlock(f, repo: repo["path"] as? String ?? "") }
                    ForEach(Array((repo["hooks"] as? [JSON] ?? []).enumerated()), id: \.offset) { _, h in
                        note("exclamationmark.triangle.fill", DT.orange, h["title"] as? String ?? "", tildePath(h["path"] as? String ?? ""), h["explanation"] as? String ?? "")
                    }
                }
                ForEach(Array((inc["machine"] as? [JSON] ?? []).enumerated()), id: \.offset) { _, m in
                    note("exclamationmark.octagon.fill", DT.red, m["title"] as? String ?? "", tildePath(m["path"] as? String ?? (m["ip"] as? String) ?? ""), m["explanation"] as? String ?? "")
                }
            }
        }
    }

    private func block<C: View>(@ViewBuilder _ content: () -> C) -> some View {
        VStack(alignment: .leading, spacing: 8) { content() }
            .padding(16).frame(maxWidth: .infinity, alignment: .leading)
            .background(DT.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(DT.border))
    }

    private func codeBox(_ text: String) -> some View {
        Text(text).font(codeFont(12)).foregroundStyle(DT.text2).lineSpacing(2)
            .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            .padding(10).frame(maxWidth: .infinity, alignment: .leading)
            .background(DT.sunken, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    }

    private func branchBlock(_ b: JSON) -> some View {
        block {
            HStack(spacing: 8) {
                Image(systemName: "arrow.triangle.branch").font(.system(size: 12)).foregroundStyle(DT.orange)
                Text(b["ref"] as? String ?? "").font(codeFont(13, .medium)).foregroundStyle(DT.text).textSelection(.enabled)
                Text(tildePath(b["repo"] as? String ?? "")).font(uiFont(12)).foregroundStyle(DT.faint)
                Spacer()
                if let d = b["default_branch"] as? String, b["default_clean"] as? Bool == true { Tag(text: "\(d) is clean", tint: DT.green) }
            }
            if let c = b["last_commit"] as? JSON {
                Text("Last commit \(c["short"] as? String ?? "") by \(c["author"] as? String ?? ""), \(shortTime(c["date"])): “\(c["subject"] as? String ?? "")”")
                    .font(uiFont(13)).foregroundStyle(DT.dim).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            }
            ForEach(Array((b["proof"] as? [JSON] ?? []).enumerated()), id: \.offset) { _, p in
                codeBox("\(p["file"] as? String ?? ""): \(p["text"] as? String ?? "")")
            }
        }
    }

    private func note(_ icon: String, _ tint: Color, _ title: String, _ target: String, _ why: String) -> some View {
        block {
            HStack(spacing: 8) { Image(systemName: icon).foregroundStyle(tint).font(.system(size: 12)); Text(title).font(uiFont(13, .semibold)).foregroundStyle(DT.text) }
            Text(target).font(codeFont(12)).foregroundStyle(DT.dim).textSelection(.enabled)
            if !why.isEmpty { Text(why).font(uiFont(13)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true) }
        }
    }

    private func fileBlock(_ f: JSON, repo: String) -> some View {
        block {
            HStack(spacing: 8) {
                Image(systemName: "doc.text").font(.system(size: 12)).foregroundStyle(DT.red)
                Text(f["rel"] as? String ?? "").font(codeFont(13, .medium)).foregroundStyle(DT.text).textSelection(.enabled)
                Text(tildePath(repo)).font(uiFont(12)).foregroundStyle(DT.faint)
                Spacer()
                if let a = f["action"] as? String { Tag(text: a == "restored" ? "Cleaned" : "Needs you", tint: a == "restored" ? DT.accent : DT.orange) }
            }
            if let c = f["introduced_by"] as? JSON {
                (Text("Planted in ").foregroundColor(DT.dim)
                 + Text(c["short"] as? String ?? "").font(codeFont(12, .medium)).foregroundColor(DT.text)
                 + Text(" by ").foregroundColor(DT.dim)
                 + Text("\(c["committer"] as? String ?? "") <\(c["committer_email"] as? String ?? "")>").foregroundColor(DT.text)
                 + Text(", \(shortTime(c["date"])): “\(c["subject"] as? String ?? "")”").foregroundColor(DT.dim))
                    .font(uiFont(13)).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                let local = f["branches"] as? [String] ?? [], remote = f["remote_branches"] as? [String] ?? []
                if !(local + remote).isEmpty {
                    FlowRow {
                        ForEach(local, id: \.self) { b in Pill(text: b, icon: "arrow.triangle.branch", mono: true) }
                        ForEach(remote, id: \.self) { b in Pill(text: b, dot: DT.orange, mono: true) }
                    }
                }
            } else if f["tracked"] as? Bool == true {
                Text("Not committed. Something on this Mac wrote it straight to disk.").font(uiFont(13)).foregroundStyle(DT.orange)
            } else {
                Text("Not tracked by git.").font(uiFont(13)).foregroundStyle(DT.dim)
            }
            if let proof = f["evidence_text"] as? String, !proof.isEmpty {
                codeBox(proof)
            } else {
                Text("Payload signs: \(f["detail"] as? String ?? "")").font(codeFont(12)).foregroundStyle(DT.faint)
            }
        }
    }

    private var doneList: some View {
        let done = inc["done"] as? [JSON] ?? []
        return PageSection(title: "Done", count: "\(done.count)") {
            RowGroup {
                ForEach(done.indices, id: \.self) { i in
                    if i > 0 { Hairline() }
                    HStack(spacing: 12) {
                        Image(systemName: "checkmark.circle.fill").font(.system(size: 14)).foregroundStyle(DT.green)
                        Text(done[i]["title"] as? String ?? "").font(uiFont(13)).foregroundStyle(DT.dim).strikethrough(true, color: DT.faint)
                        Spacer()
                        Text(done[i]["how"] as? String == "ticked" ? "Marked done" : "Fixed and checked").font(uiFont(12)).foregroundStyle(DT.faint)
                        Text(ago(done[i]["time"])).font(uiFont(12)).foregroundStyle(DT.faint).monospacedDigit()
                    }.padding(.horizontal, 16).frame(height: 44)
                }
            }
        }
    }

    @ViewBuilder private var details: some View {
        let hunt = inc["hunt"] as? [JSON] ?? []
        let indicators = inc["indicators"] as? [JSON] ?? []
        if !hunt.isEmpty || !indicators.isEmpty {
            HStack(alignment: .top, spacing: 16) {
                if !hunt.isEmpty {
                    PageSection(title: "Planted by") {
                        RowGroup {
                            VStack(alignment: .leading, spacing: 10) {
                                ForEach(Array(hunt.enumerated()), id: \.offset) { _, h in
                                    let identity = h["identity"] as? String ?? ""
                                    HStack(spacing: 8) {
                                        Avatar(name: identity, color: h["own"] as? Bool == true ? DT.blue : DT.orange)
                                        Text(identity).font(uiFont(13)).foregroundStyle(DT.text).lineLimit(2).textSelection(.enabled)
                                    }
                                    let others = (h["repos"] as? [JSON] ?? []).reduce(0) { $0 + ($1["count"] as? Int ?? 0) }
                                    if others > 0 { Text("\(others) commit\(others == 1 ? "" : "s") across \((h["repos"] as? [Any])?.count ?? 0) repos").font(uiFont(12)).foregroundStyle(DT.dim) }
                                }
                            }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
                if !indicators.isEmpty {
                    PageSection(title: "Attacker addresses") {
                        RowGroup {
                            VStack(alignment: .leading, spacing: 8) {
                                ForEach(Array(indicators.enumerated()), id: \.offset) { _, i in
                                    HStack {
                                        Text(i["value"] as? String ?? "").font(codeFont(12)).foregroundStyle(DT.text).textSelection(.enabled)
                                        Spacer()
                                        let st = (i["status"] as? String ?? "").replacingOccurrences(of: "_", with: " ")
                                        Tag(text: st.capitalized, tint: st.contains("blocked") ? DT.green : DT.orange)
                                    }
                                }
                            }.padding(16)
                        }
                    }
                }
            }
        }
    }

    private var timeline: some View {
        PageSection(title: "Timeline") {
            VStack(alignment: .leading, spacing: 10) {
                ForEach(Array((inc["timeline"] as? [JSON] ?? []).enumerated()), id: \.offset) { _, e in
                    HStack(alignment: .firstTextBaseline, spacing: 12) {
                        Text(shortTime(e["time"])).font(uiFont(12)).foregroundStyle(DT.faint).monospacedDigit().frame(width: 96, alignment: .leading)
                        Text(e["event"] as? String ?? "").font(uiFont(13)).foregroundStyle(DT.text2).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
    }
}

/// A vertical run of dots and sentences, like an agent's work log
struct Steps: View {
    let items: [String]
    var tint: Color = DT.green
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(items.enumerated()), id: \.offset) { i, text in
                HStack(alignment: .top, spacing: 12) {
                    VStack(spacing: 0) {
                        Circle().fill(tint).frame(width: 7, height: 7).padding(.top, 5)
                        if i < items.count - 1 { Rectangle().fill(DT.border).frame(width: 1).frame(maxHeight: .infinity).padding(.top, 4) }
                    }.frame(width: 8)
                    Text(text).font(uiFont(13)).foregroundStyle(DT.text).fixedSize(horizontal: false, vertical: true)
                        .padding(.bottom, i < items.count - 1 ? 14 : 0)
                    Spacer(minLength: 0)
                }.fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

// MARK: - Repositories: a grid of cards, or a list

struct ReposPage: View {
    @ObservedObject var store: AppStore
    @State private var query = ""
    @State private var filter = "all"
    @AppStorage("reposLayout") private var layout = "grid"
    private func needsAttention(_ r: JSON) -> Bool { (r["findings"] as? Int ?? 0) > 0 || (r["infected_branches"] as? Int ?? 0) > 0 }
    private func unguarded(_ r: JSON) -> Bool { ["unprotected", "husky"].contains(r["git_guard"] as? String ?? "") }
    private var shown: [JSON] {
        store.repos.filter { r in
            (filter == "all" || (filter == "attention" && needsAttention(r)) || (filter == "unguarded" && unguarded(r)))
                && (query.isEmpty || (r["name"] as? String ?? "").localizedCaseInsensitiveContains(query) || (r["path"] as? String ?? "").localizedCaseInsensitiveContains(query))
        }
        .sorted { a, b in
            let x = needsAttention(a) ? 0 : 1, y = needsAttention(b) ? 0 : 1
            let an = (a["name"] as? String ?? "").trimmingCharacters(in: CharacterSet(charactersIn: "."))
            let bn = (b["name"] as? String ?? "").trimmingCharacters(in: CharacterSet(charactersIn: "."))
            return x != y ? x < y : an.localizedCaseInsensitiveCompare(bn) == .orderedAscending
        }
    }
    var body: some View {
        VStack(spacing: 0) {
            TopBar(crumbs: ["Repositories"]) {
                HStack(spacing: 8) {
                    if (store.status["git_guard"] as? JSON)?["unprotected"] as? Int ?? 0 > 0 {
                        Button { store.run("gitguard", ["enable", "git-guard"]) } label: { Label("Guard all on push", systemImage: "hand.raised") }.buttonStyle(SecondaryButton())
                    }
                    Button { store.scan() } label: { Label(store.busy.contains("scan") ? "Scanning" : "Scan all", systemImage: "magnifyingglass") }
                        .buttonStyle(PrimaryButton()).disabled(store.busy.contains("scan"))
                }
            }
            HStack(spacing: 12) {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundStyle(DT.faint)
                    TextField("Search repositories", text: $query).textFieldStyle(.plain).font(uiFont(13))
                }
                .padding(.horizontal, 10).frame(width: 260, height: 32)
                .background(DT.surface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(DT.border))
                Segmented(items: [("all", "All", store.repos.count), ("attention", "Needs attention", store.repos.filter(needsAttention).count),
                                  ("unguarded", "Not guarded", store.repos.filter(unguarded).count)], selection: $filter)
                Spacer()
                HStack(spacing: 2) {
                    layoutButton("grid", "square.grid.2x2")
                    layoutButton("list", "list.bullet")
                }.padding(2).background(DT.surface2, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
            }.padding(.horizontal, 20).frame(height: 56)
            Hairline()
            if store.repos.isEmpty {
                EmptyState(icon: "folder", title: store.loaded ? "No repositories" : "Looking for repositories", text: "Bastion watches every git repository in your home folder.")
            } else if shown.isEmpty {
                EmptyState(icon: "line.3.horizontal.decrease.circle", title: "Nothing matches", text: "No repository matches this search and filter.")
            } else if layout == "grid" {
                ScrollView {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 272), spacing: 16)], spacing: 16) {
                        ForEach(Array(shown.enumerated()), id: \.offset) { _, r in RepoCard(store: store, repo: r) }
                    }.padding(20)
                }
            } else {
                ScrollView {
                    RowGroup {
                        ForEach(Array(shown.enumerated()), id: \.offset) { i, r in
                            if i > 0 { Hairline() }
                            RepoRow(store: store, repo: r)
                        }
                    }.padding(20)
                }
            }
        }
    }
    private func layoutButton(_ id: String, _ icon: String) -> some View {
        Button { layout = id } label: {
            Image(systemName: icon).font(.system(size: 12, weight: .medium)).foregroundStyle(layout == id ? DT.text : DT.dim)
                .frame(width: 28, height: 26)
                .background(layout == id ? DT.panel : .clear, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                .contentShape(Rectangle())
        }.buttonStyle(.plain).help(id == "grid" ? "Cards" : "List")
    }
}

/// One repository's health, in words and a colour, shared by the card and the row
struct RepoHealth {
    let text: String, tint: Color, icon: String, help: String
    @MainActor init(_ store: AppStore, _ repo: JSON) {
        let path = repo["path"] as? String ?? ""
        if let c = store.checks[path] {
            let refs = c["infected_branch_refs"] as? [String] ?? []
            let on = (c["current_branch"] as? String).map { " on \($0)" } ?? ""
            if c["safe_to_run"] as? Bool != true {
                let n = (c["findings"] as? [Any])?.count ?? 0
                (text, tint, icon, help) = ("Not safe to run: \(n) problem\(n == 1 ? "" : "s")", DT.red, "xmark.octagon.fill", "Don't run npm here until it's fixed.")
            } else if refs.isEmpty {
                (text, tint, icon, help) = ("Safe to run\(on)", DT.green, "checkmark.circle.fill", "Just checked. Nothing suspicious.")
            } else {
                (text, tint, icon, help) = ("Safe\(on). \(refs.count) infected branch\(refs.count == 1 ? "" : "es")", DT.orange, "exclamationmark.circle.fill",
                                            "\(refs.joined(separator: ", ")) \(refs.count == 1 ? "carries" : "carry") malware. Don't check \(refs.count == 1 ? "it" : "them") out or merge \(refs.count == 1 ? "it" : "them").")
            }
        } else if let n = repo["findings"] as? Int, n > 0 {
            (text, tint, icon, help) = ("Not safe to run: \(n) finding\(n == 1 ? "" : "s")", DT.red, "xmark.octagon.fill", "Don't run npm here until it's fixed.")
        } else if let b = repo["infected_branches"] as? Int, b > 0 {
            let files = repo["infected_branch_files"] as? Int ?? b
            (text, tint, icon, help) = ("\(b) infected branch\(b == 1 ? "" : "es"), not running", DT.orange, "exclamationmark.circle.fill",
                                        "\(files) file\(files == 1 ? "" : "s") on \(b) branch\(b == 1 ? "" : "es") that \(b == 1 ? "isn't" : "aren't") checked out. Nothing runs unless someone switches to \(b == 1 ? "it" : "one") and runs npm.")
        } else {
            (text, tint, icon, help) = ("Clean", DT.green, "checkmark.circle.fill", "Nothing found in the last scan.")
        }
    }
}

func guardLabel(_ g: String) -> (text: String, tint: Color, help: String) {
    switch g {
    case "protected": return ("Guarded", DT.green, "Push guard on: a git hook refuses to push a commit that carries the payload.")
    case "unprotected": return ("Not guarded", DT.orange, "Push guard off. Turn it on with “Guard all on push”.")
    case "husky": return ("Not guarded", DT.orange, "This repo manages git hooks with husky. Use ⋯ › Guard on push to add Bastion's check to .husky/pre-push.")
    default: return ("Own hooks", DT.dim, "This repo runs its own git hooks, so Bastion doesn't add one automatically.")
    }
}

struct RepoMenu: View {
    @ObservedObject var store: AppStore
    let repo: JSON
    var body: some View {
        let path = repo["path"] as? String ?? "", name = repo["name"] as? String ?? ""
        Menu {
            Button("Hunt git history") { store.present("History · \(name)", "history:" + path, ["history", path]) }
            Button("Check dependencies") { store.present("Dependencies · \(name)", "deps:" + path, ["deps", path]) }
            if repo["git_guard"] as? String == "husky" {
                Button("Guard on push (husky)…") {
                    store.ask("Guard \(name) on push?", "Bastion adds 2 lines to .husky/pre-push. Commit the change so the check stays part of the repo. It does nothing on machines without Bastion.", button: "Add") {
                        store.run("husky:" + path, ["enable", "git-guard", "--husky", path])
                    }
                }
            }
            if repo["pr_guard"] as? Bool != true {
                Button("Add the Team PR guard…") {
                    store.ask("Add the PR guard to \(name)?", "Bastion writes .github/workflows/bastion.yml. Commit and push it yourself, and every pull request is checked from then on.", button: "Add") {
                        store.run("ci:" + path, ["ci-setup", path, "--write"], done: "Added .github/workflows/bastion.yml. Commit and push it.")
                    }
                }
            }
            Divider()
            Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)]) }
        } label: { Image(systemName: "ellipsis").font(.system(size: 12, weight: .semibold)).foregroundStyle(DT.dim).frame(width: 26, height: 26) }
            .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
    }
}

struct RepoCard: View {
    @ObservedObject var store: AppStore
    let repo: JSON
    @State private var hover = false
    var body: some View {
        let path = repo["path"] as? String ?? "", name = repo["name"] as? String ?? ""
        let health = RepoHealth(store, repo)
        let g = guardLabel(repo["git_guard"] as? String ?? "")
        let checking = store.busy.contains("check:" + path)
        let attention = (repo["findings"] as? Int ?? 0) > 0 || (repo["infected_branches"] as? Int ?? 0) > 0
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 12) {
                Text(String(name.trimmingCharacters(in: CharacterSet(charactersIn: "."))).prefix(1).uppercased())
                    .font(uiFont(13, .semibold)).foregroundStyle(DT.text2)
                    .frame(width: 32, height: 32).background(DT.surface2, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                VStack(alignment: .leading, spacing: 2) {
                    Text(name).font(uiFont(13, .semibold)).foregroundStyle(DT.text).lineLimit(1)
                    Text(tildePath(path)).font(codeFont(11)).foregroundStyle(DT.faint).lineLimit(1).truncationMode(.middle)
                }
                Spacer(minLength: 4)
                Image(systemName: health.icon).font(.system(size: 14)).foregroundStyle(health.tint).help(health.help)
            }
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 6) {
                    Pill(text: repo["branch"] as? String ?? "", icon: "arrow.triangle.branch", mono: true).layoutPriority(-1)
                    Pill(text: g.text, dot: g.tint).help(g.help).fixedSize()
                }
                Text(health.text).font(uiFont(12)).foregroundStyle(health.tint == DT.green ? DT.dim : health.tint).lineLimit(1).help(health.help)
            }
            HStack(spacing: 8) {
                Button { store.check(path) } label: { Text(checking ? "Checking" : "Check") }.buttonStyle(SecondaryButton()).disabled(checking)
                if attention { Button { Router.shared.openNeedsYou() } label: { Text("Review") }.buttonStyle(PrimaryButton()) }
                Spacer()
                RepoMenu(store: store, repo: repo)
            }
        }
        .padding(16)
        .background(DT.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(hover ? DT.dim.opacity(0.4) : DT.border))
        .shadow(color: hover ? DT.shadow : .clear, radius: 6, y: 2)
        .onHover { hover = $0 }
    }
}

struct RepoRow: View {
    @ObservedObject var store: AppStore
    let repo: JSON
    var body: some View {
        let path = repo["path"] as? String ?? ""
        let health = RepoHealth(store, repo)
        let g = guardLabel(repo["git_guard"] as? String ?? "")
        return HStack(spacing: 12) {
            Image(systemName: health.icon).font(.system(size: 13)).foregroundStyle(health.tint).frame(width: 18).help(health.help)
            VStack(alignment: .leading, spacing: 2) {
                Text(repo["name"] as? String ?? "").font(uiFont(13, .medium)).foregroundStyle(DT.text)
                Text(tildePath(path)).font(codeFont(11)).foregroundStyle(DT.faint).lineLimit(1).truncationMode(.middle)
            }.frame(maxWidth: .infinity, alignment: .leading)
            Text(health.text).font(uiFont(12)).foregroundStyle(DT.text2).lineLimit(1).frame(width: 220, alignment: .leading).help(health.help)
            Text(repo["branch"] as? String ?? "").font(codeFont(12)).foregroundStyle(DT.text2).lineLimit(1).frame(width: 120, alignment: .leading)
            HStack(spacing: 6) {
                Circle().fill(g.tint).frame(width: 6, height: 6)
                Text(g.text).font(uiFont(12)).foregroundStyle(DT.text2).lineLimit(1)
            }.frame(width: 100, alignment: .leading).help(g.help)
            HStack(spacing: 4) {
                Button(store.busy.contains("check:" + path) ? "Checking" : "Check") { store.check(path) }
                    .buttonStyle(SecondaryButton()).disabled(store.busy.contains("check:" + path))
                RepoMenu(store: store, repo: repo)
            }.frame(width: 110, alignment: .trailing)
        }.padding(.horizontal, 16).frame(height: 56).hoverRow(radius: 0)
    }
}

// MARK: - Activity

struct ActivityPage: View {
    @ObservedObject var store: AppStore
    @State private var query = ""
    private var days: [(String, [JSON])] {
        let events = query.isEmpty ? store.activity : store.activity.filter { said($0).localizedCaseInsensitiveContains(query) || ($0["message"] as? String ?? "").localizedCaseInsensitiveContains(query) }
        var out: [(String, [JSON])] = []
        let f = DateFormatter(); f.dateFormat = "EEEE, MMM d"
        for e in events {
            let d = parseDate(e["time"])
            let label = d.map { Calendar.current.isDateInToday($0) ? "Today" : Calendar.current.isDateInYesterday($0) ? "Yesterday" : f.string(from: $0) } ?? "Earlier"
            if out.last?.0 == label { out[out.count - 1].1.append(e) } else { out.append((label, [e])) }
        }
        return out
    }
    var body: some View {
        VStack(spacing: 0) {
            TopBar(crumbs: ["Activity"]) {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundStyle(DT.faint)
                    TextField("Filter", text: $query).textFieldStyle(.plain).font(uiFont(13)).frame(width: 180)
                }.padding(.horizontal, 10).frame(height: 28)
                .background(DT.surface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(DT.border))
            }
            if days.isEmpty {
                EmptyState(icon: "clock.arrow.circlepath", title: query.isEmpty ? "No activity yet" : "Nothing matches “\(query)”", text: "Everything Bastion catches, blocks, fixes or changes shows up here.")
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 28) {
                        ForEach(Array(days.enumerated()), id: \.offset) { _, day in
                            VStack(alignment: .leading, spacing: 10) {
                                Text(day.0).font(uiFont(13, .semibold)).foregroundStyle(DT.text).padding(.leading, 2)
                                RowGroup {
                                    ForEach(Array(day.1.enumerated()), id: \.offset) { i, e in
                                        if i > 0 { Hairline() }
                                        ActivityRow(event: e, open: activityTarget(e, in: store.activity))
                                    }
                                }
                            }
                        }
                    }
                    .padding(.horizontal, 32).padding(.vertical, 28).frame(maxWidth: 900).frame(maxWidth: .infinity)
                }
            }
        }
    }
}

// MARK: - Quarantine

struct QuarantinePage: View {
    @ObservedObject var store: AppStore
    var body: some View {
        VStack(spacing: 0) {
            TopBar(crumbs: ["Quarantine"])
            if store.quarantine.isEmpty {
                EmptyState(icon: "archivebox", title: "Nothing in quarantine", text: "Known-malicious leftovers and infected copies are moved here, never deleted, so you can look at them or put them back.", tint: DT.green)
            } else {
                PageBody(width: 900) {
                    PageSection(title: "Quarantined", count: "\(store.quarantine.count)", note: "Moved here, never deleted. Restore a batch only if Bastion got it wrong.") {
                        RowGroup {
                            ForEach(Array(store.quarantine.enumerated()), id: \.offset) { i, item in
                                if i > 0 { Hairline() }
                                row(item)
                            }
                        }
                    }
                }
            }
        }
    }
    private func row(_ item: JSON) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "archivebox.fill").font(.system(size: 11)).foregroundStyle(DT.orange)
                .frame(width: 28, height: 28).background(DT.orange.opacity(0.11), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            VStack(alignment: .leading, spacing: 2) {
                Text(tildePath(item["original_path"] as? String ?? item["stored_at"] as? String ?? "")).font(codeFont(12)).foregroundStyle(DT.text).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                Text("Batch \(item["id"] as? String ?? "") · \(shortTime(item["time"]))").font(uiFont(12)).foregroundStyle(DT.faint)
            }
            Spacer()
            Tag(text: (item["reason"] as? String ?? "").replacingOccurrences(of: "-", with: " ").replacingOccurrences(of: "_", with: " "), tint: DT.orange)
            IconButton(icon: "folder", help: "Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: item["stored_at"] as? String ?? "")]) }
            if item["original_path"] != nil, let batch = item["id"] as? String {
                Button("Restore") {
                    store.ask("Restore batch \(batch)?", "Everything in it goes back where it was. Only do this if Bastion got it wrong.", button: "Restore") {
                        store.run("restore", ["quarantine", "restore", batch, "--yes"])
                    }
                }.buttonStyle(SecondaryButton())
            }
        }.padding(.horizontal, 16).frame(height: 60).hoverRow(radius: 0)
    }
}

// MARK: - AI agents

struct AgentsPage: View {
    @ObservedObject var store: AppStore
    private let tools: [(String, String)] = [
        ("bastion_check_path", "Is it safe to run npm here? Checks one project in about a second."),
        ("bastion_respond", "Investigates, contains what it can prove (with undo) and returns an incident report."),
        ("bastion_todos", "What needs the person, with proof and the fix."),
        ("bastion_status", "Is this Mac protected right now?"),
        ("bastion_scan", "Sweeps every repo plus temp folders, processes and network."),
        ("bastion_incidents, bastion_incident", "Incident history and full reports."),
        ("bastion_findings, activity, quarantine, lists", "Everything else Bastion knows, read-only."),
        ("bastion_enable", "Turns a protection on. Agents can never turn one off."),
        ("bastion_block_indicator", "Blocks an attacker address, only when an incident found it in malware."),
    ]
    var body: some View {
        let found = store.agents.filter { $0["installed"] as? Bool == true }
        let linked = found.contains { $0["connected"] as? Bool == true }
        let bin = store.connect["command"] as? String ?? BASTION_CLI
        let short = bin.hasPrefix(HOME_DIR + "/") && !bin.contains(" ") ? tildePath(bin) : "\"\(bin)\""
        VStack(spacing: 0) {
            TopBar(crumbs: ["AI agents"])
            PageBody(width: 860) {
                HStack(alignment: .top, spacing: 16) {
                    AgentFace(tint: linked ? DT.green : DT.ink, size: 44)
                    VStack(alignment: .leading, spacing: 6) {
                        Text(linked ? "Your coding agent works with Bastion" : "Connect your coding agent").font(.system(size: 20, weight: .semibold)).tracking(-0.3).foregroundStyle(DT.text)
                        Text("Bastion runs as an MCP server. A connected agent checks a repository with Bastion before it runs install, dev, build or test there, and can hand problems to Bastion.")
                            .font(uiFont(13)).foregroundStyle(DT.dim).lineSpacing(1.5).fixedSize(horizontal: false, vertical: true)
                    }
                }
                if !found.isEmpty {
                    PageSection(title: "Your agents", count: "\(found.count)") {
                        RowGroup {
                            ForEach(found.indices, id: \.self) { i in
                                if i > 0 { Hairline() }
                                agentRow(found[i])
                            }
                        }
                    }
                }
                let installed = Set(found.compactMap { $0["id"] as? String })
                let guards = [("claude", "Claude Code", "~/.claude/settings.json"), ("cursor", "Cursor", "~/.cursor/hooks.json")]
                    .filter { store.agents.isEmpty || installed.contains($0.0) }
                PageSection(title: "Hard-guard", note: "A hook that stops an agent's install, dev, build or test command before it runs in an unsafe repo. Enforced, not just asked.") {
                    if guards.isEmpty {
                        Text("Neither Claude Code nor Cursor is installed on this Mac.").font(uiFont(13)).foregroundStyle(DT.faint)
                    } else {
                        RowGroup {
                            ForEach(guards.indices, id: \.self) { i in
                                if i > 0 { Hairline() }
                                guardRow(guards[i].0, guards[i].1, guards[i].2)
                            }
                        }
                    }
                }
                PageSection(title: "Set it up by hand", note: "For any other MCP client, or if you'd rather edit the config yourself.") {
                    VStack(alignment: .leading, spacing: 16) {
                        setup("Claude Code", "Run once in a terminal.", "claude mcp add --scope user bastion -- \(short) mcp")
                        setup("Cursor, Claude Desktop, Windsurf", "Add to the mcpServers section of the app's MCP config.", "\"bastion\": { \"command\": \"\(bin)\", \"args\": [\"mcp\"] }")
                        setup("Codex CLI", "Add to ~/.codex/config.toml.", "[mcp_servers.bastion]\ncommand = \"\(bin)\"\nargs = [\"mcp\"]")
                    }
                }
                PageSection(title: "What your agent gets") {
                    RowGroup {
                        ForEach(Array(tools.enumerated()), id: \.offset) { i, t in
                            if i > 0 { Hairline() }
                            HStack(alignment: .firstTextBaseline, spacing: 16) {
                                Text(t.0).font(codeFont(12, .medium)).foregroundStyle(DT.text).frame(width: 280, alignment: .leading)
                                Text(t.1).font(uiFont(13)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true)
                                Spacer(minLength: 0)
                            }.padding(.horizontal, 16).padding(.vertical, 12)
                        }
                    }
                }
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "lock.shield").font(.system(size: 13)).foregroundStyle(DT.green)
                    Text("Agents can make you safer, never less safe. Turning protection off, trusting a host, ignoring a path and restoring quarantine stay with you, and every change is logged and announced.")
                        .font(uiFont(12)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
    private func agentRow(_ a: JSON) -> some View {
        let id = a["id"] as? String ?? "", name = a["name"] as? String ?? ""
        let on = a["connected"] as? Bool ?? false
        return HStack(spacing: 12) {
            Image(systemName: on ? "checkmark.circle.fill" : "circle.dashed").font(.system(size: 15)).foregroundStyle(on ? DT.green : DT.dim).frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(name).font(uiFont(13, .medium)).foregroundStyle(DT.text)
                Text(on ? "Connected" + ((a["hard_guard"] as? Bool) == true ? " and hard-guarded" : "")
                        : "Not connected. Settings file: \(a["config"] as? String ?? "")").font(uiFont(12)).foregroundStyle(DT.dim)
            }
            Spacer()
            if store.busy.contains("connect:" + id) { ProgressView().controlSize(.small).scaleEffect(0.7) }
            if !on {
                if a["can_connect"] as? Bool == true {
                    Button("Connect") { store.run("connect:" + id, ["connect", id, "--write"]) }.buttonStyle(PrimaryButton())
                } else if let cmd = a["connect_command"] as? String {
                    Button { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(cmd, forType: .string); store.flash("Copied. Run it in a terminal where Claude Code's `claude` command works.") } label: {
                        Label("Copy command", systemImage: "doc.on.doc")
                    }.buttonStyle(SecondaryButton()).help(cmd)
                }
            }
        }.padding(.horizontal, 16).padding(.vertical, 12)
    }

    private func guardRow(_ agent: String, _ name: String, _ file: String) -> some View {
        let on = store.hooks[agent] as? Bool ?? false
        return HStack(spacing: 12) {
            Image(systemName: on ? "checkmark.shield.fill" : "shield").font(.system(size: 13)).foregroundStyle(on ? DT.green : DT.dim).frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(name).font(uiFont(13, .medium)).foregroundStyle(DT.text)
                Text(on ? "Guarded. Unsafe repos are blocked." : "Adds a hook to \(file). A backup is kept.").font(uiFont(12)).foregroundStyle(DT.dim)
            }
            Spacer()
            if store.busy.contains("hook:" + agent) { ProgressView().controlSize(.small).scaleEffect(0.7) }
            if on {
                Button("Remove") {
                    store.ask("Remove the hard-guard from \(name)?", "Its agent will be able to run install and dev in unsafe repos again.", button: "Remove") {
                        store.run("hook:" + agent, ["hooks", "remove", agent, "--yes"], done: "Removed the hard-guard from \(name).")
                    }
                }.buttonStyle(SecondaryButton())
            } else {
                Button("Add") { store.run("hook:" + agent, ["hooks", "install", agent], done: "\(name) is hard-guarded. Restart it to load the hook.") }.buttonStyle(PrimaryButton())
            }
        }.padding(.horizontal, 16).padding(.vertical, 12)
    }

    private func setup(_ title: String, _ hint: String, _ code: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(title).font(uiFont(13, .semibold)).foregroundStyle(DT.text)
                Text(hint).font(uiFont(12)).foregroundStyle(DT.dim)
            }
            CommandBlock(text: code)
        }
    }
}

// MARK: - Settings

struct SettingsPage: View {
    @ObservedObject var store: AppStore
    private let levels: [(String, String, String)] = [
        ("contain", "Contain", "Investigates and takes the steps it can prove: removes injected code when the file then matches its last clean commit byte for byte (with undo), stops loaders, quarantines leftovers and blocks attacker addresses. Commits, pushes and access changes stay with you."),
        ("observe", "Observe", "Investigates and writes incident reports, but changes nothing on its own."),
        ("off", "Off", "Doesn't respond on its own. The watcher and scans still run, and you can respond by hand."),
    ]
    var body: some View {
        VStack(spacing: 0) {
            TopBar(crumbs: ["Settings"])
            PageBody(width: 780) {
                PageSection(title: "Appearance", note: "Light, dark, or the same as your Mac.") { AppearanceCards() }
                PageSection(title: "Auto-respond", note: "How much Bastion does on its own when it finds something.") {
                    RowGroup {
                        ForEach(Array(levels.enumerated()), id: \.offset) { i, l in
                            if i > 0 { Hairline() }
                            Button { store.setAutonomy(l.0) } label: {
                                HStack(alignment: .top, spacing: 12) {
                                    ZStack {
                                        Circle().strokeBorder(store.autonomy == l.0 ? DT.ink : DT.border, lineWidth: 1.5).frame(width: 16, height: 16)
                                        if store.autonomy == l.0 { Circle().fill(DT.ink).frame(width: 7, height: 7) }
                                    }.padding(.top, 1)
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(l.1).font(uiFont(13, .semibold)).foregroundStyle(DT.text)
                                        Text(l.2).font(uiFont(12)).foregroundStyle(DT.dim).lineSpacing(1.5).fixedSize(horizontal: false, vertical: true).multilineTextAlignment(.leading)
                                    }
                                    Spacer(minLength: 0)
                                }.padding(16).contentShape(Rectangle())
                            }.buttonStyle(.plain)
                        }
                    }
                }
                PageSection(title: "Protection", note: "What runs in the background.") { ProtectionGroup(store: store) }
                PageSection(title: "Online malware check", note: "Compares your exact package versions with osv.dev's list of malicious packages.") {
                    RowGroup {
                        HStack(spacing: 12) {
                            Image(systemName: "network").font(.system(size: 13)).foregroundStyle(DT.dim).frame(width: 18)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Check dependencies against osv.dev").font(uiFont(13, .medium)).foregroundStyle(DT.text)
                                Text("Sends package names and versions, never your code. Off until you turn it on.").font(uiFont(12)).foregroundStyle(DT.dim)
                            }
                            Spacer()
                            Toggle("osv", isOn: Binding(get: { store.status["osv"] as? Bool ?? false }, set: { on in
                                if on {
                                    store.ask("Turn on the online malware check?", "Bastion will send package names and versions (never your code) to osv.dev.", button: "Turn on") {
                                        store.run("osv", ["osv", "on", "--yes"], done: "Online malware check is on.")
                                    }
                                } else { store.run("osv", ["osv", "off"], done: "Online malware check is off.") }
                            })).labelsHidden().toggleStyle(ThemeSwitch())
                        }.padding(.horizontal, 16).padding(.vertical, 12)
                    }
                }
                PageSection(title: "Allowlist", note: "Your own servers. Never treated as a threat.") {
                    ListEditor(store: store, key: "allowlist", command: "allow", placeholder: "api.mycompany.com")
                }
                PageSection(title: "Blocklist", note: "Attacker addresses. Node processes that connect to them are stopped.") {
                    ListEditor(store: store, key: "blocklist", command: "block", placeholder: "203.0.113.7")
                }
                PageSection(title: "Ignore list", note: "Docs and tests that only quote a signature. Build configs are only skipped by exact path.") {
                    ListEditor(store: store, key: "ignore", command: "ignore", placeholder: "/docs/security-notes/")
                }
                PageSection(title: "About") {
                    RowGroup {
                        HStack(spacing: 12) {
                            BrandMark(size: 22)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Bastion \(store.status["version"] as? String ?? "")").font(uiFont(13, .semibold)).foregroundStyle(DT.text)
                                Text(tildePath(store.status["engine"] as? String ?? "")).font(codeFont(12)).foregroundStyle(DT.dim)
                            }
                            Spacer()
                            Button("Engine folder") { NSWorkspace.shared.open(URL(fileURLWithPath: store.status["engine"] as? String ?? "")) }.buttonStyle(SecondaryButton())
                            Button("Website") { NSWorkspace.shared.open(URL(string: "https://bastion-neon.vercel.app")!) }.buttonStyle(SecondaryButton())
                            Button("GitHub") { NSWorkspace.shared.open(URL(string: "https://github.com/realanshuman/bastion")!) }.buttonStyle(SecondaryButton())
                        }.padding(16)
                    }
                }
            }
        }
    }
}

struct ListEditor: View {
    @ObservedObject var store: AppStore
    let key: String, command: String, placeholder: String
    @State private var draft = ""
    var body: some View {
        let entries = store.lists[key] as? [String] ?? []
        RowGroup {
            ForEach(entries, id: \.self) { e in
                HStack {
                    Text(e).font(codeFont(12)).foregroundStyle(DT.text).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    IconButton(icon: "xmark", help: "Remove") { remove(e) }
                }.padding(.leading, 16).padding(.trailing, 8).frame(height: 40)
                Hairline()
            }
            HStack(spacing: 8) {
                TextField(placeholder, text: $draft).textFieldStyle(.plain).font(codeFont(12)).onSubmit(add)
                Button("Add", action: add).buttonStyle(SecondaryButton()).disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty)
            }.padding(.leading, 16).padding(.trailing, 8).frame(height: 44)
        }
    }
    private func add() {
        let v = draft.trimmingCharacters(in: .whitespaces)
        guard !v.isEmpty else { return }
        let go = { store.run("list:" + key, [command, "add", v, "--yes"]); draft = "" }
        switch command {
        case "allow": store.ask("Trust \(v)?", "Connections to it will never be treated as a threat.", button: "Trust", go)
        case "block": store.ask("Block \(v)?", "The watcher will stop node processes that connect to it.", button: "Block", go)
        default: store.ask("Ignore paths containing “\(v)”?", "Findings in matching docs and tests won't be reported. Build configs are only skipped by exact path.", button: "Ignore", go)
        }
    }
    private func remove(_ v: String) {
        if command == "block" {
            store.ask("Remove \(v) from the blocklist?", "Connections to it will no longer be stopped.", button: "Remove") { store.run("list:" + key, [command, "remove", v, "--yes"]) }
        } else { store.run("list:" + key, [command, "remove", v]) }
    }
}

// MARK: - Search or ask (⌘K)

struct CommandPalette: View {
    @ObservedObject var store: AppStore
    @ObservedObject private var router = Router.shared
    @State private var query = ""
    @State private var index = 0
    @FocusState private var focused: Bool

    struct Command: Identifiable {
        let id = UUID()
        let group: String, title: String, icon: String
        var hint: String = ""
        let run: () -> Void
    }

    private var commands: [Command] {
        var list: [Command] = []
        let q = query.trimmingCharacters(in: .whitespaces)
        if !q.isEmpty {   // anything typed can go to Bastion as a question
            list.append(Command(group: "Ask Bastion", title: q, icon: "mark", hint: "↩") { store.askBastion(q); router.go(.home) })
        }
        list += [
            Command(group: "Actions", title: "Scan all repositories", icon: "magnifyingglass") { store.scan() },
            Command(group: "Actions", title: "Respond now: investigate and contain", icon: "bolt.shield") { store.respond() },
            Command(group: "Actions", title: "Guard every repository on push", icon: "hand.raised") { store.run("gitguard", ["enable", "git-guard"]) },
            Command(group: "Actions", title: "Refresh", icon: "arrow.clockwise", hint: "⌘R") { store.refresh() },
        ]
        let p = store.protection
        for (feature, title) in [("watcher", "real-time watcher"), ("exec_guard", "execution guard"), ("scheduled_scan", "scheduled scan")] {
            let on = p[feature] as? Bool ?? false
            list.append(Command(group: "Actions", title: "Turn \(on ? "off" : "on") the \(title)", icon: on ? "pause.circle" : "play.circle") {
                // decide on the state right now, not the one shown when the menu opened
                let now = store.protection[feature] as? Bool ?? false
                store.setFeature(feature, title: title, on: !now)
            })
        }
        for (level, title) in [("contain", "Contain"), ("observe", "Observe"), ("off", "Off")] where level != store.autonomy {
            list.append(Command(group: "Actions", title: "Set auto-respond to \(title)", icon: "wand.and.stars") { store.setAutonomy(level) })
        }
        for (mode, title, icon) in [("system", "Match the Mac's appearance", "circle.lefthalf.filled"), ("light", "Light mode", "sun.max"), ("dark", "Dark mode", "moon")]
        where Appearance.shared.mode != mode {
            list.append(Command(group: "Appearance", title: title, icon: icon) { Appearance.shared.mode = mode })
        }
        for pane in Pane.allCases {
            list.append(Command(group: "Go to", title: pane.title, icon: pane.icon, hint: "⌘" + String(pane.key)) { router.go(pane) })
        }
        for inc in store.incidents {
            let id = inc["id"] as? String ?? ""
            list.append(Command(group: "Incidents", title: withoutTodoCount(inc["summary"]), icon: "exclamationmark.shield", hint: id) { router.open(incident: id) })
        }
        for (agent, name) in [("claude", "Claude Code"), ("cursor", "Cursor")] where store.hooks[agent] as? Bool != true {
            list.append(Command(group: "Actions", title: "Hard-guard \(name)", icon: "lock.shield") { store.run("hook:" + agent, ["hooks", "install", agent], done: "\(name) is hard-guarded.") })
        }
        for repo in store.repos {
            let path = repo["path"] as? String ?? "", name = repo["name"] as? String ?? ""
            list.append(Command(group: "Repositories", title: "Check \(name)", icon: "folder", hint: tildePath(path)) { router.go(.repos); store.check(path) })
            list.append(Command(group: "Repositories", title: "Hunt git history in \(name)", icon: "clock.arrow.circlepath", hint: tildePath(path)) {
                store.present("History · \(name)", "history:" + path, ["history", path])
            })
            list.append(Command(group: "Repositories", title: "Check dependencies in \(name)", icon: "shippingbox", hint: tildePath(path)) {
                store.present("Dependencies · \(name)", "deps:" + path, ["deps", path])
            })
        }
        guard !q.isEmpty else { return list }
        return list.filter { $0.group == "Ask Bastion" || $0.title.localizedCaseInsensitiveContains(q) || $0.group.localizedCaseInsensitiveContains(q) || $0.hint.localizedCaseInsensitiveContains(q) }
    }

    var body: some View {
        let items = commands
        ZStack(alignment: .top) {
            DT.scrim.ignoresSafeArea().onTapGesture { close() }
            VStack(spacing: 0) {
                HStack(spacing: 10) {
                    Image(systemName: "magnifyingglass").font(.system(size: 14)).foregroundStyle(DT.dim)
                    TextField("Search, or ask Bastion a question", text: $query)
                        .textFieldStyle(.plain).font(uiFont(15)).focused($focused)
                        .onChange(of: query) { index = 0 }
                        .onKeyPress(.downArrow) { index = min(index + 1, max(items.count - 1, 0)); return .handled }
                        .onKeyPress(.upArrow) { index = max(index - 1, 0); return .handled }
                        .onKeyPress(.return) { if items.indices.contains(index) { let c = items[index]; close(); c.run() }; return .handled }
                        .onKeyPress(.escape) { close(); return .handled }
                    KeyCap(key: "esc")
                }.padding(.horizontal, 16).frame(height: 54)
                Hairline()
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 0) {
                            ForEach(Array(items.enumerated()), id: \.element.id) { i, c in
                                if i == 0 || items[i - 1].group != c.group {
                                    Text(c.group).font(uiFont(11, .medium)).foregroundStyle(DT.faint).padding(.horizontal, 16).padding(.top, 12).padding(.bottom, 4)
                                }
                                Button { close(); c.run() } label: {
                                    HStack(spacing: 10) {
                                        Group {
                                            if c.icon == "mark" { BrandMark(size: 13, tint: i == index ? DT.text : DT.dim) }
                                            else { Image(systemName: c.icon).font(.system(size: 13)).foregroundStyle(i == index ? DT.text : DT.dim) }
                                        }.frame(width: 18)
                                        Text(c.group == "Ask Bastion" ? "“\(c.title)”" : c.title).font(uiFont(13, c.group == "Ask Bastion" ? .medium : .regular)).foregroundStyle(DT.text).lineLimit(1)
                                        Spacer()
                                        if !c.hint.isEmpty {
                                            if c.hint.hasPrefix("⌘") || c.hint == "↩" { KeyCap(key: c.hint) } else { Text(c.hint).font(codeFont(11)).foregroundStyle(DT.faint).lineLimit(1) }
                                        }
                                    }
                                    .padding(.horizontal, 10).frame(height: 36).contentShape(Rectangle())
                                    .background(i == index ? DT.surface2 : .clear, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                                }.buttonStyle(.plain).padding(.horizontal, 6).id(i)
                                .onHover { if $0 { index = i } }
                            }
                            if items.isEmpty {
                                Text("Type a question and press Return to ask Bastion.").font(uiFont(13)).foregroundStyle(DT.dim).padding(16)
                            }
                        }.padding(.bottom, 8)
                    }
                    .onChange(of: index) { proxy.scrollTo(index, anchor: .center) }
                }
            }
            .frame(width: 640, height: 460)
            .background(DT.surface, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(DT.border))
            .shadow(color: DT.shadow, radius: 30, y: 14)
            .padding(.top, 90)
        }
        .onAppear { query = ""; index = 0; focused = true }
    }

    private func close() { withAnimation(.easeOut(duration: 0.12)) { router.palette = false } }
}

// MARK: - Result sheet (history hunt, dependency check)

struct ResultSheetContent: Identifiable { let id = UUID(); let title: String; let json: JSON }

struct ResultSheet: View {
    let content: ResultSheetContent
    let close: () -> Void
    var body: some View {
        let j = content.json
        VStack(spacing: 0) {
            HStack {
                Text(content.title).font(uiFont(15, .semibold)).foregroundStyle(DT.text)
                Spacer()
                Button("Done", action: close).buttonStyle(SecondaryButton()).keyboardShortcut(.defaultAction)
            }.padding(.horizontal, 20).frame(height: 54)
            Hairline()
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Text((j["error"] as? String) ?? (j["summary"] as? String) ?? "").font(uiFont(15, .medium)).foregroundStyle(DT.text).fixedSize(horizontal: false, vertical: true)
                    section("Findings", j["findings"]) { f in (f["title"] as? String ?? "", tildePath(f["path"] as? String ?? "") + "  " + (f["detail"] as? String ?? ""), f["remediation"] as? String ?? "") }
                    section("Commits that brought a payload in", j["introduced"]) { e in
                        ("\(e["short"] as? String ?? "")  \(e["file"] as? String ?? "")", "\(e["committer"] as? String ?? "") <\(e["committer_email"] as? String ?? "")>, \(shortTime(e["date"])): \(e["subject"] as? String ?? "")",
                         "On: " + (e["refs"] as? [String] ?? []).joined(separator: ", "))
                    }
                    section("Branches that still carry it", j["infected_branches"]) { b in (b["ref"] as? String ?? "", b["file"] as? String ?? "", "") }
                    section("Left over from deleted branches", j["unreachable"]) { o in ("\(o["short"] as? String ?? "")  \(o["file"] as? String ?? "")", o["subject"] as? String ?? "", "") }
                    if let out = j["output"] as? String, !out.isEmpty { CommandBlock(text: out) }
                    if let note = j["note"] as? String { Text(note).font(uiFont(12)).foregroundStyle(DT.dim) }
                    if let e = j["online_error"] as? String { Text(e).font(uiFont(12)).foregroundStyle(DT.orange) }
                }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .frame(width: 640, height: 520).background(DT.panel)
    }

    @ViewBuilder private func section(_ title: String, _ raw: Any?, _ row: @escaping (JSON) -> (String, String, String)) -> some View {
        let items = raw as? [JSON] ?? []
        if !items.isEmpty {
            PageSection(title: title, count: "\(items.count)") {
                RowGroup {
                    ForEach(Array(items.enumerated()), id: \.offset) { i, item in
                        if i > 0 { Hairline() }
                        let r = row(item)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(r.0).font(codeFont(12, .medium)).foregroundStyle(DT.text).textSelection(.enabled)
                            if !r.1.isEmpty { Text(r.1).font(uiFont(12)).foregroundStyle(DT.dim).textSelection(.enabled).fixedSize(horizontal: false, vertical: true) }
                            if !r.2.isEmpty { Text(r.2).font(uiFont(12)).foregroundStyle(DT.text2).fixedSize(horizontal: false, vertical: true) }
                        }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
        }
    }
}

// MARK: - One status, everywhere

struct StateLook { let title: String; let short: String; let detail: String; let tint: Color }

@MainActor func stateLook(_ store: AppStore) -> StateLook {
    let n = store.needsYouCount
    switch store.state {
    case "act_now":
        let t = max((store.status["active_threats"] as? [Any])?.count ?? 0, 1)
        return StateLook(title: "Act now: \(t) active threat\(t == 1 ? "" : "s")", short: "Act now", detail: "Something is running, or will run as soon as npm runs there.", tint: DT.red)
    case "clean_up":
        return StateLook(title: "\(n) thing\(n == 1 ? "" : "s") to clean up", short: "\(n) to clean up", detail: "Nothing is running.", tint: DT.orange)
    default:
        return StateLook(title: "All clear", short: "All clear", detail: "Nothing needs you.", tint: DT.green)
    }
}
