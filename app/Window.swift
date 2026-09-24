// Window.swift — Bastion's main window. Design language after Linear: a flat sidebar, an inset content panel with
// breadcrumbs, status-grouped lists, detail pages with a properties column, and a ⌘K command menu. Bastion keeps its
// own name and mark. Every page reads `bastion … --json`, so the window, the terminal and AI agents see the same thing.
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
        return ["error": "Bastion's engine isn't installed yet — quit and reopen the app to set it up."]
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
    guard let d = parseDate(any) else { return "—" }
    let o = DateFormatter(); o.dateFormat = Calendar.current.isDateInToday(d) ? "'Today' HH:mm" : "MMM d, HH:mm"
    return o.string(from: d)
}

/// Linear-style compact age: now, 4m, 3h, 2d, Sep 24
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

/// Summaries end with "N things for you to do." — lists show that count on their own.
func withoutTodoCount(_ s: Any?) -> String {
    ((s as? String) ?? "").replacingOccurrences(of: #"\s*\d+ things? for you to do\.$"#, with: "", options: .regularExpression)
}

/// Log lines → sentences: "INCIDENT INC-… [contained]: Contained…" → "Contained…", "CHANGED: x" → "X", and so on.
func humanizeEvent(_ message: String) -> String {
    var s = message
    // a scan's summary: "0 quarantined, 5 need your attention. See logs.  (/path/scan.log)"
    if let re = try? NSRegularExpression(pattern: #"^(\d+) quarantined, (\d+) need your attention\. See logs\."#),
       let m = re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)),
       let q = Range(m.range(at: 1), in: s).flatMap({ Int(s[$0]) }), let n = Range(m.range(at: 2), in: s).flatMap({ Int(s[$0]) }) {
        let parts = [n > 0 ? "\(n) need\(n == 1 ? "s" : "") your attention" : nil, q > 0 ? "\(q) quarantined" : nil].compactMap { $0 }
        return parts.isEmpty ? "Scan finished — all clear" : "Scan finished — " + parts.joined(separator: ", ")
    }
    if let r = s.range(of: #"^INCIDENT \S+ \[\w+\]: "#, options: .regularExpression) { s = String(s[r.upperBound...]) }
    else if s.hasPrefix("INCIDENT ") { s = String(s.dropFirst(9)).replacingOccurrences(of: ": ", with: " ", options: [], range: nil) }
    for (pattern, template) in [(#"^CHANGED: "#, ""), (#"^ALERT: "#, ""), (#"^QUARANTINED \[([^\]]+)\]: "#, "Quarantined ($1): "),
                                (#"^BLOCKED \[([^\]]+)\]: "#, "Blocked $1: "), (#"^KILLED "#, "Killed ")] {
        s = s.replacingOccurrences(of: pattern, with: template, options: .regularExpression)
    }
    return s.prefix(1).uppercased() + s.dropFirst()
}

func initials(_ name: String) -> String {
    let parts = name.split(whereSeparator: { $0 == " " || $0 == "-" || $0 == "_" || $0 == "." })
    return String(parts.prefix(2).compactMap(\.first)).uppercased()
}

// MARK: - Navigation

enum Pane: String, CaseIterable, Identifiable {
    case overview, incidents, repos, activity, quarantine, agents, settings
    var id: String { rawValue }
    var title: String {
        switch self {
        case .overview: return "Overview"
        case .incidents: return "Incidents"
        case .repos: return "Repositories"
        case .activity: return "Activity"
        case .quarantine: return "Quarantine"
        case .agents: return "AI agents"
        case .settings: return "Settings"
        }
    }
    var icon: String {
        switch self {
        case .overview: return "square.grid.2x2"
        case .incidents: return "exclamationmark.shield"
        case .repos: return "folder"
        case .activity: return "tray"
        case .quarantine: return "archivebox"
        case .agents: return "sparkles"
        case .settings: return "gearshape"
        }
    }
    var key: Character { Character("\((Pane.allCases.firstIndex(of: self) ?? 0) + 1)") }
}

@MainActor
final class Router: ObservableObject {
    static let shared = Router()
    @Published var pane: Pane = .overview
    @Published var incident: String?          // an open incident page (Incidents › INC-…)
    @Published var palette = false
    func go(_ p: Pane) { pane = p; incident = nil; palette = false }
    func open(incident id: String) { pane = .incidents; incident = id; palette = false }
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

// MARK: - Store

@MainActor
final class AppStore: ObservableObject {
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

    func refresh() {
        Task {
            let r = await Task.detached(priority: .userInitiated) { () -> [Box] in
                bastionAll([["status"], ["incidents"], ["repos"], ["activity", "-n", "300"], ["quarantine"], ["lists"], ["connect"], ["hooks", "status"]])
            }.value
            hooks = r[7].json
            status = r[0].json
            incidents = r[1].json["incidents"] as? [JSON] ?? []
            repos = r[2].json["repos"] as? [JSON] ?? []
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
            flash(r["safe_to_run"] as? Bool == true ? "\((path as NSString).lastPathComponent) is safe to run." : "\((path as NSString).lastPathComponent) is not safe to run.")
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

    /// Scan every repo. The response runs as part of the scan, so the result — and the incident, if there is one — shows at once.
    func scan() {
        busy.insert("scan")
        Task {
            let r = await Task.detached(priority: .userInitiated) { Box(json: bastion(["scan"])) }.value.json
            busy.remove("scan")
            refresh()
            if let error = r["error"] as? String { flash(error); return }
            let n = (r["findings"] as? [Any])?.count ?? 0
            let secs = max(1, (r["duration_ms"] as? Int ?? 0) / 1000)
            guard n > 0 else { flash("Scan finished in \(secs)s — all clear."); return }
            let resp = r["response"] as? JSON
            if let id = resp?["id"] as? String {
                flash("Scan finished in \(secs)s — \(withoutTodoCount(resp?["summary"]))", action: ToastAction(title: "Open incident") { Router.shared.open(incident: id) })
            } else {
                flash("Scan finished in \(secs)s — \(n) need\(n == 1 ? "s" : "") your attention.", action: ToastAction(title: "Repositories") { Router.shared.go(.repos) })
            }
        }
    }

    func ask(_ title: String, _ message: String, button: String, _ run: @escaping () -> Void) {
        confirm = Confirm(title: title, message: message, button: button, run: run)
    }

    var protection: JSON { status["protection"] as? JSON ?? [:] }
    var autonomy: String { status["autonomy"] as? String ?? "contain" }
    var protected: Bool { (status["active_threats"] as? [Any] ?? []).isEmpty }
    var openIncidents: Int { incidents.filter { ($0["status"] as? String) != "resolved" }.count }

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

// MARK: - Components

/// Linear-style status glyphs: open = half-filled ring, contained = filled accent check, resolved = filled grey check.
struct StatusIcon: View {
    let status: String
    var size: CGFloat = 14
    var body: some View {
        ZStack {
            switch status {
            case "open", "at_risk":
                Circle().strokeBorder(DT.orange, lineWidth: 1.5)
                Pie(fraction: 0.5).fill(DT.orange).padding(size * 0.24)
            case "contained", "resolved":
                Circle().fill(status == "contained" ? DT.accent : DT.faint)
                Image(systemName: "checkmark").font(.system(size: size * 0.5, weight: .heavy)).foregroundStyle(DT.panel)
            default:
                Circle().strokeBorder(DT.dim, lineWidth: 1.5)
            }
        }.frame(width: size, height: size)
    }
}

struct Pie: Shape {
    var fraction: Double
    func path(in r: CGRect) -> Path {
        var p = Path(); let c = CGPoint(x: r.midX, y: r.midY)
        p.move(to: c)
        p.addArc(center: c, radius: min(r.width, r.height) / 2, startAngle: .degrees(-90), endAngle: .degrees(-90 + 360 * fraction), clockwise: false)
        p.closeSubpath()
        return p
    }
}

struct Pill: View {
    let text: String
    var dot: Color? = nil
    var icon: String? = nil
    var mono = false
    var body: some View {
        HStack(spacing: 5) {
            if let dot { Circle().fill(dot).frame(width: 7, height: 7) }
            if let icon { Image(systemName: icon).font(.system(size: 9.5, weight: .semibold)).foregroundStyle(DT.dim) }
            Text(text).font(mono ? codeFont(11) : uiFont(11.5, .medium)).foregroundStyle(DT.text.opacity(0.86)).lineLimit(1)
        }
        .padding(.horizontal, 8).frame(height: 22)
        .background(DT.surface, in: Capsule()).overlay(Capsule().strokeBorder(DT.border))
    }
}

struct KeyCap: View {
    let key: String
    var body: some View {
        Text(key).font(uiFont(10.5, .medium)).foregroundStyle(DT.dim)
            .frame(minWidth: 18, minHeight: 18).padding(.horizontal, 3)
            .background(DT.surface2, in: RoundedRectangle(cornerRadius: 4, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 4, style: .continuous).strokeBorder(DT.border))
    }
}

struct Avatar: View {
    let name: String
    var color: Color = DT.orange
    var size: CGFloat = 20
    var body: some View {
        Text(initials(name)).font(uiFont(size * 0.42, .bold)).foregroundStyle(.white)
            .frame(width: size, height: size).background(color.opacity(0.85), in: Circle())
    }
}

struct PrimaryButton: ButtonStyle {
    var tint: Color = DT.accent
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(uiFont(12.5, .medium)).foregroundStyle(.white)
            .padding(.horizontal, 12).frame(height: 28)
            .background(tint.opacity(enabled ? (configuration.isPressed ? 0.8 : 1) : 0.5), in: RoundedRectangle(cornerRadius: 6, style: .continuous))
    }
}

struct SecondaryButton: ButtonStyle {
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(uiFont(12.5, .medium)).foregroundStyle(enabled ? DT.text : DT.faint)
            .padding(.horizontal, 10).frame(height: 28)
            .background(configuration.isPressed ? DT.surface2 : DT.surface, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous).strokeBorder(DT.border))
    }
}

struct IconButton: View {
    let icon: String, help: String
    let action: () -> Void
    @State private var hover = false
    var body: some View {
        Button(action: action) {
            Image(systemName: icon).font(.system(size: 12, weight: .medium)).foregroundStyle(hover ? DT.text : DT.dim)
                .frame(width: 26, height: 26).background(hover ? DT.surface2 : .clear, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
        }.buttonStyle(.plain).help(help).onHover { hover = $0 }
    }
}

struct HoverRow: ViewModifier {
    var selected = false
    var radius: CGFloat = 6
    @State private var hover = false
    func body(content: Content) -> some View {
        content
            .background(RoundedRectangle(cornerRadius: radius, style: .continuous).fill(selected ? DT.surface2 : hover ? DT.surface : .clear))
            .onHover { hover = $0 }
    }
}
extension View { func hoverRow(selected: Bool = false, radius: CGFloat = 6) -> some View { modifier(HoverRow(selected: selected, radius: radius)) } }

struct Hairline: View { var body: some View { Rectangle().fill(DT.hairline).frame(height: 1) } }

/// The breadcrumb bar at the top of the content panel
struct TopBar<Trailing: View>: View {
    let crumbs: [String]
    var back: (() -> Void)? = nil
    @ViewBuilder var trailing: Trailing
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                ForEach(Array(crumbs.enumerated()), id: \.offset) { i, c in
                    if i > 0 { Image(systemName: "chevron.right").font(.system(size: 9, weight: .semibold)).foregroundStyle(DT.faint) }
                    if i == 0, crumbs.count > 1, let back {
                        Button(c, action: back).buttonStyle(.plain).font(uiFont(13, .medium)).foregroundStyle(DT.dim)
                    } else {
                        Text(c).font(i == crumbs.count - 1 && crumbs.count > 1 ? codeFont(12.5, .medium) : uiFont(13, .medium))
                            .foregroundStyle(DT.text).lineLimit(1)
                    }
                }
                Spacer()
                trailing
            }.padding(.horizontal, 16).frame(height: 46)
            Hairline()
        }
    }
}
extension TopBar where Trailing == EmptyView {
    init(crumbs: [String], back: (() -> Void)? = nil) { self.init(crumbs: crumbs, back: back) { EmptyView() } }
}

/// A shaded group header, as in Linear's lists
struct GroupHeader: View {
    let status: String, title: String, count: Int
    var body: some View {
        HStack(spacing: 8) {
            StatusIcon(status: status, size: 13)
            Text(title).font(uiFont(12.5, .medium)).foregroundStyle(DT.text)
            Text("\(count)").font(uiFont(12)).foregroundStyle(DT.dim)
            Spacer()
        }.padding(.horizontal, 16).frame(height: 34).background(DT.surface2.opacity(0.55))
    }
}

struct SectionLabel: View {
    let text: String
    var trailing: String? = nil
    var body: some View {
        HStack {
            Text(text).font(uiFont(13, .semibold)).foregroundStyle(DT.text)
            if let trailing { Text(trailing).font(uiFont(12.5)).foregroundStyle(DT.dim) }
            Spacer()
        }
    }
}

/// A bordered group of rows, as in Linear's settings
struct RowGroup<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(spacing: 0) { content }
            .background(DT.surface.opacity(0.6), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(DT.border))
    }
}

struct CommandBlock: View {
    let text: String
    @State private var copied = false
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Text(text).font(codeFont(11.5)).foregroundStyle(DT.text.opacity(0.92))
                .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).fixedSize(horizontal: false, vertical: true)
            Button { copy() } label: {
                Image(systemName: copied ? "checkmark" : "doc.on.doc").font(.system(size: 11, weight: .medium))
                    .foregroundStyle(copied ? DT.green : DT.dim).frame(width: 22, height: 22)
            }.buttonStyle(.plain).help("Copy")
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .background(DT.bg, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous).strokeBorder(DT.border))
    }
    private func copy() {
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(text, forType: .string)
        withAnimation { copied = true }
        Task { try? await Task.sleep(nanoseconds: 1_500_000_000); withAnimation { copied = false } }
    }
}

struct EmptyState: View {
    let icon: String, title: String, text: String
    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: icon).font(.system(size: 28, weight: .light)).foregroundStyle(DT.faint)
            Text(title).font(uiFont(14, .semibold)).foregroundStyle(DT.text)
            Text(text).font(uiFont(12.5)).foregroundStyle(DT.dim).multilineTextAlignment(.center).frame(maxWidth: 380)
        }.frame(maxWidth: .infinity, maxHeight: .infinity).padding(40)
    }
}

/// Scrolling page body with Linear's centred reading width
struct PageBody<Content: View>: View {
    var width: CGFloat = 880
    @ViewBuilder var content: Content
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 26) { content }
                .padding(.horizontal, 36).padding(.vertical, 30)
                .frame(maxWidth: width, alignment: .leading).frame(maxWidth: .infinity)
        }
    }
}

// MARK: - Window

struct MainWindow: View {
    @StateObject private var store = AppStore()
    @ObservedObject private var router = Router.shared
    private let ticker = Timer.publish(every: 20, on: .main, in: .common).autoconnect()

    var body: some View {
        HStack(spacing: 0) {
            Sidebar(store: store)
            content
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(DT.panel)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(DT.hairline))
                .padding(.vertical, 8).padding(.trailing, 8)
        }
        .background(DT.bg)
        .overlay { if router.palette { CommandPalette(store: store).transition(.opacity) } }
        .overlay(alignment: .bottom) { toast }
        .background(shortcuts)
        .frame(minWidth: 1000, minHeight: 640)
        .environment(\.colorScheme, .dark)
        .confirmationDialog(store.confirm?.title ?? "", isPresented: Binding(get: { store.confirm != nil }, set: { if !$0 { store.confirm = nil } }),
                            presenting: store.confirm) { c in
            Button(c.button, role: .destructive) { c.run() }
            Button("Cancel", role: .cancel) {}
        } message: { c in Text(c.message) }
        .sheet(item: $store.sheet) { ResultSheet(content: $0) { store.sheet = nil } }
        .onAppear {
            store.refresh()
            // a Dock icon while the window is open, back to menu-bar-only when it closes
            if NSApp.activationPolicy() != .prohibited { NSApp.setActivationPolicy(.regular); NSApp.activate(ignoringOtherApps: true) }
        }
        .onDisappear { if NSApp.activationPolicy() != .prohibited { NSApp.setActivationPolicy(.accessory) } }
        .onReceive(ticker) { _ in store.refresh() }
    }

    @ViewBuilder private var content: some View {
        switch router.pane {
        case .overview: OverviewPage(store: store)
        case .incidents:
            if let id = router.incident { IncidentPage(store: store, id: id) } else { IncidentsPage(store: store) }
        case .repos: ReposPage(store: store)
        case .activity: ActivityPage(store: store)
        case .quarantine: QuarantinePage(store: store)
        case .agents: AgentsPage(store: store)
        case .settings: SettingsPage(store: store)
        }
    }

    /// ⌘K opens the command menu, ⌘1–7 jump between pages, Esc goes back
    private var shortcuts: some View {
        ZStack {
            Button("Command menu") { withAnimation(.easeOut(duration: 0.12)) { router.palette.toggle() } }.keyboardShortcut("k", modifiers: .command)
            ForEach(Pane.allCases) { p in Button(p.title) { router.go(p) }.keyboardShortcut(KeyEquivalent(p.key), modifiers: .command) }
            Button("Back") { if router.palette { router.palette = false } else { router.incident = nil } }.keyboardShortcut(.escape, modifiers: [])
        }.opacity(0).frame(width: 0, height: 0).accessibilityHidden(true)
    }

    @ViewBuilder private var toast: some View {
        if let t = store.toast {
            HStack(spacing: 12) {
                Text(t).font(uiFont(12.5, .medium)).foregroundStyle(DT.text).lineLimit(2)
                if let a = store.toastAction {
                    Button(a.title) { withAnimation { store.toast = nil; store.toastAction = nil }; a.run() }.buttonStyle(PrimaryButton())
                }
            }
                .padding(.horizontal, 14).padding(.vertical, 9)
                .background(DT.surface2, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(DT.border))
                .shadow(color: .black.opacity(0.4), radius: 14, y: 6)
                .padding(.bottom, 22).frame(maxWidth: 560)
                .transition(.move(edge: .bottom).combined(with: .opacity))
        }
    }
}

struct Sidebar: View {
    @ObservedObject var store: AppStore
    @ObservedObject private var router = Router.shared
    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            HStack(spacing: 8) {
                BrandMark(size: 20, tint: store.protected ? DT.green : DT.orange)
                Text("Bastion").font(uiFont(13.5, .semibold)).foregroundStyle(DT.text)
                Spacer()
                IconButton(icon: "magnifyingglass", help: "Search and commands  ⌘K") { withAnimation(.easeOut(duration: 0.12)) { router.palette = true } }
                IconButton(icon: "arrow.clockwise", help: "Refresh") { store.refresh() }
            }.padding(.leading, 8).padding(.top, 38).padding(.bottom, 12)
            item(.overview)
            item(.incidents, count: store.openIncidents)
            header("Protection")
            item(.repos)
            item(.activity)
            item(.quarantine, count: store.quarantine.count)
            header("Connect")
            item(.agents)
            item(.settings)
            Spacer()
            HStack(spacing: 8) {
                Circle().fill(store.protected ? DT.green : DT.orange).frame(width: 7, height: 7)
                Text(store.protected ? "Protected" : "At risk").font(uiFont(12, .medium)).foregroundStyle(DT.dim)
                Spacer()
                Text("v\(store.status["version"] as? String ?? "")").font(uiFont(11)).foregroundStyle(DT.faint)
            }.padding(.horizontal, 10).padding(.bottom, 14)
        }
        .padding(.horizontal, 8).frame(width: 236)
    }

    private func item(_ p: Pane, count: Int = 0) -> some View {
        let selected = router.pane == p
        return Button { router.go(p) } label: {
            HStack(spacing: 9) {
                Image(systemName: p.icon).font(.system(size: 12.5, weight: .medium)).foregroundStyle(selected ? DT.text : DT.dim).frame(width: 16)
                Text(p.title).font(uiFont(13, selected ? .medium : .regular)).foregroundStyle(selected ? DT.text : DT.text.opacity(0.8))
                Spacer()
                if count > 0 { Text("\(count)").font(uiFont(11.5, .medium)).foregroundStyle(DT.dim) }
            }.padding(.horizontal, 8).frame(height: 28).contentShape(Rectangle())
        }.buttonStyle(.plain).hoverRow(selected: selected)
    }

    private func header(_ title: String) -> some View {
        Text(title).font(uiFont(11.5, .medium)).foregroundStyle(DT.faint).padding(.horizontal, 8).padding(.top, 16).padding(.bottom, 5)
    }
}

// MARK: - Overview

struct OverviewPage: View {
    @ObservedObject var store: AppStore
    var body: some View {
        VStack(spacing: 0) {
            TopBar(crumbs: ["Overview"]) {
                HStack(spacing: 8) {
                    Button { store.respond() } label: { Label(store.busy.contains("respond") ? "Investigating…" : "Respond", systemImage: "bolt.shield") }
                        .buttonStyle(SecondaryButton()).disabled(store.busy.contains("respond"))
                        .help("Investigate every finding, contain what can be proven, and write an incident report")
                    Button { store.scan() } label: { Label(store.busy.contains("scan") ? "Scanning…" : "Scan now", systemImage: "magnifyingglass") }
                        .buttonStyle(PrimaryButton()).disabled(store.busy.contains("scan"))
                }
            }
            PageBody {
                hero
                if let inc = store.status["incident"] as? JSON { incidentRow(inc) }
                stats
                VStack(alignment: .leading, spacing: 10) {
                    SectionLabel(text: "Protection")
                    ProtectionGroup(store: store)
                }
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        SectionLabel(text: "Recent activity")
                        Button("View all") { Router.shared.go(.activity) }.buttonStyle(.plain).font(uiFont(12.5, .medium)).foregroundStyle(DT.dim)
                    }
                    RowGroup {
                        if store.activity.isEmpty {
                            Text("Nothing yet — all quiet.").font(uiFont(12.5)).foregroundStyle(DT.dim).frame(maxWidth: .infinity, alignment: .leading).padding(14)
                        }
                        ForEach(Array(store.activity.prefix(6).enumerated()), id: \.offset) { i, e in
                            if i > 0 { Hairline() }
                            ActivityRow(event: e, open: activityTarget(e, in: store.activity))
                        }
                    }
                }
            }
        }
    }

    private var hero: some View {
        let threats = store.status["active_threats"] as? [JSON] ?? []
        let last = store.status["last_scan"] as? JSON
        let g = store.status["git_guard"] as? JSON ?? [:]
        return HStack(spacing: 16) {
            BrandMark(size: 48, tint: threats.isEmpty ? DT.green : DT.orange).shadow(color: (threats.isEmpty ? DT.green : DT.orange).opacity(0.3), radius: 10, y: 3)
            VStack(alignment: .leading, spacing: 4) {
                Text(threats.isEmpty ? "You're protected" : "\(threats.count) active threat\(threats.count == 1 ? "" : "s")")
                    .font(uiFont(22, .semibold)).foregroundStyle(DT.text)
                Text("Watching \(g["repos"] as? Int ?? store.repos.count) repositories · last scan \(shortTime(last?["time"]).lowercased())\((last?["clean"] as? Bool) == true ? " · clean" : "")")
                    .font(uiFont(13)).foregroundStyle(DT.dim)
                if store.status["responding"] as? Bool == true || store.busy.contains("scan") {
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small).scaleEffect(0.6).frame(width: 12, height: 12)
                        Text(store.busy.contains("scan") ? "Scanning your repositories…" : "Investigating what the scan found…").font(uiFont(12.5, .medium)).foregroundStyle(DT.accent)
                    }
                }
            }
        }
    }

    private func incidentRow(_ inc: JSON) -> some View {
        let status = inc["status"] as? String ?? "open"
        return Button { if let id = inc["id"] as? String { Router.shared.open(incident: id) } } label: {
            HStack(spacing: 12) {
                StatusIcon(status: status, size: 16)
                VStack(alignment: .leading, spacing: 3) {
                    Text(withoutTodoCount(inc["summary"])).font(uiFont(13, .medium)).foregroundStyle(DT.text).lineLimit(2)
                    Text(inc["id"] as? String ?? "").font(codeFont(11)).foregroundStyle(DT.dim)
                }
                Spacer()
                Pill(text: "\(inc["todos"] as? Int ?? 0) to-dos", icon: "checklist")
                Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold)).foregroundStyle(DT.faint)
            }
            .padding(14).contentShape(Rectangle())
            .background(DT.surface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(status == "contained" ? DT.accent.opacity(0.45) : DT.orange.opacity(0.45)))
        }.buttonStyle(.plain)
    }

    private var stats: some View {
        let g = store.status["git_guard"] as? JSON ?? [:]
        let cells: [(String, String, Color)] = [
            ("Repositories", "\(g["repos"] as? Int ?? store.repos.count)", DT.text),
            ("Push-guarded", "\(g["protected"] as? Int ?? 0)", DT.text),
            ("Open incidents", "\(store.openIncidents)", store.openIncidents > 0 ? DT.orange : DT.text),
            ("Quarantined", "\(store.status["quarantine_count"] as? Int ?? 0)", DT.text),
        ]
        return HStack(spacing: 0) {
            ForEach(Array(cells.enumerated()), id: \.offset) { i, c in
                if i > 0 { Rectangle().fill(DT.hairline).frame(width: 1) }
                VStack(alignment: .leading, spacing: 4) {
                    Text(c.0).font(uiFont(12)).foregroundStyle(DT.dim)
                    Text(c.1).font(uiFont(22, .semibold)).foregroundStyle(c.2).contentTransition(.numericText())
                }.frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 16).padding(.vertical, 14)
            }
        }
        .background(DT.surface.opacity(0.6), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(DT.border))
    }
}

struct ProtectionGroup: View {
    @ObservedObject var store: AppStore
    var body: some View {
        RowGroup {
            row("bolt", "Real-time watcher", "Kills malware loaders and attacker connections within seconds.", "watcher", store.protection["watcher"] as? Bool ?? false)
            Hairline()
            row("clock", "Scheduled scan", "Scans at login and every 6 hours.", "scheduled_scan", store.protection["scheduled_scan"] as? Bool ?? false)
            Hairline()
            row("lock.shield", "Execution guard", "node, npm, pnpm, yarn and bun refuse to run in an infected project.", "exec_guard", store.protection["exec_guard"] as? Bool ?? false)
            Hairline()
            HStack(spacing: 12) {
                Image(systemName: "wand.and.stars").font(.system(size: 13)).foregroundStyle(DT.dim).frame(width: 18)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Auto-respond").font(uiFont(13, .medium)).foregroundStyle(DT.text)
                    Text("Investigates and takes the proven, reversible steps. Off means report only.").font(uiFont(12)).foregroundStyle(DT.dim)
                }
                Spacer()
                if store.busy.contains("autonomy") { ProgressView().controlSize(.small).scaleEffect(0.7) }
                Toggle("Auto-respond", isOn: Binding(get: { store.autonomy == "contain" }, set: { store.setAutonomy($0 ? "contain" : "observe") }))
                    .labelsHidden().toggleStyle(ThemeSwitch())
            }.padding(.horizontal, 14).padding(.vertical, 12)
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
        }.padding(.horizontal, 14).padding(.vertical, 12)
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
    default: return nil
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
        let type = event["type"] as? String ?? "event"
        let raw = event["message"] as? String ?? ""
        let message = humanizeEvent(raw)
        let (icon, tint): (String, Color) = {
            switch type {
            case "killed": return ("bolt.fill", DT.red)
            case "quarantined": return ("archivebox.fill", DT.orange)
            case "blocked": return ("hand.raised.fill", DT.orange)
            case "alert": return ("exclamationmark.triangle.fill", DT.orange)
            case "setting_changed": return ("slider.horizontal.3", DT.blue)
            case "scan": return (event["attention"] as? Int ?? 0 > 0 ? "magnifyingglass.circle.fill" : "checkmark.circle.fill", event["attention"] as? Int ?? 0 > 0 ? DT.orange : DT.green)
            default: return (raw.hasPrefix("INCIDENT") ? "exclamationmark.shield.fill" : "circle.fill", raw.hasPrefix("INCIDENT") ? DT.accent : DT.faint)
            }
        }()
        return HStack(spacing: 10) {
            Image(systemName: icon).font(.system(size: icon == "circle.fill" ? 5 : 11)).foregroundStyle(tint).frame(width: 16)
            Text(message).font(uiFont(12.5)).foregroundStyle(DT.text.opacity(0.9)).lineLimit(1).truncationMode(.tail)
            Spacer(minLength: 10)
            Text(ago(event["time"])).font(uiFont(12)).foregroundStyle(DT.faint)
            if chevron { Image(systemName: "chevron.right").font(.system(size: 9.5, weight: .semibold)).foregroundStyle(DT.faint) }
        }.padding(.horizontal, 14).frame(height: 36).contentShape(Rectangle()).help(message)
    }
}

// MARK: - Incidents

struct IncidentsPage: View {
    @ObservedObject var store: AppStore
    @State private var filter = "all"
    private let groups: [(String, String)] = [("open", "Needs you"), ("contained", "Contained"), ("resolved", "Resolved")]
    var body: some View {
        VStack(spacing: 0) {
            TopBar(crumbs: ["Incidents"]) {
                Button { store.respond() } label: { Label(store.busy.contains("respond") ? "Investigating…" : "Respond", systemImage: "bolt.shield") }
                    .buttonStyle(SecondaryButton()).disabled(store.busy.contains("respond"))
            }
            HStack(spacing: 4) {
                ForEach([("all", "All incidents"), ("open", "Needs you"), ("contained", "Contained"), ("resolved", "Resolved")], id: \.0) { f in
                    Button { filter = f.0 } label: {
                        Text(f.1).font(uiFont(12.5, .medium)).foregroundStyle(filter == f.0 ? DT.text : DT.dim)
                            .padding(.horizontal, 10).frame(height: 26)
                            .background(filter == f.0 ? DT.surface2 : .clear, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                            .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous).strokeBorder(filter == f.0 ? DT.border : .clear))
                    }.buttonStyle(.plain)
                }
                Spacer()
            }.padding(.horizontal, 12).frame(height: 44)
            Hairline()
            if store.incidents.isEmpty {
                EmptyState(icon: "checkmark.shield", title: "No incidents", text: "When Bastion finds something it investigates, contains what it can prove and opens an incident here with a report and your to-dos.")
            } else {
                ScrollView {
                    LazyVStack(spacing: 0, pinnedViews: [.sectionHeaders]) {
                        ForEach(groups, id: \.0) { g in
                            let rows = store.incidents.filter { ($0["status"] as? String ?? "open") == g.0 }
                            if !rows.isEmpty && (filter == "all" || filter == g.0) {
                                Section {
                                    ForEach(Array(rows.enumerated()), id: \.offset) { _, inc in IncidentRow(inc: inc) }
                                } header: { GroupHeader(status: g.0, title: g.1, count: rows.count) }
                            }
                        }
                    }
                }
            }
        }
    }
}

struct IncidentRow: View {
    let inc: JSON
    var body: some View {
        let status = inc["status"] as? String ?? "open"
        return Button { if let id = inc["id"] as? String { Router.shared.open(incident: id) } } label: {
            HStack(spacing: 12) {
                Text(inc["id"] as? String ?? "").font(codeFont(11.5)).foregroundStyle(DT.dim).frame(width: 150, alignment: .leading)
                StatusIcon(status: status)
                Text(withoutTodoCount(inc["summary"])).font(uiFont(13, .medium)).foregroundStyle(DT.text).lineLimit(1)
                Spacer(minLength: 12)
                ForEach(Array((inc["repos"] as? [String] ?? []).prefix(2).enumerated()), id: \.offset) { _, r in Pill(text: r, dot: DT.blue) }
                if let todos = inc["todos"] as? Int, todos > 0, status != "resolved" { Pill(text: "\(todos) to-do\(todos == 1 ? "" : "s")", icon: "checklist") }
                Text(ago(inc["opened"])).font(uiFont(12)).foregroundStyle(DT.faint).frame(width: 46, alignment: .trailing)
            }.padding(.horizontal, 16).frame(height: 42).contentShape(Rectangle())
        }.buttonStyle(.plain).hoverRow(radius: 0)
    }
}

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
                HStack(alignment: .top, spacing: 0) {
                    IncidentMain(inc: inc)
                    Rectangle().fill(DT.hairline).frame(width: 1)
                    IncidentProperties(inc: inc).frame(width: 280)
                }
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
                    .buttonStyle(PrimaryButton())
            }
        }
    }
}

struct IncidentMain: View {
    let inc: JSON
    private var actions: [JSON] { inc["actions"] as? [JSON] ?? [] }
    var body: some View {
        PageBody(width: 760) {
            VStack(alignment: .leading, spacing: 8) {
                Text(withoutTodoCount(inc["summary"])).font(uiFont(22, .semibold)).foregroundStyle(DT.text).fixedSize(horizontal: false, vertical: true)
                Text(lede).font(uiFont(13.5)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true)
            }
            happened
            if inc["status"] as? String != "resolved" { todos }
            did
            timeline
        }
    }

    private var lede: String {
        switch inc["ran"] as? String ?? "no sign" {
        case "yes": return "The payload ran on this Mac. Bastion contained what it could prove; the rest is on the list below."
        case "possibly": return "The payload may have run on this Mac. Bastion contained what it could prove; the rest is on the list below."
        default: return "No sign the payload ran on this Mac. It runs the moment a dev server, build or test loads the file."
        }
    }

    private var happened: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionLabel(text: "What happened")
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

    private func note(_ icon: String, _ tint: Color, _ title: String, _ target: String, _ why: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) { Image(systemName: icon).foregroundStyle(tint).font(.system(size: 12)); Text(title).font(uiFont(13, .medium)).foregroundStyle(DT.text) }
            Text(target).font(codeFont(11.5)).foregroundStyle(DT.dim).textSelection(.enabled)
            if !why.isEmpty { Text(why).font(uiFont(12.5)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true) }
        }
        .padding(14).frame(maxWidth: .infinity, alignment: .leading)
        .background(DT.surface.opacity(0.6), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(DT.border))
    }

    private func fileBlock(_ f: JSON, repo: String) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 8) {
                Image(systemName: "doc.text").font(.system(size: 12)).foregroundStyle(DT.red)
                Text(f["rel"] as? String ?? "").font(codeFont(12.5, .medium)).foregroundStyle(DT.text).textSelection(.enabled)
                Text(tildePath(repo)).font(uiFont(12)).foregroundStyle(DT.faint)
                Spacer()
                if let a = f["action"] as? String {
                    Pill(text: a == "restored" ? "Cleaned" : "Needs you", dot: a == "restored" ? DT.accent : DT.orange)
                }
            }
            if let c = f["introduced_by"] as? JSON {
                (Text("Planted in ").foregroundColor(DT.dim)
                 + Text(c["short"] as? String ?? "").font(codeFont(12, .medium)).foregroundColor(DT.text)
                 + Text(" by ").foregroundColor(DT.dim)
                 + Text("\(c["committer"] as? String ?? "") <\(c["committer_email"] as? String ?? "")>").foregroundColor(DT.text)
                 + Text(" · \(shortTime(c["date"])) · “\(c["subject"] as? String ?? "")”").foregroundColor(DT.dim))
                    .font(uiFont(12.5)).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                let local = f["branches"] as? [String] ?? [], remote = f["remote_branches"] as? [String] ?? []
                if !(local + remote).isEmpty {
                    HStack(spacing: 6) {
                        ForEach(local, id: \.self) { b in Pill(text: b, icon: "arrow.triangle.branch", mono: true) }
                        ForEach(remote, id: \.self) { b in Pill(text: b, dot: DT.orange, mono: true) }
                    }
                }
            } else if f["tracked"] as? Bool == true {
                Text("Not committed — something on this Mac wrote it straight to disk.").font(uiFont(12.5)).foregroundStyle(DT.orange)
            } else {
                Text("Not tracked by git.").font(uiFont(12.5)).foregroundStyle(DT.dim)
            }
            Text("Payload signs: \(f["detail"] as? String ?? "")").font(codeFont(11)).foregroundStyle(DT.faint)
        }
        .padding(14).frame(maxWidth: .infinity, alignment: .leading)
        .background(DT.surface.opacity(0.6), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(DT.border))
    }

    private var todos: some View {
        let list = (inc["todos"] as? [JSON] ?? []).filter { !(($0["cmd"] as? String) ?? "").hasPrefix("bastion incident resolve") }
        return VStack(alignment: .leading, spacing: 10) {
            SectionLabel(text: "Your to-dos", trailing: "\(list.count)")
            RowGroup {
                ForEach(Array(list.enumerated()), id: \.offset) { n, t in
                    if n > 0 { Hairline() }
                    HStack(alignment: .top, spacing: 12) {
                        Circle().strokeBorder(DT.dim, lineWidth: 1.4).frame(width: 14, height: 14).padding(.top, 2)
                        VStack(alignment: .leading, spacing: 6) {
                            Text(t["title"] as? String ?? "").font(uiFont(13, .medium)).foregroundStyle(DT.text).fixedSize(horizontal: false, vertical: true)
                            if let why = t["why"] as? String, !why.isEmpty { Text(why).font(uiFont(12.5)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true) }
                            if let how = t["how"] as? String, !how.isEmpty { Text(how).font(uiFont(12.5)).foregroundStyle(DT.text.opacity(0.85)).fixedSize(horizontal: false, vertical: true) }
                            if let cmd = t["cmd"] as? String, !cmd.isEmpty { CommandBlock(text: cmd).padding(.top, 2) }
                        }
                    }.padding(14)
                }
            }
        }
    }

    private var did: some View {
        let done = actions.filter { ["done", "undone"].contains($0["status"] as? String ?? "") }
        return VStack(alignment: .leading, spacing: 10) {
            SectionLabel(text: "What Bastion did")
            RowGroup {
                if done.isEmpty {
                    Text(inc["mode"] as? String == "observe" ? "Nothing yet — auto-respond is set to observe, so Bastion only investigated." : "Nothing automatic was safe to do here.")
                        .font(uiFont(12.5)).foregroundStyle(DT.dim).frame(maxWidth: .infinity, alignment: .leading).padding(14)
                }
                ForEach(Array(done.enumerated()), id: \.offset) { i, a in
                    if i > 0 { Hairline() }
                    HStack(alignment: .top, spacing: 12) {
                        StatusIcon(status: a["status"] as? String == "undone" ? "resolved" : "contained", size: 14).padding(.top, 1)
                        Text((a["status"] as? String == "undone" ? "Undone — " : "") + (a["detail"] as? String ?? ""))
                            .font(uiFont(12.5)).foregroundStyle(DT.text.opacity(0.92)).fixedSize(horizontal: false, vertical: true)
                        Spacer(minLength: 0)
                    }.padding(14)
                }
            }
        }
    }

    private var timeline: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionLabel(text: "Activity")
            VStack(alignment: .leading, spacing: 10) {
                ForEach(Array((inc["timeline"] as? [JSON] ?? []).enumerated()), id: \.offset) { _, e in
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Circle().fill(DT.faint).frame(width: 6, height: 6).offset(y: -1)
                        (Text(e["event"] as? String ?? "").foregroundColor(DT.text.opacity(0.85)) + Text("  ·  \(ago(e["time"]))").foregroundColor(DT.faint))
                            .font(uiFont(12.5)).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }.padding(.leading, 4)
        }
    }
}

struct IncidentProperties: View {
    let inc: JSON
    var body: some View {
        let status = inc["status"] as? String ?? "open"
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                card("Properties") {
                    prop("Status") { HStack(spacing: 7) { StatusIcon(status: status, size: 13); Text(status.capitalized).font(uiFont(12.5, .medium)).foregroundStyle(DT.text) } }
                    prop("Ran here") {
                        let ran = inc["ran"] as? String ?? "no sign"
                        Text(ran == "yes" ? "Yes" : ran == "possibly" ? "Possibly" : "No sign").font(uiFont(12.5)).foregroundStyle(ran == "no sign" ? DT.text : DT.orange)
                    }
                    prop("Mode") { Text((inc["mode"] as? String ?? "").capitalized).font(uiFont(12.5)).foregroundStyle(DT.text) }
                    prop("Opened") { Text(shortTime(inc["opened"])).font(uiFont(12.5)).foregroundStyle(DT.text) }
                    prop("Updated") { Text(shortTime(inc["updated"])).font(uiFont(12.5)).foregroundStyle(DT.text) }
                }
                let repos = (inc["repos"] as? [JSON] ?? []).compactMap { ($0["path"] as? String).map { ($0 as NSString).lastPathComponent } }
                if !repos.isEmpty {
                    card("Repositories") { FlowRow { ForEach(repos, id: \.self) { Pill(text: $0, dot: DT.blue) } } }
                }
                let hunt = inc["hunt"] as? [JSON] ?? []
                if !hunt.isEmpty {
                    card("Planted by") {
                        ForEach(Array(hunt.enumerated()), id: \.offset) { _, h in
                            let identity = h["identity"] as? String ?? ""
                            HStack(spacing: 8) {
                                Avatar(name: identity, color: h["own"] as? Bool == true ? DT.blue : DT.orange)
                                Text(identity).font(uiFont(12.5)).foregroundStyle(DT.text).lineLimit(2).textSelection(.enabled)
                            }
                            let others = (h["repos"] as? [JSON] ?? []).reduce(0) { $0 + ($1["count"] as? Int ?? 0) }
                            if others > 0 { Text("\(others) commit\(others == 1 ? "" : "s") across \((h["repos"] as? [Any])?.count ?? 0) repos").font(uiFont(12)).foregroundStyle(DT.dim) }
                        }
                    }
                }
                let indicators = inc["indicators"] as? [JSON] ?? []
                if !indicators.isEmpty {
                    card("Indicators") {
                        ForEach(Array(indicators.enumerated()), id: \.offset) { _, i in
                            HStack {
                                Text(i["value"] as? String ?? "").font(codeFont(11.5)).foregroundStyle(DT.text).textSelection(.enabled)
                                Spacer()
                                let st = (i["status"] as? String ?? "").replacingOccurrences(of: "_", with: " ")
                                Text(st.capitalized).font(uiFont(11.5, .medium)).foregroundStyle(st.contains("blocked") ? DT.green : DT.orange)
                            }
                        }
                    }
                }
            }.padding(16)
        }
    }

    private func card<Content: View>(_ title: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(uiFont(12, .medium)).foregroundStyle(DT.dim)
            content()
        }
        .padding(12).frame(maxWidth: .infinity, alignment: .leading)
        .background(DT.surface.opacity(0.6), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(DT.border))
    }

    private func prop<V: View>(_ label: String, @ViewBuilder _ value: () -> V) -> some View {
        HStack(spacing: 8) {
            Text(label).font(uiFont(12.5)).foregroundStyle(DT.dim).frame(width: 74, alignment: .leading)
            value()
            Spacer(minLength: 0)
        }
    }
}

/// Wrapping row of pills
struct FlowRow: Layout {
    var spacing: CGFloat = 6
    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? 260
        var x: CGFloat = 0, y: CGFloat = 0, line: CGFloat = 0
        for s in subviews {
            let d = s.sizeThatFits(.unspecified)
            if x + d.width > width, x > 0 { x = 0; y += line + spacing; line = 0 }
            x += d.width + spacing; line = max(line, d.height)
        }
        return CGSize(width: width, height: y + line)
    }
    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, line: CGFloat = 0
        for s in subviews {
            let d = s.sizeThatFits(.unspecified)
            if x + d.width > bounds.maxX, x > bounds.minX { x = bounds.minX; y += line + spacing; line = 0 }
            s.place(at: CGPoint(x: x, y: y), proposal: .unspecified)
            x += d.width + spacing; line = max(line, d.height)
        }
    }
}

// MARK: - Repositories

struct ReposPage: View {
    @ObservedObject var store: AppStore
    var body: some View {
        VStack(spacing: 0) {
            TopBar(crumbs: ["Repositories"]) {
                HStack(spacing: 8) {
                    if (store.status["git_guard"] as? JSON)?["unprotected"] as? Int ?? 0 > 0 {
                        Button { store.run("gitguard", ["enable", "git-guard"]) } label: { Label("Protect all", systemImage: "hand.raised") }.buttonStyle(SecondaryButton())
                    }
                    Button { store.scan() } label: { Label(store.busy.contains("scan") ? "Scanning…" : "Scan all", systemImage: "magnifyingglass") }
                        .buttonStyle(PrimaryButton()).disabled(store.busy.contains("scan"))
                }
            }
            HStack(spacing: 12) {
                Text("Name").frame(maxWidth: .infinity, alignment: .leading)
                Text("Health").frame(width: 130, alignment: .leading)
                Text("Branch").frame(width: 120, alignment: .leading)
                Text("Push guard").frame(width: 120, alignment: .leading)
                Color.clear.frame(width: 96, height: 1)
            }.font(uiFont(12, .medium)).foregroundStyle(DT.faint).padding(.horizontal, 16).frame(height: 36)
            Hairline()
            if store.repos.isEmpty {
                EmptyState(icon: "folder", title: store.loaded ? "No repositories" : "Looking for repositories…", text: "Bastion watches every git repository in your home folder.")
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(Array(store.repos.enumerated()), id: \.offset) { _, r in RepoRow(store: store, repo: r) }
                    }
                }
            }
        }
    }
}

struct RepoRow: View {
    @ObservedObject var store: AppStore
    let repo: JSON
    var body: some View {
        let path = repo["path"] as? String ?? ""
        let g = repo["git_guard"] as? String ?? ""
        return HStack(spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: "folder.fill").font(.system(size: 12)).foregroundStyle(DT.blue.opacity(0.8))
                VStack(alignment: .leading, spacing: 1) {
                    Text(repo["name"] as? String ?? "").font(uiFont(13, .medium)).foregroundStyle(DT.text)
                    Text(tildePath(path)).font(codeFont(11)).foregroundStyle(DT.faint).lineLimit(1).truncationMode(.middle)
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
            health(path).frame(width: 130, alignment: .leading)
            Text(repo["branch"] as? String ?? "").font(codeFont(12)).foregroundStyle(DT.text.opacity(0.85)).lineLimit(1).frame(width: 120, alignment: .leading)
            HStack(spacing: 6) {
                Circle().fill(g == "protected" ? DT.green : g == "unprotected" ? DT.orange : DT.faint).frame(width: 7, height: 7)
                Text(g == "protected" ? "On" : g == "unprotected" ? "Off" : "Own hooks").font(uiFont(12.5)).foregroundStyle(DT.text.opacity(0.85))
            }.frame(width: 120, alignment: .leading)
            HStack(spacing: 4) {
                Button(store.busy.contains("check:" + path) ? "Checking…" : "Check") { store.check(path) }
                    .buttonStyle(SecondaryButton()).disabled(store.busy.contains("check:" + path))
                Menu {
                    Button("Hunt git history") { store.present("History · \(repo["name"] as? String ?? "")", "history:" + path, ["history", path]) }
                    Button("Check dependencies") { store.present("Dependencies · \(repo["name"] as? String ?? "")", "deps:" + path, ["deps", path]) }
                    if repo["pr_guard"] as? Bool != true {
                        Button("Add Team PR guard…") {
                            store.ask("Add the PR guard to \(repo["name"] as? String ?? "")?", "Bastion writes .github/workflows/bastion.yml. Commit and push it yourself — every pull request is checked from then on.", button: "Add") {
                                store.run("ci:" + path, ["ci-setup", path, "--write"], done: "Added .github/workflows/bastion.yml — commit and push it.")
                            }
                        }
                    }
                    Divider()
                    Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)]) }
                } label: { Image(systemName: "ellipsis").font(.system(size: 12, weight: .semibold)).foregroundStyle(DT.dim).frame(width: 26, height: 26) }
                    .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
            }.frame(width: 96, alignment: .trailing)
        }.padding(.horizontal, 16).frame(height: 50).hoverRow(radius: 0)
    }

    @ViewBuilder private func health(_ path: String) -> some View {
        if let c = store.checks[path] {
            let safe = c["safe_to_run"] as? Bool ?? false
            badge(safe ? DT.green : DT.red, safe ? "Safe to run" : "\((c["findings"] as? [Any])?.count ?? 0) problem(s)")
        } else if let n = repo["findings"] as? Int, n > 0 {
            badge(DT.red, "\(n) finding\(n == 1 ? "" : "s")")
        } else if let b = repo["infected_branches"] as? Int, b > 0 {
            badge(DT.orange, "\(b) infected branch\(b == 1 ? "" : "es")")
        } else {
            badge(DT.green, "Clean")
        }
    }
    private func badge(_ tint: Color, _ text: String) -> some View {
        HStack(spacing: 6) {
            Image(systemName: tint == DT.green ? "checkmark.circle" : "exclamationmark.circle").font(.system(size: 11.5, weight: .medium)).foregroundStyle(tint)
            Text(text).font(uiFont(12.5)).foregroundStyle(DT.text.opacity(0.85))
        }
    }
}

// MARK: - Activity

struct ActivityPage: View {
    @ObservedObject var store: AppStore
    @State private var query = ""
    private var days: [(String, [JSON])] {
        let events = query.isEmpty ? store.activity : store.activity.filter { ($0["message"] as? String ?? "").localizedCaseInsensitiveContains(query) }
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
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass").font(.system(size: 11)).foregroundStyle(DT.faint)
                    TextField("Filter activity", text: $query).textFieldStyle(.plain).font(uiFont(12.5)).frame(width: 190)
                }.padding(.horizontal, 10).frame(height: 28)
                .background(DT.surface, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous).strokeBorder(DT.border))
            }
            if days.isEmpty {
                EmptyState(icon: "tray", title: query.isEmpty ? "No activity yet" : "Nothing matches “\(query)”", text: "Everything Bastion catches, blocks or changes shows up here.")
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0, pinnedViews: [.sectionHeaders]) {
                        ForEach(Array(days.enumerated()), id: \.offset) { _, day in
                            Section {
                                ForEach(Array(day.1.enumerated()), id: \.offset) { i, e in
                                    if i > 0 { Hairline().padding(.leading, 40) }
                                    ActivityRow(event: e, open: activityTarget(e, in: store.activity)).padding(.horizontal, 2)
                                }
                            } header: {
                                Text(day.0).font(uiFont(12, .medium)).foregroundStyle(DT.dim)
                                    .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 16).frame(height: 32).background(DT.panel)
                            }
                        }
                    }.padding(.bottom, 20)
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
                EmptyState(icon: "archivebox", title: "Nothing quarantined", text: "Known-malicious leftovers and infected copies are moved here — never deleted — so you can inspect or restore them.")
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(Array(store.quarantine.enumerated()), id: \.offset) { i, item in
                            if i > 0 { Hairline() }
                            row(item)
                        }
                    }
                }
            }
        }
    }
    private func row(_ item: JSON) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "archivebox.fill").font(.system(size: 12)).foregroundStyle(DT.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text(tildePath(item["original_path"] as? String ?? item["stored_at"] as? String ?? "")).font(codeFont(12)).foregroundStyle(DT.text).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                Text("Batch \(item["id"] as? String ?? "")").font(uiFont(11.5)).foregroundStyle(DT.faint)
            }
            Spacer()
            Pill(text: (item["reason"] as? String ?? "").replacingOccurrences(of: "-", with: " ").replacingOccurrences(of: "_", with: " "), dot: DT.orange)
            Text(ago(item["time"])).font(uiFont(12)).foregroundStyle(DT.faint).frame(width: 40, alignment: .trailing)
            IconButton(icon: "folder", help: "Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: item["stored_at"] as? String ?? "")]) }
            if item["original_path"] != nil, let batch = item["id"] as? String {
                Button("Restore") {
                    store.ask("Restore batch \(batch)?", "Everything in it goes back where it was. Only do this if Bastion got it wrong.", button: "Restore") {
                        store.run("restore", ["quarantine", "restore", batch, "--yes"])
                    }
                }.buttonStyle(SecondaryButton())
            }
        }.padding(.horizontal, 16).frame(height: 52).hoverRow(radius: 0)
    }
}

// MARK: - AI agents

struct AgentsPage: View {
    @ObservedObject var store: AppStore
    private let tools: [(String, String)] = [
        ("bastion_check_path", "“Is it safe to run npm here?” — checks one project in about a second"),
        ("bastion_respond", "Investigates, contains what it can prove (with undo) and returns an incident report"),
        ("bastion_status", "Is this Mac protected right now?"),
        ("bastion_scan", "Sweeps every repo plus temp folders, processes and network"),
        ("bastion_incidents · bastion_incident", "Incident history and full reports"),
        ("bastion_findings · activity · quarantine · lists", "Everything else Bastion knows, read-only"),
        ("bastion_enable", "Turns a protection on — agents can never turn one off"),
        ("bastion_block_indicator", "Blocks an attacker address, only when an incident found it in malware"),
    ]
    var body: some View {
        let linked = agentConnected(HOME_DIR)
        let bin = store.connect["command"] as? String ?? BASTION_CLI
        let short = bin.hasPrefix(HOME_DIR + "/") && !bin.contains(" ") ? tildePath(bin) : "\"\(bin)\""
        VStack(spacing: 0) {
            TopBar(crumbs: ["AI agents"])
            PageBody(width: 820) {
                HStack(spacing: 14) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 10, style: .continuous).fill(DT.surface2).frame(width: 44, height: 44)
                        Image(systemName: linked ? "checkmark.seal.fill" : "sparkles").font(.system(size: 20)).foregroundStyle(linked ? DT.green : DT.accent)
                    }
                    VStack(alignment: .leading, spacing: 3) {
                        Text(linked ? "Your agent is connected" : "Connect your coding agent").font(uiFont(20, .semibold)).foregroundStyle(DT.text)
                        Text("Bastion is an MCP server. Once connected, your agent checks a repository before it runs install, dev, build or test in it.")
                            .font(uiFont(13)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true)
                    }
                }
                VStack(alignment: .leading, spacing: 10) {
                    SectionLabel(text: "Hard-guard")
                    Text("Hooks that stop an agent's install, dev, build or test command before it runs in an unsafe repo — enforced, not just instructed.")
                        .font(uiFont(12.5)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true)
                    RowGroup {
                        guardRow("claude", "Claude Code", "~/.claude/settings.json")
                        Hairline()
                        guardRow("cursor", "Cursor", "~/.cursor/hooks.json")
                    }
                }
                setup("Claude Code", "Run once in a terminal.", "claude mcp add --scope user bastion -- \(short) mcp")
                setup("Cursor · Claude Desktop · Windsurf", "Add to the mcpServers section of the app's MCP config.", "\"bastion\": { \"command\": \"\(bin)\", \"args\": [\"mcp\"] }")
                setup("Codex CLI", "Add to ~/.codex/config.toml.", "[mcp_servers.bastion]\ncommand = \"\(bin)\"\nargs = [\"mcp\"]")
                VStack(alignment: .leading, spacing: 10) {
                    SectionLabel(text: "What your agent gets")
                    RowGroup {
                        ForEach(Array(tools.enumerated()), id: \.offset) { i, t in
                            if i > 0 { Hairline() }
                            HStack(alignment: .firstTextBaseline, spacing: 14) {
                                Text(t.0).font(codeFont(12, .medium)).foregroundStyle(DT.text).frame(width: 290, alignment: .leading)
                                Text(t.1).font(uiFont(12.5)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true)
                                Spacer(minLength: 0)
                            }.padding(.horizontal, 14).padding(.vertical, 10)
                        }
                    }
                }
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "lock.shield").foregroundStyle(DT.green)
                    Text("Agents can make you safer, never less safe. Turning protection off, trusting a host, ignoring a path and restoring quarantine stay with you — and every change is logged and announced.")
                        .font(uiFont(12.5)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
    private func guardRow(_ agent: String, _ name: String, _ file: String) -> some View {
        let on = store.hooks[agent] as? Bool ?? false
        return HStack(spacing: 12) {
            Image(systemName: on ? "checkmark.shield.fill" : "shield").font(.system(size: 13)).foregroundStyle(on ? DT.green : DT.dim).frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(name).font(uiFont(13, .medium)).foregroundStyle(DT.text)
                Text(on ? "Guarded — unsafe repos are blocked" : "Adds a hook to \(file) (a backup is kept)").font(uiFont(12)).foregroundStyle(DT.dim)
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
        }.padding(.horizontal, 14).padding(.vertical, 12)
    }

    private func setup(_ title: String, _ hint: String, _ code: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text(title).font(uiFont(13, .semibold)).foregroundStyle(DT.text)
                Text(hint).font(uiFont(12.5)).foregroundStyle(DT.dim)
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
        ("off", "Off", "Doesn't respond on its own. The watcher and scans still run; you can respond manually."),
    ]
    var body: some View {
        VStack(spacing: 0) {
            TopBar(crumbs: ["Settings"])
            PageBody(width: 760) {
                block("Auto-respond", "How much Bastion does on its own when it finds something.") {
                    RowGroup {
                        ForEach(Array(levels.enumerated()), id: \.offset) { i, l in
                            if i > 0 { Hairline() }
                            Button { store.setAutonomy(l.0) } label: {
                                HStack(alignment: .top, spacing: 12) {
                                    ZStack {
                                        Circle().strokeBorder(store.autonomy == l.0 ? DT.accent : DT.border, lineWidth: 1.5).frame(width: 16, height: 16)
                                        if store.autonomy == l.0 { Circle().fill(DT.accent).frame(width: 8, height: 8) }
                                    }.padding(.top, 1)
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(l.1).font(uiFont(13, .medium)).foregroundStyle(DT.text)
                                        Text(l.2).font(uiFont(12)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true).multilineTextAlignment(.leading)
                                    }
                                    Spacer(minLength: 0)
                                }.padding(14).contentShape(Rectangle())
                            }.buttonStyle(.plain)
                        }
                    }
                }
                block("Protection", "What runs in the background.") { ProtectionGroup(store: store) }
                block("Online malware check", "Compares your exact package versions with osv.dev's list of malicious packages.") {
                    RowGroup {
                        HStack(spacing: 12) {
                            Image(systemName: "network").font(.system(size: 13)).foregroundStyle(DT.dim).frame(width: 18)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Check dependencies against osv.dev").font(uiFont(13, .medium)).foregroundStyle(DT.text)
                                Text("Sends package names and versions — never your code. Off by default.").font(uiFont(12)).foregroundStyle(DT.dim)
                            }
                            Spacer()
                            Toggle("osv", isOn: Binding(get: { store.status["osv"] as? Bool ?? false }, set: { on in
                                if on {
                                    store.ask("Turn on the online malware check?", "Bastion will send package names and versions (never your code) to osv.dev.", button: "Turn on") {
                                        store.run("osv", ["osv", "on", "--yes"], done: "Online malware check is on.")
                                    }
                                } else { store.run("osv", ["osv", "off"], done: "Online malware check is off.") }
                            })).labelsHidden().toggleStyle(ThemeSwitch())
                        }.padding(.horizontal, 14).padding(.vertical, 12)
                    }
                }
                block("Allowlist", "Your own servers — never treated as a threat.") {
                    ListEditor(store: store, key: "allowlist", command: "allow", placeholder: "api.mycompany.com")
                }
                block("Blocklist", "Attacker addresses — node processes that connect to them get stopped.") {
                    ListEditor(store: store, key: "blocklist", command: "block", placeholder: "203.0.113.7")
                }
                block("Ignore list", "Docs and tests that only quote a signature. Build configs are only skipped by exact path.") {
                    ListEditor(store: store, key: "ignore", command: "ignore", placeholder: "/docs/security-notes/")
                }
                block("About", nil) {
                    RowGroup {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Bastion \(store.status["version"] as? String ?? "")").font(uiFont(13, .medium)).foregroundStyle(DT.text)
                                Text(tildePath(store.status["engine"] as? String ?? "")).font(codeFont(11.5)).foregroundStyle(DT.dim)
                            }
                            Spacer()
                            Button("Engine folder") { NSWorkspace.shared.open(URL(fileURLWithPath: store.status["engine"] as? String ?? "")) }.buttonStyle(SecondaryButton())
                            Button("GitHub") { NSWorkspace.shared.open(URL(string: "https://github.com/realanshuman/bastion")!) }.buttonStyle(SecondaryButton())
                        }.padding(14)
                    }
                }
            }
        }
    }
    private func block<Content: View>(_ title: String, _ subtitle: String?, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(uiFont(14, .semibold)).foregroundStyle(DT.text)
                if let subtitle { Text(subtitle).font(uiFont(12.5)).foregroundStyle(DT.dim) }
            }
            content()
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
                }.padding(.leading, 14).padding(.trailing, 8).frame(height: 36)
                Hairline()
            }
            HStack(spacing: 8) {
                TextField(placeholder, text: $draft).textFieldStyle(.plain).font(codeFont(12)).onSubmit(add)
                Button("Add", action: add).buttonStyle(SecondaryButton()).disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty)
            }.padding(.leading, 14).padding(.trailing, 8).frame(height: 42)
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

// MARK: - Command menu (⌘K)

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
        var list: [Command] = [
            Command(group: "Actions", title: "Scan all repositories", icon: "magnifyingglass") { store.scan() },
            Command(group: "Actions", title: "Respond now — investigate and contain", icon: "bolt.shield") { store.respond() },
            Command(group: "Actions", title: "Protect every repository on push", icon: "hand.raised") { store.run("gitguard", ["enable", "git-guard"]) },
            Command(group: "Actions", title: "Refresh", icon: "arrow.clockwise") { store.refresh() },
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
        list.append(Command(group: "Actions", title: "Copy the Claude Code setup command", icon: "doc.on.doc") {
            let bin = store.connect["command"] as? String ?? BASTION_CLI
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString("claude mcp add --scope user bastion -- \"\(bin)\" mcp", forType: .string)
            store.flash("Copied — paste it in a terminal.")
        })
        for pane in Pane.allCases {
            list.append(Command(group: "Go to", title: pane.title, icon: pane.icon, hint: "⌘\(pane.key)") { router.go(pane) })
        }
        for inc in store.incidents {
            let id = inc["id"] as? String ?? ""
            list.append(Command(group: "Incidents", title: "\(id)  \(withoutTodoCount(inc["summary"]))", icon: "exclamationmark.shield") { router.open(incident: id) })
        }
        for (agent, name) in [("claude", "Claude Code"), ("cursor", "Cursor")] where store.hooks[agent] as? Bool != true {
            list.append(Command(group: "Actions", title: "Hard-guard \(name)", icon: "lock.shield") { store.run("hook:" + agent, ["hooks", "install", agent], done: "\(name) is hard-guarded.") })
        }
        for repo in store.repos {
            let path = repo["path"] as? String ?? "", name = repo["name"] as? String ?? ""
            list.append(Command(group: "Repositories", title: "Hunt git history in \(name)", icon: "clock.arrow.circlepath", hint: tildePath(path)) {
                store.present("History · \(name)", "history:" + path, ["history", path])
            })
            list.append(Command(group: "Repositories", title: "Check dependencies in \(name)", icon: "shippingbox", hint: tildePath(path)) {
                store.present("Dependencies · \(name)", "deps:" + path, ["deps", path])
            })
            list.append(Command(group: "Repositories", title: "Check \(repo["name"] as? String ?? "")", icon: "folder", hint: tildePath(path)) {
                router.go(.repos); store.check(path)
            })
        }
        guard !query.isEmpty else { return list }
        return list.filter { $0.title.localizedCaseInsensitiveContains(query) || $0.group.localizedCaseInsensitiveContains(query) || $0.hint.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        let items = commands
        ZStack(alignment: .top) {
            Color.black.opacity(0.45).ignoresSafeArea().onTapGesture { close() }
            VStack(spacing: 0) {
                HStack(spacing: 10) {
                    Image(systemName: "magnifyingglass").font(.system(size: 13)).foregroundStyle(DT.dim)
                    TextField("Type a command or search…", text: $query)
                        .textFieldStyle(.plain).font(uiFont(15)).focused($focused)
                        .onChange(of: query) { index = 0 }
                        .onKeyPress(.downArrow) { index = min(index + 1, max(items.count - 1, 0)); return .handled }
                        .onKeyPress(.upArrow) { index = max(index - 1, 0); return .handled }
                        .onKeyPress(.return) { if items.indices.contains(index) { let c = items[index]; close(); c.run() }; return .handled }
                        .onKeyPress(.escape) { close(); return .handled }
                    KeyCap(key: "esc")
                }.padding(.horizontal, 16).frame(height: 52)
                Hairline()
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 0) {
                            ForEach(Array(items.enumerated()), id: \.element.id) { i, c in
                                if i == 0 || items[i - 1].group != c.group {
                                    Text(c.group).font(uiFont(11.5, .medium)).foregroundStyle(DT.faint).padding(.horizontal, 16).padding(.top, 10).padding(.bottom, 4)
                                }
                                Button { close(); c.run() } label: {
                                    HStack(spacing: 10) {
                                        Image(systemName: c.icon).font(.system(size: 12.5)).foregroundStyle(i == index ? DT.text : DT.dim).frame(width: 18)
                                        Text(c.title).font(uiFont(13)).foregroundStyle(DT.text).lineLimit(1)
                                        Spacer()
                                        if !c.hint.isEmpty {
                                            if c.hint.hasPrefix("⌘") { KeyCap(key: c.hint) } else { Text(c.hint).font(codeFont(11)).foregroundStyle(DT.faint).lineLimit(1) }
                                        }
                                    }
                                    .padding(.horizontal, 10).frame(height: 36).contentShape(Rectangle())
                                    .background(i == index ? DT.surface2 : .clear, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                                }.buttonStyle(.plain).padding(.horizontal, 6).id(i)
                                .onHover { if $0 { index = i } }
                            }
                            if items.isEmpty {
                                Text("No commands match “\(query)”").font(uiFont(13)).foregroundStyle(DT.dim).padding(16)
                            }
                        }.padding(.bottom, 8)
                    }
                    .onChange(of: index) { proxy.scrollTo(index, anchor: .center) }
                }
            }
            .frame(width: 640, height: 440)
            .background(DT.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(DT.border))
            .shadow(color: .black.opacity(0.55), radius: 40, y: 16)
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
                Text(content.title).font(uiFont(14, .semibold)).foregroundStyle(DT.text)
                Spacer()
                Button("Done", action: close).buttonStyle(SecondaryButton()).keyboardShortcut(.defaultAction)
            }.padding(.horizontal, 18).frame(height: 52)
            Hairline()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    Text((j["error"] as? String) ?? (j["summary"] as? String) ?? "").font(uiFont(14, .medium)).foregroundStyle(DT.text).fixedSize(horizontal: false, vertical: true)
                    section("Findings", j["findings"]) { f in (f["title"] as? String ?? "", tildePath(f["path"] as? String ?? "") + "  " + (f["detail"] as? String ?? ""), f["remediation"] as? String ?? "") }
                    section("Commits that brought a payload in", j["introduced"]) { e in
                        ("\(e["short"] as? String ?? "")  \(e["file"] as? String ?? "")", "\(e["committer"] as? String ?? "") <\(e["committer_email"] as? String ?? "")> · \(shortTime(e["date"])) · \(e["subject"] as? String ?? "")",
                         "On: " + (e["refs"] as? [String] ?? []).joined(separator: ", "))
                    }
                    section("Branches that still carry it", j["infected_branches"]) { b in (b["ref"] as? String ?? "", b["file"] as? String ?? "", "") }
                    section("Left over from deleted branches", j["unreachable"]) { o in ("\(o["short"] as? String ?? "")  \(o["file"] as? String ?? "")", o["subject"] as? String ?? "", "") }
                    if let note = j["note"] as? String { Text(note).font(uiFont(12)).foregroundStyle(DT.dim) }
                    if let e = j["online_error"] as? String { Text(e).font(uiFont(12)).foregroundStyle(DT.orange) }
                }.padding(18).frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .frame(width: 640, height: 520).background(DT.panel).environment(\.colorScheme, .dark)
    }

    @ViewBuilder private func section(_ title: String, _ raw: Any?, _ row: @escaping (JSON) -> (String, String, String)) -> some View {
        let items = raw as? [JSON] ?? []
        if !items.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                SectionLabel(text: title, trailing: "\(items.count)")
                RowGroup {
                    ForEach(Array(items.enumerated()), id: \.offset) { i, item in
                        if i > 0 { Hairline() }
                        let r = row(item)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(r.0).font(codeFont(12, .medium)).foregroundStyle(DT.text).textSelection(.enabled)
                            if !r.1.isEmpty { Text(r.1).font(uiFont(12)).foregroundStyle(DT.dim).textSelection(.enabled).fixedSize(horizontal: false, vertical: true) }
                            if !r.2.isEmpty { Text(r.2).font(uiFont(12)).foregroundStyle(DT.text.opacity(0.85)).fixedSize(horizontal: false, vertical: true) }
                        }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
        }
    }
}
