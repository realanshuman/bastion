import SwiftUI
import AppKit

func runShell(_ cmd: String) -> String {
    let p = Process(); p.launchPath = "/bin/bash"; p.arguments = ["-lc", cmd]
    let pipe = Pipe(); p.standardOutput = pipe; p.standardError = Pipe()
    do { try p.run() } catch { return "" }
    let d = pipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
    return String(data: d, encoding: .utf8) ?? ""
}

/// Runs a program directly (no shell, no login profile) and returns stdout.
func runTool(_ exe: String, _ args: [String]) -> String {
    let p = Process(); p.executableURL = URL(fileURLWithPath: exe); p.arguments = args
    let pipe = Pipe(); p.standardOutput = pipe; p.standardError = Pipe(); p.standardInput = FileHandle.nullDevice
    do { try p.run() } catch { return "" }
    let d = pipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
    return String(data: d, encoding: .utf8) ?? ""
}

/// Active-threat count from `bastion status` — the same answer an AI agent gets. nil if the CLI isn't installed.
func cliStatus(_ cli: String) -> [String: Any]? {
    guard FileManager.default.isExecutableFile(atPath: cli),
          let obj = try? JSONSerialization.jsonObject(with: Data(runTool(cli, ["status", "--fast", "--json"]).utf8)) as? [String: Any],
          obj["active_threats"] is [Any] else { return nil }
    return obj
}

/// Is Bastion registered as an MCP server? Claude Code: ~/.claude.json (user scope at the top, local scope per project).
/// Cursor: ~/.cursor/mcp.json. The byte check keeps the common "not connected" case cheap.
func agentConnected(_ home: String) -> Bool {
    func listsBastion(_ obj: Any?) -> Bool { ((obj as? [String: Any])?["mcpServers"] as? [String: Any])?["bastion"] != nil }
    for path in ["\(home)/.claude.json", "\(home)/.cursor/mcp.json"] {
        guard let d = FileManager.default.contents(atPath: path), d.range(of: Data("\"bastion\"".utf8)) != nil,
              let root = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { continue }
        if listsBastion(root) { return true }
        if let projects = root["projects"] as? [String: Any], projects.values.contains(where: listsBastion) { return true }
    }
    return false
}

@MainActor
final class GuardModel: ObservableObject {
    // fast status
    @Published var clean = true
    @Published var lastScan = "—"
    @Published var lastResult = "—"
    @Published var quarantineCount = 0
    @Published var findings: [String] = []
    @Published var activeThreats = 0
    @Published var history: [String] = []
    @Published var quarantineItems: [(name: String, path: String, when: String)] = []
    @Published var watcherOn = false
    @Published var scheduleOn = false
    @Published var executionGuardOn = false
    // slow stats (computed rarely)
    @Published var reposMonitored = 0
    @Published var configsMonitored = 0
    @Published var gitReposUnprotected = 0
    @Published var statsLoading = false
    // action states
    @Published var scanning = false
    @Published var applying = ""     // which toggle/action is mid-flight ("watcher"/"schedule"/"guard")
    @Published var agentCopied = false
    @Published var agentLinked = false
    @Published var incidentId = ""
    @Published var incidentStatus = ""
    @Published var incidentSummary = ""
    @Published var incidentTodos = 0
    @Published var autonomy = "contain"

    let dir = HOME_DIR + "/.security-guard"
    let home = HOME_DIR
    let version = "4.1.0"
    private var statsLoaded = false
    var cli: String { "\(dir)/bin/bastion" }

    init() { refreshFast(); loadStats(); bootstrapEngine() }

    /// First launch (e.g. from the DMG): install or update the engine and the `bastion` CLI from inside the app.
    private func bootstrapEngine() {
        let helper = Bundle.main.bundlePath + "/Contents/Helpers/bastion"
        guard FileManager.default.isExecutableFile(atPath: helper) else { return }
        Task.detached(priority: .userInitiated) {
            let out = runTool(helper, ["bootstrap", "--json"])
            if out.contains("\"installed\"") || out.contains("\"updated\"") {
                await MainActor.run { self.refreshFast(); self.loadStats(force: true) }
            }
        }
    }

    // FAST: log result, alerts, quarantine, agent on/off. Sub-second. Safe to call often.
    func refreshFast() {
        let dir = self.dir, cli = self.cli, home = self.home
        Task.detached(priority: .userInitiated) {
            let linked = agentConnected(home)
            let latest = runShell("ls -1t \(dir)/logs/scan-*.log 2>/dev/null | head -1").trimmingCharacters(in: .whitespacesAndNewlines)
            var result = "—", scan = "—"
            if !latest.isEmpty {
                let body = runShell("grep RESULT: '\(latest)' 2>/dev/null | head -1")
                if !body.isEmpty { result = body.replacingOccurrences(of: "RESULT:", with: "").trimmingCharacters(in: .whitespacesAndNewlines) }
                let stamp = (latest as NSString).lastPathComponent.replacingOccurrences(of: "scan-", with: "").replacingOccurrences(of: ".log", with: "")
                let f = DateFormatter(); f.dateFormat = "yyyyMMdd-HHmmss"
                if let d = f.date(from: stamp) { let o = DateFormatter(); o.dateFormat = "MMM d, h:mm a"; scan = o.string(from: d) } else { scan = stamp }
            }
            let hist = runShell("tail -40 '\(dir)/ALERTS.txt' 2>/dev/null").split(separator: "\n").map(String.init).filter { !$0.isEmpty }.reversed().map { $0 }
            let finds = hist.filter { $0.contains("ALERT") || $0.contains("QUARANTINED") || $0.contains("DETECTED") || $0.contains("KILLED") }
            // CURRENT posture (not history): a live loader, a live C2 connection, or a non-clean last scan
            let liveLoader = !runShell(". \"$HOME/.security-guard/lib.sh\" 2>/dev/null && loader_pids").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            let liveC2 = !runShell(". \"$HOME/.security-guard/lib.sh\" 2>/dev/null && remote_peers | awk '{print $3}' | grep -xF -f <(bastion_list blocklist.txt)").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            let qCount = Int(runShell("find '\(dir)/quarantine' -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l").trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
            var qItems: [(name: String, path: String, when: String)] = []
            for b in runShell("ls -1t '\(dir)/quarantine' 2>/dev/null | head -15").split(separator: "\n").map(String.init) where !b.isEmpty {
                let full = "\(dir)/quarantine/\(b)"
                let leaf = runShell("find '\(full)' -mindepth 1 2>/dev/null | tail -1 | xargs basename 2>/dev/null").trimmingCharacters(in: .whitespacesAndNewlines)
                let when = runShell("stat -f '%Sm' -t '%b %d, %H:%M' '\(full)' 2>/dev/null").trimmingCharacters(in: .whitespacesAndNewlines)
                qItems.append((name: leaf.isEmpty ? b : leaf, path: full, when: when))
            }
            let w = runShell("launchctl list 2>/dev/null | grep -c com.bastion.guard.watcher").trimmingCharacters(in: .whitespacesAndNewlines) != "0"
            let sc = runShell("launchctl list 2>/dev/null | grep -c com.bastion.guard.scan").trimmingCharacters(in: .whitespacesAndNewlines) != "0"
            let eg = runShell("bash '\(dir)/harden.sh' status 2>/dev/null").trimmingCharacters(in: .whitespacesAndNewlines) == "on"
            let resultClean = result.contains("CLEAN") || result == "—"
            var active = 0
            let cs = cliStatus(cli)
            let inc = cs?["incident"] as? [String: Any]
            let (incId, incStatus, incSummary, incTodos) = (inc?["id"] as? String ?? "", inc?["status"] as? String ?? "", inc?["summary"] as? String ?? "", inc?["todos"] as? Int ?? 0)
            let level = cs?["autonomy"] as? String ?? "contain"
            if let n = (cs?["active_threats"] as? [Any])?.count { active = n }   // live loaders, C2 links, unresolved scan findings
            else {
                if liveLoader { active += 1 }
                if liveC2 { active += 1 }
                if !resultClean { active += 1 }
            }
            let isClean = active == 0
            let (res, when, items, threats) = (result, scan, qItems, active)   // immutable copies for the main actor
            await MainActor.run {
                withAnimation(.easeInOut(duration: 0.2)) {
                    self.lastResult = res; self.lastScan = when; self.history = hist; self.findings = finds
                    self.quarantineCount = qCount; self.quarantineItems = items
                    self.watcherOn = w; self.scheduleOn = sc; self.executionGuardOn = eg; self.clean = isClean; self.activeThreats = threats
                    self.agentLinked = linked
                    self.incidentId = incId; self.incidentStatus = incStatus; self.incidentSummary = incSummary; self.incidentTodos = incTodos
                    self.autonomy = level
                }
            }
        }
    }

    // SLOW: repo/config counts. Scoped to repos (not all of $HOME). Runs on first open + after a scan.
    func loadStats(force: Bool = false) {
        if statsLoaded && !force { return }
        statsLoaded = true
        withAnimation { statsLoading = true }
        let home = self.home
        Task.detached(priority: .utility) {
            let repoRoots = runShell("find '\(home)' -maxdepth 4 -type d -name .git -not -path '*/node_modules/*' -not -path '*/Library/*' 2>/dev/null | sed 's|/.git$||'")
                .split(separator: "\n").map(String.init).filter { !$0.isEmpty }
            let repos = repoRoots.count
            var configs = 0, unprot = 0
            if !repoRoots.isEmpty {
                let quoted = repoRoots.map { "'\($0)'" }.joined(separator: " ")
                configs = Int(runShell("find \(quoted) -maxdepth 3 -type f \\( -name '*.config.js' -o -name '*.config.mjs' -o -name '*.config.cjs' -o -name '*.config.ts' -o -name 'postcss.config.*' -o -name 'vite.config.*' -o -name 'next.config.*' \\) -not -path '*/node_modules/*' 2>/dev/null | wc -l").trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
                let globalHooks = ((try? String(contentsOfFile: "\(home)/.gitconfig", encoding: .utf8)) ?? "").lowercased().contains("hookspath")
                for r in repoRoots {
                    let cfg = ((try? String(contentsOfFile: "\(r)/.git/config", encoding: .utf8)) ?? "").lowercased()
                    let hookExists = FileManager.default.fileExists(atPath: "\(r)/.git/hooks/pre-push")
                    if !globalHooks && !cfg.contains("hookspath") && !hookExists { unprot += 1 }
                }
            }
            let (configCount, unprotected) = (configs, unprot)
            await MainActor.run {
                withAnimation(.easeInOut(duration: 0.25)) {
                    self.reposMonitored = repos; self.configsMonitored = configCount
                    self.gitReposUnprotected = unprotected; self.statsLoading = false
                }
            }
        }
    }

    func scanNow(reposOnly: Bool) {
        withAnimation { scanning = true }
        let dir = self.dir, home = self.home
        Task.detached(priority: .userInitiated) {
            let roots = reposOnly
                ? runShell("find '\(home)' -maxdepth 4 -type d -name .git -not -path '*/node_modules/*' -not -path '*/Library/*' 2>/dev/null | sed 's|/.git$||' | tr '\\n' ' '").trimmingCharacters(in: .whitespacesAndNewlines)
                : home
            _ = runShell("bash '\(dir)/guard.sh' \(roots.isEmpty ? home : roots)")
            await MainActor.run { withAnimation { self.scanning = false }; self.refreshFast() }
        }
    }

    // Toggles are OPTIMISTIC: flip the UI instantly, run the (fast) command, then confirm with a fast refresh.
    private func act(_ key: String, _ cmd: String) {
        withAnimation { applying = key }
        Task.detached(priority: .userInitiated) {
            _ = runShell(cmd)
            await MainActor.run { withAnimation { self.applying = "" }; self.refreshFast() }
        }
    }
    func toggleWatcher(_ on: Bool) {
        withAnimation { watcherOn = on }   // optimistic
        act("watcher", on ? "bash '\(dir)/install.sh' --watch"
                          : "launchctl unload ~/Library/LaunchAgents/com.bastion.guard.watcher.plist 2>/dev/null; rm -f ~/Library/LaunchAgents/com.bastion.guard.watcher.plist")
    }
    func toggleSchedule(_ on: Bool) {
        withAnimation { scheduleOn = on }  // optimistic
        act("schedule", on ? "bash '\(dir)/install.sh' --scan"
                           : "launchctl unload ~/Library/LaunchAgents/com.bastion.guard.scan.plist 2>/dev/null; rm -f ~/Library/LaunchAgents/com.bastion.guard.scan.plist")
    }
    func toggleExecutionGuard(_ on: Bool) {
        withAnimation { executionGuardOn = on }  // optimistic
        act("guard-exec", on ? "bash '\(dir)/harden.sh' install" : "bash '\(dir)/harden.sh' remove")
    }
    func installGitGuard() {
        withAnimation { applying = "guard" }
        let dir = self.dir, home = self.home, cli = self.cli
        Task.detached(priority: .userInitiated) {
            if FileManager.default.isExecutableFile(atPath: cli) { _ = runTool(cli, ["enable", "git-guard", "--json"]) }
            else {   // same rule as the CLI: only repos with no hook setup of their own
                _ = runShell("while IFS= read -r g; do r=$(dirname \"$g\"); grep -qi hookspath \"$r/.git/config\" 2>/dev/null && continue; [ -e \"$r/.git/hooks/pre-push\" ] && continue; cp '\(dir)/git-guard' \"$r/.git/hooks/pre-push\" 2>/dev/null && chmod +x \"$r/.git/hooks/pre-push\" 2>/dev/null; done < <(find '\(home)' -maxdepth 4 -type d -name .git -not -path '*/node_modules/*' -not -path '*/Library/*' 2>/dev/null)")
            }
            await MainActor.run { withAnimation { self.applying = "" }; self.loadStats(force: true) }
        }
    }
    func reveal(_ path: String) { NSWorkspace.shared.open(URL(fileURLWithPath: path)) }
    func setAutonomy(_ on: Bool) {
        withAnimation { autonomy = on ? "contain" : "observe" }   // optimistic
        act("autonomy", "'\(cli)' autonomy \(on ? "contain" : "observe --yes")")
    }
    /// Copies the one-liner that registers Bastion as an MCP server in Claude Code.
    func copyAgentSetup() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString("claude mcp add --scope user bastion -- \"\(cli)\" mcp", forType: .string)
        withAnimation { agentCopied = true }
        Task { try? await Task.sleep(nanoseconds: 1_800_000_000); withAnimation { self.agentCopied = false } }
    }
    func openRepo() { NSWorkspace.shared.open(URL(string: "https://github.com/realanshuman/bastion")!) }
}

// MARK: - Design system
// Linear-inspired dark: flat layered surfaces, hairline borders, tight SF Pro type, indigo accent.
// Bastion keeps its own name and shield mark.

extension Color {
    init(hex: UInt32, alpha: Double = 1) {
        self.init(.sRGB, red: Double((hex >> 16) & 0xFF) / 255, green: Double((hex >> 8) & 0xFF) / 255,
                  blue: Double(hex & 0xFF) / 255, opacity: alpha)
    }
}

enum DT {
    static let bg       = Color(hex: 0x0E0F11)   // window and sidebar
    static let panel    = Color(hex: 0x141518)   // inset content panel
    static let surface  = Color(hex: 0x1A1B1E)   // cards, hovered rows
    static let surface2 = Color(hex: 0x222327)   // group headers, selected rows, controls
    static let border   = Color(hex: 0x2B2C31)
    static let hairline = Color(hex: 0x1F2024)
    static let text     = Color(hex: 0xEDEEF0)
    static let dim      = Color(hex: 0x8A8D95)
    static let faint    = Color(hex: 0x5D6068)
    static let accent   = Color(hex: 0x5E6AD2)   // indigo: primary actions, selection, "contained"
    static let green    = Color(hex: 0x4CB782)
    static let blue     = Color(hex: 0x4EA7FC)
    static let purple   = Color(hex: 0xA38BFA)
    static let yellow   = Color(hex: 0xF2C94C)
    static let orange   = Color(hex: 0xF2994A)
    static let red      = Color(hex: 0xEB5757)
}

/// Interface text: SF Pro at Linear-like sizes
func uiFont(_ size: CGFloat, _ w: Font.Weight = .regular) -> Font { .system(size: size, weight: w) }
/// IDs, paths and commands
func codeFont(_ size: CGFloat, _ w: Font.Weight = .regular) -> Font { .system(size: size, weight: w, design: .monospaced) }

/// Switch in the accent colour. NSSwitch ignores .tint and turns grey when its window isn't key.
struct ThemeSwitch: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        Button { configuration.isOn.toggle() } label: {
            ZStack(alignment: configuration.isOn ? .trailing : .leading) {
                Capsule().fill(configuration.isOn ? DT.accent : DT.surface2)
                    .overlay(Capsule().strokeBorder(configuration.isOn ? Color.clear : DT.border))
                Circle().fill(Color.white).frame(width: 14, height: 14).padding(2)
                    .shadow(color: .black.opacity(0.35), radius: 1, y: 0.5)
            }
            .frame(width: 30, height: 18)
            .animation(.spring(response: 0.22, dampingFraction: 0.85), value: configuration.isOn)
        }
        .buttonStyle(.plain)
        .accessibilityValue(configuration.isOn ? "on" : "off")
        .accessibilityAddTraits(.isToggle)
    }
}

/// Bastion's mark: the shield on a rounded square, tinted by posture.
struct BrandMark: View {
    var size: CGFloat = 20
    var tint: Color = DT.green
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
                .fill(LinearGradient(colors: [tint, tint.opacity(0.62)], startPoint: .topLeading, endPoint: .bottomTrailing))
            Image(systemName: "checkmark.shield.fill").font(.system(size: size * 0.56, weight: .bold)).foregroundStyle(.white)
        }.frame(width: size, height: size)
    }
}

// MARK: - Menu-bar panel (glanceable; the window holds the detail)

struct PanelView: View {
    @ObservedObject var model: GuardModel
    @Environment(\.openWindow) private var openWindow
    @State private var reposOnly = false
    @State private var ticker: Timer?
    private var tint: Color { model.clean ? DT.green : DT.orange }

    var body: some View {
        VStack(spacing: 0) {
            header
            Rectangle().fill(DT.hairline).frame(height: 1)
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    status
                    if !model.incidentId.isEmpty { incident }
                    stats
                    scan
                    protection
                    recent
                }.padding(14)
            }
            Rectangle().fill(DT.hairline).frame(height: 1)
            footer
        }
        .frame(width: 360).frame(maxHeight: 660)
        .background(DT.panel)
        .environment(\.colorScheme, .dark)
        .animation(.easeInOut(duration: 0.2), value: model.clean)
        .onAppear {
            model.refreshFast(); model.loadStats()
            ticker?.invalidate()
            ticker = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { _ in Task { @MainActor in model.refreshFast() } }
        }
        .onDisappear { ticker?.invalidate(); ticker = nil }
    }

    private func openMain(_ pane: Pane, incident: String? = nil) {
        if let incident { Router.shared.open(incident: incident) } else { Router.shared.go(pane) }
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }

    private var header: some View {
        HStack(spacing: 8) {
            BrandMark(size: 20, tint: tint)
            Text("Bastion").font(uiFont(13, .semibold)).foregroundStyle(DT.text)
            Text("v\(model.version)").font(uiFont(11)).foregroundStyle(DT.faint)
            Spacer()
            Button { openMain(.overview) } label: {
                HStack(spacing: 5) {
                    Text("Open").font(uiFont(12, .medium))
                    Image(systemName: "arrow.up.right").font(.system(size: 9, weight: .bold))
                }.foregroundStyle(DT.dim).padding(.horizontal, 8).frame(height: 24)
                .background(DT.surface, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous).strokeBorder(DT.border))
            }.buttonStyle(.plain).help("Open the Bastion window")
        }.padding(.horizontal, 14).frame(height: 46)
    }

    private var status: some View {
        HStack(spacing: 12) {
            BrandMark(size: 38, tint: tint).shadow(color: tint.opacity(0.35), radius: 6, y: 2)
            VStack(alignment: .leading, spacing: 3) {
                Text(model.clean ? "You're protected" : "\(model.activeThreats) active threat\(model.activeThreats == 1 ? "" : "s")")
                    .font(uiFont(15, .semibold)).foregroundStyle(DT.text)
                Text("Last scan \(model.lastScan) · \(model.lastResult.lowercased())").font(uiFont(12)).foregroundStyle(DT.dim).lineLimit(1)
            }
            Spacer(minLength: 0)
        }
    }

    private var incident: some View {
        Button { openMain(.incidents, incident: model.incidentId) } label: {
            HStack(spacing: 10) {
                PanelStatusDot(open: model.incidentStatus != "contained")
                VStack(alignment: .leading, spacing: 2) {
                    Text(model.incidentStatus == "contained" ? "Attack contained" : "Incident needs you").font(uiFont(12.5, .semibold)).foregroundStyle(DT.text)
                    Text("\(model.incidentTodos) to-do\(model.incidentTodos == 1 ? "" : "s") · \(model.incidentId)").font(codeFont(10.5)).foregroundStyle(DT.dim)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold)).foregroundStyle(DT.faint)
            }
            .padding(10).contentShape(Rectangle())
            .background(DT.surface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(model.incidentStatus == "contained" ? DT.accent.opacity(0.5) : DT.orange.opacity(0.5)))
        }.buttonStyle(.plain)
    }

    private var stats: some View {
        HStack(spacing: 0) {
            stat(model.statsLoading ? "–" : "\(model.reposMonitored)", "Repos")
            Rectangle().fill(DT.hairline).frame(width: 1)
            stat(model.statsLoading ? "–" : "\(model.configsMonitored)", "Configs")
            Rectangle().fill(DT.hairline).frame(width: 1)
            stat("\(model.quarantineCount)", "Quarantined", warn: model.quarantineCount > 0)
        }
        .frame(height: 54)
        .background(DT.surface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(DT.border))
    }

    private func stat(_ value: String, _ label: String, warn: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(uiFont(11)).foregroundStyle(DT.dim)
            Text(value).font(uiFont(16, .semibold)).foregroundStyle(warn ? DT.orange : DT.text).contentTransition(.numericText())
        }.frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 12)
    }

    private var scan: some View {
        HStack(spacing: 10) {
            Button { model.scanNow(reposOnly: reposOnly) } label: {
                HStack(spacing: 6) {
                    if model.scanning { ProgressView().controlSize(.small).scaleEffect(0.7).tint(.white) } else { Image(systemName: "magnifyingglass").font(.system(size: 11, weight: .semibold)) }
                    Text(model.scanning ? "Scanning…" : "Scan now").font(uiFont(12.5, .semibold))
                }
                .foregroundStyle(.white).frame(maxWidth: .infinity).frame(height: 30)
                .background(DT.accent.opacity(model.scanning ? 0.6 : 1), in: RoundedRectangle(cornerRadius: 7, style: .continuous))
            }.buttonStyle(.plain).disabled(model.scanning)
            Toggle(isOn: $reposOnly) { Text("Repos only").font(uiFont(11.5)).foregroundStyle(DT.dim) }
                .toggleStyle(.checkbox).controlSize(.small).help("Scan only git repositories (faster)")
        }
    }

    private var protection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Protection").font(uiFont(11.5, .medium)).foregroundStyle(DT.faint)
            VStack(spacing: 0) {
                toggleRow("Real-time watcher", on: model.watcherOn, busy: model.applying == "watcher") { model.toggleWatcher($0) }
                divider
                toggleRow("Scheduled scan · 6h", on: model.scheduleOn, busy: model.applying == "schedule") { model.toggleSchedule($0) }
                divider
                toggleRow("Execution guard", on: model.executionGuardOn, busy: model.applying == "guard-exec") { model.toggleExecutionGuard($0) }
                divider
                toggleRow("Auto-respond", on: model.autonomy == "contain", busy: model.applying == "autonomy") { model.setAutonomy($0) }
                if model.gitReposUnprotected > 0 {
                    divider
                    Button { model.installGitGuard() } label: {
                        HStack {
                            Text("Protect \(model.gitReposUnprotected) repo\(model.gitReposUnprotected == 1 ? "" : "s") on push").font(uiFont(12.5)).foregroundStyle(DT.orange)
                            Spacer()
                            if model.applying == "guard" { ProgressView().controlSize(.small).scaleEffect(0.6) }
                            else { Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold)).foregroundStyle(DT.faint) }
                        }.padding(.horizontal, 12).frame(height: 34).contentShape(Rectangle())
                    }.buttonStyle(.plain).disabled(model.applying == "guard")
                }
            }
            .background(DT.surface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(DT.border))
        }
    }

    private var divider: some View { Rectangle().fill(DT.hairline).frame(height: 1).padding(.leading, 12) }

    private func toggleRow(_ title: String, on: Bool, busy: Bool, _ set: @escaping (Bool) -> Void) -> some View {
        HStack {
            Text(title).font(uiFont(12.5)).foregroundStyle(DT.text)
            Spacer()
            if busy { ProgressView().controlSize(.small).scaleEffect(0.6) }
            Toggle(title, isOn: Binding(get: { on }, set: set)).labelsHidden().toggleStyle(ThemeSwitch())
        }.padding(.horizontal, 12).frame(height: 34)
    }

    private var recent: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Recent activity").font(uiFont(11.5, .medium)).foregroundStyle(DT.faint)
                Spacer()
                Button("View all") { openMain(.activity) }.buttonStyle(.plain).font(uiFont(11.5, .medium)).foregroundStyle(DT.dim)
            }
            VStack(alignment: .leading, spacing: 0) {
                if model.history.isEmpty {
                    Text("Nothing yet — all quiet.").font(uiFont(12)).foregroundStyle(DT.dim).padding(12)
                }
                ForEach(Array(model.history.prefix(4).enumerated()), id: \.offset) { i, line in
                    if i > 0 { divider }
                    let parts = line.components(separatedBy: "  ")
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Circle().fill(line.contains("KILLED") ? DT.red : line.contains("QUARANTINED") || line.contains("ALERT") ? DT.orange : DT.faint).frame(width: 6, height: 6)
                        Text(humanizeEvent(parts.dropFirst().joined(separator: "  ").trimmingCharacters(in: .whitespaces))).font(uiFont(12)).foregroundStyle(DT.text.opacity(0.9)).lineLimit(1)
                        Spacer(minLength: 4)
                        Text(ago(parts.first)).font(uiFont(11)).foregroundStyle(DT.faint)
                    }.padding(.horizontal, 12).frame(height: 32)
                }
            }
            .background(DT.surface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(DT.border))
        }
    }

    private var footer: some View {
        HStack(spacing: 14) {
            Button("Logs") { model.reveal("\(model.dir)/logs") }
            Button("GitHub") { model.openRepo() }
            Spacer()
            Button { model.refreshFast(); model.loadStats(force: true) } label: { Image(systemName: "arrow.clockwise") }.help("Refresh")
            Button { NSApp.terminate(nil) } label: { Image(systemName: "power") }.help("Quit Bastion")
        }
        .buttonStyle(.plain).font(uiFont(11.5, .medium)).foregroundStyle(DT.dim)
        .padding(.horizontal, 14).frame(height: 36)
    }
}

private struct PanelStatusDot: View {
    let open: Bool
    var body: some View { StatusIcon(status: open ? "open" : "contained", size: 16) }
}

@main
struct BastionApp: App {
    @StateObject private var model = GuardModel()
    var body: some Scene {
        MenuBarExtra {
            PanelView(model: model)
        } label: {
            Image(systemName: model.clean && model.incidentStatus != "open" ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
        }.menuBarExtraStyle(.window)
        Window("Bastion", id: "main") { MainWindow() }
            .windowStyle(.hiddenTitleBar)
            .defaultSize(width: 1180, height: 780)
            .windowResizability(.contentMinSize)
    }
}
