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

/// Active-threat count from `bastion status`: the same answer an AI agent gets. nil if the CLI isn't installed.
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
    @Published var lastScan = "never"
    @Published var lastResult = ""
    @Published var quarantineCount = 0
    @Published var findings: [String] = []
    @Published var activeThreats = 0
    @Published var history: [String] = []
    @Published var events: [[String: Any]] = []     // the same activity as the window, with Bastion's own sentence in "said"
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
    @Published var state = "all_clear"          // act_now · clean_up · all_clear (same answer as the window)
    @Published var needsYou = 0

    let dir = HOME_DIR + "/.security-guard"
    let home = HOME_DIR
    let version = "5.0.0"
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
            var result = "", scan = "never"
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
            let resultClean = result.contains("CLEAN") || result.isEmpty
            var active = 0
            let cs = cliStatus(cli)
            let evs = FileManager.default.isExecutableFile(atPath: cli)
                ? ((try? JSONSerialization.jsonObject(with: Data(runTool(cli, ["activity", "-n", "4", "--json"]).utf8)) as? [String: Any])?["events"] as? [[String: Any]] ?? [])
                : []
            let inc = cs?["incident"] as? [String: Any]
            let (incId, incStatus, incSummary, incTodos) = (inc?["id"] as? String ?? "", inc?["status"] as? String ?? "", inc?["summary"] as? String ?? "", inc?["todos"] as? Int ?? 0)
            let level = cs?["autonomy"] as? String ?? "contain"
            let st = cs?["state"] as? String ?? "all_clear", ny = cs?["needs_you"] as? Int ?? 0
            if let n = (cs?["active_threats"] as? [Any])?.count { active = n }   // live loaders, C2 links, unresolved scan findings
            else {
                if liveLoader { active += 1 }
                if liveC2 { active += 1 }
                if !resultClean { active += 1 }
            }
            let isClean = active == 0
            let (res, when, items, threats, recentEvents) = (result, scan, qItems, active, evs)   // immutable copies for the main actor
            await MainActor.run {
                withAnimation(.easeInOut(duration: 0.2)) {
                    self.lastResult = res; self.lastScan = when; self.history = hist; self.findings = finds; self.events = recentEvents
                    self.quarantineCount = qCount; self.quarantineItems = items
                    self.watcherOn = w; self.scheduleOn = sc; self.executionGuardOn = eg; self.clean = isClean; self.activeThreats = threats
                    self.agentLinked = linked
                    self.incidentId = incId; self.incidentStatus = incStatus; self.incidentSummary = incSummary; self.incidentTodos = incTodos
                    self.autonomy = level
                    self.state = st; self.needsYou = ny
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
            // the CLI finds the repos, scans them and runs the response in one go, so the incident is ready when this returns
            let cli = dir + "/bin/bastion"
            if FileManager.default.isExecutableFile(atPath: cli) {
                _ = runShell("'\(cli)' scan \(reposOnly ? "" : "--full") >/dev/null 2>&1")
            } else {
                _ = runShell("bash '\(dir)/guard.sh' '\(home)'")
            }
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

// MARK: - Menu-bar icon

/// The mark as a template image, so it takes the menu bar's colour. Something to clean up adds a dot; act now fills the
/// shield and cuts an exclamation mark out of it.
func menuBarIcon(_ state: String) -> NSImage {
    let img = NSImage(size: NSSize(width: 18, height: 18), flipped: true) { _ in
        guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
        let s: CGFloat = 16 / 24, o: CGFloat = 1
        func p(_ x: CGFloat, _ y: CGFloat) -> NSPoint { NSPoint(x: o + x * s, y: o + y * s) }
        let shield = NSBezierPath()
        shield.move(to: p(12, 1.6)); shield.line(to: p(20.6, 4.6)); shield.line(to: p(20.6, 11.2))
        shield.curve(to: p(12, 22.6), controlPoint1: p(20.6, 16.6), controlPoint2: p(17.1, 20.6))
        shield.curve(to: p(3.4, 11.2), controlPoint1: p(6.9, 20.6), controlPoint2: p(3.4, 16.6))
        shield.line(to: p(3.4, 4.6)); shield.close()
        NSColor.black.setFill()
        if state == "act_now" {
            shield.fill()
            ctx.setBlendMode(.clear)
            NSBezierPath(roundedRect: NSRect(x: 8.1, y: 4.6, width: 1.8, height: 6.6), xRadius: 0.9, yRadius: 0.9).fill()
            NSBezierPath(ovalIn: NSRect(x: 8.05, y: 12.3, width: 1.9, height: 1.9)).fill()
            ctx.setBlendMode(.normal)
        } else {
            NSGraphicsContext.saveGraphicsState()
            shield.addClip()
            for (y, h) in [(0.0, 7.0), (8.35, 3.05), (12.75, 3.05), (17.15, 7.0)] as [(CGFloat, CGFloat)] {
                NSRect(x: 0, y: o + y * s, width: 18, height: h * s).fill()
            }
            NSGraphicsContext.restoreGraphicsState()
            if state == "clean_up" {
                ctx.setBlendMode(.clear)
                NSBezierPath(ovalIn: NSRect(x: 10.9, y: -0.1, width: 7.6, height: 7.6)).fill()
                ctx.setBlendMode(.normal)
                NSBezierPath(ovalIn: NSRect(x: 12.2, y: 1.2, width: 5, height: 5)).fill()
            }
        }
        return true
    }
    img.isTemplate = true
    img.accessibilityDescription = state == "act_now" ? "Bastion: act now" : state == "clean_up" ? "Bastion: something to clean up" : "Bastion: all clear"
    return img
}

// MARK: - Menu-bar panel (a glance; the window holds the detail)

struct PanelView: View {
    @ObservedObject var model: GuardModel
    @ObservedObject private var look = Appearance.shared
    @Environment(\.openWindow) private var openWindow
    @State private var ticker: Timer?
    private var tint: Color { model.state == "act_now" ? DT.red : model.state == "clean_up" ? DT.orange : DT.green }

    var body: some View {
        VStack(spacing: 0) {
            header
            Hairline()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    status
                    ask
                    if model.needsYou > 0 { incident }
                    stats
                    scan
                    protection
                    recent
                }.padding(14)
            }
            Hairline()
            footer
        }
        .frame(width: 360).frame(maxHeight: 690)
        .background(DT.panel)
        .animation(.easeInOut(duration: 0.2), value: model.clean)
        .onAppear {
            Appearance.shared.apply()
            model.refreshFast(); model.loadStats()
            ticker?.invalidate()
            ticker = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { _ in Task { @MainActor in model.refreshFast() } }
        }
        .onDisappear { ticker?.invalidate(); ticker = nil }
    }

    private func openMain(_ pane: Pane, incident: String? = nil, needsYou: Bool = false, ask: Bool = false) {
        if ask { Router.shared.askHome() }
        else if needsYou { Router.shared.openNeedsYou() } else if let incident { Router.shared.open(incident: incident) } else { Router.shared.go(pane) }
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }

    private var header: some View {
        HStack(spacing: 8) {
            BrandMark(size: 17)
            Text("Bastion").font(uiFont(13, .semibold)).foregroundStyle(DT.text)
            Text("v\(model.version)").font(uiFont(11)).foregroundStyle(DT.faint)
            Spacer()
            Button { openMain(.home) } label: {
                HStack(spacing: 5) {
                    Text("Open").font(uiFont(12, .medium))
                    Image(systemName: "arrow.up.right").font(.system(size: 9, weight: .bold))
                }.foregroundStyle(DT.text2).padding(.horizontal, 9).frame(height: 24)
                .background(DT.surface, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous).strokeBorder(DT.border))
            }.buttonStyle(.plain).help("Open the Bastion window")
        }.padding(.horizontal, 14).frame(height: 46)
    }

    private var status: some View {
        HStack(spacing: 12) {
            AgentFace(tint: tint, size: 40, working: model.scanning)
            VStack(alignment: .leading, spacing: 3) {
                Text(model.scanning ? "Checking your repositories…"
                     : model.state == "act_now" ? "Act now: \(max(model.activeThreats, 1)) active threat\(model.activeThreats == 1 ? "" : "s")"
                     : model.state == "clean_up" ? "\(model.needsYou) thing\(model.needsYou == 1 ? "" : "s") need\(model.needsYou == 1 ? "s" : "") you" : "Your code is clean")
                    .font(uiFont(15, .semibold)).foregroundStyle(DT.text)
                Text((model.state == "act_now" ? "Something is running or about to" : "Nothing is running") + " · last scan \(model.lastScan)")
                    .font(uiFont(12)).foregroundStyle(DT.dim).lineLimit(1)
            }
            Spacer(minLength: 0)
        }
    }

    /// Straight to the Ask box in the window
    private var ask: some View {
        Button { openMain(.home, ask: true) } label: {
            HStack(spacing: 8) {
                BrandMark(size: 13, tint: DT.faint)
                Text("Ask Bastion").font(uiFont(13)).foregroundStyle(DT.dim)
                Spacer()
                KeyCap(key: "⌘K")
            }
            .padding(.horizontal, 11).frame(height: 34)
            .background(DT.surface, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(DT.border))
            .contentShape(Rectangle())
        }.buttonStyle(.plain)
    }

    private var incident: some View {
        Button { openMain(.incidents, needsYou: true) } label: {
            HStack(spacing: 10) {
                DangerIcon(danger: model.state == "act_now" ? "now" : "dormant", size: 26)
                VStack(alignment: .leading, spacing: 2) {
                    Text(model.state == "act_now" ? "Needs you now" : "Needs you").font(uiFont(13, .semibold)).foregroundStyle(DT.text)
                    Text("\(model.needsYou) item\(model.needsYou == 1 ? "" : "s"), each with proof and a one-click fix")
                        .font(uiFont(12)).foregroundStyle(DT.dim).lineLimit(1)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold)).foregroundStyle(DT.faint)
            }
            .padding(10).contentShape(Rectangle())
            .background(DT.surface, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(tint.opacity(0.5)))
        }.buttonStyle(.plain)
    }

    private var stats: some View {
        HStack(spacing: 0) {
            stat(model.statsLoading ? "–" : "\(model.reposMonitored)", "Repos")
            Rectangle().fill(DT.hairline).frame(width: 1)
            stat("\(model.needsYou)", "Needs you", warn: model.needsYou > 0)
            Rectangle().fill(DT.hairline).frame(width: 1)
            stat("\(model.quarantineCount)", "Quarantined", warn: model.quarantineCount > 0)
        }
        .frame(height: 56)
        .background(DT.surface, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(DT.border))
    }

    private func stat(_ value: String, _ label: String, warn: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(uiFont(11)).foregroundStyle(DT.dim)
            Text(value).font(uiFont(15, .semibold)).monospacedDigit().foregroundStyle(warn ? DT.orange : DT.text).contentTransition(.numericText())
        }.frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 12)
    }

    private var scan: some View {
        Button { model.scanNow(reposOnly: true) } label: {
            HStack(spacing: 6) {
                if model.scanning { ProgressView().controlSize(.small).scaleEffect(0.6).frame(width: 12, height: 12) }
                else { Image(systemName: "magnifyingglass").font(.system(size: 11, weight: .semibold)) }
                Text(model.scanning ? "Scanning…" : "Scan now")
            }.frame(maxWidth: .infinity)
        }.buttonStyle(PrimaryButton(large: true)).disabled(model.scanning)
    }

    private var protection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Protection").font(uiFont(12, .medium)).foregroundStyle(DT.dim)
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
                            Text("Guard \(model.gitReposUnprotected) repo\(model.gitReposUnprotected == 1 ? "" : "s") on push").font(uiFont(13)).foregroundStyle(DT.orange)
                            Spacer()
                            if model.applying == "guard" { ProgressView().controlSize(.small).scaleEffect(0.6) }
                            else { Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold)).foregroundStyle(DT.faint) }
                        }.padding(.horizontal, 12).frame(height: 36).contentShape(Rectangle())
                    }.buttonStyle(.plain).disabled(model.applying == "guard")
                }
            }
            .background(DT.surface, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(DT.border))
        }
    }

    private var divider: some View { Rectangle().fill(DT.hairline).frame(height: 1).padding(.leading, 12) }

    private func toggleRow(_ title: String, on: Bool, busy: Bool, _ set: @escaping (Bool) -> Void) -> some View {
        HStack {
            Text(title).font(uiFont(13)).foregroundStyle(DT.text)
            Spacer()
            if busy { ProgressView().controlSize(.small).scaleEffect(0.6) }
            Toggle(title, isOn: Binding(get: { on }, set: set)).labelsHidden().toggleStyle(ThemeSwitch())
        }.padding(.horizontal, 12).frame(height: 36)
    }

    private var recent: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Recent activity").font(uiFont(12, .medium)).foregroundStyle(DT.dim)
                Spacer()
                LinkButton(title: "All") { openMain(.activity) }
            }
            VStack(alignment: .leading, spacing: 0) {
                if model.events.isEmpty {
                    Text("Nothing yet. All quiet.").font(uiFont(12)).foregroundStyle(DT.dim).padding(12)
                }
                ForEach(Array(model.events.prefix(4).enumerated()), id: \.offset) { i, e in
                    if i > 0 { divider }
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Circle().fill(eventStyle(e).tint).frame(width: 6, height: 6)
                        Text(said(e)).font(uiFont(12)).foregroundStyle(DT.text2).lineLimit(1).help(said(e))
                        Spacer(minLength: 4)
                        Text(ago(e["time"])).font(uiFont(11)).foregroundStyle(DT.faint)
                    }.padding(.horizontal, 12).frame(height: 34)
                }
            }
            .background(DT.surface, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(DT.border))
        }
    }

    private var footer: some View {
        HStack(spacing: 14) {
            Button("Logs") { model.reveal("\(model.dir)/logs") }
            Button("GitHub") { model.openRepo() }
            Spacer()
            AppearanceSwitch()
            Button { model.refreshFast(); model.loadStats(force: true) } label: { Image(systemName: "arrow.clockwise") }.help("Refresh")
            Button { NSApp.terminate(nil) } label: { Image(systemName: "power") }.help("Quit Bastion")
        }
        .buttonStyle(.plain).font(uiFont(12, .medium)).foregroundStyle(DT.dim)
        .padding(.horizontal, 14).frame(height: 40)
    }
}

extension Notification.Name { static let bastionShowWindow = Notification.Name("bastion.showWindow") }

/// Opening Bastion yourself shows its window; when macOS starts it as a login item it stays in the menu bar.
/// Opening it again while it runs brings the window back.
final class AppDelegate: NSObject, NSApplicationDelegate {
    static var showWindowAtLaunch = true
    func applicationWillFinishLaunching(_ notification: Notification) {
        let e = NSAppleEventManager.shared().currentAppleEvent
        let loginItem = e?.eventID == kAEOpenApplication && e?.paramDescriptor(forKeyword: keyAEPropData)?.enumCodeValue == keyAELaunchedAsLogInItem
        AppDelegate.showWindowAtLaunch = !loginItem
        Appearance.shared.apply()
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        NotificationCenter.default.post(name: .bastionShowWindow, object: nil)
        return true
    }
}

/// The menu-bar icon. It lives for the whole run, so it's also what opens the window when asked to.
struct MenuBarLabel: View {
    let state: String
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        Image(nsImage: menuBarIcon(state))
            .onAppear {
                guard AppDelegate.showWindowAtLaunch else { return }
                AppDelegate.showWindowAtLaunch = false
                show()
            }
            .onReceive(NotificationCenter.default.publisher(for: .bastionShowWindow)) { _ in show() }
    }
    private func show() {
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }
}

@main
struct BastionApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = GuardModel()
    var body: some Scene {
        MenuBarExtra {
            PanelView(model: model)
        } label: {
            MenuBarLabel(state: model.state)
        }.menuBarExtraStyle(.window)
        Window("Bastion", id: "main") { MainWindow() }
            .windowStyle(.hiddenTitleBar)
            .defaultSize(width: 1200, height: 800)
            .windowResizability(.contentMinSize)
    }
}
