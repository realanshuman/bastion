import SwiftUI
import AppKit

func runShell(_ cmd: String) -> String {
    let p = Process(); p.launchPath = "/bin/bash"; p.arguments = ["-lc", cmd]
    let pipe = Pipe(); p.standardOutput = pipe; p.standardError = Pipe()
    do { try p.run() } catch { return "" }
    let d = pipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
    return String(data: d, encoding: .utf8) ?? ""
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

    let dir = (NSHomeDirectory() as NSString).appendingPathComponent(".security-guard")
    let home = NSHomeDirectory()
    let version = "3.0.0"
    private var statsLoaded = false

    init() { refreshFast(); loadStats() }

    // FAST: log result, alerts, quarantine, agent on/off. Sub-second. Safe to call often.
    func refreshFast() {
        let dir = self.dir
        Task.detached(priority: .userInitiated) {
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
            let liveLoader = runShell("ps -axo comm=,command= 2>/dev/null | awk '$1 ~ /node$/ && index($0,\"global.r=require\")>0' | wc -l").trimmingCharacters(in: .whitespacesAndNewlines) != "0"
            let liveC2 = runShell("bl=\"$HOME/.security-guard/blocklist.txt\"; lsof -nP -i 2>/dev/null | grep -F -f <(grep -vE '^[[:space:]]*#|^[[:space:]]*$' \"$bl\" 2>/dev/null) 2>/dev/null | grep -c ESTABLISHED").trimmingCharacters(in: .whitespacesAndNewlines) != "0"
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
            if liveLoader { active += 1 }
            if liveC2 { active += 1 }
            if !resultClean { active += 1 }
            let isClean = active == 0
            await MainActor.run {
                withAnimation(.easeInOut(duration: 0.2)) {
                    self.lastResult = result; self.lastScan = scan; self.history = hist; self.findings = finds
                    self.quarantineCount = qCount; self.quarantineItems = qItems
                    self.watcherOn = w; self.scheduleOn = sc; self.executionGuardOn = eg; self.clean = isClean; self.activeThreats = active
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
                for r in repoRoots {
                    let hp = runShell("git -C '\(r)' config core.hooksPath 2>/dev/null").trimmingCharacters(in: .whitespacesAndNewlines)
                    let has = runShell("grep -l security-guard '\(r)/.git/hooks/pre-push' 2>/dev/null").isEmpty == false
                    if hp.isEmpty && !has { unprot += 1 }
                }
            }
            await MainActor.run {
                withAnimation(.easeInOut(duration: 0.25)) {
                    self.reposMonitored = repos; self.configsMonitored = configs
                    self.gitReposUnprotected = unprot; self.statsLoading = false
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
        let dir = self.dir, home = self.home
        Task.detached(priority: .userInitiated) {
            _ = runShell("while IFS= read -r g; do r=$(dirname \"$g\"); hp=$(git -C \"$r\" config core.hooksPath 2>/dev/null); if [ -z \"$hp\" ]; then cp '\(dir)/git-guard' \"$r/.git/hooks/pre-push\" 2>/dev/null && chmod +x \"$r/.git/hooks/pre-push\" 2>/dev/null; fi; done < <(find '\(home)' -maxdepth 4 -type d -name .git -not -path '*/node_modules/*' -not -path '*/Library/*' 2>/dev/null)")
            await MainActor.run { withAnimation { self.applying = "" }; self.loadStats(force: true) }
        }
    }
    func reveal(_ path: String) { NSWorkspace.shared.open(URL(fileURLWithPath: path)) }
    func openRepo() { NSWorkspace.shared.open(URL(string: "https://github.com/realanshuman/bastion")!) }
}

// MARK: - Developer (dark) theme
private enum DT {
    static let bg      = Color(red:0.043, green:0.055, blue:0.078)  // #0B0E14
    static let surface = Color(red:0.090, green:0.106, blue:0.145)  // #171B25
    static let surface2 = Color(red:0.125, green:0.145, blue:0.19)
    static let border  = Color(red:0.192, green:0.212, blue:0.255)  // #30363D
    static let text    = Color(red:0.79,  green:0.82,  blue:0.85)   // #C9D1D9
    static let dim     = Color(red:0.55,  green:0.58,  blue:0.62)   // #8B949E
    static let green   = Color(red:0.247, green:0.725, blue:0.314)  // #3FB950
    static let blue    = Color(red:0.345, green:0.651, blue:1.0)    // #58A6FF
    static let purple  = Color(red:0.737, green:0.549, blue:1.0)    // #BC8CFF
    static let orange  = Color(red:0.941, green:0.533, blue:0.243)  // #F0883E
    static let red     = Color(red:0.973, green:0.318, blue:0.286)  // #F85149
    static let mono    = "SF Mono"
}
private func monoFont(_ size: CGFloat, _ w: Font.Weight = .regular) -> Font {
    .system(size: size, weight: w, design: .monospaced)
}

private struct Panel<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        content.frame(maxWidth: .infinity)
            .background(DT.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(DT.border, lineWidth: 1))
    }
}

private struct StatTile: View {
    let value: String, label: String, systemImage: String, tint: Color, loading: Bool
    var body: some View {
        VStack(spacing: 6) {
            Image(systemName: systemImage).font(.system(size: 13, weight: .semibold)).foregroundStyle(tint)
            if loading { ProgressView().controlSize(.small).frame(height: 22) }
            else { Text(value).font(monoFont(19, .bold)).foregroundStyle(DT.text).contentTransition(.numericText()).frame(height: 22) }
            Text(label).font(monoFont(8.5, .medium)).foregroundStyle(DT.dim).textCase(.lowercase)
        }
        .frame(maxWidth: .infinity).padding(.vertical, 12)
        .background(DT.surface, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 11, style: .continuous).strokeBorder(DT.border, lineWidth: 1))
    }
}

private struct Section<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text("// \(title)").font(monoFont(10, .medium)).foregroundStyle(DT.dim).padding(.leading, 4)
            VStack(spacing: 0) { content }
                .background(DT.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(DT.border, lineWidth: 1))
        }
    }
}
private struct RowDivider: View { var body: some View { Rectangle().fill(DT.border).frame(height: 1).padding(.leading, 44) } }

struct PanelView: View {
    @ObservedObject var model: GuardModel
    @State private var tab = 0
    @State private var reposOnly = false
    @State private var ticker: Timer?
    private var accent: Color { model.clean ? DT.green : DT.orange }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 15) {
                header
                hero
                stats
                scanButton
                Picker("", selection: $tab.animation(.easeInOut)) {
                    Text("overview").tag(0); Text("activity").tag(1); Text("quarantine").tag(2)
                }.pickerStyle(.segmented).labelsHidden().font(monoFont(11))
                Group { switch tab { case 0: overview; case 1: activity; default: quarantine } }
                footer
            }
            .padding(16)
        }
        .frame(width: 372).frame(maxHeight: 640)
        .background(DT.bg)
        .environment(\.colorScheme, .dark)
        .animation(.easeInOut(duration: 0.2), value: model.clean)
        .onAppear {
            model.refreshFast(); model.loadStats()
            ticker?.invalidate()
            ticker = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { _ in Task { @MainActor in model.refreshFast() } }
        }
        .onDisappear { ticker?.invalidate(); ticker = nil }
    }

    private var header: some View {
        HStack(spacing: 9) {
            Circle().fill(accent).frame(width: 9, height: 9).shadow(color: accent.opacity(0.7), radius: 4)
            Text("bastion").font(monoFont(16, .bold)).foregroundStyle(DT.text)
            Text("v\(model.version)").font(monoFont(10)).foregroundStyle(DT.dim)
            Spacer()
            Text(model.clean ? "PROTECTED" : "\(model.activeThreats) THREAT\(model.activeThreats == 1 ? "" : "S")")
                .font(monoFont(9.5, .bold)).padding(.horizontal, 9).padding(.vertical, 4)
                .background(accent.opacity(0.15), in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous).strokeBorder(accent.opacity(0.4)))
                .foregroundStyle(accent)
        }
    }

    private var hero: some View {
        Panel {
            HStack(spacing: 13) {
                ZStack {
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(LinearGradient(colors: [accent.opacity(0.9), accent.opacity(0.55)], startPoint: .topLeading, endPoint: .bottomTrailing))
                        .frame(width: 48, height: 48).shadow(color: accent.opacity(0.4), radius: 6, y: 2)
                    Image(systemName: model.clean ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                        .font(.system(size: 22, weight: .bold)).foregroundStyle(.white).contentTransition(.symbolEffect(.replace))
                }
                VStack(alignment: .leading, spacing: 3) {
                    Text(model.clean ? "no threats detected" : "threats need attention")
                        .font(monoFont(14, .semibold)).foregroundStyle(DT.text)
                    Text("last scan \(model.lastScan.lowercased()) · \(model.lastResult.lowercased())")
                        .font(monoFont(10)).foregroundStyle(DT.dim).lineLimit(1)
                }
                Spacer()
            }.padding(15)
        }
    }

    private var stats: some View {
        HStack(spacing: 9) {
            StatTile(value: "\(model.reposMonitored)", label: "repos", systemImage: "folder.fill", tint: DT.blue, loading: model.statsLoading)
            StatTile(value: "\(model.configsMonitored)", label: "configs", systemImage: "doc.text.fill", tint: DT.purple, loading: model.statsLoading)
            StatTile(value: "\(model.quarantineCount)", label: "locked", systemImage: "lock.fill", tint: model.quarantineCount > 0 ? DT.orange : DT.dim, loading: false)
        }
    }

    private var scanButton: some View {
        VStack(spacing: 8) {
            Button(action: { model.scanNow(reposOnly: reposOnly) }) {
                HStack(spacing: 7) {
                    if model.scanning { ProgressView().controlSize(.small) } else { Image(systemName: "magnifyingglass") }
                    Text(model.scanning ? "scanning…" : "$ scan now").font(monoFont(13, .semibold))
                }
                .frame(maxWidth: .infinity).padding(.vertical, 11)
                .background(LinearGradient(colors: [accent, accent.opacity(0.78)], startPoint: .top, endPoint: .bottom),
                            in: RoundedRectangle(cornerRadius: 11, style: .continuous))
                .foregroundStyle(Color.black.opacity(0.85))
                .shadow(color: accent.opacity(0.35), radius: 5, y: 2)
            }
            .buttonStyle(.plain).disabled(model.scanning)
            Toggle(isOn: $reposOnly) { Text("git repos only (faster)").font(monoFont(10)).foregroundStyle(DT.dim) }
                .toggleStyle(.checkbox).controlSize(.small)
        }
    }

    private func row<Trailing: View>(_ icon: String, _ tint: Color, _ title: String, @ViewBuilder trailing: () -> Trailing) -> some View {
        HStack(spacing: 11) {
            ZStack {
                RoundedRectangle(cornerRadius: 7, style: .continuous).fill(tint.opacity(0.16)).frame(width: 28, height: 28)
                Image(systemName: icon).font(.system(size: 12, weight: .semibold)).foregroundStyle(tint)
            }
            Text(title).font(monoFont(12)).foregroundStyle(DT.text)
            Spacer()
            trailing()
        }.padding(.horizontal, 11).padding(.vertical, 9).contentShape(Rectangle())
    }

    private var overview: some View {
        Section(title: "protection") {
            row("bolt.fill", DT.green, "real-time watcher") {
                HStack(spacing: 6) {
                    if model.applying == "watcher" { ProgressView().controlSize(.small).scaleEffect(0.7) }
                    Toggle("", isOn: Binding(get: { model.watcherOn }, set: { model.toggleWatcher($0) })).labelsHidden().toggleStyle(.switch).controlSize(.small).tint(DT.green)
                }
            }
            RowDivider()
            row("clock.fill", DT.blue, "scheduled scan · 6h") {
                HStack(spacing: 6) {
                    if model.applying == "schedule" { ProgressView().controlSize(.small).scaleEffect(0.7) }
                    Toggle("", isOn: Binding(get: { model.scheduleOn }, set: { model.toggleSchedule($0) })).labelsHidden().toggleStyle(.switch).controlSize(.small).tint(DT.green)
                }
            }
            RowDivider()
            row("lock.shield.fill", DT.purple, "execution guard") {
                HStack(spacing: 6) {
                    if model.applying == "guard-exec" { ProgressView().controlSize(.small).scaleEffect(0.7) }
                    Toggle("", isOn: Binding(get: { model.executionGuardOn }, set: { model.toggleExecutionGuard($0) })).labelsHidden().toggleStyle(.switch).controlSize(.small).tint(DT.green)
                }
            }
            RowDivider()
            if model.gitReposUnprotected > 0 {
                Button(action: { model.installGitGuard() }) {
                    row("hand.raised.fill", DT.orange, "protect \(model.gitReposUnprotected) repo\(model.gitReposUnprotected == 1 ? "" : "s")") {
                        if model.applying == "guard" { ProgressView().controlSize(.small).scaleEffect(0.7) }
                        else { Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold)).foregroundStyle(DT.dim) }
                    }
                }.buttonStyle(.plain).disabled(model.applying == "guard")
            } else {
                row("checkmark.seal.fill", DT.green, "all git repos protected") { EmptyView() }
            }
        }
    }

    private var activity: some View {
        Section(title: "activity.log") {
            if model.history.isEmpty {
                row("checkmark.circle.fill", DT.green, "no activity — all clear") { EmptyView() }
            } else {
                ScrollView {
                    VStack(spacing: 0) {
                        ForEach(Array(model.history.prefix(40).enumerated()), id: \.offset) { i, line in
                            if i > 0 { RowDivider() }
                            HStack(alignment: .top, spacing: 8) {
                                Image(systemName: line.contains("KILLED") ? "bolt.shield.fill" : line.contains("QUARANTINED") ? "lock.fill" : "chevron.right")
                                    .font(.system(size: 10)).foregroundStyle(line.contains("KILLED") ? DT.red : line.contains("QUARANTINED") ? DT.orange : DT.dim).padding(.top, 2)
                                Text(line).font(monoFont(9.5)).foregroundStyle(DT.dim).textSelection(.enabled).lineLimit(3)
                                Spacer(minLength: 0)
                            }.padding(.horizontal, 11).padding(.vertical, 7)
                        }
                    }
                }.frame(height: 150)
            }
        }
    }

    private var quarantine: some View {
        Section(title: "quarantine") {
            if model.quarantineItems.isEmpty {
                row("lock.open.fill", DT.dim, "nothing quarantined") { EmptyView() }
            } else {
                ScrollView {
                    VStack(spacing: 0) {
                        ForEach(Array(model.quarantineItems.enumerated()), id: \.element.path) { i, item in
                            if i > 0 { RowDivider() }
                            row("lock.doc.fill", DT.orange, item.name) {
                                Button("reveal") { model.reveal(item.path) }.buttonStyle(.plain).font(monoFont(10, .semibold)).foregroundStyle(DT.blue)
                            }
                        }
                    }
                }.frame(height: 150)
            }
        }
    }

    private var footer: some View {
        HStack(spacing: 14) {
            Button(action: { model.reveal("\(model.dir)/logs") }) { Text("logs").font(monoFont(10)) }.buttonStyle(.plain).foregroundStyle(DT.blue)
            Button(action: { model.openRepo() }) { Text("github").font(monoFont(10)) }.buttonStyle(.plain).foregroundStyle(DT.blue)
            Spacer()
            Button(action: { model.refreshFast(); model.loadStats(force: true) }) { Image(systemName: "arrow.clockwise") }.buttonStyle(.plain).foregroundStyle(DT.dim).font(.system(size: 11))
            Button(action: { NSApp.terminate(nil) }) { Image(systemName: "power") }.buttonStyle(.plain).foregroundStyle(DT.dim).font(.system(size: 11))
        }.padding(.top, 2)
    }
}

@main
struct BastionApp: App {
    @StateObject private var model = GuardModel()
    var body: some Scene {
        MenuBarExtra {
            PanelView(model: model)
        } label: {
            Image(systemName: model.clean ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
        }.menuBarExtraStyle(.window)
    }
}
