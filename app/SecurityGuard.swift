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
    @Published var history: [String] = []
    @Published var quarantineItems: [(name: String, path: String, when: String)] = []
    @Published var watcherOn = false
    @Published var scheduleOn = false
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
    let version = "2.1.0"
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
            let finds = hist.filter { $0.contains("ALERT") || $0.contains("QUARANTINED") || $0.contains("DETECTED") }
            let qCount = Int(runShell("find '\(dir)/quarantine' -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l").trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
            var qItems: [(name: String, path: String, when: String)] = []
            for b in runShell("ls -1t '\(dir)/quarantine' 2>/dev/null | head -15").split(separator: "\n").map(String.init) where !b.isEmpty {
                let full = "\(dir)/quarantine/\(b)"
                let leaf = runShell("find '\(full)' -mindepth 1 2>/dev/null | tail -1 | xargs basename 2>/dev/null").trimmingCharacters(in: .whitespacesAndNewlines)
                let when = runShell("stat -f '%Sm' -t '%b %d, %H:%M' '\(full)' 2>/dev/null").trimmingCharacters(in: .whitespacesAndNewlines)
                qItems.append((name: leaf.isEmpty ? b : leaf, path: full, when: when))
            }
            let w = runShell("launchctl list 2>/dev/null | grep -c io.anshuman.bastion.watcher").trimmingCharacters(in: .whitespacesAndNewlines) != "0"
            let sc = runShell("launchctl list 2>/dev/null | grep -c io.anshuman.bastion.scan").trimmingCharacters(in: .whitespacesAndNewlines) != "0"
            let isClean = finds.isEmpty && (result.contains("CLEAN") || result == "—")
            await MainActor.run {
                withAnimation(.easeInOut(duration: 0.2)) {
                    self.lastResult = result; self.lastScan = scan; self.history = hist; self.findings = finds
                    self.quarantineCount = qCount; self.quarantineItems = qItems
                    self.watcherOn = w; self.scheduleOn = sc; self.clean = isClean
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
                          : "launchctl unload ~/Library/LaunchAgents/io.anshuman.bastion.watcher.plist 2>/dev/null; rm -f ~/Library/LaunchAgents/io.anshuman.bastion.watcher.plist")
    }
    func toggleSchedule(_ on: Bool) {
        withAnimation { scheduleOn = on }  // optimistic
        act("schedule", on ? "bash '\(dir)/install.sh' --scan"
                           : "launchctl unload ~/Library/LaunchAgents/io.anshuman.bastion.scan.plist 2>/dev/null; rm -f ~/Library/LaunchAgents/io.anshuman.bastion.scan.plist")
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

struct StatTile: View {
    let value: String, label: String, systemImage: String, tint: Color, loading: Bool
    var body: some View {
        VStack(spacing: 4) {
            Image(systemName: systemImage).font(.system(size: 15, weight: .semibold)).foregroundStyle(tint)
            if loading { ProgressView().controlSize(.small).frame(height: 22) }
            else { Text(value).font(.system(size: 18, weight: .bold, design: .rounded)).contentTransition(.numericText()).frame(height: 22) }
            Text(label).font(.system(size: 9)).foregroundStyle(.secondary).textCase(.uppercase)
        }
        .frame(maxWidth: .infinity).padding(.vertical, 11)
        .background(Color.primary.opacity(0.045)).clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

struct PanelView: View {
    @ObservedObject var model: GuardModel
    @State private var tab = 0
    @State private var reposOnly = false
    @State private var ticker: Timer?
    private var accent: Color { model.clean ? .green : .orange }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header; hero; stats; scanButton
            Picker("", selection: $tab.animation(.easeInOut)) {
                Text("Overview").tag(0); Text("Activity").tag(1); Text("Quarantine").tag(2)
            }.pickerStyle(.segmented).labelsHidden()
            Group { switch tab { case 0: overview; case 1: activity; default: quarantine } }
            Divider(); footer
        }
        .padding(16).frame(width: 360)
        .animation(.easeInOut(duration: 0.2), value: model.clean)
        .onAppear {
            model.refreshFast(); model.loadStats()
            ticker?.invalidate()
            ticker = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { _ in Task { @MainActor in model.refreshFast() } }
        }
        .onDisappear { ticker?.invalidate(); ticker = nil }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: model.clean ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                .font(.system(size: 20, weight: .semibold)).foregroundStyle(accent).contentTransition(.symbolEffect(.replace))
            Text("Bastion").font(.system(size: 17, weight: .bold))
            Text("v\(model.version)").font(.caption2).foregroundStyle(.secondary)
            Spacer()
            Text(model.clean ? "PROTECTED" : "\(model.findings.count) ALERT\(model.findings.count == 1 ? "" : "S")")
                .font(.system(size: 10, weight: .heavy)).padding(.horizontal, 9).padding(.vertical, 4)
                .background(accent.opacity(0.16)).foregroundStyle(accent).clipShape(Capsule())
        }
    }
    private var hero: some View {
        HStack(spacing: 12) {
            Image(systemName: model.clean ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                .font(.system(size: 30)).foregroundStyle(accent).contentTransition(.symbolEffect(.replace))
            VStack(alignment: .leading, spacing: 2) {
                Text(model.clean ? "No threats detected" : "Threats need attention").font(.system(size: 15, weight: .semibold))
                Text("Last scan \(model.lastScan) · \(model.lastResult)").font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
        }
        .padding(14)
        .background(LinearGradient(colors: [accent.opacity(0.18), accent.opacity(0.06)], startPoint: .topLeading, endPoint: .bottomTrailing))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
    private var stats: some View {
        HStack(spacing: 8) {
            StatTile(value: "\(model.reposMonitored)", label: "Repos", systemImage: "folder.fill", tint: .blue, loading: model.statsLoading)
            StatTile(value: "\(model.configsMonitored)", label: "Configs", systemImage: "doc.text.fill", tint: .purple, loading: model.statsLoading)
            StatTile(value: "\(model.quarantineCount)", label: "Quarantine", systemImage: "lock.fill", tint: model.quarantineCount > 0 ? .orange : .secondary, loading: false)
        }
    }
    private var scanButton: some View {
        VStack(spacing: 6) {
            Button(action: { model.scanNow(reposOnly: reposOnly) }) {
                HStack(spacing: 6) {
                    if model.scanning { ProgressView().controlSize(.small) } else { Image(systemName: "magnifyingglass") }
                    Text(model.scanning ? "Scanning…" : "Scan Now").fontWeight(.semibold)
                }.frame(maxWidth: .infinity)
            }.buttonStyle(.borderedProminent).controlSize(.large).tint(accent).disabled(model.scanning)
            Toggle(isOn: $reposOnly) { Text("Git repos only (faster)").font(.caption).foregroundStyle(.secondary) }
                .toggleStyle(.checkbox).controlSize(.small)
        }
    }
    private var overview: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("PROTECTION").font(.system(size: 10, weight: .bold)).foregroundStyle(.secondary)
            toggleRow("Real-time watcher", "bolt.shield.fill", .green, isOn: model.watcherOn, key: "watcher") { model.toggleWatcher($0) }
            toggleRow("Scheduled scan (6h + login)", "clock.arrow.circlepath", .blue, isOn: model.scheduleOn, key: "schedule") { model.toggleSchedule($0) }
            if model.gitReposUnprotected > 0 {
                Button(action: { model.installGitGuard() }) {
                    HStack(spacing: 6) {
                        if model.applying == "guard" { ProgressView().controlSize(.small) } else { Image(systemName: "hand.raised.fill") }
                        Text("Protect \(model.gitReposUnprotected) repo\(model.gitReposUnprotected == 1 ? "" : "s") (block commits)")
                    }.font(.caption)
                }.buttonStyle(.bordered).controlSize(.small).disabled(model.applying == "guard")
            } else if !model.statsLoading {
                Label("All git repos protected", systemImage: "checkmark.seal.fill").font(.caption).foregroundStyle(.green)
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
    private func toggleRow(_ label: String, _ icon: String, _ tint: Color, isOn: Bool, key: String, _ set: @escaping (Bool) -> Void) -> some View {
        HStack {
            Image(systemName: icon).foregroundStyle(tint).frame(width: 18)
            Text(label).font(.callout)
            Spacer()
            if model.applying == key { ProgressView().controlSize(.small).scaleEffect(0.8) }
            Toggle("", isOn: Binding(get: { isOn }, set: set)).labelsHidden().toggleStyle(.switch).controlSize(.small)
        }
    }
    private var activity: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 6) {
                if model.history.isEmpty {
                    Label("No activity — all clear", systemImage: "checkmark.circle").font(.caption).foregroundStyle(.secondary).padding(.vertical, 8)
                } else {
                    ForEach(model.history.prefix(30), id: \.self) { line in
                        Text(line).font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(line.contains("QUARANTINED") ? .orange : .primary).textSelection(.enabled).lineLimit(3)
                        Divider().opacity(0.4)
                    }
                }
            }
        }.frame(height: 120)
    }
    private var quarantine: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 6) {
                if model.quarantineItems.isEmpty {
                    Label("Nothing quarantined", systemImage: "lock.open").font(.caption).foregroundStyle(.secondary).padding(.vertical, 8)
                } else {
                    ForEach(model.quarantineItems, id: \.path) { item in
                        HStack {
                            Image(systemName: "lock.doc.fill").foregroundStyle(.orange)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(item.name).font(.caption.weight(.medium)).lineLimit(1)
                                Text(item.when).font(.system(size: 9)).foregroundStyle(.secondary)
                            }
                            Spacer(); Button("Reveal") { model.reveal(item.path) }.buttonStyle(.link).font(.caption2)
                        }
                        Divider().opacity(0.4)
                    }
                }
            }
        }.frame(height: 120)
    }
    private var footer: some View {
        HStack(spacing: 12) {
            Button("Logs") { model.reveal("\(model.dir)/logs") }.buttonStyle(.link).font(.caption)
            Button("GitHub") { model.openRepo() }.buttonStyle(.link).font(.caption)
            Spacer()
            Button(action: { model.refreshFast(); model.loadStats(force: true) }) { Text("Refresh") }.buttonStyle(.link).font(.caption)
            Button("Quit") { NSApp.terminate(nil) }.buttonStyle(.link).font(.caption).foregroundStyle(.secondary)
        }
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
