import SwiftUI
import AppKit

// Background-safe shell helper (never runs on the main thread).
func runShell(_ cmd: String) -> String {
    let p = Process(); p.launchPath = "/bin/bash"; p.arguments = ["-lc", cmd]
    let pipe = Pipe(); p.standardOutput = pipe; p.standardError = Pipe()
    do { try p.run() } catch { return "" }
    let d = pipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
    return String(data: d, encoding: .utf8) ?? ""
}

struct Snapshot {
    var clean = true, lastScan = "never", lastResult = "—"
    var quarantineCount = 0, reposMonitored = 0, configsMonitored = 0, gitReposUnprotected = 0
    var findings: [String] = [], history: [String] = []
    var quarantineItems: [(name: String, path: String, when: String)] = []
    var watcherOn = false, scheduleOn = false
}

@MainActor
final class GuardModel: ObservableObject {
    @Published var s = Snapshot()
    @Published var scanning = false
    @Published var busy = false          // a toggle/action is applying
    let dir = (NSHomeDirectory() as NSString).appendingPathComponent(".security-guard")
    let home = NSHomeDirectory()
    let version = "2.0.2"
    private let libExcl = "-not -path '*/node_modules/*' -not -path '*/Library/*'"

    init() { refresh() }

    // All reads happen off the main thread; UI updates are animated on the main actor.
    func refresh() {
        let dir = self.dir, home = self.home, libExcl = self.libExcl
        Task.detached(priority: .userInitiated) {
            var snap = Snapshot()
            let latest = runShell("ls -1t \(dir)/logs/scan-*.log 2>/dev/null | head -1").trimmingCharacters(in: .whitespacesAndNewlines)
            if !latest.isEmpty {
                let body = runShell("cat '\(latest)' 2>/dev/null")
                if let r = body.split(separator: "\n").first(where: { $0.contains("RESULT:") }) {
                    snap.lastResult = r.replacingOccurrences(of: "RESULT:", with: "").trimmingCharacters(in: .whitespaces)
                }
                let stamp = (latest as NSString).lastPathComponent.replacingOccurrences(of: "scan-", with: "").replacingOccurrences(of: ".log", with: "")
                let f = DateFormatter(); f.dateFormat = "yyyyMMdd-HHmmss"
                if let d = f.date(from: stamp) { let o = DateFormatter(); o.dateFormat = "MMM d, h:mm a"; snap.lastScan = o.string(from: d) } else { snap.lastScan = stamp }
            }
            let alerts = runShell("tail -40 '\(dir)/ALERTS.txt' 2>/dev/null")
            snap.history = alerts.split(separator: "\n").map(String.init).filter { !$0.isEmpty }.reversed()
            snap.findings = snap.history.filter { $0.contains("ALERT") || $0.contains("QUARANTINED") || $0.contains("DETECTED") }
            snap.clean = snap.findings.isEmpty && (snap.lastResult.contains("CLEAN") || snap.lastResult == "—")
            snap.quarantineCount = Int(runShell("find '\(dir)/quarantine' -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l").trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
            let batches = runShell("ls -1t '\(dir)/quarantine' 2>/dev/null | head -20").split(separator: "\n").map(String.init).filter { !$0.isEmpty }
            snap.quarantineItems = batches.map { b in
                let full = "\(dir)/quarantine/\(b)"
                let leaf = runShell("find '\(full)' -mindepth 1 2>/dev/null | tail -1 | xargs basename 2>/dev/null").trimmingCharacters(in: .whitespacesAndNewlines)
                let when = runShell("stat -f '%Sm' -t '%b %d, %H:%M' '\(full)' 2>/dev/null").trimmingCharacters(in: .whitespacesAndNewlines)
                return (name: leaf.isEmpty ? b : leaf, path: full, when: when)
            }
            snap.watcherOn = runShell("launchctl list 2>/dev/null | grep -c io.anshuman.bastion.watcher").trimmingCharacters(in: .whitespacesAndNewlines) != "0"
            snap.scheduleOn = runShell("launchctl list 2>/dev/null | grep -c io.anshuman.bastion.scan").trimmingCharacters(in: .whitespacesAndNewlines) != "0"
            snap.reposMonitored = Int(runShell("find '\(home)' -maxdepth 5 -type d -name .git \(libExcl) 2>/dev/null | wc -l").trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
            snap.configsMonitored = Int(runShell("find '\(home)' -maxdepth 6 -type f \\( -name '*.config.js' -o -name '*.config.mjs' -o -name '*.config.cjs' -o -name '*.config.ts' -o -name 'postcss.config.*' -o -name 'vite.config.*' -o -name 'next.config.*' \\) \(libExcl) 2>/dev/null | wc -l").trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
            snap.gitReposUnprotected = Int(runShell("c=0; while IFS= read -r g; do r=$(dirname \"$g\"); hp=$(git -C \"$r\" config core.hooksPath 2>/dev/null); if [ -z \"$hp\" ] && ! grep -q security-guard \"$r/.git/hooks/pre-push\" 2>/dev/null; then c=$((c+1)); fi; done < <(find '\(home)' -maxdepth 5 -type d -name .git \(libExcl) 2>/dev/null); echo $c").trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
            let final = snap; await MainActor.run { withAnimation(.easeInOut(duration: 0.25)) { self.s = final } }
        }
    }

    func scanNow(reposOnly: Bool) {
        withAnimation { scanning = true }
        let dir = self.dir, home = self.home, libExcl = self.libExcl
        Task.detached(priority: .userInitiated) {
            let roots = reposOnly
                ? runShell("find '\(home)' -maxdepth 5 -type d -name .git \(libExcl) 2>/dev/null | sed 's|/.git$||' | tr '\\n' ' '").trimmingCharacters(in: .whitespacesAndNewlines)
                : home
            _ = runShell("bash '\(dir)/guard.sh' \(roots.isEmpty ? home : roots)")
            await MainActor.run { withAnimation { self.scanning = false }; self.refresh() }
        }
    }

    private func apply(_ cmd: String) {
        withAnimation { busy = true }
        Task.detached(priority: .userInitiated) {
            _ = runShell(cmd)
            await MainActor.run { withAnimation { self.busy = false }; self.refresh() }
        }
    }
    func toggleWatcher(_ on: Bool) {
        apply(on ? "bash '\(dir)/install.sh' --watch"
                 : "launchctl unload ~/Library/LaunchAgents/io.anshuman.bastion.watcher.plist 2>/dev/null; rm -f ~/Library/LaunchAgents/io.anshuman.bastion.watcher.plist")
    }
    func toggleSchedule(_ on: Bool) {
        apply(on ? "bash '\(dir)/install.sh' --scan"
                 : "launchctl unload ~/Library/LaunchAgents/io.anshuman.bastion.scan.plist 2>/dev/null; rm -f ~/Library/LaunchAgents/io.anshuman.bastion.scan.plist")
    }
    func installGitGuard() {
        apply("while IFS= read -r g; do r=$(dirname \"$g\"); hp=$(git -C \"$r\" config core.hooksPath 2>/dev/null); if [ -z \"$hp\" ]; then cp '\(dir)/git-guard' \"$r/.git/hooks/pre-push\" 2>/dev/null && chmod +x \"$r/.git/hooks/pre-push\" 2>/dev/null; fi; done < <(find '\(home)' -maxdepth 5 -type d -name .git \(libExcl) 2>/dev/null)")
    }
    func reveal(_ path: String) { NSWorkspace.shared.open(URL(fileURLWithPath: path)) }
    func openRepo() { NSWorkspace.shared.open(URL(string: "https://github.com/realanshuman/bastion")!) }
}

struct StatTile: View {
    let value: String, label: String, systemImage: String, tint: Color
    var body: some View {
        VStack(spacing: 4) {
            Image(systemName: systemImage).font(.system(size: 15, weight: .semibold)).foregroundStyle(tint)
            Text(value).font(.system(size: 18, weight: .bold, design: .rounded)).contentTransition(.numericText())
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
    private var s: Snapshot { model.s }
    private var accent: Color { s.clean ? .green : .orange }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header; hero; stats; scanButton
            Picker("", selection: $tab.animation(.easeInOut)) {
                Text("Overview").tag(0); Text("Activity").tag(1); Text("Quarantine").tag(2)
            }.pickerStyle(.segmented).labelsHidden()
            Group {
                switch tab { case 0: overview; case 1: activity; default: quarantine }
            }.transition(.opacity)
            Divider(); footer
        }
        .padding(16).frame(width: 360)
        .animation(.easeInOut(duration: 0.25), value: s.clean)
        .onAppear {
            model.refresh()
            ticker?.invalidate()
            ticker = Timer.scheduledTimer(withTimeInterval: 4, repeats: true) { _ in Task { @MainActor in model.refresh() } }
        }
        .onDisappear { ticker?.invalidate(); ticker = nil }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: s.clean ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                .font(.system(size: 20, weight: .semibold)).foregroundStyle(accent).contentTransition(.symbolEffect(.replace))
            Text("Bastion").font(.system(size: 17, weight: .bold))
            Text("v\(model.version)").font(.caption2).foregroundStyle(.secondary)
            Spacer()
            Text(s.clean ? "PROTECTED" : "\(s.findings.count) ALERT\(s.findings.count == 1 ? "" : "S")")
                .font(.system(size: 10, weight: .heavy))
                .padding(.horizontal, 9).padding(.vertical, 4)
                .background(accent.opacity(0.16)).foregroundStyle(accent).clipShape(Capsule())
        }
    }
    private var hero: some View {
        HStack(spacing: 12) {
            Image(systemName: s.clean ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                .font(.system(size: 30)).foregroundStyle(accent).contentTransition(.symbolEffect(.replace))
            VStack(alignment: .leading, spacing: 2) {
                Text(s.clean ? "No threats detected" : "Threats need attention").font(.system(size: 15, weight: .semibold))
                Text("Last scan \(s.lastScan) · \(s.lastResult)").font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
        }
        .padding(14)
        .background(LinearGradient(colors: [accent.opacity(0.18), accent.opacity(0.06)], startPoint: .topLeading, endPoint: .bottomTrailing))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
    private var stats: some View {
        HStack(spacing: 8) {
            StatTile(value: "\(s.reposMonitored)", label: "Repos", systemImage: "folder.fill", tint: .blue)
            StatTile(value: "\(s.configsMonitored)", label: "Configs", systemImage: "doc.text.fill", tint: .purple)
            StatTile(value: "\(s.quarantineCount)", label: "Quarantine", systemImage: "lock.fill", tint: s.quarantineCount > 0 ? .orange : .secondary)
        }
    }
    private var scanButton: some View {
        VStack(spacing: 6) {
            Button(action: { model.scanNow(reposOnly: reposOnly) }) {
                HStack(spacing: 6) {
                    if model.scanning { ProgressView().controlSize(.small) } else { Image(systemName: "magnifyingglass") }
                    Text(model.scanning ? "Scanning…" : "Scan Now").fontWeight(.semibold)
                }.frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent).controlSize(.large).tint(accent).disabled(model.scanning)
            Toggle(isOn: $reposOnly) { Text("Git repos only (faster)").font(.caption).foregroundStyle(.secondary) }
                .toggleStyle(.checkbox).controlSize(.small)
        }
    }
    private var overview: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack { Text("PROTECTION").font(.system(size: 10, weight: .bold)).foregroundStyle(.secondary)
                if model.busy { ProgressView().controlSize(.small).scaleEffect(0.7) } }
            Toggle(isOn: Binding(get: { s.watcherOn }, set: { model.toggleWatcher($0) })) {
                Label { Text("Real-time watcher").font(.callout) } icon: { Image(systemName: "bolt.shield.fill").foregroundStyle(.green) }
            }.disabled(model.busy)
            Toggle(isOn: Binding(get: { s.scheduleOn }, set: { model.toggleSchedule($0) })) {
                Label { Text("Scheduled scan (6h + login)").font(.callout) } icon: { Image(systemName: "clock.arrow.circlepath").foregroundStyle(.blue) }
            }.disabled(model.busy)
            if s.gitReposUnprotected > 0 {
                Button(action: { model.installGitGuard() }) {
                    Label("Protect \(s.gitReposUnprotected) repo\(s.gitReposUnprotected == 1 ? "" : "s") (block commits)", systemImage: "hand.raised.fill").font(.caption)
                }.buttonStyle(.bordered).controlSize(.small).disabled(model.busy)
            } else {
                Label("All git repos protected", systemImage: "checkmark.seal.fill").font(.caption).foregroundStyle(.green)
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
    private var activity: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 6) {
                if s.history.isEmpty {
                    Label("No activity — all clear", systemImage: "checkmark.circle").font(.caption).foregroundStyle(.secondary).padding(.vertical, 8)
                } else {
                    ForEach(s.history.prefix(30), id: \.self) { line in
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
                if s.quarantineItems.isEmpty {
                    Label("Nothing quarantined", systemImage: "lock.open").font(.caption).foregroundStyle(.secondary).padding(.vertical, 8)
                } else {
                    ForEach(s.quarantineItems, id: \.path) { item in
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
            Button("Refresh") { model.refresh() }.buttonStyle(.link).font(.caption)
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
            Image(systemName: model.s.clean ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
        }.menuBarExtraStyle(.window)
    }
}
