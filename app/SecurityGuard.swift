import SwiftUI
import AppKit

// MARK: - Model
@MainActor
final class GuardModel: ObservableObject {
    @Published var clean = true
    @Published var lastScan = "never"
    @Published var lastResult = "—"
    @Published var quarantineCount = 0
    @Published var reposMonitored = 0
    @Published var configsMonitored = 0
    @Published var findings: [String] = []
    @Published var history: [String] = []
    @Published var quarantineItems: [(name: String, path: String, when: String)] = []
    @Published var watcherOn = false
    @Published var scheduleOn = false
    @Published var scanning = false
    @Published var gitReposUnprotected = 0

    let dir = (NSHomeDirectory() as NSString).appendingPathComponent(".security-guard")
    var home: String { NSHomeDirectory() }
    var user: String { NSUserName() }
    let version = "2.0"

    init() { refresh(); computeStats() }

    @discardableResult
    private func sh(_ cmd: String) -> String {
        let p = Process(); p.launchPath = "/bin/bash"; p.arguments = ["-lc", cmd]
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = Pipe()
        do { try p.run() } catch { return "" }
        let d = pipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        return String(data: d, encoding: .utf8) ?? ""
    }

    func refresh() {
        let logs = "\(dir)/logs"
        let latest = sh("ls -1t \(logs)/scan-*.log 2>/dev/null | head -1").trimmingCharacters(in: .whitespacesAndNewlines)
        if !latest.isEmpty {
            let body = sh("cat '\(latest)' 2>/dev/null")
            if let r = body.split(separator: "\n").first(where: { $0.contains("RESULT:") }) {
                lastResult = r.replacingOccurrences(of: "RESULT:", with: "").trimmingCharacters(in: .whitespaces)
            }
            let stamp = (latest as NSString).lastPathComponent
                .replacingOccurrences(of: "scan-", with: "").replacingOccurrences(of: ".log", with: "")
            lastScan = prettyStamp(stamp)
        }
        let alerts = sh("tail -40 '\(dir)/ALERTS.txt' 2>/dev/null")
        history = alerts.split(separator: "\n").map(String.init).filter { !$0.isEmpty }.reversed()
        findings = history.filter { $0.contains("ALERT") || $0.contains("QUARANTINED") || $0.contains("DETECTED") }
        clean = findings.isEmpty && (lastResult.contains("CLEAN") || lastResult == "—")
        let qc = sh("find '\(dir)/quarantine' -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l").trimmingCharacters(in: .whitespacesAndNewlines)
        quarantineCount = Int(qc) ?? 0
        loadQuarantine()
        watcherOn = sh("launchctl list 2>/dev/null | grep -c securityguard.watcher").trimmingCharacters(in: .whitespacesAndNewlines) != "0"
        scheduleOn = sh("launchctl list 2>/dev/null | grep securityguard | grep -vc watcher").trimmingCharacters(in: .whitespacesAndNewlines) != "0"
    }

    func computeStats() {
        Task.detached { [dir, home] in
            let count: (String) -> Int = { cmd in
                let p = Process(); p.launchPath = "/bin/bash"; p.arguments = ["-lc", cmd]
                let pipe = Pipe(); p.standardOutput = pipe; p.standardError = Pipe()
                try? p.run(); let d = pipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
                return Int((String(data:d,encoding:.utf8) ?? "0").trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
            }
            let repos = count("find '\(home)' -maxdepth 5 -type d -name .git -not -path '*/node_modules/*' 2>/dev/null | wc -l")
            let cfgs  = count("find '\(home)' -maxdepth 6 -type f \\( -name '*.config.js' -o -name '*.config.mjs' -o -name '*.config.cjs' -o -name '*.config.ts' -o -name 'postcss.config.*' -o -name 'vite.config.*' -o -name 'next.config.*' \\) -not -path '*/node_modules/*' 2>/dev/null | wc -l")
            // git repos whose pre-push doesn't have the guard yet (default-hooks repos)
            let unprot = count("c=0; while IFS= read -r g; do r=$(dirname \"$g\"); hp=$(git -C \"$r\" config core.hooksPath 2>/dev/null); if [ -z \"$hp\" ] && ! grep -q security-guard \"$r/.git/hooks/pre-push\" 2>/dev/null; then c=$((c+1)); fi; done < <(find '\(home)' -maxdepth 5 -type d -name .git -not -path '*/node_modules/*' 2>/dev/null); echo $c")
            await MainActor.run { self.reposMonitored = repos; self.configsMonitored = cfgs; self.gitReposUnprotected = unprot }
        }
    }

    private func loadQuarantine() {
        let out = sh("ls -1t '\(dir)/quarantine' 2>/dev/null | head -20")
        quarantineItems = out.split(separator: "\n").map(String.init).filter { !$0.isEmpty }.map { batch in
            let full = "\(dir)/quarantine/\(batch)"
            let leaf = sh("find '\(full)' -mindepth 1 2>/dev/null | tail -1 | xargs basename 2>/dev/null").trimmingCharacters(in: .whitespacesAndNewlines)
            let when = sh("stat -f '%Sm' -t '%b %d, %H:%M' '\(full)' 2>/dev/null").trimmingCharacters(in: .whitespacesAndNewlines)
            return (name: leaf.isEmpty ? batch : leaf, path: full, when: when)
        }
    }

    private func prettyStamp(_ s: String) -> String {
        let f = DateFormatter(); f.dateFormat = "yyyyMMdd-HHmmss"
        if let d = f.date(from: s) { let o = DateFormatter(); o.dateFormat = "MMM d, h:mm a"; return o.string(from: d) }
        return s
    }

    func scanNow(reposOnly: Bool) {
        scanning = true
        let roots = reposOnly
            ? sh("find '\(home)' -maxdepth 5 -type d -name .git -not -path '*/node_modules/*' 2>/dev/null | sed 's|/.git$||' | tr '\\n' ' '")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            : home
        Task.detached { [dir] in
            let p = Process(); p.launchPath = "/bin/bash"
            p.arguments = ["-lc", "bash '\(dir)/guard.sh' \(roots.isEmpty ? NSHomeDirectory() : roots)"]
            try? p.run(); p.waitUntilExit()
            await MainActor.run { self.scanning = false; self.refresh() }
        }
    }

    func toggleWatcher(_ on: Bool) {
        if on { sh("bash '\(dir)/install.sh' --watch") }
        else { sh("launchctl unload ~/Library/LaunchAgents/com.\(user).securityguard.watcher.plist 2>/dev/null; rm -f ~/Library/LaunchAgents/com.\(user).securityguard.watcher.plist") }
        refresh()
    }
    func toggleSchedule(_ on: Bool) {
        if on { sh("bash '\(dir)/install.sh' --scan") }
        else { sh("launchctl unload ~/Library/LaunchAgents/com.\(user).securityguard.plist 2>/dev/null; rm -f ~/Library/LaunchAgents/com.\(user).securityguard.plist") }
        refresh()
    }
    func installGitGuard() {
        sh("""
        while IFS= read -r g; do r=$(dirname "$g"); hp=$(git -C "$r" config core.hooksPath 2>/dev/null);
          if [ -z "$hp" ]; then cp '\(dir)/git-guard' "$r/.git/hooks/pre-push" 2>/dev/null && chmod +x "$r/.git/hooks/pre-push" 2>/dev/null; fi;
        done < <(find '\(home)' -maxdepth 5 -type d -name .git -not -path '*/node_modules/*' 2>/dev/null)
        """)
        computeStats()
    }
    func reveal(_ path: String) { NSWorkspace.shared.open(URL(fileURLWithPath: path)) }
    func openRepo() { NSWorkspace.shared.open(URL(string: "https://github.com/realanshuman/bastion")!) }
}

// MARK: - Reusable bits
struct StatTile: View {
    let value: String, label: String, systemImage: String, tint: Color
    var body: some View {
        VStack(spacing: 3) {
            Image(systemName: systemImage).font(.system(size: 15, weight: .semibold)).foregroundStyle(tint)
            Text(value).font(.system(size: 17, weight: .bold, design: .rounded))
            Text(label).font(.system(size: 9)).foregroundStyle(.secondary).textCase(.uppercase)
        }
        .frame(maxWidth: .infinity).padding(.vertical, 10)
        .background(Color.primary.opacity(0.04)).clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

struct PanelView: View {
    @ObservedObject var model: GuardModel
    @State private var tab = 0
    @State private var reposOnly = false
    private var accent: Color { model.clean ? .green : .orange }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            hero
            stats
            scanButton
            Picker("", selection: $tab) {
                Text("Overview").tag(0); Text("Activity").tag(1); Text("Quarantine").tag(2)
            }.pickerStyle(.segmented).labelsHidden()
            Group {
                if tab == 0 { overview } else if tab == 1 { activity } else { quarantine }
            }
            Divider()
            footer
        }
        .padding(16).frame(width: 360)
        .onAppear { model.refresh(); model.computeStats() }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: model.clean ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                .font(.system(size: 20, weight: .semibold)).foregroundStyle(accent)
            Text("Bastion").font(.system(size: 17, weight: .bold))
            Text("v\(model.version)").font(.caption2).foregroundStyle(.secondary)
            Spacer()
            Text(model.clean ? "PROTECTED" : "\(model.findings.count) ALERT\(model.findings.count == 1 ? "" : "S")")
                .font(.system(size: 10, weight: .heavy))
                .padding(.horizontal, 9).padding(.vertical, 4)
                .background(accent.opacity(0.16)).foregroundStyle(accent).clipShape(Capsule())
        }
    }

    private var hero: some View {
        HStack(spacing: 12) {
            Image(systemName: model.clean ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                .font(.system(size: 30)).foregroundStyle(accent)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.clean ? "No threats detected" : "Threats need attention")
                    .font(.system(size: 15, weight: .semibold))
                Text("Last scan \(model.lastScan) · \(model.lastResult)")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
        }
        .padding(14)
        .background(LinearGradient(colors: [accent.opacity(0.18), accent.opacity(0.06)], startPoint: .topLeading, endPoint: .bottomTrailing))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private var stats: some View {
        HStack(spacing: 8) {
            StatTile(value: "\(model.reposMonitored)", label: "Repos", systemImage: "folder.fill", tint: .blue)
            StatTile(value: "\(model.configsMonitored)", label: "Configs", systemImage: "doc.text.fill", tint: .purple)
            StatTile(value: "\(model.quarantineCount)", label: "Quarantine", systemImage: "lock.fill", tint: model.quarantineCount > 0 ? .orange : .secondary)
        }
    }

    private var scanButton: some View {
        VStack(spacing: 6) {
            Button(action: { model.scanNow(reposOnly: reposOnly) }) {
                HStack { if model.scanning { ProgressView().controlSize(.small) }
                    Image(systemName: "magnifyingglass")
                    Text(model.scanning ? "Scanning…" : "Scan Now").fontWeight(.semibold) }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent).controlSize(.large).tint(accent).disabled(model.scanning)
            Toggle(isOn: $reposOnly) { Text("Git repos only (faster)").font(.caption).foregroundStyle(.secondary) }
                .toggleStyle(.checkbox).controlSize(.small)
        }
    }

    private var overview: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("PROTECTION").font(.system(size: 10, weight: .bold)).foregroundStyle(.secondary)
            Toggle(isOn: Binding(get: { model.watcherOn }, set: { model.toggleWatcher($0) })) {
                Label { Text("Real-time watcher").font(.callout) } icon: { Image(systemName: "bolt.shield.fill").foregroundStyle(.green) }
            }
            Toggle(isOn: Binding(get: { model.scheduleOn }, set: { model.toggleSchedule($0) })) {
                Label { Text("Scheduled scan (6h + login)").font(.callout) } icon: { Image(systemName: "clock.arrow.circlepath").foregroundStyle(.blue) }
            }
            if model.gitReposUnprotected > 0 {
                Button(action: { model.installGitGuard() }) {
                    Label("Protect \(model.gitReposUnprotected) repo\(model.gitReposUnprotected == 1 ? "" : "s") (block infected commits)", systemImage: "hand.raised.fill")
                        .font(.caption)
                }.buttonStyle(.bordered).controlSize(.small)
            } else {
                Label("All git repos protected", systemImage: "checkmark.seal.fill").font(.caption).foregroundStyle(.green)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var activity: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 6) {
                if model.history.isEmpty {
                    Label("No activity — all clear", systemImage: "checkmark.circle").font(.caption).foregroundStyle(.secondary).padding(.vertical, 8)
                } else {
                    ForEach(model.history.prefix(30), id: \.self) { line in
                        Text(line).font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(line.contains("QUARANTINED") ? .orange : .primary)
                            .textSelection(.enabled).lineLimit(3)
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
                            Spacer()
                            Button("Reveal") { model.reveal(item.path) }.buttonStyle(.link).font(.caption2)
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
            Button("Refresh") { model.refresh(); model.computeStats() }.buttonStyle(.link).font(.caption)
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
        }
        .menuBarExtraStyle(.window)
    }
}
