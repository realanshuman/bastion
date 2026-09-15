import SwiftUI
import AppKit

// MARK: - Model
@MainActor
final class GuardModel: ObservableObject {
    @Published var clean = true
    @Published var lastScan = "never"
    @Published var lastResult = "—"
    @Published var quarantineCount = 0
    @Published var findings: [String] = []
    @Published var watcherOn = false
    @Published var scheduleOn = false
    @Published var scanning = false

    let dir = (NSHomeDirectory() as NSString).appendingPathComponent(".security-guard")
    var home: String { NSHomeDirectory() }
    var user: String { NSUserName() }

    init() { refresh() }

    @discardableResult
    private func sh(_ cmd: String) -> String {
        let p = Process()
        p.launchPath = "/bin/bash"
        p.arguments = ["-lc", cmd]
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = Pipe()
        do { try p.run() } catch { return "" }
        let d = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(data: d, encoding: .utf8) ?? ""
    }

    func refresh() {
        // latest scan log
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
        // findings
        let alerts = sh("tail -20 '\(dir)/ALERTS.txt' 2>/dev/null")
        findings = alerts.split(separator: "\n").map(String.init).filter { !$0.isEmpty }
        clean = findings.isEmpty && (lastResult.contains("CLEAN") || lastResult == "—")
        // quarantine
        let qc = sh("find '\(dir)/quarantine' -mindepth 1 -maxdepth 2 2>/dev/null | wc -l").trimmingCharacters(in: .whitespacesAndNewlines)
        quarantineCount = Int(qc) ?? 0
        // agent states
        watcherOn = sh("launchctl list 2>/dev/null | grep -c securityguard.watcher").trimmingCharacters(in: .whitespacesAndNewlines) != "0"
        scheduleOn = sh("launchctl list 2>/dev/null | grep securityguard | grep -vc watcher").trimmingCharacters(in: .whitespacesAndNewlines) != "0"
    }

    private func prettyStamp(_ s: String) -> String {
        let f = DateFormatter(); f.dateFormat = "yyyyMMdd-HHmmss"
        if let d = f.date(from: s) { let o = DateFormatter(); o.dateFormat = "MMM d, h:mm a"; return o.string(from: d) }
        return s
    }

    func scanNow() {
        scanning = true
        Task.detached { [dir, home] in
            let p = Process(); p.launchPath = "/bin/bash"
            p.arguments = ["\(dir)/guard.sh", home]
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
    func reveal(_ sub: String) { NSWorkspace.shared.open(URL(fileURLWithPath: "\(dir)/\(sub)")) }
}

// MARK: - UI
struct PanelView: View {
    @ObservedObject var model: GuardModel
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            statusBlock
            Divider().padding(.vertical, 2)
            controls
            Divider().padding(.vertical, 2)
            footer
        }
        .padding(14)
        .frame(width: 340)
        .onAppear { model.refresh() }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: model.clean ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                .font(.system(size: 22, weight: .semibold))
                .foregroundStyle(model.clean ? Color.green : Color.orange)
            VStack(alignment: .leading, spacing: 1) {
                Text("Security Guard").font(.headline)
                Text(model.clean ? "Protected" : "Threats need attention")
                    .font(.caption).foregroundStyle(model.clean ? Color.secondary : Color.orange)
            }
            Spacer()
            statusPill
        }
        .padding(.bottom, 10)
    }

    private var statusPill: some View {
        Text(model.clean ? "CLEAN" : "\(model.findings.count)")
            .font(.caption2.bold())
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(model.clean ? Color.green.opacity(0.15) : Color.orange.opacity(0.2))
            .foregroundStyle(model.clean ? Color.green : Color.orange)
            .clipShape(Capsule())
    }

    private var statusBlock: some View {
        VStack(alignment: .leading, spacing: 6) {
            row("Last scan", model.lastScan)
            row("Result", model.lastResult)
            row("Quarantined", "\(model.quarantineCount) item\(model.quarantineCount == 1 ? "" : "s")")
            if !model.findings.isEmpty {
                Text("Findings").font(.caption.bold()).foregroundStyle(.orange).padding(.top, 4)
                ForEach(model.findings.prefix(4), id: \.self) { f in
                    Text(f).font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary).lineLimit(2)
                }
            }
        }
        .padding(.vertical, 8)
    }

    private var controls: some View {
        VStack(spacing: 10) {
            Button(action: { model.scanNow() }) {
                HStack { if model.scanning { ProgressView().controlSize(.small) }
                    Text(model.scanning ? "Scanning…" : "Scan Now").frame(maxWidth: .infinity) }
            }
            .buttonStyle(.borderedProminent).controlSize(.large).disabled(model.scanning)

            Toggle(isOn: Binding(get: { model.watcherOn }, set: { model.toggleWatcher($0) })) {
                Label("Real-time watcher", systemImage: "bolt.shield").font(.callout)
            }
            Toggle(isOn: Binding(get: { model.scheduleOn }, set: { model.toggleSchedule($0) })) {
                Label("Scheduled scan (6h + login)", systemImage: "clock.arrow.circlepath").font(.callout)
            }
        }
        .padding(.vertical, 6)
    }

    private var footer: some View {
        HStack {
            Button("Quarantine") { model.reveal("quarantine") }.buttonStyle(.link).font(.caption)
            Button("Logs") { model.reveal("logs") }.buttonStyle(.link).font(.caption)
            Spacer()
            Button("Quit") { NSApp.terminate(nil) }.buttonStyle(.link).font(.caption).foregroundStyle(.secondary)
        }
        .padding(.top, 8)
    }

    private func row(_ k: String, _ v: String) -> some View {
        HStack { Text(k).font(.caption).foregroundStyle(.secondary); Spacer()
            Text(v).font(.caption.weight(.medium)) }
    }
}

@main
struct SecurityGuardApp: App {
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
