// Protection.swift: how much Bastion does for you. Three levels most people pick from (Basic, Recommended, Maximum),
// then every part of them, grouped by what it does, each with one plain sentence. Changing a part is fine: the level
// just reads "Custom". Levels come from `bastion protect`, so the window, the terminal and Ask always agree.
import SwiftUI
import AppKit

struct ProtectionPage: View {
    @ObservedObject var store: AppStore
    var body: some View {
        VStack(spacing: 0) {
            TopBar(crumbs: ["Protection"])
            PageBody(width: 900) {
                PageSection(title: "Protection level", note: "How much Bastion does on its own. You can change each part below.") {
                    VStack(alignment: .leading, spacing: 12) {
                        if store.level == "custom" || store.level == "off" { LevelNotice(level: store.level) }
                        LevelCards(store: store)
                    }
                }
                PageSection(title: "Watching this Mac") {
                    RowGroup {
                        toggleRow("bolt", "Real-time watcher", "Stops malware the moment it starts, and cuts its connections to attackers.", feature: "watcher")
                        Hairline()
                        ScheduleRow(store: store)
                    }
                }
                PageSection(title: "Stopping malware before it runs") {
                    RowGroup {
                        toggleRow("lock.shield", "Execution guard", "npm, node, pnpm, yarn and bun refuse to start inside an infected project, in any terminal.",
                                  feature: "exec_guard")
                        Hairline()
                        PushGuardRow(store: store)
                    }
                }
                PageSection(title: "When Bastion finds something") { AutoRespondChoice(store: store) }
                PageSection(title: "Extra checks", note: "Optional. Each one says what it sends or changes before it's on.") {
                    RowGroup {
                        OnlineCheckRow(store: store)
                        Hairline()
                        AgentsGuardRow(store: store)
                    }
                }
            }
        }
    }

    private func toggleRow(_ icon: String, _ title: String, _ detail: String, feature: String) -> some View {
        let on = store.protection[feature] as? Bool ?? false
        return ProtectionRow(icon: icon, title: title, detail: detail) {
            if store.busy.contains("feature:" + feature) { ProgressView().controlSize(.small).scaleEffect(0.7) }
            Toggle(title, isOn: Binding(get: { on }, set: { store.setFeature(feature, title: title.lowercased(), on: $0) }))
                .labelsHidden().toggleStyle(ThemeSwitch())
        }
    }
}

/// One protection: an icon, its name, one sentence, and its control on the right
struct ProtectionRow<Control: View>: View {
    let icon: String, title: String, detail: String
    @ViewBuilder var control: Control
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon).font(.system(size: 13)).foregroundStyle(DT.dim).frame(width: 18).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(uiFont(13, .medium)).foregroundStyle(DT.text)
                Text(detail).font(uiFont(12)).foregroundStyle(DT.dim).lineSpacing(1.5).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 12)
            control
        }.padding(.horizontal, 16).padding(.vertical, 12)
    }
}

// MARK: - Levels

/// "Custom" or "Off": what that means, and that a level puts it back
struct LevelNotice: View {
    let level: String
    var body: some View {
        let off = level == "off"
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: off ? "shield.slash" : "slider.horizontal.3").font(.system(size: 12, weight: .semibold))
                .foregroundStyle(off ? DT.red : DT.dim).padding(.top, 1).accessibilityHidden(true)
            Text(off ? "Protection is off. Nothing is watching this Mac. Pick a level to turn it back on."
                     : "Custom: you've changed some of the settings below, so they don't match one level. Pick a level to reset them.")
                .font(uiFont(12)).foregroundStyle(DT.text2).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .background((off ? DT.red : DT.dim).opacity(0.08), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

struct LevelCards: View {
    @ObservedObject var store: AppStore
    var body: some View {
        let levels = store.levels["levels"] as? [JSON] ?? []
        if levels.isEmpty {
            ProgressView().controlSize(.small).frame(maxWidth: .infinity, minHeight: 160)
        } else {
            Grid(horizontalSpacing: 12) {
                GridRow {
                    ForEach(levels.indices, id: \.self) { i in LevelCard(store: store, level: levels[i]).frame(maxHeight: .infinity) }
                }
            }
        }
    }
}

struct LevelCard: View {
    @ObservedObject var store: AppStore
    let level: JSON
    @State private var hover = false
    var body: some View {
        let id = level["id"] as? String ?? "", title = level["title"] as? String ?? ""
        let current = level["current"] as? Bool == true
        let includes = level["includes"] as? [String] ?? []
        Button { if !current { store.applyLevel(id) } } label: {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .center, spacing: 8) {
                    Text(title).font(uiFont(15, .semibold)).foregroundStyle(DT.text)
                    Spacer(minLength: 4)
                    if store.busy.contains("level") && !current { ProgressView().controlSize(.small).scaleEffect(0.6).frame(width: 14, height: 14) }
                    ZStack {
                        Circle().strokeBorder(current ? DT.ink : DT.border, lineWidth: 1.5).frame(width: 18, height: 18)
                        if current { Circle().fill(DT.ink).frame(width: 8, height: 8) }
                    }.accessibilityHidden(true)
                }
                Text(level["summary"] as? String ?? "").font(uiFont(12)).foregroundStyle(DT.text2).lineSpacing(1.5)
                    .fixedSize(horizontal: false, vertical: true)
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(includes.indices, id: \.self) { i in
                        HStack(alignment: .firstTextBaseline, spacing: 7) {
                            Image(systemName: i == 0 && includes[i].hasPrefix("Everything") ? "plus" : "checkmark")
                                .font(.system(size: 9, weight: .bold)).foregroundStyle(i == 0 && includes[i].hasPrefix("Everything") ? DT.dim : DT.green)
                                .frame(width: 11)
                            Text(includes[i]).font(uiFont(12)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                Spacer(minLength: 0)
            }
            .padding(16)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .background(hover && !current ? DT.surface2.opacity(0.6) : DT.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(current ? DT.ink : DT.border, lineWidth: current ? 1.5 : 1))
            .contentShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        }
        .buttonStyle(.plain).onHover { hover = $0 }
        .disabled(store.busy.contains("level"))
        .modifier(FocusRing(radius: 12))
        .accessibilityLabel("\(title) protection. \(level["summary"] as? String ?? "")")
        .accessibilityAddTraits(current ? .isSelected : [])
    }
}

// MARK: - The parts

/// On or off, and how often: every hour, every 6 hours or once a day
struct ScheduleRow: View {
    @ObservedObject var store: AppStore
    var body: some View {
        let on = store.protection["scheduled_scan"] as? Bool ?? false
        let every = store.scanEveryHours
        ProtectionRow(icon: "clock", title: "Scheduled scan",
                      detail: "Checks every repository when you log in and then \(everyWords(every)), so a new infection never waits for you.") {
            if store.busy.contains("feature:scheduled_scan") || store.busy.contains("schedule") { ProgressView().controlSize(.small).scaleEffect(0.7) }
            if on {
                Menu {
                    ForEach([1, 6, 24], id: \.self) { h in
                        Button { store.setScanEvery(h) } label: { if h == every { Label(everyTitle(h), systemImage: "checkmark") } else { Text(everyTitle(h)) } }
                    }
                } label: {
                    HStack(spacing: 5) {
                        Text(everyTitle(every)).font(uiFont(12, .medium))
                        Image(systemName: "chevron.up.chevron.down").font(.system(size: 8, weight: .bold))
                    }.foregroundStyle(DT.text2)
                }
                .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
                .accessibilityLabel("How often: \(everyTitle(every))")
            }
            Toggle("Scheduled scan", isOn: Binding(get: { on }, set: { store.setFeature("scheduled_scan", title: "scheduled scan", on: $0) }))
                .labelsHidden().toggleStyle(ThemeSwitch())
        }
    }
    private func everyTitle(_ h: Int) -> String { h == 1 ? "Every hour" : h == 24 ? "Once a day" : "Every \(h) hours" }
    private func everyWords(_ h: Int) -> String { h == 1 ? "every hour" : h == 24 ? "once a day" : "every \(h) hours" }
}

/// A git hook in each repository that refuses a push carrying malware. Bastion only adds it; removing it is yours.
struct PushGuardRow: View {
    @ObservedObject var store: AppStore
    var body: some View {
        let g = store.status["git_guard"] as? JSON ?? [:]
        let repos = g["repos"] as? Int ?? 0, guarded = g["protected"] as? Int ?? 0, open = g["unprotected"] as? Int ?? 0
        let own = (g["husky"] as? Int ?? 0) + (g["custom_hooks"] as? Int ?? 0)
        let detail = "Checks each push and refuses one that carries malware. "
            + (repos == 0 ? "No repositories found yet." : "\(guarded) of \(repos) \(repos == 1 ? "repository" : "repositories") guarded.")
            + (own > 0 ? " \(own) use their own git hooks, so Bastion leaves \(own == 1 ? "it" : "them") alone." : "")
        ProtectionRow(icon: "hand.raised", title: "Push guard", detail: detail) {
            if open > 0 {
                Button(store.busy.contains("gitguard") ? "Guarding" : "Guard \(open)") { store.run("gitguard", ["enable", "git-guard"]) }
                    .buttonStyle(SecondaryButton()).disabled(store.busy.contains("gitguard"))
            } else if repos > 0 {
                Tag(text: "On", tint: DT.green)
            }
            Button("Repositories") { Router.shared.go(.repos) }.buttonStyle(GhostButton())
        }
    }
}

/// Contain, report only, or off: what Bastion does on its own when it finds something
struct AutoRespondChoice: View {
    @ObservedObject var store: AppStore
    private let levels: [(String, String, String)] = [
        ("contain", "Contain", "Investigates and takes the steps it can prove: removes injected code when the file then matches its last clean commit byte for byte (with undo), stops loaders, quarantines leftovers and blocks attacker addresses. Commits, pushes and access changes stay with you."),
        ("observe", "Report only", "Investigates and writes incident reports, but changes nothing on its own."),
        ("off", "Off", "Doesn't respond on its own. The watcher and scans still run, and you can respond by hand."),
    ]
    var body: some View {
        RowGroup {
            ForEach(Array(levels.enumerated()), id: \.offset) { i, l in
                if i > 0 { Hairline() }
                Button { store.setAutonomy(l.0) } label: {
                    HStack(alignment: .top, spacing: 12) {
                        ZStack {
                            Circle().strokeBorder(store.autonomy == l.0 ? DT.ink : DT.border, lineWidth: 1.5).frame(width: 16, height: 16)
                            if store.autonomy == l.0 { Circle().fill(DT.ink).frame(width: 7, height: 7) }
                        }.padding(.top, 1).accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(l.1).font(uiFont(13, .semibold)).foregroundStyle(DT.text)
                            Text(l.2).font(uiFont(12)).foregroundStyle(DT.dim).lineSpacing(1.5).fixedSize(horizontal: false, vertical: true).multilineTextAlignment(.leading)
                        }
                        Spacer(minLength: 0)
                    }.padding(16).contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("\(l.1). \(l.2)").accessibilityAddTraits(store.autonomy == l.0 ? .isSelected : [])
            }
        }
    }
}

/// osv.dev's list of known-malicious package versions. Off until you say yes, because it sends package names.
struct OnlineCheckRow: View {
    @ObservedObject var store: AppStore
    var body: some View {
        let on = store.status["osv"] as? Bool ?? false
        ProtectionRow(icon: "network", title: "Online malware check",
                      detail: "Compares your exact package versions with osv.dev's list of malicious packages. Sends package names and versions, never your code.") {
            Toggle("Online malware check", isOn: Binding(get: { on }, set: { turnOn in
                if turnOn {
                    store.ask("Turn on the online malware check?", "Bastion will send package names and versions (never your code) to osv.dev.", button: "Turn on") {
                        store.run("osv", ["osv", "on", "--yes"], done: "Online malware check is on.")
                    }
                } else { store.run("osv", ["osv", "off"], done: "Online malware check is off.") }
            })).labelsHidden().toggleStyle(ThemeSwitch())
        }
    }
}

/// Your AI coding agents: connected to Bastion, and hard-guarded so they can't run npm in an unsafe project
struct AgentsGuardRow: View {
    @ObservedObject var store: AppStore
    var body: some View {
        let installed = store.agents.filter { $0["installed"] as? Bool == true }
        // "Cursor: connected, hard-guarded." One short line per agent, then what those words buy you
        let each = installed.map { a -> String in
            var parts = [a["connected"] as? Bool == true ? "connected" : "not connected"]
            if let hg = a["hard_guard"] as? Bool { parts.append(hg ? "hard-guarded" : "not hard-guarded") }
            return "\(a["name"] as? String ?? ""): \(parts.joined(separator: ", "))."
        }
        let detail = installed.isEmpty
            ? "No AI coding agent found on this Mac. When you install Claude Code, Cursor or Codex, connect it here."
            : each.joined(separator: " ") + " A connected agent checks a project with Bastion before it runs npm; a hard-guarded one can't run npm in an unsafe project."
        ProtectionRow(icon: "sparkles", title: "AI agents", detail: detail) {
            Button("Manage") { Router.shared.go(.agents) }.buttonStyle(SecondaryButton())
        }
    }
}
