// Terminal.swift: "Install command-line tool". Bastion works out what a new terminal window needs (`bastion path`),
// shows the exact change, and makes it only after you press the button. Removing it takes out only what Bastion added.
import SwiftUI
import AppKit

struct CommandLineFlow {
    enum Phase { case checking, plan, working, done }
    var phase: Phase = .checking
    var plan: JSON = [:]
    var result: JSON = [:]
}

extension AppStore {
    /// installed · how (shell, link, manual or none) · where · ours (bastion command status)
    var commandLine: JSON { status["command_line"] as? JSON ?? [:] }
    /// Bastion set it up (lines or a link), so Bastion can take it out again
    var commandLineIsOurs: Bool { !(commandLine["ours"] as? [Any] ?? []).isEmpty }

    /// Opens the sheet and works out the change. Nothing changes until "Add".
    func installCommandLine() {
        withAnimation(.easeOut(duration: 0.15)) { cliFlow = CommandLineFlow() }
        Task {
            let plan = await Task.detached(priority: .userInitiated) { Box(json: bastion(["path"])) }.value.json
            guard cliFlow?.phase == .checking else { return }   // closed meanwhile
            withAnimation(.easeOut(duration: 0.15)) { cliFlow?.plan = plan; cliFlow?.phase = .plan }
        }
    }

    /// The person pressed "Add": make exactly the change the sheet showed
    func confirmCommandLine() {
        guard cliFlow?.phase == .plan else { return }
        withAnimation(.easeOut(duration: 0.15)) { cliFlow?.phase = .working }
        Task {
            let r = await Task.detached(priority: .userInitiated) { Box(json: bastion(["path", "install", "--yes"])) }.value.json
            withAnimation(.easeOut(duration: 0.15)) { cliFlow?.result = r; cliFlow?.phase = .done }
            refresh()
        }
    }

    func removeCommandLine() {
        let ours = commandLine["ours"] as? [JSON] ?? []
        guard !ours.isEmpty else { return }
        let places = ours.map { tildePath($0["where"] as? String ?? "") }.joined(separator: " and ")
        let what = ours.allSatisfy({ $0["how"] as? String == "link" })
            ? "Bastion will delete its link at \(places)."
            : "Bastion will take its lines out of \(places). Nothing else changes."
        ask("Remove the bastion command?", what + " New terminal windows won't find bastion.", button: "Remove") {
            self.run("cli", ["path", "remove", "--yes"])
        }
    }
}

// MARK: - The sheet

struct CommandLineSheet: View {
    @ObservedObject var store: AppStore
    private var flow: CommandLineFlow { store.cliFlow ?? CommandLineFlow() }
    private var plan: JSON { flow.plan }
    private var action: String { plan["error"] != nil ? "error" : plan["action"] as? String ?? "" }
    private var isLink: Bool { action == "link" }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            header
            content
            HStack(spacing: 8) {
                Spacer()
                buttons
            }
        }
        .padding(24)
        .frame(width: 540, alignment: .leading)
        .background(DT.panel)
    }

    // icon, tint, title and the line under it, for where the flow is
    private var look: (icon: String, tint: Color, title: String, sub: String) {
        let intro = "Everything in this window also works in a terminal: bastion check, bastion scan, bastion fix and more."
        switch flow.phase {
        case .checking, .working:
            return ("terminal", DT.ink, "Use bastion in your terminal", intro)
        case .plan:
            switch action {
            case "none": return ("checkmark", DT.green, "bastion already works", "New terminal windows find it. Nothing needs to change.")
            case "conflict": return ("exclamationmark.triangle", DT.orange, "Another bastion comes first", "Something else with the same name is already on your PATH.")
            case "unsupported": return ("terminal", DT.ink, "Add it yourself", "Bastion doesn't know how \(plan["shell"] as? String ?? "your shell") starts, so it won't guess.")
            case "error": return ("exclamationmark.triangle", DT.red, "Couldn't check your terminal", "Nothing changed.")
            default: return ("terminal", DT.ink, "Use bastion in your terminal", intro)
            }
        case .done:
            let r = flow.result
            guard r["ok"] as? Bool == true else { return ("xmark", DT.red, "Nothing changed", "") }
            switch r["verified"] as? Bool {
            case true?: return ("checkmark", DT.green, "bastion is ready",
                                r["how"] as? String == "link" ? "It works now, in any terminal window." : "It works in every terminal window you open from now on.")
            case false?: return ("exclamationmark.triangle", DT.orange, "Added, but not found yet", "")
            case nil: return ("checkmark", DT.green, "Added", "Open a new terminal window to use it.")
            }
        }
    }

    private var header: some View {
        let l = look
        return HStack(alignment: .top, spacing: 14) {
            Image(systemName: l.icon).font(.system(size: 15, weight: .semibold)).foregroundStyle(l.tint)
                .frame(width: 38, height: 38).background(l.tint.opacity(0.1), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(l.title).font(uiFont(20, .semibold)).foregroundStyle(DT.text)
                if !l.sub.isEmpty {
                    Text(l.sub).font(uiFont(13)).foregroundStyle(DT.dim).lineSpacing(2).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    @ViewBuilder private var content: some View {
        switch flow.phase {
        case .checking:
            HStack(spacing: 10) {
                ProgressView().controlSize(.small)
                Text("Checking how your terminal starts…").font(uiFont(13)).foregroundStyle(DT.dim)
            }.frame(maxWidth: .infinity, minHeight: 90, alignment: .leading)
        case .plan, .working:
            planContent
        case .done:
            doneContent
        }
    }

    @ViewBuilder private var planContent: some View {
        switch action {
        case "shell", "link":
            VStack(alignment: .leading, spacing: 10) {
                Text("What changes").font(uiFont(12, .semibold)).foregroundStyle(DT.dim)
                Text(plan["summary"] as? String ?? "").font(uiFont(13)).foregroundStyle(DT.text2).lineSpacing(2).fixedSize(horizontal: false, vertical: true)
                CommandBlock(text: isLink
                             ? "\(tildePath(plan["link"] as? String ?? "")) → \(tildePath(plan["command"] as? String ?? ""))"
                             : (plan["lines"] as? [String] ?? []).joined(separator: "\n"))
                Text(isLink ? "You can remove the link in Settings at any time."
                            : "Terminal windows that are already open won't see it. You can remove it in Settings at any time.")
                    .font(uiFont(12)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true)
                if let note = plan["note"] as? String {
                    Text(note).font(uiFont(12)).foregroundStyle(DT.orange).fixedSize(horizontal: false, vertical: true)
                }
            }
        case "none":
            tryIt("Try it in a new terminal window:")
        case "conflict":
            VStack(alignment: .leading, spacing: 10) {
                Text(plan["summary"] as? String ?? "").font(uiFont(13)).foregroundStyle(DT.text2).fixedSize(horizontal: false, vertical: true)
                CommandBlock(text: tildePath(plan["found"] as? String ?? ""))
                Text("Bastion's own command is at \(tildePath(plan["command"] as? String ?? "")). You can run it by that path.")
                    .font(uiFont(12)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true)
            }
        case "unsupported":
            VStack(alignment: .leading, spacing: 10) {
                Text("Add this folder to the end of your PATH in your shell's setup:").font(uiFont(13)).foregroundStyle(DT.text2)
                CommandBlock(text: tildePath(plan["folder"] as? String ?? ""))
            }
        default:
            Text(plan["error"] as? String ?? "Bastion couldn't work out what your terminal needs.")
                .font(uiFont(13)).foregroundStyle(DT.text2).fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder private var doneContent: some View {
        let r = flow.result
        if r["ok"] as? Bool == true && r["verified"] as? Bool != false {
            tryIt(r["how"] as? String == "link" ? "Try it in any terminal window:" : "Open a new terminal window and try:")
        } else {
            Text((r["message"] as? String) ?? (r["error"] as? String) ?? "Something went wrong. Nothing changed.")
                .font(uiFont(13)).foregroundStyle(DT.text2).lineSpacing(2).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func tryIt(_ lead: String) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(lead).font(uiFont(13)).foregroundStyle(DT.text2)
            CommandBlock(text: "bastion status")
        }
    }

    @ViewBuilder private var buttons: some View {
        let close = { withAnimation(.easeOut(duration: 0.15)) { store.cliFlow = nil } }
        switch flow.phase {
        case .checking:
            Button("Cancel", action: close).buttonStyle(SecondaryButton()).keyboardShortcut(.cancelAction)
        case .plan where action == "shell" || action == "link", .working:
            Button("Cancel", action: close).buttonStyle(SecondaryButton()).keyboardShortcut(.cancelAction).disabled(flow.phase == .working)
            Button { store.confirmCommandLine() } label: {
                HStack(spacing: 6) {
                    if flow.phase == .working { ProgressView().controlSize(.small).scaleEffect(0.6).frame(width: 12, height: 12) }
                    Text(flow.phase == .working ? "Adding…" : addLabel)
                }
            }
            .buttonStyle(PrimaryButton()).keyboardShortcut(.defaultAction).disabled(flow.phase == .working)
        default:
            Button("Done", action: close).buttonStyle(PrimaryButton()).keyboardShortcut(.defaultAction)
        }
    }

    private var addLabel: String {
        if isLink { return "Add link" }
        let file = tildePath(plan["file"] as? String ?? "")
        return plan["creates_file"] as? Bool == true ? "Create \(file)" : "Add to \(file)"
    }
}

// MARK: - Settings row

struct CommandLineRow: View {
    @ObservedObject var store: AppStore
    var body: some View {
        let c = store.commandLine
        let installed = c["installed"] as? Bool == true
        let how = c["how"] as? String ?? "none"
        let place = tildePath(c["where"] as? String ?? "")
        HStack(spacing: 12) {
            Image(systemName: "terminal").font(.system(size: 13)).foregroundStyle(DT.dim).frame(width: 18).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 8) {
                    Text("The bastion command").font(uiFont(13, .medium)).foregroundStyle(DT.text)
                    if installed { Tag(text: "Set up", tint: DT.green) }
                }
                Text(detail(how, place)).font(uiFont(12)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 12)
            if !installed {
                Button("Install command-line tool") { store.installCommandLine() }.buttonStyle(SecondaryButton())
            } else if store.commandLineIsOurs {
                Button(store.busy.contains("cli") ? "Removing" : "Remove") { store.removeCommandLine() }
                    .buttonStyle(GhostButton()).disabled(store.busy.contains("cli"))
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
    }

    private func detail(_ how: String, _ place: String) -> String {
        switch how {
        case "shell": return "Works in new terminal windows. Bastion added it to \(place)."
        case "link": return "Works in any terminal window, through a link at \(place)."
        case "manual": return "Works in new terminal windows. You set this up yourself, in \(place)."
        default: return "Not set up yet. Bastion shows you the exact change first, and asks."
        }
    }
}
