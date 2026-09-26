// Guide.swift: "How it works", written like documentation. Every part of Bastion in plain words: what it does, why it
// helps you, whether it's on right now, and a button to turn it on or go there. "On this page" on the right jumps to
// each section and follows your place as you read.
import SwiftUI
import AppKit

private struct SectionTops: PreferenceKey {
    static var defaultValue: [String: CGFloat] = [:]
    static func reduce(value: inout [String: CGFloat], nextValue: () -> [String: CGFloat]) { value.merge(nextValue()) { $1 } }
}

struct GuidePage: View {
    @ObservedObject var store: AppStore
    @State private var active = "overview"
    static let toc: [(id: String, title: String)] = [
        ("overview", "Overview"), ("short", "The short version"), ("threat", "What it protects you from"),
        ("finding", "Finding malware"), ("stopping", "Stopping it before it runs"), ("responding", "When something is found"),
        ("everyday", "Everyday use"), ("lists", "Settings you control"), ("words", "What the words mean"), ("promises", "What Bastion promises"),
    ]
    var body: some View {
        VStack(spacing: 0) {
            TopBar(crumbs: ["How it works"])
            GeometryReader { geo in
                let showTOC = geo.size.width > 900
                ScrollViewReader { proxy in
                    HStack(alignment: .top, spacing: 0) {
                        ScrollView {
                            VStack(alignment: .leading, spacing: 48) {
                                overview
                                short(wide: geo.size.width > 760)
                                threat
                                finding
                                stopping
                                responding
                                everyday
                                lists
                                words(wide: geo.size.width > 900)
                                promises(wide: geo.size.width > 760)
                            }
                            .padding(.leading, 48).padding(.trailing, showTOC ? 24 : 48).padding(.top, 36).padding(.bottom, 64)
                            .frame(maxWidth: 760, alignment: .leading)
                            .frame(maxWidth: .infinity, alignment: showTOC ? .leading : .center)
                        }
                        .coordinateSpace(name: "doc")
                        .onPreferenceChange(SectionTops.self) { tops in
                            // the last section whose title has scrolled up to near the top is the one you're reading
                            let passed = Self.toc.filter { (tops[$0.id] ?? .infinity) < 120 }
                            if let id = passed.last?.id ?? Self.toc.first?.id, id != active { active = id }
                        }
                        if showTOC {
                            OnThisPage(active: active) { id in
                                active = id
                                withAnimation(.easeOut(duration: 0.25)) { proxy.scrollTo(id, anchor: .top) }
                            }
                            .frame(width: 220)
                        }
                    }
                }
            }
        }
    }

    // MARK: Sections

    private var overview: some View {
        DocSection(id: "overview") {
            VStack(alignment: .leading, spacing: 10) {
                Text("Guide").font(uiFont(12, .semibold)).foregroundStyle(DT.green)
                Text("How Bastion works").font(.system(size: 28, weight: .semibold)).tracking(-0.6).foregroundStyle(DT.text)
                Text("Bastion is a security guard for the code on your Mac. It looks for malware hidden in your JavaScript projects, stops it before it can run, and tells you in plain words what to do. This page walks through every part of it, what each one does and why it helps you.")
                    .font(uiFont(15)).foregroundStyle(DT.text2).lineSpacing(3).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func short(wide: Bool) -> some View {
        DocSection(id: "short", title: "The short version", lead: "Four things happen, mostly without you.") {
            StepStrip(wide: wide)
        }
    }

    private var threat: some View {
        DocSection(id: "threat", title: "What it protects you from") {
            VStack(alignment: .leading, spacing: 14) {
                Para("Attackers hide code in files that run by themselves: build configs like postcss.config.js, install scripts in package.json, and editor tasks.")
                Para("They often push it 2,000 spaces to the right, so the file looks normal in your editor and on GitHub. The moment you run npm install, dev, build or test, it runs. It usually goes after passwords, keys and crypto wallets.")
                HiddenLine()
                Para("Bastion reads every character, so the trick doesn't work on it.")
            }
        }
    }

    private var finding: some View {
        let p = store.protection
        let last = agoWords((store.status["last_scan"] as? JSON)?["time"])
        return DocSection(id: "finding", title: "Finding malware", lead: "How Bastion spots it, wherever it hides.") {
            DocList {
                DocFeature(icon: "magnifyingglass", title: "Scan", state: last.map { ("Last scan \($0)", nil) },
                           what: "Checks every git repository in your home folder: build configs, source files, install scripts, editor tasks, CI workflows and every branch.",
                           why: "Finds an infection before anyone runs it.",
                           action: (store.busy.contains("scan") ? "Scanning" : "Scan now", { store.scan() }))
                DocFeature(icon: "clock", title: "Scheduled scan", state: onOff(p["scheduled_scan"]),
                           what: "Runs the same scan when you log in and every 6 hours.",
                           why: "New infections don't wait for you to remember to check.",
                           action: p["scheduled_scan"] as? Bool == true ? nil : ("Turn on", { store.setFeature("scheduled_scan", title: "scheduled scan", on: true) }))
                DocFeature(icon: "bolt", title: "Real-time watcher", state: onOff(p["watcher"]),
                           what: "Runs quietly in the background. Every few seconds it looks for malware that is running, or talking to an attacker's server, and stops it.",
                           why: "If something slips through, it's stopped within seconds.",
                           action: p["watcher"] as? Bool == true ? nil : ("Turn on", { store.setFeature("watcher", title: "real-time watcher", on: true) }))
                DocFeature(icon: "arrow.triangle.branch", title: "Every branch and its history",
                           what: "Looks through every branch, including ones you haven't checked out and ones already deleted from GitHub. It can name the commit and the person that planted the code.",
                           why: "Malware on an old branch can't surprise you later.",
                           action: ("Repositories", { Router.shared.go(.repos) }))
                DocFeature(icon: "shippingbox", title: "Dependency check",
                           state: (store.status["osv"] as? Bool == true ? "Online check on" : "Online check off", store.status["osv"] as? Bool == true ? DT.green : DT.dim),
                           what: "Reads the install scripts of your packages and where your lockfile downloads them from. If you turn it on, it also compares your exact versions with osv.dev's list of malicious packages.",
                           why: "Catches a bad npm package before it runs on your Mac.",
                           action: ("Settings", { Router.shared.go(.settings) }))
            }
        }
    }

    private var stopping: some View {
        let p = store.protection
        let g = store.status["git_guard"] as? JSON ?? [:]
        let repos = g["repos"] as? Int ?? 0, guarded = g["protected"] as? Int ?? 0, open = g["unprotected"] as? Int ?? 0
        let installed = store.agents.filter { $0["installed"] as? Bool == true }.count
        let connected = store.agents.filter { $0["connected"] as? Bool == true }.count
        return DocSection(id: "stopping", title: "Stopping it before it runs", lead: "Guards that make it hard to run or spread malware, even by accident.") {
            DocList {
                DocFeature(icon: "lock.shield", title: "Execution guard", state: onOff(p["exec_guard"]),
                           what: "npm, node, pnpm, yarn and bun refuse to start inside an infected project, in any terminal.",
                           why: "You can't run malware by accident, even if you forget to check first.",
                           action: p["exec_guard"] as? Bool == true ? nil : ("Turn on", { store.setFeature("exec_guard", title: "execution guard", on: true) }))
                DocFeature(icon: "hand.raised", title: "Push guard",
                           state: repos > 0 ? ("\(guarded) of \(repos) repositories", guarded == repos ? DT.green : DT.orange) : nil,
                           what: "A small git hook checks each commit before you push it, and refuses a push that carries malware.",
                           why: "Malware never travels from your Mac to GitHub or to your team.",
                           action: open > 0 ? ("Guard all", { store.run("gitguard", ["enable", "git-guard"]) }) : nil)
                DocFeature(icon: "person.2", title: "Team PR guard",
                           what: "A GitHub Action that checks every pull request and fails the ones that add hidden code.",
                           why: "Protects teammates who don't use Bastion, before anything reaches main.",
                           action: ("Repositories", { Router.shared.go(.repos) }))
                DocFeature(icon: "sparkles", title: "AI agent guard",
                           state: installed > 0 ? ("\(connected) of \(installed) connected", connected > 0 ? DT.green : DT.dim) : nil,
                           what: "Your coding agent (Claude Code, Cursor, Codex) asks Bastion whether a repository is safe before it runs npm there. The hard-guard goes further and blocks the command.",
                           why: "An AI agent can't run malware on your behalf.",
                           action: ("AI agents", { Router.shared.go(.agents) }))
            }
        }
    }

    private var responding: some View {
        let level = store.autonomy
        let n = store.needsYouCount
        return DocSection(id: "responding", title: "When something is found", lead: "What Bastion does on its own, and what it leaves to you.") {
            DocList {
                DocFeature(icon: "wand.and.stars", title: "Auto-respond",
                           state: (level == "contain" ? "Contain" : level == "observe" ? "Report only" : "Off", level == "contain" ? DT.green : DT.dim),
                           what: "Bastion investigates by itself: which commit brought the malware in, whether it ran, and which branches carry it. In Contain mode it also removes injected code when it can prove the clean version, stops malware processes, quarantines leftovers and blocks attacker addresses.",
                           why: "The urgent part is handled while you're busy, and every change can be undone.",
                           action: ("Settings", { Router.shared.go(.settings) }))
                DocFeature(icon: "exclamationmark.shield", title: "Needs you",
                           state: (n == 0 ? "Nothing right now" : "\(n) to do", n == 0 ? DT.green : DT.orange),
                           what: "One list of everything left for you. Each item says how dangerous it is right now, shows the proof (the exact line and column) and puts the fix on a button.",
                           why: "You always know what to do next. Anything that changes GitHub or deletes a branch asks you first.",
                           action: ("Open", { Router.shared.openNeedsYou() }))
                DocFeature(icon: "doc.text", title: "Incidents",
                           what: "A short report for each attack: what happened, whether it ran on this Mac, what Bastion did, and what's left. Items tick themselves off when Bastion sees them fixed.",
                           why: "A clear record for you and your team, without digging through logs.",
                           action: ("Open", { Router.shared.go(.incidents) }))
                DocFeature(icon: "archivebox", title: "Quarantine",
                           state: store.quarantine.isEmpty ? nil : ("\(store.quarantine.count) item\(store.quarantine.count == 1 ? "" : "s")", DT.orange),
                           what: "Where known-malicious files go. Nothing is deleted.",
                           why: "If Bastion ever gets something wrong, you can put it back in one click.",
                           action: ("Open", { Router.shared.go(.quarantine) }))
                DocFeature(icon: "arrow.uturn.backward", title: "Undo",
                           what: "Every file Bastion cleans keeps a copy of the version it replaced.",
                           why: "No change is permanent unless you want it to be.")
            }
        }
    }

    private var everyday: some View {
        DocSection(id: "everyday", title: "Everyday use", lead: "Where to look, and the quickest way to do things.") {
            DocList {
                DocFeature(icon: "house", title: "Home",
                           what: "Says in one sentence how things stand, then shows what needs you, recent activity and your protection.",
                           why: "One glance tells you whether you need to do anything.",
                           action: ("Open", { Router.shared.go(.home) }))
                DocFeature(icon: "shield.lefthalf.filled", title: "Menu bar",
                           what: "The shield in your menu bar shows the same status: all clear, something to clean up, or act now. Click it for Scan now and every protection switch.",
                           why: "You see trouble without opening the app.")
                DocFeature(icon: "bell", title: "Notifications",
                           what: "A Mac notification when Bastion stops, quarantines or finds something.",
                           why: "You hear about it the moment it happens.")
                DocFeature(icon: "magnifyingglass", title: "Search or ask (⌘K)",
                           what: "Jump to any page, run any action, or type a plain question like “is my-app safe?”. Bastion answers from what it already knows. It isn't a chatbot, and nothing leaves your Mac.",
                           why: "Get anywhere in a couple of keystrokes.",
                           action: ("Try it", { withAnimation(.easeOut(duration: 0.12)) { Router.shared.palette = true } }))
                DocFeature(icon: "terminal", title: "Command line",
                           what: "Everything the app does also works in a terminal: bastion check, bastion scan, bastion todos and bastion fix.",
                           why: "Check a project before you install it, or use Bastion in your own scripts.")
            }
        }
    }

    private var lists: some View {
        DocSection(id: "lists", title: "Settings you control", lead: "Three short lists that tune what Bastion treats as safe or dangerous.") {
            DocList {
                DocFeature(icon: "checkmark.seal", title: "Allowlist", what: "Your own servers and APIs.",
                           why: "Their traffic is never mistaken for an attacker's.")
                DocFeature(icon: "nosign", title: "Blocklist", what: "Known attacker addresses. Anything that connects to them is stopped.",
                           why: "Cuts malware off from the server it reports to.")
                DocFeature(icon: "eye.slash", title: "Ignore list", what: "Docs and tests that only mention a malware signature.",
                           why: "No false alarms for files that are just talking about malware.",
                           action: ("Settings", { Router.shared.go(.settings) }))
            }
        }
    }

    private func words(wide: Bool) -> some View {
        DocSection(id: "words", title: "What the words mean", lead: "The labels you'll see across the app.") {
            Glossary(wide: wide)
        }
    }

    private func promises(wide: Bool) -> some View {
        let items: [(String, String, String)] = [
            ("desktopcomputer", "Runs on your Mac", "No account and no cloud. Your code never leaves your computer."),
            ("arrow.uturn.backward", "Never destructive", "Nothing is deleted. Every file Bastion cleans can be undone."),
            ("hand.tap", "You decide", "Pushing, deleting a branch or turning protection off always asks you first."),
            ("chevron.left.forwardslash.chevron.right", "Open source", "Every rule Bastion uses is public on GitHub."),
        ]
        let cols = Array(repeating: GridItem(.flexible(), spacing: 12, alignment: .top), count: 2)
        return DocSection(id: "promises", title: "What Bastion promises") {
            LazyVGrid(columns: cols, alignment: .leading, spacing: 12) {
                ForEach(items, id: \.1) { it in
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: it.0).font(.system(size: 12, weight: .semibold)).foregroundStyle(DT.green)
                            .frame(width: 28, height: 28).background(DT.green.opacity(0.11), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                        VStack(alignment: .leading, spacing: 3) {
                            Text(it.1).font(uiFont(13, .semibold)).foregroundStyle(DT.text)
                            Text(it.2).font(uiFont(12)).foregroundStyle(DT.dim).lineSpacing(1.5).fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(14).frame(maxWidth: .infinity, minHeight: 84, alignment: .topLeading)
                    .background(DT.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(DT.border))
                }
            }
        }
    }

    private func onOff(_ v: Any?) -> (String, Color?) { v as? Bool == true ? ("On", DT.green) : ("Off", DT.dim) }
}

// MARK: - Doc building blocks

/// A section of the guide: a title, an optional lead sentence, then the content. It reports where it is so
/// "On this page" can follow along.
struct DocSection<Content: View>: View {
    let id: String
    var title: String? = nil
    var lead: String? = nil
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let title {
                VStack(alignment: .leading, spacing: 6) {
                    Text(title).font(.system(size: 20, weight: .semibold)).tracking(-0.3).foregroundStyle(DT.text)
                    if let lead { Text(lead).font(uiFont(13)).foregroundStyle(DT.dim) }
                }
            }
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .id(id)
        .background(GeometryReader { g in Color.clear.preference(key: SectionTops.self, value: [id: g.frame(in: .named("doc")).minY]) })
    }
}

/// A paragraph at reading size
struct Para: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text).font(uiFont(13)).foregroundStyle(DT.text2).lineSpacing(3).fixedSize(horizontal: false, vertical: true)
    }
}

/// Features, one after another, with a hairline between them
struct DocList<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        _VariadicView.Tree(DocListLayout()) { content }
    }
}

private struct DocListLayout: _VariadicView_MultiViewRoot {
    func body(children: _VariadicView.Children) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(children) { child in
                if child.id != children.first?.id { Hairline() }
                child
            }
        }
        .overlay(alignment: .top) { Hairline() }
        .overlay(alignment: .bottom) { Hairline() }
    }
}

/// One feature, written like a doc entry: what it does, why it helps you, whether it's on, and one button
struct DocFeature: View {
    let icon: String
    let title: String
    var state: (String, Color?)? = nil
    let what: String
    let why: String
    var action: (String, () -> Void)? = nil
    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: icon).font(.system(size: 13, weight: .medium)).foregroundStyle(DT.text2)
                .frame(width: 30, height: 30).background(DT.surface2, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Text(title).font(uiFont(15, .semibold)).foregroundStyle(DT.text)
                    if let state {
                        if let tint = state.1 { Tag(text: state.0, tint: tint) }
                        else { Text(state.0).font(uiFont(12)).foregroundStyle(DT.dim) }
                    }
                }
                Text(what).font(uiFont(13)).foregroundStyle(DT.text2).lineSpacing(3).fixedSize(horizontal: false, vertical: true)
                (Text("Why it helps  ").font(uiFont(12, .semibold)).foregroundColor(DT.green) + Text(why).font(uiFont(12)).foregroundColor(DT.dim))
                    .lineSpacing(2).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 12)
            if let action {
                Button(action: action.1) { Text(action.0) }.buttonStyle(SecondaryButton())
            }
        }
        .padding(.vertical, 18)
    }
}

/// "On this page": the sections, with the one you're reading marked
struct OnThisPage: View {
    let active: String
    let go: (String) -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("On this page").font(uiFont(11, .medium)).foregroundStyle(DT.faint).padding(.leading, 12).padding(.bottom, 8)
            ForEach(GuidePage.toc, id: \.id) { s in
                TocItem(title: s.title, on: s.id == active) { go(s.id) }
            }
            Spacer()
        }
        .padding(.top, 44).padding(.trailing, 16)
    }
}

private struct TocItem: View {
    let title: String
    let on: Bool
    let action: () -> Void
    @State private var hover = false
    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                RoundedRectangle(cornerRadius: 1).fill(on ? DT.ink : Color.clear).frame(width: 2, height: 16)
                Text(title).font(uiFont(12, on ? .semibold : .regular)).foregroundStyle(on ? DT.text : hover ? DT.text2 : DT.dim).lineLimit(1)
                Spacer(minLength: 0)
            }
            .padding(.leading, 2).frame(height: 26).contentShape(Rectangle())
        }.buttonStyle(.plain).onHover { hover = $0 }
    }
}

/// The four steps, side by side, all the same height
struct StepStrip: View {
    let wide: Bool
    private let steps: [(String, String, String)] = [
        ("eye", "Watch", "It checks your code when you scan, every 6 hours, and all the time in the background."),
        ("hand.raised", "Stop", "If something is hidden in a project, npm won't start it and git won't push it."),
        ("wand.and.stars", "Respond", "It investigates, removes what it can prove, and keeps an undo for every change."),
        ("checklist", "Tell you", "Anything left shows up in Needs you, with the proof and a one-click fix."),
    ]
    var body: some View {
        Grid(horizontalSpacing: 12, verticalSpacing: 12) {
            if wide {
                GridRow { ForEach(0..<4, id: \.self) { cell($0) } }
            } else {
                GridRow { cell(0); cell(1) }
                GridRow { cell(2); cell(3) }
            }
        }
    }
    private func cell(_ i: Int) -> some View {
        let s = steps[i]
        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: s.0).font(.system(size: 12, weight: .semibold)).foregroundStyle(DT.text)
                    .frame(width: 26, height: 26).background(DT.surface2, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                Spacer()
                Text(String(format: "%02d", i + 1)).font(codeFont(11, .medium)).foregroundStyle(DT.faint)
            }
            Text(s.1).font(uiFont(15, .semibold)).foregroundStyle(DT.text).padding(.top, 2)
            Text(s.2).font(uiFont(12)).foregroundStyle(DT.dim).lineSpacing(1.5).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(16).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(DT.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(DT.border))
    }
}

/// "What the words mean": every label the app uses, in a sentence
struct Glossary: View {
    let wide: Bool
    private let words: [(String, String, String)] = [
        ("Act now", "red", "Malware is running, or will run as soon as npm runs in that folder. Do these first."),
        ("Dormant", "orange", "The malware is on a branch you don't have checked out. Nothing runs unless someone switches to it and runs npm."),
        ("Leftover", "dim", "An old pointer on this Mac to a branch already deleted on GitHub. Clearing it just tidies up."),
        ("To check", "blue", "A step only you can confirm, like changing a password that might have been stolen."),
        ("Contained", "blue", "Bastion stopped what it could prove. The incident shows anything left for you."),
        ("Resolved", "green", "Everything from that attack is done."),
        ("Proof", "dim", "Exactly where the hidden code is: the file, the line and the column."),
        ("Hidden code", "red", "Malware pushed far to the right of a normal-looking line, so you don't see it."),
    ]
    private func tint(_ s: String) -> Color {
        switch s { case "red": return DT.red; case "orange": return DT.orange; case "blue": return DT.accent; case "green": return DT.green; default: return DT.dim }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(words.enumerated()), id: \.offset) { i, w in
                if i > 0 { Hairline() }
                HStack(alignment: .firstTextBaseline, spacing: 16) {
                    Tag(text: w.0, tint: tint(w.1)).frame(width: 100, alignment: .leading)
                    Text(w.2).font(uiFont(13)).foregroundStyle(DT.text2).lineSpacing(2).fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                }
                .padding(.vertical, 12)
            }
        }
        .overlay(alignment: .top) { Hairline() }
        .overlay(alignment: .bottom) { Hairline() }
    }
}

/// A config file's last line, with the malware pushed off to the right
struct HiddenLine: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 12) {
                Text("7").foregroundStyle(DT.faint).frame(width: 14, alignment: .trailing)
                Text("    autoprefixer: {},").foregroundStyle(DT.text2)
                Spacer(minLength: 0)
            }
            HStack(spacing: 12) {
                Text("8").foregroundStyle(DT.red).frame(width: 14, alignment: .trailing)
                Text("};").foregroundStyle(DT.text2)
                ZStack {
                    DashedLine().stroke(DT.red.opacity(0.6), style: StrokeStyle(lineWidth: 1, dash: [4, 3])).frame(height: 1)
                    Text("2,000 spaces").font(codeFont(11, .medium)).foregroundStyle(DT.red)
                        .padding(.horizontal, 6).frame(height: 18).background(DT.sunken)
                }.frame(minWidth: 120)
                Text("global.o='1-183';var _$_d8bf=…").foregroundStyle(DT.red).lineLimit(1)
            }
        }
        .font(codeFont(12))
        .padding(14).frame(maxWidth: .infinity, alignment: .leading)
        .background(DT.sunken, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(DT.border))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Line 8 looks like a closing brace. After 2,000 spaces, hidden code starts.")
    }
}

struct DashedLine: Shape {
    func path(in r: CGRect) -> Path { var p = Path(); p.move(to: CGPoint(x: r.minX, y: r.midY)); p.addLine(to: CGPoint(x: r.maxX, y: r.midY)); return p }
}
