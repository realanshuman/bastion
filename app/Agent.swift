// Agent.swift: Home is Bastion itself. It reports how things stand in plain words, answers questions through
// `bastion ask` ("is my-app safe?", "what needs me?", "what does dormant mean?"), does what you ask, and shows its work.
import SwiftUI
import AppKit

// MARK: - Asking

extension AppStore {
    /// Sends a question to `bastion ask` and adds the answer to the thread. `quiet`: Bastion following up on its own.
    func askBastion(_ raw: String, quiet: Bool = false) {
        let q = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !q.isEmpty else { return }
        let ex = Exchange(question: quiet ? "" : q)
        withAnimation(.easeOut(duration: 0.2)) {
            chat.append(ex)
            if chat.count > 16 { chat.removeFirst(chat.count - 16) }
        }
        Task {
            let r = await Task.detached(priority: .userInitiated) { Box(json: bastion(["ask", q])) }.value.json
            setExchange(ex.id) { $0.answer = r }
            if let auto = r["auto"] as? JSON { perform(auto, from: ex.id) }
            if r["intent"] as? String == "turn_on" { refresh() }   // it just switched something on
        }
    }

    func setExchange(_ id: UUID, _ change: (inout Exchange) -> Void) {
        guard let i = chat.firstIndex(where: { $0.id == id }) else { return }
        withAnimation(.easeOut(duration: 0.2)) { change(&chat[i]) }
    }

    /// Does one of the steps an answer offers, or the one the question asked for.
    func perform(_ a: JSON, from exchange: UUID? = nil) {
        switch a["kind"] as? String ?? "" {
        case "scan":
            scan(full: a["full"] as? Bool == true) { text, tone in
                if let exchange { self.setExchange(exchange) { $0.note = text; $0.noteTone = tone } }
                if tone == "warn" { self.askBastion("what needs me", quiet: true) }
            }
        case "fix":
            if let id = a["id"] as? String, let item = todos.first(where: { $0["id"] as? String == id }) { fix(item) }
            else { flash("That one is already gone. Bastion checked again."); refresh() }
        case "steps": doRecommended()
        case "step":
            if let id = a["id"] as? String, let s = steps.first(where: { $0["id"] as? String == id }) { doStep(s) }
        case "run":
            if let args = a["args"] as? [String] { run("ask:" + args.joined(separator: " "), args) }
        case "open":
            switch a["page"] as? String ?? "" {
            case "needs": Router.shared.openNeedsYou()
            case "incident": if let id = a["id"] as? String { Router.shared.open(incident: id) }
            case "activity": Router.shared.go(.activity)
            case "quarantine": Router.shared.go(.quarantine)
            case "agents": Router.shared.go(.agents)
            case "repos": Router.shared.go(.repos)
            case "settings": Router.shared.go(.settings)
            default: break
            }
        case "ask":
            if let q = a["question"] as? String { askBastion(q) }
        case "connect":
            if let agent = a["agent"] as? String { run("connect:" + agent, ["connect", agent, "--write"]) }
        case "copy":
            if let t = a["text"] as? String {
                NSPasteboard.general.clearContents(); NSPasteboard.general.setString(t, forType: .string)
                flash("Copied. Paste it in a terminal.")
            }
        case "present":
            if let args = a["args"] as? [String] { present(a["title"] as? String ?? "Result", "present:" + args.joined(separator: " "), args) }
        case "feature_off":
            if let f = a["feature"] as? String { setFeature(f, title: a["title"] as? String ?? f, on: false) }
        case "appearance":
            if let v = a["value"] as? String { Appearance.shared.mode = v }
        default: break
        }
    }

    /// The busy key an action runs under, so its button can show that it's working
    func busyKey(_ a: JSON) -> String? {
        switch a["kind"] as? String ?? "" {
        case "scan": return "scan"
        case "fix": return (a["id"] as? String).map { "fix:" + $0 }
        case "steps": return "steps"
        case "step": return (a["id"] as? String).map { "step:" + $0 }
        case "run": return (a["args"] as? [String]).map { "ask:" + $0.joined(separator: " ") }
        case "connect": return (a["agent"] as? String).map { "connect:" + $0 }
        case "present": return (a["args"] as? [String]).map { "present:" + $0.joined(separator: " ") }
        default: return nil
        }
    }
}

// MARK: - How things stand, in Bastion's words

struct AgentBrief { let label: String; let when: String?; let headline: String; let detail: String; let tint: Color; let working: Bool }

@MainActor func agentBrief(_ store: AppStore) -> AgentBrief {
    let g = store.status["git_guard"] as? JSON ?? [:]
    let repos = g["repos"] as? Int ?? store.repos.count
    let plural = repos == 1 ? "repository" : "repositories"
    let when = agoWords((store.status["last_scan"] as? JSON)?["time"]).map { "Last check \($0)" } ?? "No scan yet"
    if !store.loaded {
        return AgentBrief(label: "Starting", when: nil, headline: "Getting ready", detail: "Reading what I know about this Mac.", tint: DT.dim, working: true)
    }
    if store.busy.contains("scan") {
        return AgentBrief(label: "Scanning", when: nil, headline: "Checking \(repos) \(plural)",
                          detail: "Build configs, source files, install hooks and every branch. This usually takes a few seconds.",
                          tint: DT.accent, working: true)
    }
    if store.status["responding"] as? Bool == true {
        return AgentBrief(label: "Responding", when: nil, headline: "Handling what I found",
                          detail: "I'm investigating and containing what I can prove. The report will be ready in a moment.",
                          tint: DT.accent, working: true)
    }
    switch store.state {
    case "act_now":
        let threats = store.status["active_threats"] as? [JSON] ?? []
        let t = max(threats.count, 1)
        let place = threats.compactMap { $0["path"] as? String }
            .compactMap { p in store.repos.first { p.hasPrefix(($0["path"] as? String ?? "\u{0}") + "/") }?["name"] as? String }.first
        return AgentBrief(label: "Act now", when: when, headline: "Malware can run on this Mac",
                          detail: "\(t == 1 ? "One active threat" : "\(t) active threats")\(place.map { " in \($0)" } ?? ""). Don't run npm there until it's fixed. The fix is one click away, below.",
                          tint: DT.red, working: false)
    case "clean_up":
        let n = store.needsYouCount
        let them = n == 1 ? "it" : "them"
        let branches = !store.todos.isEmpty && store.todos.allSatisfy { $0["type"] as? String == "branch" }
        if branches {
            return AgentBrief(label: "\(n) to clean up", when: when,
                              headline: n == 1 ? "An old branch carries hidden malware" : "\(n) old branches carry hidden malware",
                              detail: "Nothing is running. Clean \(them) up so nobody checks \(them) out and runs npm by accident.",
                              tint: DT.orange, working: false)
        }
        return AgentBrief(label: "\(n) to clean up", when: when, headline: "\(n) thing\(n == 1 ? "" : "s") need\(n == 1 ? "s" : "") you",
                          detail: "Nothing is running. Each one below comes with the proof and a one-click fix.", tint: DT.orange, working: false)
    default:
        return AgentBrief(label: "All clear", when: when, headline: "Your code is clean",
                          detail: "Watching \(repos) \(plural). Nothing needs you right now.", tint: DT.green, working: false)
    }
}

/// Questions worth one click right now
@MainActor func homeSuggestions(_ store: AppStore) -> [String] {
    var c: [String] = []
    if store.needsYouCount > 0 { c.append("What needs me?") }
    if let r = store.sampleRepo { c.append("Is \(r) safe?") }
    c.append("What happened today?")
    if !store.bulkSteps.isEmpty { c.append("Turn on protection") }
    c.append("What does dormant mean?")
    return c
}

// MARK: - Home

struct HomePage: View {
    @ObservedObject var store: AppStore
    var body: some View {
        VStack(spacing: 0) {
            TopBar(crumbs: ["Home"]) {
                HStack(spacing: 8) {
                    if !store.chat.isEmpty {
                        Button("Clear answers") { withAnimation(.easeOut(duration: 0.2)) { store.chat.removeAll() } }.buttonStyle(GhostButton())
                    }
                    Button { store.scan() } label: { Label(store.busy.contains("scan") ? "Scanning" : "Scan now", systemImage: "magnifyingglass") }
                        .buttonStyle(PrimaryButton()).disabled(store.busy.contains("scan"))
                }
            }
            GeometryReader { geo in
                ScrollViewReader { proxy in
                    ScrollView {
                        VStack(alignment: .leading, spacing: 36) {
                            StatusHeader(store: store)
                            VStack(alignment: .leading, spacing: 12) {
                                AskBox(store: store)
                                TryLine(store: store)
                                if !store.chat.isEmpty { Conversation(store: store).padding(.top, 12) }
                            }
                            HomeSections(store: store, wide: geo.size.width > 900)
                        }
                        .padding(.horizontal, 40).padding(.top, 36).padding(.bottom, 44)
                        .frame(maxWidth: 960, alignment: .leading).frame(maxWidth: .infinity)
                    }
                    .onChange(of: store.chat.map { "\($0.id)\($0.answer == nil)\($0.note ?? "")" }) {
                        withAnimation(.easeOut(duration: 0.25)) { proxy.scrollTo("thread-end", anchor: .center) }
                    }
                }
            }
        }
    }
}

struct StatusHeader: View {
    @ObservedObject var store: AppStore
    var body: some View {
        let b = agentBrief(store)
        HStack(alignment: .top, spacing: 16) {
            AgentFace(tint: b.tint, size: 44, working: b.working)
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 6) {
                    Circle().fill(b.tint).frame(width: 6, height: 6)
                    Text(b.label).font(uiFont(12, .semibold)).foregroundStyle(b.tint)
                    if let when = b.when {
                        Text("·").font(uiFont(12)).foregroundStyle(DT.faint)
                        Text(when).font(uiFont(12)).foregroundStyle(DT.dim)
                    }
                }.frame(height: 16)
                Text(b.headline).font(.system(size: 28, weight: .semibold)).tracking(-0.6).foregroundStyle(DT.text)
                    .fixedSize(horizontal: false, vertical: true)
                Text(b.detail).font(uiFont(15)).foregroundStyle(DT.dim).lineSpacing(2)
                    .fixedSize(horizontal: false, vertical: true).frame(maxWidth: 620, alignment: .leading)
            }
            Spacer(minLength: 0)
        }
    }
}

struct AskBox: View {
    @ObservedObject var store: AppStore
    @ObservedObject private var router = Router.shared
    @State private var text = ""
    @FocusState private var focused: Bool
    var body: some View {
        HStack(spacing: 12) {
            BrandMark(size: 15, tint: focused ? DT.text : DT.faint)
            TextField("Ask Bastion about a repo, a finding or what to do next", text: $text)
                .textFieldStyle(.plain).font(uiFont(15)).focused($focused).onSubmit(send)
            if empty {
                KeyCap(key: "⌘K").opacity(focused ? 0 : 1).help("Ask from anywhere with ⌘K")
            } else {
                Button(action: send) {
                    Image(systemName: "arrow.up").font(.system(size: 12, weight: .bold)).foregroundStyle(DT.onInk)
                        .frame(width: 26, height: 26).background(DT.ink, in: Circle())
                }.buttonStyle(.plain).help("Ask")
            }
        }
        .padding(.leading, 14).padding(.trailing, 10).frame(height: 46)
        .background(DT.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(focused ? DT.dim.opacity(0.55) : DT.border, lineWidth: focused ? 1.5 : 1))
        .shadow(color: DT.shadow, radius: 6, y: 2)
        .onChange(of: router.focusAsk) { focused = true }
        .onAppear { if router.focusAsk > 0 { focused = true } }
    }
    private var empty: Bool { text.trimmingCharacters(in: .whitespaces).isEmpty }
    private func send() {
        guard !empty else { return }
        let q = text; text = ""
        store.askBastion(q)
    }
}

/// "Try  What needs me? · Is workspace safe? · …": examples, one click each
struct TryLine: View {
    @ObservedObject var store: AppStore
    var body: some View {
        let all = homeSuggestions(store)
        ViewThatFits(in: .horizontal) {
            row(Array(all.prefix(4)))
            row(Array(all.prefix(3)))
            row(Array(all.prefix(2)))
        }.padding(.leading, 2)
    }
    private func row(_ items: [String]) -> some View {
        HStack(spacing: 8) {
            Text("Try").font(uiFont(12)).foregroundStyle(DT.faint)
            ForEach(Array(items.enumerated()), id: \.offset) { i, q in
                if i > 0 { Text("·").font(uiFont(12)).foregroundStyle(DT.faint) }
                TextLink(text: q) { store.askBastion(q) }
            }
        }.fixedSize()
    }
}

struct TextLink: View {
    let text: String
    let action: () -> Void
    @State private var hover = false
    var body: some View {
        Button(action: action) {
            Text(text).font(uiFont(12, .medium)).foregroundStyle(hover ? DT.text : DT.text2).underline(hover, color: DT.faint)
        }.buttonStyle(.plain).onHover { hover = $0 }
    }
}

// MARK: - Answers

struct Conversation: View {
    @ObservedObject var store: AppStore
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ForEach(store.chat) { ex in ExchangeView(store: store, ex: ex, latest: ex.id == store.chat.last?.id) }
            Color.clear.frame(height: 1).id("thread-end")
        }
    }
}

struct ExchangeView: View {
    @ObservedObject var store: AppStore
    let ex: Exchange
    let latest: Bool
    private var tint: Color {
        switch ex.answer?["tone"] as? String ?? "" {
        case "good": return DT.green
        case "warn": return DT.orange
        case "bad": return DT.red
        default: return DT.ink
        }
    }
    /// the answer started a scan that's still going
    private var scanning: Bool { (ex.answer?["auto"] as? JSON)?["kind"] as? String == "scan" && ex.note == nil && store.busy.contains("scan") }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if !ex.question.isEmpty {
                HStack(spacing: 7) {
                    Image(systemName: "arrow.turn.down.right").font(.system(size: 10, weight: .semibold)).foregroundStyle(DT.faint)
                    Text(ex.question).font(uiFont(13, .medium)).foregroundStyle(DT.dim).textSelection(.enabled)
                }
            }
            HStack(alignment: .top, spacing: 12) {
                AgentFace(tint: ex.answer == nil ? DT.dim : tint, size: 26, working: ex.answer == nil || scanning)
                VStack(alignment: .leading, spacing: 10) {
                    if let a = ex.answer { answer(a) } else { Thinking() }
                }.padding(.top, 3)
                Spacer(minLength: 0)
            }
        }
        .padding(16)
        .background(DT.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(DT.border))
    }

    @ViewBuilder private func answer(_ a: JSON) -> some View {
        Text(a["answer"] as? String ?? "").font(uiFont(15, .semibold)).foregroundStyle(DT.text)
            .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
        let points = a["points"] as? [String] ?? []
        if !points.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(points.indices, id: \.self) { i in
                    let proof = points[i].hasPrefix("Proof: ")
                    if proof {
                        Text(String(points[i].dropFirst(7))).font(codeFont(12)).foregroundStyle(DT.text2).lineLimit(4)
                            .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                            .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                            .background(DT.sunken, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    } else {
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Circle().fill(DT.faint).frame(width: 4, height: 4).offset(y: -3)
                            Text(points[i]).font(uiFont(13)).foregroundStyle(DT.text2).lineSpacing(1.5)
                                .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                        }
                    }
                }
            }
        }
        if scanning {
            HStack(spacing: 8) {
                ProgressView().controlSize(.small).scaleEffect(0.6).frame(width: 12, height: 12)
                Text("Scanning").font(uiFont(13, .medium)).foregroundStyle(DT.dim)
            }
        }
        if let note = ex.note {
            HStack(spacing: 7) {
                Image(systemName: ex.noteTone == "good" ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                    .font(.system(size: 12)).foregroundStyle(ex.noteTone == "good" ? DT.green : DT.orange)
                Text(note).font(uiFont(13, .medium)).foregroundStyle(DT.text).fixedSize(horizontal: false, vertical: true)
            }
        }
        let actions = a["actions"] as? [JSON] ?? []
        if !actions.isEmpty {
            FlowRow(spacing: 8) {
                ForEach(actions.indices, id: \.self) { i in actionButton(actions[i], first: i == 0) }
            }.padding(.top, 2)
        }
        if latest, let s = a["suggestions"] as? [String], !s.isEmpty {
            HStack(spacing: 8) {
                Text("Next").font(uiFont(12)).foregroundStyle(DT.faint)
                ForEach(Array(s.prefix(3).enumerated()), id: \.offset) { i, q in
                    if i > 0 { Text("·").font(uiFont(12)).foregroundStyle(DT.faint) }
                    TextLink(text: q) { store.askBastion(q) }
                }
            }.padding(.top, 2)
        }
    }

    private func actionButton(_ a: JSON, first: Bool) -> some View {
        let busy = store.busyKey(a).map { store.busy.contains($0) } ?? false
        let kind = a["kind"] as? String ?? ""
        let primary = first && !["open", "ask", "copy"].contains(kind)
        return Button { store.perform(a) } label: {
            HStack(spacing: 6) {
                if busy { ProgressView().controlSize(.small).scaleEffect(0.55).frame(width: 12, height: 12) }
                Text(a["label"] as? String ?? "Go")
                if kind == "open" { Image(systemName: "arrow.right").font(.system(size: 10, weight: .semibold)) }
            }
        }
        .buttonStyle(primary ? AnyButtonStyle(PrimaryButton()) : AnyButtonStyle(SecondaryButton()))
        .disabled(busy)
        .help((a["command"] as? String).map { "In a terminal: \($0)" } ?? "")
    }
}

/// Three dots while Bastion looks into it
struct Thinking: View {
    var body: some View {
        TimelineView(.periodic(from: .now, by: 0.35)) { ctx in
            let step = Int(ctx.date.timeIntervalSinceReferenceDate / 0.35) % 3
            HStack(spacing: 5) {
                ForEach(0..<3, id: \.self) { i in Circle().fill(DT.dim).frame(width: 6, height: 6).opacity(i == step ? 1 : 0.3) }
                Text("Looking into it").font(uiFont(13)).foregroundStyle(DT.dim).padding(.leading, 4)
            }.frame(height: 20)
        }
    }
}

// MARK: - Sections

struct HomeSections: View {
    @ObservedObject var store: AppStore
    let wide: Bool
    var body: some View {
        let setupOpen = store.steps.contains { $0["done"] as? Bool != true && $0["optional"] as? Bool != true }
        if wide {
            HStack(alignment: .top, spacing: 32) {
                VStack(alignment: .leading, spacing: 36) {
                    NeedsSection(store: store)
                    if setupOpen { SetupSection(store: store) }
                }.frame(maxWidth: .infinity)
                VStack(alignment: .leading, spacing: 36) {
                    ActivitySection(store: store)
                    ProtectionSection(store: store)
                }.frame(width: 300)
            }
        } else {
            VStack(alignment: .leading, spacing: 36) {
                NeedsSection(store: store)
                ActivitySection(store: store)
                if setupOpen { SetupSection(store: store) }
                ProtectionSection(store: store)
            }
        }
    }
}

struct NeedsSection: View {
    @ObservedObject var store: AppStore
    var body: some View {
        let items = store.todos
        PageSection(title: "Needs you", count: items.isEmpty ? nil : "\(items.count)") {
            if !items.isEmpty { LinkButton(title: "See all") { Router.shared.openNeedsYou() } }
        } content: {
            RowGroup {
                if items.isEmpty {
                    HStack(spacing: 12) {
                        Image(systemName: "checkmark").font(.system(size: 11, weight: .bold)).foregroundStyle(DT.green)
                            .frame(width: 28, height: 28).background(DT.green.opacity(0.11), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Nothing needs you right now").font(uiFont(13, .semibold)).foregroundStyle(DT.text)
                            Text("When something does, it shows up here and in the menu bar.").font(uiFont(12)).foregroundStyle(DT.dim)
                        }
                        Spacer(minLength: 0)
                    }.padding(16)
                } else {
                    ForEach(Array(items.prefix(4).enumerated()), id: \.offset) { i, item in
                        if i > 0 { Hairline() }
                        NeedsRow(store: store, item: item)
                    }
                    if items.count > 4 {
                        Hairline()
                        HStack { LinkButton(title: "\(items.count - 4) more") { Router.shared.openNeedsYou() }; Spacer() }.padding(.horizontal, 16).frame(height: 40)
                    }
                }
            }
        }
    }
}

struct NeedsRow: View {
    @ObservedObject var store: AppStore
    let item: JSON
    var body: some View {
        let fix = item["fix"] as? JSON ?? [:]
        let danger = item["danger"] as? String ?? ""
        let id = item["id"] as? String ?? ""
        let busy = store.busy.contains("fix:" + id)
        HStack(alignment: .top, spacing: 12) {
            DangerIcon(danger: danger, size: 28)
            VStack(alignment: .leading, spacing: 6) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(item["title"] as? String ?? "").font(uiFont(13, .semibold)).foregroundStyle(DT.text).lineLimit(2)
                    if let what = item["what"] as? String, !what.isEmpty {
                        Text(what).font(uiFont(12)).foregroundStyle(DT.dim).lineLimit(2).fixedSize(horizontal: false, vertical: true)
                    }
                }
                HStack(spacing: 6) {
                    DangerPill(danger: danger)
                    if let r = item["repo_name"] as? String { Pill(text: r, icon: "folder") }
                }
            }
            Spacer(minLength: 8)
            if fix["runnable"] as? Bool == true {
                Button { store.fix(item) } label: { Text(busy ? "Working" : fix["button"] as? String ?? "Fix it") }
                    .buttonStyle(danger == "now" ? AnyButtonStyle(PrimaryButton(tint: DT.red)) : AnyButtonStyle(SecondaryButton())).disabled(busy)
            } else {
                Button("Review") { Router.shared.openNeedsYou() }.buttonStyle(SecondaryButton())
            }
        }.padding(16)
    }
}

/// Bastion's work log: what it checked, caught, fixed and changed
struct ActivitySection: View {
    @ObservedObject var store: AppStore
    struct Entry { let text: String; let date: Date; let tint: Color; let open: (() -> Void)? }
    private var entries: [Entry] {
        var out: [Entry] = store.activity.prefix(10).compactMap { e in
            parseDate(e["time"]).map { Entry(text: said(e), date: $0, tint: eventStyle(e).tint, open: activityTarget(e, in: store.activity)) }
        }
        // clean scans aren't written to the activity log, so the last scan comes from the status
        if let last = store.status["last_scan"] as? JSON, let t = parseDate(last["time"]),
           !out.contains(where: { abs($0.date.timeIntervalSince(t)) < 90 && $0.text.hasPrefix("Scanned") }) {
            let clean = last["clean"] as? Bool == true
            out.append(Entry(text: clean ? "Scanned your repositories: all clean" : "Scanned your repositories: found things to look at",
                             date: t, tint: clean ? DT.green : DT.orange, open: { Router.shared.go(.repos) }))
        }
        return Array(out.sorted { $0.date > $1.date }.prefix(5))
    }
    var body: some View {
        let items = entries
        PageSection(title: "Recent activity") {
            LinkButton(title: "All") { Router.shared.go(.activity) }
        } content: {
            RowGroup {
                if items.isEmpty {
                    Text("Nothing yet. Everything I check, catch, fix or change shows up here.").font(uiFont(12)).foregroundStyle(DT.dim)
                        .fixedSize(horizontal: false, vertical: true).frame(maxWidth: .infinity, alignment: .leading).padding(16)
                } else {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(items.indices, id: \.self) { i in
                            let e = items[i]
                            Button { e.open?() } label: {
                                HStack(alignment: .top, spacing: 12) {
                                    VStack(spacing: 0) {
                                        Circle().fill(e.tint).frame(width: 7, height: 7).padding(.top, 5)
                                        if i < items.count - 1 { Rectangle().fill(DT.border).frame(width: 1).frame(maxHeight: .infinity).padding(.top, 4) }
                                    }.frame(width: 8)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(e.text).font(uiFont(13, .medium)).foregroundStyle(DT.text).lineLimit(2).fixedSize(horizontal: false, vertical: true)
                                        Text(agoWords(ISO8601DateFormatter().string(from: e.date)) ?? "").font(uiFont(12)).foregroundStyle(DT.dim)
                                    }.padding(.bottom, i < items.count - 1 ? 14 : 0)
                                    Spacer(minLength: 0)
                                }.fixedSize(horizontal: false, vertical: true).contentShape(Rectangle())
                            }.buttonStyle(.plain).disabled(e.open == nil)
                        }
                    }.padding(16)
                }
            }
        }
    }
}

/// What Bastion keeps an eye on, one line each. Every row leads to where it's changed.
struct ProtectionSection: View {
    @ObservedObject var store: AppStore
    var body: some View {
        let g = store.status["git_guard"] as? JSON ?? [:]
        let p = store.protection
        let connected = store.agents.filter { $0["connected"] as? Bool == true }.count
        let installed = store.agents.filter { $0["installed"] as? Bool == true }.count
        let level = store.autonomy
        PageSection(title: "Protection") {
            RowGroup {
                row("folder", "Repositories", "\(g["repos"] as? Int ?? store.repos.count) watched", sub: "\(g["protected"] as? Int ?? 0) guarded on push", on: nil) { Router.shared.go(.repos) }
                Hairline()
                row("bolt", "Real-time watcher", p["watcher"] as? Bool == true ? "On" : "Off", on: p["watcher"] as? Bool == true) { Router.shared.go(.settings) }
                Hairline()
                row("clock", "Scheduled scan", p["scheduled_scan"] as? Bool == true ? "Every 6h" : "Off", on: p["scheduled_scan"] as? Bool == true) { Router.shared.go(.settings) }
                Hairline()
                row("lock.shield", "Execution guard", p["exec_guard"] as? Bool == true ? "On" : "Off", on: p["exec_guard"] as? Bool == true) { Router.shared.go(.settings) }
                Hairline()
                row("wand.and.stars", "Auto-respond", level == "contain" ? "Contain" : level == "observe" ? "Report only" : "Off", on: level == "contain") { Router.shared.go(.settings) }
                Hairline()
                row("sparkles", "AI agents", installed == 0 ? "None found" : "\(connected) of \(installed)", on: installed == 0 ? nil : connected > 0) { Router.shared.go(.agents) }
            }
        }
    }
    private func row(_ icon: String, _ title: String, _ value: String, sub: String? = nil, on: Bool?, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: icon).font(.system(size: 12, weight: .medium)).foregroundStyle(DT.dim).frame(width: 16)
                VStack(alignment: .leading, spacing: 1) {
                    Text(title).font(uiFont(13)).foregroundStyle(DT.text)
                    if let sub { Text(sub).font(uiFont(12)).foregroundStyle(DT.dim) }
                }
                Spacer(minLength: 8)
                if let on { Tag(text: value, tint: on ? DT.green : DT.dim) } else { Text(value).font(uiFont(12, .medium)).foregroundStyle(DT.text2) }
            }.padding(.horizontal, 16).frame(height: sub == nil ? 40 : 52).contentShape(Rectangle())
        }.buttonStyle(.plain).hoverRow(radius: 0)
    }
}

/// The setup checklist: what's on, what's left, one click for the safe ones
struct SetupSection: View {
    @ObservedObject var store: AppStore
    @State private var showAll = false
    @State private var showDone = false
    var body: some View {
        let required = store.steps.filter { $0["optional"] as? Bool != true }
        let done = store.steps.filter { $0["done"] as? Bool == true }
        let open = store.steps.filter { $0["done"] as? Bool != true }
            .sorted { ($0["optional"] as? Bool == true ? 1 : 0) < ($1["optional"] as? Bool == true ? 1 : 0) }
        let shown = showAll ? open : Array(open.prefix(4))
        let bulk = store.bulkSteps
        let doneRequired = required.filter { $0["done"] as? Bool == true }.count
        PageSection(title: "Setup", count: "\(doneRequired) of \(required.count) on") {
            if !bulk.isEmpty {
                Button { store.doRecommended() } label: {
                    Text(store.busy.contains("steps") ? "Turning on" : "Turn on \(bulk.count)")
                }.buttonStyle(PrimaryButton()).disabled(store.busy.contains("steps"))
                    .help("Turns on, one after another:\n" + bulk.compactMap { $0["title"] as? String }.joined(separator: "\n"))
            }
        } content: {
            RowGroup {
                ProgressBar(value: Double(doneRequired) / Double(max(required.count, 1))).padding(16)
                ForEach(Array(shown.enumerated()), id: \.offset) { _, s in
                    Hairline()
                    row(s)
                }
                if open.count > 4 {
                    Hairline()
                    HStack {
                        Button(showAll ? "Show fewer" : "Show \(open.count - 4) more") { withAnimation(.easeOut(duration: 0.15)) { showAll.toggle() } }.buttonStyle(GhostButton())
                        Spacer()
                    }.padding(.horizontal, 8).frame(height: 40)
                }
                if !done.isEmpty {
                    Hairline()
                    Button { withAnimation(.easeOut(duration: 0.15)) { showDone.toggle() } } label: {
                        HStack(spacing: 8) {
                            Image(systemName: showDone ? "chevron.down" : "chevron.right").font(.system(size: 9, weight: .bold)).foregroundStyle(DT.faint).frame(width: 16)
                            Text("\(done.count) done").font(uiFont(12, .medium)).foregroundStyle(DT.dim)
                            Spacer()
                        }.padding(.horizontal, 16).frame(height: 40).contentShape(Rectangle())
                    }.buttonStyle(.plain)
                    if showDone {
                        ForEach(Array(done.enumerated()), id: \.offset) { _, s in
                            HStack(spacing: 12) {
                                Image(systemName: "checkmark.circle.fill").font(.system(size: 14)).foregroundStyle(DT.green).frame(width: 16)
                                Text(s["title"] as? String ?? "").font(uiFont(13)).foregroundStyle(DT.dim).strikethrough(true, color: DT.faint)
                                Spacer()
                            }.padding(.horizontal, 16).frame(height: 34)
                        }
                    }
                }
            }
        }
    }

    private func row(_ s: JSON) -> some View {
        let id = s["id"] as? String ?? ""
        let action = s["action"] as? [String] ?? []
        let label: String = {
            if action.first == "connect" { return "Connect" }
            if action.first == "hooks" { return "Add" }
            if action.contains("--husky") { return "Protect" }
            if action.first == "enable" && action.dropFirst().first == "git-guard" { return "Protect" }
            if action.isEmpty { return "Show me" }
            return "Turn on"
        }()
        return HStack(alignment: .top, spacing: 12) {
            Circle().strokeBorder(DT.border, lineWidth: 1.5).frame(width: 16, height: 16).padding(.top, 1)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(s["title"] as? String ?? "").font(uiFont(13, .medium)).foregroundStyle(DT.text)
                    if s["optional"] as? Bool == true { Tag(text: "Optional", tint: DT.dim) }
                }
                Text(s["why"] as? String ?? "").font(uiFont(12)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            if store.busy.contains("step:" + id) { ProgressView().controlSize(.small).scaleEffect(0.6).frame(width: 14, height: 14) }
            Button(label) { store.doStep(s) }.buttonStyle(SecondaryButton()).disabled(store.busy.contains("step:" + id))
        }.padding(16)
    }
}
