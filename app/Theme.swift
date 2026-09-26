// Theme.swift: Bastion's look. Ink on white (or white on ink), green for "protected", amber for "clean up", red for
// "act now". Every colour has a light and a dark value, so the app follows the Mac or the choice in Settings.
// Six type sizes (28, 20, 15, 13, 12, 11) and a 4-point spacing grid; nothing in between.
import SwiftUI
import AppKit

extension Color {
    init(hex: UInt32, alpha: Double = 1) {
        self.init(.sRGB, red: Double((hex >> 16) & 0xFF) / 255, green: Double((hex >> 8) & 0xFF) / 255,
                  blue: Double(hex & 0xFF) / 255, opacity: alpha)
    }
}

/// A colour with a light and a dark value, picked each time it's drawn.
func dyn(_ light: UInt32, _ dark: UInt32, _ lightAlpha: CGFloat = 1, _ darkAlpha: CGFloat = 1) -> Color {
    Color(nsColor: NSColor(name: nil) { appearance in
        let isDark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
        let hex = isDark ? dark : light
        return NSColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
                       blue: CGFloat(hex & 0xFF) / 255, alpha: isDark ? darkAlpha : lightAlpha)
    })
}

enum DT {
    static let chrome    = dyn(0xF3F4F3, 0x0A0A0B)   // window and sidebar, like a browser's frame
    static let panel     = dyn(0xFFFFFF, 0x111213)   // the page, floating on the frame
    static let surface   = dyn(0xFFFFFF, 0x161719)   // lists and boxes on the page
    static let surface2  = dyn(0xF3F4F3, 0x1F2023)   // hover, selection, controls
    static let sunken    = dyn(0xF7F8F7, 0x0C0D0E)   // code and proof
    static let sideHover = dyn(0xE7E8E7, 0x18191B)
    static let border    = dyn(0xE3E4E6, 0x2A2B2E)
    static let hairline  = dyn(0xEDEEEF, 0x1F2023)
    static let text      = dyn(0x0D0E10, 0xEDEEF0)
    static let text2     = dyn(0x3A3D42, 0xC2C5CA)
    static let dim       = dyn(0x6B6F76, 0x8D9198)
    static let faint     = dyn(0x9EA2A9, 0x5E6269)
    static let ink       = dyn(0x0D0E10, 0xEDEEF0)   // primary buttons: black on light, white on dark
    static let onInk     = dyn(0xFFFFFF, 0x0D0E10)
    static let accent    = dyn(0x1F6FEB, 0x4EA2FF)   // links, focus, "contained"
    static let green     = dyn(0x1A8F55, 0x3DBE7C)
    static let red       = dyn(0xDC3F44, 0xF2555A)
    static let orange    = dyn(0xB95A08, 0xF0A04B)
    static let blue      = dyn(0x1F6FEB, 0x4EA2FF)
    static let purple    = dyn(0x7C5CE0, 0xA38BFA)
    static let yellow    = dyn(0xB7950B, 0xF2C94C)
    static let shadow    = dyn(0x000000, 0x000000, 0.06, 0.5)
    static let scrim     = dyn(0x000000, 0x000000, 0.14, 0.55)
}

/// System, light or dark. Kept in the app's defaults and applied to every window, the menu-bar panel included.
@MainActor
final class Appearance: ObservableObject {
    static let shared = Appearance()
    @Published var mode: String {
        didSet { UserDefaults.standard.set(mode, forKey: "appearance"); apply() }
    }
    private init() { mode = UserDefaults.standard.string(forKey: "appearance") ?? "system" }
    func apply() {
        NSApp?.appearance = mode == "light" ? NSAppearance(named: .aqua) : mode == "dark" ? NSAppearance(named: .darkAqua) : nil
    }
}

/// Interface text: SF Pro
func uiFont(_ size: CGFloat, _ w: Font.Weight = .regular) -> Font { .system(size: size, weight: w) }
/// IDs, paths and commands
func codeFont(_ size: CGFloat, _ w: Font.Weight = .regular) -> Font { .system(size: size, weight: w, design: .monospaced) }

// MARK: - The mark: a shield of four bands (the same drawing as the website's logo)

struct MarkShape: Shape {
    func path(in r: CGRect) -> Path {
        let s = min(r.width, r.height) / 24, ox = r.midX - 12 * s, oy = r.midY - 12 * s
        func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: ox + x * s, y: oy + y * s) }
        var shield = Path()
        shield.move(to: p(12, 1.6)); shield.addLine(to: p(20.6, 4.6)); shield.addLine(to: p(20.6, 11.2))
        shield.addCurve(to: p(12, 22.6), control1: p(20.6, 16.6), control2: p(17.1, 20.6))
        shield.addCurve(to: p(3.4, 11.2), control1: p(6.9, 20.6), control2: p(3.4, 16.6))
        shield.addLine(to: p(3.4, 4.6)); shield.closeSubpath()
        var bands = Path()
        for (y, h) in [(0.0, 7.0), (8.35, 3.05), (12.75, 3.05), (17.15, 7.0)] {
            bands.addRect(CGRect(x: ox, y: oy + y * s, width: 24 * s, height: h * s))
        }
        return shield.intersection(bands)
    }
}

/// Bastion's mark in one colour
struct BrandMark: View {
    var size: CGFloat = 20
    var tint: Color = DT.ink
    var body: some View { MarkShape().fill(tint).frame(width: size, height: size) }
}

/// The agent's face: the mark on a soft tile in the colour of how things stand. It pulses while Bastion is working.
struct AgentFace: View {
    let tint: Color
    var size: CGFloat = 40
    var working = false
    @State private var pulse = false
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.28, style: .continuous).fill(tint.opacity(0.1))
            RoundedRectangle(cornerRadius: size * 0.28, style: .continuous).strokeBorder(tint.opacity(0.22))
            MarkShape().fill(tint).frame(width: size * 0.56, height: size * 0.56)
        }
        .frame(width: size, height: size)
        .overlay {
            if working {
                RoundedRectangle(cornerRadius: size * 0.28, style: .continuous).stroke(tint.opacity(pulse ? 0 : 0.55), lineWidth: 2)
                    .scaleEffect(pulse ? 1.35 : 1)
                    .onAppear { withAnimation(.easeOut(duration: 1.25).repeatForever(autoreverses: false)) { pulse = true } }
                    .onDisappear { pulse = false }
            }
        }
        .accessibilityHidden(true)
    }
}

// MARK: - Controls

/// A switch in Bastion's green. NSSwitch ignores .tint and turns grey when its window isn't key.
struct ThemeSwitch: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        Button { configuration.isOn.toggle() } label: {
            ZStack(alignment: configuration.isOn ? .trailing : .leading) {
                Capsule().fill(configuration.isOn ? DT.green : DT.surface2)
                    .overlay(Capsule().strokeBorder(configuration.isOn ? Color.clear : DT.border))
                Circle().fill(Color.white).frame(width: 14, height: 14).padding(2)
                    .shadow(color: .black.opacity(0.22), radius: 1, y: 0.5)
            }
            .frame(width: 30, height: 18)
            .animation(.spring(response: 0.22, dampingFraction: 0.85), value: configuration.isOn)
        }
        .buttonStyle(.plain)
        .accessibilityValue(configuration.isOn ? "on" : "off")
        .accessibilityAddTraits(.isToggle)
    }
}

/// A ring in the accent colour when a control has keyboard focus (Full Keyboard Access, Tab)
struct FocusRing: ViewModifier {
    var radius: CGFloat = 8
    @Environment(\.isFocused) private var focused
    func body(content: Content) -> some View {
        content.overlay(RoundedRectangle(cornerRadius: radius + 3, style: .continuous).strokeBorder(DT.accent, lineWidth: 2).padding(-3).opacity(focused ? 1 : 0))
    }
}

/// Ink by default (black on light, white on dark); a colour for danger. 28 tall, or 32 when large.
struct PrimaryButton: ButtonStyle {
    var tint: Color? = nil
    var large = false
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(uiFont(13, .medium)).foregroundStyle(tint == nil ? DT.onInk : Color.white)
            .padding(.horizontal, large ? 16 : 12).frame(height: large ? 32 : 28)
            .background((tint ?? DT.ink).opacity(enabled ? (configuration.isPressed ? 0.78 : 1) : 0.35),
                        in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .contentShape(Rectangle())
            .modifier(FocusRing())
    }
}

struct SecondaryButton: ButtonStyle {
    var large = false
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(uiFont(13, .medium)).foregroundStyle(enabled ? DT.text : DT.faint)
            .padding(.horizontal, large ? 14 : 10).frame(height: large ? 32 : 28)
            .background(configuration.isPressed ? DT.surface2 : DT.surface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(DT.border))
            .contentShape(Rectangle())
            .modifier(FocusRing())
    }
}

/// Text only, with a soft background on hover
struct GhostButton: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View { GhostBody(configuration: configuration) }
    private struct GhostBody: View {
        let configuration: ButtonStyleConfiguration
        @State private var hover = false
        var body: some View {
            configuration.label.font(uiFont(12, .medium)).foregroundStyle(hover ? DT.text : DT.dim)
                .padding(.horizontal, 8).frame(height: 24)
                .background(hover || configuration.isPressed ? DT.surface2 : .clear, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                .contentShape(Rectangle()).onHover { hover = $0 }
                .modifier(FocusRing(radius: 6))
        }
    }
}

/// "See all ›": a quiet link at the end of a section header
struct LinkButton: View {
    let title: String
    let action: () -> Void
    @State private var hover = false
    var body: some View {
        Button(action: action) {
            HStack(spacing: 3) {
                Text(title).font(uiFont(12, .medium))
                Image(systemName: "chevron.right").font(.system(size: 8, weight: .bold))
            }.foregroundStyle(hover ? DT.text : DT.dim).contentShape(Rectangle())
        }.buttonStyle(.plain).onHover { hover = $0 }
    }
}

struct IconButton: View {
    let icon: String, help: String
    var enabled = true
    let action: () -> Void
    @State private var hover = false
    var body: some View {
        Button(action: action) {
            Image(systemName: icon).font(.system(size: 12, weight: .medium)).foregroundStyle(!enabled ? DT.faint.opacity(0.6) : hover ? DT.text : DT.dim)
                .frame(width: 26, height: 26)
                .background(hover && enabled ? DT.surface2 : .clear, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
        }.buttonStyle(.plain).help(help).onHover { hover = $0 }.disabled(!enabled)
        .accessibilityLabel(help.components(separatedBy: "  ").first ?? help)
    }
}

/// A neutral label: a branch, a repo, a setting
struct Pill: View {
    let text: String
    var dot: Color? = nil
    var icon: String? = nil
    var mono = false
    var body: some View {
        HStack(spacing: 5) {
            if let dot { Circle().fill(dot).frame(width: 6, height: 6) }
            if let icon { Image(systemName: icon).font(.system(size: 9, weight: .semibold)).foregroundStyle(DT.dim) }
            Text(text).font(mono ? codeFont(11) : uiFont(11, .medium)).foregroundStyle(DT.text2).lineLimit(1)
        }
        .padding(.horizontal, 7).frame(height: 20)
        .background(DT.surface2, in: RoundedRectangle(cornerRadius: 5, style: .continuous))
    }
}

/// A coloured state label: "Act now", "Contained", "On"
struct Tag: View {
    let text: String
    let tint: Color
    var body: some View {
        Text(text).font(uiFont(11, .semibold)).foregroundStyle(tint).lineLimit(1)
            .padding(.horizontal, 7).frame(height: 20)
            .background(tint.opacity(0.11), in: RoundedRectangle(cornerRadius: 5, style: .continuous))
    }
}

struct KeyCap: View {
    let key: String
    var body: some View {
        Text(key).font(uiFont(11, .medium)).foregroundStyle(DT.dim)
            .frame(minWidth: 18, minHeight: 18).padding(.horizontal, 4)
            .background(DT.surface2, in: RoundedRectangle(cornerRadius: 4, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 4, style: .continuous).strokeBorder(DT.border))
    }
}

struct Avatar: View {
    let name: String
    var color: Color = DT.orange
    var size: CGFloat = 20
    var body: some View {
        Text(initials(name)).font(uiFont(size * 0.42, .bold)).foregroundStyle(.white)
            .frame(width: size, height: size).background(color.opacity(0.9), in: Circle())
    }
}

func initials(_ name: String) -> String {
    let parts = name.split(whereSeparator: { $0 == " " || $0 == "-" || $0 == "_" || $0 == "." })
    return String(parts.prefix(2).compactMap(\.first)).uppercased()
}

struct HoverRow: ViewModifier {
    var selected = false
    var radius: CGFloat = 6
    @State private var hover = false
    func body(content: Content) -> some View {
        content
            .background(RoundedRectangle(cornerRadius: radius, style: .continuous).fill(selected ? DT.surface2 : hover ? DT.surface2.opacity(0.55) : .clear))
            .onHover { hover = $0 }
    }
}
extension View { func hoverRow(selected: Bool = false, radius: CGFloat = 6) -> some View { modifier(HoverRow(selected: selected, radius: radius)) } }

struct Hairline: View { var body: some View { Rectangle().fill(DT.hairline).frame(height: 1) } }

/// A section's title above its content: "Needs you  2 ........ See all ›"
struct SectionHeader<Trailing: View>: View {
    let title: String
    var count: String? = nil
    @ViewBuilder var trailing: Trailing
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(title).font(uiFont(15, .semibold)).foregroundStyle(DT.text)
            if let count { Text(count).font(uiFont(13)).foregroundStyle(DT.dim).monospacedDigit() }
            Spacer(minLength: 8)
            trailing
        }.frame(minHeight: 24)
    }
}
extension SectionHeader where Trailing == EmptyView {
    init(title: String, count: String? = nil) { self.init(title: title, count: count) { EmptyView() } }
}

/// A section: header, then content
struct PageSection<Content: View, Trailing: View>: View {
    let title: String
    var count: String? = nil
    var note: String? = nil
    @ViewBuilder var trailing: Trailing
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                SectionHeader(title: title, count: count) { trailing }
                if let note { Text(note).font(uiFont(12)).foregroundStyle(DT.dim).fixedSize(horizontal: false, vertical: true) }
            }
            content
        }
    }
}
extension PageSection where Trailing == EmptyView {
    init(title: String, count: String? = nil, note: String? = nil, @ViewBuilder content: () -> Content) {
        self.init(title: title, count: count, note: note, trailing: { EmptyView() }, content: content)
    }
}

/// A bordered list of rows
struct RowGroup<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(spacing: 0) { content }
            .background(DT.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(DT.border))
    }
}

struct CommandBlock: View {
    let text: String
    @State private var copied = false
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Text(text).font(codeFont(12)).foregroundStyle(DT.text2)
                .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).fixedSize(horizontal: false, vertical: true)
            Button { copy() } label: {
                Image(systemName: copied ? "checkmark" : "doc.on.doc").font(.system(size: 11, weight: .medium))
                    .foregroundStyle(copied ? DT.green : DT.dim).frame(width: 22, height: 22)
            }.buttonStyle(.plain).help("Copy").accessibilityLabel("Copy")
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .background(DT.sunken, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(DT.border))
    }
    private func copy() {
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(text, forType: .string)
        withAnimation { copied = true }
        Task { try? await Task.sleep(nanoseconds: 1_500_000_000); withAnimation { copied = false } }
    }
}

struct EmptyState: View {
    let icon: String, title: String, text: String
    var tint: Color = DT.dim
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: icon).font(.system(size: 18, weight: .medium)).foregroundStyle(tint)
                .frame(width: 44, height: 44).background(tint.opacity(0.1), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            VStack(spacing: 4) {
                Text(title).font(uiFont(15, .semibold)).foregroundStyle(DT.text)
                Text(text).font(uiFont(13)).foregroundStyle(DT.dim).multilineTextAlignment(.center).frame(maxWidth: 380)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity).padding(40)
    }
}

/// open = half-filled amber ring · contained = blue check · resolved = green check
struct StatusIcon: View {
    let status: String
    var size: CGFloat = 14
    var body: some View {
        ZStack {
            switch status {
            case "open", "at_risk":
                Circle().strokeBorder(DT.orange, lineWidth: 1.5)
                Pie(fraction: 0.5).fill(DT.orange).padding(size * 0.24)
            case "contained", "resolved":
                Circle().fill(status == "contained" ? DT.accent : DT.green)
                Image(systemName: "checkmark").font(.system(size: size * 0.5, weight: .heavy)).foregroundStyle(DT.panel)
            default:
                Circle().strokeBorder(DT.dim, lineWidth: 1.5)
            }
        }.frame(width: size, height: size)
    }
}

struct Pie: Shape {
    var fraction: Double
    func path(in r: CGRect) -> Path {
        var p = Path(); let c = CGPoint(x: r.midX, y: r.midY)
        p.move(to: c)
        p.addArc(center: c, radius: min(r.width, r.height) / 2, startAngle: .degrees(-90), endAngle: .degrees(-90 + 360 * fraction), clockwise: false)
        p.closeSubpath()
        return p
    }
}

struct ProgressBar: View {
    let value: Double          // 0…1
    var tint: Color = DT.green
    var body: some View {
        GeometryReader { g in
            ZStack(alignment: .leading) {
                Capsule().fill(DT.surface2)
                Capsule().fill(tint).frame(width: max(6, g.size.width * min(max(value, 0), 1)))
            }
        }.frame(height: 6)
    }
}

/// Wrapping row of pills and buttons
struct FlowRow: Layout {
    var spacing: CGFloat = 6
    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? 260
        var x: CGFloat = 0, y: CGFloat = 0, line: CGFloat = 0
        for s in subviews {
            let d = s.sizeThatFits(.unspecified)
            if x + d.width > width, x > 0 { x = 0; y += line + spacing; line = 0 }
            x += d.width + spacing; line = max(line, d.height)
        }
        return CGSize(width: width, height: y + line)
    }
    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, line: CGFloat = 0
        for s in subviews {
            let d = s.sizeThatFits(.unspecified)
            if x + d.width > bounds.maxX, x > bounds.minX { x = bounds.minX; y += line + spacing; line = 0 }
            s.place(at: CGPoint(x: x, y: y), proposal: .unspecified)
            x += d.width + spacing; line = max(line, d.height)
        }
    }
}

// MARK: - Appearance controls

/// The small System / Light / Dark switch at the foot of the sidebar
struct AppearanceSwitch: View {
    @ObservedObject private var look = Appearance.shared
    var body: some View {
        HStack(spacing: 2) {
            ForEach([("system", "circle.lefthalf.filled", "Match the Mac"), ("light", "sun.max", "Light"), ("dark", "moon", "Dark")], id: \.0) { m in
                Button { look.mode = m.0 } label: {
                    Image(systemName: m.1).font(.system(size: 11, weight: .medium))
                        .foregroundStyle(look.mode == m.0 ? DT.text : DT.dim)
                        .frame(width: 26, height: 22)
                        .background(look.mode == m.0 ? DT.panel : .clear, in: RoundedRectangle(cornerRadius: 5, style: .continuous))
                        .shadow(color: look.mode == m.0 ? DT.shadow : .clear, radius: 1, y: 0.5)
                        .contentShape(Rectangle())
                }.buttonStyle(.plain).help(m.2).accessibilityLabel(m.2)
            }
        }
        .padding(2)
        .background(DT.sideHover, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
    }
}

/// Settings › Appearance: three little windows to pick from
struct AppearanceCards: View {
    @ObservedObject private var look = Appearance.shared
    var body: some View {
        HStack(spacing: 12) {
            card("system", "Match the Mac")
            card("light", "Light")
            card("dark", "Dark")
        }
    }
    private func card(_ mode: String, _ title: String) -> some View {
        let on = look.mode == mode
        return Button { look.mode = mode } label: {
            VStack(alignment: .leading, spacing: 10) {
                Group {
                    if mode == "system" {
                        HStack(spacing: 0) { MiniWindow(dark: false).clipped(); MiniWindow(dark: true).clipped() }
                    } else { MiniWindow(dark: mode == "dark") }
                }
                .frame(height: 76).clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(DT.border))
                HStack(spacing: 8) {
                    ZStack {
                        Circle().strokeBorder(on ? DT.ink : DT.border, lineWidth: 1.5).frame(width: 14, height: 14)
                        if on { Circle().fill(DT.ink).frame(width: 6, height: 6) }
                    }
                    Text(title).font(uiFont(13, .medium)).foregroundStyle(DT.text)
                }
            }
            .padding(10).frame(maxWidth: .infinity, alignment: .leading)
            .background(DT.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(on ? DT.ink.opacity(0.75) : DT.border, lineWidth: on ? 1.5 : 1))
            .contentShape(Rectangle())
        }.buttonStyle(.plain)
    }
}

/// A tiny Bastion window in fixed colours, for the appearance picker
private struct MiniWindow: View {
    let dark: Bool
    var body: some View {
        let frame = Color(hex: dark ? 0x0A0A0B : 0xF3F4F3), page = Color(hex: dark ? 0x161719 : 0xFFFFFF)
        let line = Color(hex: dark ? 0x2A2B2E : 0xE3E4E6), ink = Color(hex: dark ? 0xEDEEF0 : 0x0D0E10)
        HStack(spacing: 5) {
            VStack(alignment: .leading, spacing: 5) {
                MarkShape().fill(ink).frame(width: 10, height: 10)
                ForEach(0..<4, id: \.self) { i in Capsule().fill(ink.opacity(i == 0 ? 0.55 : 0.18)).frame(width: 22, height: 3) }
            }.frame(width: 28, alignment: .leading)
            VStack(alignment: .leading, spacing: 6) {
                Capsule().fill(ink.opacity(0.75)).frame(width: 46, height: 5)
                Capsule().fill(ink.opacity(0.2)).frame(width: 62, height: 3)
                RoundedRectangle(cornerRadius: 3).fill(Color(hex: 0x1A8F55).opacity(0.85)).frame(width: 24, height: 8)
            }
            .padding(8).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .background(page, in: RoundedRectangle(cornerRadius: 5))
            .overlay(RoundedRectangle(cornerRadius: 5).strokeBorder(line))
        }
        .padding(6).frame(maxWidth: .infinity, maxHeight: .infinity).background(frame)
    }
}
