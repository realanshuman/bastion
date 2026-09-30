// snapshot.swift: renders the real window and menu-bar panel offscreen (live data) in light and dark, at 2x.
import SwiftUI
import AppKit
final class KeyWindow: NSWindow {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
    override var isKeyWindow: Bool { true }
    override var isMainWindow: Bool { true }
}
@MainActor func capture(_ view: NSView, _ size: NSSize, radius: CGFloat, to path: String) {
    let scale: CGFloat = 2
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size.width * scale), pixelsHigh: Int(size.height * scale),
                               bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = size
    view.cacheDisplay(in: view.bounds, to: rep)
    let out = NSImage(size: size)
    out.lockFocus()
    NSBezierPath(roundedRect: NSRect(origin: .zero, size: size), xRadius: radius, yRadius: radius).addClip()
    rep.draw(in: NSRect(origin: .zero, size: size))
    out.unlockFocus()
    var rect = NSRect(origin: .zero, size: size)
    let cg = out.cgImage(forProposedRect: &rect, context: nil, hints: [.ctm: AffineTransform(scale: scale)])!
    try! NSBitmapImageRep(cgImage: cg).representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: path))
    print("wrote", (path as NSString).lastPathComponent)
}
@main struct Snap {
    static func main() {
        _ = NSApplication.shared
        NSApp.setActivationPolicy(.prohibited)
        MainActor.assumeIsolated {
            let dir = CommandLine.arguments[1]
            let only = CommandLine.arguments.count > 2 ? Set(CommandLine.arguments[2].split(separator: ",").map(String.init)) : nil
            let size = NSSize(width: 1200, height: Double(ProcessInfo.processInfo.environment["SNAP_H"] ?? "800") ?? 800)
            let shots: [(String, () -> Void, Double)] = [
                ("home", { Router.shared.go(.home) }, 6),
                ("chat", { Router.shared.go(.home); AppStore.shared.chat.removeAll(); AppStore.shared.askBastion("is workspace safe?") }, 9),
                ("needs", { Router.shared.openNeedsYou() }, 3.5),
                ("incidents", { Router.shared.openHistory("incidents") }, 3.5),
                ("protection", { Router.shared.go(.protection) }, 4),
                ("quarantine", { Router.shared.openHistory("quarantine") }, 3),
                ("repos", { Router.shared.go(.repos) }, 3.5),
                ("activity", { Router.shared.openHistory("activity") }, 3),
                ("settings", { Router.shared.go(.settings) }, 3),
                ("agents", { Router.shared.go(.agents) }, 3),
                ("palette", { Router.shared.go(.home) }, 3),
                ("guide", { Router.shared.go(.guide) }, 3.5),
                ("incident", { Router.shared.open(incident: ProcessInfo.processInfo.environment["INC"] ?? "") }, 4),
            ]
            for mode in ["light", "dark"] {
                let appearance = NSAppearance(named: mode == "dark" ? .darkAqua : .aqua)!
                NSApp.appearance = appearance
                for (name, setup, wait) in shots where only == nil || only!.contains(name) {
                    setup()
                    let host = NSHostingView(rootView: MainWindow().environment(\.controlActiveState, .key))
                    let win = KeyWindow(contentRect: NSRect(origin: NSPoint(x: -6000, y: -6000), size: size), styleMask: [.borderless], backing: .buffered, defer: false)
                    win.appearance = appearance
                    win.contentView = host
                    win.orderFrontRegardless()
                    RunLoop.main.run(until: Date().addingTimeInterval(wait))
                    if name == "palette" { Router.shared.palette = true; RunLoop.main.run(until: Date().addingTimeInterval(1.2)) }
                    capture(host, size, radius: 12, to: "\(dir)/\(mode)-\(name).png")
                    Router.shared.palette = false
                    win.orderOut(nil)
                }
                if only == nil || only!.contains("panel") {
                    let model = GuardModel()
                    let panel = NSHostingView(rootView: PanelView(model: model).environment(\.controlActiveState, .key))
                    let pw = KeyWindow(contentRect: NSRect(x: -6000, y: -6000, width: 372, height: 760), styleMask: [.borderless], backing: .buffered, defer: false)
                    pw.appearance = appearance
                    pw.contentView = panel
                    pw.orderFrontRegardless()
                    RunLoop.main.run(until: Date().addingTimeInterval(7))
                    let fit = panel.fittingSize
                    pw.setContentSize(fit)
                    RunLoop.main.run(until: Date().addingTimeInterval(1.2))
                    capture(panel, fit, radius: 14, to: "\(dir)/\(mode)-panel.png")
                    pw.orderOut(nil)
                }
            }
            // the "Install command-line tool" sheet: the plan this HOME really gets, then a finished install
            if only?.contains("cli") == true {
                @MainActor func sheetShot(_ name: String, _ mode: String) {
                    let appearance = NSAppearance(named: mode == "dark" ? .darkAqua : .aqua)!
                    NSApp.appearance = appearance
                    let host = NSHostingView(rootView: CommandLineSheet(store: AppStore.shared))
                    let w = KeyWindow(contentRect: NSRect(x: -6000, y: -6000, width: 540, height: 400), styleMask: [.borderless], backing: .buffered, defer: false)
                    w.appearance = appearance; w.contentView = host; w.orderFrontRegardless()
                    RunLoop.main.run(until: Date().addingTimeInterval(0.8))
                    let fit = host.fittingSize; w.setContentSize(fit)
                    RunLoop.main.run(until: Date().addingTimeInterval(0.6))
                    capture(host, fit, radius: 12, to: "\(dir)/\(mode)-cli-\(name).png")
                    w.orderOut(nil)
                }
                AppStore.shared.refresh(); RunLoop.main.run(until: Date().addingTimeInterval(2))
                AppStore.shared.installCommandLine(); RunLoop.main.run(until: Date().addingTimeInterval(5))
                for m in ["light", "dark"] { sheetShot("plan", m) }
                let command = HOME_DIR + "/.security-guard/bin/bastion"
                AppStore.shared.cliFlow = CommandLineFlow(phase: .plan, plan: ["action": "link", "link": HOME_DIR + "/.local/bin/bastion", "command": command,
                    "summary": "Bastion will add a link at ~/.local/bin/bastion. That folder is already on your PATH, so your shell setup doesn't change, and it works in terminal windows that are already open too."])
                for m in ["light", "dark"] { sheetShot("link", m) }
                AppStore.shared.cliFlow = CommandLineFlow(phase: .done, plan: [:], result: ["ok": true, "verified": true, "how": "shell"])
                for m in ["light", "dark"] { sheetShot("done", m) }
                print("done"); return
            }
            // the menu-bar icon in its three states, big enough to inspect
            for st in ["all_clear", "clean_up", "act_now", "not_running"] {
                let icon = menuBarIcon(st); icon.isTemplate = false
                let big = NSImage(size: NSSize(width: 72, height: 72)); big.lockFocus()
                NSColor.white.setFill(); NSRect(x: 0, y: 0, width: 72, height: 72).fill()
                icon.draw(in: NSRect(x: 0, y: 0, width: 72, height: 72)); big.unlockFocus()
                var r = NSRect(x: 0, y: 0, width: 72, height: 72)
                try! NSBitmapImageRep(cgImage: big.cgImage(forProposedRect: &r, context: nil, hints: nil)!).representation(using: .png, properties: [:])!
                    .write(to: URL(fileURLWithPath: "\(dir)/menubar-\(st).png"))
            }
            print("done")
        }
    }
}
