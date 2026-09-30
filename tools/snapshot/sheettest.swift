// sheettest.swift: opens "Install command-line tool" as a real sheet on the app's main window, clicks through it
// (Install, then Add, which really installs, so run it with a fake HOME), and checks at every step that the sheet's
// window is as tall as its content. A sheet that doesn't grow with its content cuts off its title and buttons.
import SwiftUI
import AppKit
final class KeyWin: NSWindow {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
}
@main struct SheetTest {
    static func main() {
        _ = NSApplication.shared
        NSApp.setActivationPolicy(.accessory)
        MainActor.assumeIsolated {
            let store = AppStore.shared
            let win = KeyWin(contentRect: NSRect(x: -6000, y: -6000, width: 1000, height: 700), styleMask: [.titled], backing: .buffered, defer: false)
            win.contentView = NSHostingView(rootView: MainWindow()); win.makeKeyAndOrderFront(nil)
            RunLoop.main.run(until: Date().addingTimeInterval(0.5))
            var worst: CGFloat = 0
            func report(_ label: String) {
                RunLoop.main.run(until: Date().addingTimeInterval(1.2))
                guard let sheet = win.attachedSheet, let cv = sheet.contentView else { print(label, ": no sheet"); return }
                let have = sheet.contentLayoutRect.height, need = cv.fittingSize.height
                worst = max(worst, need - have)
                print(String(format: "%-8@ window %4.0f  content needs %4.0f  %@", label as NSString, have, need, need - have > 1 ? "CLIPPED" : "fits"))
            }
            for (label, step) in [("clicked", { store.installCommandLine() }), ("plan", {}), ("adding", { store.confirmCommandLine() }), ("done", {})] as [(String, () -> Void)] {
                step(); report(label)
            }
            print(worst > 1 ? "RESULT: clipped by \(Int(worst))pt" : "RESULT: fits at every step")
        }
    }
}
