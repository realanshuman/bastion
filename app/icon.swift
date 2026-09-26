// icon.swift: renders Bastion's app icon: the four-band shield in white on an ink tile, on the macOS icon grid.
import AppKit
let S: CGFloat = 1024
let img = NSImage(size: NSSize(width: S, height: S), flipped: true) { _ in
    guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
    let tile = NSRect(x: 100, y: 100, width: 824, height: 824)
    let body = NSBezierPath(roundedRect: tile, xRadius: 186, yRadius: 186)
    // soft drop shadow under the tile
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: 14), blur: 30, color: NSColor.black.withAlphaComponent(0.32).cgColor)
    NSColor(srgbRed: 0.05, green: 0.055, blue: 0.063, alpha: 1).setFill(); body.fill()
    ctx.restoreGState()
    // ink, a little lighter at the top
    ctx.saveGState(); body.addClip()
    NSGradient(colors: [NSColor(srgbRed: 0.17, green: 0.18, blue: 0.20, alpha: 1), NSColor(srgbRed: 0.05, green: 0.055, blue: 0.063, alpha: 1)])!
        .draw(in: tile, angle: 90)
    NSColor.white.withAlphaComponent(0.10).setStroke()
    let rim = NSBezierPath(roundedRect: tile.insetBy(dx: 1.5, dy: 1.5), xRadius: 185, yRadius: 185); rim.lineWidth = 3; rim.stroke()
    ctx.restoreGState()
    // the mark (24-unit drawing, as on the website), centred
    let s: CGFloat = 21, ox = S / 2 - 12 * s, oy = S / 2 - 12 * s + 6
    func p(_ x: CGFloat, _ y: CGFloat) -> NSPoint { NSPoint(x: ox + x * s, y: oy + y * s) }
    let shield = NSBezierPath()
    shield.move(to: p(12, 1.6)); shield.line(to: p(20.6, 4.6)); shield.line(to: p(20.6, 11.2))
    shield.curve(to: p(12, 22.6), controlPoint1: p(20.6, 16.6), controlPoint2: p(17.1, 20.6))
    shield.curve(to: p(3.4, 11.2), controlPoint1: p(6.9, 20.6), controlPoint2: p(3.4, 16.6))
    shield.line(to: p(3.4, 4.6)); shield.close()
    ctx.saveGState(); shield.addClip()
    let bands = NSBezierPath()
    for (y, h) in [(0.0, 7.0), (8.35, 3.05), (12.75, 3.05), (17.15, 7.0)] as [(CGFloat, CGFloat)] {
        bands.appendRect(NSRect(x: ox, y: oy + y * s, width: 24 * s, height: h * s))
    }
    bands.addClip()
    NSGradient(colors: [NSColor.white, NSColor(srgbRed: 0.84, green: 0.86, blue: 0.89, alpha: 1)])!.draw(in: NSRect(x: ox, y: oy, width: 24 * s, height: 24 * s), angle: 90)
    ctx.restoreGState()
    return true
}
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(S), pixelsHigh: Int(S), bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                           isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
img.draw(in: NSRect(x: 0, y: 0, width: S, height: S))
NSGraphicsContext.restoreGraphicsState()
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
print("icon written")
