import AppKit
let S: CGFloat = 1024
let img = NSImage(size: NSSize(width: S, height: S))
img.lockFocus()
let ctx = NSGraphicsContext.current!.cgContext
// background gradient (deep indigo -> blue)
let rr = NSBezierPath(roundedRect: NSRect(x: 0, y: 0, width: S, height: S), xRadius: 224, yRadius: 224)
rr.addClip()
let cols = [NSColor(calibratedRed:0.10,green:0.11,blue:0.30,alpha:1).cgColor,
            NSColor(calibratedRed:0.16,green:0.30,blue:0.85,alpha:1).cgColor] as CFArray
let grad = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: cols, locations: [0,1])!
ctx.drawLinearGradient(grad, start: CGPoint(x:0,y:S), end: CGPoint(x:S,y:0), options: [])
// shield
let cx = S/2
func shield(_ scale: CGFloat, _ color: NSColor) {
    let w = 470*scale, topY = 800*scale + (S-820)/2, h = 560*scale
    let p = NSBezierPath()
    let left = cx-w/2, right = cx+w/2, top = topY, bot = topY-h
    p.move(to: NSPoint(x: cx, y: top))
    p.line(to: NSPoint(x: right, y: top-h*0.18))
    p.curve(to: NSPoint(x: cx, y: bot), controlPoint1: NSPoint(x: right, y: bot+h*0.30), controlPoint2: NSPoint(x: cx+w*0.28, y: bot+h*0.02))
    p.curve(to: NSPoint(x: left, y: top-h*0.18), controlPoint1: NSPoint(x: cx-w*0.28, y: bot+h*0.02), controlPoint2: NSPoint(x: left, y: bot+h*0.30))
    p.close(); color.setFill(); p.fill()
}
shield(1.0, NSColor.white.withAlphaComponent(0.95))
// check mark
let ck = NSBezierPath(); ck.lineWidth = 62; ck.lineCapStyle = .round; ck.lineJoinStyle = .round
let midY = (S/2)
ck.move(to: NSPoint(x: cx-118, y: midY-6))
ck.line(to: NSPoint(x: cx-24,  y: midY-96))
ck.line(to: NSPoint(x: cx+140, y: midY+118))
NSColor(calibratedRed:0.16,green:0.30,blue:0.85,alpha:1).setStroke(); ck.stroke()
img.unlockFocus()
let tiff = img.tiffRepresentation!
let png = NSBitmapImageRep(data: tiff)!.representation(using: .png, properties: [:])!
try! png.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
print("icon written")
