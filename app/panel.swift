import AppKit
let W: CGFloat = 380, H: CGFloat = 468
let img = NSImage(size: NSSize(width: W, height: H)); img.lockFocus()
NSColor(calibratedWhite:0.98,alpha:1).setFill(); NSRect(x:0,y:0,width:W,height:H).fill()
let green=NSColor(calibratedRed:0.20,green:0.72,blue:0.35,alpha:1)
let blue=NSColor(calibratedRed:0.16,green:0.42,blue:0.95,alpha:1)
let purple=NSColor(calibratedRed:0.55,green:0.35,blue:0.90,alpha:1)
let gray=NSColor(calibratedWhite:0.45,alpha:1)
let dark=NSColor(calibratedWhite:0.12,alpha:1)
func T(_ s:String,_ x:CGFloat,_ y:CGFloat,_ sz:CGFloat,_ c:NSColor,_ b:Bool=false,mono:Bool=false){
  let f = mono ? NSFont.monospacedSystemFont(ofSize:sz,weight:.regular) : (b ? NSFont.boldSystemFont(ofSize:sz):NSFont.systemFont(ofSize:sz))
  (s as NSString).draw(at:NSPoint(x:x,y:H-y-sz),withAttributes:[.font:f,.foregroundColor:c])}
func RR(_ r:NSRect,_ rad:CGFloat,_ c:NSColor){c.setFill();NSBezierPath(roundedRect:r,xRadius:rad,yRadius:rad).fill()}
func shield(_ x:CGFloat,_ y:CGFloat,_ s:CGFloat,_ col:NSColor){
  let p=NSBezierPath(); p.move(to:NSPoint(x:x+s/2,y:H-y))
  p.line(to:NSPoint(x:x+s,y:H-y-s*0.2)); p.curve(to:NSPoint(x:x+s/2,y:H-y-s),controlPoint1:NSPoint(x:x+s,y:H-y-s*0.7),controlPoint2:NSPoint(x:x+s*0.75,y:H-y-s))
  p.curve(to:NSPoint(x:x,y:H-y-s*0.2),controlPoint1:NSPoint(x:x+s*0.25,y:H-y-s),controlPoint2:NSPoint(x:x,y:H-y-s*0.7)); p.close(); col.setFill(); p.fill()
  let ck=NSBezierPath(); ck.lineWidth=s*0.09; ck.lineCapStyle = .round; ck.lineJoinStyle = .round
  ck.move(to:NSPoint(x:x+s*0.28,y:H-y-s*0.52)); ck.line(to:NSPoint(x:x+s*0.44,y:H-y-s*0.66)); ck.line(to:NSPoint(x:x+s*0.74,y:H-y-s*0.36))
  NSColor.white.setStroke(); ck.stroke()}
// header
shield(16,20,22,green); T("Bastion",48,20,16,dark,true); T("v2.0",118,24,10,gray)
RR(NSRect(x:W-96,y:H-38,width:80,height:20),10,green.withAlphaComponent(0.16))
T("PROTECTED",W-88,22,9.5,green,true)
// hero card
RR(NSRect(x:16,y:H-132,width:W-32,height:78),12,green.withAlphaComponent(0.12))
shield(30,66,34,green)
T("No threats detected",78,60,15,dark,true)
T("Last scan Sep 16, 4:10 AM · CLEAN",78,84,11,gray)
// stat tiles
let tw=(W-32-16)/3
func tile(_ i:CGFloat,_ icon:NSColor,_ val:String,_ lab:String){
  let x=16+i*(tw+8); RR(NSRect(x:x,y:H-214,width:tw,height:64),10,NSColor(calibratedWhite:0.94,alpha:1))
  RR(NSRect(x:x+tw/2-6,y:H-166,width:12,height:12),3,icon)
  let f=NSFont.boldSystemFont(ofSize:17); let s=val as NSString; let sz=s.size(withAttributes:[.font:f])
  s.draw(at:NSPoint(x:x+(tw-sz.width)/2,y:H-190),withAttributes:[.font:f,.foregroundColor:dark])
  let lf=NSFont.systemFont(ofSize:8.5); let ls=lab as NSString; let lz=ls.size(withAttributes:[.font:lf])
  ls.draw(at:NSPoint(x:x+(tw-lz.width)/2,y:H-206),withAttributes:[.font:lf,.foregroundColor:gray])}
tile(0,blue,"7","REPOS"); tile(1,purple,"53","CONFIGS"); tile(2,gray,"0","QUARANTINE")
// scan button
RR(NSRect(x:16,y:H-262,width:W-32,height:36),9,green)
let bf=NSFont.boldSystemFont(ofSize:14); let bs="🔍  Scan Now" as NSString
("Scan Now" as NSString).draw(at:NSPoint(x:W/2-38,y:H-262+9),withAttributes:[.font:bf,.foregroundColor:NSColor.white])
// segmented
RR(NSRect(x:16,y:H-306,width:W-32,height:28),7,NSColor(calibratedWhite:0.90,alpha:1))
RR(NSRect(x:18,y:H-304,width:(W-36)/3,height:24),6,NSColor.white)
let seg=["Overview","Activity","Quarantine"]
for (i,s) in seg.enumerated(){let x=16+CGFloat(i)*((W-32)/3); let f=NSFont.systemFont(ofSize:11,weight: i==0 ? .semibold : .regular)
  let ss=s as NSString; let z=ss.size(withAttributes:[.font:f]); ss.draw(at:NSPoint(x:x+((W-32)/3-z.width)/2,y:H-303+5),withAttributes:[.font:f,.foregroundColor: i==0 ? dark:gray])}
// overview content
T("PROTECTION",20,320,10,gray,true)
func toggle(_ label:String,_ icon:NSColor,_ y:CGFloat,_ on:Bool){
  RR(NSRect(x:20,y:H-y-2,width:12,height:12),3,icon); T(label,40,y-1,12,dark)
  let tw2:CGFloat=36,th:CGFloat=20,tx=W-20-tw2
  (on ? green:NSColor(calibratedWhite:0.8,alpha:1)).setFill(); NSBezierPath(roundedRect:NSRect(x:tx,y:H-y-th+3,width:tw2,height:th),xRadius:10,yRadius:10).fill()
  NSColor.white.setFill(); NSBezierPath(ovalIn:NSRect(x: on ? tx+tw2-17:tx+3,y:H-y-th+5,width:14,height:14)).fill()}
toggle("Real-time watcher",green,344,true)
toggle("Scheduled scan (6h + login)",blue,374,false)
RR(NSRect(x:20,y:H-408,width:210,height:22),6,NSColor(calibratedWhite:0.93,alpha:1))
T("🛡 Protect 2 repos (block commits)",26,394,10.5,dark)
// divider + footer
gray.withAlphaComponent(0.25).setFill(); NSRect(x:16,y:H-430,width:W-32,height:1).fill()
T("Logs   GitHub",20,442,11,blue); T("Refresh   Quit",W-108,442,11,gray)
img.unlockFocus()
let png=NSBitmapImageRep(data:img.tiffRepresentation!)!.representation(using:.png,properties:[:])!
try! png.write(to:URL(fileURLWithPath:CommandLine.arguments[1])); print("v2 panel rendered")
