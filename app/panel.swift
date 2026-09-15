import AppKit
let W: CGFloat = 380, H: CGFloat = 496
let img = NSImage(size: NSSize(width: W, height: H)); img.lockFocus()
NSColor(calibratedWhite:0.985,alpha:1).setFill(); NSRect(x:0,y:0,width:W,height:H).fill()
let green=NSColor(calibratedRed:0.20,green:0.72,blue:0.35,alpha:1)
let blue=NSColor(calibratedRed:0.16,green:0.42,blue:0.95,alpha:1)
let purple=NSColor(calibratedRed:0.55,green:0.35,blue:0.90,alpha:1)
let gray=NSColor(calibratedWhite:0.50,alpha:1)
let dark=NSColor(calibratedWhite:0.13,alpha:1)
// screen coords: (x, topY) with y growing downward. P converts to NSView space.
func P(_ x:CGFloat,_ y:CGFloat)->NSPoint{NSPoint(x:x,y:H-y)}
func box(_ x:CGFloat,_ top:CGFloat,_ w:CGFloat,_ h:CGFloat,_ rad:CGFloat,_ c:NSColor){c.setFill();NSBezierPath(roundedRect:NSRect(x:x,y:H-top-h,width:w,height:h),xRadius:rad,yRadius:rad).fill()}
func txt(_ s:String,_ x:CGFloat,_ top:CGFloat,_ sz:CGFloat,_ c:NSColor,_ b:Bool=false){
  let f = b ? NSFont.boldSystemFont(ofSize:sz):NSFont.systemFont(ofSize:sz)
  (s as NSString).draw(at:NSPoint(x:x,y:H-top-sz),withAttributes:[.font:f,.foregroundColor:c])}
func txtC(_ s:String,_ cx:CGFloat,_ top:CGFloat,_ sz:CGFloat,_ c:NSColor,_ b:Bool=false){
  let f = b ? NSFont.boldSystemFont(ofSize:sz):NSFont.systemFont(ofSize:sz)
  let z=(s as NSString).size(withAttributes:[.font:f]); (s as NSString).draw(at:NSPoint(x:cx-z.width/2,y:H-top-sz),withAttributes:[.font:f,.foregroundColor:c])}
func strokeP(_ pts:[(CGFloat,CGFloat)],_ c:CGFloat,_ w:CGFloat,_ col:NSColor,_ closed:Bool=false){
  let p=NSBezierPath();p.lineWidth=w;p.lineCapStyle = .round;p.lineJoinStyle = .round
  for (i,pt) in pts.enumerated(){ i==0 ? p.move(to:P(pt.0,pt.1)):p.line(to:P(pt.0,pt.1)) }; if closed{p.close()}; col.setStroke(); p.stroke()}
func fillP(_ pts:[(CGFloat,CGFloat)],_ col:NSColor){let p=NSBezierPath();for (i,pt) in pts.enumerated(){i==0 ? p.move(to:P(pt.0,pt.1)):p.line(to:P(pt.0,pt.1))};p.close();col.setFill();p.fill()}
// glyphs in screen coords (x,top,size)
func gShield(_ x:CGFloat,_ t:CGFloat,_ s:CGFloat,_ col:NSColor){
  let p=NSBezierPath(); p.move(to:P(x+s/2,t)); p.line(to:P(x+s,t+s*0.2))
  p.curve(to:P(x+s/2,t+s),controlPoint1:P(x+s,t+s*0.7),controlPoint2:P(x+s*0.75,t+s))
  p.curve(to:P(x,t+s*0.2),controlPoint1:P(x+s*0.25,t+s),controlPoint2:P(x,t+s*0.7)); p.close(); col.setFill(); p.fill()
  strokeP([(x+s*0.28,t+s*0.5),(x+s*0.44,t+s*0.64),(x+s*0.74,t+s*0.34)],0,s*0.1,NSColor.white)}
func gFolder(_ x:CGFloat,_ t:CGFloat,_ s:CGFloat,_ c:NSColor){
  box(x,t,s*0.5,s*0.22,2,c); box(x,t+s*0.18,s,s*0.62,3,c)}
func gDoc(_ x:CGFloat,_ t:CGFloat,_ s:CGFloat,_ c:NSColor){
  box(x+s*0.12,t,s*0.76,s*0.86,3,c)
  strokeP([(x+s*0.28,t+s*0.34),(x+s*0.72,t+s*0.34)],0,s*0.07,NSColor.white)
  strokeP([(x+s*0.28,t+s*0.54),(x+s*0.72,t+s*0.54)],0,s*0.07,NSColor.white)}
func gLock(_ x:CGFloat,_ t:CGFloat,_ s:CGFloat,_ c:NSColor){
  let arc=NSBezierPath(); arc.appendArc(withCenter:P(x+s*0.5,t+s*0.44),radius:s*0.2,startAngle:0,endAngle:180); arc.lineWidth=s*0.11; c.setStroke(); arc.stroke()
  box(x+s*0.22,t+s*0.42,s*0.56,s*0.42,3,c)}
func gBolt(_ x:CGFloat,_ t:CGFloat,_ s:CGFloat,_ c:NSColor){
  fillP([(x+s*0.56,t),(x+s*0.22,t+s*0.56),(x+s*0.46,t+s*0.56),(x+s*0.4,t+s),(x+s*0.8,t+s*0.42),(x+s*0.52,t+s*0.42)],c)}
func gClock(_ x:CGFloat,_ t:CGFloat,_ s:CGFloat,_ c:NSColor){
  let circ=NSBezierPath(ovalIn:NSRect(x:x+s*0.1,y:H-t-s*0.9,width:s*0.8,height:s*0.8)); circ.lineWidth=s*0.09; c.setStroke(); circ.stroke()
  strokeP([(x+s*0.5,t+s*0.5),(x+s*0.5,t+s*0.26)],0,s*0.08,c); strokeP([(x+s*0.5,t+s*0.5),(x+s*0.68,t+s*0.5)],0,s*0.08,c)}
func sw(_ x:CGFloat,_ top:CGFloat,_ on:Bool){
  let tw:CGFloat=38,th:CGFloat=22; box(x,top,tw,th,11,on ? green:NSColor(calibratedWhite:0.80,alpha:1))
  NSColor.white.setFill(); NSBezierPath(ovalIn:NSRect(x: on ? x+tw-19:x+3,y:H-top-th+3,width:16,height:16)).fill()}

// header
gShield(16,18,24,green); txt("Bastion",50,18,17,dark,true); txt("v2.0.2",122,23,10.5,gray)
box(W-100,20,84,20,10,green.withAlphaComponent(0.16)); txtC("PROTECTED",W-58,24,9.5,green,true)
// hero
box(16,52,W-32,74,12,green.withAlphaComponent(0.11)); gShield(30,66,34,green)
txt("No threats detected",80,62,15,dark,true); txt("Last scan Sep 16, 4:10 AM · CLEAN",80,86,11,gray)
// stat tiles
let tw=(W-32-16)/3
func tile(_ i:CGFloat,_ g:(CGFloat,CGFloat,CGFloat,NSColor)->Void,_ tint:NSColor,_ v:String,_ l:String){
  let x=16+i*(tw+8); box(x,146,tw,66,10,NSColor(calibratedWhite:0.945,alpha:1))
  g(x+tw/2-8,156,16,tint); txtC(v,x+tw/2,176,17,dark,true); txtC(l,x+tw/2,198,8.5,gray)}
tile(0,gFolder,blue,"7","REPOS"); tile(1,gDoc,purple,"46","CONFIGS"); tile(2,gLock,gray,"0","QUARANTINE")
// scan button
box(16,228,W-32,38,9,green); txtC("Scan Now",W/2,240,14,NSColor.white,true)
// segmented
box(16,282,W-32,28,7,NSColor(calibratedWhite:0.90,alpha:1)); box(18,284,(W-36)/3,24,6,NSColor.white)
let seg=["Overview","Activity","Quarantine"]
for (i,s) in seg.enumerated(){txtC(s,16+(CGFloat(i)+0.5)*((W-32)/3),290,11,i==0 ? dark:gray,i==0)}
// protection
txt("PROTECTION",18,326,10,gray,true)
gBolt(18,346,16,green); txt("Real-time watcher",44,347,12.5,dark); sw(W-54,346,false)
gClock(18,382,16,blue); txt("Scheduled scan (6h + login)",44,383,12.5,dark); sw(W-54,382,false)
box(18,416,236,24,6,NSColor(calibratedWhite:0.945,alpha:1)); gShield(26,419,14,green); txt("Protect 2 repos (block commits)",48,421,10.5,dark)
// footer
gray.withAlphaComponent(0.22).setFill(); NSRect(x:16,y:H-456,width:W-32,height:1).fill()
txt("Logs",18,466,11,blue); txt("GitHub",58,466,11,blue); txt("Refresh",W-116,466,11,gray); txt("Quit",W-46,466,11,gray)
img.unlockFocus()
let png=NSBitmapImageRep(data:img.tiffRepresentation!)!.representation(using:.png,properties:[:])!
try! png.write(to:URL(fileURLWithPath:CommandLine.arguments[1])); print("redrawn v3")
