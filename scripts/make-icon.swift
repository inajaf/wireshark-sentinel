import AppKit
import Foundation

// Draws the 1024×1024 master icon. The rounded-square, shadow and palette follow
// the macOS app-icon grid; the shield and Wi-Fi arcs carry the app's meaning.
// Run: swift scripts/make-icon.swift <output.png>

let size: CGFloat = 1024
let output = CommandLine.arguments.count > 1
    ? URL(fileURLWithPath: CommandLine.arguments[1])
    : URL(fileURLWithPath: "Assets/AppIcon-1024.png")

guard let rep = NSBitmapImageRep(
    bitmapDataPlanes: nil,
    pixelsWide: Int(size),
    pixelsHigh: Int(size),
    bitsPerSample: 8,
    samplesPerPixel: 4,
    hasAlpha: true,
    isPlanar: false,
    colorSpaceName: .deviceRGB,
    bytesPerRow: 0,
    bitsPerPixel: 0
) else {
    fatalError("could not create the bitmap")
}

guard let context = NSGraphicsContext(bitmapImageRep: rep) else {
    fatalError("could not create the graphics context")
}

NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = context

func color(_ hex: UInt32, alpha: CGFloat = 1) -> NSColor {
    NSColor(
        srgbRed: CGFloat((hex >> 16) & 0xff) / 255,
        green: CGFloat((hex >> 8) & 0xff) / 255,
        blue: CGFloat(hex & 0xff) / 255,
        alpha: alpha
    )
}

let canvas = NSRect(x: 0, y: 0, width: size, height: size)
color(0x000000, alpha: 0).setFill()
canvas.fill()

// The macOS grid: 824 pt of artwork on a 1024 pt canvas, with room for a shadow.
let tile = NSRect(x: 100, y: 116, width: 824, height: 824)
let tilePath = NSBezierPath(roundedRect: tile, xRadius: 186, yRadius: 186)

// Soft contact shadow under the tile.
NSGraphicsContext.saveGraphicsState()
let tileShadow = NSShadow()
tileShadow.shadowColor = color(0x000000, alpha: 0.38)
tileShadow.shadowBlurRadius = 34
tileShadow.shadowOffset = NSSize(width: 0, height: -14)
tileShadow.set()
color(0x0a1a27).setFill()
tilePath.fill()
NSGraphicsContext.restoreGraphicsState()

// Deep teal background with a lighter lower edge.
let background = NSGradient(colors: [color(0x081521), color(0x0d3541)])!
background.draw(in: tilePath, angle: -90)

// A quiet radial glow gives the shield something to sit on.
if let glow = NSGradient(colors: [color(0x2ad4bd, alpha: 0.32), color(0x2ad4bd, alpha: 0)]) {
    glow.draw(
        fromCenter: NSPoint(x: 512, y: 535),
        radius: 0,
        toCenter: NSPoint(x: 512, y: 535),
        radius: 360,
        options: []
    )
}

// Thin listening rings, kept faint so they disappear at 16 pt rather than turn to noise.
for (radius, alpha) in [(300.0, 0.075), (390.0, 0.05), (475.0, 0.032)] {
    let ring = NSBezierPath(ovalIn: NSRect(
        x: 512 - radius,
        y: 535 - radius,
        width: radius * 2,
        height: radius * 2
    ))
    ring.lineWidth = 2
    color(0xb9fbe8, alpha: alpha).setStroke()
    ring.stroke()
}

// Top inner highlight on the tile.
let tileHighlight = NSBezierPath(roundedRect: tile.insetBy(dx: 2, dy: 2), xRadius: 184, yRadius: 184)
tileHighlight.lineWidth = 2
color(0xffffff, alpha: 0.07).setStroke()
tileHighlight.stroke()

// Shield.
let shield = NSBezierPath()
shield.move(to: NSPoint(x: 512, y: 782))
shield.curve(
    to: NSPoint(x: 714, y: 700),
    controlPoint1: NSPoint(x: 604, y: 782),
    controlPoint2: NSPoint(x: 676, y: 748)
)
shield.curve(
    to: NSPoint(x: 708, y: 520),
    controlPoint1: NSPoint(x: 722, y: 660),
    controlPoint2: NSPoint(x: 708, y: 590)
)
shield.curve(
    to: NSPoint(x: 512, y: 238),
    controlPoint1: NSPoint(x: 704, y: 398),
    controlPoint2: NSPoint(x: 620, y: 296)
)
shield.curve(
    to: NSPoint(x: 316, y: 520),
    controlPoint1: NSPoint(x: 404, y: 296),
    controlPoint2: NSPoint(x: 320, y: 398)
)
shield.curve(
    to: NSPoint(x: 310, y: 700),
    controlPoint1: NSPoint(x: 312, y: 590),
    controlPoint2: NSPoint(x: 298, y: 660)
)
shield.curve(
    to: NSPoint(x: 512, y: 782),
    controlPoint1: NSPoint(x: 348, y: 748),
    controlPoint2: NSPoint(x: 420, y: 782)
)
shield.close()

// Shield shadow, then the mint face.
NSGraphicsContext.saveGraphicsState()
let shieldShadow = NSShadow()
shieldShadow.shadowColor = color(0x000000, alpha: 0.32)
shieldShadow.shadowBlurRadius = 32
shieldShadow.shadowOffset = NSSize(width: 0, height: -12)
shieldShadow.set()
color(0x1a8f86).setFill()
shield.fill()
NSGraphicsContext.restoreGraphicsState()

let shieldFill = NSGradient(colors: [color(0xc3fdec), color(0x43cdb7)])!
shieldFill.draw(in: shield, angle: -90)

shield.lineWidth = 3
color(0xffffff, alpha: 0.28).setStroke()
shield.stroke()

// Wi-Fi symbol cut out of the shield.
let signalCenter = NSPoint(x: 512, y: 520)
let ink = color(0x07232d)

for radius in [72.0, 140.0, 208.0] {
    let arc = NSBezierPath()
    arc.appendArc(
        withCenter: signalCenter,
        radius: radius,
        startAngle: 40,
        endAngle: 140
    )
    arc.lineWidth = 40
    arc.lineCapStyle = .round
    ink.setStroke()
    arc.stroke()
}

let dot = NSBezierPath(ovalIn: NSRect(x: signalCenter.x - 31, y: signalCenter.y - 31, width: 62, height: 62))
ink.setFill()
dot.fill()

NSGraphicsContext.restoreGraphicsState()

guard let png = rep.representation(using: .png, properties: [:]) else {
    fatalError("could not encode the PNG")
}
try png.write(to: output)
print("wrote \(output.path)")
