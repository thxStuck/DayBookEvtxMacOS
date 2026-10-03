// Draws the DayBookEvtxMacOS app icon (a log page with a time histogram and event rows)
// and writes every size of DayBookEvtxMacOS/Assets.xcassets/AppIcon.appiconset.
//
//   DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift scripts/make_icon.swift
import AppKit

let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
let set = root.appendingPathComponent("DayBookEvtxMacOS/Assets.xcassets/AppIcon.appiconset")

func color(_ hex: UInt32, _ a: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: CGFloat(hex >> 16 & 0xFF) / 255, green: CGFloat(hex >> 8 & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255, alpha: a)
}

/// Draws on a 1024-unit canvas with the origin at the top left: a ring-bound log book with a
/// time histogram and event rows, and a magnifier over the orange spike (an anomaly under the lens).
func draw(_ ctx: CGContext) {
    ctx.translateBy(x: 0, y: 1024)
    ctx.scaleBy(x: 1, y: -1)
    let space = CGColorSpace(name: CGColorSpace.sRGB)!
    func rounded(_ r: CGRect, _ radius: CGFloat) -> CGPath { CGPath(roundedRect: r, cornerWidth: radius, cornerHeight: radius, transform: nil) }

    // Tile (macOS icon grid: 824 × 824 at 100).
    let tile = CGRect(x: 100, y: 100, width: 824, height: 824)
    let tilePath = rounded(tile, 186)
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: 12), blur: 30, color: color(0x000000, 0.40))
    ctx.addPath(tilePath)
    ctx.setFillColor(color(0x0E1A2E))
    ctx.fillPath()
    ctx.restoreGState()
    ctx.saveGState()
    ctx.addPath(tilePath)
    ctx.clip()
    let bg = CGGradient(colorsSpace: space, colors: [color(0x2A4A78), color(0x0B1526)] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(bg, start: CGPoint(x: 300, y: 100), end: CGPoint(x: 724, y: 924),
                           options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
    let gloss = CGGradient(colorsSpace: space, colors: [color(0xFFFFFF, 0.10), color(0xFFFFFF, 0)] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(gloss, start: CGPoint(x: 512, y: 100), end: CGPoint(x: 512, y: 420), options: [])
    ctx.restoreGState()

    // Log book: page with a ring-bound spine on the left.
    let page = CGRect(x: 236, y: 196, width: 500, height: 620)
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: 10), blur: 24, color: color(0x000000, 0.45))
    ctx.addPath(rounded(page, 40))
    ctx.setFillColor(color(0xF6F8FC))
    ctx.fillPath()
    ctx.restoreGState()
    ctx.saveGState()
    ctx.addPath(rounded(page, 40))
    ctx.clip()
    ctx.setFillColor(color(0xDCE4EF))
    ctx.fill(CGRect(x: page.minX, y: page.minY, width: 64, height: page.height))
    ctx.restoreGState()
    for i in 0..<6 {
        let y = page.minY + 70 + CGFloat(i) * 96
        ctx.setFillColor(color(0x1B2B45))
        ctx.fillEllipse(in: CGRect(x: page.minX + 20, y: y, width: 24, height: 24))
        ctx.setStrokeColor(color(0x9AA9BF))
        ctx.setLineWidth(6)
        ctx.addArc(center: CGPoint(x: page.minX + 32, y: y + 12), radius: 20, startAngle: .pi * 0.75, endAngle: .pi * 1.25, clockwise: false)
        ctx.strokePath()
    }

    // Time histogram on the page.
    let heights: [CGFloat] = [36, 62, 46, 84, 54, 120, 58, 40]
    let baseline: CGFloat = 392
    for (i, h) in heights.enumerated() {
        let bar = CGRect(x: 336 + CGFloat(i) * 46, y: baseline - h, width: 32, height: h)
        ctx.addPath(rounded(bar, 7))
        ctx.setFillColor(color(i == 5 ? 0xF59E0B : 0x3B82F6))
        ctx.fillPath()
    }
    ctx.setFillColor(color(0xCBD5E1))
    ctx.fill(CGRect(x: 326, y: baseline + 12, width: 370, height: 5))

    // Event rows with level dots.
    let dots: [UInt32] = [0xEF4444, 0x3B82F6, 0xF59E0B, 0x94A3B8, 0x3B82F6]
    let widths: [CGFloat] = [300, 250, 280, 210, 240]
    for i in 0..<dots.count {
        let y = 446 + CGFloat(i) * 62
        ctx.setFillColor(color(dots[i]))
        ctx.fillEllipse(in: CGRect(x: 336, y: y, width: 26, height: 26))
        ctx.addPath(rounded(CGRect(x: 380, y: y + 5, width: widths[i], height: 16), 8))
        ctx.setFillColor(color(i == 0 ? 0xB8C4D4 : 0xD6DEE8))
        ctx.fillPath()
    }

    // Magnifier: the lens shows the orange spike enlarged.
    let center = CGPoint(x: 676, y: 676), radius: CGFloat = 148
    let lens = CGRect(x: center.x - radius, y: center.y - radius, width: radius * 2, height: radius * 2)
    // Handle (drawn first, under the ring).
    ctx.saveGState()
    ctx.translateBy(x: center.x, y: center.y)
    ctx.rotate(by: .pi / 4)
    ctx.setShadow(offset: CGSize(width: 0, height: 6), blur: 14, color: color(0x000000, 0.45))
    ctx.addPath(rounded(CGRect(x: radius - 6, y: -30, width: 150, height: 60), 30))
    ctx.setFillColor(color(0xE2E8F0))
    ctx.fillPath()
    ctx.addPath(rounded(CGRect(x: radius + 64, y: -30, width: 86, height: 60), 30))
    ctx.setFillColor(color(0xF59E0B))
    ctx.fillPath()
    ctx.restoreGState()
    // Glass with the magnified spike.
    ctx.saveGState()
    ctx.addEllipse(in: lens)
    ctx.clip()
    ctx.setFillColor(color(0xF6F8FC))
    ctx.fill(lens)
    let zoom: [(CGFloat, UInt32)] = [(70, 0x3B82F6), (205, 0xF59E0B), (95, 0x3B82F6)]
    let zbase = center.y + 92
    for (i, z) in zoom.enumerated() {
        let bar = CGRect(x: center.x - 118 + CGFloat(i) * 84, y: zbase - z.0, width: 66, height: z.0)
        ctx.addPath(rounded(bar, 12))
        ctx.setFillColor(color(z.1))
        ctx.fillPath()
    }
    ctx.setFillColor(color(0xCBD5E1))
    ctx.fill(CGRect(x: center.x - 140, y: zbase + 14, width: 280, height: 9))
    let glare = CGGradient(colorsSpace: space, colors: [color(0xFFFFFF, 0.35), color(0xFFFFFF, 0)] as CFArray, locations: [0, 1])!
    ctx.drawRadialGradient(glare, startCenter: CGPoint(x: center.x - 60, y: center.y - 70), startRadius: 0,
                           endCenter: CGPoint(x: center.x - 60, y: center.y - 70), endRadius: 130, options: [])
    ctx.restoreGState()
    // Ring.
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: 6), blur: 16, color: color(0x000000, 0.35))
    ctx.setStrokeColor(color(0xF1F5F9))
    ctx.setLineWidth(30)
    ctx.strokeEllipse(in: lens)
    ctx.restoreGState()
    ctx.setStrokeColor(color(0x94A3B8))
    ctx.setLineWidth(3)
    ctx.strokeEllipse(in: lens.insetBy(dx: 15, dy: 15))
}

func png(_ px: Int) -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                               colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    let ctx = NSGraphicsContext(bitmapImageRep: rep)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = ctx
    let cg = ctx.cgContext
    cg.clear(CGRect(x: 0, y: 0, width: px, height: px))
    cg.scaleBy(x: CGFloat(px) / 1024, y: CGFloat(px) / 1024)
    draw(cg)
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

var images: [[String: String]] = []
for (size, scale) in [(16, 1), (16, 2), (32, 1), (32, 2), (128, 1), (128, 2), (256, 1), (256, 2), (512, 1), (512, 2)] {
    let name = "icon_\(size)x\(size)\(scale == 2 ? "@2x" : "").png"
    try! png(size * scale).write(to: set.appendingPathComponent(name))
    images.append(["filename": name, "idiom": "mac", "scale": "\(scale)x", "size": "\(size)x\(size)"])
}
let contents: [String: Any] = ["images": images, "info": ["author": "xcode", "version": 1]]
let data = try! JSONSerialization.data(withJSONObject: contents, options: [.prettyPrinted, .sortedKeys])
try! data.write(to: set.appendingPathComponent("Contents.json"))
print("wrote \(images.count) icons to \(set.path)")
