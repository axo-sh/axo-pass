// Render the Chrome PNG icons from the app icon glyph.
//
// Usage: swift scripts/make-icons.swift <glyph.svg> <output dir>
//
// Chrome does not accept SVG icons. The glyph is drawn alone in three colors:
// `axo-<size>.png` in neutral gray, which is visible on any toolbar and is the
// default, `axo-light-<size>.png` in a dark color for a light toolbar, and
// `axo-dark-<size>.png` in a light color for a dark toolbar. The background
// script switches between the last two with `action.setIcon`.
// The SVG has about 11% padding on each side, which the drawing crops.
import AppKit

let args = CommandLine.arguments
guard args.count == 3, let glyph = NSImage(contentsOfFile: args[1]) else {
  FileHandle.standardError.write(Data("usage: make-icons.swift <glyph.svg> <output dir>\n".utf8))
  exit(2)
}
let outDir = URL(fileURLWithPath: args[2])
let crop: CGFloat = 1.2

func gray(_ value: CGFloat) -> NSColor {
  NSColor(srgbRed: value, green: value, blue: value, alpha: 1)
}

let variants: [(name: String, color: NSColor)] = [
  ("axo", NSColor(srgbRed: 0.545, green: 0.553, blue: 0.569, alpha: 1)),
  ("axo-light", gray(0.235)),
  ("axo-dark", gray(0.91)),
]

for variant in variants {
  for size in [16, 32, 48, 128] {
    let px = CGFloat(size)
    guard
      let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8,
        samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
        bytesPerRow: 0, bitsPerPixel: 0)
    else { exit(1) }
    rep.size = NSSize(width: px, height: px)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    NSGraphicsContext.current?.imageInterpolation = .high
    let drawn = px * crop
    let offset = (px - drawn) / 2
    glyph.draw(in: NSRect(x: offset, y: offset, width: drawn, height: drawn))
    // Tint the white glyph, keeping its alpha.
    variant.color.setFill()
    NSRect(x: 0, y: 0, width: px, height: px).fill(using: .sourceAtop)
    NSGraphicsContext.restoreGraphicsState()
    let png = rep.representation(using: .png, properties: [:])!
    try png.write(to: outDir.appendingPathComponent("\(variant.name)-\(size).png"))
  }
}
