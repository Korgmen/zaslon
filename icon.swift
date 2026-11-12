// Рисует иконку приложения (белый щит с оранжевой паузой) и собирает AppIcon.icns.
// Сборка и запуск: см. README, раздел «Иконка».

import AppKit

func rgb(_ hex: UInt32) -> CGColor {
    CGColor(srgbRed: CGFloat((hex >> 16) & 0xff) / 255, green: CGFloat((hex >> 8) & 0xff) / 255,
            blue: CGFloat(hex & 0xff) / 255, alpha: 1)
}

/// Рисует в координатах 1024×1024 с осью y вниз. Подложка по сетке иконок macOS: 824×824 с полями 100.
/// Фигуры заданы в квадрате 120×120 эскиза и масштабируются в подложку.
func draw(_ ctx: CGContext, px: CGFloat) {
    ctx.scaleBy(x: px / 1024, y: px / 1024)
    ctx.translateBy(x: 0, y: 1024)
    ctx.scaleBy(x: 1, y: -1)

    let k: CGFloat = 824 / 120
    func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: 100 + x * k, y: 100 + y * k) }

    ctx.addPath(CGPath(roundedRect: CGRect(x: 100, y: 100, width: 824, height: 824),
                       cornerWidth: 185, cornerHeight: 185, transform: nil))
    ctx.setFillColor(rgb(0x1f2a44))
    ctx.fillPath()

    let shield = CGMutablePath()
    shield.move(to: p(60, 22))
    shield.addLine(to: p(92, 34))
    shield.addLine(to: p(92, 60))
    shield.addCurve(to: p(60, 104), control1: p(92, 82), control2: p(78, 96))
    shield.addCurve(to: p(28, 60), control1: p(42, 96), control2: p(28, 82))
    shield.addLine(to: p(28, 34))
    shield.closeSubpath()
    ctx.addPath(shield)
    ctx.setFillColor(rgb(0xffffff))
    ctx.fillPath()

    ctx.setFillColor(rgb(0xf59e0b))
    for x in [47.0, 64.0] {
        let o = p(x, 48)
        ctx.addPath(CGPath(roundedRect: CGRect(x: o.x, y: o.y, width: 9 * k, height: 32 * k),
                           cornerWidth: 2 * k, cornerHeight: 2 * k, transform: nil))
    }
    ctx.fillPath()
}

func png(_ px: Int) -> Data {
    let ctx = CGContext(data: nil, width: px, height: px, bitsPerComponent: 8, bytesPerRow: 0,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    draw(ctx, px: CGFloat(px))
    return NSBitmapImageRep(cgImage: ctx.makeImage()!).representation(using: .png, properties: [:])!
}

// Каждый размер рисуется из векторов отдельно: мелкие размеры не размываются при уменьшении.
let out = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.icns")
let iconset = FileManager.default.temporaryDirectory.appendingPathComponent("AppIcon.iconset")
try? FileManager.default.removeItem(at: iconset)
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
for base in [16, 32, 128, 256, 512] {
    try png(base).write(to: iconset.appendingPathComponent("icon_\(base)x\(base).png"))
    try png(base * 2).write(to: iconset.appendingPathComponent("icon_\(base)x\(base)@2x.png"))
}

let p = Process()
p.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
p.arguments = ["-c", "icns", "-o", out.path, iconset.path]
try p.run()
p.waitUntilExit()
try? FileManager.default.removeItem(at: iconset)
guard p.terminationStatus == 0 else { fatalError("iconutil завершился с кодом \(p.terminationStatus)") }
print("Готово: \(out.path)")
