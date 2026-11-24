// Рисует иконку приложения (белый щит с оранжевой паузой) и собирает AppIcon.icns для macOS
// или windows/AppIcon.ico для Windows, по расширению выходного файла.
// Сборка и запуск: см. README, раздел «Иконка».

import AppKit

func rgb(_ hex: UInt32) -> CGColor {
    CGColor(srgbRed: CGFloat((hex >> 16) & 0xff) / 255, green: CGFloat((hex >> 8) & 0xff) / 255,
            blue: CGFloat(hex & 0xff) / 255, alpha: 1)
}

/// Рисует в координатах 1024×1024 с осью y вниз. Подложка по сетке иконок macOS: 824×824 с полями 100.
/// Иконки Windows занимают почти весь квадрат, для них поля 32.
/// Фигуры заданы в квадрате 120×120 эскиза и масштабируются в подложку.
func draw(_ ctx: CGContext, px: CGFloat, inset: CGFloat) {
    ctx.scaleBy(x: px / 1024, y: px / 1024)
    ctx.translateBy(x: 0, y: 1024)
    ctx.scaleBy(x: 1, y: -1)

    let side = 1024 - 2 * inset
    let k: CGFloat = side / 120
    func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: inset + x * k, y: inset + y * k) }

    ctx.addPath(CGPath(roundedRect: CGRect(x: inset, y: inset, width: side, height: side),
                       cornerWidth: side * 185 / 824, cornerHeight: side * 185 / 824, transform: nil))
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

func render(_ px: Int, inset: CGFloat) -> CGContext {
    let ctx = CGContext(data: nil, width: px, height: px, bitsPerComponent: 8, bytesPerRow: px * 4,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    draw(ctx, px: CGFloat(px), inset: inset)
    return ctx
}

func png(_ px: Int, inset: CGFloat = 100) -> Data {
    NSBitmapImageRep(cgImage: render(px, inset: inset).makeImage()!).representation(using: .png, properties: [:])!
}

/// Кадр ICO в формате DIB: BITMAPINFOHEADER, BGRA снизу вверх без премультипликации, пустая маска AND.
func dib(_ px: Int) -> Data {
    let ctx = render(px, inset: 32)
    let src = ctx.data!.assumingMemoryBound(to: UInt8.self)
    var d = Data()
    func u16(_ v: Int) { withUnsafeBytes(of: UInt16(v).littleEndian) { d.append(contentsOf: $0) } }
    func u32(_ v: Int) { withUnsafeBytes(of: UInt32(v).littleEndian) { d.append(contentsOf: $0) } }
    u32(40); u32(px); u32(px * 2); u16(1); u16(32); u32(0); u32(0); u32(0); u32(0); u32(0); u32(0)
    for y in (0..<px).reversed() {
        for x in 0..<px {
            let i = (y * px + x) * 4
            let a = Int(src[i + 3])
            func un(_ c: UInt8) -> UInt8 { a == 0 ? 0 : UInt8(min(255, Int(c) * 255 / a)) }
            d.append(contentsOf: [un(src[i + 2]), un(src[i + 1]), un(src[i]), UInt8(a)])
        }
    }
    d.append(Data(count: ((px + 31) / 32) * 4 * px))
    return d
}

/// ICO: мелкие размеры кадрами DIB, 256 — PNG (так их читают и Проводник, и System.Drawing).
func ico(_ out: URL) throws {
    let frames = [16, 20, 24, 32, 40, 48, 64].map { ($0, dib($0)) } + [(256, png(256, inset: 32))]
    var d = Data()
    func u8(_ v: Int) { d.append(UInt8(v & 0xff)) }
    func u16(_ v: Int) { withUnsafeBytes(of: UInt16(v).littleEndian) { d.append(contentsOf: $0) } }
    func u32(_ v: Int) { withUnsafeBytes(of: UInt32(v).littleEndian) { d.append(contentsOf: $0) } }
    u16(0); u16(1); u16(frames.count)
    var offset = 6 + 16 * frames.count
    for (px, data) in frames {
        u8(px); u8(px); u8(0); u8(0); u16(1); u16(32); u32(data.count); u32(offset)
        offset += data.count
    }
    for (_, data) in frames { d.append(data) }
    try d.write(to: out)
}

// Каждый размер рисуется из векторов отдельно: мелкие размеры не размываются при уменьшении.
let out = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.icns")
if out.pathExtension.lowercased() == "ico" {
    try ico(out)
    print("Готово: \(out.path)")
    exit(0)
}
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
