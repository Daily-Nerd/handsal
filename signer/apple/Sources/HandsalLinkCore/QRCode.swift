import CoreImage
import Foundation

/// A QR code as a square of dark and light modules, and its drawing for a terminal.
///
/// CoreImage owns the encoding (error correction M); this type reads the modules back out of the
/// filter's one-pixel-per-module image, so what is drawn is exactly what the filter produced.
/// Failure mode: nil when the system cannot make the code (the caller says `internal`): there is
/// no fallback drawing.
public enum QRCode {
    public static func modules(for text: String) -> [[Bool]]? {
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(Data(text.utf8), forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")
        guard let image = filter.outputImage else { return nil }
        let width = Int(image.extent.width), height = Int(image.extent.height)
        guard width > 0, width == height else { return nil }
        let context = CIContext(options: [.useSoftwareRenderer: true])
        var pixels = [UInt8](repeating: 0, count: width * height * 4)
        context.render(image, toBitmap: &pixels, rowBytes: width * 4, bounds: image.extent,
                       format: .RGBA8, colorSpace: CGColorSpaceCreateDeviceRGB())
        // The image has its origin at the bottom left; the bitmap is written from the top row down.
        return (0..<height).map { row in (0..<width).map { column in pixels[(row * width + column) * 4] < 128 } }
    }

    private static let quietZone = 4

    /// Lines of half blocks, two module rows to a text row, dark modules black on a white ground
    /// whatever the terminal's own colors are, with a quiet zone of four modules around.
    public static func terminalLines(_ modules: [[Bool]]) -> [String] {
        let side = modules.count + 2 * quietZone
        func dark(_ row: Int, _ column: Int) -> Bool {
            let r = row - quietZone, c = column - quietZone
            return r >= 0 && c >= 0 && r < modules.count && c < modules.count && modules[r][c]
        }
        return stride(from: 0, to: side, by: 2).map { row in
            let cells = (0..<side).map { column -> String in
                switch (dark(row, column), dark(row + 1, column)) {
                case (false, false): return " "
                case (true, false): return "▀"
                case (false, true): return "▄"
                case (true, true): return "█"
                }
            }
            return "\u{1B}[30;47m" + cells.joined() + "\u{1B}[0m"
        }
    }
}
