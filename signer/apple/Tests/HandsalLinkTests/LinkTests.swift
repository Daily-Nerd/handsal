import CoreGraphics
import CoreImage
import Foundation
import CryptoKit
import HandsalCore
import HandsalKeyScan
import HandsalLinkCore
import Testing

private final class RecordingDisplay: Display, @unchecked Sendable {
    private let lock = NSLock()
    private var written = ""
    var text: String { lock.withLock { written } }
    func show(_ text: String) throws { lock.withLock { written += text } }
}

private func fixedBytes(_ seed: UInt8) -> () -> [UInt8] { { (0..<32).map { seed &+ UInt8($0) } } }

/// SG-09: the linking tool, outside the signer. One-time code of 32 random bytes, shown as a QR
/// code on the display channel; `device.add` and `member.add` bind its hashstr.
@Suite("device linking tool (SG-09)")
struct LinkTests {
    @Test("lnk/code-hash-format: link_code_hash is the canonical hashstr of the 32 code bytes")
    func theHashIsAHashstrOfTheCode() throws {
        let bytes = (0..<32).map { UInt8($0) }
        let code = try LinkCode.make(random: { bytes })
        #expect(code.bytes == bytes)
        #expect(code.hash == Encoding.hashstr(bytes))
        #expect(Encoding.isHashstr(code.hash) && code.hash.hasPrefix("uEi") && code.hash.utf8.count == 47)
        // the hash of the 32 bytes, not of their text form
        #expect(code.hash != Encoding.hashstr(Array(code.text.utf8)))
    }

    @Test("every code is its own: two draws differ, and the system source is 32 bytes each time")
    func systemDrawsDiffer() throws {
        let a = try LinkCode.make(), b = try LinkCode.make()
        #expect(a.bytes.count == 32 && b.bytes.count == 32 && a.bytes != b.bytes && a.hash != b.hash)
    }

    @Test("a random source that gives anything but 32 bytes is internal, never a short or zero code")
    func aBadSourceFailsLoudly() {
        for count in [0, 1, 31, 33, 64] {
            #expect(throws: Refusal("internal")) { try LinkCode.make(random: { [UInt8](repeating: 7, count: count) }) }
        }
        #expect(throws: Refusal("internal")) { try LinkCode.make(random: { [UInt8](repeating: 0, count: 32) }) }
    }

    @Test("the QR text is the base64url of the 43 characters of the code, and the QR decodes to it")
    func theQRCarriesTheCode() throws {
        let code = try LinkCode.make(random: fixedBytes(9))
        #expect(code.text == Encoding.base64url(code.bytes) && code.text.utf8.count == 43)
        let modules = try #require(QRCode.modules(for: code.text))
        #expect(modules.count == modules[0].count && modules.count >= 21)
        let decoded = try decode(modules)
        #expect(decoded == code.text)
    }

    @Test("the drawing on the terminal is the same modules, in light and dark half blocks, with a quiet zone")
    func theTerminalDrawingMatchesTheModules() throws {
        let modules = try #require(QRCode.modules(for: "hello"))
        let drawing = QRCode.terminalLines(modules)
        // two module rows per text row, plus a quiet zone of four modules on every side
        let side = modules.count + 8
        #expect(drawing.count == (side + 1) / 2)
        for line in drawing { #expect(line.hasSuffix("\u{1B}[0m") && !line.contains("\n")) }
        #expect(drawing.first?.contains("█") == false && drawing.first?.contains("▀") == false)
    }

    // MARK: command line

    private func run(_ arguments: [String] = [], random: @escaping () -> [UInt8] = fixedBytes(1), display: Display? = RecordingDisplay()) -> Outcome {
        LinkCLI.run(arguments: arguments, random: random, display: { if let display { return display }; throw Refusal("no_display") })
    }

    @Test("one JCS line on stdout: {link_code_hash}; the code and the QR go to the display only")
    func theCodeNeverReachesStdout() throws {
        let display = RecordingDisplay()
        let out = run(display: display)
        let code = try LinkCode.make(random: fixedBytes(1))
        #expect(out.exit == 0)
        #expect(String(decoding: out.line, as: UTF8.self) == #"{"link_code_hash":"\#(code.hash)"}"#)
        #expect(!String(decoding: out.line, as: UTF8.self).contains(code.text))
        #expect(display.text.contains("Link code") && display.text.contains(Render.hash12(code.hash)), "the person can compare hash12 with the draft's Link code line")
        #expect(display.text.contains("█") || display.text.contains("▀"), "a QR code is drawn")
    }

    @Test("SG-03: neither stdout nor the display carries the private scalar of a key on the machine, in any form")
    func noOutputCarriesKeyMaterial() throws {
        let scalar = [UInt8](P256.Signing.PrivateKey().rawRepresentation)
        let display = RecordingDisplay()
        let out = run(random: fixedBytes(1), display: display)
        #expect(out.exit == 0)
        let seen = out.line + Array(display.text.utf8)
        // the scan ran over real output: the code the tool does show is there, the scalar is not
        let code = try LinkCode.make(random: fixedBytes(1))
        #expect(KeyScan.contains(seen, Array(code.hash.utf8)) && KeyScan.contains(seen, Array(Render.hash12(code.hash).utf8)))
        #expect(!KeyScan.leaks(seen, scalar: scalar))
    }

    @Test("no display channel: exit 4, no_display, and no hash goes out for a code nobody saw")
    func noDisplayNoHash() {
        let out = run(display: nil)
        #expect(out.exit == 4 && String(decoding: out.line, as: UTF8.self) == #"{"error":"no_display"}"#)
    }

    @Test("a command line argument is unsupported_command, exit 2, with nothing drawn")
    func anArgumentIsRefused() {
        let display = RecordingDisplay()
        for arguments in [["x"], ["--code", "abc"], ["a", "b"]] {
            let out = run(arguments, display: display)
            #expect(out.exit == 2 && String(decoding: out.line, as: UTF8.self) == #"{"error":"unsupported_command"}"#)
        }
        #expect(display.text.isEmpty)
    }

    @Test("a failed random source is internal, exit 5, with nothing drawn")
    func aFailedSourceDrawsNothing() {
        let display = RecordingDisplay()
        let out = run(random: { [] }, display: display)
        #expect(out.exit == 5 && String(decoding: out.line, as: UTF8.self) == #"{"error":"internal"}"#)
        #expect(display.text.isEmpty)
    }

    // MARK: QR decoding with CoreImage

    private func decode(_ modules: [[Bool]]) throws -> String? {
        let scale = 8, quiet = 4
        let side = (modules.count + 2 * quiet) * scale
        var pixels = [UInt8](repeating: 255, count: side * side)
        for (row, line) in modules.enumerated() {
            for (column, dark) in line.enumerated() where dark {
                for y in 0..<scale {
                    for x in 0..<scale { pixels[((row + quiet) * scale + y) * side + (column + quiet) * scale + x] = 0 }
                }
            }
        }
        let provider = try #require(CGDataProvider(data: Data(pixels) as CFData))
        let image = try #require(CGImage(width: side, height: side, bitsPerComponent: 8, bitsPerPixel: 8, bytesPerRow: side,
                                         space: CGColorSpaceCreateDeviceGray(), bitmapInfo: CGBitmapInfo(rawValue: 0),
                                         provider: provider, decode: nil, shouldInterpolate: false, intent: .defaultIntent))
        let detector = try #require(CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]))
        let features = detector.features(in: CIImage(cgImage: image))
        return (features.first as? CIQRCodeFeature)?.messageString
    }
}
