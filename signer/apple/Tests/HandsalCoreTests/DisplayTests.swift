import Foundation
import HandsalCore
import Testing

/// SG-07: the display channel is the controlling terminal; no channel is `no_display`.
@Suite("display channel (SG-07)")
struct DisplayTests {
    private func tempFile() -> String { NSTemporaryDirectory() + "handsal-display-\(UUID().uuidString).txt" }

    @Test func writesExactlyWhatItIsShownToItsPath() throws {
        let path = tempFile()
        FileManager.default.createFile(atPath: path, contents: nil)
        let display = try TTYDisplay.open(path: path)
        try display.show("line one\n")
        try display.show("Signing as alice with E5ua-1p9O-mQf5\n")
        #expect(try String(contentsOfFile: path, encoding: .utf8) == "line one\nSigning as alice with E5ua-1p9O-mQf5\n")
    }

    @Test func aChannelThatCannotBeOpenedIsNoDisplay() {
        #expect(throws: Refusal("no_display")) { try TTYDisplay.open(path: "/nonexistent-directory/tty") }
        #expect(throws: Refusal("no_display")) { try TTYDisplay.open(path: "") }
    }

    @Test func theLiveChannelIsDevTtyAndAFailureIsNoDisplay() {
        #expect(TTYDisplay.standardPath == "/dev/tty")
        // Under a test run without a controlling terminal this is the no-display case; with one it opens.
        do { _ = try TTYDisplay.open(path: TTYDisplay.standardPath) } catch let refusal as Refusal { #expect(refusal == Refusal("no_display")) } catch { Issue.record("\(error)") }
    }

    @Test func aDirectoryIsNotADisplay() {
        #expect(throws: Refusal("no_display")) { try TTYDisplay.open(path: NSTemporaryDirectory()) }
    }
}
