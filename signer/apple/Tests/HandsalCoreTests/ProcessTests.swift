import Foundation
import HandsalCore
import Testing

/// The shipped binary, started as a process. `CLITests` cover the logic; these cover the plumbing
/// in `main.swift`: exit status, one stdout line, nothing on stderr.
@Suite("handsal-sign process")
struct ProcessTests {
    static let binary = Vector.root.appendingPathComponent("signer/apple/.build/debug/handsal-sign")

    struct Result { let status: Int32; let out: [UInt8]; let err: [UInt8] }

    static func run(_ args: [String], stdin: [UInt8] = []) throws -> Result {
        let process = Process()
        process.executableURL = binary
        process.arguments = args
        let input = Pipe(), output = Pipe(), error = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = error
        try process.run()
        input.fileHandleForWriting.write(Data(stdin))
        try input.fileHandleForWriting.close()
        let out = output.fileHandleForReading.readDataToEndOfFile()
        let err = error.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return Result(status: process.terminationStatus, out: [UInt8](out), err: [UInt8](err))
    }

    @Test func versionIsOneLineAndExitZero() throws {
        let r = try Self.run(["version"])
        #expect(r.status == 0 && r.err.isEmpty)
        #expect(String(decoding: r.out, as: UTF8.self) == #"{"class":"apple-se-bio","impl":"handsal-sign-swift","spec":"\#(Profiles.standard.production)"}"# + "\n")
    }

    @Test func unknownCommandIsExitTwoWithOneErrorLine() throws {
        let r = try Self.run(["info"])
        #expect(r.status == 2 && r.err.isEmpty)
        #expect(String(decoding: r.out, as: UTF8.self) == #"{"error":"unsupported_method"}"# + "\n")
    }

    @Test func noArgumentsIsExitTwo() throws {
        #expect(try Self.run([]).status == 2)
    }

    @Test func emitReadsStdinAndWritesOnlyTheResult() throws {
        let kid = "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI"
        let draft = #"{"body":{"kid":"NAjtfK8uPx9mTY3cWuF1yDIJ4DUhiXDyS8-_7hYNraY","person":"carol"},"method":"local:handsal.device.remove","org":"\#(Encoding.emptyHash)","parent":{"id":"\#(Encoding.emptyHash)","performer":"bob"}}"#
        let input = #"{"attachments":{},"draft":\#(draft),"fixed":{"kid":"\#(kid)","nonce":"\#(Encoding.emptyHash)","performer":"alice","ts":"2026-11-08T11:59:00Z"}}"# + "\n"
        let r = try Self.run(["emit"], stdin: Array(input.utf8))
        #expect(r.status == 0 && r.err.isEmpty)
        let text = String(decoding: r.out, as: UTF8.self)
        #expect(text.hasPrefix(#"{"payload_hex":""#) && text.hasSuffix("\"}\n") && text.filter { $0 == "\n" }.count == 1)
    }

    @Test func badStdinIsExitTwo() throws {
        let r = try Self.run(["emit"], stdin: Array("{ }\n".utf8))
        #expect(r.status == 2 && String(decoding: r.out, as: UTF8.self) == #"{"error":"schema_refused"}"# + "\n")
    }
}
