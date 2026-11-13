import Foundation
import HandsalCore
import Testing

/// The shipped binary, started as a process. `CLITests` cover the logic; these cover the plumbing
/// in `main.swift`: exit status, one stdout line, nothing on stderr.
@Suite("handsal-sign process")
struct ProcessTests {
    static func binary(_ name: String) -> URL { Vector.root.appendingPathComponent("signer/apple/.build/debug/" + name) }

    struct Result { let status: Int32; let out: [UInt8]; let err: [UInt8] }

    static func run(_ args: [String], stdin: [UInt8] = [], binary name: String = "handsal-sign") throws -> Result {
        let process = Process()
        process.executableURL = binary(name)
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
        #expect(String(decoding: r.out, as: UTF8.self) == #"{"error":"unsupported_command"}"# + "\n")
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

/// CF-04: the conformance executable is a different file with a different entry point. These tests
/// start it as the harness does and check that neither executable carries the other's code.
@Suite("handsal-sign-conformance process")
struct ConformanceProcessTests {
    static let conformance = "handsal-sign-conformance"

    @Test func renderReadsTheCheckerFormAndExitsZero() throws {
        let row = try #require(try Vector.load(commands: ["render"]).first { $0.name == "rnd/approve" })
        let r = try ProcessTests.run(["render"], stdin: VectorAdapter.stdin(row), binary: Self.conformance)
        #expect(r.status == 0 && r.err.isEmpty)
        #expect(String(decoding: r.out, as: UTF8.self) == row.anchor + "\n")
    }

    @Test func aRefusedRenderIsStillExitZeroAndOneLine() throws {
        let r = try ProcessTests.run(["render"], stdin: Array(#"{"a":1,"a":2}"#.utf8), binary: Self.conformance)
        #expect(r.status == 0 && r.err.isEmpty)
        #expect(String(decoding: r.out, as: UTF8.self) == #"{"error":"unparseable_input"}"# + "\n")
    }

    @Test func everythingButRenderAndEmitIsUnsupportedCommandExitTwo() throws {
        for args in [["version"], ["keygen"], ["sign"], [], ["render", "emit"]] {
            let r = try ProcessTests.run(args, binary: Self.conformance)
            #expect(r.status == 2 && r.err.isEmpty, "\(args)")
            #expect(String(decoding: r.out, as: UTF8.self) == #"{"error":"unsupported_command"}"# + "\n", "\(args)")
        }
    }

    @Test func emitIsTheShippedEmitAsAProcess() throws {
        let draft = #"{"body":{"kid":"NAjtfK8uPx9mTY3cWuF1yDIJ4DUhiXDyS8-_7hYNraY","person":"carol"},"method":"local:handsal.device.remove","org":"\#(Encoding.emptyHash)","parent":{"id":"\#(Encoding.emptyHash)","performer":"bob"}}"#
        let input = #"{"attachments":{},"draft":\#(draft),"fixed":{"kid":"E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI","nonce":"\#(Encoding.emptyHash)","performer":"alice","ts":"2026-11-08T11:59:00Z"}}"#
        let shipped = try ProcessTests.run(["emit"], stdin: Array(input.utf8))
        let other = try ProcessTests.run(["emit"], stdin: Array(input.utf8), binary: Self.conformance)
        #expect(shipped.status == 0 && other.status == shipped.status && other.out == shipped.out)
        let bad = try ProcessTests.run(["emit"], stdin: Array("{}".utf8), binary: Self.conformance)
        #expect(bad.status == 2 && String(decoding: bad.out, as: UTF8.self) == #"{"error":"schema_refused"}"# + "\n")
    }

    private func contains(_ file: String, _ needle: String) throws -> Bool {
        let data = try Data(contentsOf: ProcessTests.binary(file))
        return data.range(of: Data(needle.utf8)) != nil
    }

    /// The build is picked by the file that was started: the shipped signer has no path to the
    /// conformance code, and the conformance executable has no path to a key backend.
    @Test func neitherExecutableCarriesTheOthersCode() throws {
        #expect(try contains(Self.conformance, "HandsalConformance"))
        #expect(try !contains("handsal-sign", "HandsalConformance"))
        #expect(try !contains("handsal-sign", "IJSON"))
        #expect(try !contains("handsal-sign", "ConformanceCLI"))
        #expect(try !contains(Self.conformance, "SecureEnclave"))
        #expect(try !contains(Self.conformance, "LocalAuthentication"))
    }
}
