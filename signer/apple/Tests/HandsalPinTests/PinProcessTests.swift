import Foundation
import Testing

/// The installed helper, started as a process. `PinHelperTests` cover the logic; these cover the
/// plumbing in `main.swift` and the rule that nothing but its stdin and the SG-14 paths reaches
/// it. Only inputs that fail before step 0 are used: no run here can touch the real pin directory.
@Suite("handsal-pin process (GP-12, GP-14)")
struct PinProcessTests {
    private static var binary: URL {
        // <repo>/signer/apple/Tests/HandsalPinTests/PinProcessTests.swift
        let apple = (0..<3).reduce(#filePath) { path, _ in (path as NSString).deletingLastPathComponent }
        return URL(fileURLWithPath: apple + "/.build/debug/handsal-pin")
    }

    private struct Result { let status: Int32; let out: String; let err: Data }

    private func run(_ arguments: [String], stdin: String, environment: [String: String] = [:]) throws -> Result {
        let process = Process()
        process.executableURL = Self.binary
        process.arguments = arguments
        process.environment = environment
        let input = Pipe(), output = Pipe(), error = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = error
        try process.run()
        input.fileHandleForWriting.write(Data(stdin.utf8))
        try input.fileHandleForWriting.close()
        let out = output.fileHandleForReading.readDataToEndOfFile()
        let err = error.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return Result(status: process.terminationStatus, out: String(decoding: out, as: UTF8.self), err: err)
    }

    @Test("an argument is one report line, malformed_input, exit 2, nothing on stderr")
    func anArgumentIsMalformedInput() throws {
        let r = try run(["--root", "/tmp"], stdin: #"{"acts":[],"lineage":[]}"# + "\n")
        #expect(r.status == 2 && r.err.isEmpty)
        #expect(r.out == #"{"inner_reason":null,"reason":"malformed_input","written":"no"}"# + "\n")
    }

    @Test("input the recognizer refuses is unparseable_input, exit 2")
    func badFramingIsUnparseable() throws {
        for input in ["", "{}", #"{"acts":[],"lineage":[]}"#, #"{"acts":[],"acts":[],"lineage":[]}"# + "\n"] {
            let r = try run([], stdin: input)
            #expect(r.status == 2 && r.out == #"{"inner_reason":null,"reason":"unparseable_input","written":"no"}"# + "\n", "\(input)")
        }
    }

    @Test("a third key is malformed_input, exit 2")
    func aThirdKeyIsMalformed() throws {
        let r = try run([], stdin: #"{"acts":[],"lineage":[],"pin_line":"x"}"# + "\n")
        #expect(r.status == 2 && r.out == #"{"inner_reason":null,"reason":"malformed_input","written":"no"}"# + "\n")
    }

    @Test("an environment variable names neither a root nor a checker: the answer is the same with and without")
    func theEnvironmentReachesNothing() throws {
        let input = #"{"acts":[],"lineage":[],"pin_line":"x"}"# + "\n"
        let plain = try run([], stdin: input)
        let loud = try run([], stdin: input, environment: [
            "HANDSAL_PIN_ROOT": "/tmp", "HANDSAL_CHECKER": "/bin/true", "HANDSAL_ROOT": "/tmp", "PATH": "/tmp", "ROOT": "/tmp", "HOME": "/tmp",
        ])
        #expect(plain.out == loud.out && plain.status == loud.status)
    }

    @Test("the binary holds no test seam: no conformance reader, no software backend, no stub")
    func theInstalledBinaryHoldsNoTestSeam() throws {
        let data = try Data(contentsOf: Self.binary)
        for needle in ["HandsalConformance", "SoftwareBackend", "RecordingDisplay", "handsal-check-conformance", "handsal-sign-conformance"] {
            #expect(data.range(of: Data(needle.utf8)) == nil, "\(needle)")
        }
        #expect(data.range(of: Data("/Library/Application Support/handsal/bin/handsal-check".utf8)) != nil, "the SG-14 checker path is in it")
    }
}
