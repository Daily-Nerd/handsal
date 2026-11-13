import Darwin
import Foundation
import HandsalCore
import Testing
@testable import HandsalPinCore

private let org = PinRig.hashstr("org")

/// The reader is the Python probe of the checker (GP-10, GP-14), an independent implementation of
/// the same rule. The helper's output is judged by it, not by a copy of its checks written in
/// Swift: `sgn/pin-helper-written-file-passes-probe`.
@Suite("the written pin passes the platform probe (GP-21 S3)")
struct PinProbeTests {
    private static var repository: String {
        // <repo>/signer/apple/Tests/HandsalPinTests/PinProbeTests.swift
        (0..<5).reduce(#filePath) { path, _ in (path as NSString).deletingLastPathComponent }
    }

    private static let script = """
    import json, sys
    sys.path.insert(0, sys.argv[1])
    from handsal_check import probe_posix
    probe = probe_posix.PosixProbe(root=sys.argv[2], owner_uid=int(sys.argv[3])).read(sys.argv[4])
    print(json.dumps({"owner_ok": probe.owner_ok, "reason": probe.reason, "raw": probe.raw.decode("ascii")}))
    """

    /// The probe object for `org` under the virtual root `root`, treating `uid` as the administrator.
    private func probe(root: String, uid: uid_t, org: String) throws -> [String: Any] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["-u", "VIRTUAL_ENV", "uv", "run", "--no-project", "python", "-I", "-c", Self.script,
                             Self.repository + "/checker/python/src", root, String(uid), org]
        let out = Pipe()
        process.standardOutput = out
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        #expect(process.terminationStatus == 0, "the probe ran")
        return (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
    }

    @Test("sgn/pin-helper-written-file-passes-probe: the probe reports owner_ok:true and the bytes the checker returned")
    func theWrittenFilePassesTheProbe() throws {
        let rig = try PinRig(withHandsalDirectory: false)   // the helper made every directory the probe walks
        let pin = PinRig.pin(org: org, genesis: PinRig.documentHash(named: "a"))
        let helper = try rig.helper(answering: PinRig.validAnswer(pin: pin))
        #expect(helper.run(arguments: [], stdin: PinRig.request(names: ["a"])).reason == .ok)
        let result = try probe(root: rig.root, uid: getuid(), org: org)
        #expect(result["owner_ok"] as? Bool == true && result["reason"] as? String == "ok")
        #expect(result["raw"] as? String == pin)
    }

    @Test("an extension over an existing pin passes the probe too")
    func anExtensionPassesTheProbe() throws {
        let rig = try PinRig()
        try rig.place(PinRig.pin(org: org, genesis: PinRig.documentHash(named: "a")), org: org)
        let next = PinRig.pin(org: org, genesis: PinRig.documentHash(named: "b"))
        #expect(try rig.helper(answering: PinRig.validAnswer(pin: next)).run(arguments: [], stdin: PinRig.request(names: ["a", "b"])).reason == .ok)
        let result = try probe(root: rig.root, uid: getuid(), org: org)
        #expect(result["owner_ok"] as? Bool == true && result["raw"] as? String == next)
    }

    @Test("the probe is a real judge: a pin the helper did not write with these attributes fails it")
    func theProbeRejectsWhatTheReaderRejects() throws {
        let rig = try PinRig()
        try rig.place(PinRig.pin(org: org, genesis: PinRig.documentHash(named: "a")), org: org, mode: 0o664)
        let result = try probe(root: rig.root, uid: getuid(), org: org)
        #expect(result["owner_ok"] as? Bool == false && result["reason"] as? String == "pin_owner")
    }
}
