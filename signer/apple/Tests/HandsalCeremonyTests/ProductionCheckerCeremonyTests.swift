import Foundation
import HandsalCore
import Testing
@testable import HandsalCeremonyCore

/// The ceremony against the real production command table of the checker, not a scripted one.
///
/// Every other ceremony test answers the checker from a queue, which is a model of a checker that holds no
/// machine state. The production checker is not that: some of its commands read this machine's pin, store and
/// clock. This suite runs the Python production table over an empty temporary root (no pin, no store), the
/// state of a Mac that has never enrolled, so a step before the pin write that depends on the machine fails
/// here the way it fails on that Mac. The verifier is the checker tests' fake one and the profile set has no
/// fixture kid, as in the checker's own production tests, so the lineages are built by the checker's builders.
@Suite("enrollment ceremony over the production checker (SG-12 steps 3 to 8)")
struct ProductionCheckerCeremonyTests {
    private static var repository: String {
        // <repo>/signer/apple/Tests/HandsalCeremonyTests/ProductionCheckerCeremonyTests.swift
        (0..<5).reduce(#filePath) { path, _ in (path as NSString).deletingLastPathComponent }
    }

    private static let script = """
    import io, json, os, sys
    repository, mode, root = sys.argv[1:4]
    sys.path.insert(0, repository + "/checker/python/src")
    sys.path.insert(0, repository + "/checker/python")
    from handsal_check import core, emit, genesis, production
    from handsal_check.probe_posix import PosixProbe
    from handsal_check.store_posix import PosixStore
    from tests.act_builder import FakeVitni, kid_of
    from tests.checkact_world import NOW
    from tests.genesis_fixtures import change, policy
    from tests.profile_sets import production_of
    from tests.test_enrolled import FIXTURE, PRODUCTION_ONLY, production_world

    if mode == "serve":
        table = production.build_commands(FakeVitni(), PosixProbe(root=root, owner_uid=os.getuid()), lambda: NOW,
                                          PosixStore(root=root, uid=os.getuid()), load_profiles=lambda: PRODUCTION_ONLY)
        sys.exit(core.run(table, [sys.argv[4]], sys.stdin.buffer, sys.stdout.buffer))

    people = ("alice", "bob", "carol")
    world = production_world()
    lineage = [{"doc": world.doc, "sigs": world.sigs(world.doc, people)}]
    if mode == "change":
        doc = change(production_of(FIXTURE), world.id, genesis.doc_hash(world.doc), world.id, people=people,
                     pol=policy(), name="NEXT")
        lineage.append({"doc": doc, "sigs": world.sigs(doc, people)})
    line = emit.emit_result({"acts": [], "device_kid": kid_of("alice"), "lineage": lineage})
    sys.stdout.write(production_of(FIXTURE) + "\\n" + line.decode("utf-8") + "\\n")
    """

    private struct Setup {
        let root: URL
        let checker: ProductionChecker
        let profiles: Profiles
        let input: [UInt8]
    }

    private static func uv() -> String? {
        let path = (ProcessInfo.processInfo.environment["PATH"] ?? "").split(separator: ":").map(String.init) + ["/opt/homebrew/bin", "/usr/local/bin"]
        return path.map { $0 + "/uv" }.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    private static func python(_ arguments: [String], uv: String) throws -> [UInt8] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["-u", "VIRTUAL_ENV", uv, "run", "--no-project", "python", "-I", "-c", script, repository] + arguments
        let out = Pipe()
        process.standardOutput = out
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw Refusal("internal") }
        return [UInt8](data)
    }

    /// An empty root, the checker as a program over it, and the ceremony input of `mode` (`original` or `change`).
    private static func setup(_ mode: String) throws -> Setup {
        let uv = try #require(Self.uv(), "uv is needed to run the checker")
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("handsal-ceremony-" + UUID().uuidString)
        let root = directory.appendingPathComponent("root")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        // The ceremony starts the checker with an empty environment, so the wrapper carries what uv needs.
        let wrapper = directory.appendingPathComponent("handsal-check")
        let source = directory.appendingPathComponent("serve.py")
        try Self.script.write(to: source, atomically: true, encoding: .utf8)
        let text = "#!/bin/sh\nexport HOME='\(NSHomeDirectory())' PATH='/usr/bin:/bin:\((uv as NSString).deletingLastPathComponent)'\n"
            + "exec '\(uv)' run --no-project python -I '\(source.path)' '\(Self.repository)' serve '\(root.path)' \"$1\"\n"
        try text.write(to: wrapper, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: wrapper.path)
        let lines = String(decoding: try Self.python([mode, root.path], uv: uv), as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: true)
        try #require(lines.count == 2)
        let production = String(lines[0])
        let profiles = Profiles(editions: [Edition(label: "current", production: production, fixture: hash("an unused fixture profile"), fixtureKids: [], registry: .standard)])
        return Setup(root: root, checker: ProductionChecker(executable: wrapper.path), profiles: profiles, input: Array(String(lines[1]).utf8) + [0x0A])
    }

    private func ceremony(_ mode: String) throws -> (result: CeremonyResult, shown: String, question: [String]) {
        let setup = try Self.setup(mode)
        defer { try? FileManager.default.removeItem(at: setup.root.deletingLastPathComponent()) }
        let console = FakeConsole(answers: [false])
        let helper = FakeHelper()
        let result = Ceremony(checker: setup.checker, helper: helper, console: console, context: GenesisContext(profiles: setup.profiles))
            .run(arguments: [], stdin: setup.input)
        #expect(helper.lines.isEmpty, "nothing was handed to the pin helper")
        return (result, console.shown, console.questions)
    }

    @Test("sgn/ceremony-aids-without-pin: an original on a machine with no pin reaches the hash12 question")
    func anOriginalWithNoPinReachesTheQuestion() throws {
        let run = try ceremony("original")
        #expect(run.result == CeremonyResult(reason: "not_confirmed", written: "no", exit: 1), "got \(text(run.result))")
        #expect(run.question.count == 1)
    }

    @Test("sgn/ceremony-aids-without-pin: a change on a machine with no pin shows the head line and reaches the question")
    func aChangeWithNoPinShowsTheHeadLineAndReachesTheQuestion() throws {
        let run = try ceremony("change")
        #expect(run.result == CeremonyResult(reason: "not_confirmed", written: "no", exit: 1), "got \(text(run.result))")
        #expect(run.shown.contains("H is the tip"), "the head line is on the screen")
        #expect(run.question.count == 1)
    }
}
