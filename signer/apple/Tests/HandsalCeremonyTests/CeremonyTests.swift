import Foundation
import HandsalCore
import Testing
@testable import HandsalCeremonyCore

private let fixtureKid = "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI"

/// One ceremony run against scripted parts. `lineage` is the bag the person collected.
private struct Run {
    let checker: FakeChecker
    let console: FakeConsole
    let helper: FakeHelper
    let result: CeremonyResult
}

private func run(_ lineage: [(doc: JValue, sigs: [String])], acts: [String] = [], checker answers: [String: [JValue]],
                 confirm: [Bool] = [true], helper: FakeHelper = FakeHelper(), arguments: [String] = []) -> Run {
    let checker = FakeChecker(answers), console = FakeConsole(answers: confirm)
    let result = Ceremony(checker: checker, helper: helper, console: console)
        .run(arguments: arguments, stdin: ceremonyInput(lineage: lineage, acts: acts))
    return Run(checker: checker, console: console, helper: helper, result: result)
}

/// The answers of a ceremony that goes through: the checker accepts the lineage and returns the pin
/// of its last document, the helper reports `ok`, `enrolled` says yes.
private func goingThrough(_ lineage: [(doc: JValue, sigs: [String])]) -> [String: [JValue]] {
    let last = lineage[lineage.count - 1].doc
    let pin = pinLine(genesis: docHash(last), org: docHash(lineage[0].doc))
    return ["genesis-check": [checkAnswer(pin: pin)], "enrolled": [enrolledYes]]
}

@Suite("enrollment ceremony (SG-12, GP-12, SG-14)")
struct CeremonyTests {
    // MARK: the sequence

    @Test("an original goes through every step in order and ends with enrolled as the judge")
    func anOriginalGoesThrough() {
        var docs = Docs()
        let original = docs.document()
        let lineage = [(doc: original, sigs: ["sig-1"])]
        let r = run(lineage, acts: ["act-1"], checker: goingThrough(lineage))
        #expect(r.result == CeremonyResult(reason: "ok", written: "yes", exit: 0))
        #expect(text(r.result) == #"{"reason":"ok","written":"yes"}"#)
        #expect(r.checker.commands() == ["genesis-check", "enrolled"])
        #expect(r.helper.lines.count == 1)
        // genesis-check gets the lineage and the bag; enrolled gets the org of the first document and no pin, no clock
        guard case .object(let check)? = r.checker.inputs("genesis-check").first, case .object(let enrolled)? = r.checker.inputs("enrolled").first else {
            Issue.record("inputs missing"); return
        }
        #expect(Set(check.keys) == ["acts", "lineage"])
        #expect(Set(enrolled.keys) == ["acts", "device_kid", "lineage", "org", "synced_at", "tip_statement"])
        #expect(enrolled["org"] == str(docHash(original)))
        #expect(r.console.questions.count == 1)
    }

    @Test("the render of the document is shown in full, with the witness lines of the policy")
    func theRenderIsShown() throws {
        var docs = Docs()
        docs.witness = relayWitness()
        let original = docs.document()
        let lineage = [(doc: original, sigs: [String]())]
        let r = run(lineage, checker: goingThrough(lineage))
        let shown = try Render.genesisText(document: original, previous: nil)
        for line in [shown.firstLine] + shown.lines { #expect(r.console.shown.contains(line), "\(line)") }
        #expect(r.console.shown.contains("relay"), "the witness policy is on the screen")
    }

    @Test("sgn/ceremony-shows-pin-hash12: hash12 of the pinned genesis is shown and equals line 1 of the genesis.sign prompt")
    func thePinHash12IsShown() throws {
        var docs = Docs()
        let original = docs.document()
        let lineage = [(doc: original, sigs: [String]())]
        let r = run(lineage, checker: goingThrough(lineage))
        let expected = Render.hash12(docHash(original))
        #expect(r.console.shown.contains(expected))
        #expect(try Render.genesisText(document: original, previous: nil).firstLine.contains(expected), "the prompt line carries the same hash12")
        #expect(r.console.questions.first?.contains(expected) == true, "the question names it")
        // the exact pin line is on screen too
        #expect(r.console.shown.contains(pinLine(genesis: docHash(original), org: docHash(original)).dropLast()))
    }

    @Test("a person who does not confirm the hash12 stops the ceremony before the helper")
    func noConfirmationNoWrite() {
        var docs = Docs()
        let lineage = [(doc: docs.document(), sigs: [String]())]
        let r = run(lineage, checker: goingThrough(lineage), confirm: [false])
        #expect(r.result == CeremonyResult(reason: "not_confirmed", written: "no", exit: 1))
        #expect(r.helper.lines.isEmpty && r.checker.commands() == ["genesis-check"])
    }

    @Test("persons holding a single device are flagged, and a person with two are not")
    func singleDevicePersonsAreFlagged() {
        var one = Docs()
        let single = [(doc: one.document(), sigs: [String]())]
        let shown = run(single, checker: goingThrough(single)).console.shown
        for person in ["alice", "bob", "carol"] { #expect(shown.contains("\(person) holds a single device")) }
        var two = Docs()
        two.devicesPerPerson = 2
        let many = [(doc: two.document(), sigs: [String]())]
        #expect(!run(many, checker: goingThrough(many)).console.shown.contains("single device"))
        var mixed = Docs()
        let first = mixed.document()
        mixed.keys["bob"]?.append(Persons.key())
        let both = [(doc: mixed.document(), sigs: [String]())]
        _ = first
        let flags = run(both, checker: goingThrough(both)).console.shown
        #expect(flags.contains("alice holds a single device") && !flags.contains("bob holds a single device"))
    }

    // MARK: refusals before any write

    @Test("sgn/ceremony-refuses-fix-profile: a fixture profile is refused before anything runs")
    func aFixtureProfileIsRefused() {
        var docs = Docs()
        docs.profile = Profiles.standard.fixture
        let lineage = [(doc: docs.document(), sigs: [String]())]
        let r = run(lineage, checker: goingThrough(lineage))
        #expect(r.result == CeremonyResult(reason: "fixture_profile", written: "no", exit: 1))
        #expect(r.checker.calls.isEmpty && r.helper.lines.isEmpty && r.console.questions.isEmpty)
    }

    @Test("sgn/ceremony-refuses-fixture-kid: a fixture kid, in a device or as the relay key, is refused before anything runs")
    func aFixtureKidIsRefused() {
        var docs = Docs()
        var doc = docs.document()
        guard case .object(var members) = doc, case .array(var devices)? = members["devices"], case .object(var device) = devices[0] else { Issue.record("shape"); return }
        device["kid"] = str(fixtureKid)
        devices[0] = .object(device)
        members["devices"] = .array(devices)
        doc = .object(members)
        let viaDevice = run([(doc: doc, sigs: [String]())], checker: goingThrough([(doc: doc, sigs: [String]())]))
        #expect(viaDevice.result == CeremonyResult(reason: "fixture_key", written: "no", exit: 1))
        #expect(viaDevice.checker.calls.isEmpty && viaDevice.helper.lines.isEmpty)

        var relay = Docs()
        relay.witness = .object(["max_tip_age_s": str("3600"), "mode": str("relay"), "relay_kid": str(fixtureKid)])
        let relayDoc = relay.document()
        let viaRelay = run([(doc: relayDoc, sigs: [String]())], checker: goingThrough([(doc: relayDoc, sigs: [String]())]))
        #expect(viaRelay.result == CeremonyResult(reason: "fixture_key", written: "no", exit: 1))
        #expect(viaRelay.checker.calls.isEmpty && viaRelay.helper.lines.isEmpty)
    }

    @Test("sgn/ceremony-refuses-two-person-org: a policy without a spare person is policy_unreachable, before confirmation")
    func aTwoPersonOrganizationIsRefused() {
        var docs = Docs()
        docs.names = ["alice", "bob"]
        let lineage = [(doc: docs.document(), sigs: [String]())]
        let r = run(lineage, checker: goingThrough(lineage))
        #expect(r.result == CeremonyResult(reason: "policy_unreachable", written: "no", exit: 1))
        #expect(r.console.questions.isEmpty && r.helper.lines.isEmpty)
    }

    @Test("a lineage the checker does not accept stops the ceremony with the checker's reason, nothing written")
    func aRefusedLineageStops() {
        var docs = Docs()
        let lineage = [(doc: docs.document(), sigs: [String]())]
        let checker: [String: [JValue]] = ["genesis-check": [.object(["pin": .null, "reason": str("genesis_unsigned"), "valid": .bool(false)])]]
        let r = run(lineage, checker: checker)
        #expect(r.result == CeremonyResult(reason: "genesis_unsigned", written: "no", exit: 1))
        #expect(r.helper.lines.isEmpty && r.console.questions.isEmpty)
        let error = run(lineage, checker: ["genesis-check": [.object(["error": str("verifier_unavailable")])]])
        #expect(error.result == CeremonyResult(reason: "verifier_unavailable", written: "no", exit: 1))
        let missing = run(lineage, checker: [:])
        #expect(missing.result == CeremonyResult(reason: "internal", written: "no", exit: 1))
    }

    @Test("input that is not one {acts, device_kid, lineage, synced_at, tip_statement} line is refused: usage, no step runs")
    func badInputIsRefused() {
        let checker = FakeChecker(), console = FakeConsole(), helper = FakeHelper()
        let ceremony = Ceremony(checker: checker, helper: helper, console: console)
        #expect(ceremony.run(arguments: ["--yes"], stdin: []) == CeremonyResult(reason: "malformed_input", written: "no", exit: 2))
        #expect(ceremony.run(arguments: [], stdin: []) == CeremonyResult(reason: "unparseable_input", written: "no", exit: 2))
        #expect(ceremony.run(arguments: [], stdin: Array("{}\n".utf8)) == CeremonyResult(reason: "malformed_input", written: "no", exit: 2))
        #expect(ceremony.run(arguments: [], stdin: Array(#"{"acts":[],"lineage":[]}"#.utf8) + [0x0A]) == CeremonyResult(reason: "malformed_input", written: "no", exit: 2))
        var docs = Docs()
        let empty = ceremonyInput(lineage: [])
        #expect(ceremony.run(arguments: [], stdin: empty).reason == "malformed_input")
        #expect(ceremony.run(arguments: [], stdin: ceremonyInput(lineage: [(doc: docs.document(), sigs: [String]())]) + [0x0A]).reason == "unparseable_input")
        #expect(checker.calls.isEmpty && helper.lines.isEmpty && console.questions.isEmpty)
    }

    // MARK: the pin helper

    @Test("sgn/ceremony-sudo-k-command: the helper gets exactly the {acts, lineage} line, once, and nothing else")
    func theHelperIsGivenTheLineageOnce() throws {
        var docs = Docs()
        let lineage = [(doc: docs.document(), sigs: ["sig-1", "sig-2"])]
        let r = run(lineage, acts: ["act-1", "act-2"], checker: goingThrough(lineage))
        #expect(r.helper.lines.count == 1)
        let want = try Emit.subset(.object(["acts": .array([str("act-1"), str("act-2")]),
                                            "lineage": .array([.object(["doc": lineage[0].doc, "sigs": .array([str("sig-1"), str("sig-2")])])])])) + [0x0A]
        #expect(r.helper.lines[0] == want)
    }

    @Test("sgn/ceremony-sudo-absolute and -k: the channel is /usr/bin/sudo -k <helper>, no PATH lookup, empty environment")
    func theChannelIsSudoMinusKAtTheFixedPaths() {
        let channel = SudoChannel.installed
        #expect(channel.sudo == "/usr/bin/sudo")
        #expect(channel.helper == "/Library/Application Support/handsal/bin/handsal-pin")
        let process = channel.makeProcess()
        #expect(process.executableURL?.path == "/usr/bin/sudo")
        #expect(process.arguments == ["-k", "/Library/Application Support/handsal/bin/handsal-pin"], "one invocation, no other argument")
        #expect(process.environment == [:], "nothing the caller exported reaches sudo")
    }

    @Test("a fake sudo first on PATH is not used: the process is started from the absolute path")
    func aFakeSudoOnPathIsNotUsed() throws {
        let directory = NSTemporaryDirectory() + "fake-sudo-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let marker = directory + "/ran"
        try "#!/bin/sh\ntouch '\(marker)'\n".write(toFile: directory + "/sudo", atomically: true, encoding: .utf8)
        chmod(directory + "/sudo", 0o755)
        let old = String(cString: getenv("PATH"))
        setenv("PATH", directory + ":" + old, 1)
        defer { setenv("PATH", old, 1) }
        let process = SudoChannel.installed.makeProcess()
        #expect(process.executableURL?.path == "/usr/bin/sudo" && process.executableURL?.pathComponents.first == "/")
        #expect(!FileManager.default.fileExists(atPath: marker))
    }

    @Test("a helper report is accepted only when its reason matches the exit code")
    func onlyAMatchingReportIsAccepted() {
        var docs = Docs()
        let lineage = [(doc: docs.document(), sigs: [String]())]
        // a real failure report: the ceremony reports it, writes nothing of its own and runs no enrolled
        let refused = run(lineage, checker: goingThrough(lineage), helper: FakeHelper(reply: FakeHelper.report("pin_rollback", exit: 3)))
        #expect(refused.result == CeremonyResult(reason: "pin_rollback", written: "no", exit: 3))
        #expect(refused.checker.commands() == ["genesis-check"])
        let owner = run(lineage, checker: goingThrough(lineage), helper: FakeHelper(reply: FakeHelper.report("pin_owner", exit: 3)))
        #expect(owner.result == CeremonyResult(reason: "pin_owner", written: "no", exit: 3))
        // anything that does not match is a failed report: the next enrolled decides what is pinned
        let bad: [HelperReply] = [
            HelperReply(exit: 0, output: FakeHelper.report("pin_rollback", exit: 3).output),       // exit says ok, line says rollback
            HelperReply(exit: 3, output: FakeHelper.ok.output),                                    // exit says refused, line says ok
            HelperReply(exit: 1, output: []),                                                      // sudo failed, the helper never ran
            HelperReply(exit: 0, output: []), HelperReply(exit: 0, output: Array("garbage\n".utf8)),
            HelperReply(exit: 0, output: FakeHelper.ok.output + FakeHelper.ok.output),
            HelperReply(exit: 0, output: Array((#"{"inner_reason":"ok","reason":"ok","written":"no"}"# + "\n").utf8)),   // ok but not written
            HelperReply(exit: 3, output: Array((#"{"inner_reason":"ok","reason":"pin_owner","written":"yes"}"# + "\n").utf8)),
            HelperReply(exit: 7, output: FakeHelper.ok.output),
        ]
        for reply in bad {
            let r = run(lineage, checker: goingThrough(lineage), helper: FakeHelper(reply: reply))
            #expect(r.result == CeremonyResult(reason: "helper_report_invalid", written: "unknown", exit: 3), "\(reply)")
            #expect(r.checker.commands() == ["genesis-check"], "enrolled is not run on a report nobody can trust")
        }
    }

    // MARK: after the write

    @Test("sgn/ceremony-pin-kept-on-later-failure and sgn/enroll-rollback: enrolled false fails the ceremony and the pin stays")
    func aFailedEnrolledLeavesThePin() throws {
        var docs = Docs()
        let lineage = [(doc: docs.document(), sigs: [String]())]
        let directory = NSTemporaryDirectory() + "pin-kept-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let pinPath = directory + "/x.pin"
        let pin = pinLine(genesis: docHash(lineage[0].doc), org: docHash(lineage[0].doc))
        let helper = FakeHelper()
        helper.effect = { try? pin.write(toFile: pinPath, atomically: true, encoding: .utf8) }
        var answers = goingThrough(lineage)
        answers["enrolled"] = [enrolledNo("stale_view")]
        let r = run(lineage, checker: answers, helper: helper)
        #expect(r.result == CeremonyResult(reason: "stale_view", written: "yes", exit: 3))
        #expect(try String(contentsOfFile: pinPath, encoding: .utf8) == pin, "the pin file is unchanged after the failure")
        #expect(r.checker.commands() == ["genesis-check", "enrolled"])
    }

    @Test("an enrolled that cannot be run, or answers something else, fails the ceremony after the write")
    func anUnusableEnrolledFails() {
        var docs = Docs()
        let lineage = [(doc: docs.document(), sigs: [String]())]
        for answer in [JValue.object(["error": str("pin_missing")]), .object(["enrolled": .bool(true)]), .null,
                       .object(["enrolled": .bool(true), "reason": str("stale_view")]), .object(["enrolled": str("yes"), "reason": str("ok")])] {
            var answers = goingThrough(lineage)
            answers["enrolled"] = [answer]
            let r = run(lineage, checker: answers)
            #expect(r.result.exit == 3 && r.result.written == "yes" && r.result.reason != "ok", "\(answer)")
        }
        var none = goingThrough(lineage)
        none["enrolled"] = []
        #expect(run(lineage, checker: none).result == CeremonyResult(reason: "internal", written: "yes", exit: 3))
    }

    @Test("the ceremony has no way to remove, truncate or restore a pin")
    func noRemovalCodeExists() throws {
        let here = (0..<3).reduce(#filePath) { path, _ in (path as NSString).deletingLastPathComponent }
        for directory in ["Sources/HandsalCeremonyCore", "Sources/handsal-ceremony"] {
            let root = here + "/" + directory
            for name in try FileManager.default.contentsOfDirectory(atPath: root) where name.hasSuffix(".swift") {
                let source = try String(contentsOfFile: root + "/" + name, encoding: .utf8)
                for forbidden in ["unlink(", "removeItem", "truncate(", "ftruncate", "rename(", "remove(", "FileManager"] {
                    #expect(!source.contains(forbidden), "\(name) uses \(forbidden)")
                }
            }
        }
    }
}
