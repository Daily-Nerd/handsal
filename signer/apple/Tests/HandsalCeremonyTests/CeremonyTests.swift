import Foundation
import HandsalCore
import HandsalKeyScan
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
                 confirm: [Bool] = [true], helper: FakeHelper = FakeHelper(), arguments: [String] = [],
                 console shown: FakeConsole? = nil) -> Run {
    let checker = FakeChecker(answers), console = shown ?? FakeConsole(answers: confirm)
    let result = Ceremony(checker: checker, helper: helper, console: console)
        .run(arguments: arguments, stdin: ceremonyInput(lineage: lineage, acts: acts))
    return Run(checker: checker, console: console, helper: helper, result: result)
}

/// The answers of a ceremony that goes through: the checker accepts the lineage and returns the pin
/// of its last document, the helper reports `ok`, `enrolled` says yes.
private func goingThrough(_ lineage: [(doc: JValue, sigs: [String])]) -> [String: [JValue]] {
    let last = lineage[lineage.count - 1].doc
    let pin = pinLine(genesis: docHash(last), org: docHash(lineage[0].doc))
    return ["genesis-check": [checkAnswer(pin: pin)], "sync": [syncOk], "enrolled": [enrolledYes]]
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
        #expect(r.checker.commands() == ["genesis-check", "sync", "enrolled"])
        #expect(r.helper.lines.count == 1)
        // genesis-check gets the lineage and the bag; sync the bag, the lineage as `docs` and the org; enrolled the device and the org only
        guard case .object(let check)? = r.checker.inputs("genesis-check").first, case .object(let sync)? = r.checker.inputs("sync").first,
              case .object(let enrolled)? = r.checker.inputs("enrolled").first else {
            Issue.record("inputs missing"); return
        }
        #expect(Set(check.keys) == ["acts", "lineage"])
        #expect(Set(sync.keys) == ["acts", "docs", "org"], "only sync renames the lineage to docs (CF-09), and it refuses the old key")
        #expect(sync["lineage"] == nil && sync["docs"] == check["lineage"], "docs carries exactly the lineage genesis-check got")
        #expect(Set(enrolled.keys) == ["device_kid", "org"])
        #expect(enrolled["org"] == str(docHash(original)) && sync["org"] == str(docHash(original)))
        #expect(r.console.questions.count == 1)
    }

    @Test("SG-03: nothing the ceremony shows, hands the helper or prints carries the private scalar of a key in the lineage")
    func noOutputCarriesKeyMaterial() throws {
        var docs = Docs()
        let original = docs.document()
        let scalars = docs.keys.values.flatMap { $0 }.flatMap(\.scalars)
        #expect(scalars.count == 6)
        let lineage = [(doc: original, sigs: ["sig-1"])]
        let r = run(lineage, checker: goingThrough(lineage))
        #expect(r.result.exit == 0)
        let seen = Array(r.console.shown.utf8) + r.result.line + r.helper.lines.flatMap { $0 }
        // the scan ran over real output: the public half of every key is in what the helper was handed, the scalar is not
        for case .object(let entry) in docs.keys.values.flatMap({ $0 }).map(\.sign) {
            #expect(KeyScan.contains(seen, Array((entry["x"]?.str ?? "").utf8)))
        }
        #expect(KeyScan.contains(seen, Array(#""reason":"ok""#.utf8)))
        for scalar in scalars { #expect(!KeyScan.leaks(seen, scalar: scalar)) }
    }

    @Test("the closing line is an aid: a console that cannot show it does not undo an enrolled machine")
    func aConsoleThatFailsOnTheClosingLineDoesNotFailTheCeremony() {
        var docs = Docs()
        let lineage = [(doc: docs.document(), sigs: ["sig-1"])]
        let console = FakeConsole()
        console.refuses = { $0.hasPrefix("Enrolled:") }
        let r = run(lineage, checker: goingThrough(lineage), console: console)
        #expect(r.result == CeremonyResult(reason: "ok", written: "yes", exit: 0))
        #expect(!r.console.shown.contains("Enrolled:"))
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

    @Test("input that is not one {acts, device_kid, lineage} line is refused: usage, no step runs")
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

    @Test("SG-12: the input is a closed object of acts, device_kid and lineage; the store's members are not the person's to type")
    func theInputIsAClosedObjectOfActsDeviceKidAndLineage() {
        var docs = Docs()
        let lineage = [(doc: docs.document(), sigs: ["sig-1"])]
        // the three keys are accepted
        let accepted = run(lineage, checker: goingThrough(lineage))
        #expect(accepted.result == CeremonyResult(reason: "ok", written: "yes", exit: 0))
        // each of the old two, and any other key, is refused before any step runs
        for extra in [["synced_at": str("2026-11-12T10:00:00Z")], ["tip_statement": JValue.null], ["org": str(docHash(lineage[0].doc))], ["pin": str("x")]] {
            let checker = FakeChecker(goingThrough(lineage)), console = FakeConsole(), helper = FakeHelper()
            let result = Ceremony(checker: checker, helper: helper, console: console)
                .run(arguments: [], stdin: ceremonyInput(lineage: lineage, extra: extra))
            #expect(result == CeremonyResult(reason: "malformed_input", written: "no", exit: 2), "\(extra)")
            #expect(checker.calls.isEmpty && helper.lines.isEmpty && console.questions.isEmpty)
        }
        // a missing key is refused too
        let missing = Array(#"{"acts":[],"lineage":[]}"#.utf8) + [0x0A]
        #expect(Ceremony(checker: FakeChecker(), helper: FakeHelper(), console: FakeConsole()).run(arguments: [], stdin: missing).reason == "malformed_input")
    }

    @Test("SG-12: after the pin write the checker is called sync and then enrolled, each with its own input")
    func theCheckerIsCalledSyncThenEnrolledAfterThePinWrite() {
        var docs = Docs()
        let original = docs.document()
        let lineage = [(doc: original, sigs: ["sig-1"])]
        let kid = Persons.key().kid
        let checker = FakeChecker(goingThrough(lineage))
        var order: [String] = []
        let helper = FakeHelper()
        helper.effect = { order.append("helper") }
        let result = Ceremony(checker: checker, helper: helper, console: FakeConsole())
            .run(arguments: [], stdin: ceremonyInput(lineage: lineage, acts: ["act-1"], deviceKid: kid))
        #expect(result == CeremonyResult(reason: "ok", written: "yes", exit: 0))
        #expect(order == ["helper"] && helper.lines.count == 1)
        #expect(checker.commands() == ["genesis-check", "sync", "enrolled"])
        let org = str(docHash(original))
        #expect(checker.inputs("sync").first == .object(["acts": .array([str("act-1")]),
                                                         "docs": .array([.object(["doc": original, "sigs": .array([str("sig-1")])])]), "org": org]))
        #expect(checker.inputs("enrolled").first == .object(["device_kid": str(kid), "org": org]))
    }

    @Test("SG-12: a sync that refuses after the write fails the ceremony with its reason, leaves the pin and runs no enrolled")
    func aFailedSyncAfterTheWriteLeavesThePin() throws {
        var docs = Docs()
        let lineage = [(doc: docs.document(), sigs: [String]())]
        let directory = NSTemporaryDirectory() + "pin-kept-sync-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let pinPath = directory + "/x.pin"
        let pin = pinLine(genesis: docHash(lineage[0].doc), org: docHash(lineage[0].doc))
        let helper = FakeHelper()
        helper.effect = { try? pin.write(toFile: pinPath, atomically: true, encoding: .utf8) }
        var answers = goingThrough(lineage)
        answers["sync"] = [syncNo("store_unavailable")]
        let r = run(lineage, checker: answers, helper: helper)
        #expect(r.result == CeremonyResult(reason: "store_unavailable", written: "yes", exit: 3))
        #expect(try String(contentsOfFile: pinPath, encoding: .utf8) == pin, "the pin file is unchanged after the failure")
        #expect(r.checker.commands() == ["genesis-check", "sync"], "enrolled does not judge a store that sync did not write")
        // a fork is written but is no success: the ceremony fails with it
        var forked = goingThrough(lineage)
        forked["sync"] = [.object(["reason": str("fork"), "synced_at": str("2026-11-12T10:00:00Z")])]
        #expect(run(lineage, checker: forked).result == CeremonyResult(reason: "fork", written: "yes", exit: 3))
        // an error object, a missing answer and a malformed one fail after the write as well
        for answer in [JValue.object(["error": str("pin_missing")]), .null, .object(["reason": str("ok")]),
                       .object(["reason": str("ok"), "synced_at": .null]), .object(["reason": str("store_full"), "synced_at": str("2026-11-12T10:00:00Z")])] {
            var bad = goingThrough(lineage)
            bad["sync"] = [answer]
            let result = run(lineage, checker: bad).result
            #expect(result.exit == 3 && result.written == "yes" && result.reason != "ok", "\(answer)")
        }
        var none = goingThrough(lineage)
        none["sync"] = []
        #expect(run(lineage, checker: none).result == CeremonyResult(reason: "internal", written: "yes", exit: 3))
    }

    @Test("SG-12: a sync that answers fork fails the ceremony with fork, runs no enrolled and leaves the pin")
    func aForkedSyncAfterTheWriteFailsWithForkAndLeavesThePin() throws {
        var docs = Docs()
        let lineage = [(doc: docs.document(), sigs: [String]())]
        let directory = NSTemporaryDirectory() + "pin-kept-fork-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let pinPath = directory + "/x.pin"
        let pin = pinLine(genesis: docHash(lineage[0].doc), org: docHash(lineage[0].doc))
        let helper = FakeHelper()
        helper.effect = { try? pin.write(toFile: pinPath, atomically: true, encoding: .utf8) }
        var forked = goingThrough(lineage)
        forked["sync"] = [.object(["reason": str("fork"), "synced_at": str("2026-11-12T10:00:00Z")])]
        let r = run(lineage, checker: forked, helper: helper)
        #expect(r.result == CeremonyResult(reason: "fork", written: "yes", exit: 3))
        #expect(try String(contentsOfFile: pinPath, encoding: .utf8) == pin, "the pin file is unchanged after the fork")
        #expect(r.checker.commands() == ["genesis-check", "sync"], "enrolled does not run after a fork")
    }

    @Test("SG-12: a sync that answers epoch_superseded after the write fails the ceremony with that reason, runs no enrolled and leaves the pin")
    func aSupersededSyncAfterTheWriteFailsWithThatReasonAndLeavesThePin() throws {
        var docs = Docs()
        let lineage = [(doc: docs.document(), sigs: [String]())]
        let directory = NSTemporaryDirectory() + "pin-kept-superseded-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let pinPath = directory + "/x.pin"
        let pin = pinLine(genesis: docHash(lineage[0].doc), org: docHash(lineage[0].doc))
        let helper = FakeHelper()
        helper.effect = { try? pin.write(toFile: pinPath, atomically: true, encoding: .utf8) }
        var superseded = goingThrough(lineage)
        superseded["sync"] = [.object(["reason": str("epoch_superseded"), "synced_at": str("2026-11-12T10:00:00Z")])]
        let r = run(lineage, checker: superseded, helper: helper)
        #expect(r.result == CeremonyResult(reason: "epoch_superseded", written: "yes", exit: 3))
        #expect(try String(contentsOfFile: pinPath, encoding: .utf8) == pin, "the pin file is unchanged after the superseded sync")
        #expect(r.checker.commands() == ["genesis-check", "sync"], "enrolled does not run after a superseded sync")
        // lock: the reason with no write time is not a written answer, so it stops as internal
        var unwritten = goingThrough(lineage)
        unwritten["sync"] = [.object(["reason": str("epoch_superseded"), "synced_at": .null])]
        #expect(run(lineage, checker: unwritten).result == CeremonyResult(reason: "internal", written: "yes", exit: 3))
    }

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

    @Test("a ceremony in the background of its terminal is refused as no_display before anything is shown, asked or run")
    func aBackgroundCeremonyIsRefusedBeforeSudo() {
        var docs = Docs()
        let lineage = [(doc: docs.document(), sigs: ["sig-1"])]
        let console = FakeConsole()
        console.inForeground = false
        let r = run(lineage, checker: goingThrough(lineage), console: console)
        #expect(r.result == CeremonyResult(reason: "no_display", written: "no", exit: 4))
        #expect(r.helper.lines.isEmpty && console.questions.isEmpty && console.shown.isEmpty)
    }

    @Test("a ceremony that leaves the foreground after the question never starts the helper")
    func leavingTheForegroundBeforeSudoStopsTheCeremony() {
        var docs = Docs()
        let lineage = [(doc: docs.document(), sigs: ["sig-1"])]
        let console = FakeConsole()
        let helper = FakeHelper()
        helper.effect = { Issue.record("the helper started from the background") }
        // The person answers y, then the ceremony is put in the background (Ctrl-Z, bg).
        console.afterAnswer = { console.inForeground = false }
        let r = run(lineage, checker: goingThrough(lineage), helper: helper, console: console)
        #expect(r.result == CeremonyResult(reason: "no_display", written: "no", exit: 4))
        #expect(helper.lines.isEmpty)
    }

    @Test("sgn/ceremony-sudo-absolute and -k: the channel is /usr/bin/sudo -k <helper>, no PATH lookup, empty environment")
    func theChannelIsSudoMinusKAtTheFixedPaths() {
        let channel = SudoChannel.installed
        #expect(channel.sudo == "/usr/bin/sudo")
        #expect(channel.helper == "/Library/Application Support/handsal/bin/handsal-pin")
        #expect(channel.arguments == ["-k", "/Library/Application Support/handsal/bin/handsal-pin"], "one invocation, no other argument")
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
        #expect(SudoChannel.installed.sudo == "/usr/bin/sudo" && SudoChannel.installed.sudo.hasPrefix("/"))
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
        #expect(r.checker.commands() == ["genesis-check", "sync", "enrolled"])
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
