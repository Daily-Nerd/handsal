import Foundation
import HandsalCore
import Testing
@testable import HandsalCeremonyCore

private let signerKid = Persons.key().kid

/// A chain act (`device.remove`) over `parent`, as the signer writes it, with a signature that
/// nobody checks here: the ceremony reads structure (ids and parents), and the checker, which is
/// scripted, judges validity.
private struct ActMaker {
    var counter = 0

    mutating func remove(parent: String, kid: String = "NAjtfK8uPx9mTY3cWuF1yDIJ4DUhiXDyS8-_7hYNraY", signer: String = signerKid) throws -> (jws: String, id: String) {
        counter += 1
        let draft = JValue.object(["body": .object(["kid": str(kid), "person": str("carol")]), "method": str(Methods.deviceRemove),
                                   "org": str(hash("org")), "parent": .object(["id": str(parent), "performer": str("bob")])])
        let payload = try PayloadBuilder.build(draft: Draft.read(draft), attachments: .object([:]),
                                               fixed: Fixed(kid: signer, nonce: hash("nonce \(counter)"), performer: "alice", ts: "2026-11-08T11:59:00Z"))
        let bytes = try Emit.subset(payload)
        let header = Array(#"{"alg":"ES256","kid":"\#(signer)"}"#.utf8)
        let jws = Encoding.base64url(header) + "." + Encoding.base64url(bytes) + "." + Encoding.base64url([UInt8](repeating: 7, count: 64))
        return (jws, Encoding.hashstr(bytes))
    }
}

/// A genesis.sign receipt as far as the ceremony reads it: the header kid.
private func signature(kid: String) -> String {
    Encoding.base64url(Array(#"{"alg":"ES256","kid":"\#(kid)"}"#.utf8)) + ".e30." + Encoding.base64url([UInt8](repeating: 1, count: 64))
}

private func foldTip(_ id: String, removed: [String] = []) -> JValue {
    var devices: [String: JValue] = [:]
    for (index, kid) in removed.enumerated() { devices["person\(index)"] = .object([kid: .object(["status": str("removed")])]) }
    devices["alice"] = .object([signerKid: .object(["status": str("active")])])
    return .object(["devices": .object(devices), "keys": .object([:]), "org": str(hash("org")), "tip": .object(["genesis": str(hash("g")), "id": str(id), "n": str("2")])])
}

private func foldFork(parent: String, candidates: [String]) -> JValue {
    .object(["error": str("fork"), "fork": .object(["candidates": .array(candidates.sorted().map { str($0) }), "parent": str(parent)])])
}

private struct World {
    var docs = Docs()
    var previous: JValue
    var org: String
    init() {
        previous = docs.document()
        org = docHash(previous)
    }

    /// A change of `previous` with head `head`, carrying the devices of the previous document.
    mutating func change(head: String) -> JValue { docs.document(prev: org, org: org, head: head) }
}

private func answers(for lineage: [(doc: JValue, sigs: [String])], fold: [JValue]) -> [String: [JValue]] {
    let last = lineage[lineage.count - 1].doc
    return ["genesis-check": [checkAnswer(pin: pinLine(genesis: docHash(last), org: docHash(lineage[0].doc)))],
            "fold": fold, "enrolled": [enrolledYes]]
}

private func run(_ lineage: [(doc: JValue, sigs: [String])], acts: [String], _ answers: [String: [JValue]]) -> (checker: FakeChecker, console: FakeConsole, helper: FakeHelper, result: CeremonyResult) {
    let checker = FakeChecker(answers), console = FakeConsole(), helper = FakeHelper()
    let result = Ceremony(checker: checker, helper: helper, console: console).run(arguments: [], stdin: ceremonyInput(lineage: lineage, acts: acts))
    return (checker, console, helper, result)
}

@Suite("enrollment ceremony, a change (SG-12 steps 6 and 7)")
struct CeremonyChangeTests {
    @Test("the previous epoch ends at a tip T: H is the tip, or H is not the tip and T is shown in full")
    func theHeadLineAtATip() throws {
        var world = World()
        var maker = ActMaker()
        let act = try maker.remove(parent: world.org)
        // H is the tip
        let head = act.id
        let change = world.change(head: head)
        let lineage = [(doc: world.previous, sigs: [String]()), (doc: change, sigs: [String]())]
        let atTip = run(lineage, acts: [act.jws], answers(for: lineage, fold: [foldTip(act.id)]))
        #expect(atTip.result.exit == 0 && atTip.console.shown.contains("H is the tip"))
        #expect(!atTip.console.shown.contains("H is not the tip"))
        // H is below the tip: the tip is T = a later act
        let later = try maker.remove(parent: act.id)
        let notTip = run(lineage, acts: [act.jws, later.jws], answers(for: lineage, fold: [foldTip(later.id)]))
        #expect(notTip.console.shown.contains("H is not the tip (tip \(later.id))"))
        // the fold is run on the previous epoch only, with the org of the first document and no pin, no clock
        guard case .object(let input)? = notTip.checker.inputs("fold").first else { Issue.record("no fold"); return }
        #expect(Set(input.keys) == ["acts", "lineage", "org"] && input["org"] == str(world.org))
        guard case .array(let sent)? = input["lineage"] else { Issue.record("no lineage"); return }
        #expect(sent.count == 1 && sent[0]["doc"] == world.previous, "the candidate document is not part of the previous epoch")
    }

    @Test("sgn/ceremony-head-display-forked-epoch: a fork shows P and where H lies")
    func theHeadLineAtAFork() throws {
        var world = World()
        var maker = ActMaker()
        let c1 = try maker.remove(parent: world.org), c2 = try maker.remove(parent: world.org)
        let below = try maker.remove(parent: c2.id)
        let acts = [c1.jws, c2.jws, below.jws]
        func ceremony(head: String) -> (checker: FakeChecker, console: FakeConsole, helper: FakeHelper, result: CeremonyResult) {
            var world = world
            let change = world.change(head: head)
            let lineage = [(doc: world.previous, sigs: [String]()), (doc: change, sigs: [String]())]
            // the fork, then one fold per branch
            return run(lineage, acts: acts, answers(for: lineage, fold: [foldFork(parent: world.org, candidates: [c1.id, c2.id]), foldTip(c1.id), foldTip(below.id)]))
        }
        let underC2 = ceremony(head: below.id)
        #expect(underC2.console.shown.contains("Previous epoch forked at \(world.org); H is below candidate \(c2.id)"))
        let atCandidate = ceremony(head: c1.id)
        #expect(atCandidate.console.shown.contains("Previous epoch forked at \(world.org); H is below candidate \(c1.id)"))
        let atP = ceremony(head: world.org)
        #expect(atP.console.shown.contains("Previous epoch forked at \(world.org); H is P"))
        let elsewhere = ceremony(head: hash("somewhere else"))
        #expect(elsewhere.console.shown.contains("Previous epoch forked at \(world.org); H is not below P"))
        _ = world
    }

    @Test("a forked epoch is folded once per branch, each with the acts of its own branch only")
    func eachBranchIsFoldedAlone() throws {
        var world = World()
        var maker = ActMaker()
        let c1 = try maker.remove(parent: world.org), c2 = try maker.remove(parent: world.org)
        let below = try maker.remove(parent: c2.id)
        let change = world.change(head: below.id)
        let lineage = [(doc: world.previous, sigs: [String]()), (doc: change, sigs: [String]())]
        let r = run(lineage, acts: [c1.jws, c2.jws, below.jws, "not-an-act"],
                    answers(for: lineage, fold: [foldFork(parent: world.org, candidates: [c1.id, c2.id]), foldTip(c1.id), foldTip(below.id)]))
        let sent = r.checker.inputs("fold").map { input -> Set<String> in
            guard case .array(let acts)? = input["acts"] else { return [] }
            return Set(acts.compactMap(\.str))
        }
        #expect(sent.count == 3)
        #expect(sent[0] == [c1.jws, c2.jws, below.jws, "not-an-act"], "first the whole epoch, which is what forks")
        let branches = Set(sent.dropFirst())
        #expect(branches.contains([c1.jws, "not-an-act"]) && branches.contains([c2.jws, below.jws, "not-an-act"]))
    }

    @Test("sgn/ceremony-removed-key-carried-aid: a carried key that a valid removal removes is shown in full")
    func aRemovedKeyThatTheDocumentCarriesIsShown() throws {
        var world = World()
        var maker = ActMaker()
        let removal = try maker.remove(parent: world.org)
        let change = world.change(head: removal.id)
        // the document carries every device of the previous one, alice kid included
        let carried = world.docs.keys["alice"]![0].kid
        let lineage = [(doc: world.previous, sigs: [String]()), (doc: change, sigs: [String]())]
        let shown = run(lineage, acts: [removal.jws], answers(for: lineage, fold: [foldTip(removal.id, removed: [carried])])).console.shown
        #expect(shown.contains("Key removed in the previous epoch: \(carried)"))
        // a removed kid the document does not carry and no signer used is not shown
        let stranger = Persons.key().kid
        let quiet = run(lineage, acts: [removal.jws], answers(for: lineage, fold: [foldTip(removal.id, removed: [stranger])])).console.shown
        #expect(!quiet.contains("Key removed in the previous epoch"))
        // nothing removed: no line
        #expect(!run(lineage, acts: [removal.jws], answers(for: lineage, fold: [foldTip(removal.id)])).console.shown.contains("Key removed"))
    }

    @Test("a key that signed the change counts too, and a removal on either branch of a fork counts")
    func aSigningKeyAndAnyBranchCount() throws {
        var world = World()
        var maker = ActMaker()
        let c1 = try maker.remove(parent: world.org), c2 = try maker.remove(parent: world.org)
        let change = world.change(head: c2.id)
        let outsider = Persons.key().kid
        let lineage = [(doc: world.previous, sigs: [String]()), (doc: change, sigs: [signature(kid: outsider)])]
        let r = run(lineage, acts: [c1.jws, c2.jws],
                    answers(for: lineage, fold: [foldFork(parent: world.org, candidates: [c1.id, c2.id]), foldTip(c1.id, removed: [outsider]), foldTip(c2.id)]))
        #expect(r.console.shown.contains("Key removed in the previous epoch: \(outsider)"))
        #expect(r.console.shown.components(separatedBy: "Key removed in the previous epoch").count == 2, "once, not once per branch")
    }

    @Test("a previous epoch the checker cannot fold stops the ceremony with its reason: the aid cannot be shown")
    func anUnfoldablePreviousEpochStops() throws {
        var world = World()
        let change = world.change(head: world.org)
        let lineage = [(doc: world.previous, sigs: [String]()), (doc: change, sigs: [String]())]
        let r = run(lineage, acts: [], answers(for: lineage, fold: [.object(["error": str("pin_missing")])]))
        #expect(r.result == CeremonyResult(reason: "pin_missing", written: "no", exit: 1))
        #expect(r.helper.lines.isEmpty && r.console.questions.isEmpty)
    }

    @Test("an original has no previous epoch: no fold, no head line")
    func anOriginalNeverFolds() {
        var world = World()
        let lineage = [(doc: world.previous, sigs: [String]())]
        let r = run(lineage, acts: [], answers(for: lineage, fold: []))
        #expect(r.result.exit == 0 && !r.checker.commands().contains("fold"))
        #expect(!r.console.shown.contains("H is ") && !r.console.shown.contains("Key removed"))
    }

    @Test("a change of a lineage of three: the previous epoch is the one before the candidate")
    func theEpochBeforeTheCandidate() throws {
        var world = World()
        let second = world.change(head: world.org)
        var next = world
        next.previous = second
        next.org = world.org
        let third = next.docs.document(prev: docHash(second), org: world.org, head: docHash(second))
        let lineage = [(doc: world.previous, sigs: [String]()), (doc: second, sigs: [String]()), (doc: third, sigs: [String]())]
        let r = run(lineage, acts: [], answers(for: lineage, fold: [foldTip(docHash(second))]))
        #expect(r.console.shown.contains("H is the tip"))
        guard case .object(let input)? = r.checker.inputs("fold").first, case .array(let sent)? = input["lineage"] else { Issue.record("no fold"); return }
        #expect(sent.count == 2 && input["org"] == str(world.org))
    }
}
