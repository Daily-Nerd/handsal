import Foundation
import HandsalCore
import Testing
@testable import HandsalCeremonyCore

/// The ceremony shows what `genesis-aids` answers (SG-12 steps 6 and 7). The checker owns the facts, so these tests
/// script its answer and check the lines the person reads, the input the ceremony sends and what it does with an
/// answer that is a refusal or is not of the shape. Against the real production checker the same step is run in
/// `ProductionCheckerCeremonyTests`.

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

private func answers(for lineage: [(doc: JValue, sigs: [String])], aids: [JValue]) -> [String: [JValue]] {
    let last = lineage[lineage.count - 1].doc
    return ["genesis-check": [checkAnswer(pin: pinLine(genesis: docHash(last), org: docHash(lineage[0].doc)))],
            "genesis-aids": aids, "sync": [syncOk], "enrolled": [enrolledYes]]
}

private func run(_ lineage: [(doc: JValue, sigs: [String])], acts: [String] = [], _ answers: [String: [JValue]]) -> (checker: FakeChecker, console: FakeConsole, helper: FakeHelper, result: CeremonyResult) {
    let checker = FakeChecker(answers), console = FakeConsole(), helper = FakeHelper()
    let result = Ceremony(checker: checker, helper: helper, console: console).run(arguments: [], stdin: ceremonyInput(lineage: lineage, acts: acts))
    return (checker, console, helper, result)
}

private let tip = hash("tip"), other = hash("another node")
private let forkParent = hash("fork parent"), first = hash("candidate one"), second = hash("candidate two")

@Suite("enrollment ceremony, a change (SG-12 steps 6 and 7)")
struct CeremonyChangeTests {
    private func shown(_ aids: JValue) -> (result: CeremonyResult, shown: String, run: (checker: FakeChecker, console: FakeConsole, helper: FakeHelper, result: CeremonyResult)) {
        var world = World()
        let change = world.change(head: world.org)
        let lineage = [(doc: world.previous, sigs: [String]()), (doc: change, sigs: [String]())]
        let r = run(lineage, answers(for: lineage, aids: [aids]))
        return (r.result, r.console.shown, r)
    }

    @Test("the previous epoch ends at a tip T: H is the tip, or H is not the tip and T is shown in full")
    func theHeadLineAtATip() {
        let atTip = shown(aidsAtTip(tip))
        #expect(atTip.result.exit == 0 && atTip.shown.contains("H is the tip"))
        #expect(!atTip.shown.contains("H is not the tip"))
        let notTip = shown(aidsAtTip(tip, is: "not_tip"))
        #expect(notTip.shown.contains("H is not the tip (tip \(tip))"))
        #expect(!notTip.shown.contains("H is the tip"))
    }

    @Test("sgn/ceremony-head-display-forked-epoch: a fork shows P and where H lies")
    func theHeadLineAtAFork() {
        let candidates = [first, second]
        let underOne = shown(aidsAtFork(parent: forkParent, candidates: candidates, place: "below", candidate: second))
        #expect(underOne.shown.contains("Previous epoch forked at \(forkParent); H is below candidate \(second)"))
        let atParent = shown(aidsAtFork(parent: forkParent, candidates: candidates, place: "parent"))
        #expect(atParent.shown.contains("Previous epoch forked at \(forkParent); H is P"))
        let elsewhere = shown(aidsAtFork(parent: forkParent, candidates: candidates, place: "not_below"))
        #expect(elsewhere.shown.contains("Previous epoch forked at \(forkParent); H is not below P"))
        #expect([underOne, atParent, elsewhere].allSatisfy { $0.result.exit == 0 })
    }

    @Test("the ceremony asks genesis-aids with the genesis-check input, and nothing of this machine")
    func theAidsAreAskedWithTheLineageInput() throws {
        var world = World()
        let change = world.change(head: world.org)
        let lineage = [(doc: world.previous, sigs: [String]()), (doc: change, sigs: ["receipt"])]
        let r = run(lineage, acts: ["act-1"], answers(for: lineage, aids: [aidsAtTip(tip)]))
        let aids = try #require(r.checker.inputs("genesis-aids").first)
        #expect(aids == r.checker.inputs("genesis-check").first, "the same {acts, lineage} object")
        guard case .object(let input) = aids else { Issue.record("no object"); return }
        #expect(Set(input.keys) == ["acts", "lineage"], "no pin, no clock, no org: nothing the answer could depend on")
        guard case .array(let sent)? = input["lineage"] else { Issue.record("no lineage"); return }
        #expect(sent.count == 2 && sent[1]["doc"] == change, "the candidate is part of the lineage that is asked about")
        #expect(r.checker.commands() == ["genesis-check", "genesis-aids", "sync", "enrolled"], "the per-machine commands come after the write")
    }

    @Test("sgn/ceremony-removed-key-carried-aid: a removed key in the answer is shown in full, once")
    func aRemovedKeyThatTheDocumentCarriesIsShown() {
        let carried = Persons.key().kid, signer = Persons.key().kid
        let lines = shown(aidsAtTip(tip, removed: [carried, signer])).shown
        #expect(lines.contains("Key removed in the previous epoch: \(carried)"))
        #expect(lines.contains("Key removed in the previous epoch: \(signer)"))
        #expect(lines.components(separatedBy: "Key removed in the previous epoch").count == 3)
        #expect(!shown(aidsAtTip(tip)).shown.contains("Key removed"), "nothing removed: no line")
    }

    @Test("a removal on a discarded branch and a fork inside a branch are shown, and the ceremony goes on")
    func aRemovalOnADiscardedBranchAndANestedForkAreShown() {
        let kid = Persons.key().kid
        let r = shown(aidsAtFork(parent: forkParent, candidates: [first, second], place: "not_below", removed: [kid]))
        #expect(r.result.exit == 0, "got \(text(r.result))")
        #expect(r.shown.contains("Previous epoch forked at \(forkParent); H is not below P"))
        #expect(r.shown.contains("Key removed in the previous epoch: \(kid)"))
        #expect(r.run.helper.lines.count == 1, "the pin write is reached")
    }

    @Test("a refusal of genesis-aids stops the ceremony with its reason: the aid cannot be shown")
    func aRefusedAidStopsTheCeremonyWithItsReason() {
        for (answer, reason) in [(JValue.object(["aids": .null, "reason": str("verifier_unavailable")]), "verifier_unavailable"),
                                 (.object(["aids": .null, "reason": str("genesis_head_unknown")]), "genesis_head_unknown"),
                                 (.object(["error": str("malformed_input")]), "malformed_input")] {
            let r = shown(answer)
            #expect(r.result == CeremonyResult(reason: reason, written: "no", exit: 1), "got \(text(r.result))")
            #expect(r.run.helper.lines.isEmpty && r.run.console.questions.isEmpty, "stopped before the question and the write")
            #expect(r.run.checker.commands() == ["genesis-check", "genesis-aids"])
        }
    }

    @Test("an answer of another shape is internal, whatever it says about H")
    func aMalformedAidIsInternal() {
        let good = aidsAtTip(tip)
        guard case .object(var withExtra) = good else { return }
        withExtra["pin"] = .null
        let tipNoPlace = JValue.object(["aids": .object(["head": .object(["at": str("tip"), "tip": str(tip)]), "removed": .array([])]), "reason": str("ok")])
        let badTip = aidsAtTip("not a hash")
        let belowNoCandidate = aidsAtFork(parent: forkParent, candidates: [first], place: "below")
        let belowOutsider = aidsAtFork(parent: forkParent, candidates: [first], place: "below", candidate: other)
        let parentWithCandidate = aidsAtFork(parent: forkParent, candidates: [first], place: "parent", candidate: first)
        let noCandidates = aidsAtFork(parent: forkParent, candidates: [], place: "parent")
        let badKid = aidsAtTip(tip, removed: ["short"])
        let unsorted = aidsAnswer(head: .object(["at": str("tip"), "place": str("tip"), "tip": str(tip)]), removed: [])
        guard case .object(var unsortedMembers) = unsorted, case .object(var inner)? = unsortedMembers["aids"] else { return }
        let a = Persons.key().kid, b = Persons.key().kid
        let ordered = [a, b].sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) }
        inner["removed"] = .array([str(ordered[1]), str(ordered[0])])
        unsortedMembers["aids"] = .object(inner)
        let okButNull = JValue.object(["aids": .null, "reason": str("ok")])
        let refusedWithAids = JValue.object(["aids": good["aids"] ?? .null, "reason": str("verifier_unavailable")])
        for answer in [.object(withExtra), tipNoPlace, badTip, belowNoCandidate, belowOutsider, parentWithCandidate, noCandidates, badKid, .object(unsortedMembers), okButNull,
                       refusedWithAids, JValue.array([]), JValue.string("ok")] {
            let r = shown(answer)
            #expect(r.result == CeremonyResult(reason: "internal", written: "no", exit: 1), "\(answer) gave \(text(r.result))")
            #expect(r.run.helper.lines.isEmpty)
        }
    }

    @Test("an original has no previous epoch: no genesis-aids, no head line")
    func anOriginalNeverAsksForAids() {
        var world = World()
        let lineage = [(doc: world.previous, sigs: [String]())]
        let r = run(lineage, answers(for: lineage, aids: []))
        #expect(r.result.exit == 0 && !r.checker.commands().contains("genesis-aids"))
        #expect(!r.console.shown.contains("H is ") && !r.console.shown.contains("Key removed"))
    }

    @Test("a change of a lineage of three: the aids are asked of the whole lineage, the candidate last")
    func theLastLinkIsTheCandidate() throws {
        var world = World()
        let second = world.change(head: world.org)
        var next = world
        next.previous = second
        let third = next.docs.document(prev: docHash(second), org: world.org, head: docHash(second))
        let lineage = [(doc: world.previous, sigs: [String]()), (doc: second, sigs: [String]()), (doc: third, sigs: [String]())]
        let r = run(lineage, answers(for: lineage, aids: [aidsAtTip(docHash(second))]))
        #expect(r.console.shown.contains("H is the tip"))
        guard case .object(let input)? = r.checker.inputs("genesis-aids").first, case .array(let sent)? = input["lineage"] else { Issue.record("no aids call"); return }
        #expect(sent.count == 3 && sent[2]["doc"] == third)
    }
}
