import CryptoKit
import Foundation
import HandsalCore
@testable import HandsalCeremonyCore

/// A scripted production checker: it answers each command from a queue, records every call, and
/// never runs anything. Running a command it was not given an answer for is a test bug, so it throws.
final class FakeChecker: LineageQueries, MachineQueries, @unchecked Sendable {
    private let lock = NSLock()
    private var queues: [String: [JValue]]
    private(set) var calls: [(command: String, input: JValue)] = []

    init(_ answers: [String: [JValue]] = [:]) { queues = answers }

    func genesisCheck(_ input: [UInt8]) throws -> JValue { try run("genesis-check", input: input) }
    func genesisAids(_ input: [UInt8]) throws -> JValue { try run("genesis-aids", input: input) }
    func sync(_ input: [UInt8]) throws -> JValue { try run("sync", input: input) }
    func enrolled(_ input: [UInt8]) throws -> JValue { try run("enrolled", input: input) }

    private func run(_ command: String, input: [UInt8]) throws -> JValue {
        try lock.withLock {
            guard case .success(let value) = Subset.parse(input, maxSize: Limits.maxInput) else { throw Refusal("internal") }
            calls.append((command, value))
            guard var queue = queues[command], !queue.isEmpty else { throw Refusal("internal") }
            let answer = queue.removeFirst()
            queues[command] = queue
            return answer
        }
    }

    func commands() -> [String] { lock.withLock { calls.map(\.command) } }
    func inputs(_ command: String) -> [JValue] { lock.withLock { calls.filter { $0.command == command }.map(\.input) } }
}

final class FakeConsole: Console, @unchecked Sendable {
    private let lock = NSLock()
    private var written: [String] = []
    private var answers: [Bool]
    private(set) var questions: [String] = []

    init(answers: [Bool] = [true]) { self.answers = answers }

    var shown: String { lock.withLock { written.joined() } }
    /// Text this console cannot show: `show` throws for it, as a closed terminal does.
    var refuses: @Sendable (String) -> Bool = { _ in false }
    func show(_ text: String) throws {
        if refuses(text) { throw Refusal("no_display") }
        lock.withLock { written.append(text) }
    }
    /// False stands for a ceremony run in the background of its terminal.
    var inForeground = true
    /// Runs once the person has answered.
    var afterAnswer: (() -> Void)?
    func requireForeground() throws { if !inForeground { throw Refusal("no_display") } }
    func confirm(_ question: String) throws -> Bool {
        try lock.withLock {
            questions.append(question)
            guard !answers.isEmpty else { throw Refusal("no_display") }
            let answer = answers.removeFirst()
            afterAnswer?()
            return answer
        }
    }
}

/// A helper channel that records the line it was given and answers a canned report, or runs `effect`.
final class FakeHelper: HelperChannel, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var lines: [[UInt8]] = []
    var reply: HelperReply
    var effect: (() -> Void)?

    init(reply: HelperReply = FakeHelper.ok) { self.reply = reply }

    static let ok = HelperReply(exit: 0, output: Array((#"{"inner_reason":"ok","reason":"ok","written":"yes"}"# + "\n").utf8))

    static func report(_ reason: String, exit: Int32, written: String = "no") -> HelperReply {
        HelperReply(exit: exit, output: Array((#"{"inner_reason":"ok","reason":"\#(reason)","written":"\#(written)"}"# + "\n").utf8))
    }

    func submit(_ line: [UInt8]) throws -> HelperReply {
        lock.withLock { lines.append(line) }
        effect?()
        return reply
    }
}

func str(_ text: String) -> JValue { .string(text) }
func hash(_ seed: String) -> String { Encoding.hashstr(Array(seed.utf8)) }

/// Production-profile documents built from fresh P-256 keys, so no kid is a fixture kid.
struct Persons {
    struct Key {
        let kid: String; let sign: JValue; let agree: JValue
        /// The private scalars of the two keys, kept only so a test can look for them in what a tool shows or writes.
        var scalars: [[UInt8]] = []
    }

    static func key() -> Key {
        func point(_ key: P256.Signing.PublicKey) -> (x: String, y: String) {
            let raw = [UInt8](key.x963Representation)
            return (Encoding.base64url(Array(raw[1..<33])), Encoding.base64url(Array(raw[33..<65])))
        }
        let signing = P256.Signing.PrivateKey(), agreeing = P256.Signing.PrivateKey()
        let sign = point(signing.publicKey), agree = point(agreeing.publicKey)
        return Key(kid: Encoding.thumbprint(x: sign.x, y: sign.y), sign: .object(["x": str(sign.x), "y": str(sign.y)]),
                   agree: .object(["x": str(agree.x), "y": str(agree.y)]),
                   scalars: [[UInt8](signing.rawRepresentation), [UInt8](agreeing.rawRepresentation)])
    }
}

struct Docs {
    var names: [String] = ["alice", "bob", "carol"]
    /// persons needed by every rule; 2 of 3 holders leaves a spare, 2 of 2 does not.
    var persons = "2"
    var devicesPerPerson = 1
    var profile = Profiles.standard.production
    var witness: JValue = .object(["mode": str("none")])
    /// The policy's `relays` (GP-02): sorted, unique hostnames, none by default.
    var relays: [String] = []
    var keys: [String: [Persons.Key]] = [:]

    mutating func document(prev: String? = nil, org: String? = nil, head: String? = nil, name: String = "example") -> JValue {
        var devices: [(kid: String, value: JValue)] = []
        for person in names {
            if keys[person] == nil { keys[person] = (0..<devicesPerPerson).map { _ in Persons.key() } }
            for (index, key) in keys[person]!.enumerated() {
                devices.append((key.kid, .object(["agree": key.agree, "class": str("apple-se-bio"), "kid": str(key.kid), "label": str("\(person) se-bio \(index)"),
                                                  "person": str(person), "sign": key.sign])))
            }
        }
        let rule = JValue.object(["persons": str(persons), "roles": .array([str("maintainer")])])
        var members: [String: JValue] = [
            "devices": .array(devices.sorted { Array($0.kid.utf8).lexicographicallyPrecedes(Array($1.kid.utf8)) }.map(\.value)), "members": .array(names.map { .object(["id": str($0), "role": str("maintainer")]) }),
            "name": str(name), "org": org.map { str($0) } ?? .null,
            "policy": .object(["classes": .array([.object(["class": str("apple-se-bio"), "user_verification": str("biometric_only")])]),
                               "freshness": .object(["clock_skew_s": str("300"), "max_validity_s": str("604800"), "max_view_age_s": str("86400")]),
                               "relays": .array(relays.map { str($0) }), "roles": .array([str("maintainer"), str("member")]),
                               "rules": .object(["chain.resolve": rule, "device.remove": rule, "genesis.change": rule, "member.add": rule]),
                               "v": str("handsal-policy/1"), "witness": witness]),
            "prev": prev.map { str($0) } ?? .null, "profile": str(profile), "v": str("handsal-genesis/1"),
        ]
        if let head { members["head"] = str(head) }
        return .object(members)
    }
}

/// The ceremony input: the closed object `{acts, device_kid, lineage}`, a line. `extra` adds members
/// a test wants the reader to refuse.
func ceremonyInput(lineage: [(doc: JValue, sigs: [String])], acts: [String] = [], deviceKid: String = Persons.key().kid,
                   extra: [String: JValue] = [:]) -> [UInt8] {
    let entries = lineage.map { JValue.object(["doc": $0.doc, "sigs": .array($0.sigs.map { str($0) })]) }
    var members: [String: JValue] = ["acts": .array(acts.map { str($0) }), "device_kid": str(deviceKid), "lineage": .array(entries)]
    for (key, value) in extra { members[key] = value }
    return ((try? Emit.subset(.object(members))) ?? []) + [0x0A]
}

func pinLine(genesis: String, org: String, spec: String = Profiles.standard.production) -> String {
    #"{"genesis":"\#(genesis)","org":"\#(org)","spec":"\#(spec)","v":"handsal-pin/1"}"# + "\n"
}

func checkAnswer(pin: String) -> JValue { .object(["pin": str(pin), "reason": str("ok"), "valid": .bool(true)]) }
/// What `sync` answers (CF-09): `ok` with the clock it stamped, or a refusal with a null clock.
let syncOk = JValue.object(["reason": str("ok"), "synced_at": str("2026-11-12T10:00:00Z")])
func syncNo(_ reason: String) -> JValue { .object(["reason": str(reason), "synced_at": .null]) }
let enrolledYes = JValue.object(["enrolled": .bool(true), "reason": str("ok")])
func enrolledNo(_ reason: String) -> JValue { .object(["enrolled": .bool(false), "reason": str(reason)]) }

/// What `genesis-aids` answers for a change (CF-03): where H lies and the kids a valid removal removed.
func aidsAnswer(head: JValue, removed: [String] = []) -> JValue {
    .object(["aids": .object(["head": head, "removed": .array(removed.sorted().map { str($0) })]), "reason": str("ok")])
}
func aidsAtTip(_ tip: String, is place: String = "tip", removed: [String] = []) -> JValue {
    aidsAnswer(head: .object(["at": str("tip"), "place": str(place), "tip": str(tip)]), removed: removed)
}
func aidsAtFork(parent: String, candidates: [String], place: String, candidate: String? = nil, removed: [String] = []) -> JValue {
    aidsAnswer(head: .object(["at": str("fork"), "candidate": candidate.map { str($0) } ?? .null, "candidates": .array(candidates.sorted().map { str($0) }),
                              "parent": str(parent), "place": str(place)]), removed: removed)
}

func docHash(_ doc: JValue) -> String { (try? Genesis.docHash(doc)) ?? "" }

func text(_ result: CeremonyResult) -> String { String(decoding: result.line, as: UTF8.self) }

/// A relay witness policy over a fresh relay key (WT-01): the kid is the thumbprint of the key.
func relayWitness() -> JValue {
    let key = Persons.key()
    guard case .object(let sign) = key.sign, case .string(let x)? = sign["x"], case .string(let y)? = sign["y"] else { return .null }
    return .object(["max_tip_age_s": str("3600"), "mode": str("relay"), "relay_kid": str(key.kid),
                    "relay_pub_jwk": .object(["crv": str("P-256"), "kty": str("EC"), "x": str(x), "y": str(y)])])
}

/// A synthetic two-edition set (the catalog has no row yet), injected through `GenesisContext(profiles:)`.
/// Neither edition lists a fixture kid unless a test says so.
enum SyntheticEditions {
    static let oldProduction = hash("synthetic old production")
    static let oldFixture = hash("synthetic old fixture")
    static let newProduction = hash("synthetic new production")
    static let newFixture = hash("synthetic new fixture")
    static let unknown = hash("an edition no catalog row names")

    static func profiles(oldKids: Set<String> = [], newKids: Set<String> = []) -> Profiles {
        Profiles(editions: [Edition(label: "old", production: oldProduction, fixture: oldFixture, fixtureKids: oldKids, registry: .standard),
                            Edition(label: "new", production: newProduction, fixture: newFixture, fixtureKids: newKids, registry: .standard)])
    }

    static func context(oldKids: Set<String> = [], newKids: Set<String> = []) -> GenesisContext {
        GenesisContext(profiles: profiles(oldKids: oldKids, newKids: newKids))
    }
}
