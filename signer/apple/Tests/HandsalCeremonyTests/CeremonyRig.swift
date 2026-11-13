import CryptoKit
import Foundation
import HandsalCore
@testable import HandsalCeremonyCore

/// A scripted production checker: it answers each command from a queue, records every call, and
/// never runs anything. Running a command it was not given an answer for is a test bug, so it throws.
final class FakeChecker: CeremonyChecker, @unchecked Sendable {
    private let lock = NSLock()
    private var queues: [String: [JValue]]
    private(set) var calls: [(command: String, input: JValue)] = []

    init(_ answers: [String: [JValue]] = [:]) { queues = answers }

    func run(_ command: String, input: [UInt8]) throws -> JValue {
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
    func confirm(_ question: String) throws -> Bool {
        try lock.withLock {
            questions.append(question)
            guard !answers.isEmpty else { throw Refusal("no_display") }
            return answers.removeFirst()
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
    struct Key { let kid: String; let sign: JValue; let agree: JValue }

    static func key() -> Key {
        func point(_ key: P256.Signing.PublicKey) -> (x: String, y: String) {
            let raw = [UInt8](key.x963Representation)
            return (Encoding.base64url(Array(raw[1..<33])), Encoding.base64url(Array(raw[33..<65])))
        }
        let sign = point(P256.Signing.PrivateKey().publicKey), agree = point(P256.Signing.PrivateKey().publicKey)
        return Key(kid: Encoding.thumbprint(x: sign.x, y: sign.y), sign: .object(["x": str(sign.x), "y": str(sign.y)]),
                   agree: .object(["x": str(agree.x), "y": str(agree.y)]))
    }
}

struct Docs {
    var names: [String] = ["alice", "bob", "carol"]
    /// persons needed by every rule; 2 of 3 holders leaves a spare, 2 of 2 does not.
    var persons = "2"
    var devicesPerPerson = 1
    var profile = Profiles.standard.production
    var witness: JValue = .object(["mode": str("none")])
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
                               "roles": .array([str("maintainer"), str("member")]),
                               "rules": .object(["chain.resolve": rule, "device.remove": rule, "genesis.change": rule, "member.add": rule]),
                               "v": str("handsal-policy/1"), "witness": witness]),
            "prev": prev.map { str($0) } ?? .null, "profile": str(profile), "v": str("handsal-genesis/1"),
        ]
        if let head { members["head"] = str(head) }
        return .object(members)
    }
}

/// The ceremony input: `{acts, device_kid, lineage, synced_at, tip_statement}`, a line.
func ceremonyInput(lineage: [(doc: JValue, sigs: [String])], acts: [String] = [], deviceKid: String = Persons.key().kid) -> [UInt8] {
    let entries = lineage.map { JValue.object(["doc": $0.doc, "sigs": .array($0.sigs.map { str($0) })]) }
    let value = JValue.object(["acts": .array(acts.map { str($0) }), "device_kid": str(deviceKid), "lineage": .array(entries),
                               "synced_at": str("2026-11-12T10:00:00Z"), "tip_statement": .null])
    return ((try? Emit.subset(value)) ?? []) + [0x0A]
}

func pinLine(genesis: String, org: String, spec: String = Profiles.standard.production) -> String {
    #"{"genesis":"\#(genesis)","org":"\#(org)","spec":"\#(spec)","v":"handsal-pin/1"}"# + "\n"
}

func checkAnswer(pin: String) -> JValue { .object(["pin": str(pin), "reason": str("ok"), "valid": .bool(true)]) }
let enrolledYes = JValue.object(["enrolled": .bool(true), "reason": str("ok")])
func enrolledNo(_ reason: String) -> JValue { .object(["enrolled": .bool(false), "reason": str(reason)]) }

func docHash(_ doc: JValue) -> String { (try? Genesis.docHash(doc)) ?? "" }

func text(_ result: CeremonyResult) -> String { String(decoding: result.line, as: UTF8.self) }

/// A relay witness policy over a fresh relay key (WT-01): the kid is the thumbprint of the key.
func relayWitness() -> JValue {
    let key = Persons.key()
    guard case .object(let sign) = key.sign, case .string(let x)? = sign["x"], case .string(let y)? = sign["y"] else { return .null }
    return .object(["max_tip_age_s": str("3600"), "mode": str("relay"), "relay_kid": str(key.kid),
                    "relay_pub_jwk": .object(["crv": str("P-256"), "kty": str("EC"), "x": str(x), "y": str(y)])])
}
