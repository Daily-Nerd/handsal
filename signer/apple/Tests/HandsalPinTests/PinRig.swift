import Darwin
import Foundation
import HandsalCore
@testable import HandsalPinCore

/// What every pin helper test needs: a temporary tree that stands for `/` (the constructor's test
/// only root), owned by the current user (the stand-in for root:wheel, the reader's `owner_uid`),
/// a stub checker that answers a canned line, and the helper built by the test constructor.
final class PinRig {
    static let me = Owner(uid: getuid(), gid: getgid())

    let root: String
    let tools: String
    let owner: Owner

    var handsal: String { root + "/Library/Application Support/handsal" }
    var orgs: String { handsal + "/orgs" }
    var seen: String { tools + "/seen.json" }
    var environmentSeen: String { tools + "/env.txt" }

    /// `withHandsalDirectory`: false leaves `handsal` and `orgs` absent, so the helper creates them.
    init(owner: Owner = PinRig.me, withHandsalDirectory: Bool = true) throws {
        self.owner = owner
        let base = URL(fileURLWithPath: NSTemporaryDirectory()).resolvingSymlinksInPath().path
        let unique = base + "/handsal-pin-\(UUID().uuidString)"
        root = unique + "/root"
        tools = unique + "/tools"
        for path in [unique, root, tools] { try Self.directory(path, 0o755) }
        try Self.directory(root + "/Library", 0o755)
        try Self.directory(root + "/Library/Application Support", 0o755)
        if withHandsalDirectory {
            try Self.directory(handsal, 0o755)
            try Self.directory(orgs, 0o755)
        }
    }

    deinit { try? FileManager.default.removeItem(atPath: (root as NSString).deletingLastPathComponent) }

    static func directory(_ path: String, _ mode: mode_t) throws {
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: false)
        chmod(path, mode)
    }

    // MARK: stub checker

    /// A checker that reads its stdin into `seen.json`, records its environment and prints `answer`.
    func checker(printing answer: String, exit code: Int = 0) throws -> CheckerCommand {
        let path = tools + "/checker-\(UUID().uuidString).sh"
        let script = """
        #!/bin/sh
        /bin/cat > '\(seen)'
        /usr/bin/env > '\(environmentSeen)'
        printf '%s\\n' '\(answer)'
        exit \(code)
        """
        try script.write(toFile: path, atomically: true, encoding: .utf8)
        chmod(path, 0o755)
        return CheckerCommand(executable: path, arguments: ["genesis-check"])
    }

    func helper(_ checker: CheckerCommand) -> PinHelper { PinHelper(checker: checker, root: root, owner: owner) }

    func helper(answering answer: String, exit code: Int = 0) throws -> PinHelper { helper(try checker(printing: answer, exit: code)) }

    // MARK: pin lines and answers

    static func hashstr(_ seed: String) -> String { Encoding.hashstr(Array(seed.utf8)) }

    static func pin(org: String, genesis: String, spec: String = PinRig.hashstr("spec")) -> String {
        #"{"genesis":"\#(genesis)","org":"\#(org)","spec":"\#(spec)","v":"handsal-pin/1"}"# + "\n"
    }

    /// The checker's JCS answer for a valid lineage: the pin is a string with its closing LF escaped.
    static func validAnswer(pin: String) -> String {
        let escaped = pin.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"").replacingOccurrences(of: "\n", with: "\\n")
        return #"{"pin":"\#(escaped)","reason":"ok","valid":true}"#
    }

    static func invalidAnswer(_ reason: String) -> String { #"{"pin":null,"reason":"\#(reason)","valid":false}"# }

    /// A lineage of documents named by `names`, each `{doc: {name}, sigs: []}`, and its input line.
    static func request(names: [String], acts: [String] = []) -> [UInt8] {
        let entries = names.map { #"{"doc":{"name":"\#($0)"},"sigs":[]}"# }.joined(separator: ",")
        let list = acts.map { "\"\($0)\"" }.joined(separator: ",")
        return Array((#"{"acts":[\#(list)],"lineage":[\#(entries)]}"# + "\n").utf8)
    }

    /// Like `request(names:)`, with a `profile` on each document: `documents` is `(name, profile)` in lineage order.
    static func request(documents: [(name: String, profile: String)]) -> [UInt8] {
        let entries = documents.map { #"{"doc":{"name":"\#($0.name)","profile":"\#($0.profile)"},"sigs":[]}"# }.joined(separator: ",")
        return Array((#"{"acts":[],"lineage":[\#(entries)]}"# + "\n").utf8)
    }

    static func documentHash(named name: String) -> String { Encoding.hashstr(Array(#"{"name":"\#(name)"}"#.utf8)) }

    // MARK: files

    func pinPath(org: String) -> String { orgs + "/" + (PinLine.fileName(org: org) ?? "bad") }

    func place(_ text: String, org: String, mode: mode_t = 0o644) throws {
        let path = pinPath(org: org)
        try Data(text.utf8).write(to: URL(fileURLWithPath: path))
        chmod(path, mode)
    }

    func contents(org: String) -> String? { try? String(contentsOfFile: pinPath(org: org), encoding: .utf8) }

    func entries() -> [String] { ((try? FileManager.default.contentsOfDirectory(atPath: orgs)) ?? []).sorted() }

    func attributes(_ path: String) -> stat {
        var info = stat()
        lstat(path, &info)
        return info
    }
}

func text(_ report: PinReport) -> String { String(decoding: report.line, as: UTF8.self) }
