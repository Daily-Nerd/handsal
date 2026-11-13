import HandsalCore

/// What the ceremony talks to, as three ports. The ceremony is a procedure (SG-12): its decisions
/// are in `Ceremony`, and everything it touches outside itself is one of these, so every step is
/// testable without a terminal, a checker or `sudo`.

/// The production checker at its SG-14 path (CF-03, CF-08). `command` is `genesis-check`, `fold` or
/// `enrolled`; `input` is the command's one JSON object, and the answer is the parsed result line.
/// A checker that cannot be run, or answers anything but one result line, throws `internal`.
public protocol CeremonyChecker: Sendable {
    func run(_ command: String, input: [UInt8]) throws -> JValue
}

/// What came back from one run of the pin helper through `/usr/bin/sudo -k` (GP-12, GP-21): its exit
/// code and what it wrote to stdout. Exit 1 with no line means the helper never ran.
public struct HelperReply: Equatable, Sendable {
    public let exit: Int32
    public let output: [UInt8]
    public init(exit: Int32, output: [UInt8]) { self.exit = exit; self.output = output }
}

/// The channel to the pin helper: one call, one input line (GP-21), one reply.
public protocol HelperChannel: Sendable {
    func submit(_ line: [UInt8]) throws -> HelperReply
}

/// The person at the terminal: what the ceremony shows (never on stdout) and the one question it
/// asks. No terminal is `no_display` (SG-07).
public protocol Console: Sendable {
    func show(_ text: String) throws
    func confirm(_ question: String) throws -> Bool
}

/// The outcome of a run, and the one JCS line the ceremony writes: `{"reason":R,"written":W}`.
/// `written` is `yes` once the helper reported a completed write, `no` when nothing was written,
/// and `unknown` when the helper's report could not be trusted. Exit codes: 0 pinned and enrolled;
/// 1 refused or stopped before any write; 2 input rejected; 3 failed at or after the write (a
/// pin that was written stays, GP-21); 4 no terminal.
public struct CeremonyResult: Equatable, Sendable {
    public let reason: String
    public let written: String
    public let exit: Int32

    public init(reason: String, written: String, exit: Int32) { self.reason = reason; self.written = written; self.exit = exit }

    public var line: [UInt8] {
        let value = JValue.object(["reason": .string(reason), "written": .string(written)])
        return (try? Emit.resultLine(value)) ?? Array(#"{"reason":"internal","written":"unknown"}"#.utf8)
    }

    public var outcome: Outcome { Outcome(exit: exit, line: line) }
}

/// A step that ends the ceremony.
struct Stop: Error {
    let result: CeremonyResult

    static func refused(_ code: String) -> Stop { Stop(result: CeremonyResult(reason: code, written: "no", exit: 1)) }
    static func input(_ code: String) -> Stop { Stop(result: CeremonyResult(reason: code, written: "no", exit: 2)) }
    static func failedWrite(_ code: String) -> Stop { Stop(result: CeremonyResult(reason: code, written: "no", exit: 3)) }
    static func untrustedReport() -> Stop { Stop(result: CeremonyResult(reason: "helper_report_invalid", written: "unknown", exit: 3)) }
    static func afterWrite(_ code: String) -> Stop { Stop(result: CeremonyResult(reason: code, written: "yes", exit: 3)) }
    static func noTerminal() -> Stop { Stop(result: CeremonyResult(reason: "no_display", written: "no", exit: 4)) }
}
