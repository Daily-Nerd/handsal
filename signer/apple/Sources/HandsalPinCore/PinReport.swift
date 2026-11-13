import HandsalCore

/// The one line the pin helper writes, and its exit code (GP-21 Output).
///
/// `{"inner_reason":I,"reason":R,"written":W}`: R is one of the cases below, I the reason the
/// checker's `genesis-check` returned when step 1 ran (`ok` when valid), else null, W is `yes` iff
/// the rename completed. The exit code follows R, so a caller can tell a report that was tampered
/// with on the channel from one that was not (the ceremony accepts only a line whose R matches the
/// exit code).
/// Invariant: `written` is true only on `ok`. A failure before the rename writes nothing.
public enum PinReason: String, Sendable, CaseIterable {
    case ok
    case malformedInput = "malformed_input"
    case unparseableInput = "unparseable_input"
    case pinInvalid = "pin_invalid"
    case pinOwner = "pin_owner"
    case pinMalformed = "pin_malformed"
    case pinRollback = "pin_rollback"
    case `internal` = "internal"

    /// 0 `ok`; 2 `malformed_input`, `unparseable_input`; 3 `pin_invalid`, `pin_owner`, `pin_malformed`,
    /// `pin_rollback`; 5 `internal`. Exit 1 with no line means the helper never ran (sudo or UAC).
    public var exit: Int32 {
        switch self {
        case .ok: return 0
        case .malformedInput, .unparseableInput: return 2
        case .pinInvalid, .pinOwner, .pinMalformed, .pinRollback: return 3
        case .internal: return 5
        }
    }
}

public struct PinReport: Equatable, Sendable {
    public let reason: PinReason
    public let inner: String?
    public let written: Bool

    public init(reason: PinReason, inner: String? = nil, written: Bool = false) {
        self.reason = reason; self.inner = inner; self.written = written
    }

    public var exit: Int32 { reason.exit }

    /// The JCS line, without its closing LF (`ProcessIO.finish` adds it).
    public var line: [UInt8] {
        let value = JValue.object(["inner_reason": inner.map { .string($0) } ?? .null,
                                   "reason": .string(reason.rawValue),
                                   "written": .string(written ? "yes" : "no")])
        // A result line never fails to emit: three strings and a null.
        return (try? Emit.resultLine(value)) ?? Array(#"{"inner_reason":null,"reason":"internal","written":"no"}"#.utf8)
    }

    public var outcome: Outcome { Outcome(exit: exit, line: line) }
}

/// A step of the helper that failed: the reason it reports and the checker's reason, when it ran.
struct PinFailure: Error {
    let reason: PinReason
    let inner: String?
    init(_ reason: PinReason, inner: String? = nil) { self.reason = reason; self.inner = inner }
}

extension PinReport {
    /// The report of a helper run from what the run produced: its stdout bytes and its exit code,
    /// or nil. Only a line that is exactly one JCS report followed by one LF, whose reason is one the
    /// helper has and whose exit code is that reason's, is a report: anything else is a line that
    /// nobody can trust, and the caller decides what is pinned by asking `enrolled`.
    /// `written` is `yes` iff the reason is `ok` (an `ok` has an inner reason: the checker ran).
    public static func read(output: [UInt8], exit: Int32) -> PinReport? {
        var reader = JCSLine(bytes: output)
        guard let members = reader.object(), Set(members.keys) == ["inner_reason", "reason", "written"],
              case .string(let name)? = members["reason"], let reason = PinReason(rawValue: name), reason.exit == exit,
              case .string(let written)? = members["written"], written == (reason == .ok ? "yes" : "no") else { return nil }
        let inner: String?
        switch members["inner_reason"] {
        case .null?: inner = nil
        case .string(let code)?: inner = code
        default: return nil
        }
        guard reason != .ok || inner == "ok" else { return nil }
        return PinReport(reason: reason, inner: inner, written: reason == .ok)
    }
}
