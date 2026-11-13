import HandsalCore

/// The helper's input (GP-21 Input): exactly one line, one JSON object with exactly the keys
/// `acts` and `lineage` (the `genesis-check` input, CF-03), then one LF.
///
/// The grammar is the canonical subset recognizer with MAX_INPUT in place of MAX_PAYLOAD. Any
/// recognizer failure (a duplicate key, more than MAX_INPUT bytes, a missing LF, bytes after the
/// LF) is `unparseable_input`; a missing, extra or mistyped key is `malformed_input`; any argument
/// is `malformed_input` (a caller-supplied name would be a second source for the org).
/// `object` is the bytes of the input without the LF: that is what the checker is given, so the
/// checker judges exactly the bytes the helper received.
struct PinRequest {
    let acts: [JValue]
    let lineage: [JValue]
    let object: [UInt8]

    static func read(arguments: [String], stdin: [UInt8]) throws -> PinRequest {
        guard arguments.isEmpty else { throw PinFailure(.malformedInput) }
        guard stdin.count <= Limits.maxInput, stdin.last == 0x0A else { throw PinFailure(.unparseableInput) }
        let body = Array(stdin.dropLast())
        // A second LF is a byte the recognizer has no place for, so it fails here too.
        guard case .success(let value) = Subset.parse(body, maxSize: Limits.maxInput) else { throw PinFailure(.unparseableInput) }
        guard case .object(let members) = value, Set(members.keys) == ["acts", "lineage"],
              case .array(let acts)? = members["acts"], case .array(let lineage)? = members["lineage"] else {
            throw PinFailure(.malformedInput)
        }
        return PinRequest(acts: acts, lineage: lineage, object: body)
    }
}
