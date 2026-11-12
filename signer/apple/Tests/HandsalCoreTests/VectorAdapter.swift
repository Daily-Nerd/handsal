import HandsalCore

/// Turns one vector into the output line its anchor holds, using only the public core.
enum VectorAdapter {
    static func line(_ row: Vector) -> String {
        switch row.command {
        case "subset": return subset(row)
        case "render": return render(row)
        default: return "unsupported command \(row.command)"
        }
    }

    static func subset(_ row: Vector) -> String {
        guard case .bytes(let bytes) = row.input else { return "subset needs raw bytes" }
        switch Subset.parse(bytes, maxSize: 16384) {
        case .success: return #"{"canonical":true,"reason":"ok"}"#
        case .failure(.tooLarge): return #"{"canonical":false,"reason":"payload_too_large"}"#
        case .failure(.notCanonical): return #"{"canonical":false,"reason":"payload_not_canonical_subset"}"#
        }
    }

    /// The checker-form `render` command (CF-03): exactly `{attachments, kid, method, payload}`.
    /// A mistyped input is `malformed_input`; a rule of the profile saying no is `{"error": code}`.
    static func render(_ row: Vector) -> String {
        guard case .json(.object(let input)) = row.input, Set(input.keys) == ["attachments", "kid", "method", "payload"],
              case .object? = input["attachments"], case .string(let kid)? = input["kid"],
              case .string(let method)? = input["method"], case .object? = input["payload"],
              let attachments = input["attachments"], let payload = input["payload"] else {
            return #"{"error":"malformed_input"}"#
        }
        let result: JValue
        do {
            let out = try Render.render(RenderInput(attachments: attachments, kid: kid, method: method, payload: payload))
            result = .object(["first_line": .string(out.firstLine), "text": .string(out.text)])
        } catch let refusal as Refusal {
            result = .object(["error": .string(refusal.code)])
        } catch {
            return "unexpected error \(error)"
        }
        return String(decoding: (try? Emit.resultLine(result)) ?? [], as: UTF8.self)
    }
}
