public struct RenderInput: Sendable {
    public var attachments: JValue
    public var kid: String
    public var method: String
    public var payload: JValue
    public init(attachments: JValue, kid: String, method: String, payload: JValue) {
        self.attachments = attachments
        self.kid = kid
        self.method = method
        self.payload = payload
    }
}

public struct Rendered: Equatable, Sendable {
    public let firstLine: String
    public let text: String
    public init(firstLine: String, text: String) { self.firstLine = firstLine; self.text = text }
}

/// The render core (RN-01, RN-02, RN-03, RN-06): short forms, the layout frame and the refusals.
///
/// The render is a pure function of signed bytes plus the attachments bound to them: ASCII, no
/// locale, no clock, no I/O. `frame` is the one place that lays lines out, wraps them and counts
/// them against 72; the signer and the fold's genesis size check both go through it.
/// Failure mode: a `Refusal` carrying a code of section 11, never a partial render.
public enum Render {
    static func group(_ text: [UInt8]) -> String {
        var out: [UInt8] = []
        for (index, byte) in text.enumerated() {
            if index > 0, index % 4 == 0 { out.append(UInt8(ascii: "-")) }
            out.append(byte)
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// The 12 characters after the constant `uEi` of a hashstr, grouped `xxxx-xxxx-xxxx` (section 2.1).
    public static func hash12(_ value: String) -> String { group(Array(Array(value.utf8).dropFirst(3).prefix(12))) }

    /// The first 12 characters of a kid, grouped like `hash12`.
    public static func kid12(_ value: String) -> String { group(Array(Array(value.utf8).prefix(12))) }

    /// A free field in line 1: as is up to 12 characters, else its first 11 and `~` (RN-03).
    public static func cut12(_ value: String) -> String { cut(value, to: 11, ifLongerThan: 12) }

    /// `text` as is up to `size` bytes, else its first `size` bytes and `~` (RN-03).
    public static func cut(_ text: String, to size: Int) -> String { cut(text, to: size, ifLongerThan: size) }

    private static func cut(_ text: String, to size: Int, ifLongerThan limit: Int) -> String {
        let bytes = Array(text.utf8)
        return bytes.count <= limit ? text : String(decoding: bytes.prefix(size), as: UTF8.self) + "~"
    }

    /// A line of at most 100 bytes as is; a longer one in segments of at most 98 bytes, each
    /// continuation prefixed `+ `, so no signed byte is hidden (RN-02).
    public static func wrap(_ line: String) -> [String] {
        let bytes = Array(line.utf8)
        guard bytes.count > Limits.lineMax else { return [line] }
        var out = [String(decoding: bytes.prefix(Limits.wrapSegment), as: UTF8.self)]
        var index = Limits.wrapSegment
        while index < bytes.count {
            out.append("+ " + String(decoding: bytes[index..<min(index + Limits.wrapSegment, bytes.count)], as: UTF8.self))
            index += Limits.wrapSegment
        }
        return out
    }

    /// The `Rendered` of RN-02: line 1, `Method`, `Org`, `Signer`, the method lines `body`, `Signed at`,
    /// `Expires`, `Parent`, `Head`, and `Sender: not proven` for verdicts. A render over 72 lines is
    /// `render_refused`. `org`, `parent` and `head` are hashstrs shown as `hash12`.
    public static func frame(first: String, method: String, org: String, performer: String, kid: String, body: [String],
                             ts: String, expires: String?, parent: String?, head: String?, sender: Bool) throws -> Rendered {
        var lines = ["Method: " + method, "Org: " + hash12(org), "Signer: \(performer) key \(kid12(kid))"]
        lines.append(contentsOf: body)
        lines.append("Signed at: " + ts)
        if let expires { lines.append("Expires: " + expires) }
        if let parent { lines.append("Parent: " + hash12(parent)) }
        if let head { lines.append("Head: " + hash12(head)) }
        if sender { lines.append("Sender: not proven") }
        let out = [first] + lines.flatMap(wrap)
        guard out.count <= Limits.maxLines else { throw Refusal("render_refused") }
        return Rendered(firstLine: first, text: out.joined(separator: "\n") + "\n")
    }
}
