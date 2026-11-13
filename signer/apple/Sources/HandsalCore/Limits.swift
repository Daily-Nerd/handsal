/// The constants of section 2.3, read from the registry. `spec/registry.json` is the one owner:
/// `Registry.standard` is its Swift form (and `RegistryGuardTests` compares it with the file), and
/// every limit here is looked up in it, so no number is written twice.
public enum Limits {
    /// Every signed or hashed value: payload, header, genesis document.
    public static var maxPayload: Int { Registry.standard.number("MAX_PAYLOAD") }
    public static var maxDepth: Int { Registry.standard.number("MAX_DEPTH") }
    /// The bytes a signer reads from its input channel.
    public static var maxInput: Int { Registry.standard.number("MAX_INPUT") }
    public static var maxExpiresInS: Int { Registry.standard.number("MAX_EXPIRES_IN_S") }
    public static var line1Max: Int { Registry.standard.number("render_line_1.max") }
    public static var lineMax: Int { Registry.standard.number("render_line.max") }
    public static var wrapSegment: Int { Registry.standard.number("render_line.wrap_segment_max") }
    public static var maxLines: Int { Registry.standard.number("render_length.max") }
    public static var blockMaxBytes: Int { Registry.standard.number("request_and_record_block.max_source_bytes") }
    public static var blockMaxLines: Int { Registry.standard.number("request_and_record_block.max_block_lines") }
    public static var blockLineBytes: Int { Registry.standard.number("request_and_record_block.max_escaped_bytes_per_line") }
}
