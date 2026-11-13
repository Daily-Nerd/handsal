/// The text of a genesis document as a person reads it (RN-08, RN-10), for a tool that shows it
/// outside a prompt: the enrollment ceremony. The same two functions the signer's render of a
/// `genesis.sign` is made of, so the ceremony and the signing devices cannot word it differently.
extension Render {
    /// Line 1 of the `genesis.sign` prompt and the method lines of the document: in full for an
    /// original (`previous` nil), as a difference from `previous` for a change.
    /// Both documents must be valid by themselves (`Genesis.checkAlone`), else the refusal's code.
    public static func genesisText(document: JValue, previous: JValue?,
                                   context: GenesisContext = GenesisContext()) throws -> (firstLine: String, lines: [String]) {
        try Genesis.checkAlone(document, context)
        let doc = try RenderGenesis.read(document)
        var before: RenderGenesis.Doc?
        if let previous {
            try Genesis.checkAlone(previous, context)
            before = try RenderGenesis.read(previous)
        }
        return (try RenderGenesis.summary(doc, before), try RenderGenesis.lines(doc, before))
    }
}
