/// Per-method facts that the registry table cannot say (ACT-13, ACT-08). One owner.
public enum Methods {
    public static let prefix = "local:handsal."
    public static let deviceAdd = prefix + "device.add"
    public static let deviceRemove = prefix + "device.remove"
    public static let memberAdd = prefix + "member.add"
    public static let resolve = prefix + "chain.resolve"
    public static let endorse = prefix + "act.endorse"
    public static let promote = prefix + "record.promote"
    public static let decision = prefix + "decision"
    public static let genesisSign = prefix + "genesis.sign"
    public static let approve = prefix + "request.approve"
    public static let reject = prefix + "request.reject"
    public static let needsInfo = prefix + "request.needs-info"

    public static let primaries: Set<String> = [deviceAdd, deviceRemove, memberAdd]
    public static let verdicts: Set<String> = [approve, reject, needsInfo]
    /// A chain primary or a resolve: what an endorsement can carry as its act.
    public static let chainActs: Set<String> = primaries.union([resolve])

    /// ACT-13: what the parent fields of an envelope look like for a method.
    public enum ParentRule: Sendable {
        /// both null (verdicts, record.promote, decision, genesis.sign)
        case none
        /// `parent_receipt_hash` is a position id; the performer is null exactly for the root
        case primary
        /// both set: the endorsed act and its performer
        case endorse
    }

    public static func parentRule(_ method: String) -> ParentRule {
        if method == endorse { return .endorse }
        if primaries.contains(method) || method == resolve { return .primary }
        return .none
    }
}
