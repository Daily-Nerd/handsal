//! Per-method facts that the registry table cannot say (ACT-13, ACT-08). One owner.

pub const DEVICE_ADD: &str = "local:handsal.device.add";
pub const DEVICE_REMOVE: &str = "local:handsal.device.remove";
pub const MEMBER_ADD: &str = "local:handsal.member.add";
pub const RESOLVE: &str = "local:handsal.chain.resolve";
pub const ENDORSE: &str = "local:handsal.act.endorse";
pub const PROMOTE: &str = "local:handsal.record.promote";
pub const GENESIS_SIGN: &str = "local:handsal.genesis.sign";
pub const APPROVE: &str = "local:handsal.request.approve";
pub const REJECT: &str = "local:handsal.request.reject";
pub const NEEDS_INFO: &str = "local:handsal.request.needs-info";

pub const PRIMARIES: [&str; 3] = [DEVICE_ADD, DEVICE_REMOVE, MEMBER_ADD];
pub const VERDICTS: [&str; 3] = [APPROVE, REJECT, NEEDS_INFO];
/// A chain primary or a resolve: what an endorsement can carry as its act.
pub const CHAIN_ACTS: [&str; 4] = [DEVICE_ADD, DEVICE_REMOVE, MEMBER_ADD, RESOLVE];

pub fn is_verdict(method: &str) -> bool {
    VERDICTS.contains(&method)
}

/// ACT-13: what the parent fields of an envelope look like for a method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentRule {
    /// both null (verdicts, record.promote, genesis.sign)
    None,
    /// `parent_receipt_hash` is a position id; the performer is null exactly for the root
    Primary,
    /// both set: the endorsed act and its performer
    Endorse,
}

pub fn parent_rule(method: &str) -> ParentRule {
    if method == ENDORSE {
        ParentRule::Endorse
    } else if PRIMARIES.contains(&method) || method == RESOLVE {
        ParentRule::Primary
    } else {
        ParentRule::None
    }
}
