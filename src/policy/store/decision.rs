#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
    DenyNoMatch,
    DenyDomainMismatch,
    DenyDomainNotFound,
    DenyDomainEmpty,
    DenyRoleTokenInvalid,
    DenyInvalidParameters,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyMatch {
    pub decision: PolicyDecision,
    pub matched_role: Option<String>,
}

impl PolicyMatch {
    pub(super) fn new(decision: PolicyDecision) -> Self {
        Self {
            decision,
            matched_role: None,
        }
    }
}
