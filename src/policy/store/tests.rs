use super::*;
use crate::models::{Assertion, AssertionEffect, Policy, PolicyData};
use crate::models::{
    AssertionCondition, AssertionConditionData, AssertionConditionOperator, AssertionConditions,
};
use std::collections::HashMap;

const ENFORCEMENT_STATE_KEY: &str = "enforcementState";
const ENFORCEMENT_STATE_ENFORCE: &str = "ENFORCE";

#[test]
fn policy_store_allows_and_denies() {
    let policy = Policy {
        name: "sports:policy.test".to_string(),
        modified: None,
        assertions: vec![
            Assertion {
                role: "sports:role.reader".to_string(),
                resource: "sports:resource.read".to_string(),
                action: "read".to_string(),
                effect: Some(AssertionEffect::Allow),
                id: None,
                case_sensitive: None,
                conditions: None,
            },
            Assertion {
                role: "sports:role.reader".to_string(),
                resource: "sports:resource.secret".to_string(),
                action: "read".to_string(),
                effect: Some(AssertionEffect::Deny),
                id: None,
                case_sensitive: None,
                conditions: None,
            },
        ],
        case_sensitive: None,
        version: None,
        active: None,
        description: None,
        tags: None,
        resource_ownership: None,
    };

    let policy_data = PolicyData {
        domain: "sports".to_string(),
        policies: vec![policy],
    };

    let mut store = PolicyStore::new();
    store.insert(policy_data);

    let roles = vec!["reader".to_string()];
    let decision = store.allow_action("sports", &roles, "read", "sports:resource.read");
    assert_eq!(decision.decision, PolicyDecision::Allow);

    let decision = store.allow_action("sports", &roles, "read", "sports:resource.secret");
    assert_eq!(decision.decision, PolicyDecision::Deny);
}

fn mk_assertion(role: &str, resource: &str, action: &str, effect: AssertionEffect) -> Assertion {
    Assertion {
        role: role.to_string(),
        resource: resource.to_string(),
        action: action.to_string(),
        effect: Some(effect),
        id: None,
        case_sensitive: None,
        conditions: None,
    }
}

fn mk_policy(name: &str, active: Option<bool>, assertions: Vec<Assertion>) -> Policy {
    Policy {
        name: name.to_string(),
        modified: None,
        assertions,
        case_sensitive: None,
        version: None,
        active,
        description: None,
        tags: None,
        resource_ownership: None,
    }
}

#[test]
fn policy_store_allows_colon_resource_when_single_domain_loaded() {
    let policy = mk_policy(
        "sports:policy.colon-resource",
        None,
        vec![mk_assertion(
            "sports:role.reader",
            "other:resource.read",
            "read",
            AssertionEffect::Allow,
        )],
    );
    let policy_data = PolicyData {
        domain: "sports".to_string(),
        policies: vec![policy],
    };

    let mut store = PolicyStore::new();
    store.insert(policy_data);

    let roles = vec!["reader".to_string()];
    let decision = store.allow_action("sports", &roles, "read", "other:resource.read");
    assert_eq!(decision.decision, PolicyDecision::Allow);
}

#[test]
fn policy_store_denies_domain_mismatch_when_multiple_domains_loaded() {
    let policy = mk_policy(
        "sports:policy.colon-resource",
        None,
        vec![mk_assertion(
            "sports:role.reader",
            "other:resource.read",
            "read",
            AssertionEffect::Allow,
        )],
    );
    let policy_data = PolicyData {
        domain: "sports".to_string(),
        policies: vec![policy],
    };
    let extra_domain = PolicyData {
        domain: "weather".to_string(),
        policies: vec![],
    };

    let mut store = PolicyStore::new();
    store.insert(policy_data);
    store.insert(extra_domain);

    let roles = vec!["reader".to_string()];
    let decision = store.allow_action("sports", &roles, "read", "other:resource.read");
    assert_eq!(decision.decision, PolicyDecision::DenyDomainMismatch);
}

#[test]
fn policy_store_skips_inactive_policies() {
    let inactive_policy = mk_policy(
        "sports:policy.inactive",
        Some(false),
        vec![mk_assertion(
            "sports:role.reader",
            "sports:resource.read",
            "read",
            AssertionEffect::Allow,
        )],
    );

    let active_policy = mk_policy(
        "sports:policy.active",
        Some(true),
        vec![mk_assertion(
            "sports:role.reader",
            "sports:resource.write",
            "write",
            AssertionEffect::Allow,
        )],
    );
    let default_active_policy = mk_policy(
        "sports:policy.default-active",
        None,
        vec![mk_assertion(
            "sports:role.reader",
            "sports:resource.list",
            "list",
            AssertionEffect::Allow,
        )],
    );
    let policy_data = PolicyData {
        domain: "sports".to_string(),
        policies: vec![inactive_policy, active_policy, default_active_policy],
    };

    let mut store = PolicyStore::new();
    store.insert(policy_data);

    let roles = vec!["reader".to_string()];
    let decision = store.allow_action("sports", &roles, "read", "sports:resource.read");
    assert_eq!(decision.decision, PolicyDecision::DenyNoMatch);

    let decision = store.allow_action("sports", &roles, "write", "sports:resource.write");
    assert_eq!(decision.decision, PolicyDecision::Allow);

    let decision = store.allow_action("sports", &roles, "list", "sports:resource.list");
    assert_eq!(decision.decision, PolicyDecision::Allow);
}

#[test]
fn policy_store_ignores_conditions_and_case_sensitive_fields() {
    let mut conditions = HashMap::new();
    conditions.insert(
        ENFORCEMENT_STATE_KEY.to_string(),
        AssertionConditionData {
            operator: AssertionConditionOperator::Equals,
            value: ENFORCEMENT_STATE_ENFORCE.to_string(),
        },
    );
    let assertion_conditions = AssertionConditions {
        conditions_list: vec![AssertionCondition {
            id: Some(1),
            conditions_map: conditions,
        }],
    };

    let policy = Policy {
        name: "sports:policy.case".to_string(),
        modified: None,
        assertions: vec![Assertion {
            role: "sports:role.reader".to_string(),
            resource: "Sports:Resource.Read".to_string(),
            action: "Read".to_string(),
            effect: Some(AssertionEffect::Allow),
            id: None,
            case_sensitive: Some(true),
            conditions: Some(assertion_conditions),
        }],
        case_sensitive: Some(true),
        version: None,
        active: None,
        description: None,
        tags: None,
        resource_ownership: None,
    };

    let policy_data = PolicyData {
        domain: "sports".to_string(),
        policies: vec![policy],
    };

    let mut store = PolicyStore::new();
    store.insert(policy_data);

    let roles = vec!["reader".to_string()];
    let decision = store.allow_action("sports", &roles, "READ", "sports:resource.read");
    assert_eq!(decision.decision, PolicyDecision::Allow);

    let decision = store.allow_action("sports", &roles, "Read", "Sports:Resource.Read");
    assert_eq!(decision.decision, PolicyDecision::Allow);
}

#[test]
fn policy_store_defaults_case_insensitive() {
    let policy = Policy {
        name: "sports:policy.default-case".to_string(),
        modified: None,
        assertions: vec![Assertion {
            role: "sports:role.reader".to_string(),
            resource: "Sports:Resource.Read".to_string(),
            action: "Read".to_string(),
            effect: Some(AssertionEffect::Allow),
            id: None,
            case_sensitive: None,
            conditions: None,
        }],
        case_sensitive: None,
        version: None,
        active: None,
        description: None,
        tags: None,
        resource_ownership: None,
    };

    let policy_data = PolicyData {
        domain: "sports".to_string(),
        policies: vec![policy],
    };

    let mut store = PolicyStore::new();
    store.insert(policy_data);

    let roles = vec!["reader".to_string()];
    let decision = store.allow_action("sports", &roles, "READ", "sports:resource.read");
    assert_eq!(decision.decision, PolicyDecision::Allow);
}

#[test]
fn policy_store_assertion_overrides_policy_case_sensitive() {
    let policy = Policy {
        name: "sports:policy.override-case".to_string(),
        modified: None,
        assertions: vec![Assertion {
            role: "sports:role.reader".to_string(),
            resource: "Sports:Resource.Read".to_string(),
            action: "Read".to_string(),
            effect: Some(AssertionEffect::Allow),
            id: None,
            case_sensitive: Some(false),
            conditions: None,
        }],
        case_sensitive: Some(true),
        version: None,
        active: None,
        description: None,
        tags: None,
        resource_ownership: None,
    };

    let policy_data = PolicyData {
        domain: "sports".to_string(),
        policies: vec![policy],
    };

    let mut store = PolicyStore::new();
    store.insert(policy_data);

    let roles = vec!["reader".to_string()];
    let decision = store.allow_action("sports", &roles, "READ", "sports:resource.read");
    assert_eq!(decision.decision, PolicyDecision::Allow);
}

#[test]
fn policy_store_matches_case_insensitive_condition_key() {
    let mut conditions = HashMap::new();
    conditions.insert(
        "EnforcementState".to_string(),
        AssertionConditionData {
            operator: AssertionConditionOperator::Equals,
            value: ENFORCEMENT_STATE_ENFORCE.to_string(),
        },
    );
    let assertion_conditions = AssertionConditions {
        conditions_list: vec![AssertionCondition {
            id: Some(1),
            conditions_map: conditions,
        }],
    };

    let policy = Policy {
        name: "sports:policy.case-insensitive".to_string(),
        modified: None,
        assertions: vec![Assertion {
            role: "sports:role.reader".to_string(),
            resource: "sports:resource.read".to_string(),
            action: "read".to_string(),
            effect: Some(AssertionEffect::Allow),
            id: None,
            case_sensitive: None,
            conditions: Some(assertion_conditions),
        }],
        case_sensitive: None,
        version: None,
        active: None,
        description: None,
        tags: None,
        resource_ownership: None,
    };

    let policy_data = PolicyData {
        domain: "sports".to_string(),
        policies: vec![policy],
    };

    let mut store = PolicyStore::new();
    store.insert(policy_data);

    let roles = vec!["reader".to_string()];
    let decision = store.allow_action("sports", &roles, "read", "sports:resource.read");
    assert_eq!(decision.decision, PolicyDecision::Allow);
}

#[test]
fn policy_store_ignores_non_enforced_conditions() {
    let mut conditions = HashMap::new();
    conditions.insert(
        ENFORCEMENT_STATE_KEY.to_string(),
        AssertionConditionData {
            operator: AssertionConditionOperator::Equals,
            value: "REPORT".to_string(),
        },
    );
    let assertion_conditions = AssertionConditions {
        conditions_list: vec![AssertionCondition {
            id: Some(1),
            conditions_map: conditions,
        }],
    };

    let policy = Policy {
        name: "sports:policy.conditions".to_string(),
        modified: None,
        assertions: vec![Assertion {
            role: "sports:role.reader".to_string(),
            resource: "sports:resource.read".to_string(),
            action: "read".to_string(),
            effect: Some(AssertionEffect::Allow),
            id: None,
            case_sensitive: None,
            conditions: Some(assertion_conditions),
        }],
        case_sensitive: None,
        version: None,
        active: None,
        description: None,
        tags: None,
        resource_ownership: None,
    };

    let policy_data = PolicyData {
        domain: "sports".to_string(),
        policies: vec![policy],
    };

    let mut store = PolicyStore::new();
    store.insert(policy_data);

    let roles = vec!["reader".to_string()];
    let decision = store.allow_action("sports", &roles, "read", "sports:resource.read");
    assert_eq!(decision.decision, PolicyDecision::Allow);
}

#[test]
fn policy_store_ignores_empty_conditions_list() {
    let assertion_conditions = AssertionConditions {
        conditions_list: Vec::new(),
    };

    let policy = Policy {
        name: "sports:policy.empty-conditions".to_string(),
        modified: None,
        assertions: vec![Assertion {
            role: "sports:role.reader".to_string(),
            resource: "sports:resource.read".to_string(),
            action: "read".to_string(),
            effect: Some(AssertionEffect::Allow),
            id: None,
            case_sensitive: None,
            conditions: Some(assertion_conditions),
        }],
        case_sensitive: None,
        version: None,
        active: None,
        description: None,
        tags: None,
        resource_ownership: None,
    };

    let policy_data = PolicyData {
        domain: "sports".to_string(),
        policies: vec![policy],
    };

    let mut store = PolicyStore::new();
    store.insert(policy_data);

    let roles = vec!["reader".to_string()];
    let decision = store.allow_action("sports", &roles, "read", "sports:resource.read");
    assert_eq!(decision.decision, PolicyDecision::Allow);
}

#[test]
fn policy_store_ignores_unsupported_condition_key() {
    let mut conditions = HashMap::new();
    conditions.insert(
        "unsupportedKey".to_string(),
        AssertionConditionData {
            operator: AssertionConditionOperator::Equals,
            value: "ENFORCE".to_string(),
        },
    );
    let assertion_conditions = AssertionConditions {
        conditions_list: vec![AssertionCondition {
            id: Some(1),
            conditions_map: conditions,
        }],
    };

    let policy = Policy {
        name: "sports:policy.unknown-condition".to_string(),
        modified: None,
        assertions: vec![Assertion {
            role: "sports:role.reader".to_string(),
            resource: "sports:resource.read".to_string(),
            action: "read".to_string(),
            effect: Some(AssertionEffect::Allow),
            id: None,
            case_sensitive: None,
            conditions: Some(assertion_conditions),
        }],
        case_sensitive: None,
        version: None,
        active: None,
        description: None,
        tags: None,
        resource_ownership: None,
    };

    let policy_data = PolicyData {
        domain: "sports".to_string(),
        policies: vec![policy],
    };

    let mut store = PolicyStore::new();
    store.insert(policy_data);

    let roles = vec!["reader".to_string()];
    let decision = store.allow_action("sports", &roles, "read", "sports:resource.read");
    assert_eq!(decision.decision, PolicyDecision::Allow);
}

#[test]
fn policy_store_ignores_mixed_supported_and_unsupported_conditions() {
    let mut conditions = HashMap::new();
    conditions.insert(
        ENFORCEMENT_STATE_KEY.to_string(),
        AssertionConditionData {
            operator: AssertionConditionOperator::Equals,
            value: ENFORCEMENT_STATE_ENFORCE.to_string(),
        },
    );
    conditions.insert(
        "unsupportedKey".to_string(),
        AssertionConditionData {
            operator: AssertionConditionOperator::Equals,
            value: ENFORCEMENT_STATE_ENFORCE.to_string(),
        },
    );
    let assertion_conditions = AssertionConditions {
        conditions_list: vec![AssertionCondition {
            id: Some(1),
            conditions_map: conditions,
        }],
    };

    let policy = Policy {
        name: "sports:policy.mixed-conditions".to_string(),
        modified: None,
        assertions: vec![Assertion {
            role: "sports:role.reader".to_string(),
            resource: "sports:resource.read".to_string(),
            action: "read".to_string(),
            effect: Some(AssertionEffect::Allow),
            id: None,
            case_sensitive: None,
            conditions: Some(assertion_conditions),
        }],
        case_sensitive: None,
        version: None,
        active: None,
        description: None,
        tags: None,
        resource_ownership: None,
    };

    let policy_data = PolicyData {
        domain: "sports".to_string(),
        policies: vec![policy],
    };

    let mut store = PolicyStore::new();
    store.insert(policy_data);

    let roles = vec!["reader".to_string()];
    let decision = store.allow_action("sports", &roles, "read", "sports:resource.read");
    assert_eq!(decision.decision, PolicyDecision::Allow);
}

#[test]
fn policy_store_matches_later_condition_map() {
    let mut first_conditions = HashMap::new();
    first_conditions.insert(
        ENFORCEMENT_STATE_KEY.to_string(),
        AssertionConditionData {
            operator: AssertionConditionOperator::Equals,
            value: "REPORT".to_string(),
        },
    );
    let mut second_conditions = HashMap::new();
    second_conditions.insert(
        ENFORCEMENT_STATE_KEY.to_string(),
        AssertionConditionData {
            operator: AssertionConditionOperator::Equals,
            value: ENFORCEMENT_STATE_ENFORCE.to_string(),
        },
    );
    let assertion_conditions = AssertionConditions {
        conditions_list: vec![
            AssertionCondition {
                id: Some(1),
                conditions_map: first_conditions,
            },
            AssertionCondition {
                id: Some(2),
                conditions_map: second_conditions,
            },
        ],
    };

    let policy = Policy {
        name: "sports:policy.multi-conditions".to_string(),
        modified: None,
        assertions: vec![Assertion {
            role: "sports:role.reader".to_string(),
            resource: "sports:resource.read".to_string(),
            action: "read".to_string(),
            effect: Some(AssertionEffect::Allow),
            id: None,
            case_sensitive: None,
            conditions: Some(assertion_conditions),
        }],
        case_sensitive: None,
        version: None,
        active: None,
        description: None,
        tags: None,
        resource_ownership: None,
    };

    let policy_data = PolicyData {
        domain: "sports".to_string(),
        policies: vec![policy],
    };

    let mut store = PolicyStore::new();
    store.insert(policy_data);

    let roles = vec!["reader".to_string()];
    let decision = store.allow_action("sports", &roles, "read", "sports:resource.read");
    assert_eq!(decision.decision, PolicyDecision::Allow);
}

#[test]
fn policy_store_skips_empty_map_and_matches_next() {
    let empty_conditions = HashMap::new();
    let mut matching_conditions = HashMap::new();
    matching_conditions.insert(
        ENFORCEMENT_STATE_KEY.to_string(),
        AssertionConditionData {
            operator: AssertionConditionOperator::Equals,
            value: ENFORCEMENT_STATE_ENFORCE.to_string(),
        },
    );
    let assertion_conditions = AssertionConditions {
        conditions_list: vec![
            AssertionCondition {
                id: Some(1),
                conditions_map: empty_conditions,
            },
            AssertionCondition {
                id: Some(2),
                conditions_map: matching_conditions,
            },
        ],
    };

    let policy = Policy {
        name: "sports:policy.empty-map".to_string(),
        modified: None,
        assertions: vec![Assertion {
            role: "sports:role.reader".to_string(),
            resource: "sports:resource.read".to_string(),
            action: "read".to_string(),
            effect: Some(AssertionEffect::Allow),
            id: None,
            case_sensitive: None,
            conditions: Some(assertion_conditions),
        }],
        case_sensitive: None,
        version: None,
        active: None,
        description: None,
        tags: None,
        resource_ownership: None,
    };

    let policy_data = PolicyData {
        domain: "sports".to_string(),
        policies: vec![policy],
    };

    let mut store = PolicyStore::new();
    store.insert(policy_data);

    let roles = vec!["reader".to_string()];
    let decision = store.allow_action("sports", &roles, "read", "sports:resource.read");
    assert_eq!(decision.decision, PolicyDecision::Allow);
}
