use crate::models::{AssertionConditionData, AssertionConditionOperator, AssertionConditions};
use log::warn;
use std::collections::HashMap;

pub(super) const ENFORCEMENT_STATE_KEY: &str = "enforcementState";
pub(super) const ENFORCEMENT_STATE_ENFORCE: &str = "ENFORCE";

// Matching semantics:
// - empty list => non-match (explicit conditions block must contain at least one map)
// - list => OR across maps
// - map => AND across keys
// - empty maps are skipped
pub(super) fn assertion_conditions_match(conditions: &AssertionConditions) -> bool {
    if conditions.conditions_list.is_empty() {
        return false;
    }

    for condition in &conditions.conditions_list {
        if condition.conditions_map.is_empty() {
            continue;
        }
        if condition_map_matches(&condition.conditions_map) {
            return true;
        }
    }

    false
}

fn condition_map_matches(conditions: &HashMap<String, AssertionConditionData>) -> bool {
    for (key, data) in conditions {
        if !condition_matches(key, data) {
            return false;
        }
    }
    true
}

fn condition_matches(key: &str, data: &AssertionConditionData) -> bool {
    if key.eq_ignore_ascii_case(ENFORCEMENT_STATE_KEY) {
        if matches!(data.operator, AssertionConditionOperator::Equals) {
            data.value.eq_ignore_ascii_case(ENFORCEMENT_STATE_ENFORCE)
        } else {
            false
        }
    } else {
        false
    }
}

fn condition_key_supported(key: &str, data: &AssertionConditionData) -> bool {
    key.eq_ignore_ascii_case(ENFORCEMENT_STATE_KEY)
        && matches!(data.operator, AssertionConditionOperator::Equals)
}

pub(super) fn validate_assertion_conditions(
    conditions: &AssertionConditions,
    policy_name: &str,
    assertion_id: Option<i64>,
    role: &str,
    action: &str,
    resource: &str,
) {
    if conditions.conditions_list.is_empty() {
        warn!(
            "empty assertion conditions list in policy {policy_name}: assertion_id={assertion_id:?} role='{role}' action='{action}' resource='{resource}'"
        );
        return;
    }

    for condition in &conditions.conditions_list {
        if condition.conditions_map.is_empty() {
            warn!(
                "empty assertion condition map in policy {policy_name}: assertion_id={assertion_id:?} condition_id={condition_id:?} role='{role}' action='{action}' resource='{resource}'",
                condition_id = condition.id
            );
            continue;
        }

        for (key, data) in &condition.conditions_map {
            if !condition_key_supported(key, data) {
                warn!(
                    "unsupported assertion condition in policy {policy_name}: assertion_id={assertion_id:?} condition_id={condition_id:?} key='{key}' operator={operator:?} value={value:?} role='{role}' action='{action}' resource='{resource}'",
                    condition_id = condition.id,
                    operator = data.operator,
                    value = data.value
                );
            }
        }
    }
}
