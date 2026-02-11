use crate::models::{
    Assertion, AssertionConditionData, AssertionConditionOperator, AssertionConditions,
    AssertionEffect, PolicyData,
};
use log::warn;
use regex::Regex;
use std::borrow::Cow;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
    DenyNoMatch,
    DenyDomainMismatch,
    DenyDomainNotFound,
    DenyDomainEmpty,
    DenyInvalidParameters,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyMatch {
    pub decision: PolicyDecision,
    pub matched_role: Option<String>,
}

impl PolicyMatch {
    fn new(decision: PolicyDecision) -> Self {
        Self {
            decision,
            matched_role: None,
        }
    }
}

#[derive(Default)]
pub struct PolicyStore {
    domains: HashMap<String, DomainPolicy>,
}

impl PolicyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    pub fn insert(&mut self, policy_data: PolicyData) {
        let domain = policy_data.domain.clone();
        let entry = DomainPolicy::from_policy_data(policy_data);
        self.domains.insert(domain, entry);
    }

    pub fn remove(&mut self, domain: &str) -> Option<DomainPolicy> {
        self.domains.remove(domain)
    }

    pub fn allow_action(
        &self,
        token_domain: &str,
        roles: &[String],
        action: &str,
        resource: &str,
    ) -> PolicyMatch {
        if token_domain.is_empty() || roles.is_empty() || action.is_empty() || resource.is_empty() {
            return PolicyMatch::new(PolicyDecision::DenyInvalidParameters);
        }

        let domain_policy = match self.domains.get(token_domain) {
            Some(policy) => policy,
            None => return PolicyMatch::new(PolicyDecision::DenyDomainNotFound),
        };

        let action_lower = action.to_lowercase();
        let resource_lowercased = resource.to_lowercase();
        let resource_stripped_lower = match strip_domain_prefix(&resource_lowercased, token_domain)
        {
            Some(value) => value,
            None => return PolicyMatch::new(PolicyDecision::DenyDomainMismatch),
        };
        let resource_case_sensitive = if domain_policy.has_case_sensitive {
            strip_domain_prefix_if_matches_ascii_case_insensitive(resource, token_domain)
        } else {
            Cow::Borrowed(resource_stripped_lower.as_str())
        };
        let action_match = MatchInput::new(action, &action_lower);
        let resource_match =
            MatchInput::new(resource_case_sensitive.as_ref(), &resource_stripped_lower);

        if domain_policy.is_empty() {
            return PolicyMatch::new(PolicyDecision::DenyDomainEmpty);
        }

        let mut match_role = None;
        let normalized_roles: Vec<String> = roles
            .iter()
            .map(|role| normalize_role(role, token_domain))
            .collect();

        if domain_policy.deny.matches(
            &normalized_roles,
            &action_match,
            &resource_match,
            &mut match_role,
        ) {
            return PolicyMatch {
                decision: PolicyDecision::Deny,
                matched_role: match_role,
            };
        }

        match_role = None;
        if domain_policy.allow.matches(
            &normalized_roles,
            &action_match,
            &resource_match,
            &mut match_role,
        ) {
            return PolicyMatch {
                decision: PolicyDecision::Allow,
                matched_role: match_role,
            };
        }

        PolicyMatch::new(PolicyDecision::DenyNoMatch)
    }
}

#[derive(Default)]
pub struct DomainPolicy {
    allow: RoleAssertions,
    deny: RoleAssertions,
    has_case_sensitive: bool,
}

impl DomainPolicy {
    fn from_policy_data(policy_data: PolicyData) -> Self {
        let mut allow = RoleAssertions::default();
        let mut deny = RoleAssertions::default();
        let mut has_case_sensitive = false;

        let domain = policy_data.domain.clone();
        for policy in policy_data.policies {
            let policy_name = policy.name.clone();
            let policy_case_sensitive = policy.case_sensitive.unwrap_or(false);
            for assertion in policy.assertions {
                let effect = assertion.effect.clone().unwrap_or(AssertionEffect::Allow);
                let assertion_case_sensitive =
                    assertion.case_sensitive.unwrap_or(policy_case_sensitive);
                if assertion_case_sensitive {
                    has_case_sensitive = true;
                }
                let entry = AssertionEntry::from_assertion(
                    assertion,
                    &policy_name,
                    &domain,
                    assertion_case_sensitive,
                );
                match effect {
                    AssertionEffect::Allow => allow.insert(entry),
                    AssertionEffect::Deny => deny.insert(entry),
                }
            }
        }

        Self {
            allow,
            deny,
            has_case_sensitive,
        }
    }

    fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }
}

#[derive(Default)]
struct RoleAssertions {
    standard: HashMap<String, Vec<AssertionEntry>>,
    wildcard: Vec<WildcardRoleAssertions>,
}

impl RoleAssertions {
    fn is_empty(&self) -> bool {
        self.standard.is_empty() && self.wildcard.is_empty()
    }

    fn insert(&mut self, entry: AssertionEntry) {
        if entry.role_has_wildcard {
            self.wildcard.push(WildcardRoleAssertions::new(entry));
        } else {
            self.standard
                .entry(entry.role.clone())
                .or_default()
                .push(entry);
        }
    }

    fn matches(
        &self,
        roles: &[String],
        action: &MatchInput<'_>,
        resource: &MatchInput<'_>,
        matched_role: &mut Option<String>,
    ) -> bool {
        if !self.standard.is_empty() {
            for role in roles {
                if let Some(asserts) = self.standard.get(role) {
                    if match_assertions(asserts, action, resource) {
                        *matched_role = Some(role.clone());
                        return true;
                    }
                }
            }
        }

        if !self.wildcard.is_empty() {
            for role in roles {
                for wild in &self.wildcard {
                    if wild.role_match.matches(role)
                        && match_assertions(&wild.assertions, action, resource)
                    {
                        *matched_role = Some(role.clone());
                        return true;
                    }
                }
            }
        }

        false
    }
}

#[derive(Clone)]
struct WildcardRoleAssertions {
    role_match: Match,
    assertions: Vec<AssertionEntry>,
}

impl WildcardRoleAssertions {
    fn new(entry: AssertionEntry) -> Self {
        let role_match = Match::from_pattern(&entry.role, "role", &entry._policy_name);
        Self {
            role_match,
            assertions: vec![entry],
        }
    }
}

#[derive(Clone)]
struct AssertionEntry {
    role: String,
    role_has_wildcard: bool,
    action: Match,
    resource: Match,
    case_sensitive: bool,
    _policy_name: String,
    conditions: Option<AssertionConditions>,
}

impl AssertionEntry {
    fn from_assertion(
        assertion: Assertion,
        policy_name: &str,
        domain: &str,
        case_sensitive: bool,
    ) -> Self {
        let Assertion {
            role,
            resource,
            action,
            id,
            conditions,
            ..
        } = assertion;
        if let Some(ref conditions) = conditions {
            validate_assertion_conditions(conditions, policy_name, id, &role, &action, &resource);
        }
        let mut role = strip_domain_prefix_if_matches(&role, domain).into_owned();
        if let Some(stripped) = role.strip_prefix("role.") {
            role = stripped.to_string();
        }
        let role_has_wildcard = contains_match_char(&role);
        let action_value = if case_sensitive {
            action
        } else {
            action.to_lowercase()
        };
        let resource_value = if case_sensitive {
            strip_domain_prefix_if_matches_ascii_case_insensitive(&resource, domain).into_owned()
        } else {
            let resource_lowercased = resource.to_lowercase();
            strip_domain_prefix_if_matches(&resource_lowercased, domain).into_owned()
        };
        let action = Match::from_pattern(&action_value, "action", policy_name);
        let resource = Match::from_pattern(&resource_value, "resource", policy_name);
        Self {
            role,
            role_has_wildcard,
            action,
            resource,
            case_sensitive,
            _policy_name: policy_name.to_string(),
            conditions,
        }
    }

    fn conditions_match(&self) -> bool {
        let Some(conditions) = &self.conditions else {
            return true;
        };
        assertion_conditions_match(conditions)
    }
}

#[derive(Clone)]
enum Match {
    All,
    Equals(String),
    StartsWith(String),
    Regex(Regex),
    Invalid,
}

impl Match {
    fn from_pattern(pattern: &str, context: &str, policy_name: &str) -> Self {
        if pattern == "*" {
            return Match::All;
        }
        let any_char = pattern.find('*');
        let single_char = pattern.find('?');
        match (any_char, single_char) {
            (None, None) => Match::Equals(pattern.to_string()),
            (Some(pos), None) if pos == pattern.len() - 1 => {
                Match::StartsWith(pattern[..pattern.len() - 1].to_string())
            }
            _ => {
                let regex_pattern = pattern_from_glob(pattern);
                match Regex::new(&regex_pattern) {
                    Ok(regex) => Match::Regex(regex),
                    Err(err) => {
                        warn!(
                            "invalid wildcard pattern in policy {policy_name} for {context}: pattern='{pattern}' regex='{regex_pattern}' error={err}"
                        );
                        Match::Invalid
                    }
                }
            }
        }
    }

    fn matches(&self, value: &str) -> bool {
        match self {
            Match::All => true,
            Match::Equals(expected) => expected == value,
            Match::StartsWith(prefix) => value.starts_with(prefix),
            Match::Regex(regex) => regex.is_match(value),
            Match::Invalid => false,
        }
    }
}

const ENFORCEMENT_STATE_KEY: &str = "enforcementState";
const ENFORCEMENT_STATE_ENFORCE: &str = "ENFORCE";

struct MatchInput<'a> {
    case_sensitive: &'a str,
    case_insensitive: &'a str,
}

impl<'a> MatchInput<'a> {
    fn new(case_sensitive: &'a str, case_insensitive: &'a str) -> Self {
        Self {
            case_sensitive,
            case_insensitive,
        }
    }

    fn value(&self, case_sensitive: bool) -> &str {
        if case_sensitive {
            self.case_sensitive
        } else {
            self.case_insensitive
        }
    }
}

fn match_assertions(
    asserts: &[AssertionEntry],
    action: &MatchInput<'_>,
    resource: &MatchInput<'_>,
) -> bool {
    for assertion in asserts {
        if !assertion.conditions_match() {
            continue;
        }
        if !assertion
            .action
            .matches(action.value(assertion.case_sensitive))
        {
            continue;
        }
        if !assertion
            .resource
            .matches(resource.value(assertion.case_sensitive))
        {
            continue;
        }
        return true;
    }
    false
}

// Matching semantics:
// - empty list => non-match (explicit conditions block must contain at least one map)
// - list => OR across maps
// - map => AND across keys
// - empty maps are skipped
fn assertion_conditions_match(conditions: &AssertionConditions) -> bool {
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

fn validate_assertion_conditions(
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

fn strip_domain_prefix(resource: &str, domain: &str) -> Option<String> {
    if let Some(index) = resource.find(':') {
        if &resource[..index] != domain {
            return None;
        }
        return Some(resource[index + 1..].to_string());
    }
    Some(resource.to_string())
}

enum DomainMatchMode {
    Exact,
    AsciiCaseInsensitive,
}

fn strip_domain_prefix_if_matches_with<'a>(
    value: &'a str,
    domain: &str,
    mode: DomainMatchMode,
) -> Cow<'a, str> {
    if let Some(index) = value.find(':') {
        let matches = match mode {
            DomainMatchMode::Exact => &value[..index] == domain,
            // Domain names are expected to be ASCII; fall back to exact match for non-ASCII input.
            DomainMatchMode::AsciiCaseInsensitive => {
                let prefix = &value[..index];
                if prefix.is_ascii() && domain.is_ascii() {
                    prefix.eq_ignore_ascii_case(domain)
                } else {
                    prefix == domain
                }
            }
        };
        if matches {
            return Cow::Borrowed(&value[index + 1..]);
        }
    }
    Cow::Borrowed(value)
}

fn strip_domain_prefix_if_matches<'a>(value: &'a str, domain: &str) -> Cow<'a, str> {
    strip_domain_prefix_if_matches_with(value, domain, DomainMatchMode::Exact)
}

fn strip_domain_prefix_if_matches_ascii_case_insensitive<'a>(
    value: &'a str,
    domain: &str,
) -> Cow<'a, str> {
    strip_domain_prefix_if_matches_with(value, domain, DomainMatchMode::AsciiCaseInsensitive)
}

fn normalize_role(role: &str, domain: &str) -> String {
    let mut normalized = strip_domain_prefix_if_matches(role, domain).into_owned();
    if let Some(stripped) = normalized.strip_prefix("role.") {
        normalized = stripped.to_string();
    }
    normalized
}

fn contains_match_char(value: &str) -> bool {
    value.contains('*') || value.contains('?')
}

fn pattern_from_glob(glob: &str) -> String {
    let mut out = String::from("^");
    for c in glob.chars() {
        match c {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            _ => {
                if is_regex_meta(c) {
                    out.push('\\');
                }
                out.push(c);
            }
        }
    }
    out.push('$');
    out
}

fn is_regex_meta(c: char) -> bool {
    matches!(
        c,
        '^' | '$' | '.' | '|' | '[' | ']' | '+' | '\\' | '(' | ')' | '{' | '}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Policy;
    use crate::models::{
        AssertionCondition, AssertionConditionData, AssertionConditionOperator, AssertionConditions,
    };
    use std::collections::HashMap;

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

    #[test]
    fn policy_store_enforces_conditions() {
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
        assert_eq!(decision.decision, PolicyDecision::DenyNoMatch);

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
    fn policy_store_skips_non_enforced_conditions() {
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
        assert_eq!(decision.decision, PolicyDecision::DenyNoMatch);
    }

    #[test]
    fn policy_store_skips_empty_conditions_list() {
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
        assert_eq!(decision.decision, PolicyDecision::DenyNoMatch);
    }

    #[test]
    fn policy_store_skips_unsupported_condition_key() {
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
        assert_eq!(decision.decision, PolicyDecision::DenyNoMatch);
    }

    #[test]
    fn policy_store_skips_mixed_supported_and_unsupported_conditions() {
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
        assert_eq!(decision.decision, PolicyDecision::DenyNoMatch);
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
}
