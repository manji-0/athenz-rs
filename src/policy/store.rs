use crate::models::{Assertion, AssertionEffect, PolicyData};
use log::warn;
use regex::Regex;
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

        let action = action.to_lowercase();
        let resource = resource.to_lowercase();
        let resource = match strip_domain_prefix(&resource, token_domain) {
            Some(value) => value,
            None => return PolicyMatch::new(PolicyDecision::DenyDomainMismatch),
        };

        if domain_policy.is_empty() {
            return PolicyMatch::new(PolicyDecision::DenyDomainEmpty);
        }

        let mut match_role = None;
        let normalized_roles: Vec<String> = roles
            .iter()
            .map(|role| normalize_role(role, token_domain))
            .collect();

        if domain_policy
            .deny
            .matches(&normalized_roles, &action, &resource, &mut match_role)
        {
            return PolicyMatch {
                decision: PolicyDecision::Deny,
                matched_role: match_role,
            };
        }

        match_role = None;
        if domain_policy
            .allow
            .matches(&normalized_roles, &action, &resource, &mut match_role)
        {
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
}

impl DomainPolicy {
    fn from_policy_data(policy_data: PolicyData) -> Self {
        let mut allow = RoleAssertions::default();
        let mut deny = RoleAssertions::default();

        let domain = policy_data.domain.clone();
        for policy in policy_data.policies {
            let policy_name = policy.name.clone();
            for assertion in policy.assertions {
                let effect = assertion.effect.clone().unwrap_or(AssertionEffect::Allow);
                let entry = AssertionEntry::from_assertion(assertion, &policy_name, &domain);
                match effect {
                    AssertionEffect::Allow => allow.insert(entry),
                    AssertionEffect::Deny => deny.insert(entry),
                }
            }
        }

        Self { allow, deny }
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
        action: &str,
        resource: &str,
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
    _policy_name: String,
}

impl AssertionEntry {
    fn from_assertion(assertion: Assertion, policy_name: &str, domain: &str) -> Self {
        let mut role = strip_domain_prefix_if_matches(&assertion.role, domain);
        if let Some(stripped) = role.strip_prefix("role.") {
            role = stripped.to_string();
        }
        let role_has_wildcard = contains_match_char(&role);
        let action = Match::from_pattern(&assertion.action.to_lowercase(), "action", policy_name);
        let resource_value =
            strip_domain_prefix_if_matches(&assertion.resource.to_lowercase(), domain);
        let resource = Match::from_pattern(&resource_value, "resource", policy_name);
        Self {
            role,
            role_has_wildcard,
            action,
            resource,
            _policy_name: policy_name.to_string(),
        }
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

fn match_assertions(asserts: &[AssertionEntry], action: &str, resource: &str) -> bool {
    for assertion in asserts {
        if !assertion.action.matches(action) {
            continue;
        }
        if !assertion.resource.matches(resource) {
            continue;
        }
        return true;
    }
    false
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

fn strip_domain_prefix_if_matches(value: &str, domain: &str) -> String {
    if let Some(index) = value.find(':') {
        if &value[..index] == domain {
            return value[index + 1..].to_string();
        }
    }
    value.to_string()
}

fn normalize_role(role: &str, domain: &str) -> String {
    let mut normalized = strip_domain_prefix_if_matches(role, domain);
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
    fn policy_store_ignores_case_sensitive_and_conditions() {
        let mut conditions = HashMap::new();
        conditions.insert(
            "enforcementState".to_string(),
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
    }
}
