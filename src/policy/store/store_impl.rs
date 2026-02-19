use crate::models::{Assertion, AssertionEffect, PolicyData};
use std::collections::HashMap;

use super::decision::{PolicyDecision, PolicyMatch};
use super::matchers::{contains_match_char, Match, MatchInput};
use super::normalize::{normalize_role, strip_domain_prefix, strip_domain_prefix_if_matches};

#[derive(Default)]
pub struct PolicyStore {
    domains: HashMap<String, DomainPolicy>,
}

impl PolicyStore {
    /// Creates an empty policy store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of domains currently loaded.
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    /// Inserts policy data for a domain, replacing any existing entry.
    pub fn insert(&mut self, policy_data: PolicyData) {
        let domain = policy_data.domain.clone();
        let entry = DomainPolicy::from_policy_data(policy_data);
        self.domains.insert(domain, entry);
    }

    /// Removes and returns the policy data for a domain, if present.
    pub fn remove(&mut self, domain: &str) -> Option<DomainPolicy> {
        self.domains.remove(domain)
    }

    /// Evaluates whether the provided roles allow the given action on a resource.
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
        let resource_stripped_lower = if self.domain_count() == 1 {
            strip_domain_prefix_if_matches(&resource_lowercased, token_domain).into_owned()
        } else {
            match strip_domain_prefix(&resource_lowercased, token_domain) {
                Some(value) => value,
                None => return PolicyMatch::new(PolicyDecision::DenyDomainMismatch),
            }
        };
        let action_match = MatchInput::new(&action_lower, &action_lower);
        let resource_match = MatchInput::new(&resource_stripped_lower, &resource_stripped_lower);

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
}

impl DomainPolicy {
    fn from_policy_data(policy_data: PolicyData) -> Self {
        let mut allow = RoleAssertions::default();
        let mut deny = RoleAssertions::default();

        let domain = policy_data.domain.clone();
        for policy in policy_data.policies {
            // Treat `active: None` as "unspecified but active".
            // Only policies explicitly marked as inactive (`Some(false)`) are skipped here.
            if matches!(policy.active, Some(false)) {
                continue;
            }
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
    _policy_name: String,
}

impl AssertionEntry {
    fn from_assertion(assertion: Assertion, policy_name: &str, domain: &str) -> Self {
        let Assertion {
            role,
            resource,
            action,
            ..
        } = assertion;
        let mut role = strip_domain_prefix_if_matches(&role, domain).into_owned();
        if let Some(stripped) = role.strip_prefix("role.") {
            role = stripped.to_string();
        }
        let role_has_wildcard = contains_match_char(&role);
        let action_value = action.to_lowercase();
        let resource_lowercased = resource.to_lowercase();
        let resource_value =
            strip_domain_prefix_if_matches(&resource_lowercased, domain).into_owned();
        let action = Match::from_pattern(&action_value, "action", policy_name);
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

fn match_assertions(
    asserts: &[AssertionEntry],
    action: &MatchInput<'_>,
    resource: &MatchInput<'_>,
) -> bool {
    for assertion in asserts {
        if !assertion.action.matches(action.value(false)) {
            continue;
        }
        if !assertion.resource.matches(resource.value(false)) {
            continue;
        }
        return true;
    }
    false
}
