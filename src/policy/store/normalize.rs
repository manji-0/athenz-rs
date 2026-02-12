use std::borrow::Cow;

pub(super) fn strip_domain_prefix(resource: &str, domain: &str) -> Option<String> {
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
            // Domain names are expected to be ASCII; compare ASCII letters case-insensitively.
            // Non-ASCII characters must match exactly.
            DomainMatchMode::AsciiCaseInsensitive => {
                let prefix = &value[..index];
                prefix.eq_ignore_ascii_case(domain)
            }
        };
        if matches {
            return Cow::Borrowed(&value[index + 1..]);
        }
    }
    Cow::Borrowed(value)
}

pub(super) fn strip_domain_prefix_if_matches<'a>(value: &'a str, domain: &str) -> Cow<'a, str> {
    strip_domain_prefix_if_matches_with(value, domain, DomainMatchMode::Exact)
}

pub(super) fn strip_domain_prefix_if_matches_ascii_case_insensitive<'a>(
    value: &'a str,
    domain: &str,
) -> Cow<'a, str> {
    strip_domain_prefix_if_matches_with(value, domain, DomainMatchMode::AsciiCaseInsensitive)
}

pub(super) fn normalize_role(role: &str, domain: &str) -> String {
    let mut normalized = strip_domain_prefix_if_matches(role, domain).into_owned();
    if let Some(stripped) = normalized.strip_prefix("role.") {
        normalized = stripped.to_string();
    }
    normalized
}
