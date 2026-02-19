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

pub(super) fn strip_domain_prefix_if_matches<'a>(value: &'a str, domain: &str) -> Cow<'a, str> {
    if let Some(index) = value.find(':') {
        if &value[..index] == domain {
            return Cow::Borrowed(&value[index + 1..]);
        }
    }
    Cow::Borrowed(value)
}

pub(super) fn normalize_role(role: &str, domain: &str) -> String {
    let mut normalized = strip_domain_prefix_if_matches(role, domain).into_owned();
    if let Some(stripped) = normalized.strip_prefix("role.") {
        normalized = stripped.to_string();
    }
    normalized
}
