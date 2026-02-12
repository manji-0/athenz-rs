use log::warn;
use regex::Regex;

#[derive(Clone)]
pub(super) enum Match {
    All,
    Equals(String),
    StartsWith(String),
    Regex(Regex),
    Invalid,
}

impl Match {
    pub(super) fn from_pattern(pattern: &str, context: &str, policy_name: &str) -> Self {
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

    pub(super) fn matches(&self, value: &str) -> bool {
        match self {
            Match::All => true,
            Match::Equals(expected) => expected == value,
            Match::StartsWith(prefix) => value.starts_with(prefix),
            Match::Regex(regex) => regex.is_match(value),
            Match::Invalid => false,
        }
    }
}

pub(super) struct MatchInput<'a> {
    case_sensitive: &'a str,
    case_insensitive: &'a str,
}

impl<'a> MatchInput<'a> {
    pub(super) fn new(case_sensitive: &'a str, case_insensitive: &'a str) -> Self {
        Self {
            case_sensitive,
            case_insensitive,
        }
    }

    pub(super) fn value(&self, case_sensitive: bool) -> &str {
        if case_sensitive {
            self.case_sensitive
        } else {
            self.case_insensitive
        }
    }
}

pub(super) fn contains_match_char(value: &str) -> bool {
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
