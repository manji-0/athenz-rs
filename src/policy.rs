use crate::error::Error;
use crate::models::{
    Assertion, AssertionEffect, DomainSignedPolicyData, JWSPolicyData, PolicyData, PublicKeyEntry,
    SignedPolicyData, SignedPolicyRequest,
};
use crate::zts::ZtsClient;
use base64::engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use pem::parse_many;
use pkcs8::DecodePublicKey;
use regex::Regex;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use rsa::RsaPublicKey;
use sha2::{Sha256, Sha384, Sha512};
use signature::Verifier as SignatureVerifier;
use std::collections::HashMap;
use std::time::Duration;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Debug, Clone)]
pub struct PolicyFetchResponse<T> {
    pub data: Option<T>,
    pub etag: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PolicyValidatorConfig {
    pub sys_auth_domain: String,
    pub zts_service: String,
    pub zms_service: String,
    pub check_zms_signature: bool,
    pub expiry_offset: Duration,
}

impl Default for PolicyValidatorConfig {
    fn default() -> Self {
        Self {
            sys_auth_domain: "sys.auth".to_string(),
            zts_service: "zts".to_string(),
            zms_service: "zms".to_string(),
            check_zms_signature: false,
            expiry_offset: Duration::from_secs(0),
        }
    }
}

pub struct PolicyClient {
    zts: ZtsClient,
    config: PolicyValidatorConfig,
}

impl PolicyClient {
    pub fn new(zts: ZtsClient) -> Self {
        Self {
            zts,
            config: PolicyValidatorConfig::default(),
        }
    }

    pub fn config_mut(&mut self) -> &mut PolicyValidatorConfig {
        &mut self.config
    }

    pub fn fetch_signed_policy_data(
        &self,
        domain: &str,
        etag: Option<&str>,
    ) -> Result<PolicyFetchResponse<DomainSignedPolicyData>, Error> {
        let response = self.zts.get_domain_signed_policy_data(domain, etag)?;
        Ok(PolicyFetchResponse {
            data: response.data,
            etag: response.etag,
        })
    }

    pub fn fetch_jws_policy_data(
        &self,
        domain: &str,
        request: &SignedPolicyRequest,
        etag: Option<&str>,
    ) -> Result<PolicyFetchResponse<JWSPolicyData>, Error> {
        let response = self
            .zts
            .post_domain_signed_policy_data_jws(domain, request, etag)?;
        Ok(PolicyFetchResponse {
            data: response.data,
            etag: response.etag,
        })
    }

    pub fn validate_signed_policy_data(
        &self,
        data: &DomainSignedPolicyData,
    ) -> Result<PolicyData, Error> {
        validate_signed_policy_data(data, &self.zts, &self.config)
    }

    pub fn validate_jws_policy_data(&self, data: &JWSPolicyData) -> Result<PolicyData, Error> {
        validate_jws_policy_data(data, &self.zts, &self.config)
    }
}

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
                    if wild.role_match.matches(role) {
                        if match_assertions(&wild.assertions, action, resource) {
                            *matched_role = Some(role.clone());
                            return true;
                        }
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
        let role_match = Match::from_pattern(&entry.role);
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
        let action = Match::from_pattern(&assertion.action.to_lowercase());
        let resource_value =
            strip_domain_prefix_if_matches(&assertion.resource.to_lowercase(), domain);
        let resource = Match::from_pattern(&resource_value);
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
}

impl Match {
    fn from_pattern(pattern: &str) -> Self {
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
                let regex = Regex::new(&pattern_from_glob(pattern))
                    .unwrap_or_else(|_| Regex::new("^$").unwrap());
                Match::Regex(regex)
            }
        }
    }

    fn matches(&self, value: &str) -> bool {
        match self {
            Match::All => true,
            Match::Equals(expected) => expected == value,
            Match::StartsWith(prefix) => value.starts_with(prefix),
            Match::Regex(regex) => regex.is_match(value),
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
        '^' | '$' | '.' | '|' | '[' | '+' | '\\' | '(' | ')' | '{'
    )
}

fn validate_signed_policy_data(
    data: &DomainSignedPolicyData,
    zts: &ZtsClient,
    config: &PolicyValidatorConfig,
) -> Result<PolicyData, Error> {
    let signed_policy = &data.signed_policy_data;

    ensure_not_expired(&signed_policy.expires, config)?;

    let zts_key_pem = get_public_key_pem(
        zts,
        &config.sys_auth_domain,
        &config.zts_service,
        &data.key_id,
    )?;
    let signed_json = canonical_json(&serde_json::to_value(signed_policy)?);
    verify_ybase64_signature_sha256(&signed_json, &data.signature, &zts_key_pem)?;

    if config.check_zms_signature {
        let zms_signature = signed_policy.zms_signature.as_deref().unwrap_or("");
        let zms_key_id = signed_policy.zms_key_id.as_deref().unwrap_or("");
        if zms_signature.is_empty() || zms_key_id.is_empty() {
            return Err(Error::Crypto("missing zms signature or key id".to_string()));
        }
        let zms_key_pem = get_public_key_pem(
            zts,
            &config.sys_auth_domain,
            &config.zms_service,
            zms_key_id,
        )?;
        let policy_json = canonical_json(&serde_json::to_value(&signed_policy.policy_data)?);
        verify_ybase64_signature_sha256(&policy_json, zms_signature, &zms_key_pem)?;
    }

    Ok(signed_policy.policy_data.clone())
}

fn validate_jws_policy_data(
    data: &JWSPolicyData,
    zts: &ZtsClient,
    config: &PolicyValidatorConfig,
) -> Result<PolicyData, Error> {
    let header = parse_jws_protected_header(&data.protected_header)?;
    let zts_key_pem = get_public_key_pem(
        zts,
        &config.sys_auth_domain,
        &config.zts_service,
        &header.kid,
    )?;

    verify_jws_signature(
        &header.alg,
        &data.protected_header,
        &data.payload,
        &data.signature,
        &zts_key_pem,
    )?;

    let payload = URL_SAFE_NO_PAD
        .decode(data.payload.as_bytes())
        .map_err(|e| Error::Crypto(format!("jws payload decode error: {}", e)))?;
    let signed_policy: SignedPolicyData = serde_json::from_slice(&payload)?;

    ensure_not_expired(&signed_policy.expires, config)?;

    if config.check_zms_signature {
        let zms_signature = signed_policy.zms_signature.as_deref().unwrap_or("");
        let zms_key_id = signed_policy.zms_key_id.as_deref().unwrap_or("");
        if zms_signature.is_empty() || zms_key_id.is_empty() {
            return Err(Error::Crypto("missing zms signature or key id".to_string()));
        }
        let zms_key_pem = get_public_key_pem(
            zts,
            &config.sys_auth_domain,
            &config.zms_service,
            zms_key_id,
        )?;
        let policy_json = canonical_json(&serde_json::to_value(&signed_policy.policy_data)?);
        verify_ybase64_signature_sha256(&policy_json, zms_signature, &zms_key_pem)?;
    }

    Ok(signed_policy.policy_data)
}

fn ensure_not_expired(expires: &str, config: &PolicyValidatorConfig) -> Result<(), Error> {
    let expires_at = OffsetDateTime::parse(expires, &Rfc3339)
        .map_err(|e| Error::Crypto(format!("invalid expires timestamp: {}", e)))?;
    let now = OffsetDateTime::now_utc();
    let offset = time::Duration::seconds(config.expiry_offset.as_secs() as i64);
    if now > expires_at - offset {
        return Err(Error::Crypto(format!(
            "policy data is expired on {}",
            expires
        )));
    }
    Ok(())
}

fn parse_jws_protected_header(header: &str) -> Result<JwsProtectedHeader, Error> {
    let decoded = URL_SAFE_NO_PAD
        .decode(header.as_bytes())
        .map_err(|e| Error::Crypto(format!("jws header decode error: {}", e)))?;
    let header: JwsProtectedHeader = serde_json::from_slice(&decoded)?;
    Ok(header)
}

#[derive(Debug, serde::Deserialize)]
struct JwsProtectedHeader {
    kid: String,
    alg: String,
}

fn get_public_key_pem(
    zts: &ZtsClient,
    domain: &str,
    service: &str,
    key_id: &str,
) -> Result<Vec<u8>, Error> {
    let entry: PublicKeyEntry = zts.get_public_key_entry(domain, service, key_id)?;
    ybase64_decode(&entry.key)
}

fn verify_ybase64_signature_sha256(
    message: &str,
    signature: &str,
    public_key_pem: &[u8],
) -> Result<(), Error> {
    let sig_bytes = ybase64_decode(signature)?;
    verify_signature_sha256(message.as_bytes(), &sig_bytes, public_key_pem)
}

fn verify_jws_signature(
    alg: &str,
    protected: &str,
    payload: &str,
    signature: &str,
    public_key_pem: &[u8],
) -> Result<(), Error> {
    let signing_input = format!("{}.{}", protected, payload);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(signature.as_bytes())
        .map_err(|e| Error::Crypto(format!("jws signature decode error: {}", e)))?;

    match alg {
        "RS256" => verify_rsa(&signing_input, &sig_bytes, public_key_pem, RsaHash::Sha256),
        "RS384" => verify_rsa(&signing_input, &sig_bytes, public_key_pem, RsaHash::Sha384),
        "RS512" => verify_rsa(&signing_input, &sig_bytes, public_key_pem, RsaHash::Sha512),
        "ES256" => verify_ecdsa(&signing_input, &sig_bytes, public_key_pem, EcdsaCurve::P256),
        "ES384" => verify_ecdsa(&signing_input, &sig_bytes, public_key_pem, EcdsaCurve::P384),
        "ES512" => verify_ecdsa(&signing_input, &sig_bytes, public_key_pem, EcdsaCurve::P521),
        _ => Err(Error::UnsupportedAlg(alg.to_string())),
    }
}

fn verify_signature_sha256(
    message: &[u8],
    signature: &[u8],
    public_key_pem: &[u8],
) -> Result<(), Error> {
    match load_public_key(public_key_pem)? {
        PublicKey::Rsa(key) => {
            let verifier = RsaVerifyingKey::<Sha256>::new(key);
            let sig = RsaSignature::try_from(signature)
                .map_err(|e| Error::Crypto(format!("rsa signature error: {}", e)))?;
            verifier
                .verify(message, &sig)
                .map_err(|e| Error::Crypto(format!("rsa verify error: {}", e)))
        }
        PublicKey::P256(key) => verify_ecdsa_raw(message, signature, EcdsaCurve::P256, key),
        PublicKey::P384(key) => verify_ecdsa_raw(message, signature, EcdsaCurve::P384, key),
        PublicKey::P521(key) => verify_ecdsa_raw(message, signature, EcdsaCurve::P521, key),
    }
}

fn verify_rsa(
    message: &str,
    signature: &[u8],
    public_key_pem: &[u8],
    hash: RsaHash,
) -> Result<(), Error> {
    let key = match load_public_key(public_key_pem)? {
        PublicKey::Rsa(key) => key,
        _ => return Err(Error::Crypto("public key is not RSA".to_string())),
    };
    match hash {
        RsaHash::Sha256 => {
            let verifier = RsaVerifyingKey::<Sha256>::new(key);
            let sig = RsaSignature::try_from(signature)
                .map_err(|e| Error::Crypto(format!("rsa signature error: {}", e)))?;
            verifier
                .verify(message.as_bytes(), &sig)
                .map_err(|e| Error::Crypto(format!("rsa verify error: {}", e)))
        }
        RsaHash::Sha384 => {
            let verifier = RsaVerifyingKey::<Sha384>::new(key);
            let sig = RsaSignature::try_from(signature)
                .map_err(|e| Error::Crypto(format!("rsa signature error: {}", e)))?;
            verifier
                .verify(message.as_bytes(), &sig)
                .map_err(|e| Error::Crypto(format!("rsa verify error: {}", e)))
        }
        RsaHash::Sha512 => {
            let verifier = RsaVerifyingKey::<Sha512>::new(key);
            let sig = RsaSignature::try_from(signature)
                .map_err(|e| Error::Crypto(format!("rsa signature error: {}", e)))?;
            verifier
                .verify(message.as_bytes(), &sig)
                .map_err(|e| Error::Crypto(format!("rsa verify error: {}", e)))
        }
    }
}

fn verify_ecdsa(
    message: &str,
    signature: &[u8],
    public_key_pem: &[u8],
    curve: EcdsaCurve,
) -> Result<(), Error> {
    let key = load_public_key(public_key_pem)?;
    match (curve, key) {
        (EcdsaCurve::P256, PublicKey::P256(key)) => {
            verify_ecdsa_raw(message.as_bytes(), signature, curve, key)
        }
        (EcdsaCurve::P384, PublicKey::P384(key)) => {
            verify_ecdsa_raw(message.as_bytes(), signature, curve, key)
        }
        (EcdsaCurve::P521, PublicKey::P521(key)) => {
            verify_ecdsa_raw(message.as_bytes(), signature, curve, key)
        }
        _ => Err(Error::Crypto("public key curve mismatch".to_string())),
    }
}

fn verify_ecdsa_raw(
    message: &[u8],
    signature: &[u8],
    curve: EcdsaCurve,
    key: impl EcdsaVerifier,
) -> Result<(), Error> {
    let raw = normalize_ecdsa_signature(signature, curve)?;
    key.verify(message, &raw)
}

#[derive(Clone, Copy)]
enum RsaHash {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone, Copy)]
enum EcdsaCurve {
    P256,
    P384,
    P521,
}

fn normalize_ecdsa_signature(signature: &[u8], curve: EcdsaCurve) -> Result<Vec<u8>, Error> {
    let size = match curve {
        EcdsaCurve::P256 => 32,
        EcdsaCurve::P384 => 48,
        EcdsaCurve::P521 => 66,
    };
    if signature.len() == size * 2 {
        return Ok(signature.to_vec());
    }
    der_to_p1363(signature, size)
}

fn der_to_p1363(signature: &[u8], size: usize) -> Result<Vec<u8>, Error> {
    if signature.len() < 8 || signature[0] != 0x30 {
        return Err(Error::Crypto("invalid der signature".to_string()));
    }
    let (seq_len, mut idx) = read_der_length(signature, 1)?;
    if idx + seq_len > signature.len() {
        return Err(Error::Crypto("invalid der length".to_string()));
    }
    if signature[idx] != 0x02 {
        return Err(Error::Crypto("invalid der signature (r)".to_string()));
    }
    let (r_len, next) = read_der_length(signature, idx + 1)?;
    idx = next;
    if idx + r_len > signature.len() {
        return Err(Error::Crypto(
            "invalid der signature (r length)".to_string(),
        ));
    }
    let r_bytes = &signature[idx..idx + r_len];
    idx += r_len;

    if idx >= signature.len() {
        return Err(Error::Crypto("invalid der signature (s)".to_string()));
    }
    if signature[idx] != 0x02 {
        return Err(Error::Crypto("invalid der signature (s)".to_string()));
    }
    let (s_len, next) = read_der_length(signature, idx + 1)?;
    idx = next;
    if idx + s_len > signature.len() {
        return Err(Error::Crypto(
            "invalid der signature (s length)".to_string(),
        ));
    }
    let s_bytes = &signature[idx..idx + s_len];

    let r = trim_leading_zero(r_bytes);
    let s = trim_leading_zero(s_bytes);
    if r.len() > size || s.len() > size {
        return Err(Error::Crypto("invalid der integer size".to_string()));
    }

    let mut out = vec![0u8; size * 2];
    out[size - r.len()..size].copy_from_slice(r);
    out[size * 2 - s.len()..size * 2].copy_from_slice(s);
    Ok(out)
}

fn read_der_length(data: &[u8], offset: usize) -> Result<(usize, usize), Error> {
    if offset >= data.len() {
        return Err(Error::Crypto("invalid der length".to_string()));
    }
    let first = data[offset];
    if first & 0x80 == 0 {
        return Ok((first as usize, offset + 1));
    }
    let num_bytes = (first & 0x7f) as usize;
    if num_bytes == 0 || num_bytes > 4 || offset + 1 + num_bytes > data.len() {
        return Err(Error::Crypto("invalid der length".to_string()));
    }
    let mut len = 0usize;
    for i in 0..num_bytes {
        len = (len << 8) | data[offset + 1 + i] as usize;
    }
    Ok((len, offset + 1 + num_bytes))
}

fn trim_leading_zero(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    while start + 1 < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    &bytes[start..]
}

trait EcdsaVerifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error>;
}

impl EcdsaVerifier for p256::ecdsa::VerifyingKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let sig = p256::ecdsa::Signature::from_slice(signature)
            .map_err(|e| Error::Crypto(format!("p256 signature error: {}", e)))?;
        signature::Verifier::verify(self, message, &sig)
            .map_err(|e| Error::Crypto(format!("p256 verify error: {}", e)))
    }
}

impl EcdsaVerifier for p384::ecdsa::VerifyingKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let sig = p384::ecdsa::Signature::from_slice(signature)
            .map_err(|e| Error::Crypto(format!("p384 signature error: {}", e)))?;
        signature::Verifier::verify(self, message, &sig)
            .map_err(|e| Error::Crypto(format!("p384 verify error: {}", e)))
    }
}

impl EcdsaVerifier for p521::ecdsa::VerifyingKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let sig = p521::ecdsa::Signature::from_slice(signature)
            .map_err(|e| Error::Crypto(format!("p521 signature error: {}", e)))?;
        signature::Verifier::verify(self, message, &sig)
            .map_err(|e| Error::Crypto(format!("p521 verify error: {}", e)))
    }
}

#[derive(Clone)]
enum PublicKey {
    Rsa(RsaPublicKey),
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    P521(p521::ecdsa::VerifyingKey),
}

fn load_public_key(pem_bytes: &[u8]) -> Result<PublicKey, Error> {
    let blocks =
        parse_many(pem_bytes).map_err(|e| Error::Crypto(format!("pem parse error: {}", e)))?;
    for block in blocks {
        match block.tag() {
            "RSA PUBLIC KEY" => {
                if let Ok(key) = RsaPublicKey::from_pkcs1_der(block.contents()) {
                    return Ok(PublicKey::Rsa(key));
                }
            }
            "PUBLIC KEY" => {
                if let Ok(key) = RsaPublicKey::from_public_key_der(block.contents()) {
                    return Ok(PublicKey::Rsa(key));
                }
                if let Ok(key) = p256::PublicKey::from_public_key_der(block.contents()) {
                    let encoded = key.to_encoded_point(false);
                    let key = p256::ecdsa::VerifyingKey::from_encoded_point(&encoded)
                        .map_err(|e| Error::Crypto(format!("p256 public key error: {}", e)))?;
                    return Ok(PublicKey::P256(key));
                }
                if let Ok(key) = p384::PublicKey::from_public_key_der(block.contents()) {
                    let encoded = key.to_encoded_point(false);
                    let key = p384::ecdsa::VerifyingKey::from_encoded_point(&encoded)
                        .map_err(|e| Error::Crypto(format!("p384 public key error: {}", e)))?;
                    return Ok(PublicKey::P384(key));
                }
                if let Ok(key) = p521::PublicKey::from_public_key_der(block.contents()) {
                    let encoded = key.to_encoded_point(false);
                    let key = p521::ecdsa::VerifyingKey::from_encoded_point(&encoded)
                        .map_err(|e| Error::Crypto(format!("p521 public key error: {}", e)))?;
                    return Ok(PublicKey::P521(key));
                }
            }
            _ => {}
        }
    }
    Err(Error::Crypto("unsupported public key format".to_string()))
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut parts = Vec::new();
            for key in keys {
                let key_json =
                    serde_json::to_string(key).unwrap_or_else(|_| format!("\"{}\"", key));
                let val = canonical_json(&map[key]);
                parts.push(format!("{}:{}", key_json, val));
            }
            format!("{{{}}}", parts.join(","))
        }
        serde_json::Value::Array(list) => {
            let mut parts = Vec::new();
            for item in list {
                parts.push(canonical_json(item));
            }
            format!("[{}]", parts.join(","))
        }
        serde_json::Value::String(val) => {
            serde_json::to_string(val).unwrap_or_else(|_| format!("\"{}\"", val))
        }
        serde_json::Value::Number(val) => val.to_string(),
        serde_json::Value::Bool(val) => val.to_string(),
        serde_json::Value::Null => "null".to_string(),
    }
}

fn ybase64_decode(data: &str) -> Result<Vec<u8>, Error> {
    let mut normalized = data.replace('.', "+").replace('_', "/").replace('-', "=");
    let rem = normalized.len() % 4;
    if rem != 0 {
        normalized.push_str(&"=".repeat(4 - rem));
    }
    BASE64_STD
        .decode(normalized.as_bytes())
        .map_err(|e| Error::Crypto(format!("ybase64 decode error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Policy;
    use crate::models::{
        AssertionCondition, AssertionConditionData, AssertionConditionOperator, AssertionConditions,
    };
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs1v15::SigningKey as RsaSigningKey;
    use rsa::RsaPrivateKey;
    use sha2::Sha256;
    use signature::SignatureEncoding;
    use signature::Signer;

    #[test]
    fn canonical_signed_policy_data_matches_go() {
        let input = r#"{"policyData":{"domain":"test","policies":[{"name":"policy1","modified":"2017-06-02T06:11:12.125Z","assertions":[{"role":"sys.auth:role.admin","resource":"*","action":"*","effect":"ALLOW"},{"role":"sys.auth:role.non-admin","resource":"*","action":"*","effect":"DENY"}]}]},"zmsSignature":"zms_signature","zmsKeyId":"0","modified":"2017-06-02T06:11:12.125Z","expires":"2017-06-09T06:11:12.125Z"}"#;
        let signed: SignedPolicyData = serde_json::from_str(input).unwrap();
        let canon = canonical_json(&serde_json::to_value(&signed).unwrap());
        assert_eq!(canon, "{\"expires\":\"2017-06-09T06:11:12.125Z\",\"modified\":\"2017-06-02T06:11:12.125Z\",\"policyData\":{\"domain\":\"test\",\"policies\":[{\"assertions\":[{\"action\":\"*\",\"effect\":\"ALLOW\",\"resource\":\"*\",\"role\":\"sys.auth:role.admin\"},{\"action\":\"*\",\"effect\":\"DENY\",\"resource\":\"*\",\"role\":\"sys.auth:role.non-admin\"}],\"modified\":\"2017-06-02T06:11:12.125Z\",\"name\":\"policy1\"}]},\"zmsKeyId\":\"0\",\"zmsSignature\":\"zms_signature\"}");
    }

    #[test]
    fn canonical_json_escapes_strings() {
        let value = serde_json::json!({
            "key": "value\"quoted\"",
            "path": "a\\b",
        });
        let canon = canonical_json(&value);
        assert_eq!(
            canon,
            "{\"key\":\"value\\\"quoted\\\"\",\"path\":\"a\\\\b\"}"
        );
    }

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

    #[test]
    fn verify_jws_signature_rs256() {
        let header = serde_json::json!({
            "alg": "RS256",
            "kid": "v1",
        });
        let payload = serde_json::json!({
            "domain": "sports",
            "policies": [],
        });
        let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload"));
        let signing_input = format!("{}.{}", protected, payload_b64);

        let private_key = RsaPrivateKey::from_pkcs1_pem(RSA_PRIVATE_KEY).expect("private key");
        let signing_key = RsaSigningKey::<Sha256>::new(private_key);
        let signature = signing_key.sign(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        verify_jws_signature(
            "RS256",
            &protected,
            &payload_b64,
            &signature_b64,
            RSA_PUBLIC_KEY.as_bytes(),
        )
        .expect("verify");
    }

    #[test]
    fn ensure_not_expired_respects_offset() {
        let mut config = PolicyValidatorConfig::default();
        let future = OffsetDateTime::now_utc() + time::Duration::seconds(60);
        let future_str = future.format(&Rfc3339).expect("format");
        ensure_not_expired(&future_str, &config).expect("future ok");

        let past = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        let past_str = past.format(&Rfc3339).expect("format");
        assert!(ensure_not_expired(&past_str, &config).is_err());

        config.expiry_offset = Duration::from_secs(60);
        let near_future = OffsetDateTime::now_utc() + time::Duration::seconds(30);
        let near_future_str = near_future.format(&Rfc3339).expect("format");
        assert!(ensure_not_expired(&near_future_str, &config).is_err());
    }

    const RSA_PRIVATE_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxq83nCd8AqH5n40dEBMElbaJd2gFWu6bjhNzyp9562dpf454
BUSN0uF+g3i1yzcwdvADTiuExKN1u/IoGURxVCa0JTzAPJw6/JIoyOZnHZCoarcg
QQqZ56/udkSQ2NssrwGSQjOwxMrgIdH6XeLgGqVN4BoEEI+gpaQZa7rSytU5RFSG
OnZWO2Vwgs1OBxiOiYg1gzA1spJXQhxcBWw/v+YrUFtjxBKsG1UrWbnHbgciiN5U
2v51Yztjo8A1T+o9eIG90jVo3EhS2qhbzd8mLAsEhjV1sP8GItjfdfwXpXT7q2QG
99W3PM75+HdwGLvJIrkED7YRj4CpMkz6F1etawIDAQABAoIBAD67C7/N56WdJodt
soNkvcnXPEfrG+W9+Hc/RQvwljnxCKoxfUuMfYrbj2pLLnrfDfo/hYukyeKcCYwx
xN9VcMK1BaPMLpX0bdtY+m+T73KyPbqT3ycqBbXVImFM/L67VLxcrqUgVOuNcn67
IWWLQF6pWpErJaVk87/Ys/4DmpJXebLDyta8+ce6r0ppSG5+AifGo1byQT7kSJkF
lyQsyKWoVN+02s7gLsln5JXXZ672y2Xtp/S3wK0vfzy/HcGSxzn1yE0M5UJtDm/Y
qECnV1LQ0FB1l1a+/itHR8ipp5rScD4ZpzOPLKthglEvNPe4Lt5rieH9TR97siEe
SrC8uyECgYEA5Q/elOJAddpE+cO22gTFt973DcPGjM+FYwgdrora+RfEXJsMDoKW
AGSm5da7eFo8u/bJEvHSJdytc4CRQYnWNryIaUw2o/1LYXRvoEt1rEEgQ4pDkErR
PsVcVuc3UDeeGtYJwJLV6pjxO11nodFv4IgaVj64SqvCOApTTJgWXF0CgYEA3gzN
d3l376mSMuKc4Ep++TxybzA5mtF2qoXucZOon8EDJKr+vGQ9Z6X4YSdkSMNXqK1j
ILmFH7V3dyMOKRBA84YeawFacPLBJq+42t5Q1OYdcKZbaArlBT8ImGT7tQODs3JN
4w7DH+V1v/VCTl2zQaZRksb0lUsQbFiEfj+SVGcCgYAYIlDoTOJPyHyF+En2tJQE
aHiNObhcs6yxH3TJJBYoMonc2/UsPjQBvJkdFD/SUWeewkSzO0lR9etMhRpI1nX8
dGbG+WG0a4aasQLl162BRadZlmLB/DAJtg+hlGDukb2VxEFoyc/CFPUttQyrLv7j
oFNuDNOsAmbHMsdOBaQtfQKBgQCb/NRuRNebdj0tIALikZLHVc5yC6e7+b/qJPIP
uZIwv++MV89h2u1EHdTxszGA6DFxXnSPraQ2VU2aVPcCo9ds+9/sfePiCrbjjXhH
0PtpxEoUM9lsqpKeb9yC6hXk4JYpfnf2tQ0gIBrrAclVsf9WdBdEDB4Prs7Xvgs9
gT0zqwKBgQCzZubFO0oTYO9e2r8wxPPPsE3ZCjbP/y7lIoBbSzxDGUubXmbvD0GO
MC8dM80plsTym96UxpKkQMAglKKLPtG2n8xB8v5H/uIB4oIegMSEx3F7MRWWIQmR
Gea7bQ16YCzM/l2yygGhAW61bg2Z2GoVF6X5z/qhKGyo97V87qTbmg==
-----END RSA PRIVATE KEY-----
"#;

    const RSA_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxq83nCd8AqH5n40dEBME
lbaJd2gFWu6bjhNzyp9562dpf454BUSN0uF+g3i1yzcwdvADTiuExKN1u/IoGURx
VCa0JTzAPJw6/JIoyOZnHZCoarcgQQqZ56/udkSQ2NssrwGSQjOwxMrgIdH6XeLg
GqVN4BoEEI+gpaQZa7rSytU5RFSGOnZWO2Vwgs1OBxiOiYg1gzA1spJXQhxcBWw/
v+YrUFtjxBKsG1UrWbnHbgciiN5U2v51Yztjo8A1T+o9eIG90jVo3EhS2qhbzd8m
LAsEhjV1sP8GItjfdfwXpXT7q2QG99W3PM75+HdwGLvJIrkED7YRj4CpMkz6F1et
awIDAQAB
-----END PUBLIC KEY-----
"#;
}
