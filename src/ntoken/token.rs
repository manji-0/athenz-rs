use crate::error::Error;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use p256::ecdsa::Signature as P256Signature;
use p384::ecdsa::Signature as P384Signature;
use p521::ecdsa::Signature as P521Signature;
use rand::RngCore;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use sha2::Sha256;
use signature::SignatureEncoding;
use signature::Signer as SignatureSigner;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::keys::{load_private_key, PrivateKey};

pub(super) const DEFAULT_VERSION: &str = "S1";
pub(super) const DEFAULT_EXPIRATION: Duration = Duration::from_secs(60 * 60);
pub(super) const EXPIRATION_DRIFT: Duration = Duration::from_secs(10 * 60);

pub(super) const TAG_VERSION: &str = "v";
pub(super) const TAG_DOMAIN: &str = "d";
pub(super) const TAG_NAME: &str = "n";
pub(super) const TAG_KEY_VERSION: &str = "k";
pub(super) const TAG_KEY_SERVICE: &str = "z";
pub(super) const TAG_HOSTNAME: &str = "h";
pub(super) const TAG_IP: &str = "i";
pub(super) const TAG_ORIGINAL_REQUESTOR: &str = "o";
pub(super) const TAG_GENERATION_TIME: &str = "t";
pub(super) const TAG_EXPIRE_TIME: &str = "e";
pub(super) const TAG_SALT: &str = "a";
pub(super) const TAG_SIGNATURE: &str = "s";
pub(super) const TAG_AUTHORIZED_SERVICES: &str = "b";
pub(super) const TAG_AUTHORIZED_SERVICE_KEY_ID: &str = "bk";
pub(super) const TAG_AUTHORIZED_SERVICE_NAME: &str = "bn";
pub(super) const TAG_AUTHORIZED_SERVICE_SIGNATURE: &str = "bs";

#[derive(Debug, Clone)]
pub struct NToken {
    pub version: String,
    pub domain: String,
    pub name: String,
    pub key_version: String,
    pub key_service: Option<String>,
    pub hostname: Option<String>,
    pub ip: Option<String>,
    pub original_requestor: Option<String>,
    pub authorized_services: Option<Vec<String>>,
    pub authorized_service_key_id: Option<String>,
    pub authorized_service_name: Option<String>,
    pub authorized_service_signature: Option<String>,
    pub generation_time: i64,
    pub expiry_time: i64,
}

pub type NTokenClaims = NToken;

impl NToken {
    /// Returns the principal name in `domain.name` form.
    pub fn principal_name(&self) -> String {
        format!("{}.{}", self.domain, self.name)
    }

    /// Returns true when the token has expired.
    pub fn is_expired(&self) -> bool {
        let now = unix_time_now();
        self.expiry_time <= now
    }
}

#[derive(Debug, Clone)]
pub struct NTokenBuilder {
    domain: String,
    name: String,
    key_version: String,
    version: String,
    key_service: Option<String>,
    hostname: Option<String>,
    ip: Option<String>,
    original_requestor: Option<String>,
    expiration: Duration,
}

impl NTokenBuilder {
    /// Creates a builder with defaults and lowercased identifiers.
    pub fn new(
        domain: impl Into<String>,
        name: impl Into<String>,
        key_version: impl Into<String>,
    ) -> Self {
        let mut domain = domain.into();
        domain.make_ascii_lowercase();
        let mut name = name.into();
        name.make_ascii_lowercase();
        let mut key_version = key_version.into();
        key_version.make_ascii_lowercase();
        Self {
            domain,
            name,
            key_version,
            version: DEFAULT_VERSION.to_string(),
            key_service: None,
            hostname: None,
            ip: None,
            original_requestor: None,
            expiration: DEFAULT_EXPIRATION,
        }
    }

    /// Sets the token version.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Sets the key service name (stored in lowercase).
    pub fn with_key_service(mut self, key_service: impl Into<String>) -> Self {
        let mut key_service = key_service.into();
        key_service.make_ascii_lowercase();
        self.key_service = Some(key_service);
        self
    }

    /// Sets the hostname claim.
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Sets the IP address claim.
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip = Some(ip.into());
        self
    }

    /// Sets the original requestor claim (stored in lowercase).
    pub fn with_original_requestor(mut self, original_requestor: impl Into<String>) -> Self {
        let mut original_requestor = original_requestor.into();
        original_requestor.make_ascii_lowercase();
        if original_requestor.is_empty() {
            self.original_requestor = None;
        } else {
            self.original_requestor = Some(original_requestor);
        }
        self
    }

    /// Sets the token expiration duration.
    pub fn with_expiration(mut self, expiration: Duration) -> Self {
        self.expiration = expiration;
        self
    }

    /// Sets the token version.
    pub fn set_version(&mut self, version: impl Into<String>) -> &mut Self {
        self.version = version.into();
        self
    }

    /// Sets the key service name (stored in lowercase).
    pub fn set_key_service(&mut self, key_service: impl Into<String>) -> &mut Self {
        let mut key_service = key_service.into();
        key_service.make_ascii_lowercase();
        self.key_service = Some(key_service);
        self
    }

    /// Sets the hostname claim.
    pub fn set_hostname(&mut self, hostname: impl Into<String>) -> &mut Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Sets the IP address claim.
    pub fn set_ip(&mut self, ip: impl Into<String>) -> &mut Self {
        self.ip = Some(ip.into());
        self
    }

    /// Sets the original requestor claim (stored in lowercase).
    pub fn set_original_requestor(&mut self, original_requestor: impl Into<String>) -> &mut Self {
        let mut original_requestor = original_requestor.into();
        original_requestor.make_ascii_lowercase();
        if original_requestor.is_empty() {
            self.original_requestor = None;
        } else {
            self.original_requestor = Some(original_requestor);
        }
        self
    }

    /// Sets the token expiration duration.
    pub fn set_expiration(&mut self, expiration: Duration) -> &mut Self {
        self.expiration = expiration;
        self
    }

    /// Signs and returns an NToken using the provided private key PEM.
    pub fn sign(&self, private_key_pem: &[u8]) -> Result<String, Error> {
        let key = load_private_key(private_key_pem)?;
        let (token, _) = sign_with_key(self, &key)?;
        Ok(token)
    }

    fn unsigned_token(&self, now: i64, expiry: i64, salt: &str) -> String {
        let mut parts = Vec::new();
        parts.push(format!("{TAG_VERSION}={}", self.version));
        parts.push(format!("{TAG_DOMAIN}={}", self.domain));
        parts.push(format!("{TAG_NAME}={}", self.name));
        parts.push(format!("{TAG_KEY_VERSION}={}", self.key_version));
        if let Some(ref key_service) = self.key_service {
            parts.push(format!("{TAG_KEY_SERVICE}={key_service}"));
        }
        if let Some(ref hostname) = self.hostname {
            parts.push(format!("{TAG_HOSTNAME}={hostname}"));
        }
        if let Some(ref ip) = self.ip {
            parts.push(format!("{TAG_IP}={ip}"));
        }
        if let Some(ref original_requestor) = self.original_requestor {
            parts.push(format!("{TAG_ORIGINAL_REQUESTOR}={original_requestor}"));
        }
        parts.push(format!("{TAG_SALT}={salt}"));
        parts.push(format!("{TAG_GENERATION_TIME}={now}"));
        parts.push(format!("{TAG_EXPIRE_TIME}={expiry}"));
        parts.join(";")
    }
}

pub(super) fn sign_with_key(
    builder: &NTokenBuilder,
    key: &PrivateKey,
) -> Result<(String, i64), Error> {
    let now = unix_time_now();
    let expiry = now + builder.expiration.as_secs() as i64;
    let token = sign_with_key_at_internal(builder, key, now, expiry)?;
    Ok((token, expiry))
}

#[cfg(test)]
pub(super) fn sign_with_key_at(
    builder: &NTokenBuilder,
    key: &PrivateKey,
    now: i64,
    expiry: i64,
) -> Result<String, Error> {
    sign_with_key_at_internal(builder, key, now, expiry)
}

fn sign_with_key_at_internal(
    builder: &NTokenBuilder,
    key: &PrivateKey,
    now: i64,
    expiry: i64,
) -> Result<String, Error> {
    let salt = random_salt()?;
    let unsigned = builder.unsigned_token(now, expiry, &salt);
    let signature = match key {
        PrivateKey::Rsa(rsa_key) => {
            let signing_key = RsaSigningKey::<Sha256>::new(rsa_key.clone());
            let sig = signing_key.sign(unsigned.as_bytes());
            sig.to_vec()
        }
        PrivateKey::P256(signing_key) => {
            let sig: P256Signature = signing_key.sign(unsigned.as_bytes());
            sig.to_der().as_bytes().to_vec()
        }
        PrivateKey::P384(signing_key) => {
            let sig: P384Signature = signing_key.sign(unsigned.as_bytes());
            sig.to_der().as_bytes().to_vec()
        }
        PrivateKey::P521(signing_key) => {
            let sig: P521Signature = signing_key.sign(unsigned.as_bytes());
            sig.to_der().as_bytes().to_vec()
        }
    };
    let signature = ybase64_encode(&signature);
    Ok(format!("{unsigned};{TAG_SIGNATURE}={signature}"))
}

pub(super) fn unix_time_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn random_salt() -> Result<String, Error> {
    let mut buf = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut buf);
    Ok(hex::encode(buf))
}

fn ybase64_encode(data: &[u8]) -> String {
    let encoded = BASE64_STD.encode(data);
    encoded
        .replace('+', ".")
        .replace('/', "_")
        .replace('=', "-")
}

#[cfg(test)]
mod tests {
    use super::{sign_with_key_at, NTokenBuilder, PrivateKey, TAG_SIGNATURE};
    use crate::ybase64::decode as ybase64_decode;
    use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
    use p384::ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey};
    use p521::ecdsa::{Signature as P521Signature, SigningKey as P521SigningKey};
    use rand::thread_rng;

    fn signature_bytes(token: &str) -> Vec<u8> {
        let marker = format!(";{TAG_SIGNATURE}=");
        let signature = token
            .rsplit_once(&marker)
            .map(|(_, value)| value)
            .expect("signature");
        ybase64_decode(signature).expect("decode signature")
    }

    #[test]
    fn ntoken_p256_signature_is_der_encoded() {
        let builder = NTokenBuilder::new("sports", "api", "v1");
        let key = PrivateKey::P256(P256SigningKey::random(&mut thread_rng()));
        let token = sign_with_key_at(&builder, &key, 1, 2).expect("token");
        let sig = signature_bytes(&token);

        assert!(P256Signature::from_der(&sig).is_ok());
        assert_ne!(sig.len(), 64);
    }

    #[test]
    fn ntoken_p384_signature_is_der_encoded() {
        let builder = NTokenBuilder::new("sports", "api", "v1");
        let key = PrivateKey::P384(P384SigningKey::random(&mut thread_rng()));
        let token = sign_with_key_at(&builder, &key, 1, 2).expect("token");
        let sig = signature_bytes(&token);

        assert!(P384Signature::from_der(&sig).is_ok());
        assert_ne!(sig.len(), 96);
    }

    #[test]
    fn ntoken_p521_signature_is_der_encoded() {
        let builder = NTokenBuilder::new("sports", "api", "v1");
        let key = PrivateKey::P521(P521SigningKey::random(&mut thread_rng()));
        let token = sign_with_key_at(&builder, &key, 1, 2).expect("token");
        let sig = signature_bytes(&token);

        assert!(P521Signature::from_der(&sig).is_ok());
        assert_ne!(sig.len(), 132);
    }
}
