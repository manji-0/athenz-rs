use crate::error::Error;
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p384::ecdsa::{SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey};
use p521::ecdsa::{SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey};
use pem::parse_many;
use pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};

#[derive(Clone)]
pub(super) enum PrivateKey {
    Rsa(RsaPrivateKey),
    P256(P256SigningKey),
    P384(P384SigningKey),
    P521(P521SigningKey),
}

#[derive(Clone)]
pub(super) enum PublicKey {
    Rsa(RsaPublicKey),
    P256(P256VerifyingKey),
    P384(P384VerifyingKey),
    P521(P521VerifyingKey),
}

pub(super) fn load_private_key(pem_bytes: &[u8]) -> Result<PrivateKey, Error> {
    let blocks =
        parse_many(pem_bytes).map_err(|e| Error::Crypto(format!("pem parse error: {e}")))?;
    for block in blocks {
        match block.tag() {
            "RSA PRIVATE KEY" => {
                if let Ok(key) = parse_rsa_private_pkcs1(block.contents()) {
                    return Ok(key);
                }
            }
            "PRIVATE KEY" => {
                if let Ok(key) = parse_rsa_private_pkcs8(block.contents()) {
                    return Ok(key);
                }
                if let Ok(key) = parse_ec_private_pkcs8(block.contents()) {
                    return Ok(key);
                }
            }
            _ => {}
        }
    }
    Err(Error::Crypto("unsupported private key format".to_string()))
}

pub(super) fn load_public_key(pem_bytes: &[u8]) -> Result<PublicKey, Error> {
    let blocks =
        parse_many(pem_bytes).map_err(|e| Error::Crypto(format!("pem parse error: {e}")))?;
    for block in blocks {
        match block.tag() {
            "RSA PUBLIC KEY" => {
                if let Ok(key) = parse_rsa_public_pkcs1(block.contents()) {
                    return Ok(key);
                }
            }
            "PUBLIC KEY" => {
                if let Ok(key) = parse_rsa_public_pkcs8(block.contents()) {
                    return Ok(key);
                }
                if let Ok(key) = parse_ec_public_pkcs8(block.contents()) {
                    return Ok(key);
                }
            }
            _ => {}
        }
    }
    Err(Error::Crypto("unsupported public key format".to_string()))
}

fn parse_rsa_private_pkcs1(der: &[u8]) -> Result<PrivateKey, Error> {
    let key = RsaPrivateKey::from_pkcs1_der(der)
        .map_err(|e| Error::Crypto(format!("rsa pkcs1 private key error: {e}")))?;
    Ok(PrivateKey::Rsa(key))
}

fn parse_rsa_private_pkcs8(der: &[u8]) -> Result<PrivateKey, Error> {
    let key = RsaPrivateKey::from_pkcs8_der(der)
        .map_err(|e| Error::Crypto(format!("rsa pkcs8 private key error: {e}")))?;
    Ok(PrivateKey::Rsa(key))
}

fn parse_ec_private_pkcs8(der: &[u8]) -> Result<PrivateKey, Error> {
    if let Ok(secret) = p256::SecretKey::from_pkcs8_der(der) {
        let key = P256SigningKey::from_bytes(&secret.to_bytes())
            .map_err(|e| Error::Crypto(format!("p256 signing key error: {e}")))?;
        return Ok(PrivateKey::P256(key));
    }
    if let Ok(secret) = p384::SecretKey::from_pkcs8_der(der) {
        let key = P384SigningKey::from_bytes(&secret.to_bytes())
            .map_err(|e| Error::Crypto(format!("p384 signing key error: {e}")))?;
        return Ok(PrivateKey::P384(key));
    }
    if let Ok(secret) = p521::SecretKey::from_pkcs8_der(der) {
        let key = P521SigningKey::from_bytes(&secret.to_bytes())
            .map_err(|e| Error::Crypto(format!("p521 signing key error: {e}")))?;
        return Ok(PrivateKey::P521(key));
    }
    Err(Error::Crypto(
        "unsupported ec pkcs8 private key".to_string(),
    ))
}

fn parse_rsa_public_pkcs1(der: &[u8]) -> Result<PublicKey, Error> {
    let key = RsaPublicKey::from_pkcs1_der(der)
        .map_err(|e| Error::Crypto(format!("rsa pkcs1 public key error: {e}")))?;
    Ok(PublicKey::Rsa(key))
}

fn parse_rsa_public_pkcs8(der: &[u8]) -> Result<PublicKey, Error> {
    let key = RsaPublicKey::from_public_key_der(der)
        .map_err(|e| Error::Crypto(format!("rsa pkcs8 public key error: {e}")))?;
    Ok(PublicKey::Rsa(key))
}

fn parse_ec_public_pkcs8(der: &[u8]) -> Result<PublicKey, Error> {
    if let Ok(public_key) = p256::PublicKey::from_public_key_der(der) {
        let encoded = public_key.to_encoded_point(false);
        let key = P256VerifyingKey::from_encoded_point(&encoded)
            .map_err(|e| Error::Crypto(format!("p256 public key error: {e}")))?;
        return Ok(PublicKey::P256(key));
    }
    if let Ok(public_key) = p384::PublicKey::from_public_key_der(der) {
        let encoded = public_key.to_encoded_point(false);
        let key = P384VerifyingKey::from_encoded_point(&encoded)
            .map_err(|e| Error::Crypto(format!("p384 public key error: {e}")))?;
        return Ok(PublicKey::P384(key));
    }
    if let Ok(public_key) = p521::PublicKey::from_public_key_der(der) {
        let encoded = public_key.to_encoded_point(false);
        let key = P521VerifyingKey::from_encoded_point(&encoded)
            .map_err(|e| Error::Crypto(format!("p521 public key error: {e}")))?;
        return Ok(PublicKey::P521(key));
    }
    Err(Error::Crypto("unsupported ec public key".to_string()))
}
