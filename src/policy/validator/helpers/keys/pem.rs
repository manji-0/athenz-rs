use crate::error::Error;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use pem::parse_many;
use pkcs8::DecodePublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::RsaPublicKey;

#[derive(Clone)]
pub(in crate::policy::validator) enum PublicKey {
    Rsa(RsaPublicKey),
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    P521(p521::ecdsa::VerifyingKey),
}

pub(in crate::policy::validator) fn load_public_key(pem_bytes: &[u8]) -> Result<PublicKey, Error> {
    let blocks =
        parse_many(pem_bytes).map_err(|e| Error::Crypto(format!("pem parse error: {e}")))?;
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
                        .map_err(|e| Error::Crypto(format!("p256 public key error: {e}")))?;
                    return Ok(PublicKey::P256(key));
                }
                if let Ok(key) = p384::PublicKey::from_public_key_der(block.contents()) {
                    let encoded = key.to_encoded_point(false);
                    let key = p384::ecdsa::VerifyingKey::from_encoded_point(&encoded)
                        .map_err(|e| Error::Crypto(format!("p384 public key error: {e}")))?;
                    return Ok(PublicKey::P384(key));
                }
                if let Ok(key) = p521::PublicKey::from_public_key_der(block.contents()) {
                    let encoded = key.to_encoded_point(false);
                    let key = p521::ecdsa::VerifyingKey::from_encoded_point(&encoded)
                        .map_err(|e| Error::Crypto(format!("p521 public key error: {e}")))?;
                    return Ok(PublicKey::P521(key));
                }
            }
            _ => {}
        }
    }
    Err(Error::Crypto("unsupported public key format".to_string()))
}

pub(in crate::policy::validator) trait EcdsaVerifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error>;
}

impl EcdsaVerifier for p256::ecdsa::VerifyingKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let sig = p256::ecdsa::Signature::from_slice(signature)
            .map_err(|e| Error::Crypto(format!("p256 signature error: {e}")))?;
        signature::Verifier::verify(self, message, &sig)
            .map_err(|e| Error::Crypto(format!("p256 verify error: {e}")))
    }
}

impl EcdsaVerifier for p384::ecdsa::VerifyingKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let sig = p384::ecdsa::Signature::from_slice(signature)
            .map_err(|e| Error::Crypto(format!("p384 signature error: {e}")))?;
        signature::Verifier::verify(self, message, &sig)
            .map_err(|e| Error::Crypto(format!("p384 verify error: {e}")))
    }
}

impl EcdsaVerifier for p521::ecdsa::VerifyingKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let sig = p521::ecdsa::Signature::from_slice(signature)
            .map_err(|e| Error::Crypto(format!("p521 signature error: {e}")))?;
        signature::Verifier::verify(self, message, &sig)
            .map_err(|e| Error::Crypto(format!("p521 verify error: {e}")))
    }
}
