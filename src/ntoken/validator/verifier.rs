use crate::error::Error;
use p256::ecdsa::Signature as P256Signature;
use p384::ecdsa::Signature as P384Signature;
use p521::ecdsa::Signature as P521Signature;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use sha2::Sha256;
use signature::Verifier as SignatureVerifier;

use super::super::keys::{load_public_key, PublicKey};
use super::helpers::ybase64_decode;

#[derive(Clone)]
pub struct NTokenVerifier {
    key: PublicKey,
}

impl NTokenVerifier {
    /// Creates a verifier from a PEM-encoded public key.
    pub fn from_public_key_pem(public_key_pem: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            key: load_public_key(public_key_pem)?,
        })
    }

    /// Verifies the signature over the unsigned token string.
    pub fn verify(&self, unsigned: &str, signature: &str) -> Result<(), Error> {
        let sig_bytes = ybase64_decode(signature)?;
        match &self.key {
            PublicKey::Rsa(rsa_key) => {
                let verifying_key = RsaVerifyingKey::<Sha256>::new(rsa_key.clone());
                let sig = RsaSignature::try_from(sig_bytes.as_slice())
                    .map_err(|e| Error::Crypto(format!("rsa signature parse error: {e}")))?;
                verifying_key
                    .verify(unsigned.as_bytes(), &sig)
                    .map_err(|e| Error::Crypto(format!("rsa signature verify error: {e}")))?;
                Ok(())
            }
            PublicKey::P256(verifying_key) => {
                let sig = P256Signature::from_der(&sig_bytes)
                    .map_err(|e| Error::Crypto(format!("p256 signature parse error: {e}")))?;
                verifying_key
                    .verify(unsigned.as_bytes(), &sig)
                    .map_err(|e| Error::Crypto(format!("p256 signature verify error: {e}")))?;
                Ok(())
            }
            PublicKey::P384(verifying_key) => {
                let sig = P384Signature::from_der(&sig_bytes)
                    .map_err(|e| Error::Crypto(format!("p384 signature parse error: {e}")))?;
                verifying_key
                    .verify(unsigned.as_bytes(), &sig)
                    .map_err(|e| Error::Crypto(format!("p384 signature verify error: {e}")))?;
                Ok(())
            }
            PublicKey::P521(verifying_key) => {
                let sig = P521Signature::from_der(&sig_bytes)
                    .map_err(|e| Error::Crypto(format!("p521 signature parse error: {e}")))?;
                verifying_key
                    .verify(unsigned.as_bytes(), &sig)
                    .map_err(|e| Error::Crypto(format!("p521 signature verify error: {e}")))?;
                Ok(())
            }
        }
    }
}
