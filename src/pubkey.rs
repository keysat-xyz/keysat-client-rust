//! Wrapper around the issuing server's Ed25519 public key.
//!
//! Typical usage: embed the PEM bytes of your issuer's public key into your
//! binary at build time using `include_str!`, then construct a
//! [`PublicKeyPem`] at startup.

use crate::error::{Error, Result};
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::VerifyingKey;

/// Parsed Ed25519 public key, ready for signature verification.
#[derive(Debug, Clone)]
pub struct PublicKeyPem {
    pub(crate) verifying: VerifyingKey,
}

impl PublicKeyPem {
    /// Parse a PEM-encoded Ed25519 public key. Matches the format emitted
    /// by the licensing-service `/v1/pubkey` endpoint.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(pem: &str) -> Result<Self> {
        let verifying = VerifyingKey::from_public_key_pem(pem)
            .map_err(|e| Error::BadPublicKey(e.to_string()))?;
        Ok(Self { verifying })
    }

    /// Parse raw 32-byte public-key material (no PEM envelope).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: &[u8; 32] = bytes.try_into().map_err(|_| {
            Error::BadPublicKey("raw Ed25519 public key must be exactly 32 bytes".into())
        })?;
        let verifying =
            VerifyingKey::from_bytes(arr).map_err(|e| Error::BadPublicKey(e.to_string()))?;
        Ok(Self { verifying })
    }
}
