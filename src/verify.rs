//! Offline signature verification.
//!
//! This is all you need if your app is happy to trust a key forever once it
//! was issued by the right server. For live revocation checking, combine
//! with the [`crate::online`] module.

use crate::error::{Error, Result};
use crate::key::{LicenseKey, LicensePayload};
use crate::pubkey::PublicKeyPem;
use ed25519_dalek::{Signature, Verifier as _};
use sha2::{Digest, Sha256};

/// Verifies license keys against a single issuing server's public key.
///
/// Cheap to construct and cheap to call; shareable across threads
/// (`Clone` + `Send` + `Sync`).
#[derive(Debug, Clone)]
pub struct Verifier {
    pubkey: PublicKeyPem,
}

/// Successful verification result.
#[derive(Debug, Clone)]
pub struct VerifyOk {
    /// Parsed payload fields.
    pub payload: LicensePayload,
    /// License id as a lowercase UUID string.
    pub license_id: String,
    /// Product id as a lowercase UUID string.
    pub product_id: String,
}

impl VerifyOk {
    /// Convenience: true if the key's `expires_at` is at or before `now`.
    /// Always false for perpetual keys.
    pub fn is_expired_at(&self, now_unix: i64) -> bool {
        self.payload.is_expired_at(now_unix)
    }

    /// Convenience: true if the key grants the given entitlement slug.
    pub fn has_entitlement(&self, slug: &str) -> bool {
        self.payload.has_entitlement(slug)
    }

    /// Convenience: true if the key is flagged as a trial.
    pub fn is_trial(&self) -> bool {
        self.payload.is_trial()
    }
}

impl Verifier {
    /// Construct a verifier bound to a single issuing server's public key.
    pub fn new(pubkey: PublicKeyPem) -> Self {
        Self { pubkey }
    }

    /// Verify a license key string. Returns either a [`VerifyOk`] on
    /// success or an [`Error`] explaining the failure.
    ///
    /// This checks only the cryptographic signature and format. It does
    /// **not** check expiry — call [`VerifyOk::is_expired_at`] if you want
    /// that, or use [`Self::verify_with_time`] to get an error on expired
    /// keys directly.
    pub fn verify(&self, key: &str) -> Result<VerifyOk> {
        let parsed = LicenseKey::parse(key)?;
        self.verify_parsed(&parsed)
    }

    /// Verify an already-parsed key.
    pub fn verify_parsed(&self, key: &LicenseKey) -> Result<VerifyOk> {
        let sig = Signature::from_bytes(&key.signature);
        self.pubkey
            .verifying
            .verify(&key.signed_bytes, &sig)
            .map_err(|_| Error::BadSignature)?;

        Ok(VerifyOk {
            license_id: key.payload.license_uuid(),
            product_id: key.payload.product_uuid(),
            payload: key.payload.clone(),
        })
    }

    /// Verify a key AND enforce that, if the key is fingerprint-bound, the
    /// provided fingerprint matches. If the key is *not* fingerprint-bound,
    /// the fingerprint is ignored (call [`Self::verify`] instead if that's
    /// what you want).
    pub fn verify_with_fingerprint(&self, key: &str, fingerprint: &str) -> Result<VerifyOk> {
        let parsed = LicenseKey::parse(key)?;
        let ok = self.verify_parsed(&parsed)?;
        if ok.payload.is_fingerprint_bound() {
            let expected = hash_fingerprint(fingerprint);
            if expected != ok.payload.fingerprint_hash {
                return Err(Error::BadSignature);
            }
        }
        Ok(ok)
    }

    /// Verify a key and additionally reject it if `now_unix` is past its
    /// `expires_at` (with no grace — for grace-window logic, use an online
    /// check against `/v1/validate`). Perpetual keys (`expires_at = 0`) are
    /// accepted regardless of `now_unix`.
    pub fn verify_with_time(&self, key: &str, now_unix: i64) -> Result<VerifyOk> {
        let ok = self.verify(key)?;
        if ok.payload.is_expired_at(now_unix) {
            return Err(Error::Expired);
        }
        Ok(ok)
    }
}

/// Hash a raw fingerprint string to the 32-byte form embedded in keys.
/// Matches the service-side implementation.
pub fn hash_fingerprint(raw: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
