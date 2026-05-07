//! License-key parsing. Matches the wire format defined by the service's
//! `crypto` module exactly — do not edit one without the other.
//!
//! ## Wire format
//!
//! A key string looks like `LIC1-<payload_b32>-<signature_b32>`. Both halves
//! are Crockford-style base32 (no padding) of the raw bytes.
//!
//! **v1 payload (74 bytes, fixed):**
//! ```text
//! offset  size  field
//!      0     1  version = 1
//!      1     1  flags
//!      2    16  product_id (UUID bytes, big-endian)
//!     18    16  license_id (UUID bytes, big-endian)
//!     34     8  issued_at   (i64 unix seconds, big-endian)
//!     42    32  fingerprint_hash (SHA-256 of the machine fingerprint,
//!                                 or all-zeros)
//! ```
//!
//! **v2 payload (83 bytes + variable-length entitlements):**
//! ```text
//! offset  size  field
//!      0     1  version = 2
//!      1     1  flags
//!      2    16  product_id
//!     18    16  license_id
//!     34     8  issued_at
//!     42     8  expires_at  (i64 unix seconds, 0 = perpetual)
//!     50    32  fingerprint_hash
//!     82     1  num_entitlements (u8, 0..=255)
//!     83     *  entitlements, each length-prefixed:
//!                  [u8 len] [len bytes of UTF-8 slug]
//! ```
//!
//! Clients verifying a v1 key zero-fill the v2-only fields so application
//! code can treat both versions uniformly.

use crate::error::{Error, Result};
use data_encoding::BASE32_NOPAD;

/// Key prefix every valid key starts with.
pub const KEY_PREFIX: &str = "LIC1";

/// Ed25519 signature is always 64 bytes on the wire.
pub(crate) const SIGNATURE_LEN: usize = 64;

/// v1 payload length (fixed).
pub(crate) const PAYLOAD_V1_LEN: usize = 74;
/// v2 fixed-head length — bytes before the variable entitlements tail.
pub(crate) const PAYLOAD_V2_HEAD_LEN: usize = 83;

/// v1 format identifier.
pub const KEY_VERSION_V1: u8 = 1;
/// v2 format identifier. New keys are issued as v2.
pub const KEY_VERSION_V2: u8 = 2;

/// Highest format version this client understands.
pub const KEY_VERSION: u8 = KEY_VERSION_V2;

/// Set when the key is bound to a specific machine fingerprint hash.
pub const FLAG_FINGERPRINT_BOUND: u8 = 0b0000_0001;
/// Set on keys that represent a trial — the application can treat this as a
/// hint to show a "trial" badge, limit features, nag before expiry, etc.
pub const FLAG_TRIAL: u8 = 0b0000_0010;

/// Decoded payload fields. 16-byte UUIDs are kept as raw bytes here — the
/// server also stores them as UUIDs but this library doesn't require the
/// `uuid` crate just to render hex.
#[derive(Debug, Clone)]
pub struct LicensePayload {
    /// Format version (1 or 2).
    pub version: u8,
    /// Feature flags (see [`FLAG_FINGERPRINT_BOUND`], [`FLAG_TRIAL`]).
    pub flags: u8,
    /// 16-byte product id.
    pub product_id: [u8; 16],
    /// 16-byte license id.
    pub license_id: [u8; 16],
    /// Unix seconds issued.
    pub issued_at: i64,
    /// Unix seconds when the key expires, or `0` for perpetual. Always `0`
    /// on v1 keys.
    pub expires_at: i64,
    /// SHA-256 hash of the bound fingerprint, or all-zeros.
    pub fingerprint_hash: [u8; 32],
    /// Entitlement slugs granted by this license. Empty on v1 keys.
    pub entitlements: Vec<String>,
}

impl LicensePayload {
    /// True if this key was issued bound to a specific machine fingerprint.
    pub fn is_fingerprint_bound(&self) -> bool {
        self.flags & FLAG_FINGERPRINT_BOUND != 0
    }

    /// True if this key represents a trial.
    pub fn is_trial(&self) -> bool {
        self.flags & FLAG_TRIAL != 0
    }

    /// True if `now` (unix seconds) is at or past `expires_at`. Always false
    /// for perpetual keys (`expires_at == 0`).
    pub fn is_expired_at(&self, now_unix: i64) -> bool {
        self.expires_at != 0 && now_unix >= self.expires_at
    }

    /// True if this license grants the given entitlement slug.
    pub fn has_entitlement(&self, slug: &str) -> bool {
        self.entitlements.iter().any(|e| e == slug)
    }

    /// Render the 16-byte product id as a standard lowercase UUID string.
    pub fn product_uuid(&self) -> String {
        uuid_to_string(&self.product_id)
    }

    /// Render the 16-byte license id as a lowercase UUID string.
    pub fn license_uuid(&self) -> String {
        uuid_to_string(&self.license_id)
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::BadPayloadLength {
                expected: PAYLOAD_V1_LEN,
                got: 0,
            });
        }
        match bytes[0] {
            KEY_VERSION_V1 => Self::from_bytes_v1(bytes),
            KEY_VERSION_V2 => Self::from_bytes_v2(bytes),
            other => Err(Error::UnsupportedVersion(other)),
        }
    }

    fn from_bytes_v1(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PAYLOAD_V1_LEN {
            return Err(Error::BadPayloadLength {
                expected: PAYLOAD_V1_LEN,
                got: bytes.len(),
            });
        }
        let mut product_id = [0u8; 16];
        product_id.copy_from_slice(&bytes[2..18]);
        let mut license_id = [0u8; 16];
        license_id.copy_from_slice(&bytes[18..34]);
        let issued_at = i64::from_be_bytes(bytes[34..42].try_into().unwrap());
        let mut fingerprint_hash = [0u8; 32];
        fingerprint_hash.copy_from_slice(&bytes[42..74]);
        Ok(LicensePayload {
            version: KEY_VERSION_V1,
            flags: bytes[1],
            product_id,
            license_id,
            issued_at,
            expires_at: 0,
            fingerprint_hash,
            entitlements: Vec::new(),
        })
    }

    fn from_bytes_v2(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < PAYLOAD_V2_HEAD_LEN {
            return Err(Error::BadPayloadLength {
                expected: PAYLOAD_V2_HEAD_LEN,
                got: bytes.len(),
            });
        }
        let mut product_id = [0u8; 16];
        product_id.copy_from_slice(&bytes[2..18]);
        let mut license_id = [0u8; 16];
        license_id.copy_from_slice(&bytes[18..34]);
        let issued_at = i64::from_be_bytes(bytes[34..42].try_into().unwrap());
        let expires_at = i64::from_be_bytes(bytes[42..50].try_into().unwrap());
        let mut fingerprint_hash = [0u8; 32];
        fingerprint_hash.copy_from_slice(&bytes[50..82]);
        let num_ents = bytes[82] as usize;

        let mut entitlements = Vec::with_capacity(num_ents);
        let mut cursor = PAYLOAD_V2_HEAD_LEN;
        for _ in 0..num_ents {
            if cursor >= bytes.len() {
                return Err(Error::BadFormat("truncated entitlement list"));
            }
            let len = bytes[cursor] as usize;
            cursor += 1;
            if cursor + len > bytes.len() {
                return Err(Error::BadFormat("truncated entitlement"));
            }
            let slug = std::str::from_utf8(&bytes[cursor..cursor + len])
                .map_err(|_| Error::BadFormat("entitlement not utf-8"))?
                .to_string();
            entitlements.push(slug);
            cursor += len;
        }
        // Payload must consume exactly all bytes.
        if cursor != bytes.len() {
            return Err(Error::BadFormat("trailing bytes in payload"));
        }

        Ok(LicensePayload {
            version: KEY_VERSION_V2,
            flags: bytes[1],
            product_id,
            license_id,
            issued_at,
            expires_at,
            fingerprint_hash,
            entitlements,
        })
    }
}

/// A parsed (but not yet verified) license key.
#[derive(Debug, Clone)]
pub struct LicenseKey {
    /// The parsed payload.
    pub payload: LicensePayload,
    /// The raw signed-over message (for re-verifying signatures). Length is
    /// 74 for v1 keys and `>= 83` for v2 keys.
    pub signed_bytes: Vec<u8>,
    /// Ed25519 signature over `signed_bytes`.
    pub signature: [u8; SIGNATURE_LEN],
}

impl LicenseKey {
    /// Parse a key string like `LIC1-XXXX...-YYYY...` into its components.
    /// Does NOT verify the signature — use [`crate::Verifier`] for that.
    pub fn parse(key: &str) -> Result<Self> {
        let key = key.trim();
        let mut parts = key.splitn(3, '-');
        let prefix = parts.next().ok_or(Error::BadFormat("missing prefix"))?;
        if prefix != KEY_PREFIX {
            return Err(Error::BadFormat("unknown prefix"));
        }
        let payload_b32 = parts.next().ok_or(Error::BadFormat("missing payload"))?;
        let signature_b32 = parts.next().ok_or(Error::BadFormat("missing signature"))?;

        let payload_bytes = BASE32_NOPAD
            .decode(payload_b32.as_bytes())
            .map_err(|_| Error::BadEncoding("payload"))?;
        let signature_bytes = BASE32_NOPAD
            .decode(signature_b32.as_bytes())
            .map_err(|_| Error::BadEncoding("signature"))?;

        let payload = LicensePayload::from_bytes(&payload_bytes)?;

        if signature_bytes.len() != SIGNATURE_LEN {
            return Err(Error::BadFormat("signature wrong size"));
        }
        let mut sig = [0u8; SIGNATURE_LEN];
        sig.copy_from_slice(&signature_bytes);

        Ok(LicenseKey {
            payload,
            signed_bytes: payload_bytes,
            signature: sig,
        })
    }
}

fn uuid_to_string(b: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_prefix() {
        let err = LicenseKey::parse("WRONG-AAAA-BBBB").unwrap_err();
        assert!(matches!(err, Error::BadFormat(_)));
    }

    #[test]
    fn rejects_missing_parts() {
        assert!(LicenseKey::parse("LIC1").is_err());
        assert!(LicenseKey::parse("LIC1-AAAA").is_err());
    }

    #[test]
    fn rejects_unknown_version() {
        // v99 payload: version=99, 82 zero bytes of filler, no entitlements.
        let mut v99 = vec![99u8];
        v99.extend(vec![0u8; PAYLOAD_V2_HEAD_LEN]); // enough bytes for v2 if version were right
        let err = LicensePayload::from_bytes(&v99).unwrap_err();
        assert!(matches!(err, Error::UnsupportedVersion(99)));
    }

    #[test]
    fn parses_v1_fixed_size() {
        let mut p = vec![KEY_VERSION_V1, 0u8];
        p.extend(std::iter::repeat(0u8).take(PAYLOAD_V1_LEN - 2));
        let parsed = LicensePayload::from_bytes(&p).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.expires_at, 0);
        assert!(parsed.entitlements.is_empty());
    }
}
