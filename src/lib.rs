//! # licensing-client
//!
//! Client library for the **licensing-service** — an open-source,
//! Bitcoin-native self-hosted software licensing service for Start9 boxes.
//!
//! This crate gives your app everything it needs to check license keys
//! issued by a `licensing-service` instance:
//!
//! - **Offline verification** — validate a signed license key without any
//!   network call. You only need the issuing server's Ed25519 public key
//!   (typically embedded in your binary at build time).
//! - **Online validation** — POST to the service's `/v1/validate` endpoint
//!   for live revocation checking and TOFU fingerprint binding.
//! - **Purchase flow** — open a checkout URL for the buyer and poll for a
//!   newly-issued license key.
//!
//! ## 5-line integration example
//!
//! ```no_run
//! use keysat_licensing_client::{Verifier, PublicKeyPem};
//!
//! // In real use, embed your issuer's key at build time:
//! //   PublicKeyPem::from_str(include_str!("../my_issuer.pub"))
//! let pubkey = PublicKeyPem::from_str("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----").unwrap();
//! let verifier = Verifier::new(pubkey);
//! let result = verifier.verify("LIC1-...").expect("valid license");
//! println!("license ok for product {}", result.product_id);
//! ```
//!
//! The `online` feature (off by default) adds an async HTTP client for
//! revocation checks and the purchase flow.

#![deny(missing_docs)]

pub mod error;
pub mod key;
#[cfg(feature = "online")]
pub mod online;
pub mod pubkey;
pub mod verify;

pub use error::{Error, Result};
pub use key::{
    LicenseKey, LicensePayload, FLAG_FINGERPRINT_BOUND, FLAG_TRIAL, KEY_VERSION,
    KEY_VERSION_V1, KEY_VERSION_V2,
};
pub use pubkey::PublicKeyPem;
pub use verify::{Verifier, VerifyOk};

#[cfg(feature = "online")]
pub use online::{
    Client, EntitlementDef, MachineResponse, PollResponse, PublicPoliciesProduct,
    PublicPoliciesResponse, PublicPolicy, PurchaseSession, StartPurchaseOptions,
    ValidateRequest, ValidateResponse,
};
