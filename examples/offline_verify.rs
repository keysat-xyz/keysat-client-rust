//! Minimum-viable license check, entirely offline.
//!
//! Run with:
//!
//!     cargo run --example offline_verify --no-default-features --features offline -- <LIC1-...>
//!
//! In real life you'd embed the public key with `include_str!` — here we
//! read it from an env var so the example has zero build-time coupling.

use licensing_client::{PublicKeyPem, Verifier};
use std::env;

fn main() {
    let pem = env::var("LICENSING_PUBKEY_PEM").expect("set LICENSING_PUBKEY_PEM to your issuer's public key");
    let key = env::args()
        .nth(1)
        .expect("pass a license key as the first argument");

    let verifier = Verifier::new(PublicKeyPem::from_str(&pem).expect("parse pubkey"));
    match verifier.verify(&key) {
        Ok(ok) => {
            println!("license OK");
            println!("  license_id = {}", ok.license_id);
            println!("  product_id = {}", ok.product_id);
            println!("  issued_at  = {}", ok.payload.issued_at);
        }
        Err(e) => {
            eprintln!("license REJECTED: {e}");
            std::process::exit(1);
        }
    }
}
