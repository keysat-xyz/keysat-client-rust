# licensing-client

Rust client for [`Keysat`](https://github.com/keysat-xyz/keysat) — a self-hosted Bitcoin-paid software licensing server that runs on Start9.

## What you get

- **Offline verification**: check a license key with just the issuing server's public key. No network. Default feature.
- **Online validation**: live revocation check and fingerprint binding via the service's `/v1/validate` endpoint. Optional.
- **Purchase flow**: kick off a BTCPay checkout and poll for the issued key. Optional.

## Install

```toml
[dependencies]
licensing-client = "0.1"

# Or, with the online features:
licensing-client = { version = "0.1", features = ["online"] }
```

## 5-line offline check

```rust
use licensing_client::{Verifier, PublicKeyPem};

let pubkey = PublicKeyPem::from_str(include_str!("issuer.pub"))?;
let verifier = Verifier::new(pubkey);
let ok = verifier.verify(&key_from_user)?;
println!("licensed for product {}", ok.product_id);
```

That's the whole integration. `include_str!("issuer.pub")` embeds your public key at build time; if the verifier says OK, the key is real and was issued by you.

## 10-line online check (with revocation + fingerprint)

```rust
use licensing_client::online::Client;

let client = Client::new("https://license.example.com")?;
let result = client
    .validate(&key_from_user, Some("my-product"), Some(&machine_fingerprint))
    .await?;
if !result.ok {
    eprintln!("rejected: {:?}", result.reason);
    std::process::exit(1);
}
```

The server enforces revocation live and does trust-on-first-use fingerprint binding, so the same key used from a second machine gets rejected.

## Purchase flow

```rust
use licensing_client::StartPurchaseOptions;

// Default tier:
let session = client.start_purchase("my-product", &Default::default()).await?;

// Specific tier (e.g. Pro):
let session = client.start_purchase("my-product", &StartPurchaseOptions {
    policy_slug: Some("pro"),
    buyer_email: Some("buyer@example.com"),
    ..Default::default()
}).await?;

// open session.checkout_url in the user's browser
loop {
    let poll = client.poll_purchase(&session.invoice_id).await?;
    if let Some(key) = poll.license_key { break key; }
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
}
```

## License

MIT OR Apache-2.0.
