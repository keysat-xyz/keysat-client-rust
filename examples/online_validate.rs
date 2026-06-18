//! Full purchase-and-validate round trip against a running
//! licensing-service instance.
//!
//!     cargo run --example online_validate --features online -- <base-url> <product-slug>
//!
//! The example will start a purchase, print the BTCPay checkout URL for
//! you to pay, then poll until a license key is issued and validate it.

use keysat_licensing_client::online::Client;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let base_url = args.next().expect("pass base URL, e.g. https://license.example.com");
    let product_slug = args.next().expect("pass product slug");

    let client = Client::new(&base_url)?;

    let session = client
        .start_purchase(&product_slug, &Default::default())
        .await?;
    println!("open the checkout in your browser:");
    println!("  {}", session.checkout_url);
    println!("waiting for settlement...");

    let license = loop {
        sleep(Duration::from_secs(5)).await;
        let p = client.poll_purchase(&session.invoice_id).await?;
        if let Some(k) = p.license_key {
            break k;
        }
        println!("  status: {}", p.status);
        if p.status == "expired" || p.status == "invalid" {
            return Err(format!("invoice ended in status {}", p.status).into());
        }
    };

    println!("license issued:\n  {license}");

    let validated = client
        .validate(&license, Some(&product_slug), None)
        .await?;
    println!("server says: ok={} reason={:?}", validated.ok, validated.reason);

    Ok(())
}
