//! Online operations against a running `licensing-service` instance.
//!
//! Two things this module gives you:
//!
//! 1. [`Client::validate`] — server-authoritative validation that checks
//!    revocation and (optionally) binds / enforces the machine fingerprint.
//! 2. [`Client::start_purchase`] + [`Client::poll_purchase`] — kick off a
//!    BTCPay checkout and watch for the resulting license key.
//!
//! All methods are `async` and built on `reqwest`. Enable with the `online`
//! feature.

use crate::error::{Error, Result};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use url::Url;

/// An async HTTP client pinned to one licensing-service base URL.
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    base: Url,
}

impl Client {
    /// Construct a client pointed at `base_url` (e.g. `"https://license.example.com"`).
    pub fn new(base_url: &str) -> Result<Self> {
        let base = Url::parse(base_url).map_err(|e| Error::BadUrl(e.to_string()))?;
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .map_err(Error::Http)?,
            base,
        })
    }

    /// Fetch the server's public key as a PEM string. Useful for bootstrap
    /// scripts; in production you should embed the key into your binary
    /// instead, so a compromised server can't swap its own key under you.
    pub async fn fetch_pubkey(&self) -> Result<String> {
        let url = self
            .base
            .join("/v1/pubkey")
            .map_err(|e| Error::BadUrl(e.to_string()))?;
        let resp = self.http.get(url).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(Error::Server {
                status: status.as_u16(),
                body: text,
            });
        }
        #[derive(Deserialize)]
        struct PubkeyResp {
            public_key_pem: String,
        }
        let p: PubkeyResp =
            serde_json::from_str(&text).map_err(|e| Error::Other(e.to_string()))?;
        Ok(p.public_key_pem)
    }

    /// Call the server's `/v1/validate` endpoint. Server enforces
    /// revocation, expiry/grace, suspension, entitlements, and (if a
    /// fingerprint is supplied) seat binding / cap enforcement.
    pub async fn validate(
        &self,
        key: &str,
        product_slug: Option<&str>,
        fingerprint: Option<&str>,
    ) -> Result<ValidateResponse> {
        self.validate_full(ValidateRequest {
            key,
            product_slug,
            fingerprint,
            hostname: None,
            platform: None,
        })
        .await
    }

    /// Same as [`Self::validate`] but with optional `hostname` and `platform`
    /// descriptors recorded against the machine row on activation.
    pub async fn validate_full(&self, req: ValidateRequest<'_>) -> Result<ValidateResponse> {
        let url = self
            .base
            .join("/v1/validate")
            .map_err(|e| Error::BadUrl(e.to_string()))?;
        let resp = self.http.post(url).json(&req).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if status != StatusCode::OK {
            return Err(Error::Server {
                status: status.as_u16(),
                body: text,
            });
        }
        serde_json::from_str(&text).map_err(|e| Error::Other(e.to_string()))
    }

    /// Send a heartbeat for an already-activated seat. Lightweight — the
    /// server updates `last_heartbeat_at` so admin tooling can spot stale
    /// installs.
    pub async fn heartbeat(&self, key: &str, fingerprint: &str) -> Result<MachineResponse> {
        self.machine_call("/v1/machines/heartbeat", key, fingerprint, None).await
    }

    /// Explicitly activate a seat for `fingerprint`. Behaves identically to a
    /// `/v1/validate` call that would have auto-activated — useful when you
    /// want to prompt the user about seat usage before starting up.
    pub async fn activate(
        &self,
        key: &str,
        fingerprint: &str,
    ) -> Result<MachineResponse> {
        self.machine_call("/v1/machines/activate", key, fingerprint, None).await
    }

    /// Free the seat currently held by `fingerprint`. Returns `ok: true` on
    /// success; the user can then activate on a different machine without
    /// hitting the seat cap.
    pub async fn deactivate(
        &self,
        key: &str,
        fingerprint: &str,
        reason: Option<&str>,
    ) -> Result<MachineResponse> {
        self.machine_call("/v1/machines/deactivate", key, fingerprint, reason).await
    }

    async fn machine_call(
        &self,
        path: &str,
        key: &str,
        fingerprint: &str,
        reason: Option<&str>,
    ) -> Result<MachineResponse> {
        let url = self
            .base
            .join(path)
            .map_err(|e| Error::BadUrl(e.to_string()))?;
        #[derive(Serialize)]
        struct Req<'a> {
            key: &'a str,
            fingerprint: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            reason: Option<&'a str>,
        }
        let body = Req { key, fingerprint, reason };
        let resp = self.http.post(url).json(&body).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if status != StatusCode::OK {
            return Err(Error::Server {
                status: status.as_u16(),
                body: text,
            });
        }
        serde_json::from_str(&text).map_err(|e| Error::Other(e.to_string()))
    }

    /// Start a purchase for `product_slug`. Returns the BTCPay checkout URL
    /// to open in the buyer's browser and the invoice id to poll.
    ///
    /// Use [`StartPurchaseOptions`] to pass tier (`policy_slug`), buyer
    /// email, redirect URL, discount code, and buyer note. For the simple
    /// "default tier, no extras" case, pass `&Default::default()`.
    pub async fn start_purchase(
        &self,
        product_slug: &str,
        options: &StartPurchaseOptions<'_>,
    ) -> Result<PurchaseSession> {
        let url = self
            .base
            .join("/v1/purchase")
            .map_err(|e| Error::BadUrl(e.to_string()))?;

        #[derive(Serialize)]
        struct Req<'a> {
            product: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            buyer_email: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            buyer_note: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            redirect_url: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            code: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            policy_slug: Option<&'a str>,
        }
        let body = Req {
            product: product_slug,
            buyer_email: options.buyer_email,
            buyer_note: options.buyer_note,
            redirect_url: options.redirect_url,
            code: options.code,
            policy_slug: options.policy_slug,
        };
        let resp = self.http.post(url).json(&body).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(Error::Server {
                status: status.as_u16(),
                body: text,
            });
        }
        serde_json::from_str(&text).map_err(|e| Error::Other(e.to_string()))
    }

    /// List public, buyer-visible policies (tiers) for a product. No
    /// auth required — same data the licensing service's `/buy/<slug>`
    /// page uses server-side. Use this to render an in-app tier picker
    /// that stays in sync with the operator's admin-side tier setup.
    ///
    /// Internal fields (id, tip recipients, raw metadata) are
    /// deliberately omitted by the server.
    pub async fn list_public_policies(
        &self,
        product_slug: &str,
    ) -> Result<PublicPoliciesResponse> {
        let url = self
            .base
            .join(&format!("/v1/products/{product_slug}/policies"))
            .map_err(|e| Error::BadUrl(e.to_string()))?;
        let resp = self.http.get(url).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(Error::Server {
                status: status.as_u16(),
                body: text,
            });
        }
        serde_json::from_str(&text).map_err(|e| Error::Other(e.to_string()))
    }

    /// Poll a purchase by its invoice id. Returns the current status and,
    /// once the invoice has settled, the signed `license_key` string.
    pub async fn poll_purchase(&self, invoice_id: &str) -> Result<PollResponse> {
        let url = self
            .base
            .join(&format!("/v1/purchase/{invoice_id}"))
            .map_err(|e| Error::BadUrl(e.to_string()))?;
        let resp = self.http.get(url).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(Error::Server {
                status: status.as_u16(),
                body: text,
            });
        }
        serde_json::from_str(&text).map_err(|e| Error::Other(e.to_string()))
    }
}

// --- request / response types ---

/// Full request body for [`Client::validate_full`].
#[derive(Debug, Clone, Serialize)]
pub struct ValidateRequest<'a> {
    /// The full `LIC1-...` key string.
    pub key: &'a str,
    /// Optional product slug the caller expects the key to cover.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_slug: Option<&'a str>,
    /// Optional raw fingerprint. Sending it enables seat binding / cap
    /// enforcement on the server side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<&'a str>,
    /// Optional client-supplied hostname, recorded against the machine row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<&'a str>,
    /// Optional client-supplied platform descriptor (e.g. `"linux-x86_64"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<&'a str>,
}

/// Response from `/v1/validate`. `ok` tells you the bottom line; `reason`
/// is populated on failure (values like `"revoked"`, `"fingerprint_mismatch"`,
/// `"bad_signature"`, `"not_found"`, `"bad_format"`, `"product_mismatch"`,
/// `"expired"`, `"suspended"`, `"too_many_machines"`, `"rate_limited"`).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ValidateResponse {
    /// Whether the key is currently valid.
    pub ok: bool,
    /// Machine-readable reason on failure.
    #[serde(default)]
    pub reason: Option<String>,
    /// License id on success.
    #[serde(default)]
    pub license_id: Option<String>,
    /// Product id on success.
    #[serde(default)]
    pub product_id: Option<String>,
    /// Product slug on success.
    #[serde(default)]
    pub product_slug: Option<String>,
    /// Issue timestamp (RFC 3339) on success.
    #[serde(default)]
    pub issued_at: Option<String>,
    /// Expiry timestamp (RFC 3339) if the license has one.
    #[serde(default)]
    pub expires_at: Option<String>,
    /// End of the grace window (RFC 3339) if the license is currently in
    /// its grace period.
    #[serde(default)]
    pub grace_until: Option<String>,
    /// True when the license is past `expires_at` but still inside the
    /// operator's configured grace window. The server returns `ok: true`
    /// in this case and populates `grace_until`.
    #[serde(default)]
    pub in_grace_period: Option<bool>,
    /// True if this license is flagged as a trial.
    #[serde(default)]
    pub is_trial: Option<bool>,
    /// Entitlement slugs granted by the license.
    #[serde(default)]
    pub entitlements: Vec<String>,
    /// License status string (`active`, `suspended`, `revoked`).
    #[serde(default)]
    pub status: Option<String>,
    /// The id of the machine row this call activated or matched (when a
    /// fingerprint was supplied).
    #[serde(default)]
    pub machine_id: Option<String>,
    /// The license's seat cap. `0` = unlimited, `1` = single-seat, `n` =
    /// n-seat.
    #[serde(default)]
    pub max_machines: Option<i64>,
}

impl ValidateResponse {
    /// True if the license grants the given entitlement slug.
    pub fn has_entitlement(&self, slug: &str) -> bool {
        self.entitlements.iter().any(|e| e == slug)
    }
}

/// Response from the `/v1/machines/*` endpoints.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct MachineResponse {
    /// Whether the call succeeded.
    pub ok: bool,
    /// Machine-readable reason on failure.
    #[serde(default)]
    pub reason: Option<String>,
    /// The machine id, when present.
    #[serde(default)]
    pub machine_id: Option<String>,
    /// Current count of active machines for this license.
    #[serde(default)]
    pub active_count: Option<i64>,
    /// Seat cap for this license (echo of `max_machines`).
    #[serde(default)]
    pub max_machines: Option<i64>,
}

/// Optional extras for [`Client::start_purchase`]. All fields are
/// optional; pass `&Default::default()` for the simple "default
/// tier, no extras" case. To buy a specific tier, set
/// `policy_slug = Some("...")`. To list available tiers without
/// auth, use [`Client::list_public_policies`].
#[derive(Debug, Clone, Default)]
pub struct StartPurchaseOptions<'a> {
    /// Email for the receipt.
    pub buyer_email: Option<&'a str>,
    /// Free-form note recorded on the invoice (admin-visible).
    pub buyer_note: Option<&'a str>,
    /// URL the buyer should be returned to after payment.
    pub redirect_url: Option<&'a str>,
    /// Discount / referral code.
    pub code: Option<&'a str>,
    /// Tier slug. When set, the policy's `price_sats_override`
    /// becomes the base price and the issued license carries the
    /// policy's entitlements / duration / max_machines / trial flag.
    pub policy_slug: Option<&'a str>,
}

/// One tier on the buyer-facing tier picker. Returned by
/// [`Client::list_public_policies`]. Mirrors what `/buy/<slug>`
/// renders server-side, so an in-app tier picker can show
/// identical text and pricing.
#[derive(Debug, Clone, Deserialize)]
pub struct PublicPolicy {
    /// Stable identifier for the tier (e.g. `"core"`, `"pro"`).
    /// Pass to [`StartPurchaseOptions::policy_slug`] to buy this tier.
    pub slug: String,
    /// Operator-set display name (e.g. `"Pro"`).
    pub name: String,
    /// Free-form per-tier blurb. Empty when not set.
    #[serde(default)]
    pub description: String,
    /// Effective price in the smallest unit of the product's listed
    /// currency: sats for SAT-priced products, cents for USD/EUR.
    pub price_sats: i64,
    /// 0 = perpetual; otherwise license lifetime in seconds.
    #[serde(default)]
    pub duration_seconds: i64,
    /// Seat cap. 0 = unlimited, 1 = single-seat, n = n-seat.
    #[serde(default = "default_one")]
    pub max_machines: i64,
    /// True if this tier is flagged as a trial.
    #[serde(default)]
    pub is_trial: bool,
    /// Entitlement slugs the issued license will carry.
    #[serde(default)]
    pub entitlements: Vec<String>,
    /// True if the operator marked this tier "Most popular".
    #[serde(default)]
    pub highlighted: bool,
    /// True if the policy is a recurring subscription.
    #[serde(default)]
    pub is_recurring: bool,
    /// Renewal cadence in days (0 for non-recurring).
    #[serde(default)]
    pub renewal_period_days: i64,
    /// First-cycle free-trial length (0 for none).
    #[serde(default)]
    pub trial_days: i64,
}

fn default_one() -> i64 {
    1
}

/// One entry in a product's entitlements catalog. Operator declares
/// the closed list once per product; policies pick from this list.
/// Use [`EntitlementDef::name`] as the human-readable label when
/// rendering an in-app tier picker (e.g. "AI summaries" instead of
/// the raw `ai_summaries` slug).
#[derive(Debug, Clone, Deserialize)]
pub struct EntitlementDef {
    /// Stable identifier — what the SDK's `has_entitlement(slug)`
    /// checks against and what gets baked into the signed payload.
    pub slug: String,
    /// Operator-set display label. Falls back to slug if empty.
    #[serde(default)]
    pub name: String,
    /// Optional one-sentence tooltip. Empty when unset.
    #[serde(default)]
    pub description: String,
}

/// Product-level fields included in the public-policies response.
#[derive(Debug, Clone, Deserialize)]
pub struct PublicPoliciesProduct {
    /// Product slug.
    pub slug: String,
    /// Operator-set product display name.
    pub name: String,
    /// Operator-set product description (free-form). Empty when unset.
    #[serde(default)]
    pub description: String,
    /// Product's base price in sats. Tiers may override via
    /// [`PublicPolicy::price_sats`].
    pub base_price_sats: i64,
    /// Closed list of entitlements this product offers, with display
    /// names + descriptions for buyer-facing rendering. Empty vec
    /// when the operator hasn't defined a catalog (legacy "free-text"
    /// mode).
    #[serde(default)]
    pub entitlements_catalog: Vec<EntitlementDef>,
}

/// Response from `/v1/products/<slug>/policies`.
#[derive(Debug, Clone, Deserialize)]
pub struct PublicPoliciesResponse {
    /// Product the tiers belong to.
    pub product: PublicPoliciesProduct,
    /// Active, public tiers — sorted by ascending effective price.
    pub policies: Vec<PublicPolicy>,
}

/// Response from `/v1/purchase` when starting a purchase.
#[derive(Debug, Clone, Deserialize)]
pub struct PurchaseSession {
    /// Our internal invoice id — use with [`Client::poll_purchase`].
    pub invoice_id: String,
    /// BTCPay's invoice id (opaque).
    pub btcpay_invoice_id: String,
    /// URL to open in the buyer's browser.
    pub checkout_url: String,
    /// Amount in satoshis.
    pub amount_sats: i64,
    /// Where the service recommends polling.
    pub poll_url: String,
}

/// Response from polling `/v1/purchase/:invoice_id`.
#[derive(Debug, Clone, Deserialize)]
pub struct PollResponse {
    /// Our invoice id.
    pub invoice_id: String,
    /// `pending | settled | expired | invalid`.
    pub status: String,
    /// Product id (UUID string).
    pub product_id: String,
    /// Price in satoshis.
    pub amount_sats: i64,
    /// Populated only once the license has been issued.
    pub license_key: Option<String>,
    /// Populated with the license row's id once issued.
    pub license_id: Option<String>,
}
