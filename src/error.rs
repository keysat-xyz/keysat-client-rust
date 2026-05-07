//! Error types.

use thiserror::Error;

/// A `Result` alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by the licensing client.
#[derive(Debug, Error)]
pub enum Error {
    /// The key string didn't match the expected `LIC1-<payload>-<sig>` shape.
    #[error("bad key format: {0}")]
    BadFormat(&'static str),

    /// Base32 decoding of the payload or signature failed.
    #[error("bad encoding: {0}")]
    BadEncoding(&'static str),

    /// The payload didn't contain the expected number of bytes.
    #[error("bad payload length: expected {expected}, got {got}")]
    BadPayloadLength {
        /// expected length
        expected: usize,
        /// observed length
        got: usize,
    },

    /// Unknown key format version.
    #[error("unsupported key version {0}")]
    UnsupportedVersion(u8),

    /// The signature failed to verify against the public key.
    #[error("signature verification failed")]
    BadSignature,

    /// The key's `expires_at` is in the past. Only returned by
    /// [`crate::Verifier::verify_with_time`].
    #[error("license expired")]
    Expired,

    /// Reading or parsing the supplied public-key PEM blob failed.
    #[error("bad public key PEM: {0}")]
    BadPublicKey(String),

    /// An HTTP call returned an error. Only present with the `online` feature.
    #[cfg(feature = "online")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// The server returned an error response. Includes status + body.
    #[cfg(feature = "online")]
    #[error("server error ({status}): {body}")]
    Server {
        /// HTTP status
        status: u16,
        /// response body as text
        body: String,
    },

    /// A URL couldn't be parsed. Online only.
    #[cfg(feature = "online")]
    #[error("bad URL: {0}")]
    BadUrl(String),

    /// Generic catch-all.
    #[error("{0}")]
    Other(String),
}
