//! Structured error types for the SCITT-backed AT Protocol signer.
//!
//! Error strings follow the workspace convention
//! `error-<crate>-<domain>-<number> <message>: <details>`, where the domain is
//! the module the failure came from. Numbers are never reused.
//!
//! Ranges in use:
//!
//! * `cbor` -- 1-19
//! * `cose` -- 1-19
//! * `key` -- 1-19
//! * `attestation` -- 1-19
//! * `scitt` -- 1-19
//! * `identity` -- 1-19
//! * `request` -- 1-19

use thiserror::Error;

/// Everything this crate can fail at.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SignerError {
    /// The CBOR writer was asked to encode something it cannot.
    #[error("error-scitt-atproto-signer-cbor-1 CBOR encoding refused: {details}")]
    Cbor {
        /// What could not be encoded, and why.
        details: String,
    },

    /// COSE_Sign1 assembly or signing failed.
    #[error("error-scitt-atproto-signer-cose-1 COSE signing failed: {details}")]
    Cose {
        /// What could not be signed, and why.
        details: String,
    },

    /// A key could not be generated, converted, or used.
    #[error("error-scitt-atproto-signer-key-1 key operation failed: {details}")]
    Key {
        /// Which key operation failed, and why.
        details: String,
    },

    /// The badge.blue inline attestation could not be created.
    #[error("error-scitt-atproto-signer-attestation-1 attestation failed: {details}")]
    Attestation {
        /// What the attestation layer refused.
        details: String,
    },

    /// The SCITT Transparency Service refused or could not answer a call.
    #[error("error-scitt-atproto-signer-scitt-1 SCITT registration failed: {details}")]
    Scitt {
        /// The endpoint, its answer, and what that means.
        details: String,
    },

    /// The service `did:plc` could not be built, published, or read back.
    #[error("error-scitt-atproto-signer-identity-1 identity operation failed: {details}")]
    Identity {
        /// Which identity step failed, and why.
        details: String,
    },

    /// The caller's request cannot be served as written.
    #[error("error-scitt-atproto-signer-request-1 bad request: {details}")]
    Request {
        /// What is wrong with the request.
        details: String,
    },
}

/// Convenience alias for results carrying [`SignerError`].
pub type Result<T, E = SignerError> = std::result::Result<T, E>;
