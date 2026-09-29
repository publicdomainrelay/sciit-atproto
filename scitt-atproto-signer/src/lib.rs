//! An AT Protocol XRPC service that registers SCITT Signed Statements and
//! issues badge.blue inline attestations.
//!
//! One call does three things, over the request body exactly as it arrived:
//!
//! 1. mints a **per-request P-256 key pair**;
//! 2. signs the body into a **SCITT Signed Statement** -- a `COSE_Sign1` whose
//!    issuer is that key's `did:jwk` -- registers it with a Transparency
//!    Service speaking [SCRAPI], and returns the **Transparent Statement**
//!    that comes back with its Receipt;
//! 3. signs the same body into a **badge.blue inline attestation**, and
//!    returns it as `inlineSignature`.
//!
//! Both artefacts come back together, with the public key needed to verify
//! either.
//!
//! # Why the body is never re-serialised
//!
//! The signature covers the bytes the caller sent. Parsing the body and
//! writing it back out would reorder keys and change whitespace, and the
//! signature would then cover a document the caller never sent -- verifiable
//! by this service and by nobody else. The body is passed through untouched,
//! and only *read* as JSON where the attestation layer needs an object.
//!
//! # The service's own identity
//!
//! The service runs under its own `did:plc`, carrying a service entry
//!
//! ```json
//! { "id": "#scitt_scrapi", "type": "SCITTSCRAPI", "serviceEndpoint": "..." }
//! ```
//!
//! whose endpoint is the Transparency Service. That DID is what an AT Protocol
//! client resolves to find this endpoint, and what a PDS names in the
//! `atproto-proxy` header when it forwards a call here.
//!
//! [SCRAPI]: https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-11

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod attestation;
pub mod cbor;
pub mod config;
pub mod cose;
pub mod errors;
pub mod identity;
pub mod jwk;
pub mod keys;
pub mod scitt;
pub mod state;
pub mod time;
pub mod xrpc;

pub use config::Config;
pub use errors::{Result, SignerError};
pub use scitt::ScrapiClient;
pub use state::AppState;
