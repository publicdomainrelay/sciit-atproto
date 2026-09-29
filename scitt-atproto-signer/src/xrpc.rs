//! The XRPC service: one `sign` procedure, and the plumbing around it.
//!
//! # The method
//!
//! ```text
//! POST /xrpc/{nsid}?repository=<did>&subject=<string>
//! Content-Type: application/json
//!
//! {"$type": "app.bsky.feed.post", "text": "..."}
//! ```
//!
//! The **request body is the artifact**. It is signed as-is -- never
//! re-serialised, because a round trip through a JSON library would change the
//! bytes and the signature would then cover something the caller never sent.
//! It has to be a JSON object all the same, because the badge.blue
//! attestation is appended to the record's `signatures` array.
//!
//! # What one request does
//!
//! 1. mints a P-256 key pair;
//! 2. signs the body into a SCITT Signed Statement, and registers it;
//! 3. mints a `did:plc` for that key, whose DID document publishes the key as
//!    a verification method and whose `#scitt_scrapi` service entry points at
//!    the Receipt the registration just produced;
//! 4. signs the same body into a badge.blue inline attestation whose `issuer`
//!    is that DID and whose `key` is the verification method inside it.
//!
//! Everything comes back in one answer, and every part of it is named by the
//! same DID. Resolving that DID answers the two questions a holder of the
//! attestation has: which key signed it, and where the transparency evidence
//! is. [`crate::identity`] has the ordering argument -- why the DID cannot be
//! inside the statement it points at.
//!
//! # Inter-service calls
//!
//! An AT Protocol service is normally reached through a PDS, which forwards
//! the call with the `atproto-proxy` header and a service-auth token. This
//! service accepts that header and does not require it: it has no identity of
//! its own for a PDS to resolve, so a caller reaches it by URL and the header
//! is logged if it arrives.

use std::sync::Arc;

use atproto_identity::plc::encoding::base64url_encode;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::Instrument as _;

use crate::attestation::{AttestationParams, attest};
use crate::cose::StatementParams;
use crate::errors::{Result, SignerError};
use crate::jwk::jwk_json;
use crate::keys::RequestKey;
use crate::state::AppState;
use crate::time::now_rfc3339;

/// The header a proxying PDS sets to name the service it is calling.
pub const ATPROTO_PROXY_HEADER: &str = "atproto-proxy";

/// Query parameters the `sign` method accepts.
#[derive(Debug, Default, Deserialize)]
pub struct SignQuery {
    /// The repository the attestation is bound to, as a DID. Defaults to the
    /// DID minted for this request.
    pub repository: Option<String>,
    /// The statement's `sub` claim. Defaults to the configured subject.
    pub subject: Option<String>,
}

/// Build the router for a configured service.
pub fn router(state: Arc<AppState>) -> Router {
    let sign_path = format!("/xrpc/{}", state.config.nsid);
    let router = Router::new()
        .route(&sign_path, post(sign))
        // `_health` is the method a client probes before it trusts an
        // endpoint. Answering it costs nothing and saves a caller from
        // treating a 404 as an outage.
        .route("/xrpc/_health", get(health))
        .route("/", get(service_index));

    // The default NSID is served too, so a caller that guessed it gets the
    // method rather than a bare 404 -- unless it is already the configured
    // one, where registering the same path twice would panic at start-up.
    let router = if state.config.nsid == crate::config::DEFAULT_NSID {
        router
    } else {
        router.route(
            &format!("/xrpc/{}", crate::config::DEFAULT_NSID),
            post(sign),
        )
    };

    router.with_state(state)
}

/// `GET /xrpc/_health`
async fn health() -> impl IntoResponse {
    Json(json!({ "version": env!("CARGO_PKG_VERSION") }))
}

/// `GET /`
///
/// What this service is and where it registers. No identity is reported
/// because the service has none: every request mints its own, and it is in
/// that request's response.
async fn service_index(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(json!({
        "service": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "method": state.config.nsid,
        "scrapiEndpoint": state.config.scrapi_endpoint,
        "plcDirectory": state.config.plc_directory,
        "subject": state.config.subject,
    }))
}

/// `POST /xrpc/{nsid}` -- the `sign` method.
async fn sign(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SignQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match sign_inner(&state, &query, &headers, &body).await {
        Ok(answer) => (StatusCode::OK, Json(answer)).into_response(),
        Err(error) => error_response(error),
    }
}

/// The body of [`sign`], with the error path separated so a failure keeps its
/// type all the way to the response.
async fn sign_inner(
    state: &AppState,
    query: &SignQuery,
    headers: &HeaderMap,
    payload: &[u8],
) -> Result<Value> {
    if payload.is_empty() {
        return Err(SignerError::Request {
            details: "the request body is the artifact to sign, and it is empty".to_string(),
        });
    }
    if let Some(proxy) = headers.get(ATPROTO_PROXY_HEADER) {
        tracing::info!(
            proxy = proxy.to_str().unwrap_or("<not utf-8>"),
            "called through a PDS proxy"
        );
    }

    let subject = query
        .subject
        .clone()
        .unwrap_or_else(|| state.config.subject.clone());
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("application/json")
        .to_string();

    // A fresh key pair for this request alone.
    let key = RequestKey::generate()?;

    // 1. The SCITT Signed Statement, over the body as sent. Its issuer is the
    //    key's own did:jwk: the did:plc below names the Receipt, which is
    //    derived from this statement, so it cannot be named inside it.
    let statement_params = StatementParams {
        issuer: key.issuer().to_string(),
        subject: subject.clone(),
        content_type: content_type.clone(),
    };
    let signed = crate::cose::sign_statement(&key, &statement_params, payload)?;

    // 2. Register it, and build the Transparent Statement from the Receipt.
    let registration = state
        .scrapi
        .register(&signed.statement)
        .instrument(tracing::info_span!("register_statement"))
        .await?;
    let transparent = crate::cose::transparent_statement(
        &signed,
        payload,
        std::slice::from_ref(&registration.receipt),
    )?;

    // 3. The identity for this request: it publishes the key and points at the
    //    Receipt.
    let identity = crate::identity::mint(
        &key,
        &state.config.scrapi_endpoint,
        &registration.entry_id,
        state.config.plc_directory.as_deref(),
    )
    .await?;

    // 4. The badge.blue inline attestation, over the same body, issued by that
    //    identity and naming its verification method.
    let attestation_params = AttestationParams {
        signature_type: state.config.signature_type.clone(),
        repository: query
            .repository
            .clone()
            .unwrap_or_else(|| identity.did.clone()),
        issuer: identity.did.clone(),
        key: key.did_key().to_string(),
        issued_at: now_rfc3339(),
    };
    let attested = attest(payload, key.private(), &attestation_params, &identity).await?;

    Ok(json!({
        "did": identity.did,
        "didPublished": identity.published,
        "didDocument": identity.document,
        "genesisOperation": identity.operation,
        "repository": attestation_params.repository,
        "contentType": content_type,
        "statement": {
            "issuer": key.issuer(),
            "key": jwk_json(key.public_jwk()),
            "didKey": key.did_key(),
            "kid": key.kid(),
            "algorithm": "ES256",
            "coseSign1": base64url_encode(&signed.statement),
        },
        "transparentStatement": {
            "entryId": registration.entry_id,
            "location": registration.location,
            "receipt": base64url_encode(&registration.receipt),
            "coseSign1": base64url_encode(&transparent),
        },
        "inlineSignature": attested.signature,
        "contentCid": attested.content_cid,
        "signedRecord": attested.signed_record,
    }))
}

/// Render a [`SignerError`] as an XRPC error body.
///
/// XRPC answers a failed call with `{"error": ..., "message": ...}`. The
/// `error` value is the short name, and the `message` carries the numbered
/// form so an operator can find it in the source.
fn error_response(error: SignerError) -> Response {
    let (status, name) = match &error {
        SignerError::Request { .. }
        | SignerError::Attestation { .. }
        | SignerError::Cbor { .. }
        | SignerError::Cose { .. } => (StatusCode::BAD_REQUEST, "InvalidRequest"),
        SignerError::Key { .. } | SignerError::Identity { .. } => {
            (StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError")
        }
        SignerError::Scitt { .. } => (StatusCode::BAD_GATEWAY, "UpstreamFailure"),
    };

    tracing::warn!(?error, status = status.as_u16(), "the sign method failed");

    let body = Json(json!({
        "error": name,
        "message": error.to_string(),
    }));
    (status, body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_error_is_a_bad_request_and_a_scitt_error_is_a_gateway_failure() {
        let bad = error_response(SignerError::Request {
            details: "no body".to_string(),
        });
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

        let upstream = error_response(SignerError::Scitt {
            details: "connection refused".to_string(),
        });
        assert_eq!(upstream.status(), StatusCode::BAD_GATEWAY);

        let internal = error_response(SignerError::Identity {
            details: "no directory".to_string(),
        });
        assert_eq!(internal.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
