//! The per-request `did:plc`: one identity per statement, pointing at it.
//!
//! Every call to `sign` mints a `did:plc` whose DID document does two things:
//!
//! * it publishes the request's public key as a verification method, so a
//!   verifier that resolves the DID holds the key that signed; and
//! * it carries one service entry,
//!
//!   ```json
//!   {
//!     "id": "#scitt_scrapi",
//!     "type": "SCITTSCRAPI",
//!     "serviceEndpoint": "http://127.0.0.1:8000/entries/<entry id>"
//!   }
//!   ```
//!
//!   whose endpoint is the SCITT Receipt itself. Resolving the DID therefore
//!   answers both questions a reader of the attestation has: *which key*, and
//!   *where is the transparency evidence*.
//!
//! # Why the DID cannot be inside the Signed Statement
//!
//! The service entry names the EntryID, and the EntryID is a hash of the
//! Signed Statement. Putting this DID in the statement's `iss` claim would
//! therefore require the EntryID before the statement exists, and the
//! statement before the EntryID exists. The statement's issuer is a `did:jwk`
//! -- the key is its own identifier, so nothing has to be resolved to check it
//! -- and this DID is minted afterwards, once the EntryID is known.
//!
//! Nothing is lost by that. The DID document names the same key the statement
//! was signed with, so resolving it checks the statement too.

use atproto_identity::model::Document;
use atproto_identity::plc::{self, DidBuilder, Operation, PlcState, ServiceEndpoint};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::Instrument as _;

use crate::errors::{Result, SignerError};
use crate::keys::RequestKey;

/// The service entry's name in the DID document. The document renders it as
/// `#{SERVICE_ID}`, and that is how a resolver addresses it.
pub const SERVICE_ID: &str = "scitt_scrapi";

/// The service entry's type.
pub const SERVICE_TYPE: &str = "SCITTSCRAPI";

/// The verification method's name, which becomes `#{VERIFICATION_METHOD_ID}`.
pub const VERIFICATION_METHOD_ID: &str = "atproto";

/// The DID document field naming the verification method's key.
const VERIFICATION_METHOD_FIELD: &str = "verificationMethod";

/// A freshly minted per-request identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintedIdentity {
    /// The `did:plc` identifier.
    pub did: String,
    /// The DID document, as a resolver reads it.
    pub document: Value,
    /// The signed genesis operation. Submitting this to a PLC directory is
    /// what makes the DID resolvable by anyone.
    pub operation: Value,
    /// Whether the genesis operation was accepted by a directory.
    pub published: bool,
    /// The directory it was submitted to, when it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plc_directory: Option<String>,
    /// The service entry's endpoint: the Receipt resource.
    pub service_endpoint: String,
}

impl MintedIdentity {
    /// The DID-document reference to this identity's verification method.
    ///
    /// `did:plc:...#atproto`. Not what the attestation is issued with -- see
    /// [`MintedIdentity::names_key`] -- but the reference a resolver follows,
    /// and the form `atproto_attestation::require_issuer_holds_key` checks.
    #[must_use]
    pub fn key_reference(&self) -> String {
        format!("{}#{VERIFICATION_METHOD_ID}", self.did)
    }

    /// Whether this identity's document publishes `did_key`.
    ///
    /// The binding the attestation relies on: `issuer` names this DID and
    /// `key` names a `did:key`, so a holder has to be able to conclude that
    /// the first holds the second. That is
    /// `atproto_attestation::require_issuer_holds_key`'s job, and it needs an
    /// `IdentityResolver` -- a directory lookup this service cannot make for a
    /// DID it has not published. The document is in hand, so the same question
    /// is answered here against the bytes the response carries.
    #[must_use]
    pub fn names_key(&self, did_key: &str) -> bool {
        self.verification_method_multibase()
            .is_some_and(|multibase| format!("did:key:{multibase}") == did_key)
    }

    /// The `publicKeyMultibase` this identity publishes for
    /// [`VERIFICATION_METHOD_ID`], read back out of the document.
    ///
    /// Read from the document rather than kept beside it so that the check
    /// this feeds is over the bytes a resolver would see. A copy held
    /// separately could agree with the signer while the document disagreed,
    /// which is the failure the check exists to catch.
    #[must_use]
    pub fn verification_method_multibase(&self) -> Option<String> {
        let expected = format!("{}#{VERIFICATION_METHOD_ID}", self.did);
        self.document
            .get(VERIFICATION_METHOD_FIELD)?
            .as_array()?
            .iter()
            .find(|method| method.get("id").and_then(Value::as_str) == Some(expected.as_str()))?
            .get("publicKeyMultibase")?
            .as_str()
            .map(str::to_string)
    }
}

/// Build the per-request `did:plc` and, when a directory is configured,
/// publish it.
///
/// The key is reused as the rotation key. The DID exists to name this one
/// statement's key and to point at its Receipt; a second key would be a second
/// thing to lose, holding authority nobody has a use for on an identity that
/// lives for one request.
///
/// # Errors
///
/// [`SignerError::Identity`] if the genesis operation cannot be built or
/// submitted, or if the DID document cannot be rendered.
pub async fn mint(
    key: &RequestKey,
    scrapi_endpoint: &str,
    entry_id: &str,
    plc_directory: Option<&str>,
) -> Result<MintedIdentity> {
    // The endpoint is joined by string, so it has to be absolute. An empty or
    // relative one would produce a `serviceEndpoint` like `/entries/abc`,
    // which resolves against whatever base a reader happens to have -- a
    // service entry that validates as non-empty and points nowhere.
    let scrapi_endpoint = scrapi_endpoint.trim_end_matches('/');
    if !scrapi_endpoint.contains("://") {
        return Err(SignerError::Identity {
            details: format!(
                "the Transparency Service endpoint `{scrapi_endpoint}` is not an absolute URL, \
                 so the Receipt resource cannot be named for a resolver"
            ),
        });
    }
    let service_endpoint = format!("{scrapi_endpoint}/entries/{entry_id}");

    let (did, operation, _keys) = DidBuilder::new()
        .add_rotation_key(key.private().clone())
        .add_verification_method(VERIFICATION_METHOD_ID.to_string(), key.private().clone())
        .add_service(
            SERVICE_ID.to_string(),
            ServiceEndpoint::new(SERVICE_TYPE.to_string(), service_endpoint.clone()),
        )
        .build()
        .map_err(|error| SignerError::Identity {
            details: format!("the did:plc genesis operation could not be built: {error}"),
        })?;

    // The document is rendered from the same operation a directory will hold,
    // so what this service reports and what a resolver reconstructs agree.
    let mut state = PlcState::new();
    operation.apply_to(&mut state);
    let document: Document = state.to_document(did.as_str());
    let document = serde_json::to_value(&document).map_err(|error| SignerError::Identity {
        details: format!("the DID document could not be serialized: {error}"),
    })?;
    let operation_json =
        serde_json::to_value(&operation).map_err(|error| SignerError::Identity {
            details: format!("the genesis operation could not be serialized: {error}"),
        })?;

    let published = match plc_directory {
        Some(directory) => {
            publish(directory, did.as_str(), &operation).await?;
            true
        }
        None => {
            tracing::warn!(
                did = did.as_str(),
                "no PLC directory is configured, so this DID cannot be resolved by anyone \
                 else; the document is in the response and the genesis operation is not \
                 published"
            );
            false
        }
    };

    Ok(MintedIdentity {
        did: did.as_str().to_string(),
        document,
        operation: operation_json,
        published,
        plc_directory: plc_directory.map(str::to_string),
        service_endpoint,
    })
}

/// Submit a signed genesis operation to a PLC directory.
///
/// # Errors
///
/// [`SignerError::Identity`] if the directory refuses the operation or cannot
/// be reached.
async fn publish(directory: &str, did: &str, operation: &Operation) -> Result<()> {
    let client = atproto_identity::reqwest::Client::new();
    plc::submit(&client, directory, did, operation)
        .instrument(tracing::info_span!("plc_submit"))
        .await
        .map_err(|error| SignerError::Identity {
            details: format!("the genesis operation for {did} was refused by {directory}: {error}"),
        })?;
    tracing::info!(did, directory, "published a per-request DID");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCRAPI: &str = "http://127.0.0.1:8000";
    const ENTRY: &str = "6jZWRUsucVNM";

    async fn mint_one() -> (RequestKey, MintedIdentity) {
        let key = RequestKey::generate().expect("generates");
        let identity = mint(&key, SCRAPI, ENTRY, None).await.expect("mints");
        (key, identity)
    }

    /// The service entry the whole module exists for: the id, the type, and an
    /// endpoint that is the Receipt for *this* statement.
    #[tokio::test]
    async fn the_document_points_at_the_receipt() {
        let (_, identity) = mint_one().await;

        assert!(identity.did.starts_with("did:plc:"));
        assert!(!identity.published);
        assert_eq!(
            identity.service_endpoint,
            "http://127.0.0.1:8000/entries/6jZWRUsucVNM"
        );

        let services = identity.document["service"]
            .as_array()
            .expect("a service array");
        assert_eq!(services.len(), 1);
        assert_eq!(services[0]["id"], format!("{}#{SERVICE_ID}", identity.did));
        assert_eq!(services[0]["type"], SERVICE_TYPE);
        assert_eq!(
            services[0]["serviceEndpoint"],
            "http://127.0.0.1:8000/entries/6jZWRUsucVNM"
        );
    }

    /// The document has to publish the key that signed, or resolving the DID
    /// answers the "where" question and not the "which key" one.
    #[tokio::test]
    async fn the_document_publishes_the_request_key() {
        let (key, identity) = mint_one().await;

        let method = &identity.document["verificationMethod"][0];
        assert_eq!(
            method["id"],
            format!("{}#{VERIFICATION_METHOD_ID}", identity.did)
        );
        assert_eq!(method["controller"], identity.did);

        // The multibase is the did:key without its prefix, and it is the key
        // this request signed with.
        let expected = key.did_key().trim_start_matches("did:key:");
        assert_eq!(method["publicKeyMultibase"], expected);
        assert_eq!(
            identity.verification_method_multibase().as_deref(),
            Some(expected)
        );
    }

    /// The DID is a hash of the genesis operation. Two requests must not
    /// collide, and the identifier must be the 24-character base32 form.
    #[tokio::test]
    async fn two_requests_mint_different_identities() {
        let (first_key, first) = mint_one().await;
        let (second_key, second) = mint_one().await;

        assert_ne!(first.did, second.did);
        for identity in [&first, &second] {
            let identifier = identity.did.strip_prefix("did:plc:").expect("a did:plc");
            assert_eq!(identifier.len(), 24);
            assert!(
                identifier
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c)),
                "not base32: {identifier}"
            );
        }
        assert_ne!(first_key.did_key(), second_key.did_key());
    }

    /// The key reference is the DID's own document reference, which is what a
    /// resolver follows to the key and to the Receipt.
    #[tokio::test]
    async fn the_key_reference_is_the_document_reference() {
        let (_, identity) = mint_one().await;
        assert_eq!(
            identity.key_reference(),
            format!("{}#atproto", identity.did)
        );
    }

    /// The document has to hold the key the attestation is issued against, or
    /// resolving the issuer tells a verifier nothing about the signature.
    #[tokio::test]
    async fn the_document_names_the_request_key_and_no_other() {
        let (key, identity) = mint_one().await;
        let stranger = RequestKey::generate().expect("generates");

        assert!(identity.names_key(key.did_key()));
        assert!(
            !identity.names_key(stranger.did_key()),
            "a document naming somebody else's key was accepted as this key's"
        );
    }

    /// The operation is submitted to a directory, which is a public, permanent
    /// log. Private key material must not reach it.
    #[tokio::test]
    async fn the_operation_publishes_only_public_keys() {
        let (_, identity) = mint_one().await;

        let rotation_keys = identity.operation["rotationKeys"]
            .as_array()
            .expect("rotationKeys");
        assert_eq!(rotation_keys.len(), 1);
        assert!(
            rotation_keys[0]
                .as_str()
                .is_some_and(|key| key.starts_with("did:key:zDna")),
            "not a P-256 public key: {}",
            rotation_keys[0]
        );

        let methods = identity.operation["verificationMethods"]
            .as_object()
            .expect("verificationMethods");
        assert!(
            methods[VERIFICATION_METHOD_ID]
                .as_str()
                .is_some_and(|key| key.starts_with("did:key:zDna")),
            "not a P-256 public key: {}",
            methods[VERIFICATION_METHOD_ID]
        );

        // The operation's services map is the PLC form, which is not the DID
        // document's: `endpoint`, not `serviceEndpoint`, and no `id`.
        let service = &identity.operation["services"][SERVICE_ID];
        assert_eq!(service["type"], SERVICE_TYPE);
        assert_eq!(service["endpoint"], identity.service_endpoint);
    }

    /// The Endpoint is caller-supplied and reaches the DID document verbatim,
    /// so an empty one has to be a build failure rather than a service entry
    /// resolving to nothing.
    #[test]
    fn an_empty_endpoint_is_refused() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let key = RequestKey::generate().expect("generates");

        let error = runtime
            .block_on(mint(&key, "", ENTRY, None))
            .expect_err("an empty endpoint must be refused");
        assert!(format!("{error}").contains("endpoint"), "{error}");
    }
}
