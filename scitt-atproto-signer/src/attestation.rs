//! The badge.blue inline attestation over the request payload.
//!
//! badge.blue attestations come in two shapes: an **inline** signature
//! embedded in the record's `signatures` array, and a **remote** one that
//! names a separate proof record with a strongRef. This service issues the
//! inline shape, because the payload it attests to is the caller's POST body
//! and there is no repository here to write a proof record into.
//!
//! # What the signature covers
//!
//! Not the payload's bytes. The signed value is a **content CID**: the hash of
//! the record, the attestation metadata and the repository DID encoded
//! together, so the signature binds the record to the repository it is meant
//! to live in and cannot be replayed under another one. That is
//! `atproto-attestation`'s job and this module does not re-derive it.
//!
//! # `issuer` and `key` are two claims, checked two ways
//!
//! `key` is a `did:key`, which is the key's own identifier. A verifier needs
//! no directory to check the signature, which matters because a DID minted
//! here is only resolvable when a PLC directory was configured -- and an
//! attestation nobody can check is not an attestation. The membership test is
//! `require_attestation_key`'s: the `did:key` must be the key that signed.
//!
//! `issuer` is the `did:plc` minted for the same request. It answers a
//! different question -- *where is the transparency evidence* -- and its
//! document also publishes the key, so the two references meet.
//!
//! That the issuer really holds the key is a third thing, and it is the one
//! claim here a verifier cannot always check for itself: it needs the DID
//! resolved. This module checks it against the document the response carries
//! ([`MintedIdentity::names_key`]), so a service that issued an attestation
//! under a DID that does not name its own key fails the request rather than
//! handing the problem to a caller.

use anyhow::anyhow;
use atproto_attestation::input::AnyInput;
use atproto_attestation::{VerifiedKind, create_inline_attestation, verify_record};
use atproto_identity::key::{KeyData, identify_key};
use atproto_identity::traits::KeyResolver;
use atproto_record::record_resolver::RecordResolver;
use serde_json::{Value, json};

use crate::errors::{Result, SignerError};
use crate::identity::MintedIdentity;

/// Default `$type` for the inline signature record.
pub const DEFAULT_SIGNATURE_TYPE: &str = "blue.badge.inlineSignature";

/// Resolves a `did:key` reference to its key, and nothing else.
///
/// The attestation's `key` is a `did:key`, so this is the whole of what a
/// verifier is asked to do: no directory, no network, and no way for a caller
/// to point the check at a document it controls. The DID that issuer names is
/// checked separately, by [`MintedIdentity::names_key`].
pub struct DidKeyOnly;

#[async_trait::async_trait]
impl KeyResolver for DidKeyOnly {
    async fn resolve(&self, key: &str) -> anyhow::Result<KeyData> {
        let (reference, _) = match key.split_once('#') {
            Some((reference, fragment)) => (reference, Some(fragment)),
            None => (key, None),
        };
        if !reference.starts_with("did:key:") {
            return Err(anyhow!(
                "an inline attestation from this service names its key as a did:key, and \
                 {key} is not one"
            ));
        }
        Ok(identify_key(reference)?)
    }
}

/// Refuses to fetch anything.
///
/// This service issues inline attestations only: it has no repository to write
/// a proof record into, so a remote attestation in a record it signed is a
/// sign that something else wrote that record. Refusing is the honest answer.
pub struct NoRemoteAttestations;

#[async_trait::async_trait]
impl RecordResolver for NoRemoteAttestations {
    async fn resolve<T>(&self, aturi: &str) -> anyhow::Result<T>
    where
        T: serde::de::DeserializeOwned + Send,
    {
        Err(anyhow!(
            "this service issues inline attestations only, so {aturi} is not a proof record it wrote"
        ))
    }

    async fn resolve_pinned<T>(&self, aturi: &str, _cid: &str) -> anyhow::Result<T>
    where
        T: serde::de::DeserializeOwned + Send,
    {
        Err(anyhow!(
            "this service issues inline attestations only, so the strongRef to {aturi} is not one it wrote"
        ))
    }
}

/// An issued inline attestation.
#[derive(Debug, Clone)]
pub struct InlineAttestation {
    /// The payload with the `signatures` array appended.
    pub signed_record: Value,
    /// The single entry added to `signatures`.
    pub signature: Value,
    /// The content CID the signature covers.
    pub content_cid: String,
}

/// Options for one inline attestation.
#[derive(Debug, Clone)]
pub struct AttestationParams {
    /// The `$type` of the signature record.
    pub signature_type: String,
    /// The repository the attestation is bound to, as a DID.
    pub repository: String,
    /// The issuer named in the metadata: the per-request `did:plc`.
    pub issuer: String,
    /// The `key` the metadata names: the signer's `did:key`.
    pub key: String,
    /// An ISO 8601 timestamp for `issuedAt`.
    pub issued_at: String,
}

/// Sign `payload` with an inline attestation.
///
/// `payload` must be a JSON object: the attestation is appended to the
/// record's `signatures` array, and there is nowhere to append it on a scalar
/// or an array.
///
/// # Errors
///
/// [`SignerError::Request`] if the payload is not a JSON object, and
/// [`SignerError::Attestation`] if the attestation cannot be created or does
/// not verify against the key its own metadata names.
pub async fn attest(
    payload: &[u8],
    key: &KeyData,
    params: &AttestationParams,
    identity: &MintedIdentity,
) -> Result<InlineAttestation> {
    let record: Value = serde_json::from_slice(payload).map_err(|error| SignerError::Request {
        details: format!(
            "the request body must be JSON for an inline attestation, and it is not: {error}"
        ),
    })?;
    if !record.is_object() {
        return Err(SignerError::Request {
            details: format!(
                "the request body must be a JSON object to carry a signatures array, and it is {}",
                json_type(&record)
            ),
        });
    }

    let metadata = json!({
        "$type": params.signature_type,
        "key": params.key,
        "issuer": params.issuer,
        "issuedAt": params.issued_at,
    });

    let signed_record = create_inline_attestation(
        AnyInput::Serialize(record),
        AnyInput::Serialize(metadata),
        &params.repository,
        key,
    )
    .map_err(|error| SignerError::Attestation {
        details: format!("the inline attestation could not be created: {error}"),
    })?;

    let signature = signed_record
        .get("signatures")
        .and_then(Value::as_array)
        .and_then(|signatures| signatures.last())
        .cloned()
        .ok_or_else(|| SignerError::Attestation {
            details: "the signed record carries no signatures array".to_string(),
        })?;

    let content_cid = signature
        .get("cid")
        .and_then(Value::as_str)
        .ok_or_else(|| SignerError::Attestation {
            details: "the inline signature carries no content CID".to_string(),
        })?
        .to_string();

    // An attestation this service cannot verify is worse than none: it would
    // be published as a signature that no verifier accepts. Checking here
    // costs one verification and turns that into a failed request instead.
    verify_record(
        AnyInput::Serialize(signed_record.clone()),
        &params.repository,
        DidKeyOnly,
        NoRemoteAttestations,
    )
    .await
    .map_err(|error| SignerError::Attestation {
        details: format!(
            "the inline attestation did not verify against {}: {error}",
            params.key
        ),
    })?
    .into_iter()
    .find(|verified| matches!(verified.kind, VerifiedKind::Inline { .. }))
    .ok_or_else(|| SignerError::Attestation {
        details: "the inline attestation verified as nothing".to_string(),
    })?;

    // And the second half of the binding, which no verifier can check for an
    // unpublished DID: the issuer really does hold the key it is claimed to.
    // Answering it here means a document that fails to name its own signing
    // key is a failed request, not a caller's problem to discover.
    if !identity.names_key(&params.key) {
        return Err(SignerError::Attestation {
            details: format!(
                "the document for {} does not publish the key this attestation was signed \
                 with, so resolving the issuer would not yield it",
                identity.did
            ),
        });
    }

    Ok(InlineAttestation {
        signed_record,
        signature,
        content_cid,
    })
}

/// The JSON type of a value, for an error message that says what arrived.
fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::RequestKey;
    use crate::time::now_rfc3339;

    const SCRAPI: &str = "http://127.0.0.1:8000";
    const ENTRY: &str = "6jZWRUsucVNM";

    /// A key, the identity minted for it, and parameters naming that identity.
    async fn fixture() -> (RequestKey, MintedIdentity, AttestationParams) {
        let key = RequestKey::generate().expect("generates");
        let identity = crate::identity::mint(&key, SCRAPI, ENTRY, None)
            .await
            .expect("mints");
        let params = AttestationParams {
            signature_type: DEFAULT_SIGNATURE_TYPE.to_string(),
            repository: identity.did.clone(),
            issuer: identity.did.clone(),
            key: key.did_key().to_string(),
            issued_at: now_rfc3339(),
        };
        (key, identity, params)
    }

    #[tokio::test]
    async fn a_json_object_comes_back_with_one_more_signature() {
        let (key, identity, params) = fixture().await;
        let payload = br#"{"$type":"app.bsky.feed.post","text":"hello"}"#;

        let attested = attest(payload, key.private(), &params, &identity)
            .await
            .expect("attests");

        assert_eq!(attested.signed_record["text"], "hello");
        assert_eq!(
            attested
                .signed_record
                .get("signatures")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
        assert!(attested.content_cid.starts_with("bafyrei"));
        assert_eq!(attested.signature["$type"], DEFAULT_SIGNATURE_TYPE);
        // The issuer is the minted DID -- resolving it leads to the Receipt and
        // to this key -- and the key is a did:key, which stands on its own so
        // that the signature is checkable even when the DID is unpublished.
        assert_eq!(attested.signature["issuer"], identity.did);
        assert_eq!(attested.signature["key"], key.did_key());
        assert!(
            identity.names_key(key.did_key()),
            "the document holds a different key"
        );
    }

    /// The whole point of returning a signature is that a third party can
    /// check it, so a signed record that does not verify is a bug this test
    /// would catch even if `attest`'s own check were removed.
    #[tokio::test]
    async fn the_signature_verifies_against_the_named_did_key() {
        let (key, identity, params) = fixture().await;
        let attested = attest(
            br#"{"$type":"app.example.thing","n":1}"#,
            key.private(),
            &params,
            &identity,
        )
        .await
        .expect("attests");

        let verified = verify_record(
            AnyInput::Serialize(attested.signed_record.clone()),
            &params.repository,
            DidKeyOnly,
            NoRemoteAttestations,
        )
        .await
        .expect("verifies");
        assert_eq!(verified.len(), 1);
        assert!(matches!(verified[0].kind, VerifiedKind::Inline { .. }));
    }

    /// The two halves of the binding are separate claims and are checked
    /// separately: the signature is over the content CID and names a key,
    /// while the issuer is a DID that has to hold that key. A document that
    /// does not is a failed request -- a verifier with no directory access
    /// could not have discovered it.
    #[tokio::test]
    async fn a_document_that_does_not_hold_the_signing_key_fails_the_request() {
        let (key, identity, params) = fixture().await;

        let mut nameless = identity.clone();
        let stranger = RequestKey::generate().expect("generates");
        nameless.document["verificationMethod"][0]["publicKeyMultibase"] = Value::String(
            stranger
                .did_key()
                .trim_start_matches("did:key:")
                .to_string(),
        );

        let error = attest(
            br#"{"$type":"app.example.thing"}"#,
            key.private(),
            &params,
            &nameless,
        )
        .await
        .expect_err("a document naming another key must not sign");
        assert!(
            format!("{error}").contains("does not publish the key"),
            "{error}"
        );
        assert!(
            identity.names_key(key.did_key()),
            "the untampered document still holds it"
        );
    }

    /// A resolver that answered any DID would let a caller point the key check
    /// at a document it controls.
    #[tokio::test]
    async fn a_key_reference_that_is_not_a_did_key_is_refused() {
        let resolver = DidKeyOnly;
        assert!(resolver.resolve("did:key:zDnaeZ").await.is_err());

        let error = match resolver.resolve("https://example.com/jwks.json#kid1").await {
            Ok(_) => panic!("a URI must not resolve here"),
            Err(error) => error,
        };
        assert!(format!("{error}").contains("did:key"), "{error}");
    }

    /// A different repository is a different content CID, so a verifier
    /// checking the wrong one must reject the signature -- that is the replay
    /// binding the CID exists for.
    #[tokio::test]
    async fn the_repository_is_bound_into_the_signature() {
        let (key, identity, params) = fixture().await;
        let attested = attest(
            br#"{"$type":"app.example.thing"}"#,
            key.private(),
            &params,
            &identity,
        )
        .await
        .expect("attests");

        let error = verify_record(
            AnyInput::Serialize(attested.signed_record.clone()),
            "did:plc:somewhere-else",
            DidKeyOnly,
            NoRemoteAttestations,
        )
        .await
        .expect_err("a signature bound to another repository must not verify here");
        assert!(!format!("{error}").is_empty());
    }

    #[tokio::test]
    async fn a_payload_that_is_not_an_object_is_refused() {
        let (key, identity, params) = fixture().await;
        for payload in [&b"[1,2,3]"[..], &b"\"text\""[..], &b"7"[..]] {
            let error = attest(payload, key.private(), &params, &identity)
                .await
                .expect_err("must be refused");
            assert!(format!("{error}").contains("JSON object"), "{error}");
        }
    }

    #[tokio::test]
    async fn a_payload_that_is_not_json_is_refused() {
        let (key, identity, params) = fixture().await;
        let error = attest(b"not json", key.private(), &params, &identity)
            .await
            .expect_err("must be refused");
        assert!(format!("{error}").contains("must be JSON"), "{error}");
    }
}
