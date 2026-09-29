//! The per-request signing key.
//!
//! Every call to the `sign` method mints a fresh P-256 key pair, signs the
//! caller's payload with it, and hands the public half back in the response.
//! Nothing is reused between requests and nothing is persisted.
//!
//! # Why a fresh key per request
//!
//! The two artefacts a caller receives -- a SCITT Transparent Statement and a
//! badge.blue inline attestation -- are meant to be verifiable *later*, by
//! somebody who was not present at signing time, and to be unlinkable to each
//! other across requests. A service-wide key would make every statement this
//! service ever produced part of one correlation set, and would put that key's
//! compromise in the past of every statement already issued.
//!
//! The cost is that a verifier cannot resolve the key from a directory. That
//! is why the key travels in the response, why the SCITT issuer is a
//! `did:jwk` -- the key *is* the identifier -- and why the attestation metadata
//! names it as a `did:key`.

use atproto_identity::jwk::Jwk;
use atproto_identity::key::{KeyData, KeyType, generate_key, to_public};

use crate::errors::{Result, SignerError};
use crate::jwk::{did_jwk, public_jwk, thumbprint};

/// A freshly generated P-256 key pair, and the identifiers that name it.
///
/// `Debug` is written by hand rather than derived: the private key must not
/// reach a log line, a panic message or an `assert_eq!` failure, and a derived
/// implementation would print it in full.
pub struct RequestKey {
    /// The private key. Never leaves this process.
    private: KeyData,
    /// The public key as a JWK.
    public_jwk: Jwk,
    /// The RFC 7638 thumbprint, which is the COSE `kid`.
    kid: String,
    /// The `did:jwk` identifier, which is the SCITT issuer.
    did_jwk: String,
    /// The `did:key` identifier, which is what badge.blue metadata carries.
    did_key: String,
}

impl std::fmt::Debug for RequestKey {
    /// Everything but the private scalar.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestKey")
            .field("kid", &self.kid)
            .field("issuer", &self.did_jwk)
            .field("did_key", &self.did_key)
            .field("private", &"<redacted>")
            .finish()
    }
}

impl RequestKey {
    /// Generate a new P-256 key pair.
    ///
    /// # Errors
    ///
    /// [`SignerError::Key`] if the key cannot be generated, or its public half
    /// cannot be derived.
    pub fn generate() -> Result<Self> {
        let private = generate_key(KeyType::P256Private).map_err(|error| SignerError::Key {
            details: format!("P-256 key generation failed: {error}"),
        })?;
        Self::from_private(private)
    }

    /// Wrap an existing private key.
    ///
    /// # Errors
    ///
    /// [`SignerError::Key`] if the key is not a P-256 private key.
    pub fn from_private(private: KeyData) -> Result<Self> {
        if *private.key_type() != KeyType::P256Private {
            return Err(SignerError::Key {
                details: format!(
                    "the statement signer needs a P-256 private key, got {}",
                    private.key_type()
                ),
            });
        }

        let public_jwk = public_jwk(&private)?;
        let kid = thumbprint(&public_jwk);
        let did_jwk = did_jwk(&public_jwk);
        let did_key = to_public(&private)
            .map(|public_key_data| format!("{public_key_data}"))
            .map_err(|error| SignerError::Key {
                details: format!(
                    "the did:key form of the public key could not be derived: {error}"
                ),
            })?;

        Ok(Self {
            private,
            public_jwk,
            kid,
            did_jwk,
            did_key,
        })
    }

    /// The private key, for signing.
    #[must_use]
    pub fn private(&self) -> &KeyData {
        &self.private
    }

    /// The public key as a JWK.
    #[must_use]
    pub fn public_jwk(&self) -> &Jwk {
        &self.public_jwk
    }

    /// The COSE `kid`: the RFC 7638 thumbprint.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The SCITT issuer: the `did:jwk` of the public key.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.did_jwk
    }

    /// The badge.blue metadata `key`: the `did:key` of the public key.
    #[must_use]
    pub fn did_key(&self) -> &str {
        &self.did_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_key_carries_consistent_identifiers() {
        let key = RequestKey::generate().expect("generates");

        assert!(key.issuer().starts_with("did:jwk:"));
        assert!(key.did_key().starts_with("did:key:zDna"));
        assert_eq!(key.kid(), thumbprint(key.public_jwk()));
    }

    /// The point of the module: two requests must not share a key.
    #[test]
    fn consecutive_keys_differ() {
        let first = RequestKey::generate().expect("generates");
        let second = RequestKey::generate().expect("generates");

        assert_ne!(first.kid(), second.kid());
        assert_ne!(first.issuer(), second.issuer());
        assert_ne!(first.private().bytes(), second.private().bytes());
    }

    #[test]
    fn a_k256_key_is_refused() {
        let k256 = generate_key(KeyType::K256Private).expect("generates");
        let error = match RequestKey::from_private(k256) {
            Ok(_) => panic!("K-256 must be refused"),
            Err(error) => error,
        };
        assert!(format!("{error}").contains("P-256"), "{error}");
    }

    /// A derived `Debug` would print the private scalar, and this type reaches
    /// log lines and panic messages.
    #[test]
    fn debug_does_not_print_the_private_key() {
        let key = RequestKey::generate().expect("generates");
        let rendered = format!("{key:?}");

        assert!(rendered.contains("<redacted>"), "{rendered}");
        let secret = key
            .private()
            .bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(!rendered.contains(&secret), "{rendered}");
        // Nor may the shorter decimal rendering of it appear.
        let base58 = format!("{}", key.private());
        assert!(!rendered.contains(&base58), "{rendered}");
    }
}
