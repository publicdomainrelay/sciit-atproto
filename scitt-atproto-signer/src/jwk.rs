//! P-256 public keys as JWKs, as `did:jwk` identifiers, and as RFC 7638
//! thumbprints.
//!
//! Three encodings of one key are needed, and each is used for a different
//! job:
//!
//! * the **JWK** is what a verifier is handed so it can check a signature it
//!   has no other way to resolve keys for;
//! * the **`did:jwk` identifier** carries that JWK inside the issuer string of
//!   a SCITT Signed Statement, which is how a Transparency Service resolves
//!   the signing key without a directory lookup;
//! * the **thumbprint** is the `kid` a COSE header names.
//!
//! The thumbprint is computed over a canonical object, not over the JWK as
//! written. Reusing the serialised JWK would make the `kid` depend on member
//! order, and two encoders of one key would then publish two identifiers for
//! it.

use atproto_identity::jwk::{CRV_P256, Jwk};
use atproto_identity::key::{KeyData, KeyType};
use atproto_identity::plc::encoding::{base64url_encode, sha256};
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToSec1Point;
use serde_json::{Value, json};

use crate::errors::{Result, SignerError};

/// The `did:jwk` method prefix.
pub const DID_JWK_PREFIX: &str = "did:jwk:";

/// Derive the public JWK of a P-256 private key.
///
/// `atproto_identity::key::to_public` returns the **compressed** SEC1 point,
/// which is what a `did:key` carries. A JWK needs the uncompressed form -- the
/// affine `x` and `y` -- so the point is rebuilt here rather than sliced.
///
/// # Errors
///
/// [`SignerError::Key`] if the key is not a P-256 private key or its public
/// point cannot be derived.
pub fn public_jwk(private_key: &KeyData) -> Result<Jwk> {
    // The type check is load-bearing, not defensive. A secp256k1 scalar is 32
    // bytes and parses as a P-256 scalar without complaint, so a K-256 key
    // would come back as a well-formed JWK for a key nobody holds.
    if *private_key.key_type() != KeyType::P256Private {
        return Err(SignerError::Key {
            details: format!(
                "a P-256 private key is needed for a P-256 JWK, got {}",
                private_key.key_type()
            ),
        });
    }

    let secret_key =
        SecretKey::from_slice(private_key.bytes()).map_err(|error| SignerError::Key {
            details: format!("P-256 private key could not be read: {error}"),
        })?;
    let public_key = secret_key.public_key();
    let point = public_key.to_sec1_point(false);
    Jwk::from_sec1_uncompressed(CRV_P256, point.as_bytes()).map_err(|error| SignerError::Key {
        details: format!("public key could not be encoded as a JWK: {error}"),
    })
}

/// The public JWK as JSON.
#[must_use]
pub fn jwk_json(jwk: &Jwk) -> Value {
    json!({
        "kty": jwk.kty,
        "crv": jwk.crv,
        "x": jwk.x,
        "y": jwk.y,
    })
}

/// The RFC 7638 thumbprint of a JWK: base64url of SHA-256 over the required
/// members, in lexicographic order, with no whitespace.
///
/// For an EC key the required members are `crv`, `kty`, `x` and `y`, and that
/// is exactly the order the canonical form lists them in.
#[must_use]
pub fn thumbprint(jwk: &Jwk) -> String {
    let canonical = format!(
        "{{\"crv\":\"{}\",\"kty\":\"{}\",\"x\":\"{}\",\"y\":\"{}\"}}",
        jwk.crv, jwk.kty, jwk.x, jwk.y
    );
    base64url_encode(&sha256(canonical.as_bytes()))
}

/// The `did:jwk` identifier for a public JWK.
///
/// RFC 7515 Section2: the identifier is the JWK as unpadded base64url. The
/// `did:jwk` method spec adds that the key must carry no private material,
/// which a JWK built by [`public_jwk`] cannot.
#[must_use]
pub fn did_jwk(jwk: &Jwk) -> String {
    let json = serde_json::to_string(&jwk_json(jwk)).unwrap_or_default();
    format!("{DID_JWK_PREFIX}{}", base64url_encode(json.as_bytes()))
}

#[cfg(test)]
mod tests {
    use atproto_identity::key::{KeyType, generate_key};
    use base64_lite::decode_url_nopad;

    use super::*;

    /// Kept local so the crate under test needs no base64 dependency of its
    /// own for one assertion.
    mod base64_lite {
        /// Decode unpadded base64url, for tests only.
        pub fn decode_url_nopad(value: &str) -> Vec<u8> {
            let mut out = Vec::new();
            let mut buffer: u32 = 0;
            let mut bits = 0;
            for byte in value.bytes() {
                let digit = match byte {
                    b'A'..=b'Z' => byte - b'A',
                    b'a'..=b'z' => byte - b'a' + 26,
                    b'0'..=b'9' => byte - b'0' + 52,
                    b'-' => 62,
                    b'_' => 63,
                    _ => panic!("not base64url: {value}"),
                };
                buffer = (buffer << 6) | u32::from(digit);
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    out.push((buffer >> bits) as u8);
                }
            }
            out
        }
    }

    /// RFC 7638 Section3.1 publishes a thumbprint for a known RSA key. There is no
    /// such vector for P-256, so the check is the property the RFC states:
    /// the canonical form is over the required members in lexicographic order,
    /// and the digest covers exactly those bytes.
    #[test]
    fn thumbprint_is_sha256_over_the_canonical_members() {
        let key = generate_key(KeyType::P256Private).expect("generates");
        let jwk = public_jwk(&key).expect("derives");

        let canonical = format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            jwk.x, jwk.y
        );
        assert_eq!(
            thumbprint(&jwk),
            base64url_encode(&sha256(canonical.as_bytes()))
        );
    }

    /// A `did:jwk` carries the public JWK as unpadded base64url, and round
    /// trips back to the same key.
    #[test]
    fn did_jwk_round_trips_to_the_same_public_key() {
        let key = generate_key(KeyType::P256Private).expect("generates");
        let jwk = public_jwk(&key).expect("derives");

        let did = did_jwk(&jwk);
        let encoded = did.strip_prefix(DID_JWK_PREFIX).expect("prefixed");
        assert!(
            !encoded.contains('='),
            "did:jwk must be unpadded: {encoded}"
        );

        let decoded: Value =
            serde_json::from_slice(&decode_url_nopad(encoded)).expect("decodes to JSON");
        assert_eq!(decoded["kty"], "EC");
        assert_eq!(decoded["crv"], "P-256");
        assert_eq!(decoded["x"], jwk.x);
        assert_eq!(decoded["y"], jwk.y);
        assert!(decoded.get("d").is_none(), "no private material may appear");
    }

    /// The `y` coordinate is the half a compressed-point shortcut loses, so
    /// it must equal the second half of the uncompressed SEC1 point.
    #[test]
    fn the_jwk_carries_both_coordinates() {
        let key = generate_key(KeyType::P256Private).expect("generates");
        let jwk = public_jwk(&key).expect("derives");

        let point = decode_url_nopad(&jwk.x);
        let y = decode_url_nopad(&jwk.y);
        assert_eq!(point.len(), 32);
        assert_eq!(y.len(), 32);
        assert_ne!(point, y);
    }

    /// A secp256k1 scalar is 32 bytes and parses as a P-256 scalar, so without
    /// the key-type check this would return a JWK for a key nobody holds.
    #[test]
    fn a_key_of_the_wrong_curve_is_refused() {
        for key_type in [KeyType::K256Private, KeyType::Ed25519Private] {
            let key = generate_key(key_type.clone()).expect("generates");
            let error = public_jwk(&key).expect_err("only P-256 is a P-256 JWK");
            assert!(format!("{error}").contains("P-256"), "{error}");
        }
    }

    /// Two keys must not share a thumbprint, and one key must always have the
    /// same one.
    #[test]
    fn thumbprints_are_stable_and_distinct() {
        let first =
            public_jwk(&generate_key(KeyType::P256Private).expect("generates")).expect("derives");
        let second =
            public_jwk(&generate_key(KeyType::P256Private).expect("generates")).expect("derives");

        assert_eq!(thumbprint(&first), thumbprint(&first.clone()));
        assert_ne!(thumbprint(&first), thumbprint(&second));
    }
}
