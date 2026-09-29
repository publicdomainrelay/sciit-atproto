//! COSE_Sign1 Signed Statements, as SCITT defines them.
//!
//! A Signed Statement is a CBOR tag-18 `COSE_Sign1` whose payload is the
//! artifact and whose protected header carries the signer
//! ([RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html) Section4, Figure 5):
//!
//! * `1` (`alg`) -- `-7`, ECDSA with SHA-256 on P-256 (`ES256`);
//! * `3` (`content type`) -- the media type of the payload;
//! * `4` (`kid`) -- the signer's key identifier, as a byte string;
//! * `15` (`CWT Claims`, [RFC 9597]) -- a plain CWT Claims Set holding `iss`
//!   (`1`) and `sub` (`2`).
//!
//! [RFC 9597]: https://www.rfc-editor.org/rfc/rfc9597.html
//!
//! # What the signature covers
//!
//! Per [RFC 9052 Section4.4], the signature is over the CBOR encoding of:
//!
//! ```text
//! Sig_structure = [
//!     "Signature1",   ; context
//!     protected,      ; the encoded protected header, as a byte string
//!     external_aad,   ; empty
//!     payload,        ; the artifact, as a byte string
//! ]
//! ```
//!
//! The unprotected header is **not** covered. That is the property a
//! Transparent Statement relies on: receipts are added there, after signing,
//! and the signature stays valid.
//!
//! [RFC 9052 Section4.4]: https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4

use atproto_identity::key::sign;

use crate::cbor::Cbor;
use crate::errors::{Result, SignerError};
use crate::keys::RequestKey;

/// COSE header label 1: the signature algorithm.
pub const HEADER_ALG: i64 = 1;
/// COSE header label 3: the payload's media type.
pub const HEADER_CONTENT_TYPE: i64 = 3;
/// COSE header label 4: the key identifier.
pub const HEADER_KID: i64 = 4;
/// COSE header label 15: the CWT Claims Set (RFC 9597).
pub const HEADER_CWT_CLAIMS: i64 = 15;
/// COSE header label 394: the receipts of a Transparent Statement (RFC 9943).
pub const HEADER_RECEIPTS: i64 = 394;

/// COSE algorithm identifier for ECDSA with SHA-256 on P-256.
pub const ALG_ES256: i64 = -7;

/// COSE_Sign1 tag number.
pub const TAG_COSE_SIGN1: u64 = 18;

/// CWT claim 1: the issuer.
pub const CWT_ISS: i64 = 1;
/// CWT claim 2: the subject.
pub const CWT_SUB: i64 = 2;

/// The inputs a Signed Statement is built from.
#[derive(Debug, Clone)]
pub struct StatementParams {
    /// The issuer: who is making the statement. A `did:jwk` here.
    pub issuer: String,
    /// The subject: what the statement is about, chosen by the issuer.
    pub subject: String,
    /// The media type of the payload.
    pub content_type: String,
}

/// A Signed Statement, in both the forms a caller needs.
#[derive(Debug, Clone)]
pub struct SignedStatement {
    /// The `COSE_Sign1` as registered: tag 18, empty unprotected header.
    pub statement: Vec<u8>,
    /// The protected header as encoded, kept so a Transparent Statement can
    /// reuse it byte for byte rather than re-encode it.
    pub protected: Vec<u8>,
}

/// Build and sign a COSE_Sign1 Signed Statement over `payload`.
///
/// The `kid` names the key inside `key`, so a verifier that resolves the
/// issuer finds the key the signature was made with.
///
/// # Errors
///
/// [`SignerError::Cbor`] if a header cannot be encoded, and
/// [`SignerError::Cose`] if the signature cannot be produced or its length is
/// not the 64 bytes ES256 requires.
pub fn sign_statement(
    key: &RequestKey,
    params: &StatementParams,
    payload: &[u8],
) -> Result<SignedStatement> {
    let protected = protected_header(key, params)?.encode()?;

    let to_be_signed = Cbor::Array(vec![
        Cbor::text("Signature1"),
        Cbor::bytes(protected.clone()),
        Cbor::bytes(Vec::new()),
        Cbor::bytes(payload.to_vec()),
    ])
    .encode()?;

    // `atproto_identity::key::sign` is ES256 for a P-256 key -- ECDSA with
    // SHA-256 -- and normalises `s` to the low form, which is what the
    // workspace's other AT Protocol signature paths expect of it.
    let signature = sign(key.private(), &to_be_signed).map_err(|error| SignerError::Cose {
        details: format!("the statement signature could not be produced: {error}"),
    })?;
    if signature.len() != 64 {
        return Err(SignerError::Cose {
            details: format!(
                "ES256 signatures are 64 bytes, this one is {}",
                signature.len()
            ),
        });
    }

    let statement = Cbor::Tag(
        TAG_COSE_SIGN1,
        Box::new(Cbor::Array(vec![
            Cbor::bytes(protected.clone()),
            Cbor::Map(Vec::new()),
            Cbor::bytes(payload.to_vec()),
            Cbor::bytes(signature),
        ])),
    )
    .encode()?;

    Ok(SignedStatement {
        statement,
        protected,
    })
}

/// Wrap a Signed Statement and its Receipts into a Transparent Statement.
///
/// [RFC 9943 Section4] and Figure 3 type label 394 as `[+ bstr .cbor Receipt]` in
/// the *unprotected* header, so the receipts are added there and the protected
/// header -- and therefore the signature -- is untouched. The caller's
/// `protected` bytes are written back verbatim for that reason: re-encoding
/// them would risk a different, still-valid encoding that no longer matches
/// the signature.
///
/// # Errors
///
/// [`SignerError::Cbor`] if the outer structure cannot be encoded.
pub fn transparent_statement(
    statement: &SignedStatement,
    payload: &[u8],
    receipts: &[Vec<u8>],
) -> Result<Vec<u8>> {
    // The signature is carried over unchanged. It is read back out of the
    // statement rather than kept beside it so there is one place the
    // statement's shape is defined.
    let signature = signature_of(&statement.statement)?;

    let unprotected = if receipts.is_empty() {
        Cbor::Map(Vec::new())
    } else {
        Cbor::Map(vec![(
            Cbor::int(HEADER_RECEIPTS),
            Cbor::Array(receipts.iter().map(|r| Cbor::bytes(r.clone())).collect()),
        )])
    };

    Cbor::Tag(
        TAG_COSE_SIGN1,
        Box::new(Cbor::Array(vec![
            Cbor::bytes(statement.protected.clone()),
            unprotected,
            Cbor::bytes(payload.to_vec()),
            Cbor::bytes(signature),
        ])),
    )
    .encode()
}

/// The protected header of a Signed Statement.
fn protected_header(key: &RequestKey, params: &StatementParams) -> Result<Cbor> {
    Ok(Cbor::Map(vec![
        (Cbor::int(HEADER_ALG), Cbor::int(ALG_ES256)),
        (
            Cbor::int(HEADER_CONTENT_TYPE),
            Cbor::text(params.content_type.clone()),
        ),
        (
            Cbor::int(HEADER_KID),
            Cbor::bytes(key.kid().as_bytes().to_vec()),
        ),
        (
            Cbor::int(HEADER_CWT_CLAIMS),
            Cbor::Map(vec![
                (Cbor::int(CWT_ISS), Cbor::text(params.issuer.clone())),
                (Cbor::int(CWT_SUB), Cbor::text(params.subject.clone())),
            ]),
        ),
    ]))
}

/// Read the signature out of an encoded `COSE_Sign1`.
///
/// Deliberately a small CBOR reader rather than a decoder: the shape is fixed
/// by [`sign_statement`], which is in this module, so the only thing this has
/// to survive is being handed something that is not one.
///
/// # Errors
///
/// [`SignerError::Cose`] if `encoded` is not a tag-18 array of four items
/// whose last is a byte string.
fn signature_of(encoded: &[u8]) -> Result<Vec<u8>> {
    let not_a_statement = || SignerError::Cose {
        details: "the signed statement is not a tag-18 COSE_Sign1 array".to_string(),
    };

    // Tag head: major type 6, argument 18, then a 4-element array head.
    let body = match encoded {
        [0xd2, 0x84, rest @ ..] => rest,
        _ => return Err(not_a_statement()),
    };

    let mut cursor = 0usize;
    for _ in 0..3 {
        skip_item(body, &mut cursor).ok_or_else(not_a_statement)?;
    }
    read_byte_string(body, &mut cursor).ok_or_else(not_a_statement)
}

/// Advance `cursor` past one CBOR item.
fn skip_item(bytes: &[u8], cursor: &mut usize) -> Option<()> {
    let head = *bytes.get(*cursor)?;
    *cursor += 1;
    let major = head >> 5;
    let argument = read_argument(head & 0x1f, bytes, cursor)?;

    match major {
        0 | 1 => Some(()),
        2 | 3 => {
            *cursor = cursor.checked_add(usize::try_from(argument).ok()?)?;
            (*cursor <= bytes.len()).then_some(())
        }
        4 => {
            for _ in 0..argument {
                skip_item(bytes, cursor)?;
            }
            Some(())
        }
        5 => {
            for _ in 0..argument.checked_mul(2)? {
                skip_item(bytes, cursor)?;
            }
            Some(())
        }
        6 => skip_item(bytes, cursor),
        7 => (argument == 20 || argument == 21 || argument == 22).then_some(()),
        _ => None,
    }
}

/// Read a byte string item.
fn read_byte_string(bytes: &[u8], cursor: &mut usize) -> Option<Vec<u8>> {
    let head = *bytes.get(*cursor)?;
    *cursor += 1;
    if head >> 5 != 2 {
        return None;
    }
    let length = usize::try_from(read_argument(head & 0x1f, bytes, cursor)?).ok()?;
    let end = cursor.checked_add(length)?;
    let value = bytes.get(*cursor..end)?.to_vec();
    *cursor = end;
    Some(value)
}

/// Read a head's argument, advancing `cursor` past any extra bytes.
fn read_argument(small: u8, bytes: &[u8], cursor: &mut usize) -> Option<u64> {
    match small {
        0..=23 => Some(u64::from(small)),
        24 => {
            let value = u64::from(*bytes.get(*cursor)?);
            *cursor += 1;
            Some(value)
        }
        25 => {
            let slice = bytes.get(*cursor..*cursor + 2)?;
            *cursor += 2;
            Some(u64::from(u16::from_be_bytes(slice.try_into().ok()?)))
        }
        26 => {
            let slice = bytes.get(*cursor..*cursor + 4)?;
            *cursor += 4;
            Some(u64::from(u32::from_be_bytes(slice.try_into().ok()?)))
        }
        27 => {
            let slice = bytes.get(*cursor..*cursor + 8)?;
            *cursor += 8;
            Some(u64::from_be_bytes(slice.try_into().ok()?))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> StatementParams {
        StatementParams {
            issuer: "did:jwk:abc".to_string(),
            subject: "atproto-xrpc-sign".to_string(),
            content_type: "application/json".to_string(),
        }
    }

    /// A Signed Statement is a tag-18 array. The tag byte and the four-element
    /// array head are the two bytes a reader keys off, so they are pinned.
    #[test]
    fn a_statement_is_a_tag_18_array_of_four() {
        let key = RequestKey::generate().expect("generates");
        let signed = sign_statement(&key, &params(), b"{\"a\":1}").expect("signs a statement");

        assert_eq!(&signed.statement[..2], &[0xd2, 0x84]);
        assert_eq!(
            signature_of(&signed.statement).expect("reads back").len(),
            64
        );
    }

    /// The protected header must name the key that signed, the algorithm, the
    /// media type and both CWT claims. Checked by decoding the header's own
    /// bytes, because a header that encodes but silently drops a field is the
    /// failure this guards.
    #[test]
    fn the_protected_header_carries_alg_kid_content_type_and_cwt_claims() {
        let key = RequestKey::generate().expect("generates");
        let signed = sign_statement(&key, &params(), b"x").expect("signs");

        // The whole header, byte for byte. A 4-entry map, then the labels in
        // RFC 8949 Section4.2.1 order -- alg (1), content type (3), kid (4), CWT
        // claims (15) are all one byte, so they sort bytewise to 1, 3, 4, 15.
        let mut expected = vec![
            0xa4, // map of four
            0x01, 0x26, // alg: -7, ES256
            0x03, 0x70, // content type: a 16-byte text string
        ];
        expected.extend_from_slice(b"application/json");
        expected.extend_from_slice(&[
            0x04, 0x58, 43, // kid: a 43-byte byte string
        ]);
        expected.extend_from_slice(key.kid().as_bytes());
        expected.extend_from_slice(&[
            0x0f, 0xa2, // CWT claims: a map of two
            0x01, 0x6b, // iss: an 11-byte text string
        ]);
        expected.extend_from_slice(b"did:jwk:abc");
        expected.extend_from_slice(&[
            0x02, 0x71, // sub: a 17-byte text string
        ]);
        expected.extend_from_slice(b"atproto-xrpc-sign");

        // The comparison above carries the kid, because `expected` splices in
        // the key's own thumbprint. State that separately so the test says
        // what it is checking rather than leaving it to be inferred.
        assert!(
            signed
                .protected
                .windows(key.kid().len())
                .any(|window| window == key.kid().as_bytes()),
            "the kid is not in the protected header"
        );
        assert_eq!(signed.protected, expected);
    }

    /// The subject and issuer are inside the CWT Claims header, so both must
    /// appear in the protected bytes, and the signature must depend on them.
    #[test]
    fn the_signature_covers_the_issuer_and_subject() {
        let key = RequestKey::generate().expect("generates");

        let first = sign_statement(&key, &params(), b"payload").expect("signs");
        let mut changed = params();
        changed.subject = "a different subject".to_string();
        let second = sign_statement(&key, &changed, b"payload").expect("signs");

        let find = |haystack: &[u8], needle: &str| {
            haystack
                .windows(needle.len())
                .any(|window| window == needle.as_bytes())
        };
        assert!(find(&first.protected, "did:jwk:abc"));
        assert!(find(&first.protected, "atproto-xrpc-sign"));
        assert_ne!(
            signature_of(&first.statement).expect("reads"),
            signature_of(&second.statement).expect("reads")
        );
    }

    /// The payload is covered too: changing it must change the signature.
    #[test]
    fn the_signature_covers_the_payload() {
        let key = RequestKey::generate().expect("generates");
        let first = sign_statement(&key, &params(), b"one").expect("signs");
        let second = sign_statement(&key, &params(), b"two").expect("signs");
        assert_ne!(
            signature_of(&first.statement).expect("reads"),
            signature_of(&second.statement).expect("reads")
        );
    }

    /// The receipt lives in the unprotected header, so adding one must leave
    /// the protected header and the signature byte for byte identical -- that
    /// is the whole reason a Transparent Statement can exist.
    #[test]
    fn receipts_go_in_the_unprotected_header_and_leave_the_signature_alone() {
        let key = RequestKey::generate().expect("generates");
        let payload = b"{\"a\":1}";
        let signed = sign_statement(&key, &params(), payload).expect("signs");

        let receipt = vec![0xd2, 0x84, 0x40, 0xa0, 0x40, 0x40];
        let transparent =
            transparent_statement(&signed, payload, std::slice::from_ref(&receipt)).expect("wraps");

        assert_eq!(&transparent[..2], &[0xd2, 0x84]);
        // Protected header: the same byte string, at the same offset.
        assert_eq!(
            &transparent[2..2 + 2 + signed.protected.len()],
            &[
                vec![0x58, signed.protected.len() as u8],
                signed.protected.clone()
            ]
            .concat()
        );
        assert_eq!(
            signature_of(&transparent).expect("reads"),
            signature_of(&signed.statement).expect("reads")
        );
        // Label 394 is present, and the receipt is inside it.
        assert!(
            find_bytes(&transparent, &[0x19, 0x01, 0x8a]),
            "receipts label"
        );
    }

    /// A Transparent Statement with no receipts is a plain Signed Statement
    /// with an empty unprotected header -- not an error, and not a header
    /// carrying an empty array.
    #[test]
    fn no_receipts_leaves_the_unprotected_header_empty() {
        let key = RequestKey::generate().expect("generates");
        let payload = b"payload";
        let signed = sign_statement(&key, &params(), payload).expect("signs");
        let transparent = transparent_statement(&signed, payload, &[]).expect("wraps");
        assert_eq!(transparent, signed.statement);
    }

    /// The reader is fed three things that are not a COSE_Sign1, and must say
    /// so rather than panic or return something plausible.
    #[test]
    fn a_malformed_statement_is_refused() {
        assert!(signature_of(&[]).is_err());
        assert!(signature_of(&[0xd2, 0x84]).is_err());
        assert!(signature_of(&[0x84, 0x40, 0xa0, 0x40, 0x40]).is_err());
        // Truncated: the signature byte string runs past the end.
        assert!(signature_of(&[0xd2, 0x84, 0x40, 0xa0, 0x40, 0x58, 0xff]).is_err());
    }

    fn find_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
