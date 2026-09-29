//! A small, deterministic CBOR writer, sized for COSE.
//!
//! [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html) CBOR, restricted to
//! the seven major types a COSE structure needs: unsigned and negative
//! integers, byte strings, text strings, arrays, maps and tags. No indefinite
//! lengths, no simple values, no floating point.
//!
//! # Why this exists rather than a CBOR crate
//!
//! A COSE signed structure is hashed and then signed, so its *bytes* are the
//! message. Two encoders that disagree about map ordering produce two
//! different signatures over the same logical statement -- a failure that only
//! shows up when a peer verifies. Owning the encoder makes the ordering rule
//! visible in one place, and keeps the dependency set of a signing service
//! small.
//!
//! # Determinism
//!
//! Map entries are sorted by [RFC 8949 Section4.2.1] core deterministic encoding:
//! the encoded key with the shorter length comes first, and keys of equal
//! length are compared byte by byte. For integer keys -- which is what a COSE
//! header is -- this puts the small-label entries first, and for text keys it
//! is a length-first ordering rather than a lexicographic one.
//!
//! [RFC 8949 Section4.2.1]: https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1

use crate::errors::{Result, SignerError};

/// Major type 0: an unsigned integer.
const MAJOR_UNSIGNED: u8 = 0;
/// Major type 1: a negative integer.
const MAJOR_NEGATIVE: u8 = 1;
/// Major type 2: a byte string.
const MAJOR_BYTES: u8 = 2;
/// Major type 3: a text string.
const MAJOR_TEXT: u8 = 3;
/// Major type 4: an array.
const MAJOR_ARRAY: u8 = 4;
/// Major type 5: a map.
const MAJOR_MAP: u8 = 5;
/// Major type 6: a tagged item.
const MAJOR_TAG: u8 = 6;

/// A CBOR item, as much of one as this crate encodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cbor {
    /// Major type 0.
    Unsigned(u64),
    /// Major type 1. Stored as the signed value, not the encoded argument.
    Negative(i64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3.
    Text(String),
    /// Major type 4.
    Array(Vec<Cbor>),
    /// Major type 5. Order is not significant: [`Cbor::encode`] sorts.
    Map(Vec<(Cbor, Cbor)>),
    /// Major type 6.
    Tag(u64, Box<Cbor>),
}

impl Cbor {
    /// A text string.
    #[must_use]
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    /// A byte string.
    #[must_use]
    pub fn bytes(value: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(value.into())
    }

    /// An integer of either sign.
    #[must_use]
    pub fn int(value: i64) -> Self {
        if value < 0 {
            Self::Negative(value)
        } else {
            Self::Unsigned(value as u64)
        }
    }

    /// Encode this item as deterministic CBOR.
    ///
    /// # Errors
    ///
    /// [`SignerError::Cbor`] when a map key is not an integer or text string,
    /// which is outside what deterministic encoding of a COSE header needs.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.write(&mut out)?;
        Ok(out)
    }

    /// Encode into an existing buffer.
    ///
    /// # Errors
    ///
    /// As [`Cbor::encode`].
    pub fn write(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Unsigned(value) => {
                write_head(out, MAJOR_UNSIGNED, *value);
            }
            Self::Negative(value) => {
                // Major type 1 encodes `-1 - n`, so the argument is `-1 - value`.
                let argument = (-1i128 - i128::from(*value)) as u128;
                let argument = u64::try_from(argument).map_err(|_| SignerError::Cbor {
                    details: format!("negative integer {value} is out of CBOR range"),
                })?;
                write_head(out, MAJOR_NEGATIVE, argument);
            }
            Self::Bytes(value) => {
                write_head(out, MAJOR_BYTES, value.len() as u64);
                out.extend_from_slice(value);
            }
            Self::Text(value) => {
                write_head(out, MAJOR_TEXT, value.len() as u64);
                out.extend_from_slice(value.as_bytes());
            }
            Self::Array(items) => {
                write_head(out, MAJOR_ARRAY, items.len() as u64);
                for item in items {
                    item.write(out)?;
                }
            }
            Self::Map(entries) => {
                write_head(out, MAJOR_MAP, entries.len() as u64);
                for (key, value) in sort_entries(entries)? {
                    key.write(out)?;
                    value.write(out)?;
                }
            }
            Self::Tag(tag, inner) => {
                write_head(out, MAJOR_TAG, *tag);
                inner.write(out)?;
            }
        }
        Ok(())
    }
}

/// Write a head: the major type, the argument, and its shortest form.
fn write_head(out: &mut Vec<u8>, major: u8, argument: u64) {
    let prefix = major << 5;
    if argument < 24 {
        out.push(prefix | argument as u8);
    } else if argument <= u64::from(u8::MAX) {
        out.push(prefix | 24);
        out.push(argument as u8);
    } else if argument <= u64::from(u16::MAX) {
        out.push(prefix | 25);
        out.extend_from_slice(&(argument as u16).to_be_bytes());
    } else if argument <= u64::from(u32::MAX) {
        out.push(prefix | 26);
        out.extend_from_slice(&(argument as u32).to_be_bytes());
    } else {
        out.push(prefix | 27);
        out.extend_from_slice(&argument.to_be_bytes());
    }
}

/// A map key as the sort sees it: its encoding, kept so the comparison is made
/// once per key rather than once per comparison.
struct SortableKey<'a> {
    /// Index into the caller's entry list.
    index: usize,
    /// The key's encoded bytes.
    encoded: Vec<u8>,
    /// The key itself, for the type check.
    key: &'a Cbor,
}

/// Order map entries by RFC 8949 Section4.2.1 core deterministic encoding.
///
/// # Errors
///
/// [`SignerError::Cbor`] for a key that is neither an integer nor a text
/// string, and for a duplicate key, which would encode a map no decoder reads
/// back the way it was written.
fn sort_entries(entries: &[(Cbor, Cbor)]) -> Result<Vec<(&Cbor, &Cbor)>> {
    let mut sortable = Vec::with_capacity(entries.len());
    for (index, (key, _)) in entries.iter().enumerate() {
        if !matches!(key, Cbor::Unsigned(_) | Cbor::Negative(_) | Cbor::Text(_)) {
            return Err(SignerError::Cbor {
                details: format!("map key is not an integer or text string: {key:?}"),
            });
        }
        sortable.push(SortableKey {
            index,
            encoded: key.encode()?,
            key,
        });
    }

    sortable.sort_by(|left, right| {
        left.encoded
            .len()
            .cmp(&right.encoded.len())
            .then_with(|| left.encoded.cmp(&right.encoded))
    });

    for window in sortable.windows(2) {
        if window[0].encoded == window[1].encoded {
            return Err(SignerError::Cbor {
                details: format!("duplicate map key: {:?}", window[0].key),
            });
        }
    }

    Ok(sortable
        .into_iter()
        .map(|sortable| (&entries[sortable.index].0, &entries[sortable.index].1))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(item: &Cbor) -> Vec<u8> {
        item.encode().expect("encodes")
    }

    /// The shortest form, one test per head width, so the boundaries are
    /// pinned rather than assumed.
    #[test]
    fn integers_use_the_shortest_head() {
        assert_eq!(encoded(&Cbor::Unsigned(0)), vec![0x00]);
        assert_eq!(encoded(&Cbor::Unsigned(10)), vec![0x0a]);
        assert_eq!(encoded(&Cbor::Unsigned(23)), vec![0x17]);
        assert_eq!(encoded(&Cbor::Unsigned(24)), vec![0x18, 0x18]);
        assert_eq!(encoded(&Cbor::Unsigned(255)), vec![0x18, 0xff]);
        assert_eq!(encoded(&Cbor::Unsigned(256)), vec![0x19, 0x01, 0x00]);
        assert_eq!(
            encoded(&Cbor::Unsigned(65_536)),
            vec![0x1a, 0x00, 0x01, 0x00, 0x00]
        );
        assert_eq!(
            encoded(&Cbor::Unsigned(u64::from(u32::MAX) + 1)),
            vec![0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
    }

    /// Major type 1 encodes `-1 - n`, which is the part an off-by-one gets
    /// wrong: `-7` (ES256) must be the single byte `0x26`.
    #[test]
    fn negative_integers_encode_minus_one_minus_n() {
        assert_eq!(encoded(&Cbor::int(-1)), vec![0x20]);
        assert_eq!(encoded(&Cbor::int(-7)), vec![0x26]);
        assert_eq!(encoded(&Cbor::int(-35)), vec![0x38, 0x22]);
        assert_eq!(encoded(&Cbor::int(-36)), vec![0x38, 0x23]);
        assert_eq!(encoded(&Cbor::int(-8)), vec![0x27]);
    }

    #[test]
    fn strings_carry_their_length_in_bytes() {
        assert_eq!(encoded(&Cbor::text("")), vec![0x60]);
        assert_eq!(encoded(&Cbor::text("a")), vec![0x61, b'a']);
        assert_eq!(encoded(&Cbor::bytes(vec![1, 2, 3])), vec![0x43, 1, 2, 3]);
        // A multi-byte character counts bytes, not characters. Written as an
        // escape so this source file stays ASCII; the encoded bytes below are
        // its two-byte UTF-8 form, which is the thing being asserted.
        assert_eq!(encoded(&Cbor::text("\u{e9}")), vec![0x62, 0xc3, 0xa9]);
    }

    #[test]
    fn tags_wrap_their_content() {
        // Tag 18 is COSE_Sign1; here over an empty array.
        assert_eq!(encoded(&Cbor::Tag(18, Box::new(Cbor::Array(vec![])))), {
            vec![0xd2, 0x80]
        });
    }

    /// RFC 8949 Section4.2.1: shorter encoding first, then bytewise. Integer keys
    /// make this the "smaller label first" rule a COSE header depends on.
    #[test]
    fn map_keys_are_sorted_by_encoded_length_then_bytes() {
        let map = Cbor::Map(vec![
            (Cbor::text("zz"), Cbor::Unsigned(3)),
            (Cbor::text("a"), Cbor::Unsigned(1)),
            (Cbor::text("bb"), Cbor::Unsigned(2)),
        ]);
        // "a" is one byte of content, "bb" and "zz" are two, so "bb" precedes
        // "zz" -- length first, and only then lexicographic.
        assert_eq!(
            encoded(&map),
            vec![
                0xa3, 0x61, b'a', 0x01, 0x62, b'b', b'b', 0x02, 0x62, b'z', b'z', 0x03
            ]
        );
    }

    #[test]
    fn cos_e_header_labels_sort_by_size() {
        // alg (1), content type (3), kid (4), CWT claims (15): all single byte.
        let map = Cbor::Map(vec![
            (Cbor::Unsigned(15), Cbor::Map(vec![])),
            (Cbor::Unsigned(4), Cbor::bytes(vec![0xaa])),
            (Cbor::Unsigned(1), Cbor::int(-7)),
        ]);
        assert_eq!(
            encoded(&map),
            vec![0xa3, 0x01, 0x26, 0x04, 0x41, 0xaa, 0x0f, 0xa0]
        );
    }

    /// Two entries under one key is a map no decoder reads back as written.
    #[test]
    fn duplicate_keys_are_refused() {
        let map = Cbor::Map(vec![
            (Cbor::Unsigned(1), Cbor::Unsigned(2)),
            (Cbor::Unsigned(1), Cbor::Unsigned(3)),
        ]);
        let error = map.encode().expect_err("duplicate key must be refused");
        assert!(format!("{error}").contains("duplicate map key"), "{error}");
    }

    #[test]
    fn a_non_scalar_map_key_is_refused() {
        let map = Cbor::Map(vec![(Cbor::Array(vec![]), Cbor::Unsigned(1))]);
        let error = map.encode().expect_err("array key must be refused");
        assert!(format!("{error}").contains("not an integer"), "{error}");
    }

    /// The encoding of a map must not depend on the order it was built in.
    #[test]
    fn map_encoding_is_order_independent() {
        let first = Cbor::Map(vec![
            (Cbor::Unsigned(3), Cbor::text("ct")),
            (Cbor::Unsigned(1), Cbor::int(-7)),
        ]);
        let second = Cbor::Map(vec![
            (Cbor::Unsigned(1), Cbor::int(-7)),
            (Cbor::Unsigned(3), Cbor::text("ct")),
        ]);
        assert_eq!(encoded(&first), encoded(&second));
    }
}
