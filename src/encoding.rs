//! Human-friendly "prefixed" encoding for the public data types.
//!
//! This module sits *on top of* the canonical byte / hex encoding in
//! [`crate::types`]. It does not change a single bit of what is hashed,
//! signed or verified — it is a pure presentation layer whose only job is
//! to make a copy-pasted value:
//!
//!  - **self-describing** — a short tag (`pk`, `sk`, `ki`, `blsag`) up
//!    front says what kind of value it is, so a public key pasted where a
//!    key image was expected is caught immediately;
//!  - **typo-resistant** — a trailing checksum detects the overwhelming
//!    majority of single-character mistakes, transpositions and truncated
//!    pastes before the bytes ever reach the cryptographic core.
//!
//! ## Wire shape
//!
//! ```text
//!   pk_3f8a…e1c0_d4e9a1b7
//!   │  │         │
//!   │  │         └ checksum: 4 bytes, hex (8 chars)
//!   │  └ body: the canonical hex encoding, exactly as `to_hex()` emits it
//!   └ tag: pk | sk | ki | blsag
//! ```
//!
//! Three `_`-separated parts. None of the parts can itself contain a `_`
//! (the tags are fixed, the other two are hexadecimal), so splitting on
//! `_` is unambiguous.
//!
//! ## Checksum
//!
//! `checksum = BLAKE3(DOMAIN || tag || 0x00 || payload)[..4]`.
//!
//! The tag is folded into the checksum pre-image (with a `0x00`
//! separator so no tag can be confused with a prefix of another), which
//! is what makes relabelling detectable: take a valid `pk_…` string,
//! rewrite the tag to `ki_`, and the checksum no longer matches. So one
//! check covers both "is the prefix coherent?" and "was the value
//! mistyped?".
//!
//! This checksum is **not** a security primitive. An attacker can
//! trivially compute a valid checksum for any bytes they like; its only
//! purpose is to catch honest mistakes. Authenticity comes from the
//! BLSAG proof, never from this.

use crate::error::{Error, Result};
use zeroize::Zeroizing;

/// Length of the checksum in bytes (hex-encoded to twice this many chars).
const CHECKSUM_LEN: usize = 4;

/// Domain-separation string mixed into every checksum. Bumping the
/// trailing version would invalidate previously-issued strings, so it is
/// part of the format's compatibility contract.
const DOMAIN: &[u8] = b"crypto_vote/prefixed-checksum/v1";

/// Which kind of value a prefixed string carries. The string form is the
/// human-readable prefix; it is also folded into the checksum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tag {
    /// A [`crate::PublicKey`] — prefix `pk`.
    PublicKey,
    /// A [`crate::SecretKey`] — prefix `sk`.
    SecretKey,
    /// A [`crate::KeyImage`] — prefix `ki`.
    KeyImage,
    /// A [`crate::Signature`] — prefix `blsag`.
    Signature,
}

impl Tag {
    /// The human-readable prefix for this tag (no trailing `_`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Tag::PublicKey => "pk",
            Tag::SecretKey => "sk",
            Tag::KeyImage => "ki",
            Tag::Signature => "blsag",
        }
    }
}

/// Compute the 4-byte checksum for `payload` under `tag`.
fn checksum(tag: Tag, payload: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(tag.as_str().as_bytes());
    // A separator the tag can never contain, so `pk` || payload can never
    // collide with some other (tag, payload) pairing.
    hasher.update(&[0u8]);
    hasher.update(payload);
    let hash = hasher.finalize();
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&hash.as_bytes()[..CHECKSUM_LEN]);
    out
}

/// Encode `payload` as `tag_<hexbody>_<hexchecksum>`.
///
/// `payload` is the canonical byte encoding of the value (what
/// `to_bytes()` returns). The body is its lowercase hex, identical to
/// what `to_hex()` would emit.
pub fn encode_prefixed(tag: Tag, payload: &[u8]) -> String {
    let cs = checksum(tag, payload);
    format!(
        "{}_{}_{}",
        tag.as_str(),
        hex::encode(payload),
        hex::encode(cs)
    )
}

/// Decode a `tag_<hexbody>_<hexchecksum>` string, verifying both the tag
/// and the checksum, and return the raw payload bytes.
///
/// The returned bytes are wrapped in [`Zeroizing`] so that decoding a
/// secret key does not leave a readable copy on the heap once the caller
/// is done with it.
///
/// Errors:
///  - [`Error::InvalidPrefix`] if the string is not in three-part shape,
///    or its tag is not the one expected for this type;
///  - [`Error::InvalidHex`] if the body or checksum part is not hex;
///  - [`Error::InvalidChecksum`] if the checksum is the wrong length or
///    does not match the recomputed value.
pub fn decode_prefixed(expected: Tag, s: &str) -> Result<Zeroizing<Vec<u8>>> {
    let parts: Vec<&str> = s.split('_').collect();
    // Not the `tag_body_checksum` shape at all — e.g. a bare hex string,
    // or one with too many separators. Deliberately do *not* echo the
    // input back: it could be a secret key, and an error `Display` should
    // never leak one.
    let [tag_str, body_hex, cs_hex] = parts.as_slice() else {
        return Err(Error::InvalidPrefix {
            expected: expected.as_str(),
            got: String::new(),
        });
    };

    if *tag_str != expected.as_str() {
        // Safe to echo: a real tag is short and never carries the body.
        return Err(Error::InvalidPrefix {
            expected: expected.as_str(),
            got: (*tag_str).to_owned(),
        });
    }

    let payload = Zeroizing::new(hex::decode(body_hex).map_err(|_| Error::InvalidHex)?);
    let provided = hex::decode(cs_hex).map_err(|_| Error::InvalidHex)?;
    if provided.len() != CHECKSUM_LEN {
        return Err(Error::InvalidChecksum);
    }
    if provided[..] != checksum(expected, &payload)[..] {
        return Err(Error::InvalidChecksum);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_tag() {
        let payload = [7u8; 32];
        for tag in [
            Tag::PublicKey,
            Tag::SecretKey,
            Tag::KeyImage,
            Tag::Signature,
        ] {
            let s = encode_prefixed(tag, &payload);
            assert!(s.starts_with(tag.as_str()));
            let back = decode_prefixed(tag, &s).unwrap();
            assert_eq!(&back[..], &payload[..]);
        }
    }

    #[test]
    fn shape_is_tag_body_checksum() {
        let s = encode_prefixed(Tag::PublicKey, &[0xab; 32]);
        let parts: Vec<&str> = s.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "pk");
        assert_eq!(parts[1].len(), 64); // 32 bytes hex
        assert_eq!(parts[2].len(), 8); // 4 bytes hex
    }

    #[test]
    fn rejects_wrong_tag() {
        // A value encoded as a public key must not decode as a key image,
        // even though both are 32-byte payloads.
        let s = encode_prefixed(Tag::PublicKey, &[1u8; 32]);
        let err = decode_prefixed(Tag::KeyImage, &s).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidPrefix {
                expected: "ki",
                got: "pk".to_owned()
            }
        );
    }

    #[test]
    fn rejects_relabelled_value() {
        // Take a valid pk string and rewrite the tag to ki_; the checksum
        // (which is bound to the tag) must now fail.
        let s = encode_prefixed(Tag::PublicKey, &[2u8; 32]);
        let relabelled = format!("ki{}", &s["pk".len()..]);
        assert_eq!(
            decode_prefixed(Tag::KeyImage, &relabelled).unwrap_err(),
            Error::InvalidChecksum
        );
    }

    #[test]
    fn rejects_corrupted_checksum() {
        let s = encode_prefixed(Tag::Signature, &[3u8; 96]);
        // Flip the last hex digit of the checksum.
        let mut bytes = s.into_bytes();
        let last = bytes.last_mut().unwrap();
        *last = if *last == b'0' { b'1' } else { b'0' };
        let corrupted = String::from_utf8(bytes).unwrap();
        assert_eq!(
            decode_prefixed(Tag::Signature, &corrupted).unwrap_err(),
            Error::InvalidChecksum
        );
    }

    #[test]
    fn rejects_corrupted_body() {
        let s = encode_prefixed(Tag::PublicKey, &[4u8; 32]);
        // Flip a digit in the body (part index 1).
        let mut parts: Vec<String> = s.split('_').map(|p| p.to_owned()).collect();
        let body = &mut parts[1];
        let first = body.remove(0);
        body.insert(0, if first == 'a' { 'b' } else { 'a' });
        let corrupted = parts.join("_");
        assert_eq!(
            decode_prefixed(Tag::PublicKey, &corrupted).unwrap_err(),
            Error::InvalidChecksum
        );
    }

    #[test]
    fn rejects_bare_hex_without_leaking_it() {
        // A bare hex string (no prefix) is rejected, and the error must
        // not contain the input — it might be a secret key.
        let secret_like = "ab".repeat(32);
        let err = decode_prefixed(Tag::SecretKey, &secret_like).unwrap_err();
        match err {
            Error::InvalidPrefix { got, .. } => assert!(got.is_empty()),
            other => panic!("expected InvalidPrefix, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_hex_parts() {
        assert_eq!(
            decode_prefixed(Tag::PublicKey, "pk_zzzz_d4e9a1b7").unwrap_err(),
            Error::InvalidHex
        );
    }
}
