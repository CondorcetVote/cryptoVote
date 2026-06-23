//! Public data types exchanged across the API boundary.
//!
//! All four types in this module are thin wrappers around their
//! underlying curve / scalar representation. They exist so that:
//!
//!  - the public API never leaks `curve25519_dalek` types directly,
//!    which would force every caller to take a dependency on the same
//!    version of that crate;
//!  - every value has exactly one canonical byte and hex encoding;
//!  - the type system stops you from accidentally passing, say, a
//!    [`KeyImage`] where a [`PublicKey`] is expected — they are both
//!    32-byte Ristretto points, but they mean different things in the
//!    protocol.
//!
//! Everything serialises to a fixed-size byte array (or a `Vec<u8>` for
//! signatures whose size depends on the ring). The encoding is the
//! curve25519-dalek canonical encoding for points (compressed Ristretto)
//! and the little-endian canonical encoding for scalars.

use crate::encoding::{self, Tag};
use crate::error::{Error, Result};
use core::fmt;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use zeroize::Zeroize;

/// A voter's public identity. Safe to publish.
///
/// Internally a Ristretto255 point; externally 32 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub(crate) point: RistrettoPoint,
}

// `RistrettoPoint` does not implement `Hash`, but the compressed
// 32-byte encoding is canonical, so hashing through it is sound and
// agrees with `PartialEq`.
impl core::hash::Hash for PublicKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

impl PublicKey {
    /// Encode the key as 32 canonical bytes (compressed Ristretto).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }

    /// Decode 32 bytes produced by [`PublicKey::to_bytes`].
    ///
    /// Returns [`Error::InvalidPoint`] if the bytes are not the canonical
    /// encoding of a point in the Ristretto255 group.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let compressed = CompressedRistretto::from_slice(bytes).map_err(|_| Error::InvalidPoint)?;
        let point = compressed.decompress().ok_or(Error::InvalidPoint)?;
        if point.is_identity() {
            return Err(Error::InvalidIdentityPoint);
        }
        Ok(PublicKey { point })
    }

    /// Hex-encode using lowercase digits (64 characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode from a 64-character hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|_| Error::InvalidHex)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidLength {
                what: "PublicKey",
                expected: 32,
                got: bytes.len(),
            })?;
        Self::from_bytes(&arr)
    }

    /// Encode in the human-friendly prefixed format: `pk_<hex>_<checksum>`.
    ///
    /// Same bytes as [`PublicKey::to_hex`], wrapped with a `pk_` tag and a
    /// checksum. See [`crate::encoding`].
    pub fn to_prefixed(&self) -> String {
        encoding::encode_prefixed(Tag::PublicKey, &self.to_bytes())
    }

    /// Decode a `pk_<hex>_<checksum>` string produced by
    /// [`PublicKey::to_prefixed`], verifying the tag and the checksum.
    pub fn from_prefixed(s: &str) -> Result<Self> {
        let bytes = encoding::decode_prefixed(Tag::PublicKey, s)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidLength {
                what: "PublicKey",
                expected: 32,
                got: bytes.len(),
            })?;
        Self::from_bytes(&arr)
    }
}

/// A voter's secret key.
///
/// Internally a Ristretto255 scalar; externally 32 bytes. Treat the
/// encoded form with the same care as any other private key — it should
/// never be transmitted off the voter's device.
///
/// `SecretKey` is intentionally **not** `Clone`. Every copy of a secret
/// scalar is one more memory region to keep track of and zeroise; if a
/// caller really needs to duplicate one, they should re-decode it from
/// the same byte representation and accept the duplication explicitly.
pub struct SecretKey {
    pub(crate) scalar: Scalar,
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}

impl SecretKey {
    /// Derive the matching [`PublicKey`].
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            point: self.scalar * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT,
        }
    }

    /// Encode the scalar as 32 little-endian bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }

    /// Decode 32 bytes produced by [`SecretKey::to_bytes`].
    ///
    /// Returns [`Error::InvalidScalar`] if the bytes are not a canonical
    /// reduction modulo the group order.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        Ok(SecretKey {
            scalar: parse_secret_scalar(bytes)?,
        })
    }

    /// Hex-encode using lowercase digits (64 characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode from a 64-character hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|_| Error::InvalidHex)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidLength {
                what: "SecretKey",
                expected: 32,
                got: bytes.len(),
            })?;
        Self::from_bytes(&arr)
    }

    /// Check whether 32 raw bytes encode a usable secret key, without
    /// constructing one.
    ///
    /// Applies the same checks as [`SecretKey::from_bytes`]: the bytes
    /// must be the canonical encoding of a scalar in `[0, ℓ)` and must
    /// not be the zero scalar.
    pub fn is_valid_bytes(bytes: &[u8; 32]) -> bool {
        parse_secret_scalar(bytes).is_ok()
    }

    /// Check whether a hex string encodes a usable secret key, without
    /// constructing one.
    ///
    /// Applies the same checks as [`SecretKey::from_hex`]: valid hex,
    /// exactly 32 decoded bytes, canonical non-zero scalar.
    pub fn is_valid_hex(s: &str) -> bool {
        let Ok(bytes) = hex::decode(s) else {
            return false;
        };
        let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) else {
            return false;
        };
        Self::is_valid_bytes(&arr)
    }

    /// Encode in the human-friendly prefixed format: `sk_<hex>_<checksum>`.
    ///
    /// Same care applies as to [`SecretKey::to_hex`]: this is the full
    /// secret and must never leave the voter's device.
    pub fn to_prefixed(&self) -> String {
        encoding::encode_prefixed(Tag::SecretKey, &self.to_bytes())
    }

    /// Decode an `sk_<hex>_<checksum>` string produced by
    /// [`SecretKey::to_prefixed`], verifying the tag and the checksum.
    pub fn from_prefixed(s: &str) -> Result<Self> {
        let bytes = encoding::decode_prefixed(Tag::SecretKey, s)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidLength {
                what: "SecretKey",
                expected: 32,
                got: bytes.len(),
            })?;
        Self::from_bytes(&arr)
    }

    /// Check whether a prefixed string encodes a usable secret key,
    /// without constructing one. Counterpart of [`SecretKey::is_valid_hex`]
    /// for the `sk_<hex>_<checksum>` format: the tag and checksum must be
    /// valid *and* the body must be a canonical non-zero scalar.
    pub fn is_valid_prefixed(s: &str) -> bool {
        let Ok(bytes) = encoding::decode_prefixed(Tag::SecretKey, s) else {
            return false;
        };
        let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) else {
            return false;
        };
        Self::is_valid_bytes(&arr)
    }
}

/// Validate-and-parse a 32-byte secret scalar.
///
/// Single source of truth for the secret-key validation rules:
/// `Scalar::from_canonical_bytes` is constant-time and returns `None`
/// outside `[0, ℓ)` (that second check matters — any other encoding
/// could let two different byte strings represent the same key), and
/// the zero scalar is rejected because its public key is the identity
/// point.
fn parse_secret_scalar(bytes: &[u8; 32]) -> Result<Scalar> {
    let scalar =
        Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes)).ok_or(Error::InvalidScalar)?;
    if scalar == Scalar::ZERO {
        return Err(Error::InvalidSecretKey);
    }
    Ok(scalar)
}

/// The protocol's "linking tag" — what the host stores to prevent double
/// voting.
///
/// Mathematically: `I_e = x · H_p(domain || election_id || x · G)`,
/// where `x` is the secret key, `G` is the Ristretto255 base point and
/// `H_p` is the Ristretto hash-to-group construction. Three properties
/// matter:
///
///  - it is **deterministic** for a given secret key and election, so
///    casting the same ballot twice in that election yields the same tag;
///  - it is **election-scoped**: reusing the same key in a different
///    election yields a different public tag;
///  - it is **anonymous**: nothing about it leaks which member of the
///    ring produced it;
///  - it is **unforgeable**: the BLSAG proof is only valid if the tag
///    was actually computed from a secret key that matches one of the
///    public keys in the ring.
///
/// Encoded as 32 canonical bytes, identical in shape to a public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyImage {
    pub(crate) point: RistrettoPoint,
}

// Same reasoning as for `PublicKey`: hash through the canonical bytes.
impl core::hash::Hash for KeyImage {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

impl KeyImage {
    /// Encode the tag as 32 canonical bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }

    /// Decode 32 bytes produced by [`KeyImage::to_bytes`].
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let compressed = CompressedRistretto::from_slice(bytes).map_err(|_| Error::InvalidPoint)?;
        let point = compressed.decompress().ok_or(Error::InvalidPoint)?;
        if point.is_identity() {
            return Err(Error::InvalidIdentityPoint);
        }
        Ok(KeyImage { point })
    }

    /// Hex-encode using lowercase digits (64 characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode from a 64-character hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|_| Error::InvalidHex)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidLength {
                what: "KeyImage",
                expected: 32,
                got: bytes.len(),
            })?;
        Self::from_bytes(&arr)
    }

    /// Encode in the human-friendly prefixed format: `ki_<hex>_<checksum>`.
    pub fn to_prefixed(&self) -> String {
        encoding::encode_prefixed(Tag::KeyImage, &self.to_bytes())
    }

    /// Decode a `ki_<hex>_<checksum>` string produced by
    /// [`KeyImage::to_prefixed`], verifying the tag and the checksum.
    pub fn from_prefixed(s: &str) -> Result<Self> {
        let bytes = encoding::decode_prefixed(Tag::KeyImage, s)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidLength {
                what: "KeyImage",
                expected: 32,
                got: bytes.len(),
            })?;
        Self::from_bytes(&arr)
    }
}

/// A ring signature produced by [`crate::sign_vote`].
///
/// The on-the-wire encoding is:
///
/// ```text
///   challenge        : 32 bytes  (canonical Scalar little-endian)
///   responses[0]     : 32 bytes
///   responses[1]     : 32 bytes
///   ...
///   responses[n-1]   : 32 bytes
/// ```
///
/// where `n` is the size of the authorised ring. The ring members
/// themselves are **not** stored inside the signature: the verifier is
/// expected to already know the canonical authorised list, and to
/// reconstruct the ring from it in the same deterministic order used at
/// signing time. That way the signer cannot ship a hand-picked ring of
/// their own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub(crate) challenge: Scalar,
    pub(crate) responses: Vec<Scalar>,
}

impl Signature {
    /// Serialise to the byte layout described in the struct docs.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * (1 + self.responses.len()));
        out.extend_from_slice(&self.challenge.to_bytes());
        for r in &self.responses {
            out.extend_from_slice(&r.to_bytes());
        }
        out
    }

    /// Deserialise from the byte layout described in the struct docs.
    ///
    /// `ring_size` must be the size of the authorised list the verifier
    /// is about to check against. We require it explicitly because the
    /// signature on its own cannot tell `n` scalars from `n+1`.
    pub fn from_bytes(bytes: &[u8], ring_size: usize) -> Result<Self> {
        let expected = 32 * (1 + ring_size);
        if bytes.len() != expected {
            return Err(Error::InvalidLength {
                what: "Signature",
                expected,
                got: bytes.len(),
            });
        }
        let mut chunks = bytes.chunks_exact(32);
        let challenge = scalar_from_chunk(chunks.next().expect("challenge present"))?;
        let mut responses = Vec::with_capacity(ring_size);
        for _ in 0..ring_size {
            responses.push(scalar_from_chunk(chunks.next().expect("response present"))?);
        }
        Ok(Signature {
            challenge,
            responses,
        })
    }

    /// Hex-encode using lowercase digits.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode from a hex string. See [`Signature::from_bytes`] for the
    /// meaning of `ring_size`.
    pub fn from_hex(s: &str, ring_size: usize) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|_| Error::InvalidHex)?;
        Self::from_bytes(&bytes, ring_size)
    }

    /// Encode in the human-friendly prefixed format:
    /// `blsag_<hex>_<checksum>`. The body length grows with the ring, but
    /// the format is otherwise identical to the fixed-size types.
    pub fn to_prefixed(&self) -> String {
        encoding::encode_prefixed(Tag::Signature, &self.to_bytes())
    }

    /// Decode a `blsag_<hex>_<checksum>` string produced by
    /// [`Signature::to_prefixed`], verifying the tag and the checksum. See
    /// [`Signature::from_bytes`] for the meaning of `ring_size`.
    pub fn from_prefixed(s: &str, ring_size: usize) -> Result<Self> {
        let bytes = encoding::decode_prefixed(Tag::Signature, s)?;
        Self::from_bytes(&bytes, ring_size)
    }
}

/// Common helper for decoding a single 32-byte scalar.
fn scalar_from_chunk(chunk: &[u8]) -> Result<Scalar> {
    let arr: [u8; 32] = chunk.try_into().map_err(|_| Error::InvalidLength {
        what: "Scalar",
        expected: 32,
        got: chunk.len(),
    })?;
    Option::<Scalar>::from(Scalar::from_canonical_bytes(arr)).ok_or(Error::InvalidScalar)
}

/// The full bundle returned by [`crate::sign_vote`]: the proof and the
/// linking tag.
///
/// The two fields travel together because the host needs the tag to do
/// its "have I already seen this voter?" check before bothering the
/// verifier with the proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoteProof {
    /// The ring signature proper.
    pub signature: Signature,
    /// The unique-per-secret-key linking tag.
    pub key_image: KeyImage,
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTITY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn rejects_zero_secret_key() {
        let zero = [0u8; 32];
        assert_eq!(
            SecretKey::from_bytes(&zero).unwrap_err(),
            Error::InvalidSecretKey
        );
        assert_eq!(
            SecretKey::from_hex(IDENTITY_HEX).unwrap_err(),
            Error::InvalidSecretKey
        );
    }

    #[test]
    fn rejects_identity_points_at_api_boundary() {
        assert_eq!(
            PublicKey::from_hex(IDENTITY_HEX).unwrap_err(),
            Error::InvalidIdentityPoint
        );
        assert_eq!(
            KeyImage::from_hex(IDENTITY_HEX).unwrap_err(),
            Error::InvalidIdentityPoint
        );
    }

    #[test]
    fn is_valid_secret_key_matches_from_bytes() {
        // Valid: any non-zero canonical scalar.
        let mut valid = [0u8; 32];
        valid[0] = 1;
        assert!(SecretKey::is_valid_bytes(&valid));
        assert!(SecretKey::is_valid_hex(&hex::encode(valid)));

        // Zero scalar — rejected.
        let zero = [0u8; 32];
        assert!(!SecretKey::is_valid_bytes(&zero));
        assert!(!SecretKey::is_valid_hex(IDENTITY_HEX));

        // Non-canonical: all-0xff is well above ℓ.
        let non_canonical = [0xffu8; 32];
        assert!(!SecretKey::is_valid_bytes(&non_canonical));
        assert!(!SecretKey::is_valid_hex(&hex::encode(non_canonical)));

        // Bad hex / wrong length / non-hex chars — rejected.
        assert!(!SecretKey::is_valid_hex("not hex at all!!"));
        assert!(!SecretKey::is_valid_hex("aa")); // too short
        assert!(!SecretKey::is_valid_hex(&"aa".repeat(33))); // too long
    }

    #[test]
    fn is_valid_agrees_with_from_bytes_on_generated_keys() {
        // A freshly generated identity must always pass validation, and
        // a corrupted copy must always fail one of the checks.
        let id = crate::identity::generate_identity();
        let bytes = id.secret_key.to_bytes();
        assert!(SecretKey::is_valid_bytes(&bytes));
        assert!(SecretKey::is_valid_hex(&hex::encode(bytes)));
    }

    #[test]
    fn secret_key_debug_is_redacted() {
        let sk =
            SecretKey::from_hex("0100000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let debug = format!("{sk:?}");
        assert_eq!(debug, "SecretKey(..)");
        assert!(!debug.contains("1"));
    }
}
