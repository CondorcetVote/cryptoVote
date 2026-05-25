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
        // `Scalar::from_canonical_bytes` is constant-time and returns
        // None if the value is outside [0, ℓ). That second check is
        // important: any other encoding could let two different byte
        // strings represent the same key.
        let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
            .ok_or(Error::InvalidScalar)?;
        if scalar == Scalar::ZERO {
            return Err(Error::InvalidSecretKey);
        }
        Ok(SecretKey { scalar })
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
    fn secret_key_debug_is_redacted() {
        let sk =
            SecretKey::from_hex("0100000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let debug = format!("{sk:?}");
        assert_eq!(debug, "SecretKey(..)");
        assert!(!debug.contains("1"));
    }
}
