//! Error type returned by every fallible public function.
//!
//! Errors are intentionally coarse-grained: the host never needs to do
//! anything with them other than reject the request. We give them
//! descriptive `Display` strings so logs are useful, but there is no
//! `#[non_exhaustive]` machinery, no error codes, no nested causes — the
//! crate's job is to say "valid" or "not valid", and these variants only
//! exist to explain *why* an input could not even be parsed.

use core::fmt;

/// Anything that can go wrong when *parsing* or *processing* inputs.
///
/// Note that a signature being mathematically invalid is not an error —
/// it is a `false` return from [`crate::verify_vote`]. An `Error` is only
/// produced when the caller hands us malformed bytes (wrong length, not
/// on the curve, etc.) or asks for an operation that does not make sense
/// (e.g. signing with a key that is not in the authorised ring).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A byte slice did not have the size required for the type it was
    /// supposed to decode into.
    InvalidLength {
        /// Human-readable name of the value being decoded.
        what: &'static str,
        /// Number of bytes that were expected.
        expected: usize,
        /// Number of bytes that were actually provided.
        got: usize,
    },
    /// 32 bytes that do not represent a valid Ristretto255 point.
    InvalidPoint,
    /// 32 bytes that do not represent a canonical scalar (mod ℓ).
    InvalidScalar,
    /// The hex string handed to a `*_from_hex` constructor could not be
    /// decoded.
    InvalidHex,
    /// `sign_vote` was called with a secret key whose public key is not
    /// in the supplied authorised ring. Signing would still mathematically
    /// produce something, but it would not verify, so we refuse it early.
    SignerNotInRing,
    /// `sign_vote` or `verify_vote` was called with an authorised ring
    /// containing fewer than two members. A ring of one trivially
    /// de-anonymises the signer, so we reject it.
    RingTooSmall,
    /// `sign_vote` was given a ring containing the same public key twice.
    /// The protocol's anonymity guarantees assume distinct members, and
    /// we refuse to silently de-duplicate.
    DuplicateRingMember,
    /// `sign_vote` was called with a zero-byte ballot. The library has
    /// no opinion on the payload format, but an empty payload is almost
    /// always a caller bug (forgot to serialise the form, fed in the
    /// wrong variable, …) so we surface it instead of silently signing
    /// nothing.
    EmptyVote,
    /// `sign_vote` was called with a zero-byte election identifier.
    /// Allowing it would defeat the whole point of binding signatures
    /// to an election context, so we refuse early.
    EmptyElectionId,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidLength {
                what,
                expected,
                got,
            } => write!(
                f,
                "invalid length for {what}: expected {expected} bytes, got {got}"
            ),
            Error::InvalidPoint => f.write_str("bytes do not encode a valid Ristretto255 point"),
            Error::InvalidScalar => f.write_str("bytes do not encode a canonical scalar"),
            Error::InvalidHex => f.write_str("input is not valid hexadecimal"),
            Error::SignerNotInRing => {
                f.write_str("signer's public key is not part of the authorised ring")
            }
            Error::RingTooSmall => {
                f.write_str("authorised ring must contain at least two members")
            }
            Error::DuplicateRingMember => {
                f.write_str("authorised ring contains a duplicate public key")
            }
            Error::EmptyVote => f.write_str("ballot is empty"),
            Error::EmptyElectionId => f.write_str("election identifier is empty"),
        }
    }
}

impl std::error::Error for Error {}

/// Local `Result` alias to keep signatures readable.
pub type Result<T> = core::result::Result<T, Error>;
