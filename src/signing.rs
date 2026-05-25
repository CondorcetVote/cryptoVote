//! Operation B — produce a vote proof (intended to run client-side).
//!
//! In the requirements spec this is the WebAssembly operation: the
//! voter's browser takes the voter's secret key, the chosen ballot, and
//! the public list of authorised voters, and emits a BLSAG ring
//! signature plus its linking tag. The secret key never leaves the
//! device — the host only ever sees the proof and the tag.
//!
//! Why BLSAG (rather than SAG / MLSAG / CLSAG)?
//!
//!  - SAG is a ring signature but **not linkable**: it cannot stop
//!    double voting.
//!  - MLSAG / CLSAG are designed for multi-input transactions, which we
//!    don't have.
//!  - BLSAG is the minimal scheme that gives us exactly one linkable
//!    tag per signer, which is precisely what the spec asks for.
//!
//! ## Ring canonicalisation
//!
//! Nazgul's [`nazgul::blsag::BLSAG::sign`] takes the ring *without* the
//! signer's own public key, plus the index where it should be inserted.
//! That index is not part of the signature, so the host must agree with
//! the signer on the order of the ring or verification fails.
//!
//! We side-step the whole "did you order the ring correctly?" question
//! by sorting the authorised list lexicographically by its compressed
//! byte representation. Both sides do that independently, so neither
//! has to trust the other's ordering.

use crate::error::{Error, Result};
use crate::types::{KeyImage, PublicKey, SecretKey, Signature, VoteProof};
use blake2::Blake2b512;
use curve25519_dalek::ristretto::RistrettoPoint;
use nazgul::blsag::BLSAG;
use nazgul::traits::Sign;
use rand::rngs::OsRng;

/// Operation B: produce the signed proof for a ballot.
///
/// # Parameters
///
/// - `secret_key` — the voter's private scalar. Stays on the device.
/// - `vote` — the exact bytes of the ballot. Whatever encoding the
///   host has chosen is fine; the module treats it as an opaque byte
///   string and only cares that the verifier later hashes the same
///   bytes.
/// - `ring` — the **full** list of authorised public keys, including
///   the voter's own. The voter's key must appear in it exactly once;
///   otherwise the signature would not verify against the canonical
///   list.
///
/// # Returns
///
/// A [`VoteProof`] holding the BLSAG signature and the linking tag.
///
/// # Errors
///
/// - [`Error::RingTooSmall`] if `ring` has fewer than 2 entries.
/// - [`Error::DuplicateRingMember`] if a public key appears twice.
/// - [`Error::SignerNotInRing`] if the voter's public key is missing.
pub fn sign_vote(
    secret_key: &SecretKey,
    vote: &[u8],
    ring: &[PublicKey],
) -> Result<VoteProof> {
    // 1. Validate and canonicalise the ring.
    //
    //    Sorting by the 32-byte compressed encoding gives a total order
    //    that is trivial to compute on either side of the wire. We do
    //    the duplicate / membership / size checks against the sorted
    //    copy so the error messages match the canonical view.
    let sorted = canonicalised_ring(ring)?;

    // 2. Locate the signer's index in that canonical ring.
    let signer_pk = secret_key.public_key();
    let secret_index = sorted
        .iter()
        .position(|pk| *pk == signer_pk)
        .ok_or(Error::SignerNotInRing)?;

    // 3. Build the "decoy" ring nazgul expects: every other authorised
    //    public key, in the same canonical order. Nazgul will re-insert
    //    the signer's key at `secret_index` itself.
    let decoy_ring: Vec<RistrettoPoint> = sorted
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != secret_index)
        .map(|(_, pk)| pk.point)
        .collect();

    // 4. Hand off to nazgul. `Blake2b512` is wired in here as the
    //    `Hash` generic, so every challenge the protocol computes goes
    //    through Blake2b-512.
    let blsag = BLSAG::sign::<Blake2b512, OsRng>(
        secret_key.scalar,
        decoy_ring,
        secret_index,
        vote,
    );

    // 5. Repackage into our public types. We drop nazgul's `ring` field
    //    on purpose: the verifier reconstructs it from its own copy of
    //    the authorised list, so shipping it would be redundant — and
    //    worse, would let a malicious signer ship a ring that does not
    //    match the authorised one.
    Ok(VoteProof {
        signature: Signature {
            challenge: blsag.challenge,
            responses: blsag.responses,
        },
        key_image: KeyImage {
            point: blsag.key_image,
        },
    })
}

/// Sort the ring, check it is well-formed, and reject pathological inputs.
///
/// Pulled out as a free function because [`crate::verifying::verify_vote`]
/// needs the exact same canonicalisation.
pub(crate) fn canonicalised_ring(ring: &[PublicKey]) -> Result<Vec<PublicKey>> {
    if ring.len() < 2 {
        return Err(Error::RingTooSmall);
    }
    let mut sorted: Vec<PublicKey> = ring.to_vec();
    sorted.sort_by_key(|pk| pk.to_bytes());
    // After sorting, duplicates are adjacent, so a single pass is enough.
    for pair in sorted.windows(2) {
        if pair[0] == pair[1] {
            return Err(Error::DuplicateRingMember);
        }
    }
    Ok(sorted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_identity;

    #[test]
    fn rejects_ring_too_small() {
        let voter = generate_identity();
        let err = sign_vote(&voter.secret_key, b"yes", &[voter.public_key]).unwrap_err();
        assert_eq!(err, Error::RingTooSmall);
    }

    #[test]
    fn rejects_duplicate_ring_members() {
        let voter = generate_identity();
        let dup = voter.public_key;
        let other = generate_identity().public_key;
        let err =
            sign_vote(&voter.secret_key, b"yes", &[voter.public_key, dup, other]).unwrap_err();
        assert_eq!(err, Error::DuplicateRingMember);
    }

    #[test]
    fn rejects_signer_outside_ring() {
        let voter = generate_identity();
        let a = generate_identity().public_key;
        let b = generate_identity().public_key;
        let err = sign_vote(&voter.secret_key, b"yes", &[a, b]).unwrap_err();
        assert_eq!(err, Error::SignerNotInRing);
    }
}
