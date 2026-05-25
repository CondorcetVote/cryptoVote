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
//!
//! ## Election binding
//!
//! Every signature is bound to an `election_id` byte string. The bytes
//! that actually go through Blake2b are
//!
//! ```text
//!   len(election_id) (8 bytes, big-endian)
//!   election_id
//!   vote
//! ```
//!
//! The fixed-width length prefix is what makes the construction
//! unambiguous — without it, `(eid="AB", vote="C")` and
//! `(eid="A", vote="BC")` would hash identically. With it, a signature
//! produced for one election never validates for another, which gives
//! the host a second line of defence on top of "store key images
//! scoped per election" (see the README's anti-double-vote contract).

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
///   bytes. Must be non-empty.
/// - `election_id` — string identifying this election (a UUID, a slug,
///   anything stable). Mixed into the hash chain so signatures from
///   one election never validate for another. Must be non-empty.
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
/// - [`Error::EmptyVote`] if `vote` is empty.
/// - [`Error::EmptyElectionId`] if `election_id` is empty.
/// - [`Error::RingTooSmall`] if `ring` has fewer than 2 entries.
/// - [`Error::DuplicateRingMember`] if a public key appears twice.
/// - [`Error::SignerNotInRing`] if the voter's public key is missing.
pub fn sign_vote(
    secret_key: &SecretKey,
    vote: &[u8],
    election_id: &str,
    ring: &[PublicKey],
) -> Result<VoteProof> {
    // 0. Cheap guardrails. These are not crypto, just sanity checks
    //    that turn a silent footgun into a loud error.
    if vote.is_empty() {
        return Err(Error::EmptyVote);
    }
    if election_id.is_empty() {
        return Err(Error::EmptyElectionId);
    }
    // Strings are bytes from here on. We commit to UTF-8 at the API
    // boundary; whatever the caller passed verbatim is what gets
    // hashed.
    let election_id = election_id.as_bytes();

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

    // 4. Bind the message to the election context before handing it
    //    to nazgul. See the module-level docs for the wire format.
    let bound = bind_to_election(election_id, vote);

    // 5. Hand off to nazgul. `Blake2b512` is wired in here as the
    //    `Hash` generic, so every challenge the protocol computes goes
    //    through Blake2b-512.
    let blsag =
        BLSAG::sign::<Blake2b512, OsRng>(secret_key.scalar, decoy_ring, secret_index, &bound);

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

/// Build the actual byte string that gets hashed.
///
/// Layout: `u64 big-endian length prefix || election_id || vote`. The
/// length prefix is the only thing standing between us and an
/// ambiguity attack where two different `(election_id, vote)` pairs
/// concatenate to the same bytes. 8 bytes is overkill for any realistic
/// election ID but it costs nothing and removes the question from the
/// caller's mind.
///
/// `verify_vote` calls the same function so the two sides cannot drift.
pub(crate) fn bind_to_election(election_id: &[u8], vote: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + election_id.len() + vote.len());
    out.extend_from_slice(&(election_id.len() as u64).to_be_bytes());
    out.extend_from_slice(election_id);
    out.extend_from_slice(vote);
    out
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

    const EID: &str = "election-2026";

    #[test]
    fn rejects_ring_too_small() {
        let voter = generate_identity();
        let err = sign_vote(&voter.secret_key, b"yes", EID, &[voter.public_key]).unwrap_err();
        assert_eq!(err, Error::RingTooSmall);
    }

    #[test]
    fn rejects_duplicate_ring_members() {
        let voter = generate_identity();
        let dup = voter.public_key;
        let other = generate_identity().public_key;
        let err = sign_vote(
            &voter.secret_key,
            b"yes",
            EID,
            &[voter.public_key, dup, other],
        )
        .unwrap_err();
        assert_eq!(err, Error::DuplicateRingMember);
    }

    #[test]
    fn rejects_signer_outside_ring() {
        let voter = generate_identity();
        let a = generate_identity().public_key;
        let b = generate_identity().public_key;
        let err = sign_vote(&voter.secret_key, b"yes", EID, &[a, b]).unwrap_err();
        assert_eq!(err, Error::SignerNotInRing);
    }

    #[test]
    fn rejects_empty_vote() {
        let voter = generate_identity();
        let other = generate_identity().public_key;
        let err = sign_vote(&voter.secret_key, b"", EID, &[voter.public_key, other]).unwrap_err();
        assert_eq!(err, Error::EmptyVote);
    }

    #[test]
    fn rejects_empty_election_id() {
        let voter = generate_identity();
        let other = generate_identity().public_key;
        let err = sign_vote(&voter.secret_key, b"yes", "", &[voter.public_key, other]).unwrap_err();
        assert_eq!(err, Error::EmptyElectionId);
    }

    #[test]
    fn binding_is_unambiguous_between_eid_and_vote() {
        // ("AB", "C") and ("A", "BC") would collide without a length
        // prefix. Check the actual bytes differ.
        let a = bind_to_election(b"AB", b"C");
        let b = bind_to_election(b"A", b"BC");
        assert_ne!(a, b);
    }
}
