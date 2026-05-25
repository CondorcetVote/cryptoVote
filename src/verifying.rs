//! Operation C — the blind validation oracle (runs on the host /
//! server).
//!
//! Given a ballot, a signature, a linking tag, and the canonical list of
//! authorised voters, this returns `true` iff:
//!
//!  - the signature verifies against the BLSAG equations, **and**
//!  - the tag inside the signature matches the tag the host received
//!    separately (so the host cannot be tricked into accepting a proof
//!    whose tag does not match what it just de-duplicated against).
//!
//! What this function deliberately does **not** check:
//!
//!  - whether the host has already seen this tag (that's the host's
//!    job; see the "contract de responsabilité anti-double vote" in the
//!    spec);
//!  - whether the election is open;
//!  - whether the voter is allowed to vote — being in the authorised
//!    ring *is* "allowed to vote", and any further policy belongs to
//!    the host.

use crate::signing::{bind_to_election, canonicalised_ring};
use crate::types::{KeyImage, PublicKey, Signature};
use blake2::Blake2b512;
use curve25519_dalek::ristretto::RistrettoPoint;
use nazgul::blsag::BLSAG;
use nazgul::traits::Verify;

/// Operation C: validate a vote proof.
///
/// # Parameters
///
/// - `vote` — the exact bytes the signer hashed in. The host must feed
///   the same byte string it received from the voter, without
///   normalisation or re-encoding.
/// - `election_id` — the same election identifier string the voter
///   used at signing time (UUID, slug, etc.). Different ID ⇒
///   signature does not validate.
/// - `signature` — the proof produced by [`crate::sign_vote`].
/// - `key_image` — the linking tag the host stored. **Must** match the
///   tag inside the signature; if it does not, the host is being lied
///   to by either the voter or the network, and we return `false`.
/// - `ring` — the canonical authorised list. Same caveat as for
///   signing: must contain at least two distinct keys, but the order
///   does not matter — we re-sort it the same way the signer did.
///
/// # Returns
///
/// `true` if every check passes, `false` otherwise. This function never
/// panics and never returns an error: any malformed input (wrong size
/// ring, empty vote / election_id, etc.) is a "not valid" answer,
/// since from the host's point of view the only useful question is
/// "should I accept this ballot?".
pub fn verify_vote(
    vote: &[u8],
    election_id: &str,
    signature: &Signature,
    key_image: &KeyImage,
    ring: &[PublicKey],
) -> bool {
    // 0. Same guardrails as signing. An empty payload could only ever
    //    come from a buggy caller, never from a legitimate voter, so
    //    refuse outright.
    if vote.is_empty() || election_id.is_empty() {
        return false;
    }
    let election_id = election_id.as_bytes();

    // 1. Sort the ring exactly like signing did. Any ring that signing
    //    would refuse (too small, duplicate keys) we refuse too.
    let sorted = match canonicalised_ring(ring) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // 2. A response per ring member. If the count is wrong the
    //    signature was generated against a different list — refuse.
    if signature.responses.len() != sorted.len() {
        return false;
    }

    // 3. Rebuild the nazgul `BLSAG` struct from our parts. The ring
    //    field on the struct is the *full* canonical list (signer
    //    included), which is exactly what we just sorted.
    let ring_points: Vec<RistrettoPoint> = sorted.iter().map(|pk| pk.point).collect();
    let blsag = BLSAG {
        challenge: signature.challenge,
        responses: signature.responses.clone(),
        ring: ring_points,
        key_image: key_image.point,
    };

    // 4. Reconstruct the same election-bound byte string the signer
    //    hashed, then hand off to nazgul. Using the same hash function
    //    and the same byte string is what closes the loop.
    let bound = bind_to_election(election_id, vote);
    BLSAG::verify::<Blake2b512>(blsag, &bound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_identity;
    use crate::signing::sign_vote;

    const EID: &str = "election-2026";

    /// Tiny helper to build an N-member ring with one designated voter.
    fn fresh_ring(n: usize) -> (crate::types::SecretKey, Vec<PublicKey>) {
        let voter = generate_identity();
        let mut ring = vec![voter.public_key];
        for _ in 1..n {
            ring.push(generate_identity().public_key);
        }
        (voter.secret_key, ring)
    }

    #[test]
    fn round_trip_succeeds() {
        let (sk, ring) = fresh_ring(5);
        let proof = sign_vote(&sk, b"option-A", EID, &ring).unwrap();
        assert!(verify_vote(
            b"option-A",
            EID,
            &proof.signature,
            &proof.key_image,
            &ring
        ));
    }

    #[test]
    fn round_trip_with_minimum_ring_size() {
        // n = 2 is the smallest ring that still hides the signer.
        let (sk, ring) = fresh_ring(2);
        let proof = sign_vote(&sk, b"yes", EID, &ring).unwrap();
        assert!(verify_vote(
            b"yes",
            EID,
            &proof.signature,
            &proof.key_image,
            &ring
        ));
    }

    #[test]
    fn ring_order_does_not_matter() {
        // Both sides sort, so the caller can pass the ring in any
        // order. Reverse it before verification and the answer is the
        // same.
        let (sk, ring) = fresh_ring(4);
        let proof = sign_vote(&sk, b"yes", EID, &ring).unwrap();
        let mut reversed = ring.clone();
        reversed.reverse();
        assert!(verify_vote(
            b"yes",
            EID,
            &proof.signature,
            &proof.key_image,
            &reversed
        ));
    }

    #[test]
    fn tampered_vote_is_rejected() {
        let (sk, ring) = fresh_ring(4);
        let proof = sign_vote(&sk, b"option-A", EID, &ring).unwrap();
        assert!(!verify_vote(
            b"option-B",
            EID,
            &proof.signature,
            &proof.key_image,
            &ring,
        ));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let (sk, ring) = fresh_ring(4);
        let mut proof = sign_vote(&sk, b"yes", EID, &ring).unwrap();
        proof.signature.responses[0] = curve25519_dalek::scalar::Scalar::ZERO;
        assert!(!verify_vote(
            b"yes",
            EID,
            &proof.signature,
            &proof.key_image,
            &ring
        ));
    }

    #[test]
    fn swapped_key_image_is_rejected() {
        let (sk_a, mut ring) = fresh_ring(3);
        let voter_b = generate_identity();
        ring.push(voter_b.public_key);

        let proof_a = sign_vote(&sk_a, b"yes", EID, &ring).unwrap();
        let proof_b = sign_vote(&voter_b.secret_key, b"yes", EID, &ring).unwrap();

        assert!(!verify_vote(
            b"yes",
            EID,
            &proof_a.signature,
            &proof_b.key_image,
            &ring
        ));
    }

    #[test]
    fn wrong_ring_is_rejected() {
        let (sk, ring) = fresh_ring(3);
        let proof = sign_vote(&sk, b"yes", EID, &ring).unwrap();
        let mut other_ring = ring.clone();
        other_ring[1] = generate_identity().public_key;
        assert!(!verify_vote(
            b"yes",
            EID,
            &proof.signature,
            &proof.key_image,
            &other_ring
        ));
    }

    #[test]
    fn wrong_election_id_is_rejected() {
        // A signature produced for election X must NOT validate when
        // verified against election Y. This is the whole point of the
        // election-binding guardrail.
        let (sk, ring) = fresh_ring(3);
        let proof = sign_vote(&sk, b"yes", "election-X", &ring).unwrap();
        assert!(!verify_vote(
            b"yes",
            "election-Y",
            &proof.signature,
            &proof.key_image,
            &ring
        ));
    }

    #[test]
    fn empty_inputs_at_verification_are_rejected() {
        let (sk, ring) = fresh_ring(3);
        let proof = sign_vote(&sk, b"yes", EID, &ring).unwrap();
        assert!(!verify_vote(b"", EID, &proof.signature, &proof.key_image, &ring));
        assert!(!verify_vote(b"yes", "", &proof.signature, &proof.key_image, &ring));
    }

    #[test]
    fn same_voter_yields_same_tag() {
        // Determinism of the linking tag is what makes double-vote
        // detection possible. Two signatures from the same voter, on
        // the same ring and election, must share a key image —
        // regardless of the ballot.
        let (sk, ring) = fresh_ring(3);
        let p1 = sign_vote(&sk, b"option-A", EID, &ring).unwrap();
        let p2 = sign_vote(&sk, b"option-B", EID, &ring).unwrap();
        assert_eq!(p1.key_image, p2.key_image);
    }

    #[test]
    fn different_voters_yield_different_tags() {
        let (sk_a, mut ring) = fresh_ring(3);
        let voter_b = generate_identity();
        ring.push(voter_b.public_key);
        let p_a = sign_vote(&sk_a, b"yes", EID, &ring).unwrap();
        let p_b = sign_vote(&voter_b.secret_key, b"yes", EID, &ring).unwrap();
        assert_ne!(p_a.key_image, p_b.key_image);
    }
}
