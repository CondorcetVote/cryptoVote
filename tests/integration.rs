//! Integration tests for the public API.
//!
//! These tests only use what `crypto_vote` re-exports at the crate
//! root — i.e. exactly what a third-party host application would have
//! access to. They double as living documentation of the host /
//! oracle contract.

use crypto_vote::{
    Error, KeyImage, PublicKey, Signature, generate_identity, sign_vote, verify_vote,
};

const EID: &str = "550e8400-e29b-41d4-a716-446655440000";

/// Build a ring of `n` voters and pick one of them as the actual signer.
fn fresh_election(n: usize) -> (crypto_vote::SecretKey, Vec<PublicKey>) {
    let voter = generate_identity();
    let mut ring = vec![voter.public_key];
    for _ in 1..n {
        ring.push(generate_identity().public_key);
    }
    (voter.secret_key, ring)
}

#[test]
fn full_flow_round_trip() {
    let (sk, ring) = fresh_election(5);
    let ballot = b"option-A";
    let proof = sign_vote(&sk, ballot, EID, &ring).expect("sign");
    assert!(verify_vote(
        ballot,
        EID,
        &proof.signature,
        &proof.key_image,
        &ring
    ));
}

#[test]
fn serialised_proof_round_trip() {
    // What a real host would store + send across the wire: hex strings.
    let (sk, ring) = fresh_election(4);
    let ballot = b"option-X";
    let proof = sign_vote(&sk, ballot, EID, &ring).unwrap();

    let sig_hex = proof.signature.to_hex();
    let tag_hex = proof.key_image.to_hex();

    let sig = Signature::from_hex(&sig_hex, ring.len()).unwrap();
    let tag = KeyImage::from_hex(&tag_hex).unwrap();
    assert!(verify_vote(ballot, EID, &sig, &tag, &ring));
}

#[test]
fn host_can_detect_double_vote_via_tag() {
    // Two different ballots, same voter, same election → same key
    // image. This is the "deterministic tag" property the
    // anti-double-vote contract relies on.
    let (sk, ring) = fresh_election(3);
    let p1 = sign_vote(&sk, b"option-A", EID, &ring).unwrap();
    let p2 = sign_vote(&sk, b"option-B", EID, &ring).unwrap();
    assert_eq!(p1.key_image, p2.key_image);
}

#[test]
fn key_images_are_not_linkable_across_elections() {
    // Same voter, same ballot, same ring, different election context:
    // election-scoped key images intentionally emit different public tags.
    let (sk, ring) = fresh_election(3);
    let p1 = sign_vote(&sk, b"option-A", "election-A", &ring).unwrap();
    let p2 = sign_vote(&sk, b"option-A", "election-B", &ring).unwrap();
    assert_ne!(p1.key_image, p2.key_image);
}

#[test]
fn election_binding_isolates_signatures_across_elections() {
    // A proof produced for election X must not validate when verified
    // against election Y, even when ring and secret key are identical.
    // The key image itself is election-scoped too, but this test keeps
    // exercising the signature binding layer.
    let (sk, ring) = fresh_election(4);
    let proof = sign_vote(&sk, b"option-A", "election-X", &ring).unwrap();
    assert!(!verify_vote(
        b"option-A",
        "election-Y",
        &proof.signature,
        &proof.key_image,
        &ring,
    ));
}

#[test]
fn empty_inputs_are_rejected_at_signing() {
    let (sk, ring) = fresh_election(3);
    assert_eq!(
        sign_vote(&sk, b"", EID, &ring).unwrap_err(),
        Error::EmptyVote
    );
    assert_eq!(
        sign_vote(&sk, b"yes", "", &ring).unwrap_err(),
        Error::EmptyElectionId
    );
}

#[test]
fn anonymity_is_indistinguishable_by_index() {
    // Every signer in the ring produces signatures that the verifier
    // cannot trace back to a specific position. We can't really test
    // unlinkability in unit tests, but at the very least the proof
    // shape (sizes, presence of the tag) must not encode the signer's
    // index.
    let voter_a = generate_identity();
    let voter_b = generate_identity();
    let voter_c = generate_identity();
    let ring = vec![voter_a.public_key, voter_b.public_key, voter_c.public_key];

    let p_a = sign_vote(&voter_a.secret_key, b"yes", EID, &ring).unwrap();
    let p_b = sign_vote(&voter_b.secret_key, b"yes", EID, &ring).unwrap();
    let p_c = sign_vote(&voter_c.secret_key, b"yes", EID, &ring).unwrap();

    assert_eq!(
        p_a.signature.to_bytes().len(),
        p_b.signature.to_bytes().len()
    );
    assert_eq!(
        p_b.signature.to_bytes().len(),
        p_c.signature.to_bytes().len()
    );
}

#[test]
fn signature_byte_length_matches_ring_size() {
    // Documents the wire format: challenge + n responses, each 32 bytes.
    let (sk, ring) = fresh_election(7);
    let proof = sign_vote(&sk, b"yes", EID, &ring).unwrap();
    assert_eq!(proof.signature.to_bytes().len(), 32 * (1 + ring.len()));
}

#[test]
fn parsing_signature_with_wrong_ring_size_fails() {
    let (sk, ring) = fresh_election(3);
    let proof = sign_vote(&sk, b"yes", EID, &ring).unwrap();
    // We tell the parser the ring has 4 entries when it really has 3.
    let err = Signature::from_hex(&proof.signature.to_hex(), 4).unwrap_err();
    assert!(matches!(err, Error::InvalidLength { .. }));
}

#[test]
fn invalid_hex_inputs_are_rejected_cleanly() {
    assert!(matches!(
        PublicKey::from_hex("not-a-hex-string").unwrap_err(),
        Error::InvalidHex
    ));
    assert!(matches!(
        KeyImage::from_hex("deadbeef").unwrap_err(),
        Error::InvalidLength { .. }
    ));
}

/// Flipping a single bit *anywhere* in the signature must invalidate it.
///
/// This is the strongest cheap malleability assertion we can make
/// without a formal model: the BLSAG construction is a hash chain over
/// every response, so changing any byte must propagate. If a region of
/// the signature were silently ignored at verification, an attacker
/// could re-broadcast a "different" proof with the same effect — this
/// test would catch that regression.
#[test]
fn signature_is_bit_malleability_resistant() {
    let (sk, ring) = fresh_election(3);
    let proof = sign_vote(&sk, b"option-A", EID, &ring).unwrap();

    let original = proof.signature.to_bytes();
    for byte_index in 0..original.len() {
        for bit in 0..8u8 {
            let mut tampered = original.clone();
            tampered[byte_index] ^= 1 << bit;

            // Parsing may already reject (the tampered byte falls in a
            // scalar that no longer reduces canonically). Either outcome
            // is fine — what we forbid is "parses *and* verifies".
            if let Ok(sig) = Signature::from_bytes(&tampered, ring.len()) {
                assert!(
                    !verify_vote(b"option-A", EID, &sig, &proof.key_image, &ring),
                    "tampered signature accepted at byte {byte_index} bit {bit}"
                );
            }
        }
    }
}

/// Flipping a single bit in the key image must invalidate the proof.
///
/// `KeyImage::from_bytes` either rejects (not on the curve, or the
/// identity) or yields a different valid Ristretto point; the latter
/// must fail BLSAG verification, otherwise an attacker could substitute
/// a different linking tag for the same ballot and slip past the host's
/// de-duplication check.
#[test]
fn key_image_is_bit_malleability_resistant() {
    let (sk, ring) = fresh_election(3);
    let proof = sign_vote(&sk, b"option-A", EID, &ring).unwrap();

    let original = proof.key_image.to_bytes();
    for byte_index in 0..original.len() {
        for bit in 0..8u8 {
            let mut tampered = original;
            tampered[byte_index] ^= 1 << bit;

            if let Ok(ki) = KeyImage::from_bytes(&tampered) {
                assert!(
                    !verify_vote(b"option-A", EID, &proof.signature, &ki, &ring),
                    "tampered key image accepted at byte {byte_index} bit {bit}"
                );
            }
        }
    }
}

/// A random Ristretto point passed as a key image must not validate.
///
/// `KeyImage::from_bytes` only checks subgroup membership and rejects
/// the identity — by design, it cannot tell a "real" linking tag from
/// an arbitrary curve point. Unforgeability of the BLSAG proof is what
/// closes that gap. This test makes the property explicit.
#[test]
fn random_key_image_is_rejected_by_verifier() {
    use curve25519_dalek::ristretto::RistrettoPoint;
    use rand::rngs::SysRng;
    use rand_core::UnwrapErr;

    let (sk, ring) = fresh_election(3);
    let proof = sign_vote(&sk, b"option-A", EID, &ring).unwrap();

    // Build a key image that decodes cleanly but is unrelated to any
    // ring member's secret. Loop on the off-chance the random point is
    // the identity (statistically impossible, but the type system does
    // not know that).
    let mut rng = UnwrapErr(SysRng);
    let bytes = loop {
        let p = RistrettoPoint::random(&mut rng);
        let compressed = p.compress().to_bytes();
        if KeyImage::from_bytes(&compressed).is_ok() {
            break compressed;
        }
    };
    let bogus = KeyImage::from_bytes(&bytes).unwrap();

    assert!(!verify_vote(
        b"option-A",
        EID,
        &proof.signature,
        &bogus,
        &ring
    ));
}

/// Subset / superset rings must be rejected.
///
/// Removing or adding a ring member changes the canonical hash chain,
/// so a signature produced under one ring cannot validate under another.
/// This is the property that lets the host pin the authorised list and
/// detect any drift between signing-time and verification-time rings.
#[test]
fn signature_does_not_verify_against_subset_or_superset_ring() {
    let (sk, mut ring) = fresh_election(4);
    let proof = sign_vote(&sk, b"yes", EID, &ring).unwrap();

    let mut subset = ring.clone();
    subset.pop();
    // The signature was generated for a ring of size 4; the parser of
    // the wire format would already reject it against a ring of size 3,
    // but the in-memory `verify_vote` path simply returns false because
    // `responses.len() != sorted.len()`.
    assert!(!verify_vote(
        b"yes",
        EID,
        &proof.signature,
        &proof.key_image,
        &subset
    ));

    ring.push(generate_identity().public_key);
    assert!(!verify_vote(
        b"yes",
        EID,
        &proof.signature,
        &proof.key_image,
        &ring
    ));
}

/// A ring populated by anyone other than the genuine signer must reject
/// a forged "signature" — i.e. you cannot impersonate a voter by being
/// in the ring and using *your own* secret while passing *their* key
/// image.
#[test]
fn cannot_impersonate_by_swapping_in_someone_elses_key_image() {
    let (sk_alice, mut ring) = fresh_election(3);
    let bob = generate_identity();
    ring.push(bob.public_key);

    let bob_proof = sign_vote(&bob.secret_key, b"yes", EID, &ring).unwrap();
    let alice_proof = sign_vote(&sk_alice, b"yes", EID, &ring).unwrap();

    // Alice's signature paired with Bob's key image: rejected.
    assert!(!verify_vote(
        b"yes",
        EID,
        &alice_proof.signature,
        &bob_proof.key_image,
        &ring
    ));
    // And the reverse: Bob's signature paired with Alice's key image.
    assert!(!verify_vote(
        b"yes",
        EID,
        &bob_proof.signature,
        &alice_proof.key_image,
        &ring
    ));
}

/// Truncated or oversized signature byte payloads must fail to parse.
#[test]
fn signature_parser_rejects_truncated_and_oversized_payloads() {
    let (sk, ring) = fresh_election(3);
    let proof = sign_vote(&sk, b"yes", EID, &ring).unwrap();
    let bytes = proof.signature.to_bytes();

    // One byte short.
    assert!(Signature::from_bytes(&bytes[..bytes.len() - 1], ring.len()).is_err());
    // One byte too long.
    let mut padded = bytes.clone();
    padded.push(0);
    assert!(Signature::from_bytes(&padded, ring.len()).is_err());
    // Empty.
    assert!(Signature::from_bytes(&[], ring.len()).is_err());
}
