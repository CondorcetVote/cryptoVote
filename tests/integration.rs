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
fn election_binding_isolates_signatures_across_elections() {
    // A proof produced for election X must not validate when verified
    // against election Y, even when ring and secret key are identical.
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
