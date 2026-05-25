//! Differential / round-trip fuzz: anything the library signs must
//! verify back, regardless of how weird the inputs are.
//!
//! The fuzz input drives the *non-cryptographic* parameters — ring
//! size, election ID bytes, vote bytes. The signer's secret is freshly
//! sampled inside the harness so the test exercises the real signing
//! path (not an attacker-controlled scalar).

#![no_main]

use crypto_vote::{generate_identity, sign_vote, verify_vote};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    // Bound ring size to 2..=8 so the fuzzer makes progress instead of
    // spending all its time inside curve25519-dalek.
    let ring_size = 2 + (data[0] as usize) % 7;
    let eid_len = 1 + (data[1] as usize) % 64;
    let vote_len = 1 + (data[2] as usize) % 256;
    let body = &data[3..];

    if body.len() < eid_len + vote_len {
        return;
    }
    let eid_bytes = &body[..eid_len];
    let vote = &body[eid_len..eid_len + vote_len];

    let Ok(eid) = std::str::from_utf8(eid_bytes) else {
        return;
    };

    let voter = generate_identity();
    let mut ring = vec![voter.public_key];
    for _ in 1..ring_size {
        ring.push(generate_identity().public_key);
    }

    let proof = match sign_vote(&voter.secret_key, vote, eid, &ring) {
        Ok(p) => p,
        Err(_) => return,
    };
    assert!(
        verify_vote(vote, eid, &proof.signature, &proof.key_image, &ring),
        "round-trip failed: signed proof did not verify"
    );
});
