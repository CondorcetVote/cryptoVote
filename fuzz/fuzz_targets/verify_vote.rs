//! Fuzz the public `verify_vote` pipeline end-to-end.
//!
//! Goal: starting from arbitrary attacker-chosen bytes, walk the full
//! parse + canonicalise + BLSAG-verify path and assert it never panics
//! and never wrongly returns `true`. We split the fuzz input into a
//! ring (a sequence of 32-byte chunks), a signature blob, a key image,
//! an election ID and a vote payload.

#![no_main]

use crypto_vote::{KeyImage, PublicKey, Signature, verify_vote};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Minimum useful split: ring_size byte, key image (32), election_id_len
    // byte, vote_len byte, then variable data. Bail out cheaply on
    // anything shorter — libfuzzer will reshape the corpus to satisfy
    // it.
    if data.len() < 35 {
        return;
    }
    let ring_size = (data[0] as usize) % 6; // bound to 0..=5 for speed.
    let eid_len = data[1] as usize;
    let vote_len = data[2] as usize;
    let mut cur = &data[3..];

    if cur.len() < 32 {
        return;
    }
    let ki_bytes: [u8; 32] = cur[..32].try_into().unwrap();
    cur = &cur[32..];

    let mut ring = Vec::with_capacity(ring_size);
    for _ in 0..ring_size {
        if cur.len() < 32 {
            return;
        }
        let pk_bytes: [u8; 32] = cur[..32].try_into().unwrap();
        cur = &cur[32..];
        if let Ok(pk) = PublicKey::from_bytes(&pk_bytes) {
            ring.push(pk);
        }
    }

    if cur.len() < eid_len + vote_len {
        return;
    }
    let eid_bytes = &cur[..eid_len];
    cur = &cur[eid_len..];
    let vote = &cur[..vote_len];
    cur = &cur[vote_len..];

    // Remaining bytes are the signature blob. Cap to a sane size so
    // the fuzzer does not waste cycles on multi-MB inputs.
    let sig_bytes = &cur[..cur.len().min(32 * 16)];

    let Ok(eid) = std::str::from_utf8(eid_bytes) else {
        return;
    };
    let Ok(key_image) = KeyImage::from_bytes(&ki_bytes) else {
        return;
    };
    let Ok(signature) = Signature::from_bytes(sig_bytes, ring.len()) else {
        return;
    };

    // The single invariant: any output is acceptable as long as we did
    // not panic. We additionally assert that a "passing" verification
    // must not have happened on a degenerate ring — that would be a
    // protocol bug.
    let ok = verify_vote(vote, eid, &signature, &key_image, &ring);
    if ok {
        assert!(ring.len() >= 2, "verify_vote returned true on ring < 2");
    }
});
