//! Criterion benchmarks for the three core operations of the crate, at
//! the scale the requirements spec calls out: a ring of 1000 voters.
//!
//! Run with:
//!
//! ```text
//! cargo bench
//! ```
//!
//! Or target a single benchmark:
//!
//! ```text
//! cargo bench -- generate_identity_1000
//! cargo bench -- sign_vote_ring_1000
//! cargo bench -- verify_vote_ring_1000
//! ```
//!
//! Criterion writes per-run statistics under `target/criterion/`, so
//! successive runs can be compared without keeping the previous numbers
//! around manually.

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};

use crypto_vote::{PublicKey, SecretKey, generate_identity, sign_vote, verify_vote};

const RING_SIZE: usize = 1000;
const ELECTION_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const BALLOT: &[u8] = b"option-A";

/// Build a deterministic-shape election: `RING_SIZE` independent
/// identities, with the first one returned separately as the signer.
/// The identities themselves are still sampled from `SysRng`; only the
/// *structure* (who signs, ring size) is fixed.
fn fresh_election() -> (SecretKey, Vec<PublicKey>) {
    let signer = generate_identity();
    let mut ring = Vec::with_capacity(RING_SIZE);
    ring.push(signer.public_key);
    for _ in 1..RING_SIZE {
        ring.push(generate_identity().public_key);
    }
    (signer.secret_key, ring)
}

fn bench_generate_identity_1000(c: &mut Criterion) {
    c.bench_function("generate_identity_1000", |b| {
        b.iter(|| {
            let mut ids = Vec::with_capacity(RING_SIZE);
            for _ in 0..RING_SIZE {
                ids.push(generate_identity());
            }
            ids
        });
    });
}

fn bench_sign_vote_ring_1000(c: &mut Criterion) {
    let (sk, ring) = fresh_election();
    c.bench_function("sign_vote_ring_1000", |b| {
        b.iter(|| sign_vote(&sk, BALLOT, ELECTION_ID, &ring).expect("sign"));
    });
}

fn bench_verify_vote_ring_1000(c: &mut Criterion) {
    let (sk, ring) = fresh_election();
    let proof = sign_vote(&sk, BALLOT, ELECTION_ID, &ring).expect("sign");
    c.bench_function("verify_vote_ring_1000", |b| {
        b.iter(|| {
            assert!(verify_vote(
                BALLOT,
                ELECTION_ID,
                &proof.signature,
                &proof.key_image,
                &ring,
            ));
        });
    });
}

// Generation of 1000 identities is heavy per-iteration, so we give
// Criterion a larger measurement budget than the default 5 s — otherwise
// it warns about not reaching its target sample count.
criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(20))
        .sample_size(20);
    targets =
        bench_generate_identity_1000,
        bench_sign_vote_ring_1000,
        bench_verify_vote_ring_1000,
}
criterion_main!(benches);
