//! Frozen test vectors — tripwires for accidental protocol changes.
//!
//! The signature itself is *not* deterministic (nazgul samples fresh
//! randomness for the signer's alpha and for every decoy response), so we
//! cannot assert byte-for-byte equality of `sign_vote`'s output. Two
//! things, however, are stable across runs and can be frozen:
//!
//! 1. **The key image** is `I = x · H_p(x · G)`. It depends only on the
//!    secret key, the curve, and the hash-to-point. Any upgrade that
//!    changes one of those — switching the hash, the curve, or the
//!    encoding of `x · G` before hashing — will break this assertion.
//!
//! 2. **A previously produced signature must still verify.** Verification
//!    is deterministic, so a frozen `(ring, signature, key_image, vote,
//!    eid)` tuple gives us coverage on `bind_to_election`, the canonical
//!    ring ordering, the BLSAG challenge derivation and the Blake2b-512
//!    instance. Any of those changing makes the assertion fail.
//!
//! Vectors were generated once from fixed secret keys (`seed = 1, 2, 3`)
//! and pasted here verbatim. If a legitimate protocol change requires
//! regenerating them, regenerate **and** bump the spec version — silent
//! regeneration is exactly the bug this file is meant to catch.

use crypto_vote::{KeyImage, PublicKey, SecretKey, Signature, sign_vote, verify_vote};

const SIGNER_SK_HEX: &str =
    "0100000000000000000000000000000000000000000000000000000000000000";
const RING_HEX: [&str; 3] = [
    "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
    "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
    "94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
];
const KEY_IMAGE_HEX: &str =
    "c6d77f893b5a01a5e995be5a568e55bb22f3931ee686f24e5d211bee967ec66d";
const SIGNATURE_HEX: &str = "f74eff0c1be85da6ce4b68d1b4f5c1fb0b1ab976a861e93c7ab799ba51030f02ef0090fd02e244dd56d2b80248577a35315cb51dcada20f66b5a14747e27030f42bd8fdeec4cef9c916aeeab40222697ebb18b48e193bd7b304963de91f493096139b44bd6e7bb65363c32c79371e04dc7c9d1c350210f337ade9eab895aa80a";
const VOTE: &[u8] = b"option-A";
const ELECTION_ID: &str = "upgrade-vector-1";

fn frozen_ring() -> Vec<PublicKey> {
    RING_HEX
        .iter()
        .map(|h| PublicKey::from_hex(h).expect("frozen ring entry decodes"))
        .collect()
}

#[test]
fn key_image_is_deterministic_for_a_fixed_secret_key() {
    // The linking tag is a pure function of the secret key (and the
    // curve / hash-to-point). Re-signing with the same key — even with
    // a different ballot — must yield exactly the same tag bytes as
    // the day the vector was minted.
    let sk = SecretKey::from_hex(SIGNER_SK_HEX).unwrap();
    let ring = frozen_ring();

    let proof = sign_vote(&sk, VOTE, ELECTION_ID, &ring).unwrap();
    assert_eq!(
        proof.key_image.to_hex(),
        KEY_IMAGE_HEX,
        "key image drifted — hash-to-point, curve encoding, or secret-scalar handling changed"
    );

    // Same key, different ballot: tag must still match. This guards
    // against any future change that accidentally folds ballot or
    // election bytes into the tag derivation.
    let proof2 = sign_vote(&sk, b"option-B", ELECTION_ID, &ring).unwrap();
    assert_eq!(proof2.key_image.to_hex(), KEY_IMAGE_HEX);
}

#[test]
fn frozen_signature_still_verifies() {
    // A previously minted proof must remain valid under the current
    // code. If this fails, something downstream of signing changed:
    // the challenge hash, the message binding format, the canonical
    // ring order, or the Blake2b instance.
    let ring = frozen_ring();
    let signature = Signature::from_hex(SIGNATURE_HEX, ring.len()).unwrap();
    let key_image = KeyImage::from_hex(KEY_IMAGE_HEX).unwrap();

    assert!(
        verify_vote(VOTE, ELECTION_ID, &signature, &key_image, &ring),
        "frozen signature no longer verifies — verifier-side protocol changed"
    );
}

#[test]
fn frozen_signature_rejects_when_inputs_diverge() {
    // Sanity check around the previous test: the frozen proof must
    // fail to verify under *any* deviation from its recorded inputs.
    // If this passes too leniently, the previous test would be a
    // hollow tripwire.
    let ring = frozen_ring();
    let signature = Signature::from_hex(SIGNATURE_HEX, ring.len()).unwrap();
    let key_image = KeyImage::from_hex(KEY_IMAGE_HEX).unwrap();

    assert!(!verify_vote(b"option-B", ELECTION_ID, &signature, &key_image, &ring));
    assert!(!verify_vote(VOTE, "other-election", &signature, &key_image, &ring));
}
