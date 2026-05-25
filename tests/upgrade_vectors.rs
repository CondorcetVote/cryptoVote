//! Frozen test vectors — tripwires for accidental protocol changes.
//!
//! The signature itself is *not* deterministic (`sign_vote` samples fresh
//! randomness for the signer's alpha and for every decoy response), so we
//! cannot assert byte-for-byte equality of new `sign_vote` outputs. Two
//! things, however, are stable across runs and can be frozen:
//!
//! 1. **The key image** is `I_e = x · H_p(domain || election_id || x · G)`.
//!    It depends on the secret key, election identifier, curve, domain
//!    separation and hash-to-point construction. Any upgrade that changes
//!    one of those will break this assertion.
//!
//! 2. **A previously produced signature must still verify.** Verification
//!    is deterministic, so a frozen `(ring, signature, key_image, vote,
//!    eid)` tuple gives us coverage on `bind_to_election`, the canonical
//!    ring ordering, the BLSAG challenge derivation and the Blake2b-512
//!    instance. Any of those changing makes the assertion fail.
//!
//! Vectors were generated once from fixed secret keys (`seed = 1, 2, 3`)
//! and pasted here verbatim. If a legitimate protocol change requires
//! regenerating them, document the protocol change too — silent
//! regeneration is exactly the bug this file is meant to catch.

use crypto_vote::{KeyImage, PublicKey, SecretKey, Signature, sign_vote, verify_vote};

const SIGNER_SK_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000";
const RING_HEX: [&str; 3] = [
    "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
    "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
    "94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
];
const KEY_IMAGE_HEX: &str = "ec073fb1bcb88afb08adbfe202c74fe6ad2a646984bbec10c763902b73d9d753";
const SIGNATURE_HEX: &str = "0fcd75bfc58d8fae5b63c6a62e18b67eb2964e6aa772d80651a967754e4d2e0e7fe0980bc1324dbcabe5f8c1a54ea01e9c972d0e3ef9cfff9f3a036d2c6ee00728251718bf7cc2f90574c1a63f6b54ec5079d376385c8d4c8f6071856b547b07db845bf3f5f5bf4010e4231bcee66145f8f38e07c8e5b477c28b0d6d820f4706";
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
    // The linking tag is a pure function of the secret key, election
    // identifier and contextual hash-to-point. Re-signing with the same
    // key in the same election — even with a different ballot — must
    // yield exactly the same tag bytes as the day the vector was minted.
    let sk = SecretKey::from_hex(SIGNER_SK_HEX).unwrap();
    let ring = frozen_ring();

    let proof = sign_vote(&sk, VOTE, ELECTION_ID, &ring).unwrap();
    assert_eq!(
        proof.key_image.to_hex(),
        KEY_IMAGE_HEX,
        "key image drifted — domain, election binding, hash-to-point, curve encoding, or secret-scalar handling changed"
    );

    // Same key, same election, different ballot: tag must still match.
    // This guards against accidentally folding ballot bytes into the
    // tag derivation.
    let proof2 = sign_vote(&sk, b"option-B", ELECTION_ID, &ring).unwrap();
    assert_eq!(proof2.key_image.to_hex(), KEY_IMAGE_HEX);

    // Same key, different election: tag must differ. This is the
    // privacy property that prevents public cross-election correlation.
    let proof3 = sign_vote(&sk, VOTE, "upgrade-vector-other-election", &ring).unwrap();
    assert_ne!(proof3.key_image.to_hex(), KEY_IMAGE_HEX);
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

    assert!(!verify_vote(
        b"option-B",
        ELECTION_ID,
        &signature,
        &key_image,
        &ring
    ));
    assert!(!verify_vote(
        VOTE,
        "other-election",
        &signature,
        &key_image,
        &ring
    ));
}
