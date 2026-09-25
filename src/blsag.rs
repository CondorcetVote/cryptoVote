//! Experimental BLSAG variant with election-scoped key images.
//!
//! The ring-signature equations are the standard LSAG/BLSAG shape from
//! Liu, Wei and Wong, "Linkable Spontaneous Anonymous Group Signature
//! for Ad Hoc Groups" (IACR ePrint 2004/027), as used in the bLSAG
//! construction documented by Zero to Monero 2.0. The application-specific
//! change is deliberately narrow: every hash-to-group base used for
//! linkability is domain-separated by the election identifier.
//!
//! Standard bLSAG uses `I = x * H_p(P)`, where `P = x * G`. Here we use
//! `I_e = x * H_p(domain || len(election_id) || election_id || P)`.
//! Verification applies the same contextual `H_p` to each ring member.
//! This preserves same-election linkability while preventing public
//! correlation of the same secret key across different elections. It is
//! the "event-oriented linkability" notion from the linkable ring
//! signature literature (Liu–Wei–Wong 2004; Tsang–Wei 2005 for e-voting),
//! with the event identifier folded into the per-key base.
//!
//! ## Hedged randomness
//!
//! The signer's commitment scalar `alpha` and the decoy responses are
//! not drawn straight from the CSPRNG. They are derived by hashing the
//! secret key, the message and 64 fresh random bytes together (the
//! "hedged" construction used by e.g. XEdDSA / hedged Ed25519). With a
//! healthy RNG the output is indistinguishable from uniform; with a
//! broken or replayed RNG (VM snapshot restored twice, fork without
//! reseed) the secret key and message still make `alpha` unique per
//! signature, so a nonce reuse — which would leak the secret key by a
//! single subtraction — cannot happen. This only changes how the signer
//! samples its randomness; the signature format and the verifier are
//! untouched.

use blake2::{Blake2b512, Digest};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use zeroize::Zeroizing;

const KEY_IMAGE_DOMAIN: &[u8] = b"crypto_vote:blsag:key-image-point";
const CHALLENGE_DOMAIN: &[u8] = b"crypto_vote:blsag:challenge";
const NONCE_DOMAIN: &[u8] = b"crypto_vote:blsag:hedged-nonce";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ContextualBlsag {
    pub(crate) challenge: Scalar,
    pub(crate) responses: Vec<Scalar>,
    pub(crate) key_image: RistrettoPoint,
}

pub(crate) fn sign(
    secret_key: Scalar,
    ring: &[RistrettoPoint],
    secret_index: usize,
    election_id: &[u8],
    message: &[u8],
) -> ContextualBlsag {
    let signer_public_key = ring[secret_index];
    let key_image_base = hash_public_key_to_point(election_id, signer_public_key);
    let key_image = secret_key * key_image_base;

    // One fresh entropy draw per signature, mixed with the secret key and
    // the message so no two signatures can share a nonce even if the RNG
    // misbehaves. See the module docs. Label 0 is `alpha`, label `i + 1`
    // is the decoy response for ring slot `i`.
    let mut rng = UnwrapErr(SysRng);
    let mut entropy = Zeroizing::new([0u8; 64]);
    rng.fill_bytes(&mut entropy[..]);
    let alpha = hedged_scalar(&secret_key, message, &entropy, 0);
    let mut responses: Vec<Scalar> = (0..ring.len())
        .map(|i| hedged_scalar(&secret_key, message, &entropy, i as u64 + 1))
        .collect();
    let mut challenges = vec![Scalar::ZERO; ring.len()];

    let mut i = (secret_index + 1) % ring.len();
    challenges[i] = challenge_scalar(
        message,
        alpha * RISTRETTO_BASEPOINT_POINT,
        alpha * key_image_base,
    );

    loop {
        let next = (i + 1) % ring.len();
        challenges[next] = next_challenge(
            message,
            election_id,
            ring[i],
            responses[i],
            challenges[i],
            key_image,
        );

        if next == secret_index {
            break;
        }
        i = next;
    }

    responses[secret_index] = alpha - challenges[secret_index] * secret_key;

    ContextualBlsag {
        challenge: challenges[0],
        responses,
        key_image,
    }
}

pub(crate) fn verify(
    challenge: Scalar,
    responses: &[Scalar],
    key_image: RistrettoPoint,
    ring: &[RistrettoPoint],
    election_id: &[u8],
    message: &[u8],
) -> bool {
    if responses.len() != ring.len() || ring.is_empty() {
        return false;
    }

    let mut reconstructed_challenge = challenge;
    for (response, public_key) in responses.iter().zip(ring) {
        reconstructed_challenge = next_challenge(
            message,
            election_id,
            *public_key,
            *response,
            reconstructed_challenge,
            key_image,
        );
    }

    challenge == reconstructed_challenge
}

fn next_challenge(
    message: &[u8],
    election_id: &[u8],
    public_key: RistrettoPoint,
    response: Scalar,
    challenge: Scalar,
    key_image: RistrettoPoint,
) -> Scalar {
    let linkability_base = hash_public_key_to_point(election_id, public_key);
    let commitment_to_public_key = RistrettoPoint::multiscalar_mul(
        &[response, challenge],
        &[RISTRETTO_BASEPOINT_POINT, public_key],
    );
    let commitment_to_key_image =
        RistrettoPoint::multiscalar_mul(&[response, challenge], &[linkability_base, key_image]);

    challenge_scalar(message, commitment_to_public_key, commitment_to_key_image)
}

fn challenge_scalar(
    message: &[u8],
    commitment_to_public_key: RistrettoPoint,
    commitment_to_key_image: RistrettoPoint,
) -> Scalar {
    let mut hash = Blake2b512::new();
    hash.update(CHALLENGE_DOMAIN);
    hash.update((message.len() as u64).to_be_bytes());
    hash.update(message);
    hash.update(commitment_to_public_key.compress().as_bytes());
    hash.update(commitment_to_key_image.compress().as_bytes());
    Scalar::from_hash(hash)
}

/// Derive one signing-side scalar from the secret key, the message, a
/// per-signature entropy block and a label.
///
/// `label` separates the different scalars drawn for the same signature
/// (`alpha` vs. each decoy response). The secret key goes in first so a
/// broken RNG (constant `entropy`) still yields a per-key, per-message
/// nonce; the entropy goes in so a healthy RNG still yields a fresh,
/// uniformly distributed one every time. The output distribution is what
/// `Scalar::random` gives, so verification is unaffected.
///
/// Shared with [`crate::ownership`], which hedges its Chaum–Pedersen
/// commitment the same way with its own, domain-prefixed `message`.
pub(crate) fn hedged_scalar(
    secret_key: &Scalar,
    message: &[u8],
    entropy: &[u8; 64],
    label: u64,
) -> Scalar {
    let mut hash = Blake2b512::new();
    hash.update(NONCE_DOMAIN);
    hash.update(secret_key.as_bytes());
    hash.update((message.len() as u64).to_be_bytes());
    hash.update(message);
    hash.update(entropy);
    hash.update(label.to_be_bytes());
    Scalar::from_hash(hash)
}

/// Hash-to-group base for the linkability tag, scoped by `election_id`.
///
/// Exposed to the crate (not the public API) so the ownership proof in
/// [`crate::ownership`] can recompute the *same* base a key image was
/// built from: `key_image = secret_key · hash_public_key_to_point(eid, P)`.
/// Both the signing path and the ownership proof must agree on this base
/// bit-for-bit, so there is a single definition here.
pub(crate) fn hash_public_key_to_point(
    election_id: &[u8],
    public_key: RistrettoPoint,
) -> RistrettoPoint {
    let mut hash = Blake2b512::new();
    hash.update(KEY_IMAGE_DOMAIN);
    hash.update((election_id.len() as u64).to_be_bytes());
    hash.update(election_id);
    hash.update(public_key.compress().as_bytes());
    RistrettoPoint::from_hash(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_image_base_is_scoped_by_election() {
        let mut rng = UnwrapErr(SysRng);
        let secret_key = Scalar::random(&mut rng);
        let public_key = secret_key * RISTRETTO_BASEPOINT_POINT;

        assert_ne!(
            secret_key * hash_public_key_to_point(b"election-A", public_key),
            secret_key * hash_public_key_to_point(b"election-B", public_key),
        );
    }

    #[test]
    fn hedged_scalars_differ_by_label_and_entropy() {
        // Different labels (alpha vs. each decoy) and different entropy
        // draws must never collide; a constant entropy block must still
        // give distinct scalars per label (the "broken RNG" case).
        let secret_key = Scalar::from(42u64);
        let zero = [0u8; 64];
        let one = [1u8; 64];
        let a0 = hedged_scalar(&secret_key, b"m", &zero, 0);
        let a1 = hedged_scalar(&secret_key, b"m", &zero, 1);
        let b0 = hedged_scalar(&secret_key, b"m", &one, 0);
        let c0 = hedged_scalar(&secret_key, b"other", &zero, 0);
        assert_ne!(a0, a1);
        assert_ne!(a0, b0);
        assert_ne!(a0, c0);
    }

    #[test]
    fn two_signatures_of_the_same_message_differ() {
        // Hedging must not make signing deterministic: the entropy block
        // still randomises every signature.
        let mut rng = UnwrapErr(SysRng);
        let secret_key = Scalar::random(&mut rng);
        let ring = vec![
            secret_key * RISTRETTO_BASEPOINT_POINT,
            RistrettoPoint::random(&mut rng),
        ];
        let p1 = sign(secret_key, &ring, 0, b"e", b"m");
        let p2 = sign(secret_key, &ring, 0, b"e", b"m");
        assert_ne!(p1.responses, p2.responses);
        assert_eq!(p1.key_image, p2.key_image);
    }

    #[test]
    fn round_trip_with_contextual_tag() {
        let mut rng = UnwrapErr(SysRng);
        let secret_key = Scalar::random(&mut rng);
        let signer_public_key = secret_key * RISTRETTO_BASEPOINT_POINT;
        let ring = vec![
            RistrettoPoint::random(&mut rng),
            signer_public_key,
            RistrettoPoint::random(&mut rng),
        ];

        let proof = sign(secret_key, &ring, 1, b"election-A", b"vote-bytes");
        assert!(verify(
            proof.challenge,
            &proof.responses,
            proof.key_image,
            &ring,
            b"election-A",
            b"vote-bytes",
        ));
        assert!(!verify(
            proof.challenge,
            &proof.responses,
            proof.key_image,
            &ring,
            b"election-B",
            b"vote-bytes",
        ));
    }
}
