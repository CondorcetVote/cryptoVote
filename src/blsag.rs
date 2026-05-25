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
//! correlation of the same secret key across different elections.

use blake2::{Blake2b512, Digest};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use rand::rngs::SysRng;
use rand_core::UnwrapErr;

const KEY_IMAGE_DOMAIN: &[u8] = b"crypto_vote:blsag:key-image-point";
const CHALLENGE_DOMAIN: &[u8] = b"crypto_vote:blsag:challenge";

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

    let mut rng = UnwrapErr(SysRng);
    let alpha = Scalar::random(&mut rng);
    let mut responses: Vec<Scalar> = ring.iter().map(|_| Scalar::random(&mut rng)).collect();
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

fn hash_public_key_to_point(election_id: &[u8], public_key: RistrettoPoint) -> RistrettoPoint {
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
