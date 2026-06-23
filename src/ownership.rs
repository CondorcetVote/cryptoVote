//! Operation D — prove ownership of a key image (intended to run
//! client-side, like signing).
//!
//! The ring signature deliberately hides *which* member voted. This
//! module is the opt-in inverse: it lets the holder of a secret key
//! prove to an arbitrary third party that a particular key image — and
//! therefore the ballot it sits next to in the public registry — is
//! theirs, **without** ever revealing the secret key.
//!
//! ## Use case
//!
//! Mandated / proxy voting. A voter (or a mandate-holder voting on
//! someone's behalf) must be able to demonstrate, after the fact, how a
//! ballot was cast. The verifier can be **anyone**, including a party
//! completely external to the election: verification needs only public
//! data — the prover's public key, the key image, the `election_id`, and
//! the proof — all of which are already in (or derivable from) the public
//! registry. No cooperation from the organisers and no secret are
//! required to check a proof.
//!
//! ## What is proven
//!
//! The key image published in the registry is
//!
//! ```text
//!   I = x · B,   where  B = H_p(domain || election_id || P),  P = x · G
//! ```
//!
//! The proof is a non-interactive Chaum–Pedersen proof of *equality of
//! discrete logarithms*: it demonstrates knowledge of a single scalar `x`
//! satisfying **both** `P = x·G` and `I = x·B`. Only the true owner of
//! `I` knows such an `x`, so the proof is sound; and because it reveals
//! nothing about `x` beyond those two equations, the secret key stays
//! secret.
//!
//! ## The `context` parameter and the verifier's nonce
//!
//! Everything the verifier wants to bind the proof to goes into
//! `context`. The intended pattern for mandated voting is a
//! **verifier-chosen nonce**:
//!
//!  1. the verifier picks a fresh random nonce and sends it to the prover;
//!  2. the prover calls [`prove_ownership`] with `context = nonce` (the
//!     service may also append the ballot bytes, etc.);
//!  3. the verifier checks with the same `context`.
//!
//! Because the nonce is folded into the Fiat–Shamir challenge, the prover
//! could not have precomputed the proof before seeing it — so the proof
//! is **fresh** (not replayable). Note this gives freshness, *not*
//! non-transferability: a Chaum–Pedersen proof is publicly checkable, so
//! whoever holds `(context, proof)` can convince anyone else too. For
//! ordinary mandate scenarios that is fine (and usually desirable). If
//! you need a proof that convinces *only* the designated verifier, you
//! need a different (designated-verifier) construction — this module does
//! not provide one.
//!
//! ## What this module does NOT check
//!
//! It does not look the key image up in any registry. `verify_ownership`
//! answers exactly one question — "does the holder of this public key
//! vouch for this key image, under this election and context?" — and
//! nothing else. Tying `I` to a specific ballot is the registry's job
//! (the vote signature binds ballot + key image, and the host
//! de-duplicates on `I`); the caller is expected to do that lookup
//! separately.

use crate::blsag::hash_public_key_to_point;
use crate::signing::normalise_election_id;
use crate::types::{KeyImage, Nonce, OwnershipProof, PublicKey, SecretKey};
use blake2::{Blake2b512, Digest};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use rand::rngs::SysRng;
use rand_core::UnwrapErr;

/// Domain-separation tag for the ownership-proof Fiat–Shamir challenge.
/// Distinct from the BLSAG challenge domain so a transcript from one
/// construction can never be replayed as the other.
const OWNERSHIP_DOMAIN: &[u8] = b"crypto_vote:ownership:challenge";

/// Generate a fresh nonce for a verifier to challenge a prover with.
///
/// This is the **verifier-side** convenience for Operation D: the
/// organisation (or any third party) requesting a proof calls this, sends
/// the nonce to the prover, and both pass it as the `context` argument of
/// [`prove_ownership`] / [`verify_ownership`]. Because the nonce is
/// unpredictable and single-use, the resulting proof cannot have been
/// precomputed — that is exactly what makes it non-replayable.
///
/// Returns a [`Nonce`] (32 bytes) from the platform CSPRNG ([`SysRng`] —
/// the same source [`crate::generate_identity`] uses; on `wasm32` it is Web
/// Crypto). The verifier is free to use any other source of randomness
/// instead via [`Nonce::from_bytes`]; the library attaches no meaning to
/// the bytes beyond "opaque, fresh context". The prover must receive and
/// reuse the same nonce.
pub fn generate_nonce() -> Nonce {
    // A uniformly random scalar's canonical encoding gives 32 fresh bytes
    // from the same CSPRNG path the rest of the crate uses for signing.
    // (~252 bits of entropy — far more than a nonce needs.)
    let mut rng = UnwrapErr(SysRng);
    Nonce::from_bytes(Scalar::random(&mut rng).to_bytes())
}

/// Operation D (prover side): prove that the key image derived from
/// `secret_key` for `election_id` is yours, bound to `context`.
///
/// # Parameters
///
/// - `secret_key` — the prover's private scalar. Stays on the device; the
///   proof reveals nothing about it.
/// - `election_id` — the same election identifier used at voting time.
///   Normalised to Unicode NFC, exactly like [`crate::sign_vote`], so the
///   election-scoped key-image base matches the one in the registry.
/// - `context` — opaque bytes the verifier wants the proof bound to,
///   typically a fresh verifier-chosen nonce (optionally with the ballot
///   bytes appended). May be empty, though a nonce is what makes the
///   proof non-replayable. The verifier must pass the identical bytes.
///
/// # Returns
///
/// An [`OwnershipProof`] (64 bytes). It is public and freely shareable —
/// it proves authorship, it does not grant it.
pub fn prove_ownership(secret_key: &SecretKey, election_id: &str, context: &[u8]) -> OwnershipProof {
    let normalized = normalise_election_id(election_id);
    let election_id = normalized.as_bytes();

    let public_key = secret_key.public_key().point;
    // Same base the key image was built from: B = H_p(election || P).
    let base = hash_public_key_to_point(election_id, public_key);
    let key_image = secret_key.scalar * base;

    // Commit to a fresh nonce on both bases: R1 = r·G, R2 = r·B.
    let mut rng = UnwrapErr(SysRng);
    let r = Scalar::random(&mut rng);
    let commitment_g = r * RISTRETTO_BASEPOINT_POINT;
    let commitment_b = r * base;

    let challenge = challenge_scalar(
        election_id,
        context,
        public_key,
        base,
        key_image,
        commitment_g,
        commitment_b,
    );

    // s = r + c·x. Reveals nothing about x on its own (r masks it).
    let response = r + challenge * secret_key.scalar;

    OwnershipProof {
        challenge,
        response,
    }
}

/// Operation D (verifier side): check an [`OwnershipProof`].
///
/// Uses only public inputs, so anyone — including a party external to the
/// election — can run it. Returns `true` iff the proof demonstrates that
/// the holder of `public_key`'s secret key produced `key_image` under this
/// `election_id` and `context`.
///
/// # Parameters
///
/// - `public_key` — the prover's claimed public identity (from the public
///   ring). The proof is checked *against this key*, which is what ties
///   `P ↔ I` and de-anonymises the prover on purpose.
/// - `key_image` — the linking tag whose ownership is being proven
///   (looked up by the caller in the registry, next to the ballot).
/// - `election_id` — same identifier used at voting / proving time.
/// - `context` — must be byte-for-byte identical to the prover's.
/// - `proof` — the [`OwnershipProof`] to check.
///
/// Never panics: any inconsistency is a `false`.
pub fn verify_ownership(
    public_key: &PublicKey,
    key_image: &KeyImage,
    election_id: &str,
    context: &[u8],
    proof: &OwnershipProof,
) -> bool {
    let normalized = normalise_election_id(election_id);
    let election_id = normalized.as_bytes();

    let public_key = public_key.point;
    let key_image = key_image.point;
    let base = hash_public_key_to_point(election_id, public_key);

    // Recover the prover's commitments from the response:
    //   R1 = s·G − c·P = r·G,   R2 = s·B − c·I = r·B
    // (the c·P / c·I terms cancel the c·x inside s exactly when P = x·G
    // and I = x·B share the same x — which is what we are checking).
    let neg_challenge = -proof.challenge;
    let commitment_g = RistrettoPoint::multiscalar_mul(
        &[proof.response, neg_challenge],
        &[RISTRETTO_BASEPOINT_POINT, public_key],
    );
    let commitment_b =
        RistrettoPoint::multiscalar_mul(&[proof.response, neg_challenge], &[base, key_image]);

    let expected = challenge_scalar(
        election_id,
        context,
        public_key,
        base,
        key_image,
        commitment_g,
        commitment_b,
    );

    expected == proof.challenge
}

/// The Fiat–Shamir challenge for the ownership proof.
///
/// Hashes the full transcript. `election_id` and `context` are
/// length-prefixed so no two `(election_id, context)` splits can collide;
/// the public key, the linkability base, the key image and both
/// commitments pin down the exact statement being proven.
#[allow(clippy::too_many_arguments)]
fn challenge_scalar(
    election_id: &[u8],
    context: &[u8],
    public_key: RistrettoPoint,
    base: RistrettoPoint,
    key_image: RistrettoPoint,
    commitment_g: RistrettoPoint,
    commitment_b: RistrettoPoint,
) -> Scalar {
    let mut hash = Blake2b512::new();
    hash.update(OWNERSHIP_DOMAIN);
    hash.update((election_id.len() as u64).to_be_bytes());
    hash.update(election_id);
    hash.update((context.len() as u64).to_be_bytes());
    hash.update(context);
    hash.update(public_key.compress().as_bytes());
    hash.update(base.compress().as_bytes());
    hash.update(key_image.compress().as_bytes());
    hash.update(commitment_g.compress().as_bytes());
    hash.update(commitment_b.compress().as_bytes());
    Scalar::from_hash(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_identity;
    use crate::sign_vote;

    const EID: &str = "election-2026";
    const NONCE: &[u8] = b"verifier-chosen-nonce-123";

    /// The key image the registry would hold for this voter / election.
    /// Derived directly from the secret key the same way the vote path
    /// does, so the tests can feed `verify_ownership` the exact tag a host
    /// would have stored.
    fn key_image_of(sk: &SecretKey, election_id: &str) -> KeyImage {
        let normalized = normalise_election_id(election_id);
        let base = hash_public_key_to_point(normalized.as_bytes(), sk.public_key().point);
        KeyImage {
            point: sk.scalar * base,
        }
    }

    #[test]
    fn round_trip_succeeds() {
        let voter = generate_identity();
        let ki = key_image_of(&voter.secret_key, EID);
        let proof = prove_ownership(&voter.secret_key, EID, NONCE);
        assert!(verify_ownership(
            &voter.public_key,
            &ki,
            EID,
            NONCE,
            &proof
        ));
    }

    #[test]
    fn key_image_matches_the_one_a_real_vote_produces() {
        // The tag proven here must be byte-identical to the tag the vote
        // path emits, otherwise a proof would never line up with the
        // registry entry.
        let voter = generate_identity();
        let other = generate_identity().public_key;
        let ring = vec![voter.public_key, other];
        let vote_proof = sign_vote(&voter.secret_key, b"option-A", EID, &ring).unwrap();

        let ki = key_image_of(&voter.secret_key, EID);
        assert_eq!(ki, vote_proof.key_image);

        let proof = prove_ownership(&voter.secret_key, EID, NONCE);
        assert!(verify_ownership(
            &voter.public_key,
            &vote_proof.key_image,
            EID,
            NONCE,
            &proof
        ));
    }

    #[test]
    fn wrong_nonce_is_rejected() {
        // Freshness: a proof made for one nonce must not verify under a
        // different one (this is what stops replay).
        let voter = generate_identity();
        let ki = key_image_of(&voter.secret_key, EID);
        let proof = prove_ownership(&voter.secret_key, EID, NONCE);
        assert!(!verify_ownership(
            &voter.public_key,
            &ki,
            EID,
            b"a-different-nonce",
            &proof
        ));
    }

    #[test]
    fn wrong_election_is_rejected() {
        let voter = generate_identity();
        let ki = key_image_of(&voter.secret_key, "election-A");
        let proof = prove_ownership(&voter.secret_key, "election-A", NONCE);
        assert!(!verify_ownership(
            &voter.public_key,
            &ki,
            "election-B",
            NONCE,
            &proof
        ));
    }

    #[test]
    fn cannot_prove_someone_elses_key_image() {
        // Soundness: Mallory cannot prove ownership of Alice's key image,
        // because she does not know the scalar tying Alice's P to Alice's I.
        let alice = generate_identity();
        let mallory = generate_identity();
        let alice_ki = key_image_of(&alice.secret_key, EID);

        // Mallory proves with her own key but points the verifier at
        // Alice's public key and key image — must fail.
        let forged = prove_ownership(&mallory.secret_key, EID, NONCE);
        assert!(!verify_ownership(
            &alice.public_key,
            &alice_ki,
            EID,
            NONCE,
            &forged
        ));
    }

    #[test]
    fn proof_against_wrong_public_key_is_rejected() {
        let voter = generate_identity();
        let other = generate_identity().public_key;
        let ki = key_image_of(&voter.secret_key, EID);
        let proof = prove_ownership(&voter.secret_key, EID, NONCE);
        assert!(!verify_ownership(&other, &ki, EID, NONCE, &proof));
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let voter = generate_identity();
        let ki = key_image_of(&voter.secret_key, EID);
        let mut proof = prove_ownership(&voter.secret_key, EID, NONCE);
        proof.response = proof.response + Scalar::ONE;
        assert!(!verify_ownership(
            &voter.public_key,
            &ki,
            EID,
            NONCE,
            &proof
        ));
    }

    #[test]
    fn election_id_is_normalised_to_nfc() {
        // Same NFC contract as signing: the same logical id in NFC vs NFD
        // must interoperate between prover and verifier.
        let nfc = "élection-2026";
        let nfd = "e\u{0301}lection-2026";
        let voter = generate_identity();
        let ki = key_image_of(&voter.secret_key, nfd);
        let proof = prove_ownership(&voter.secret_key, nfd, NONCE);
        assert!(verify_ownership(
            &voter.public_key,
            &ki,
            nfc,
            NONCE,
            &proof
        ));
    }

    #[test]
    fn generated_nonces_are_distinct() {
        // A repeated nonce would defeat freshness; SysRng must not collide.
        assert_ne!(generate_nonce().to_bytes(), generate_nonce().to_bytes());
    }

    #[test]
    fn round_trip_with_generated_nonce() {
        let voter = generate_identity();
        let ki = key_image_of(&voter.secret_key, EID);
        let nonce = generate_nonce();
        let proof = prove_ownership(&voter.secret_key, EID, nonce.as_bytes());
        assert!(verify_ownership(
            &voter.public_key,
            &ki,
            EID,
            nonce.as_bytes(),
            &proof
        ));
    }

    #[test]
    fn nonce_round_trips_through_prefixed_encoding() {
        // The prefixed form is transport only: decoding it must yield the
        // same raw bytes, so a proof made with the nonce verifies after the
        // nonce has crossed the prefixed boundary.
        let voter = generate_identity();
        let ki = key_image_of(&voter.secret_key, EID);
        let nonce = generate_nonce();
        let decoded = Nonce::from_prefixed(&nonce.to_prefixed()).unwrap();
        assert_eq!(nonce.to_bytes(), decoded.to_bytes());

        let proof = prove_ownership(&voter.secret_key, EID, nonce.as_bytes());
        assert!(verify_ownership(
            &voter.public_key,
            &ki,
            EID,
            decoded.as_bytes(),
            &proof
        ));
    }

    #[test]
    fn proof_round_trips_through_prefixed_encoding() {
        let voter = generate_identity();
        let ki = key_image_of(&voter.secret_key, EID);
        let proof = prove_ownership(&voter.secret_key, EID, NONCE);
        let wire = proof.to_prefixed();
        let decoded = OwnershipProof::from_prefixed(&wire).unwrap();
        assert!(verify_ownership(
            &voter.public_key,
            &ki,
            EID,
            NONCE,
            &decoded
        ));
    }
}
