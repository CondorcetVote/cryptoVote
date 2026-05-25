//! Operation A — generation of a cryptographic identity.
//!
//! A voter's identity is a single [`Scalar`] sampled uniformly at
//! random, plus its derived Ristretto point. The scalar is the secret
//! key, the point is the public key.
//!
//! Randomness comes from [`OsRng`], i.e. the operating-system CSPRNG:
//!
//!  - on Linux / macOS / Windows that's `getrandom(2)` /
//!    `getentropy(2)` / `BCryptGenRandom`;
//!  - in a browser, with the `wasm` feature on, `getrandom` is
//!    configured (in `Cargo.toml`) to use `Crypto.getRandomValues` via
//!    its `js` feature.
//!
//! In every case the application code is the same — that is the whole
//! point of routing through `OsRng`.

use crate::types::{PublicKey, SecretKey};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;

/// A freshly generated voter identity.
pub struct Identity {
    /// Public part — publish this so the registrar can add it to the
    /// authorised list.
    pub public_key: PublicKey,
    /// Secret part — must stay on the voter's device.
    pub secret_key: SecretKey,
}

/// Generate a new [`Identity`] from the platform CSPRNG.
///
/// This is Operation A from the requirements spec: no inputs, two
/// outputs. There is nothing else to it — every voter holds exactly one
/// independently sampled identity.
pub fn generate_identity() -> Identity {
    let mut rng = OsRng;
    let scalar = Scalar::random(&mut rng);
    let secret_key = SecretKey { scalar };
    let public_key = secret_key.public_key();
    Identity {
        public_key,
        secret_key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_identities_are_different() {
        // OsRng is supposed to be uniform; getting the same key twice
        // would mean either a catastrophic bug or the heat-death of the
        // universe.
        let a = generate_identity();
        let b = generate_identity();
        assert_ne!(a.public_key, b.public_key);
        assert_ne!(a.secret_key.to_bytes(), b.secret_key.to_bytes());
    }

    #[test]
    fn public_key_is_derived_from_secret_key() {
        let id = generate_identity();
        // Re-deriving from the encoded secret key should give the same
        // public key — that's the "secret key uniquely determines the
        // public key" property the protocol relies on.
        let restored = SecretKey::from_bytes(&id.secret_key.to_bytes()).unwrap();
        assert_eq!(restored.public_key(), id.public_key);
    }
}
