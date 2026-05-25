//! # `crypto_vote` — a cryptographic oracle for verifiable voting
//!
//! This crate is the cryptographic core described in the requirements
//! spec: a strict, agnostic "mathematical oracle" that knows nothing
//! about elections, voters, databases or networks, and only answers two
//! questions:
//!
//!  - *give me a fresh voter identity*,
//!  - *given this ballot, this proof and this authorised list, is this
//!    a mathematically valid vote?*
//!
//! Everything else — who is allowed to vote, whether the election is
//! open, whether a tag has been seen before — belongs to the **host
//! system**. The host is expected to follow the anti-double-vote
//! contract from §2 of the spec: before validating a proof, it must
//! look the linking tag up in its own storage and reject the
//! transaction if it has already seen it.
//!
//! ## The three operations
//!
//! | # | Operation | Where it runs | Function |
//! |---|-----------|---------------|----------|
//! | A | Generate identity | Either side  | [`generate_identity`] |
//! | B | Sign a ballot     | Voter's device (WASM in the browser) | [`sign_vote`] |
//! | C | Validate a proof  | Host / server | [`verify_vote`] |
//!
//! ## Cryptographic choices
//!
//! - **Curve**: Ristretto255 (a prime-order group built on Curve25519).
//!   Picked because it is implemented in pure Rust by
//!   `curve25519-dalek`, has constant-time arithmetic, and avoids the
//!   small-subgroup pitfalls of raw Curve25519.
//! - **Ring signature**: BLSAG (Back's Linkable Spontaneous Anonymous
//!   Group), from the `nazgul` crate. BLSAG is the simplest scheme
//!   that satisfies the spec's three properties (anonymity, deterministic
//!   tag, unforgeability).
//! - **Hash**: Blake2b-512 (via the `blake2` crate). Picked because it
//!   produces a 64-byte digest natively — which is exactly what every
//!   challenge in the BLSAG protocol needs to feed back into a
//!   Ristretto scalar — and because it is already a standard choice
//!   for the same algorithm in other projects.
//! - **CSPRNG**: `OsRng`. On wasm32 it is wired up to
//!   `Crypto.getRandomValues` via the `getrandom` crate's `js` feature.
//!
//! ## Encoding
//!
//! Every public byte string the crate emits is a hex-encoded ASCII
//! string. Keys, tags and signatures all have a `.to_hex()` /
//! `from_hex(..)` pair. There are also raw `to_bytes` / `from_bytes`
//! helpers for callers that want to do their own encoding.
//!
//! ## End-to-end example
//!
//! ```
//! use crypto_vote::{generate_identity, sign_vote, verify_vote};
//!
//! // Three authorised voters.
//! let alice   = generate_identity();
//! let bob     = generate_identity();
//! let charlie = generate_identity();
//!
//! let ring = vec![
//!     alice.public_key,
//!     bob.public_key,
//!     charlie.public_key,
//! ];
//!
//! // Bob signs his ballot. The host never sees `bob.secret_key`.
//! let ballot = b"option-A";
//! let proof  = sign_vote(&bob.secret_key, ballot, &ring).unwrap();
//!
//! // The host: 1. would now check `proof.key_image` against its store,
//! //           2. then asks the oracle.
//! assert!(verify_vote(ballot, &proof.signature, &proof.key_image, &ring));
//! ```

pub mod error;
pub mod identity;
pub mod signing;
pub mod types;
pub mod verifying;

#[cfg(feature = "wasm")]
pub mod wasm;

// Top-level re-exports so the public API is `crypto_vote::sign_vote`,
// not `crypto_vote::signing::sign_vote`. Anything not re-exported here
// is still reachable through its module, but is not considered the
// canonical entry point.
pub use crate::error::{Error, Result};
pub use crate::identity::{Identity, generate_identity};
pub use crate::signing::sign_vote;
pub use crate::types::{KeyImage, PublicKey, SecretKey, Signature, VoteProof};
pub use crate::verifying::verify_vote;
