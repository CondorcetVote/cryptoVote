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
//! ## Guardrails against misuse
//!
//! Two cheap protections are built into [`sign_vote`] and
//! [`verify_vote`]:
//!
//!  - **Non-empty ballot and election identifier**: the library
//!    refuses to sign a zero-byte vote, and silently rejects any proof
//!    whose vote or election ID is empty at verification time. An
//!    empty payload is almost always a caller bug.
//!  - **Election binding**: every signature is bound to an
//!    `election_id` byte string. A proof produced for election X
//!    cannot validate for election Y, even if the ring and the secret
//!    key are identical. The host should pass a stable per-election
//!    identifier (UUID, slug, hash of an event configuration, …) for
//!    every call.
//!
//! The library does **not** enforce one further protocol-level
//! invariant the host is responsible for: the ring (the full set of
//! authorised public keys) must be **frozen before voting opens** and
//! stay composition-identical until the election closes. The ring is
//! part of what gets hashed into every signature, so adding or
//! removing a member mid-election invalidates every signature
//! produced before the change. All voter identities must therefore be
//! generated during the enrolment window. See the README for the
//! details.
//!
//! ## Cryptographic choices
//!
//! - **Curve**: Ristretto255 (a prime-order group built on Curve25519).
//!   Picked because it is implemented in pure Rust by
//!   `curve25519-dalek`, has constant-time arithmetic, and avoids the
//!   small-subgroup pitfalls of raw Curve25519.
//! - **Ring signature**: an experimental BLSAG (Back's Linkable
//!   Spontaneous Anonymous Group) variant implemented locally from the
//!   LSAG/BLSAG equations. The linking tag is scoped by `election_id`,
//!   so the same identity remains linkable inside one election but not
//!   publicly correlatable across different elections.
//! - **Hash**: Blake2b-512 (via the `blake2` crate). Picked because it
//!   produces a 64-byte digest natively — which is exactly what every
//!   challenge in the BLSAG protocol needs to feed back into a
//!   Ristretto scalar — and because it is already a standard choice
//!   for the same algorithm in other projects.
//! - **CSPRNG**: `SysRng`. On wasm32 it is wired up to
//!   `Crypto.getRandomValues` via the `getrandom` crate's `wasm_js` feature.
//!
//! ## Encoding
//!
//! Every public byte string the crate emits is a hex-encoded ASCII
//! string. Keys, tags and signatures all have a `.to_hex()` /
//! `from_hex(..)` pair. There are also raw `to_bytes` / `from_bytes`
//! helpers for callers that want to do their own encoding.
//!
//! On top of the bare hex there is a **human-friendly prefixed format**
//! (`.to_prefixed()` / `from_prefixed(..)`): the same hex body, wrapped
//! with a self-describing tag (`pk_`, `sk_`, `ki_`, `blsag_`) and a
//! trailing checksum, e.g. `pk_3f8a…e1c0_d4e9a1b7`. It encodes the exact
//! same bytes — nothing about the cryptography changes — but the tag
//! stops a value being pasted in the wrong slot and the checksum catches
//! typos. See [`crate::encoding`] for the full description.
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
//! let election_id = "550e8400-e29b-41d4-a716-446655440000"; // any stable string
//! let ballot      = b"option-A";
//!
//! // Bob signs his ballot. The host never sees `bob.secret_key`.
//! let proof = sign_vote(&bob.secret_key, ballot, election_id, &ring).unwrap();
//!
//! // The host: 1. would now check `proof.key_image` against its store,
//! //           2. then asks the oracle.
//! assert!(verify_vote(
//!     ballot,
//!     election_id,
//!     &proof.signature,
//!     &proof.key_image,
//!     &ring,
//! ));
//! ```

mod blsag;

pub mod encoding;
pub mod error;
pub mod identity;
pub mod signing;
pub mod types;
pub mod verifying;

#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "extism")]
pub mod extism;

// Top-level re-exports so the public API is `crypto_vote::sign_vote`,
// not `crypto_vote::signing::sign_vote`. Anything not re-exported here
// is still reachable through its module, but is not considered the
// canonical entry point.
pub use crate::error::{Error, Result};
pub use crate::identity::{Identity, generate_identity};
pub use crate::signing::sign_vote;
pub use crate::types::{KeyImage, PublicKey, SecretKey, Signature, VoteProof};
pub use crate::verifying::verify_vote;
