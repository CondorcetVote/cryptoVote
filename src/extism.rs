//! Extism plugin layer (enabled with `--features extism`).
//!
//! Extism is a universal WebAssembly plugin system: it defines a
//! host/guest ABI on top of bare WASI so the *same* `.wasm` artefact
//! is loadable by every Extism host SDK — browser (`@extism/extism`),
//! Node.js, Deno, Bun, Python, Go, Rust, the `extism` CLI, … The
//! trade-off vs the [`crate::wasm`] flavour is the ergonomics of the
//! I/O surface: instead of native `Uint8Array` / typed bindings, every
//! call goes through a single JSON-encoded buffer.
//!
//! The plugin functions exported mirror the public API. Sign and verify
//! each come in **two flavours** that differ only in how the `vote`
//! field is carried over the JSON wire:
//!
//! | Plugin function   | JSON input shape                                                              | JSON output shape                |
//! |-------------------|-------------------------------------------------------------------------------|----------------------------------|
//! | `generate_identity`    | *(empty)*                                                                   | `{"secret": hex64, "public": hex64}` |
//! | `derive_public_key`    | `{"secret": hex64}`                                                          | `{"public": hex64}`               |
//! | `sign_vote_str`        | `{"secret": hex64, "vote": str, "election_id": str, "ring": [hex64, …]}`    | `{"signature": hex, "key_image": hex64}` |
//! | `sign_vote_hex`        | `{"secret": hex64, "vote": hex, "election_id": str, "ring": [hex64, …]}`    | `{"signature": hex, "key_image": hex64}` |
//! | `verify_vote_str`      | `{"vote": str, "election_id": str, "signature": hex, "key_image": hex64, "ring": [hex64, …]}` | `{"valid": bool}` |
//! | `verify_vote_hex`      | `{"vote": hex, "election_id": str, "signature": hex, "key_image": hex64, "ring": [hex64, …]}` | `{"valid": bool}` |
//! | `is_valid_secret_key`  | `{"secret": hex64}`                                                          | `{"valid": bool}`                |
//!
//! - **`_str`** — `vote` is a plain JSON string; its UTF-8 bytes *are*
//!   the ballot, fed verbatim with no decoding step. Ergonomic for text
//!   ballots (`"option-A"`, a stringified JSON ballot). A JSON string
//!   can only carry valid UTF-8, so this flavour cannot represent a
//!   non-UTF-8 ballot.
//! - **`_hex`** — `vote` is a hex-encoded byte string, decoded to raw
//!   bytes before hashing. Use it for *arbitrary binary* ballots (raw
//!   Protobuf, embedded NUL bytes, any non-UTF-8 sequence). Hex keeps
//!   the encoding uniform with the rest of the wire (keys, signatures,
//!   tags are all hex).
//!
//! The two are just different front doors to the same byte-level
//! operation: the library always sees `&[u8]`. So a proof produced by
//! `sign_vote_str` verifies under `verify_vote_hex` (and vice-versa) as
//! long as the underlying bytes match — e.g. signing `"oui"` with
//! `_str` is identical to signing `"6f7569"` with `_hex`. This is also
//! what makes a ballot signed by either [`crate::wasm`] binding
//! verifiable here: the only thing that matters is the vote bytes.
//!
//! ### Memory hygiene caveat
//!
//! Going through JSON means the secret key transits as a hex string in
//! the plugin's input buffer. Unlike [`crate::wasm`], the host cannot
//! call `.fill(0)` on it after the call returns — it lives wherever
//! the host SDK stored the JSON. If you care about wiping the
//! in-memory copy of the secret on the JS side, the `wasm-bindgen`
//! flavour (`crate::wasm`) is the right artefact: it exposes the
//! secret as a mutable `Uint8Array`. The Extism flavour optimises for
//! *portability across host languages* instead.

use crate::types::{KeyImage, PublicKey, SecretKey, Signature};
use extism_pdk::{FnResult, Json, plugin_fn};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Serialize)]
pub struct IdentityOut {
    /// Hex-encoded secret scalar (64 lowercase chars).
    pub secret: String,
    /// Hex-encoded public key (64 lowercase chars).
    pub public: String,
}

#[plugin_fn]
pub fn generate_identity() -> FnResult<Json<IdentityOut>> {
    let id = crate::generate_identity();
    Ok(Json(IdentityOut {
        secret: id.secret_key.to_hex(),
        public: id.public_key.to_hex(),
    }))
}

#[derive(Deserialize)]
pub struct DerivePublicIn {
    pub secret: String,
}

#[derive(Serialize)]
pub struct DerivePublicOut {
    /// Hex-encoded public key (64 lowercase chars).
    pub public: String,
}

/// Derive the public key matching a secret key.
///
/// Input: `{"secret": hex64}` — the 64-character hex encoding of the secret scalar.
/// Output: `{"public": hex64}` — the matching public key.
///
/// The derivation is a pure scalar multiplication on Ristretto255 —
/// no randomness — so the same secret always yields the same public key.
/// Useful when a caller has stored the secret key but needs to recover
/// or re-display the corresponding public key.
///
/// The secret is wrapped in `Zeroizing` so its Rust-side heap allocation
/// is overwritten before this function returns.
#[plugin_fn]
pub fn derive_public_key(Json(input): Json<DerivePublicIn>) -> FnResult<Json<DerivePublicOut>> {
    let secret = Zeroizing::new(input.secret);
    let sk = SecretKey::from_hex(&secret)?;
    Ok(Json(DerivePublicOut {
        public: sk.public_key().to_hex(),
    }))
}

#[derive(Deserialize)]
pub struct SignIn {
    pub secret: String,
    /// The ballot. Its interpretation depends on which function you
    /// call: `sign_vote_str` reads it as a plain UTF-8 string (its bytes
    /// are the ballot); `sign_vote_hex` reads it as hex-encoded bytes.
    /// Either way the library hashes the resulting bytes opaquely.
    pub vote: String,
    pub election_id: String,
    pub ring: Vec<String>,
}

#[derive(Serialize)]
pub struct SignOut {
    pub signature: String,
    pub key_image: String,
}

/// Sign a ballot whose `vote` field is a **plain UTF-8 string**. The
/// string's bytes are the ballot — no decoding. See [`sign_vote_hex`]
/// for arbitrary binary ballots.
#[plugin_fn]
pub fn sign_vote_str(Json(input): Json<SignIn>) -> FnResult<Json<SignOut>> {
    let vote_bytes = input.vote.into_bytes();
    sign_with_bytes(input.secret, &vote_bytes, &input.election_id, &input.ring)
}

/// Sign a ballot whose `vote` field is **hex-encoded bytes**. Decoded to
/// raw bytes before hashing, so any binary payload works. See
/// [`sign_vote_str`] for text ballots.
#[plugin_fn]
pub fn sign_vote_hex(Json(input): Json<SignIn>) -> FnResult<Json<SignOut>> {
    let vote_bytes = hex::decode(&input.vote)?;
    sign_with_bytes(input.secret, &vote_bytes, &input.election_id, &input.ring)
}

/// Shared signing core for both `sign_vote_*` entry points: everything
/// except how the vote bytes were obtained.
fn sign_with_bytes(
    secret: String,
    vote: &[u8],
    election_id: &str,
    ring: &[String],
) -> FnResult<Json<SignOut>> {
    // Wrap the secret hex String in `Zeroizing` so its heap allocation
    // is overwritten when this function returns. This is the most we can
    // clean up from inside the plugin — the JSON parser's intermediate
    // buffers and the Extism PDK's input buffer in WASM linear memory
    // are not under our control. The other inputs are public.
    let secret = Zeroizing::new(secret);
    let sk = SecretKey::from_hex(&secret)?;
    let ring: Vec<PublicKey> = ring
        .iter()
        .map(|h| PublicKey::from_hex(h))
        .collect::<Result<_, _>>()?;
    let proof = crate::sign_vote(&sk, vote, election_id, &ring)?;
    Ok(Json(SignOut {
        signature: proof.signature.to_hex(),
        key_image: proof.key_image.to_hex(),
    }))
}

#[derive(Deserialize)]
pub struct VerifyIn {
    /// The ballot. `verify_vote_str` reads it as a plain UTF-8 string,
    /// `verify_vote_hex` as hex-encoded bytes. Either way it must yield
    /// byte-for-byte the same bytes the voter signed, or the result is
    /// `false`.
    pub vote: String,
    pub election_id: String,
    pub signature: String,
    pub key_image: String,
    pub ring: Vec<String>,
}

#[derive(Serialize)]
pub struct VerifyOut {
    pub valid: bool,
}

/// Verify a proof whose `vote` field is a **plain UTF-8 string**. See
/// [`verify_vote_hex`] for hex-encoded binary ballots.
#[plugin_fn]
pub fn verify_vote_str(Json(input): Json<VerifyIn>) -> FnResult<Json<VerifyOut>> {
    // Mirror the public API contract: a malformed proof is "invalid",
    // not an error. The host gets a clean `{"valid": false}` rather
    // than a thrown plugin error, which keeps the verifier-side flow
    // identical regardless of who sent the bytes.
    let valid = verify_with_bytes(input.vote.as_bytes(), &input).unwrap_or(false);
    Ok(Json(VerifyOut { valid }))
}

/// Verify a proof whose `vote` field is **hex-encoded bytes**. Bad hex
/// is treated as "invalid" (`false`), never an error. See
/// [`verify_vote_str`] for text ballots.
#[plugin_fn]
pub fn verify_vote_hex(Json(input): Json<VerifyIn>) -> FnResult<Json<VerifyOut>> {
    let valid = hex::decode(&input.vote)
        .ok()
        .and_then(|vote| verify_with_bytes(&vote, &input))
        .unwrap_or(false);
    Ok(Json(VerifyOut { valid }))
}

#[derive(Deserialize)]
pub struct IsValidSecretIn {
    pub secret: String,
}

#[derive(Serialize)]
pub struct IsValidSecretOut {
    pub valid: bool,
}

/// Plugin-side counterpart of [`crate::SecretKey::is_valid_hex`].
///
/// Returns `{"valid": true}` iff the hex string is a canonical 32-byte
/// encoding of a non-zero scalar. Any malformed input (bad hex, wrong
/// length, non-canonical, zero) returns `{"valid": false}` — never an
/// error — so the host's flow is the same regardless of who sent the
/// bytes.
#[plugin_fn]
pub fn is_valid_secret_key(Json(input): Json<IsValidSecretIn>) -> FnResult<Json<IsValidSecretOut>> {
    // Same memory-hygiene caveat as `sign_with_bytes`: we wrap the
    // Rust-side copy of the secret in `Zeroizing` so its heap allocation is
    // overwritten before this function returns. The JSON parser's
    // intermediate buffers and the Extism input buffer in WASM linear
    // memory are not under our control — see the module docs.
    let secret = Zeroizing::new(input.secret);
    Ok(Json(IsValidSecretOut {
        valid: SecretKey::is_valid_hex(&secret),
    }))
}

/// Shared verify core for both `verify_vote_*` entry points: the vote
/// bytes are already decoded by the caller; here we parse the proof
/// components and run the check. Returns `None` on any parse failure,
/// which the callers map to `false`.
fn verify_with_bytes(vote: &[u8], input: &VerifyIn) -> Option<bool> {
    let ring: Vec<PublicKey> = input
        .ring
        .iter()
        .map(|h| PublicKey::from_hex(h).ok())
        .collect::<Option<_>>()?;
    let signature = Signature::from_hex(&input.signature, ring.len()).ok()?;
    let key_image = KeyImage::from_hex(&input.key_image).ok()?;
    Some(crate::verify_vote(
        vote,
        &input.election_id,
        &signature,
        &key_image,
        &ring,
    ))
}
