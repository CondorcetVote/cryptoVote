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
//! field is carried over the JSON wire.
//!
//! ### Encoding of keys, tags and signatures
//!
//! Every key / signature field uses the human-friendly prefixed form
//! (`pk_…_…`, `sk_…_…`, `ki_…_…`, `blsag_…_…`), both in and out. This
//! boundary speaks the prefixed format **exclusively**: bare hex is
//! rejected — it is only accepted by the pure-Rust library API. So
//! `secret`, `public`, `signature`, `key_image` and every `ring` entry
//! are prefixed strings. The `vote` field is unaffected (it is still a
//! UTF-8 string or hex bytes).
//!
//! | Plugin function   | JSON input shape                                                              | JSON output shape                |
//! |-------------------|-------------------------------------------------------------------------------|----------------------------------|
//! | `generate_identity`    | *(empty)*                                                                   | `{"secret": sk_…, "public": pk_…}` |
//! | `derive_public_key`    | `{"secret": sk_…}`                                                           | `{"public": pk_…}`                |
//! | `sign_vote_str`        | `{"secret": sk_…, "vote": str, "election_id": str, "ring": [pk_…, …]}`       | `{"signature": blsag_…, "key_image": ki_…}` |
//! | `sign_vote_hex`        | `{"secret": sk_…, "vote": hex, "election_id": str, "ring": [pk_…, …]}`       | `{"signature": blsag_…, "key_image": ki_…}` |
//! | `verify_vote_str`      | `{"vote": str, "election_id": str, "signature": blsag_…, "key_image": ki_…, "ring": [pk_…, …]}` | `{"valid": bool}` |
//! | `verify_vote_hex`      | `{"vote": hex, "election_id": str, "signature": blsag_…, "key_image": ki_…, "ring": [pk_…, …]}` | `{"valid": bool}` |
//! | `is_valid_secret_key`  | `{"secret": sk_…}`                                                           | `{"valid": bool}`                |
//! | `generate_nonce`       | *(empty)*                                                                   | `{"nonce": nonce_…}`             |
//! | `prove_ownership`      | `{"secret": sk_…, "election_id": str, "nonce": nonce_…}`                     | `{"proof": own_…}`               |
//! | `verify_ownership`     | `{"public": pk_…, "key_image": ki_…, "election_id": str, "nonce": nonce_…, "proof": own_…}` | `{"valid": bool}` |
//! | `ring_digest`          | `{"ring": [pk_…, …]}`                                                        | `{"digest": ring_…}`             |
//!
//! `ring_digest` computes the canonical digest of a ring (see
//! [`crate::ring_digest`]) so a voter's device, or anyone, can check that
//! the ring it was handed is the one the election published.
//!
//! `generate_nonce` / `prove_ownership` / `verify_ownership` expose
//! Operation D — proof of ownership of a key image (see
//! [`crate::ownership`]). The `nonce` is a prefixed `nonce_…_…` value
//! (validated like every other key/signature field); the prefix is
//! transport only, the proof binds the nonce's raw bytes. For a custom
//! binary context, use the pure-Rust API, which takes `context: &[u8]`.
//!
//! - **`_str`** — `vote` is a plain JSON string; its UTF-8 bytes *are*
//!   the ballot, fed verbatim with no decoding step. Ergonomic for text
//!   ballots (`"option-A"`, a stringified JSON ballot). A JSON string
//!   can only carry valid UTF-8, so this flavour cannot represent a
//!   non-UTF-8 ballot.
//! - **`_hex`** — `vote` is a hex-encoded byte string, decoded to raw
//!   bytes before hashing. Use it for *arbitrary binary* ballots (raw
//!   Protobuf, embedded NUL bytes, any non-UTF-8 sequence). Note this
//!   `hex` concerns only the *ballot*; the keys, signatures and tags on
//!   the same wire use the prefixed format.
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
//! Going through JSON means the secret key transits as a (prefixed)
//! string inside a JSON document. On the guest side every copy we own
//! is wiped: the entry points that accept a `secret` field read the raw
//! input through [`read_secret_input`], which keeps the whole JSON
//! buffer in `Zeroizing` while it is parsed, and the parsed secret
//! `String` is wrapped in `Zeroizing` too. What we cannot wipe is the
//! copy the Extism runtime holds in its own *kernel* memory: the PDK
//! only exposes read access to the input region, so it lingers there
//! until the next call overwrites it or the plugin instance is dropped.
//! Hosts that care should use a plugin instance per secret-handling
//! call and drop it right after.
//!
//! On the host side the secret lives wherever the SDK stored the JSON
//! string. Unlike [`crate::wasm`], a JS host cannot call `.fill(0)` on
//! it after the call returns. If you care about wiping the in-memory
//! copy of the secret on the JS side, the `wasm-bindgen` flavour
//! (`crate::wasm`) is the right artefact: it exposes the secret as a
//! mutable `Uint8Array`. The Extism flavour optimises for *portability
//! across host languages* instead.

use crate::types::{KeyImage, Nonce, OwnershipProof, PublicKey, SecretKey, Signature};
use extism_pdk::{FnResult, Json, plugin_fn};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Read the plugin input as JSON while keeping the raw buffer wipeable.
///
/// `#[plugin_fn]` with a `Json<T>` argument copies the input into a plain
/// `Vec<u8>` and drops it *unwiped* once parsed. For inputs that carry a
/// secret key that leaves the whole JSON document, secret included, in
/// freed guest memory. This helper does the same read by hand with the
/// raw bytes wrapped in `Zeroizing`, so they are overwritten as soon as
/// parsing is done. The parsed `secret` field lands in its own `String`
/// which each caller wraps in `Zeroizing` as well. (serde_json only
/// uses an internal scratch buffer for strings containing escapes,
/// which a prefixed `sk_…` value never does.)
///
/// Every entry point that accepts a `secret` field goes through this
/// instead of a `Json<T>` argument. The two are wire-compatible: the
/// host sends exactly the same JSON either way.
fn read_secret_input<T: DeserializeOwned>() -> FnResult<T> {
    let raw = Zeroizing::new(extism_pdk::input_bytes());
    Ok(extism_pdk::json::from_slice(&raw)?)
}

// The plugin speaks the prefixed format (`pk_…_…`, `sk_…_…`, `blsag_…_…`,
// `ki_…_…`) *exclusively*: every key / signature field is emitted in it
// and only accepted in it. Bare hex is reserved for the pure-Rust library
// API (`from_hex`). So all parsing below goes through `from_prefixed`.

#[derive(Serialize)]
pub struct IdentityOut {
    /// Prefixed secret scalar, e.g. `sk_<64 hex>_<8 hex checksum>`.
    pub secret: String,
    /// Prefixed public key, e.g. `pk_<64 hex>_<8 hex checksum>`.
    pub public: String,
}

#[plugin_fn]
pub fn generate_identity() -> FnResult<Json<IdentityOut>> {
    let id = crate::generate_identity();
    Ok(Json(IdentityOut {
        secret: id.secret_key.to_prefixed(),
        public: id.public_key.to_prefixed(),
    }))
}

#[derive(Deserialize)]
pub struct DerivePublicIn {
    pub secret: String,
}

#[derive(Serialize)]
pub struct DerivePublicOut {
    /// Prefixed public key, e.g. `pk_<64 hex>_<8 hex checksum>`.
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
/// The raw JSON input and the parsed secret are both wrapped in
/// `Zeroizing` so every guest-side copy is overwritten before this
/// function returns (see [`read_secret_input`]).
#[plugin_fn]
pub fn derive_public_key() -> FnResult<Json<DerivePublicOut>> {
    let input: DerivePublicIn = read_secret_input()?;
    let secret = Zeroizing::new(input.secret);
    let sk = SecretKey::from_prefixed(&secret)?;
    Ok(Json(DerivePublicOut {
        public: sk.public_key().to_prefixed(),
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
pub fn sign_vote_str() -> FnResult<Json<SignOut>> {
    let input: SignIn = read_secret_input()?;
    let vote_bytes = input.vote.into_bytes();
    sign_with_bytes(input.secret, &vote_bytes, &input.election_id, &input.ring)
}

/// Sign a ballot whose `vote` field is **hex-encoded bytes**. Decoded to
/// raw bytes before hashing, so any binary payload works. See
/// [`sign_vote_str`] for text ballots.
#[plugin_fn]
pub fn sign_vote_hex() -> FnResult<Json<SignOut>> {
    let input: SignIn = read_secret_input()?;
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
    // Wrap the secret String in `Zeroizing` so its heap allocation is
    // overwritten when this function returns. Together with the
    // `Zeroizing` raw-input buffer in `read_secret_input`, this covers
    // every guest-side copy; only the Extism kernel's copy is out of our
    // reach (see the module docs). The other inputs are public.
    let secret = Zeroizing::new(secret);
    let sk = SecretKey::from_prefixed(&secret)?;
    let ring: Vec<PublicKey> = ring
        .iter()
        .map(|h| PublicKey::from_prefixed(h))
        .collect::<Result<_, _>>()?;
    let proof = crate::sign_vote(&sk, vote, election_id, &ring)?;
    Ok(Json(SignOut {
        signature: proof.signature.to_prefixed(),
        key_image: proof.key_image.to_prefixed(),
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
pub fn is_valid_secret_key() -> FnResult<Json<IsValidSecretOut>> {
    // Same memory hygiene as `sign_with_bytes`: raw input and parsed
    // secret are both `Zeroizing`-wrapped — see the module docs.
    let input: IsValidSecretIn = read_secret_input()?;
    let secret = Zeroizing::new(input.secret);
    Ok(Json(IsValidSecretOut {
        valid: SecretKey::is_valid_prefixed(&secret),
    }))
}

#[derive(Serialize)]
pub struct GenerateNonceOut {
    /// Prefixed verifier nonce, e.g. `nonce_<64 hex>_<8 hex checksum>`.
    /// Pass it verbatim as the `nonce` field of `prove_ownership` /
    /// `verify_ownership`.
    pub nonce: String,
}

/// Verifier-side convenience for Operation D: generate a fresh nonce. See
/// [`crate::generate_nonce`]. The organisation requesting a proof calls
/// this, sends `nonce` to the prover, and both pass it as `nonce`.
#[plugin_fn]
pub fn generate_nonce() -> FnResult<Json<GenerateNonceOut>> {
    Ok(Json(GenerateNonceOut {
        nonce: crate::generate_nonce().to_prefixed(),
    }))
}

#[derive(Deserialize)]
pub struct ProveOwnershipIn {
    pub secret: String,
    pub election_id: String,
    /// The verifier's challenge, a prefixed `nonce_…_…` value (e.g. from
    /// `generate_nonce`). Its tag and checksum are validated; the proof
    /// binds the nonce's raw bytes.
    pub nonce: String,
}

#[derive(Serialize)]
pub struct ProveOwnershipOut {
    /// Prefixed ownership proof, e.g. `own_<128 hex>_<8 hex checksum>`.
    pub proof: String,
}

/// Operation D (prover side): prove ownership of a key image. See
/// [`crate::prove_ownership`]. The raw JSON input and the parsed secret
/// are both wrapped in `Zeroizing` so every guest-side copy is
/// overwritten before this returns; only the Extism kernel's copy is out
/// of our reach (see the module docs).
#[plugin_fn]
pub fn prove_ownership() -> FnResult<Json<ProveOwnershipOut>> {
    let input: ProveOwnershipIn = read_secret_input()?;
    let secret = Zeroizing::new(input.secret);
    let sk = SecretKey::from_prefixed(&secret)?;
    let nonce = Nonce::from_prefixed(&input.nonce)?;
    let proof = crate::prove_ownership(&sk, &input.election_id, nonce.as_bytes());
    Ok(Json(ProveOwnershipOut {
        proof: proof.to_prefixed(),
    }))
}

#[derive(Deserialize)]
pub struct VerifyOwnershipIn {
    pub public: String,
    pub key_image: String,
    pub election_id: String,
    pub nonce: String,
    pub proof: String,
}

#[derive(Serialize)]
pub struct VerifyOwnershipOut {
    pub valid: bool,
}

/// Operation D (verifier side): check an ownership proof using only public
/// inputs. See [`crate::verify_ownership`]. Any parse failure is reported
/// as `{"valid": false}` rather than an error, matching the verify-vote
/// contract.
#[plugin_fn]
pub fn verify_ownership(
    Json(input): Json<VerifyOwnershipIn>,
) -> FnResult<Json<VerifyOwnershipOut>> {
    let valid = verify_ownership_inner(&input).unwrap_or(false);
    Ok(Json(VerifyOwnershipOut { valid }))
}

/// Parse the components and run the ownership check. Returns `None` on any
/// parse failure, which the caller maps to `false`.
fn verify_ownership_inner(input: &VerifyOwnershipIn) -> Option<bool> {
    let public = PublicKey::from_prefixed(&input.public).ok()?;
    let key_image = KeyImage::from_prefixed(&input.key_image).ok()?;
    let nonce = Nonce::from_prefixed(&input.nonce).ok()?;
    let proof = OwnershipProof::from_prefixed(&input.proof).ok()?;
    Some(crate::verify_ownership(
        &public,
        &key_image,
        &input.election_id,
        nonce.as_bytes(),
        &proof,
    ))
}

#[derive(Deserialize)]
pub struct RingDigestIn {
    pub ring: Vec<String>,
}

#[derive(Serialize)]
pub struct RingDigestOut {
    /// Prefixed ring digest, e.g. `ring_<64 hex>_<8 hex checksum>`.
    pub digest: String,
}

/// Canonical digest of an authorised ring. See [`crate::ring_digest`].
/// Input: `{"ring": [pk_…, …]}` in any order. Output: `{"digest": ring_…}`.
/// A malformed entry, a duplicate member or a ring of fewer than two keys
/// is a plugin-level error, exactly as it would be for `sign_vote_*`.
#[plugin_fn]
pub fn ring_digest(Json(input): Json<RingDigestIn>) -> FnResult<Json<RingDigestOut>> {
    let ring: Vec<PublicKey> = input
        .ring
        .iter()
        .map(|h| PublicKey::from_prefixed(h))
        .collect::<Result<_, _>>()?;
    let digest = crate::ring_digest(&ring)?;
    Ok(Json(RingDigestOut {
        digest: digest.to_prefixed(),
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
        .map(|h| PublicKey::from_prefixed(h).ok())
        .collect::<Option<_>>()?;
    let signature = Signature::from_prefixed(&input.signature, ring.len()).ok()?;
    let key_image = KeyImage::from_prefixed(&input.key_image).ok()?;
    Some(crate::verify_vote(
        vote,
        &input.election_id,
        &signature,
        &key_image,
        &ring,
    ))
}
