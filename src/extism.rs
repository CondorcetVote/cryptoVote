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
//! Three plugin functions are exported, mirroring the public API:
//!
//! | Plugin function   | JSON input shape                                                              | JSON output shape                |
//! |-------------------|-------------------------------------------------------------------------------|----------------------------------|
//! | `generate_identity`    | *(empty)*                                                                   | `{"secret": hex64, "public": hex64}` |
//! | `sign_vote`            | `{"secret": hex64, "vote": hex, "election_id": str, "ring": [hex64, …]}`    | `{"signature": hex, "key_image": hex64}` |
//! | `verify_vote`          | `{"vote": hex, "election_id": str, "signature": hex, "key_image": hex64, "ring": [hex64, …]}` | `{"valid": bool}` |
//! | `is_valid_secret_key`  | `{"secret": hex64}`                                                          | `{"valid": bool}`                |
//!
//! `vote` is hex-encoded *bytes* — the host can put JSON, Protobuf or
//! anything in there, the library treats it opaquely. Hex was picked
//! over base64 to keep the encoding uniform with the rest of the
//! public API (keys, signatures, tags are all hex too); the size cost
//! over base64 is negligible for typical ballot sizes.
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
pub struct SignIn {
    pub secret: String,
    /// Hex-encoded vote bytes. Decoded as opaque bytes — any encoding
    /// (JSON, Protobuf, raw binary) the host chooses is fine; the
    /// library never parses the decoded content.
    pub vote: String,
    pub election_id: String,
    pub ring: Vec<String>,
}

#[derive(Serialize)]
pub struct SignOut {
    pub signature: String,
    pub key_image: String,
}

#[plugin_fn]
pub fn sign_vote(Json(input): Json<SignIn>) -> FnResult<Json<SignOut>> {
    // Partial-move the secret hex String out of the input struct into
    // a `Zeroizing` wrapper so its heap allocation is overwritten when
    // this function returns. This is the most we can clean up from
    // inside the plugin — the JSON parser's intermediate buffers and
    // the Extism PDK's input buffer in WASM linear memory are not
    // under our control. Other fields (`vote`, `election_id`, `ring`)
    // are public and don't need this treatment.
    let secret = Zeroizing::new(input.secret);
    let sk = SecretKey::from_hex(&secret)?;
    let vote_bytes = hex::decode(&input.vote)?;
    let ring: Vec<PublicKey> = input
        .ring
        .iter()
        .map(|h| PublicKey::from_hex(h))
        .collect::<Result<_, _>>()?;
    let proof = crate::sign_vote(&sk, &vote_bytes, &input.election_id, &ring)?;
    Ok(Json(SignOut {
        signature: proof.signature.to_hex(),
        key_image: proof.key_image.to_hex(),
    }))
}

#[derive(Deserialize)]
pub struct VerifyIn {
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

#[plugin_fn]
pub fn verify_vote(Json(input): Json<VerifyIn>) -> FnResult<Json<VerifyOut>> {
    // Mirror the public API contract: a malformed proof is "invalid",
    // not an error. The host gets a clean `{"valid": false}` rather
    // than a thrown plugin error, which keeps the verifier-side flow
    // identical regardless of who sent the bytes.
    let valid = decode_and_verify(&input).unwrap_or(false);
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
    // Same memory-hygiene caveat as `sign_vote`: we wrap the Rust-side
    // copy of the secret in `Zeroizing` so its heap allocation is
    // overwritten before this function returns. The JSON parser's
    // intermediate buffers and the Extism input buffer in WASM linear
    // memory are not under our control — see the module docs.
    let secret = Zeroizing::new(input.secret);
    Ok(Json(IsValidSecretOut {
        valid: SecretKey::is_valid_hex(&secret),
    }))
}

fn decode_and_verify(input: &VerifyIn) -> Option<bool> {
    let vote_bytes = hex::decode(&input.vote).ok()?;
    let ring: Vec<PublicKey> = input
        .ring
        .iter()
        .map(|h| PublicKey::from_hex(h).ok())
        .collect::<Option<_>>()?;
    let signature = Signature::from_hex(&input.signature, ring.len()).ok()?;
    let key_image = KeyImage::from_hex(&input.key_image).ok()?;
    Some(crate::verify_vote(
        &vote_bytes,
        &input.election_id,
        &signature,
        &key_image,
        &ring,
    ))
}
