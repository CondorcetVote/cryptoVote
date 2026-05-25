//! WebAssembly bindings (enabled with `--features wasm`).
//!
//! These are the only functions the browser ever sees. Everything they
//! do is delegate to the pure-Rust API in the rest of the crate, after
//! decoding hex strings into typed values. We pass hex (not raw byte
//! arrays) because that is the format JavaScript code already uses for
//! every other crypto artefact it manipulates, and because it keeps the
//! JS-side glue trivially debuggable.
//!
//! Errors come back to JS as `JsValue::from_str(...)` so they show up
//! as plain JS `Error` strings rather than panics. We never panic
//! across the WASM boundary on bad input.

use crate::error::Error;
use crate::types::{KeyImage, PublicKey, SecretKey, Signature};
use wasm_bindgen::prelude::*;

fn err_to_js(e: Error) -> JsValue {
    JsValue::from_str(&format!("{e}"))
}

/// Parse a list of hex-encoded public keys.
fn parse_ring(ring_hex: Vec<String>) -> Result<Vec<PublicKey>, JsValue> {
    ring_hex
        .into_iter()
        .map(|h| PublicKey::from_hex(&h))
        .collect::<Result<Vec<_>, _>>()
        .map_err(err_to_js)
}

/// Browser-facing version of [`crate::generate_identity`].
///
/// Returns a `[secretHex, publicHex]` pair as a `js_sys::Array`. We use
/// a positional array (rather than a struct) because it keeps the JS
/// call-site dependency-free: `const [sk, pk] = cryptoVote.generate();`.
#[wasm_bindgen]
pub fn generate_identity_wasm() -> js_sys::Array {
    let id = crate::generate_identity();
    let arr = js_sys::Array::new();
    arr.push(&JsValue::from_str(&id.secret_key.to_hex()));
    arr.push(&JsValue::from_str(&id.public_key.to_hex()));
    arr
}

/// Browser-facing version of [`crate::sign_vote`].
///
/// Returns a `[signatureHex, keyImageHex]` pair as a `js_sys::Array`.
///
/// `vote` is a `&[u8]` so JavaScript can pass an arbitrarily large
/// `Uint8Array` (JSON, Protobuf, anything). `election_id` is a plain
/// JS string — typically a UUID or slug.
#[wasm_bindgen]
pub fn sign_vote_wasm(
    secret_key_hex: &str,
    vote: &[u8],
    election_id: &str,
    ring_hex: Vec<String>,
) -> Result<js_sys::Array, JsValue> {
    let sk = SecretKey::from_hex(secret_key_hex).map_err(err_to_js)?;
    let ring = parse_ring(ring_hex)?;
    let proof = crate::sign_vote(&sk, vote, election_id, &ring).map_err(err_to_js)?;

    let arr = js_sys::Array::new();
    arr.push(&JsValue::from_str(&proof.signature.to_hex()));
    arr.push(&JsValue::from_str(&proof.key_image.to_hex()));
    Ok(arr)
}

/// Browser-facing version of [`crate::verify_vote`].
///
/// Returns a plain `bool`. Any input parsing error is mapped to
/// `false`, because from the host's point of view "not a valid proof"
/// and "not a parseable proof" are the same answer: reject.
#[wasm_bindgen]
pub fn verify_vote_wasm(
    vote: &[u8],
    election_id: &str,
    signature_hex: &str,
    key_image_hex: &str,
    ring_hex: Vec<String>,
) -> bool {
    let ring = match parse_ring(ring_hex) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let signature = match Signature::from_hex(signature_hex, ring.len()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let key_image = match KeyImage::from_hex(key_image_hex) {
        Ok(k) => k,
        Err(_) => return false,
    };
    crate::verify_vote(vote, election_id, &signature, &key_image, &ring)
}
