//! WebAssembly bindings (enabled with `--features wasm`).
//!
//! These are the only functions the browser ever sees. Everything they
//! do is delegate to the pure-Rust API in the rest of the crate, after
//! decoding the input into typed values. We pass:
//!
//!  - **secret material as `Uint8Array`** (raw bytes). The JS caller can
//!    overwrite the buffer with `.fill(0)` once it has been persisted or
//!    used, which is the only way to make the JS-side copy of the
//!    secret unreadable to other scripts running in the page.
//!  - **public material as hex strings** (public keys, signatures,
//!    linking tags). These are not secret, and hex is what every host
//!    API already passes around on the wire.
//!
//! Inside Rust, every temporary buffer that holds secret bytes is
//! wrapped in [`zeroize::Zeroizing`]. The wrapper ensures the WASM
//! linear-memory region containing the secret is overwritten *before*
//! its allocation is returned to the global allocator — without it, the
//! secret would persist in the heap until reallocated, where it could
//! be scraped by debuggers, core dumps, or another script with access
//! to the WASM memory.
//!
//! See the README for the full caller-side discipline; the short
//! version is "persist immediately, then `.fill(0)` the Uint8Array".
//!
//! Errors come back to JS as `JsValue::from_str(...)` so they show up
//! as plain JS `Error` strings rather than panics. We never panic
//! across the WASM boundary on bad input.

use crate::error::Error;
use crate::types::{KeyImage, PublicKey, SecretKey, Signature};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

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
/// Returns a `[secretBytes, publicHex]` pair as a `js_sys::Array`:
///
///  - `secretBytes` is a fresh `Uint8Array` of length 32. The JS caller
///    is expected to persist it (IndexedDB / encrypted storage) and
///    then call `.fill(0)` on it to wipe the in-memory copy. Failing to
///    do so leaves the secret readable by any other script with access
///    to the page's JS heap.
///  - `publicHex` is the 64-character hex encoding of the public key —
///    not secret, ready to be POSTed to the registrar.
///
/// On the Rust side the intermediate `[u8; 32]` holding the secret
/// bytes is wrapped in `Zeroizing` so the WASM linear-memory region
/// gets overwritten before the allocation is freed.
#[wasm_bindgen]
pub fn generate_identity_wasm() -> js_sys::Array {
    let id = crate::generate_identity();

    // The freshly-allocated `[u8; 32]` lives in the WASM heap until it
    // is dropped. Wrapping it in `Zeroizing` guarantees the bytes are
    // overwritten before the allocator reclaims the region.
    let secret_bytes = Zeroizing::new(id.secret_key.to_bytes());
    let secret_js = js_sys::Uint8Array::from(&secret_bytes[..]);

    let arr = js_sys::Array::new();
    arr.push(&secret_js);
    arr.push(&JsValue::from_str(&id.public_key.to_hex()));
    arr
    // `secret_bytes` drops here; its memory is zeroed.
}

/// Browser-facing version of [`crate::sign_vote`] for a **text ballot**.
///
/// `vote` is a `&str`: JavaScript passes a plain string and wasm-bindgen
/// transcodes it to UTF-8 across the boundary, so the bytes hashed here
/// are exactly `new TextEncoder().encode(vote)` — and exactly what the
/// Extism `sign_vote_str` plugin hashes for the same string. That
/// symmetry is what lets a ballot signed here be verified by any
/// flavour. For an arbitrary binary ballot, use [`sign_vote_bytes_wasm`].
///
/// See [`sign_vote_bytes_wasm`] for the shared `secret_bytes`,
/// `election_id`, ring and return-value semantics.
#[wasm_bindgen]
pub fn sign_vote_str_wasm(
    secret_bytes: Vec<u8>,
    vote: &str,
    election_id: &str,
    ring_hex: Vec<String>,
) -> Result<js_sys::Array, JsValue> {
    sign_vote_inner(secret_bytes, vote.as_bytes(), election_id, ring_hex)
}

/// Browser-facing version of [`crate::sign_vote`] for a **binary ballot**.
///
/// `vote` is a `&[u8]` — JavaScript passes a `Uint8Array` of any length
/// (raw Protobuf, embedded NUL bytes, any non-UTF-8 sequence). The bytes
/// are hashed verbatim, so a proof made here verifies under any flavour
/// whose vote bytes match (e.g. the Extism `verify_vote_hex` plugin fed
/// the hex of these same bytes).
///
/// `secret_bytes` is the 32-byte raw secret key (typically a
/// `Uint8Array` the JS caller just read out of storage). The Rust side
/// wraps it in `Zeroizing` immediately, so the WASM-internal copy is
/// overwritten when the function returns. The JS caller is responsible
/// for `.fill(0)`-ing its own `Uint8Array` once the call has returned.
/// `election_id` is a plain JS string — typically a UUID or slug — and
/// is normalised to Unicode NFC inside the crate before hashing (the
/// vote is *not*; it is hashed verbatim).
///
/// Returns a `[signatureHex, keyImageHex]` pair as a `js_sys::Array`.
/// Neither value is secret; hex is convenient for the host API.
#[wasm_bindgen]
pub fn sign_vote_bytes_wasm(
    secret_bytes: Vec<u8>,
    vote: &[u8],
    election_id: &str,
    ring_hex: Vec<String>,
) -> Result<js_sys::Array, JsValue> {
    sign_vote_inner(secret_bytes, vote, election_id, ring_hex)
}

/// Shared signing core for both `sign_vote_*_wasm` entry points:
/// everything except how the vote bytes were obtained from JS.
fn sign_vote_inner(
    secret_bytes: Vec<u8>,
    vote: &[u8],
    election_id: &str,
    ring_hex: Vec<String>,
) -> Result<js_sys::Array, JsValue> {
    // Wrap the WASM-side copy of the secret immediately. Whatever path
    // we take from here (early error, success, panic), the bytes will
    // be overwritten before the Vec's storage is freed.
    let secret = Zeroizing::new(secret_bytes);
    let secret_arr: &[u8; 32] = secret[..].try_into().map_err(|_| {
        JsValue::from_str(&format!(
            "secret must be exactly 32 bytes, got {}",
            secret.len()
        ))
    })?;
    // `SecretKey::from_bytes` clones the 32 bytes into its scalar; the
    // scalar is itself zeroized on `SecretKey::drop`. So even when this
    // function exits, no readable copy of the secret remains on the
    // Rust side.
    let sk = SecretKey::from_bytes(secret_arr).map_err(err_to_js)?;
    let ring = parse_ring(ring_hex)?;
    let proof = crate::sign_vote(&sk, vote, election_id, &ring).map_err(err_to_js)?;

    let arr = js_sys::Array::new();
    arr.push(&JsValue::from_str(&proof.signature.to_hex()));
    arr.push(&JsValue::from_str(&proof.key_image.to_hex()));
    Ok(arr)
}

/// Browser-facing version of [`crate::SecretKey::is_valid_bytes`].
///
/// Returns `true` iff `secret_bytes` is exactly 32 bytes encoding a
/// canonical non-zero scalar. Any malformed input (wrong length,
/// non-canonical encoding, zero scalar) returns `false`.
///
/// As with the `sign_vote_*_wasm` functions, the input is wrapped in
/// `Zeroizing` on the Rust side so the WASM-internal copy is overwritten
/// before its allocation is freed. The JS caller is still responsible
/// for `.fill(0)`-ing its own `Uint8Array` once the call has returned.
#[wasm_bindgen]
pub fn is_valid_secret_key_wasm(secret_bytes: Vec<u8>) -> bool {
    let secret = Zeroizing::new(secret_bytes);
    let Ok(arr) = <&[u8; 32]>::try_from(&secret[..]) else {
        return false;
    };
    SecretKey::is_valid_bytes(arr)
}

/// Derive the public key matching a secret key.
///
/// `secret_bytes` is the 32-byte raw secret key (a `Uint8Array`).
/// Returns the 64-character hex encoding of the matching public key,
/// or a JS error string if `secret_bytes` is malformed (wrong length,
/// non-canonical encoding, zero scalar).
///
/// The derivation is a pure scalar multiplication on Ristretto255 —
/// no randomness — so the same `secret_bytes` always yields the same
/// public key. Useful when a caller has persisted the secret key but
/// needs to recover or re-display the corresponding public key.
///
/// The input is wrapped in `Zeroizing` so the WASM-internal copy is
/// overwritten before its allocation is freed. The JS caller should
/// still `.fill(0)` its own `Uint8Array` once the call has returned.
#[wasm_bindgen]
pub fn derive_public_key_wasm(secret_bytes: Vec<u8>) -> Result<String, JsValue> {
    let secret = Zeroizing::new(secret_bytes);
    let arr: &[u8; 32] = secret[..].try_into().map_err(|_| {
        JsValue::from_str(&format!(
            "secret must be exactly 32 bytes, got {}",
            secret.len()
        ))
    })?;
    let sk = SecretKey::from_bytes(arr).map_err(err_to_js)?;
    Ok(sk.public_key().to_hex())
}

/// Browser-facing version of [`crate::verify_vote`] for a **text
/// ballot**: `vote` is a `&str`, hashed as its UTF-8 bytes. The
/// counterpart of [`sign_vote_str_wasm`] / Extism `verify_vote_str`.
/// For binary ballots use [`verify_vote_bytes_wasm`].
#[wasm_bindgen]
pub fn verify_vote_str_wasm(
    vote: &str,
    election_id: &str,
    signature_hex: &str,
    key_image_hex: &str,
    ring_hex: Vec<String>,
) -> bool {
    verify_vote_inner(vote.as_bytes(), election_id, signature_hex, key_image_hex, ring_hex)
}

/// Browser-facing version of [`crate::verify_vote`] for a **binary
/// ballot**: `vote` is a `&[u8]` (a `Uint8Array`). The counterpart of
/// [`sign_vote_bytes_wasm`] / Extism `verify_vote_hex`.
///
/// No secret material is involved; everything else is hex. Returns a
/// plain `bool`. Any input parsing error is mapped to `false`, because
/// from the host's point of view "not a valid proof" and "not a
/// parseable proof" are the same answer: reject.
#[wasm_bindgen]
pub fn verify_vote_bytes_wasm(
    vote: &[u8],
    election_id: &str,
    signature_hex: &str,
    key_image_hex: &str,
    ring_hex: Vec<String>,
) -> bool {
    verify_vote_inner(vote, election_id, signature_hex, key_image_hex, ring_hex)
}

/// Shared verify core for both `verify_vote_*_wasm` entry points.
fn verify_vote_inner(
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
