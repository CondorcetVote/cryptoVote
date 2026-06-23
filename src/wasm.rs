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
//!  - **public material as prefixed strings** (public keys, signatures,
//!    linking tags), both in and out — e.g. `pk_…_…`, `blsag_…_…`,
//!    `ki_…_…`. This boundary speaks the prefixed format *exclusively*;
//!    bare hex is rejected (it is only accepted by the pure-Rust library
//!    API). None of this material is secret. See [`crate::encoding`].
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
use crate::types::{KeyImage, Nonce, OwnershipProof, PublicKey, SecretKey, Signature};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn err_to_js(e: Error) -> JsValue {
    JsValue::from_str(&format!("{e}"))
}

// The browser bindings speak the prefixed format (`pk_…_…`, `blsag_…_…`,
// `ki_…_…`) *exclusively*: it is what they emit and the only thing they
// accept. Bare hex is reserved for the pure-Rust library API
// (`from_hex`). Forcing the prefixed form at this boundary means every
// value crossing into JS is self-describing and checksum-protected.

/// Parse a list of prefixed public keys (`pk_…_…`).
fn parse_ring(ring: Vec<String>) -> Result<Vec<PublicKey>, JsValue> {
    ring.into_iter()
        .map(|s| PublicKey::from_prefixed(&s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(err_to_js)
}

/// Browser-facing version of [`crate::generate_identity`].
///
/// Returns a `[secretBytes, publicKey]` pair as a `js_sys::Array`:
///
///  - `secretBytes` is a fresh `Uint8Array` of length 32. The JS caller
///    is expected to persist it (IndexedDB / encrypted storage) and
///    then call `.fill(0)` on it to wipe the in-memory copy. Failing to
///    do so leaves the secret readable by any other script with access
///    to the page's JS heap.
///  - `publicKey` is the prefixed encoding of the public key
///    (`pk_<hex>_<checksum>`) — not secret, ready to be POSTed to the
///    registrar.
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
    arr.push(&JsValue::from_str(&id.public_key.to_prefixed()));
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
    ring: Vec<String>,
) -> Result<js_sys::Array, JsValue> {
    sign_vote_inner(secret_bytes, vote.as_bytes(), election_id, ring)
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
/// Returns a `[signature, keyImage]` pair as a `js_sys::Array`, both in
/// the prefixed form (`blsag_…_…`, `ki_…_…`). Neither value is secret.
#[wasm_bindgen]
pub fn sign_vote_bytes_wasm(
    secret_bytes: Vec<u8>,
    vote: &[u8],
    election_id: &str,
    ring: Vec<String>,
) -> Result<js_sys::Array, JsValue> {
    sign_vote_inner(secret_bytes, vote, election_id, ring)
}

/// Shared signing core for both `sign_vote_*_wasm` entry points:
/// everything except how the vote bytes were obtained from JS.
fn sign_vote_inner(
    secret_bytes: Vec<u8>,
    vote: &[u8],
    election_id: &str,
    ring: Vec<String>,
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
    let ring = parse_ring(ring)?;
    let proof = crate::sign_vote(&sk, vote, election_id, &ring).map_err(err_to_js)?;

    let arr = js_sys::Array::new();
    arr.push(&JsValue::from_str(&proof.signature.to_prefixed()));
    arr.push(&JsValue::from_str(&proof.key_image.to_prefixed()));
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
/// Returns the prefixed encoding of the matching public key
/// (`pk_<hex>_<checksum>`), or a JS error string if `secret_bytes` is
/// malformed (wrong length, non-canonical encoding, zero scalar).
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
    Ok(sk.public_key().to_prefixed())
}

/// **Import** a secret key the user pasted in the prefixed form
/// (`sk_<hex>_<checksum>`) and return its 32 raw bytes as a `Uint8Array`.
///
/// This is the bridge between the human-facing string a voter backs up
/// or types into a form and the raw `Uint8Array` every other WASM
/// function consumes for secret material. It validates the `sk_` tag,
/// the checksum, and that the body is a canonical non-zero scalar; on any
/// failure it returns a JS error string (e.g. wrong prefix, mistyped
/// checksum, non-canonical scalar) rather than a silently-wrong key.
///
/// The returned `Uint8Array` **is** the secret: persist it, use it with
/// `sign_vote_*_wasm` / `derive_public_key_wasm`, then `.fill(0)` it — the
/// same discipline as the `secretBytes` from `generate_identity_wasm`.
/// The Rust-side intermediate is wrapped in `Zeroizing`, so no readable
/// copy is left in WASM memory once this returns.
///
/// To validate without materialising the bytes (e.g. live form
/// feedback), use [`is_valid_prefixed_secret_key_wasm`].
#[wasm_bindgen]
pub fn secret_key_from_prefixed_wasm(prefixed: &str) -> Result<js_sys::Uint8Array, JsValue> {
    let sk = SecretKey::from_prefixed(prefixed).map_err(err_to_js)?;
    // `to_bytes` copies the scalar out; keep that copy zeroized once the
    // Uint8Array has been built from it.
    let bytes = Zeroizing::new(sk.to_bytes());
    Ok(js_sys::Uint8Array::from(&bytes[..]))
    // `bytes` and `sk` both zeroize on drop here.
}

/// **Export** a raw secret key as the prefixed string the user can back
/// up (`sk_<hex>_<checksum>`). The inverse of
/// [`secret_key_from_prefixed_wasm`].
///
/// `secret_bytes` is the 32-byte raw key (e.g. the `secretBytes` from
/// `generate_identity_wasm`). Returns a JS error string if it is the
/// wrong length or not a canonical non-zero scalar.
///
/// Hygiene note: the result is a JS `String`, which — unlike a
/// `Uint8Array` — **cannot be wiped** with `.fill(0)`. Call this only at
/// the moment you actually show or download the backup, and drop the
/// reference promptly afterwards. The Rust-side input copy is still
/// wrapped in `Zeroizing`; you remain responsible for `.fill(0)`-ing your
/// own `Uint8Array`.
#[wasm_bindgen]
pub fn secret_key_to_prefixed_wasm(secret_bytes: Vec<u8>) -> Result<String, JsValue> {
    let secret = Zeroizing::new(secret_bytes);
    let arr: &[u8; 32] = secret[..].try_into().map_err(|_| {
        JsValue::from_str(&format!(
            "secret must be exactly 32 bytes, got {}",
            secret.len()
        ))
    })?;
    let sk = SecretKey::from_bytes(arr).map_err(err_to_js)?;
    Ok(sk.to_prefixed())
}

/// Validate a prefixed secret key string (`sk_<hex>_<checksum>`) without
/// constructing anything — handy for live form feedback before the user
/// submits. Returns `true` iff the tag, checksum and a canonical non-zero
/// scalar all check out. The prefixed counterpart of
/// [`is_valid_secret_key_wasm`] (which takes raw bytes).
#[wasm_bindgen]
pub fn is_valid_prefixed_secret_key_wasm(prefixed: &str) -> bool {
    SecretKey::is_valid_prefixed(prefixed)
}

/// Generate a fresh verifier nonce in the prefixed form (`nonce_…_…`),
/// ready to pass as `nonce` to [`prove_ownership_wasm`] /
/// [`verify_ownership_wasm`].
///
/// Browser-facing version of [`crate::generate_nonce`]: 32 random bytes
/// from Web Crypto, wrapped in the same self-describing, checksum-protected
/// format as every other value crossing this boundary. The organisation
/// requesting a proof calls this, sends the string to the prover, and both
/// sides pass it verbatim. The prefix is transport only — the bytes hashed
/// into the proof are the nonce's raw bytes, so any flavour fed the same
/// `nonce_…` string agrees.
#[wasm_bindgen]
pub fn generate_nonce_wasm() -> String {
    crate::generate_nonce().to_prefixed()
}

/// Browser-facing version of [`crate::prove_ownership`].
///
/// Proves that the key image derived from `secret_bytes` for
/// `election_id` is the caller's, bound to `nonce` — the fresh challenge
/// the verifier handed over. The secret key never leaves the device: the
/// returned proof reveals nothing about it.
///
/// `secret_bytes` is the 32-byte raw secret key (a `Uint8Array`); it is
/// wrapped in `Zeroizing` on the Rust side, and the JS caller should still
/// `.fill(0)` its own copy afterwards. `nonce` is a prefixed `nonce_…_…`
/// string (e.g. from `generate_nonce_wasm`); its tag and checksum are
/// validated before use. For a custom/binary context, use the pure-Rust
/// API, which takes opaque `context: &[u8]`.
///
/// Returns the proof in the prefixed form (`own_…_…`). It is public.
#[wasm_bindgen]
pub fn prove_ownership_wasm(
    secret_bytes: Vec<u8>,
    election_id: &str,
    nonce: &str,
) -> Result<String, JsValue> {
    let secret = Zeroizing::new(secret_bytes);
    let arr: &[u8; 32] = secret[..].try_into().map_err(|_| {
        JsValue::from_str(&format!(
            "secret must be exactly 32 bytes, got {}",
            secret.len()
        ))
    })?;
    let sk = SecretKey::from_bytes(arr).map_err(err_to_js)?;
    let nonce = Nonce::from_prefixed(nonce).map_err(err_to_js)?;
    let proof = crate::prove_ownership(&sk, election_id, nonce.as_bytes());
    Ok(proof.to_prefixed())
}

/// Browser-facing version of [`crate::verify_ownership`].
///
/// Uses only public inputs — a verifier external to the election can run
/// it. `public_key`, `key_image`, `nonce` and `proof` are all prefixed
/// strings (`pk_…`, `ki_…`, `nonce_…`, `own_…`); `nonce` must be the same
/// one the prover used. Returns a plain `bool`; any parse failure maps to
/// `false`.
#[wasm_bindgen]
pub fn verify_ownership_wasm(
    public_key: &str,
    key_image: &str,
    election_id: &str,
    nonce: &str,
    proof: &str,
) -> bool {
    let Ok(pk) = PublicKey::from_prefixed(public_key) else {
        return false;
    };
    let Ok(ki) = KeyImage::from_prefixed(key_image) else {
        return false;
    };
    let Ok(nonce) = Nonce::from_prefixed(nonce) else {
        return false;
    };
    let Ok(proof) = OwnershipProof::from_prefixed(proof) else {
        return false;
    };
    crate::verify_ownership(&pk, &ki, election_id, nonce.as_bytes(), &proof)
}

/// Browser-facing version of [`crate::verify_vote`] for a **text
/// ballot**: `vote` is a `&str`, hashed as its UTF-8 bytes. The
/// counterpart of [`sign_vote_str_wasm`] / Extism `verify_vote_str`.
/// For binary ballots use [`verify_vote_bytes_wasm`].
#[wasm_bindgen]
pub fn verify_vote_str_wasm(
    vote: &str,
    election_id: &str,
    signature: &str,
    key_image: &str,
    ring: Vec<String>,
) -> bool {
    verify_vote_inner(vote.as_bytes(), election_id, signature, key_image, ring)
}

/// Browser-facing version of [`crate::verify_vote`] for a **binary
/// ballot**: `vote` is a `&[u8]` (a `Uint8Array`). The counterpart of
/// [`sign_vote_bytes_wasm`] / Extism `verify_vote_hex`.
///
/// No secret material is involved; signature, key image and ring entries
/// are all prefixed strings (bare hex is rejected). Returns a
/// plain `bool`. Any input parsing error is mapped to `false`, because
/// from the host's point of view "not a valid proof" and "not a
/// parseable proof" are the same answer: reject.
#[wasm_bindgen]
pub fn verify_vote_bytes_wasm(
    vote: &[u8],
    election_id: &str,
    signature: &str,
    key_image: &str,
    ring: Vec<String>,
) -> bool {
    verify_vote_inner(vote, election_id, signature, key_image, ring)
}

/// Shared verify core for both `verify_vote_*_wasm` entry points.
fn verify_vote_inner(
    vote: &[u8],
    election_id: &str,
    signature: &str,
    key_image: &str,
    ring: Vec<String>,
) -> bool {
    let ring = match parse_ring(ring) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let signature = match Signature::from_prefixed(signature, ring.len()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let key_image = match KeyImage::from_prefixed(key_image) {
        Ok(k) => k,
        Err(_) => return false,
    };
    crate::verify_vote(vote, election_id, &signature, &key_image, &ring)
}
