//! Fuzz the byte-level parsers for `PublicKey`, `SecretKey`, `KeyImage`.
//!
//! Each parser must never panic and must produce a value whose byte
//! round-trip equals the input — catching any non-canonical encoding
//! the parser might otherwise accept.

#![no_main]

use crypto_vote::{KeyImage, PublicKey, SecretKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let bytes: [u8; 32] = data[..32].try_into().unwrap();

    if let Ok(pk) = PublicKey::from_bytes(&bytes) {
        assert_eq!(pk.to_bytes(), bytes);
    }
    if let Ok(ki) = KeyImage::from_bytes(&bytes) {
        assert_eq!(ki.to_bytes(), bytes);
    }
    if let Ok(sk) = SecretKey::from_bytes(&bytes) {
        // Secret-key parse strips zero scalars; the canonical-bytes
        // check still guarantees round-trip equality.
        assert_eq!(sk.to_bytes(), bytes);
    }
});
