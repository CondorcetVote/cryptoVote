//! Fuzz `Signature::from_bytes` against arbitrary input length / content.
//!
//! `Signature::from_bytes` has an internal length precondition driven by
//! a `ring_size` parameter. We drive both axes from the fuzz input and
//! assert: never panic, and on success the round-trip back to bytes is
//! identical.

#![no_main]

use crypto_vote::Signature;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // 1-byte header picks a ring size in the realistic range; the rest
    // is the candidate signature blob.
    let ring_size = (data[0] as usize) % 32;
    let blob = &data[1..];

    if let Ok(sig) = Signature::from_bytes(blob, ring_size) {
        // Re-serialise and assert byte-for-byte equality. Catches any
        // accidental normalisation inside the parser.
        let again = sig.to_bytes();
        assert_eq!(blob.len(), again.len());
        assert_eq!(blob, &again[..]);
    }
});
