# Changelog

## [1.0.1] — 2026-10-30

No change to the Rust, WASM or Extism public API, nor to any wire or
serialisation format.

### Security

- Extism plugin: every entry point that accepts a `secret` field
  (`derive_public_key`, `sign_vote_str`, `sign_vote_hex`,
  `is_valid_secret_key`, `prove_ownership`) now reads its raw JSON input
  into a `Zeroizing` buffer, so the guest-side copy of the whole input —
  secret included — is wiped once parsed instead of being left in freed
  memory. Wire-compatible: hosts send exactly the same JSON.

### Changed

- Release archives for Linux now state their linking model in their name:
  `…-linux-gnu-dynamic.tar.gz` (glibc-linked) and
  `…-linux-musl-static.tar.gz` (fully static). Scripts that download the
  v1.0.0 asset names must be updated.
- Release artefacts (native CLI binaries, both WebAssembly bundles and
  their `.tar.gz` archives) are now bit-for-bit reproducible at a fixed
  toolchain, via `scripts/reproducible-build.sh` and
  `scripts/reproducible-tar.sh`. See "Reproducible builds" in the README.
- Dependency updates (`Cargo.lock`).

### Testing

- New end-to-end harness for the Extism plugin (`tests/extism/`), run in CI.

## [1.0.0] — 2026-09-25

Initial release.
