# Project Guidelines

## Language

Everything is in **English**: code, comments, doc comments, commit messages, PR descriptions.

## Documentation

**The README is the public API documentation. Keep it up to date.**

- Any addition or change to the public API (Rust, WASM, Extism) must be reflected in `README.md`
  before the work is considered done.
- Doc comments (`///`) on every public item — functions, structs, methods, type aliases — are
  mandatory. Explain *why* and *what*, not just *how*.
- Module-level `//!` comments explain the role of the file in the overall architecture.

## Code Style

**Simple and readable beats clever and optimised.**

- Prefer the straightforward implementation. Only optimise when a benchmark or profiler
  identifies a real bottleneck.
- Short functions with a single clear purpose. If a function needs a long comment to explain
  what it does, it should probably be split.
- No unnecessary abstractions: helpers and traits earn their place only when used in at least
  two distinct call sites.

## Rust Conventions

Follow idiomatic Rust — standard library types, ownership, `Result`-based error handling:

- Use `thiserror` for error types (already the pattern in `error.rs`).
- Prefer `?` over explicit `match`/`unwrap` for error propagation inside library code.
- Secret material must be wrapped in `zeroize::Zeroizing` wherever it lives on the heap. Follow
  the existing pattern in `wasm.rs` and `extism.rs`.
- `unwrap()` and `expect()` are only acceptable in tests and in `main()` for truly unrecoverable
  conditions; never in library code.
- No `unsafe` without an explicit safety comment explaining the invariant that makes it sound.

## Testing

**Every behaviour must be covered by a test.**

- New public functions get at least one unit test in a `#[cfg(test)]` block in the same file.
- New API entry points (WASM, Extism) get a corresponding integration test in `tests/`.
- Test both the happy path and the documented error cases (wrong length, bad encoding, zero
  scalar, etc.).
- Frozen protocol vectors belong in `tests/upgrade_vectors.rs`; add an entry whenever a new
  serialisation format is stabilised.
- Run `cargo test` before marking work as done. All tests must pass.

## Build and Test

```bash
cargo check          # fast type-check
cargo test           # full test suite
cargo clippy         # lint — no warnings allowed
```
