# crypto_vote

A pure-Rust cryptographic oracle for **verifiable, anonymous, double-vote-resistant** ballots.

The crate implements the spec in
[`docs/spec.md`](docs/spec.md) — or, equivalently, in the conversation
that drove its creation: a minimal building block that offers exactly
three operations and refuses to take part in anything else.

| # | Operation | Where it runs | Function |
|---|-----------|---------------|----------|
| A | Generate identity | Either side | `generate_identity()` |
| B | Sign a ballot | Voter's device (WebAssembly in the browser) | `sign_vote(secret, vote, ring)` |
| C | Validate a proof | Host / server | `verify_vote(vote, signature, key_image, ring)` |

## Cryptographic choices

- **Curve**: Ristretto255 (`curve25519-dalek`). Prime-order, constant-time, pure Rust.
- **Ring signature scheme**: BLSAG (Back's Linkable Spontaneous Anonymous Group),
  via the [`nazgul`](https://crates.io/crates/nazgul) crate.
- **Hash**: Blake2b-512 (`blake2` crate). Natively 64-byte output, fed
  directly into `Scalar::from_hash`.
- **CSPRNG**: `OsRng`, which on `wasm32` delegates to `Crypto.getRandomValues`
  through the `getrandom` crate's `js` feature.

## Anti-double-vote contract

The module never tells the host whether a voter has already voted.
That decision belongs to the host. The protocol gives the host one
deterministic identifier per (secret key, ring) pair — the **key image**
— which it must store and de-duplicate against:

1. Retrieve the key image returned by `sign_vote`.
2. Look it up in the host's storage.
3. Reject the transaction if it already exists.
4. Otherwise ask `verify_vote` whether the proof is mathematically valid,
   and on success store the key image.

## Using the library

```rust
use crypto_vote::{generate_identity, sign_vote, verify_vote};

let alice   = generate_identity();
let bob     = generate_identity();
let charlie = generate_identity();

let ring = vec![alice.public_key, bob.public_key, charlie.public_key];

// Bob signs "option-A" — `bob.secret_key` never leaves Bob's device.
let proof = sign_vote(&bob.secret_key, b"option-A", &ring).unwrap();

// The host: first dedup `proof.key_image`, then verify.
assert!(verify_vote(b"option-A", &proof.signature, &proof.key_image, &ring));
```

## Using the command line

```bash
# Generate an identity (one per voter).
$ cryptovote keygen
secret=…
public=…

# Sign a ballot. `ring.txt` is one hex public key per line.
$ cryptovote sign --secret <hex> --vote "option-A" --ring ring.txt
signature=…
key_image=…

# Verify. Exit code 0 = valid, 1 = invalid, 2 = bad input.
$ cryptovote verify --vote "option-A" \
    --signature <hex> --key-image <hex> --ring ring.txt
valid
```

## Vote payload format

The library treats the vote as **opaque bytes** — `sign_vote` and
`verify_vote` both take `&[u8]`, with no size limit and no parsing.
JSON, Protobuf, raw text, or arbitrary binary all work the same way.

**The contract for the host:** what you sign is what you store is what
you verify, byte-for-byte. If the host re-encodes the payload between
receiving it and verifying it — JSON re-serialisation, BOM stripping,
line-ending normalisation, Unicode normalisation, lowercasing,
anything — verification *will* fail, because Blake2b is sensitive to
every single byte. The safe rule is: persist the raw bytes received
from the voter, and hand those same bytes back to `verify_vote`.

### Large or structured payloads in the browser

`sign_vote_wasm` accepts a `Uint8Array` of any length. The natural
pattern for a JSON ballot is to encode it once on the voter's device
and pass the resulting bytes everywhere afterwards:

```js
const ballotBytes = new TextEncoder().encode(JSON.stringify(form));
const [sigHex, tagHex] = sign_vote_wasm(secretHex, ballotBytes, ringHex);

// Send `ballotBytes` (the same Uint8Array), `sigHex` and `tagHex`
// to the host. The host stores `ballotBytes` verbatim — it must
// never JSON.parse + JSON.stringify the payload, or verification
// will fail.
```

### Large or structured payloads on the CLI

The `--vote` flag accepts `-` to read the ballot from standard input.
Use it for anything that exceeds your shell's argv limit, contains
newlines, or is binary:

```bash
cat ballot.json | cryptovote sign \
    --secret <hex> --vote - --ring ring.txt

cat ballot.json | cryptovote verify \
    --vote - --signature <hex> --key-image <hex> --ring ring.txt
```

## Building for the browser

The library exposes a thin `wasm-bindgen` layer behind the `wasm`
feature. To produce a browser-ready module:

```bash
wasm-pack build --target web -- --no-default-features --features wasm
```

The resulting `pkg/` directory contains the `.wasm` artefact and JS
glue. The exported functions are `generate_identity_wasm`,
`sign_vote_wasm` and `verify_vote_wasm`; they take and return hex
strings, mirroring the CLI.

## Tests

```bash
cargo test
```

Tests cover round-trips, the deterministic-tag property, ring-order
independence, and every documented "invalid" case (tampered vote,
tampered signature, swapped tag, wrong ring, malformed inputs).

## Layout

```
src/
├── lib.rs        — crate entry point, re-exports, top-level docs
├── error.rs      — `Error` enum (input parsing only)
├── types.rs      — PublicKey / SecretKey / Signature / KeyImage / VoteProof
├── identity.rs   — Operation A
├── signing.rs    — Operation B (with ring canonicalisation)
├── verifying.rs  — Operation C
├── wasm.rs       — wasm-bindgen layer (feature-gated)
└── main.rs       — CLI binary
tests/
└── integration.rs
```
