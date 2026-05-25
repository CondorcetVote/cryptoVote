# crypto_vote

A pure-Rust cryptographic oracle for **verifiable, anonymous, double-vote-resistant** ballots.

The crate implements the spec in
[`docs/spec.md`](docs/spec.md) — or, equivalently, in the conversation
that drove its creation: a minimal building block that offers exactly
three operations and refuses to take part in anything else.

| # | Operation | Where it runs | Function |
|---|-----------|---------------|----------|
| A | Generate identity | Either side | `generate_identity()` |
| B | Sign a ballot | Voter's device (WebAssembly in the browser) | `sign_vote(secret, vote, election_id, ring)` |
| C | Validate a proof | Host / server | `verify_vote(vote, election_id, signature, key_image, ring)` |

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
deterministic identifier per secret key — the **key image** — which it
must store and de-duplicate against:

1. Retrieve the key image returned by `sign_vote`.
2. Look it up in the host's storage (scoped per election — see
   "Election binding" below).
3. Reject the transaction if it already exists.
4. Otherwise ask `verify_vote` whether the proof is mathematically valid,
   and on success store the key image.

### Election binding

The key image is a function of the secret key only, so the *same*
voter using the *same* secret key in two different elections would
produce the same tag. To make sure a signature from one election
cannot be replayed (or accidentally de-duplicated) against another,
every call to `sign_vote` and `verify_vote` takes an `election_id`
byte string that is mixed into the hash chain. The host should pass a
stable per-election identifier (UUID, slug, hash of the event
configuration, …) on both sides.

This gives two independent layers of defence:

- The **key image** is stored by the host, scoped per `election_id`.
- The **signature** itself only validates against the `election_id`
  it was produced with.

A buggy host that forgets to scope its key-image store would still be
caught by the second layer.

### Ring lifecycle: freeze before voting opens

The full set of authorised public keys (the "ring") is mixed into the
hash chain of every signature, the same way `election_id` and the
ballot bytes are. As a consequence, the ring **must be frozen before
the first ballot is cast** and stay composition-identical for the
whole duration of the election. In practice:

- **All voter identities must be generated and registered before
  voting opens.** The natural moment is during the election's
  enrolment window, which closes when voting opens.
- Once voting opens, the host serves the same ring to every voter and
  uses that same ring at `verify_vote` time. Adding, removing, or
  swapping a member instantly invalidates every signature produced
  under the previous ring — there is no migration path.
- Ring **order** does not matter (both sides canonicalise it
  internally by sorting lexicographically on the compressed point
  encoding), so the host is free to return it in any order over the
  wire. Only the *set* of members matters.
- If a voter is added later, treat it as a new election: new
  `election_id`, fresh ring, fresh key-image store. Ballots from the
  old election remain verifiable as long as the host keeps a snapshot
  of the old ring.

For the same reason, the host should persist the ring it used to
verify each ballot (or at least the election's frozen ring) alongside
the ballot itself, so audits later on can rerun `verify_vote`
deterministically.

## Using the library

```rust
use crypto_vote::{generate_identity, sign_vote, verify_vote};

let alice   = generate_identity();
let bob     = generate_identity();
let charlie = generate_identity();

let ring        = vec![alice.public_key, bob.public_key, charlie.public_key];
let election_id = "550e8400-e29b-41d4-a716-446655440000"; // any stable string (UUID, slug, …)

// Bob signs "option-A" — `bob.secret_key` never leaves Bob's device.
let proof = sign_vote(&bob.secret_key, b"option-A", election_id, &ring).unwrap();

// The host: first dedup `proof.key_image`, then verify.
assert!(verify_vote(
    b"option-A",
    election_id,
    &proof.signature,
    &proof.key_image,
    &ring,
));
```

## Using the command line

```bash
# Generate an identity (one per voter).
$ cryptovote keygen
secret=…
public=…

# Sign a ballot. `ring.txt` is one hex public key per line.
$ cryptovote sign --secret <hex> --vote "option-A" \
    --election-id "election-2026-05" --ring ring.txt
signature=…
key_image=…

# Verify. Exit code 0 = valid, 1 = invalid, 2 = bad input.
$ cryptovote verify --vote "option-A" --election-id "election-2026-05" \
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
const electionId  = "550e8400-e29b-41d4-a716-446655440000"; // plain JS string
const [sigHex, tagHex] = sign_vote_wasm(
    secretHex, ballotBytes, electionId, ringHex,
);

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
    --secret <hex> --vote - --election-id "election-2026-05" --ring ring.txt

cat ballot.json | cryptovote verify --vote - \
    --election-id "election-2026-05" \
    --signature <hex> --key-image <hex> --ring ring.txt
```

## Using from JavaScript / WebAssembly

The library exposes a thin `wasm-bindgen` layer behind the `wasm`
feature. The recipe below assumes `--target web`, which produces an ES
module you can `import` directly from a static page; for bundler
setups (Webpack, Vite, …) build with `--target bundler` instead — the
function signatures are identical, only the import boilerplate changes.

### Build

```bash
wasm-pack build --target web -- --no-default-features --features wasm
```

The resulting `pkg/` directory contains the `.wasm` artefact and the
JS glue. Copy it next to your page (or import it through your
bundler).

### Initialise the module

With `--target web` you must `await` the default export exactly once
before calling anything else; it streams and instantiates the `.wasm`
file:

```js
import init, {
    generate_identity_wasm,
    sign_vote_wasm,
    verify_vote_wasm,
} from "./pkg/crypto_vote.js";

await init();
```

### Operation A — generate an identity

```js
const [secretHex, publicHex] = generate_identity_wasm();

// `secretHex` must stay on the voter's device. The natural store is
// localStorage / IndexedDB, encrypted with a passphrase if you care.
// `publicHex` is what the registrar adds to the authorised ring.
localStorage.setItem("voter_secret", secretHex);
await fetch("/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ public_key: publicHex }),
});
```

### Operation B — sign a ballot

```js
// 1. Encode the ballot ONCE. These exact bytes are what gets signed,
//    what you send to the host, and what the host must store verbatim.
//    Do not re-stringify on the host — verification compares bytes.
const ballotBytes = new TextEncoder().encode(JSON.stringify({ choice: "option-A" }));

// 2. Election context the host has told the page about.
const electionId = "550e8400-e29b-41d4-a716-446655440000";

// 3. The full authorised ring. The host returns it as a plain JSON
//    array of 64-character lowercase hex strings — one per authorised
//    voter, including the current one. The WASM module canonicalises
//    the order internally, so the server can return them in any order
//    (registration order, sorted, whatever):
//
//        GET /api/election/ring
//        200 OK
//        Content-Type: application/json
//        [
//          "84e5498b443e3617cfa8d54d9699922e2733105f287cf5bbbe90174544875b0e",
//          "541e3d09e31ac28016ce4f652f591a4745920aff4103b4e3b272204812d4f153",
//          "abcd...",
//          ...
//        ]
//
//    Each entry is exactly what `PublicKey::to_hex()` produces, i.e.
//    the 32-byte compressed Ristretto encoding rendered as hex.
const ring = await fetch("/api/election/ring").then(r => r.json());

// 4. Sign. `sign_vote_wasm` throws (rejects in JS) on bad inputs
//    (empty vote, empty election ID, signer not in the ring, …) so
//    wrap it in try/catch if you want to surface errors to the user.
const [signatureHex, keyImageHex] = sign_vote_wasm(
    localStorage.getItem("voter_secret"),
    ballotBytes,
    electionId,
    ring,
);

// 5. Send the proof + the raw bytes to the host. Use a multipart or
//    binary-safe body so the bytes survive the trip unchanged.
const form = new FormData();
form.append("election_id", electionId);
form.append("signature", signatureHex);
form.append("key_image", keyImageHex);
form.append("ballot", new Blob([ballotBytes], { type: "application/octet-stream" }));

await fetch("/api/vote", { method: "POST", body: form });
```

### Operation C — verify (server-side or in a Node host)

The same WASM module works in Node.js (or Deno / Bun) for hosts that
prefer to keep verification inside a JS runtime instead of linking the
Rust crate natively:

```js
import init, { verify_vote_wasm } from "./pkg/crypto_vote.js";

await init();

// `ballotBytes` is whatever you stored verbatim when receiving the
// vote — read it back as a Uint8Array without any re-encoding.
const isValid = verify_vote_wasm(
    ballotBytes,
    electionId,
    signatureHex,
    keyImageHex,
    ring,
);

// `verify_vote_wasm` never throws and never returns anything other
// than a boolean: any parse error / malformed input is just `false`.
if (!isValid) {
    return reject("invalid proof");
}
```

### Host-side checklist

Before calling `verify_vote_wasm`, the host should:

1. Read `key_image` from the submission and look it up in its
   per-election store. If present → reject (double vote).
2. Otherwise call `verify_vote_wasm`. On `true`, persist `key_image`
   to the store *atomically with* recording the ballot, so a crash
   between the two cannot let a voter slip through twice.

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
