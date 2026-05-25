# crypto_vote

A pure-Rust cryptographic oracle for **verifiable, anonymous, double-vote-resistant** ballots.

The crate is a minimal building block that offers exactly three
operations and refuses to take part in anything else.

| # | Operation | Where it runs | Function |
|---|-----------|---------------|----------|
| A | Generate identity | Either side | `generate_identity()` |
| B | Sign a ballot | Voter's device (WebAssembly in the browser) | `sign_vote(secret, vote, election_id, ring)` |
| C | Validate a proof | Host / server | `verify_vote(vote, election_id, signature, key_image, ring)` |

## Cryptographic choices

- **Curve**: Ristretto255 (`curve25519-dalek`). Prime-order, constant-time, pure Rust.
- **Ring signature scheme**: an experimental BLSAG (Back's Linkable
  Spontaneous Anonymous Group) variant implemented locally from the
  LSAG/BLSAG equations, with election-scoped key images.
- **Hash**: Blake2b-512 (`blake2` crate). Natively 64-byte output, fed
  directly into `Scalar::from_hash`.
- **CSPRNG**: `SysRng`, which on `wasm32` delegates to `Crypto.getRandomValues`
  through the `getrandom` crate's `wasm_js` feature.

## Anti-double-vote contract

The module never tells the host whether a voter has already voted.
That decision belongs to the host. The protocol gives the host one
deterministic identifier per `(secret key, election_id)` pair — the
**key image** — which it must store and de-duplicate against:

1. Retrieve the key image returned by `sign_vote`.
2. Look it up in the host's storage.
3. Reject the transaction if it already exists.
4. Otherwise ask `verify_vote` whether the proof is mathematically valid,
   and on success store the key image.

### Election binding

The key image is a function of both the secret key and the
`election_id`. The same voter using the same secret key twice in one
election produces the same tag, so double voting is detectable; the
same voter using that key in another election produces a different tag,
so public proofs are not linkable across elections just by comparing
key images.

Every call to `sign_vote` and `verify_vote` also mixes the same
`election_id` byte string into the BLSAG challenge chain. The host
should pass a stable per-election identifier (UUID, slug, hash of the
event configuration, …) on both sides.

This gives two election-context checks:

- The **key image** is itself scoped by `election_id`.
- The **signature** itself only validates against the `election_id`
  it was produced with.

The library normalises `election_id` to **Unicode NFC** before
hashing, on both the signing and the verification side. Callers can
therefore pass the same logical identifier in any Unicode form
(NFC, NFD, mixed) without breaking verification — the typical case
where a server stores the ID in one normalisation and the voter's
page receives it in another no longer silently invalidates every
ballot. ASCII identifiers are NFC by definition, so UUIDs and slugs
are unaffected.

### Ring size and the anonymity set

The cryptography guarantees the verifier cannot tell **which** member of
the ring produced a given signature — but the anonymity set is exactly
the ring. A ring of size *n* gives a `1/n` chance of guessing the signer
uniformly at random, and **no more**:

- **n = 2**: the protocol still validates, but the "anonymity" is
  binary — every ballot leaks down to "voter A or voter B". The
  library accepts it because cryptographically it is sound, not
  because it is privacy-meaningful. Treat it as a debugging
  configuration, not a production one.
- **n < 8**: real-world side-channels (registration order, login
  timing, IP correlation on the host) usually let an observer narrow
  the set further. Treat anything below 8 as practically
  de-anonymising.
- **n ≥ 16**: a reasonable floor for a real ballot. Larger rings cost
  more (`O(n)` for both signing and verification, plus signature size
  of `32 * (1 + n)` bytes), so pick the largest ring your latency
  budget allows.

The minimal `n = 2` floor is enforced inside the library; **picking a
useful n is the host's responsibility**.

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

## Build matrix

The release workflow produces nine artefacts; the same commands work
locally. Pick the triple/flavour that matches your need, install its
one-off prerequisite, then run the matching build command. Edition 2024
implies Rust ≥ 1.85; CI tracks `stable`.

| Triple — flavour | Build host | One-off setup | Output |
|---|---|---|---|
| `x86_64-unknown-linux-gnu` | Linux x64 | system C linker (any dev box has one) | dynamic ELF, ~700 KB |
| `x86_64-unknown-linux-musl` | Linux x64 | `musl-tools` (provides `musl-gcc`) | **static ELF**, ~800 KB |
| `aarch64-unknown-linux-gnu` | Linux x64 or arm | `gcc-aarch64-linux-gnu` cross-toolchain | dynamic ELF |
| `aarch64-unknown-linux-musl` | Linux x64 or arm | none — uses `rust-lld` | **static ELF** |
| `riscv64gc-unknown-linux-gnu` | Linux x64 or arm | `gcc-riscv64-linux-gnu` cross-toolchain | dynamic ELF |
| `aarch64-apple-darwin` | macOS arm (M-series) | Xcode Command Line Tools | Mach-O |
| `wasm32-unknown-unknown` — wasm-bindgen | any | `cargo install wasm-pack` | ES-module bundle for browsers |
| `wasm32-wasip1` — plain lib | any | none — uses `rust-lld` | bare WASI module |
| `wasm32-wasip1` — **Extism plugin** | any | none — uses `rust-lld` | single `.wasm` for every Extism host SDK |

> No `riscv64gc-unknown-linux-musl` row: rustup's bundle for that Tier 2
> target is missing parts of musl libgcc_s, so `rust-lld` cannot link
> statically. For a static RISC-V build, use
> [`cross`](https://github.com/cross-rs/cross) (Docker-based) instead.

> Install commands below are **Debian/Ubuntu** (`apt`); adapt to your
> distribution (`dnf`, `pacman`, `zypper`, `brew`, …) or use
> [`cross`](https://github.com/cross-rs/cross) for a Docker-based path
> that needs nothing on the host. CI runs on `ubuntu-latest`, which is
> why the upstream pipeline uses apt.

### Build commands

Standard template — works as-is for `x86_64-unknown-linux-gnu`,
`x86_64-unknown-linux-musl` (after `apt install musl-tools`) and
`aarch64-apple-darwin` (on a macOS host):

```bash
cargo build --release --locked --target <TRIPLE> --bin cryptovote
# → target/<TRIPLE>/release/cryptovote
```

Three cross-Linux rows need a linker selector — set it in the
environment, then run the same command:

```bash
# aarch64-unknown-linux-gnu  (after `apt install gcc-aarch64-linux-gnu`)
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc

# aarch64-unknown-linux-musl  (no apt package needed)
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld

# riscv64gc-unknown-linux-gnu  (after `apt install gcc-riscv64-linux-gnu`)
export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER=riscv64-linux-gnu-gcc
```

Browser WASM uses `wasm-pack` (which wraps `cargo build` and emits JS
glue alongside the `.wasm`):

```bash
wasm-pack build --release --target web --out-dir pkg-browser \
    -- --no-default-features --features wasm --locked
# → pkg-browser/{crypto_vote.js, crypto_vote_bg.wasm, …}
```

`--target web` emits an ES module you can `import` from a static page;
switch to `--target bundler` for Webpack/Vite (signatures unchanged).
`--no-default-features` drops `clap`; `--features wasm` enables
`wasm-bindgen`, `js-sys`, and the `getrandom/wasm_js` backend so
randomness comes from `Crypto.getRandomValues`.

Server-side WASM is a plain library build with **no** features
enabled — `getrandom` autoselects WASI's `random_get`:

```bash
cargo build --release --locked --target wasm32-wasip1 --lib --no-default-features
# → target/wasm32-wasip1/release/crypto_vote.wasm
```

`wasm64-unknown-unknown` is a Tier 3 nightly-only target with poor
dep support, which is why `wasm32-wasip1` is the documented
server-side option.

The Extism flavour is the same target with `--features extism`
instead of no features:

```bash
cargo build --release --locked --target wasm32-wasip1 --lib --no-default-features --features extism
# → target/wasm32-wasip1/release/crypto_vote.wasm   (~360 KB)
```

See [Extism plugin](#extism-plugin) for the JS-side usage.

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

# Sign a ballot. `ring.txt` is one hex public key per line; keep the
# secret in a file or pass `--secret -` to read it from stdin.
$ cryptovote sign --secret-file secret.hex --vote "option-A" \
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

Note that the vote payload is treated as *raw bytes* and is never
normalised by the library — unlike `election_id`, which is forced to
NFC. The asymmetry is deliberate: the election ID is a *label* the
host controls and re-emits across encodings, so normalising it makes
the API robust; the vote is *content* the host stores verbatim, so
normalising it would silently change what was signed.

### Large or structured payloads in the browser

`sign_vote_wasm` accepts a `Uint8Array` of any length. The natural
pattern for a JSON ballot is to encode it once on the voter's device
and pass the resulting bytes everywhere afterwards:

```js
const ballotBytes = new TextEncoder().encode(JSON.stringify(form));
const electionId  = "550e8400-e29b-41d4-a716-446655440000"; // plain JS string
const [sigHex, tagHex] = sign_vote_wasm(
    secretBytes, ballotBytes, electionId, ringHex,
);
// `secretBytes` is the `Uint8Array` returned by `generate_identity_wasm`
// (or read back from your store). Wipe it with `secretBytes.fill(0)`
// as soon as you no longer need it in memory.

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
  --secret-file secret.hex --vote - --election-id "election-2026-05" --ring ring.txt

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

See the [Build matrix](#build-matrix) above for the full command and
flag breakdown. The short version, run from the crate root:

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
// The secret comes back as a `Uint8Array` (32 raw bytes); the public
// key as a hex string. The asymmetry is deliberate: a JS string is
// immutable, so once a secret has been turned into one it cannot be
// erased from the JS heap until the GC eventually collects it. A
// `Uint8Array` is a mutable buffer the caller can wipe explicitly with
// `.fill(0)` once the secret has been used or persisted.
const [secretBytes, publicHex] = generate_identity_wasm();

// 1. Persist `secretBytes` wherever you want it to live across
//    sessions. The library does not care which store you pick.
await persistVoterSecret(secretBytes);

// 2. Register the public key with the host.
await fetch("/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ public_key: publicHex }),
});

// 3. Wipe the in-memory copy. After this point the only readable
//    instance of the secret is whatever your `persistVoterSecret`
//    produced — nothing is sitting around in the JS heap.
secretBytes.fill(0);
```

> **Note on the threat model.** Wiping the JS-side `Uint8Array` does
> not protect against XSS / a malicious script running *while the
> secret is still loaded*. What it does protect against is post-hoc
> memory inspection: core dumps, devtools snapshots taken later, swap
> partitions, extensions that scan page memory periodically. The
> window of exposure is reduced to the smallest interval the caller
> can manage. The library does its share by `Zeroizing` every
> Rust-side copy of the secret automatically.

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

// 4. Read the secret bytes back from wherever you persisted them.
//    `sign_vote_wasm` takes a `Uint8Array` of length 32. Wrap the call
//    in try/finally so the in-memory copy of the secret is wiped even
//    on error.
const secretBytes = await loadVoterSecret();
let signatureHex, keyImageHex;
try {
    // `sign_vote_wasm` throws on bad inputs (empty vote, empty election
    // ID, secret of the wrong length, signer not in the ring, …). The
    // Rust side wraps the incoming bytes in `Zeroizing` so the WASM
    // linear-memory copy is wiped on return.
    [signatureHex, keyImageHex] = sign_vote_wasm(
        secretBytes,
        ballotBytes,
        electionId,
        ring,
    );
} finally {
    // 5. Wipe the JS-side copy of the secret as soon as signing is
    //    done. The `Uint8Array` is the only place the secret lived in
    //    the JS heap; after `.fill(0)` it is unreadable.
    secretBytes.fill(0);
}

// 6. Send the proof + the raw bytes to the host. Use a multipart or
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

## Extism plugin

The Extism flavour ships **one `.wasm` artefact that runs in every
Extism host SDK** — browser via `@extism/extism`, Node, Deno, Bun,
Python, Go, Rust, Java, even the standalone `extism` CLI. Same binary,
same calls, regardless of the host language. Build it with
`--features extism --target wasm32-wasip1` (see the build matrix
above); WASI provides the RNG, no extra wiring required.

### Recommended split: pick the right flavour per role

The two flavours are **not interchangeable** for secret-handling code.
The architectural split that matches their trade-offs:

| Role | Flavour | Why |
|---|---|---|
| **Voter device** (browser, signs ballots) | wasm-bindgen | Secret is exposed as a mutable `Uint8Array` that the JS caller can `.fill(0)`. Every Rust-side temporary is `Zeroizing`-wrapped. This is the only flavour built around memory hygiene for the secret. |
| **Verifier** (server, mobile app, audit tool, CLI tooling, …) | **Extism** | Verification never touches a secret — `verify_vote` only handles public bytes (signature, key image, ring, ballot). One binary supports verifiers written in any host language. |

The Extism flavour *can* technically run `sign_vote` and
`generate_identity`, but doing so on a voter device degrades secret
hygiene compared to wasm-bindgen — see the next subsection. For
verifiers and non-secret-handling tooling, the Extism flavour is the
right default.

### Secret-hygiene trade-off vs wasm-bindgen

Going through JSON means the secret key transits as a hex string in
the plugin's input/output buffer. Three protections that the
wasm-bindgen flavour provides are weakened or lost:

- The **Rust-side intermediate `String`** holding the parsed secret
  *is* wrapped in `Zeroizing` (its heap allocation is overwritten when
  `sign_vote` returns). However the JSON parser's internal buffers and
  the Extism PDK's input buffer in WASM linear memory are not under
  our control.
- The **JS-side `String`** holding the secret is **immutable** — the
  host cannot call `.fill(0)` on it. It lives until V8 garbage-collects
  it (no guaranteed timing).
- The **Extism input/output buffers** in WASM linear memory may
  persist between plugin calls (Extism re-uses the instance), so the
  secret bytes can linger across calls until a future allocation
  overwrites the region.

Net effect: the Extism flavour reduces *post-hoc* memory hygiene
(core dumps, devtools snapshots taken later, swap to disk, periodic
memory scans). It does **not** change the *live* attack surface — a
script running in the same context while the secret is in memory can
read it under both flavours. If your threat model prioritises the
post-hoc class, sign on a voter device with the wasm-bindgen flavour.

### Plugin function signatures

| Plugin function | JSON input | JSON output |
|---|---|---|
| `generate_identity` | *(empty)* | `{"secret": <hex64>, "public": <hex64>}` |
| `sign_vote` | `{"secret": <hex64>, "vote": <hex>, "election_id": <str>, "ring": [<hex64>, …]}` | `{"signature": <hex>, "key_image": <hex64>}` |
| `verify_vote` | `{"vote": <hex>, "election_id": <str>, "signature": <hex>, "key_image": <hex64>, "ring": [<hex64>, …]}` | `{"valid": <bool>}` |

`vote` is hex-encoded *bytes* — the host can put JSON, Protobuf, or
arbitrary binary in there; the library treats it opaquely. Hex was
picked over base64 for consistency with the rest of the public API.

### Browser example

> The browser snippet below exercises all three plugin functions for
> completeness, but in a real deployment a voter device should sign
> with the [wasm-bindgen flavour](#using-from-javascript--webassembly)
> for better secret hygiene. The Extism flavour in the browser is
> idiomatic for *verifier* roles: audit pages, results dashboards,
> mobile webview verifiers, etc.

```js
// One-time install:  npm install @extism/extism
import createPlugin from "@extism/extism";

// `useWasi: true` is required because the plugin is built for
// wasm32-wasip1 (so `SysRng` can read random bytes from the WASI
// shim). The browser SDK ships a WASI polyfill internally.
const plugin = await createPlugin(
    "/static/crypto_vote-extism.wasm",
    { useWasi: true },
);

// --- Operation A — generate an identity ---
const { secret, public: publicHex } = await plugin
    .call("generate_identity", "")
    .then(out => out.json());

// `secret` is a 64-char hex string. Persist it however you want; this
// flavour does not offer the `.fill(0)` zeroisation hook that the
// wasm-bindgen flavour does.
await persistVoterSecret(secret);

// --- Operation B — sign a ballot ---
const ballotBytes = new TextEncoder().encode(JSON.stringify({ choice: "option-A" }));
const ballotHex   = Array.from(ballotBytes, b => b.toString(16).padStart(2, "0")).join("");

const ring = await fetch("/api/election/ring").then(r => r.json());

const { signature, key_image } = await plugin
    .call("sign_vote", JSON.stringify({
        secret,
        vote:        ballotHex,
        election_id: "election-2026",
        ring,
    }))
    .then(out => out.json());

// --- Operation C — verify (also works server-side; see below) ---
const { valid } = await plugin
    .call("verify_vote", JSON.stringify({
        vote:        ballotHex,
        election_id: "election-2026",
        signature,
        key_image,
        ring,
    }))
    .then(out => out.json());
```

### Node.js / Deno / Bun example

**Same code as the browser** — that is the whole point of the Extism
flavour. The only difference is how you load the `.wasm` (a file path
on the server, a URL in the browser):

```js
import createPlugin from "@extism/extism";
import { readFileSync } from "node:fs";

const plugin = await createPlugin(
    { wasm: [{ data: readFileSync("./crypto_vote-extism.wasm") }] },
    { useWasi: true },
);

const { valid } = await plugin
    .call("verify_vote", JSON.stringify({ /* ... same shape ... */ }))
    .then(out => out.json());
```

The host SDK is also available for [Python](https://github.com/extism/python-sdk),
[Go](https://github.com/extism/go-sdk),
[Rust](https://github.com/extism/extism/tree/main/runtime),
[Java](https://github.com/extism/java-sdk), and others — the JSON
shapes above are identical for all of them.

### Quick smoke test from the CLI

The `extism` standalone CLI is the fastest way to confirm the plugin
loads and behaves correctly before integrating it anywhere:

```bash
# Install once: cargo install extism-cli   (or grab a release binary)
extism call crypto_vote-extism.wasm generate_identity --wasi
# → {"secret":"…","public":"…"}
```

## Tests

```bash
cargo test
```

Tests cover round-trips, same-election deterministic tags,
cross-election tag separation, ring-order independence, bit-level
malleability resistance on both the signature and the key image, and
every documented "invalid" case (tampered vote, tampered signature,
swapped tag, wrong ring, subset/superset ring, malformed inputs).

### Fuzzing

A `cargo-fuzz` harness lives in [`fuzz/`](fuzz/) with four targets:

```bash
cargo install cargo-fuzz   # one-off
cargo +nightly fuzz run verify_vote      # parse + verify pipeline
cargo +nightly fuzz run parse_signature  # Signature::from_bytes
cargo +nightly fuzz run parse_keys       # PublicKey / SecretKey / KeyImage
cargo +nightly fuzz run roundtrip        # sign → verify differential
```

The `fuzz/` package is excluded from the main workspace so it does
not affect stable builds.

## Layout

```
src/
├── lib.rs            — crate entry point, re-exports, top-level docs
├── error.rs          — `Error` enum (input parsing only)
├── types.rs          — PublicKey / SecretKey / Signature / KeyImage / VoteProof
├── identity.rs       — Operation A
├── blsag.rs          — Experimental election-scoped BLSAG implementation
├── signing.rs        — Operation B (ring canonicalisation + NFC of election_id)
├── verifying.rs      — Operation C
├── wasm.rs           — wasm-bindgen layer (feature-gated, Zeroizing secrets)
├── extism.rs         — Extism PDK layer (feature-gated, JSON-over-WASI)
└── main.rs           — CLI binary
tests/
├── integration.rs    — public-API round-trips, malleability, negative paths
└── upgrade_vectors.rs — frozen test vectors (protocol-drift tripwires)
fuzz/
├── Cargo.toml        — separate package, excluded from the workspace
└── fuzz_targets/     — four cargo-fuzz harnesses (see "Fuzzing")
```

## License

This project is licensed under the **GNU Affero General Public License
v3.0 or later** (AGPL-3.0-or-later). See [LICENSE](LICENSE) for the
full text.

The AGPL is a strong copyleft licence. In short: anyone running a
modified version of this code as a network service must make their
modifications available to its users. If that obligation is
incompatible with your use case, please open an issue before
integrating the crate.
