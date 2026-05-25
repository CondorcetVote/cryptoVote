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

The release workflow produces five artefacts. The same commands work
locally — pick the row that matches what you actually need.

| Target | Use case | Extra toolchain (beyond `rustup target add`) |
|---|---|---|
| `x86_64-unknown-linux-gnu` | Native x64 Linux CLI (glibc-linked) | a working system C linker (any dev box has one) |
| `x86_64-unknown-linux-musl` | Fully static x64 Linux CLI (any distro) | a musl C toolchain providing `musl-gcc` |
| `aarch64-unknown-linux-gnu` | Native ARM64 / ARMv9 Linux CLI | a cross-toolchain providing `aarch64-linux-gnu-gcc` |
| `wasm32-unknown-unknown` (via `wasm-pack`) | Browser ES module | `cargo install wasm-pack` |
| `wasm32-wasip1` | Server-side WASM (wasmtime, wasmer, …) | none — `rust-lld` is used automatically |

The crate uses Rust edition 2024 (implicit toolchain floor: 1.85). CI
tracks `stable`; no stricter MSRV is advertised because it would be an
unverified promise.

> The install commands below are **Debian/Ubuntu** examples (`apt`).
> Substitute your distribution's package manager: `dnf` on Fedora,
> `pacman` on Arch, `zypper` on openSUSE, `brew` on macOS, etc. The
> package names usually map directly — search for `musl-gcc` /
> `aarch64-linux-gnu-gcc` on your distro to find the right one. The
> CI workflow runs on `ubuntu-latest`, which is why upstream artefacts
> use the apt path.

### Native x86_64 Linux CLI

Prerequisite: a working system C linker. Any dev machine already has
one (`build-essential` on Debian/Ubuntu, `base-devel` on Arch, Xcode CLT
on macOS, …). Nothing crypto_vote-specific to install.

```bash
cargo build --release --locked \
    --target x86_64-unknown-linux-gnu --bin cryptovote
# → target/x86_64-unknown-linux-gnu/release/cryptovote
```

### Static x86_64 Linux CLI (musl)

Produces a fully self-contained binary with no dynamic libc dependency,
so the same file runs on any Linux distribution regardless of its
installed glibc version. Slightly larger than the glibc build (~10–15 %)
in exchange for portability.

Prerequisite: a musl C toolchain that provides `musl-gcc`. Cargo
auto-detects it for this target — no env var needed.

```bash
# Debian / Ubuntu — adjust for your distro.
sudo apt-get install -y musl-tools          # Debian/Ubuntu
#   Fedora:  sudo dnf install musl-gcc
#   Arch:    sudo pacman -S musl
#   macOS:   brew install FiloSottile/musl-cross/musl-cross

cargo build --release --locked \
    --target x86_64-unknown-linux-musl --bin cryptovote
# → target/x86_64-unknown-linux-musl/release/cryptovote
```

The resulting binary has no `.so` dependencies (`ldd` reports
"statically linked"); copy it anywhere, no install step needed.

### Native ARM64 Linux CLI

ARMv9-A cores (Cortex-A510, A710, A720, X1+ …) are 64-bit ARM and use
the AArch64 ISA, so this is also the right target for "native ARMv9"
— there is no separate Rust triple for ARMv9 because ARMv9-A *is*
AArch64.

Prerequisite: a cross-toolchain that provides an `aarch64-linux-gnu-gcc`
binary (used as the linker driver) plus ARM64 glibc + crt files.

```bash
# Debian / Ubuntu — adjust for your distro.
sudo apt-get install -y gcc-aarch64-linux-gnu   # Debian/Ubuntu
#   Fedora:  sudo dnf install gcc-aarch64-linux-gnu
#   Arch:    sudo pacman -S aarch64-linux-gnu-gcc       (from AUR)
#   macOS:   brew install aarch64-linux-gnu-gcc          (from messense/macos-cross-toolchains)

# Tell Cargo which linker to use for the target triple.
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
cargo build --release --locked \
    --target aarch64-unknown-linux-gnu --bin cryptovote
# → target/aarch64-unknown-linux-gnu/release/cryptovote
```

If a packaged cross-toolchain is not available on your platform, the
[`cross`](https://github.com/cross-rs/cross) tool (Docker-based) builds
the same artefact without touching your host:

```bash
cargo install cross
cross build --release --locked --target aarch64-unknown-linux-gnu --bin cryptovote
```

### Browser WASM (`wasm32-unknown-unknown` via `wasm-pack`)

```bash
wasm-pack build \
    --release \
    --target web \
    --out-dir pkg-browser \
    -- \
    --no-default-features \
    --features wasm \
    --locked
# → pkg-browser/{crypto_vote.js, crypto_vote_bg.wasm, ...}
```

`--target web` emits ES-module glue suitable for `import` from a
static page. Replace by `--target bundler` for Webpack / Vite — the
exported function signatures are identical.

`--no-default-features` drops the `cli` feature so `clap` and the
binary entry point are not pulled into the WASM bundle.
`--features wasm` enables `wasm-bindgen`, `js-sys`, and the
`getrandom/wasm_js` backend so randomness comes from
`Crypto.getRandomValues`.

### Server-side WASM (`wasm32-wasip1`)

```bash
cargo build --release --locked \
    --target wasm32-wasip1 --lib --no-default-features
# → target/wasm32-wasip1/release/crypto_vote.wasm
```

Important: the `wasm` feature is **off** here — the WASI build needs
neither `wasm-bindgen` nor the browser-specific `getrandom` backend.
On `wasm32-wasip1`, `getrandom` falls back automatically to WASI's
`random_get`, so `SysRng` (used by `sign_vote` and
`generate_identity`) works out of the box. The resulting `.wasm` is a
plain WASI module any compliant runtime (wasmtime, wasmer, …) can
load and call into.

`wasm64-unknown-unknown` is a Tier 3 nightly-only target and several
transitive dependencies do not yet advertise wasm64 support, which is
why `wasm32-wasip1` is the documented server-side option.

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

See the [Browser WASM](#browser-wasm-wasm32-unknown-unknown-via-wasm-pack)
row in the build matrix above for the full command and flag breakdown.
The short version, run from the crate root, is:

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
