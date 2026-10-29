// End-to-end test of the Extism plugin (`--features extism`).
//
// The Extism PDK links against host-provided imports, so `src/extism.rs`
// cannot be exercised by `cargo test` on a native target. Instead this
// script loads the real `.wasm` artefact into the official JavaScript
// host SDK and calls every exported plugin function over the JSON wire,
// exactly as a host application would. It is the only automated check
// that the plugin ABI (function names, JSON shapes, error reporting)
// still matches what the README documents.
//
// Usage:
//   cargo build --profile wasm-release --target wasm32-wasip1 --lib \
//       --no-default-features --features extism
//   cd tests/extism && npm ci && npm test
//
// Override the plugin path with `CRYPTO_VOTE_WASM=/path/to/plugin.wasm`.
// Run under Node (24+): bun's build of the SDK refuses WASI modules.

import createPlugin from "@extism/extism";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const wasmPath =
  process.env.CRYPTO_VOTE_WASM ??
  path.resolve(here, "../../target/wasm32-wasip1/wasm-release/crypto_vote.wasm");

const EID = "550e8400-e29b-41d4-a716-446655440000";

let failures = 0;
function check(condition, label) {
  if (condition) {
    console.log(`ok   ${label}`);
  } else {
    failures += 1;
    console.error(`FAIL ${label}`);
  }
}

const plugin = await createPlugin(wasmPath, { useWasi: true });

/// Call `fn` with `input` JSON-encoded and return the decoded JSON output.
async function call(fn, input) {
  const out = await plugin.call(fn, input === undefined ? undefined : JSON.stringify(input));
  return JSON.parse(out.text());
}

/// Assert that calling `fn` with `raw` (sent verbatim) fails with a
/// plugin-originated error whose message contains `expected`.
async function expectError(fn, raw, expected, label) {
  try {
    await plugin.call(fn, raw);
    check(false, `${label}: expected an error, call succeeded`);
  } catch (e) {
    check(String(e.message).includes(expected), `${label}: ${String(e.message).slice(0, 70)}`);
  }
}

// --- Operation A: identities ------------------------------------------

const alice = await call("generate_identity");
const bob = await call("generate_identity");
const ring = [alice.public, bob.public];

check(alice.secret.startsWith("sk_") && alice.public.startsWith("pk_"), "generate_identity emits prefixed keys");
check(alice.secret !== bob.secret, "generate_identity is random");
check((await call("derive_public_key", { secret: alice.secret })).public === alice.public, "derive_public_key matches generate_identity");
check((await call("is_valid_secret_key", { secret: alice.secret })).valid === true, "is_valid_secret_key accepts a fresh key");
check((await call("is_valid_secret_key", { secret: "sk_nope" })).valid === false, "is_valid_secret_key rejects garbage without erroring");

// --- Operation B / C: sign and verify -----------------------------------

const strProof = await call("sign_vote_str", { secret: alice.secret, vote: "oui", election_id: EID, ring });
const hexProof = await call("sign_vote_hex", { secret: alice.secret, vote: "6f7569", election_id: EID, ring });
check(strProof.signature.startsWith("blsag_") && strProof.key_image.startsWith("ki_"), "sign_vote_str emits prefixed signature and key image");
check(strProof.key_image === hexProof.key_image, "key image is identical across _str and _hex flavours");

const verify = (fn, vote, proof, overrides = {}) =>
  call(fn, { vote, election_id: EID, signature: proof.signature, key_image: proof.key_image, ring, ...overrides });

check((await verify("verify_vote_str", "oui", strProof)).valid === true, "verify_vote_str accepts its own proof");
check((await verify("verify_vote_hex", "6f7569", strProof)).valid === true, "verify_vote_hex accepts a _str proof of the same bytes");
check((await verify("verify_vote_str", "oui", hexProof)).valid === true, "verify_vote_str accepts a _hex proof of the same bytes");
check((await verify("verify_vote_str", "non", strProof)).valid === false, "verify_vote_str rejects a tampered vote");
check((await verify("verify_vote_str", "oui", strProof, { election_id: "other" })).valid === false, "verify_vote_str rejects another election");
check((await verify("verify_vote_str", "oui", strProof, { ring: [bob.public] })).valid === false, "verify_vote_str rejects a different ring");
check((await verify("verify_vote_str", "oui", strProof, { key_image: hexProof.key_image, signature: "blsag_bad" })).valid === false, "verify_vote_str reports malformed input as invalid, not as an error");

// --- Ring digest ---------------------------------------------------------

const digest = (await call("ring_digest", { ring })).digest;
check(digest.startsWith("ring_"), "ring_digest emits a prefixed digest");
check((await call("ring_digest", { ring: [bob.public, alice.public] })).digest === digest, "ring_digest is order-independent");

// --- Operation D: proof of ownership ------------------------------------

const { nonce } = await call("generate_nonce");
check(nonce.startsWith("nonce_"), "generate_nonce emits a prefixed nonce");
const { proof } = await call("prove_ownership", { secret: alice.secret, election_id: EID, nonce });
check(proof.startsWith("own_"), "prove_ownership emits a prefixed proof");
const ownership = (overrides = {}) =>
  call("verify_ownership", { public: alice.public, key_image: strProof.key_image, election_id: EID, nonce, proof, ...overrides });
check((await ownership()).valid === true, "verify_ownership accepts a valid proof");
check((await ownership({ public: bob.public })).valid === false, "verify_ownership rejects another public key");
check((await ownership({ nonce: (await call("generate_nonce")).nonce })).valid === false, "verify_ownership rejects another nonce");

// --- Error reporting on secret-handling entry points ----------------------
//
// These go through `read_secret_input` rather than the PDK's `Json<T>`
// argument, so make sure a bad payload still surfaces as a plugin error.

await expectError("derive_public_key", JSON.stringify({ secret: "sk_bad" }), "sk_", "derive_public_key rejects a malformed secret");
await expectError("sign_vote_str", JSON.stringify({ secret: "nope", vote: "x", election_id: EID, ring }), "sk_", "sign_vote_str rejects an unprefixed secret");
await expectError("sign_vote_hex", JSON.stringify({ secret: alice.secret, vote: "zz", election_id: EID, ring }), "", "sign_vote_hex rejects a non-hex ballot");
await expectError("prove_ownership", JSON.stringify({ secret: alice.secret, election_id: EID, nonce: "nonce_bad" }), "nonce_", "prove_ownership rejects a malformed nonce");
await expectError("derive_public_key", "not json", "", "derive_public_key rejects a non-JSON payload");
await expectError("derive_public_key", JSON.stringify({}), "secret", "derive_public_key reports a missing field");

await plugin.close();

if (failures > 0) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nall checks passed");
