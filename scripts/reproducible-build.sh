#!/bin/sh
# Run a build command with the path remapping that makes release
# artefacts bit-for-bit reproducible: the Cargo registry, the toolchain
# sysroot, and the workspace are rewritten to the fixed virtual prefixes
# `/cargo`, `/rustc`, and `/build` in the panic-location strings rustc
# bakes into the binary. See "Reproducible builds" in README.md.
#
# Stand-in for Cargo's `trim-paths` profile option, still unstable.
#
# Usage: scripts/reproducible-build.sh cargo build --release --locked ...
#        scripts/reproducible-build.sh wasm-pack build ...
set -eu

cargo_home="${CARGO_HOME:-$HOME/.cargo}"
sysroot="$(rustc --print sysroot)"
workspace="$(cd "$(dirname "$0")/.." && pwd -P)"

RUSTFLAGS="--remap-path-prefix=${cargo_home}=/cargo --remap-path-prefix=${sysroot}=/rustc --remap-path-prefix=${workspace}=/build ${RUSTFLAGS:-}"
export RUSTFLAGS

exec "$@"
