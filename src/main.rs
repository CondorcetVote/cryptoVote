//! `cryptovote` — command-line interface around the [`crypto_vote`]
//! library.
//!
//! The CLI is only built with the default `cli` feature on (it pulls in
//! `clap`). When compiling for WebAssembly, build with
//! `--no-default-features --features wasm` and this file is ignored.
//!
//! Three subcommands map one-to-one onto the three library operations:
//!
//! ```text
//! cryptovote keygen
//! cryptovote sign   --secret <hex> --vote <text> --election-id <text> --ring <file>
//! cryptovote verify --vote <text> --election-id <text> \
//!                   --signature <hex> --key-image <hex> --ring <file>
//! ```
//!
//! The ring file is a plain text file with one hex-encoded public key
//! per line. Empty lines and lines starting with `#` are ignored, so
//! you can keep comments alongside the authorised list.

use clap::{Parser, Subcommand};
use crypto_vote::{KeyImage, PublicKey, SecretKey, Signature, generate_identity, sign_vote, verify_vote};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "cryptovote",
    version,
    about = "Linkable ring signatures for verifiable voting (Ristretto255 + Blake3)."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a new voter identity (secret + public key, hex-encoded).
    Keygen,

    /// Sign a ballot.
    Sign {
        /// Hex-encoded secret key.
        #[arg(long)]
        secret: String,
        /// Ballot text. Pass `-` to read from stdin.
        #[arg(long)]
        vote: String,
        /// Election identifier. Must be the same string the verifier
        /// uses (otherwise the signature will not validate).
        #[arg(long = "election-id")]
        election_id: String,
        /// File containing one hex-encoded public key per line.
        #[arg(long)]
        ring: PathBuf,
    },

    /// Verify a ballot.
    Verify {
        /// Ballot text. Pass `-` to read from stdin.
        #[arg(long)]
        vote: String,
        /// Election identifier — same string the signer used.
        #[arg(long = "election-id")]
        election_id: String,
        /// Hex-encoded signature.
        #[arg(long)]
        signature: String,
        /// Hex-encoded linking tag.
        #[arg(long = "key-image")]
        key_image: String,
        /// File containing one hex-encoded public key per line.
        #[arg(long)]
        ring: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli.command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

/// Inner entry point. Returns a proper `Result` so error reporting
/// happens in exactly one place (above).
fn dispatch(cmd: Command) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match cmd {
        Command::Keygen => {
            let id = generate_identity();
            // Stable, machine-friendly output. Two `key=value` lines so
            // the caller can grep / cut without writing a JSON parser.
            println!("secret={}", id.secret_key.to_hex());
            println!("public={}", id.public_key.to_hex());
            Ok(ExitCode::SUCCESS)
        }

        Command::Sign {
            secret,
            vote,
            election_id,
            ring,
        } => {
            let sk = SecretKey::from_hex(secret.trim())?;
            let vote_bytes = read_vote(&vote)?;
            let ring = read_ring(&ring)?;
            let proof = sign_vote(&sk, &vote_bytes, &election_id, &ring)?;
            println!("signature={}", proof.signature.to_hex());
            println!("key_image={}", proof.key_image.to_hex());
            Ok(ExitCode::SUCCESS)
        }

        Command::Verify {
            vote,
            election_id,
            signature,
            key_image,
            ring,
        } => {
            let vote_bytes = read_vote(&vote)?;
            let ring = read_ring(&ring)?;
            // Signature size depends on ring size, so we have to know
            // the ring length before we can parse the hex.
            let signature = Signature::from_hex(signature.trim(), ring.len())?;
            let key_image = KeyImage::from_hex(key_image.trim())?;
            let ok = verify_vote(&vote_bytes, &election_id, &signature, &key_image, &ring);
            if ok {
                println!("valid");
                Ok(ExitCode::SUCCESS)
            } else {
                println!("invalid");
                // Exit code 1 = "ran fine, answer is no". This is the
                // shell-friendly way to compose with `||`.
                Ok(ExitCode::from(1))
            }
        }
    }
}

/// Resolve a `--vote` argument: either a literal string, or stdin if
/// the user passed `-`.
fn read_vote(arg: &str) -> std::io::Result<Vec<u8>> {
    if arg == "-" {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)?;
        Ok(buf)
    } else {
        Ok(arg.as_bytes().to_vec())
    }
}

/// Parse a ring file: one hex public key per line, `#` comments and
/// blank lines tolerated.
fn read_ring(path: &PathBuf) -> Result<Vec<PublicKey>, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(path)?;
    let mut keys = Vec::new();
    for (lineno, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match PublicKey::from_hex(line) {
            Ok(pk) => keys.push(pk),
            // Wrap the parse error with the line number so users can
            // find the broken entry quickly.
            Err(e) => return Err(format!("ring file line {}: {e}", lineno + 1).into()),
        }
    }
    Ok(keys)
}
