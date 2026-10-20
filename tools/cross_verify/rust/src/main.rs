// SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
// SPDX-License-Identifier: Apache-2.0

//! Verifies an ML-DSA-87 signature made by BeamMCP.Signer.MLDSA87 (tools/mldsa_sample.exs) with
//! aws-lc-rs (AWS-LC's ML-DSA, not OpenSSL's): the signature verifies over the message, and does
//! not verify over the message with one bit flipped.
//!
//!     cargo run --locked --release -- <dir>

use aws_lc_rs::signature::{UnparsedPublicKey, ML_DSA_87};
use std::{env, fs, path::Path, process};

fn read(dir: &Path, name: &str) -> Vec<u8> {
    fs::read(dir.join(name)).unwrap_or_else(|e| fail(&format!("{name}: {e}")))
}

fn fail(why: &str) -> ! {
    println!("FAIL {why}");
    process::exit(1)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        fail("usage: cross_verify <dir>");
    }
    let dir = Path::new(&args[1]);
    let message = read(dir, "message.bin");
    let signature = read(dir, "signature.bin");
    let public_key = UnparsedPublicKey::new(&ML_DSA_87, read(dir, "public_key.bin"));

    if public_key.verify(&message, &signature).is_err() {
        fail("the signature does not verify");
    }
    println!("ok   the signature verifies over the message (ML-DSA-87, empty context)");

    let mut flipped = message.clone();
    flipped[0] ^= 1;
    if public_key.verify(&flipped, &signature).is_ok() {
        fail("the signature also verifies over the message with one bit flipped");
    }
    println!("ok   it does not verify over the message with one bit flipped");
}
