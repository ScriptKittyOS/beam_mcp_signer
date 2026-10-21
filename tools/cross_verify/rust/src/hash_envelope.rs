// SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
// SPDX-License-Identifier: Apache-2.0

//! Verifies the RFC 9995 hash envelope BeamMCP.Signer.COSE.HashEnvelope made over the same
//! message (hash-envelope.cbor), holding only the envelope and the public key until the last
//! step.
//!
//! coset 0.4.2 knows no label 258 (its IANA table predates RFC 9995), so it refuses a Sign1 whose
//! `crit` names it: the fail-closed refusal `crit` is there to cause in a verifier that does not
//! know hash envelopes, checked first. The rest is read with ciborium, and coset still builds
//! ToBeSigned (`sig_structure_data`) over the protected bytes as received and the digest, for
//! aws-lc-rs to verify. The signature does not verify once 258 or 259 is changed; then, the
//! preimage in hand, the digest is SHA-384 of message.bin.

use aws_lc_rs::digest::{digest, SHA384};
use aws_lc_rs::signature::{UnparsedPublicKey, ML_DSA_87};
use ciborium::value::{Integer, Value};
use coset::{
    sig_structure_data, CborSerializable, CoseError, CoseSign1, ProtectedHeader, SignatureContext,
};

use crate::fail;

const SINGLE_SCHEMA: u64 = 0xFFFF0003;
const TYP: &str = "application/vnd.example.b80.test_hash.v0+cose";
const THUMBPRINT_HEAD: [u8; 10] = [0xa3, 0x01, 0x07, 0x03, 0x38, 0x31, 0x20, 0x59, 0x0a, 0x20];

fn decode(name: &str, bytes: &[u8]) -> Value {
    ciborium::de::from_reader(bytes).unwrap_or_else(|e| fail(&format!("{name}: {e}")))
}

fn get(name: &str, v: &Value, key: i64) -> Value {
    v.as_map()
        .unwrap_or_else(|| fail(&format!("{name}: not a map")))
        .iter()
        .find(|(k, _)| k.as_integer() == Some(Integer::from(key)))
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| fail(&format!("{name}: no key {key}")))
}

fn to_be_signed(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let header = ProtectedHeader {
        original_data: Some(protected.to_vec()),
        ..Default::default()
    };
    sig_structure_data(SignatureContext::CoseSign1, header, None, &[], payload)
}

pub fn verify(public_key: &[u8], message: &[u8], envelope: &[u8]) {
    let c = decode("hash envelope", envelope);
    let len = c.as_map().map(|m| m.len()).unwrap_or(0);
    if len != 3 || get("hash envelope", &c, 0).as_integer() != Some(Integer::from(SINGLE_SCHEMA)) {
        fail("hash envelope: not {0: 0xFFFF0003, 1: digest, 2: Sign1}");
    }
    let payload = get("hash envelope", &c, 1)
        .into_bytes()
        .unwrap_or_else(|_| fail("hash envelope: key 1 is not a byte string"));
    let sign1 = get("hash envelope", &c, 2);
    let parts = sign1
        .as_array()
        .filter(|a| a.len() == 4)
        .unwrap_or_else(|| fail("hash envelope: key 2 is not a four-element array"));
    let protected = parts[0]
        .as_bytes()
        .cloned()
        .unwrap_or_else(|| fail("hash envelope Sign1: the protected header is not a byte string"));
    let signature = parts[3]
        .as_bytes()
        .cloned()
        .unwrap_or_else(|| fail("hash envelope Sign1: the signature is not a byte string"));
    if !parts[1].as_map().map(|m| m.is_empty()).unwrap_or(false) || !parts[2].is_null() {
        fail("hash envelope Sign1: the unprotected header is not empty, or the payload not null");
    }
    println!("ok   the hash envelope is {{0: 0xFFFF0003, 1: digest, 2: [protected, {{}}, null, signature]}}");

    let mut sign1_bytes = Vec::new();
    ciborium::ser::into_writer(&sign1, &mut sign1_bytes)
        .unwrap_or_else(|e| fail(&format!("hash envelope Sign1: {e}")));
    match CoseSign1::from_slice(&sign1_bytes) {
        Err(CoseError::UnregisteredIanaNonPrivateValue) => {
            println!("ok   coset, which knows no label 258, refuses the Sign1 over crit [258]: fail closed")
        }
        other => fail(&format!(
            "coset did not refuse the Sign1 over crit [258]: {:?}",
            other.map(|_| "parsed")
        )),
    }

    let h = decode("hash envelope header", &protected);
    let labels: Vec<Integer> = h
        .as_map()
        .unwrap_or_else(|| fail("hash envelope header: not a map"))
        .iter()
        .map(|(k, _)| {
            k.as_integer()
                .unwrap_or_else(|| fail("hash envelope header: a label is not an integer"))
        })
        .collect();
    let expected: Vec<Integer> = [1, 2, 4, 16, 258, 259].map(Integer::from).to_vec();
    let kid = digest(&SHA384, &[&THUMBPRINT_HEAD[..], public_key].concat());
    if labels != expected
        || get("header", &h, 1) != Value::Integer((-50).into())
        || get("header", &h, 2) != Value::Array(vec![Value::Integer(258.into())])
        || get("header", &h, 4).as_bytes().map(|b| b.as_slice()) != Some(kid.as_ref())
        || get("header", &h, 16) != Value::Text(TYP.into())
        || get("header", &h, 258) != Value::Integer((-43).into())
        || get("header", &h, 259) != Value::Text("application/json".into())
        || payload.len() != 48
    {
        fail("hash envelope header: not {1: -50, 2: [258], 4: kid, 16: typ, 258: -43, 259: type} in that order, or the digest is not 48 bytes");
    }
    println!("ok   protected {{1: -50, 2: [258], 4: kid, 16: typ, 258: -43, 259: type}} in canonical order, no label 3; a 48-byte digest");

    let key = UnparsedPublicKey::new(&ML_DSA_87, public_key);
    if key
        .verify(&to_be_signed(&protected, &payload), &signature)
        .is_err()
    {
        fail("the hash envelope's signature does not verify over coset's ToBeSigned");
    }
    println!("ok   the signature verifies over ToBeSigned built by coset, holding only the digest");

    for (label, value) in [
        (258, Value::Integer((-44).into())),
        (259, Value::Text("application/octet-stream".into())),
    ] {
        let mut altered = h.clone();
        if let Value::Map(entries) = &mut altered {
            for entry in entries.iter_mut() {
                if entry.0.as_integer() == Some(Integer::from(label)) {
                    entry.1 = value.clone();
                }
            }
        }
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&altered, &mut bytes).unwrap_or_else(|e| fail(&format!("{e}")));
        if key
            .verify(&to_be_signed(&bytes, &payload), &signature)
            .is_ok()
        {
            fail("the hash envelope's signature also verifies with 258 or 259 changed");
        }
    }
    println!("ok   it does not verify with the hash algorithm or the preimage type changed");

    if payload != digest(&SHA384, message).as_ref() {
        fail("the hash envelope's digest is not SHA-384 of the message");
    }
    println!("ok   with the preimage in hand: the digest is SHA-384 of the message");
}
