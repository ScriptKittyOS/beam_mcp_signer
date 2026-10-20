// SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
// SPDX-License-Identifier: Apache-2.0

//! Verifies the N6 carrier BeamMCP.Signer.COSE made (carrier.cbor) with coset, a COSE library
//! that shares nothing with the Elixir encoder, ciborium for the carrier map and the body, and
//! aws-lc-rs for ML-DSA-87: coset reads the Sign1, names its algorithm and builds ToBeSigned
//! over the detached body; the kid is SHA-384 over the RFC 9679 thumbprint input; the body names
//! the message by SHA-384 and length; and the signature does not verify once the protected
//! header is changed.

use aws_lc_rs::digest::{digest, SHA384};
use aws_lc_rs::signature::{UnparsedPublicKey, ML_DSA_87};
use ciborium::value::{Integer, Value};
use coset::{iana, Algorithm, CborSerializable, CoseSign1};

use crate::fail;

const SINGLE_SCHEMA: u64 = 0xFFFF0003;
const SCHEMA: u64 = 0x85000101;
const TYP: &str = "application/vnd.example.b85.connectome.v0+cose";
const THUMBPRINT_HEAD: [u8; 10] = [0xa3, 0x01, 0x07, 0x03, 0x38, 0x31, 0x20, 0x59, 0x0a, 0x20];

fn decode(name: &str, bytes: &[u8]) -> Value {
    ciborium::de::from_reader(bytes).unwrap_or_else(|e| fail(&format!("{name}: {e}")))
}

fn entries(name: &str, v: &Value) -> Vec<(u64, Value)> {
    let map = v
        .as_map()
        .unwrap_or_else(|| fail(&format!("{name}: not a map")));
    map.iter()
        .map(|(k, v)| {
            let k = k
                .as_integer()
                .and_then(|i| u64::try_from(i).ok())
                .unwrap_or_else(|| fail(&format!("{name}: a key is not an unsigned integer")));
            (k, v.clone())
        })
        .collect()
}

fn get(name: &str, entries: &[(u64, Value)], key: u64) -> Value {
    entries
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| fail(&format!("{name}: no key {key}")))
}

fn int(v: &Value) -> i128 {
    v.as_integer().map(i128::from).unwrap_or(i128::MIN)
}

pub fn verify(public_key: &[u8], message: &[u8], carrier: &[u8]) {
    let c = entries("carrier", &decode("carrier", carrier));
    if c.len() != 3 || int(&get("carrier", &c, 0)) != i128::from(SINGLE_SCHEMA) {
        fail("carrier: not {0: 0xFFFF0003, 1: body, 2: Sign1}");
    }
    let body = get("carrier", &c, 1)
        .into_bytes()
        .unwrap_or_else(|_| fail("carrier: key 1 is not a byte string"));

    let mut sign1_bytes = Vec::new();
    ciborium::ser::into_writer(&get("carrier", &c, 2), &mut sign1_bytes)
        .unwrap_or_else(|e| fail(&format!("Sign1: {e}")));
    let sign1 =
        CoseSign1::from_slice(&sign1_bytes).unwrap_or_else(|e| fail(&format!("Sign1: {e:?}")));
    if sign1.payload.is_some() || !sign1.unprotected.is_empty() {
        fail("Sign1: the payload is not null, or the unprotected header is not empty");
    }
    println!("ok   the carrier is {{0: 0xFFFF0003, 1: body, 2: Sign1}}, and coset reads the Sign1");

    let header = &sign1.protected.header;
    let kid = digest(&SHA384, &[&THUMBPRINT_HEAD[..], public_key].concat());
    let typ_ok = header.rest.len() == 1
        && header.rest[0].0 == coset::Label::Int(16)
        && header.rest[0].1 == Value::Text(TYP.into());
    if header.alg != Some(Algorithm::Assigned(iana::Algorithm::ML_DSA_87))
        || header.key_id != kid.as_ref()
        || !typ_ok
        || header.content_type.is_some()
        || !header.crit.is_empty()
    {
        fail("protected header: not {1: ML-DSA-87, 4: SHA-384 thumbprint, 16: typ}");
    }
    println!(
        "ok   coset reads alg ML-DSA-87 (-50), the kid is SHA-384 of the thumbprint input, and typ"
    );

    let b = entries("body", &decode("body", &body));
    let r = entries("body key 2", &get("body", &b, 2));
    let d = get("body key 2", &r, 0);
    let d = d
        .as_array()
        .unwrap_or_else(|| fail("body: the digest is not an array"));
    let sum = digest(&SHA384, message);
    if int(&get("body", &b, 0)) != i128::from(SCHEMA)
        || d.len() != 2
        || int(&d[0]) != -43
        || d[1].as_bytes().map(|v| v.as_slice()) != Some(sum.as_ref())
        || get("body key 2", &r, 1).as_integer() != Some(Integer::from(message.len() as u64))
        || get("body key 2", &r, 2) != Value::Text("application/json".into())
    {
        fail("body: does not name the message by SHA-384 and length under schema 0x85000101");
    }
    println!("ok   the body names the message: [-43, SHA-384], its length, application/json");

    let key = UnparsedPublicKey::new(&ML_DSA_87, public_key);
    sign1
        .verify_detached_signature(&body, &[], |sig, tbs| key.verify(tbs, sig))
        .unwrap_or_else(|_| {
            fail("the carrier's signature does not verify over coset's ToBeSigned")
        });
    println!("ok   the signature verifies over ToBeSigned built by coset with the detached body");

    for change in 0..3 {
        let mut altered = sign1.clone();
        altered.protected.original_data = None;
        match change {
            0 => {
                altered.protected.header.alg = Some(Algorithm::Assigned(iana::Algorithm::ML_DSA_65))
            }
            1 => altered.protected.header.key_id[0] ^= 1,
            _ => {
                altered.protected.header.rest[0].1 =
                    Value::Text("application/vnd.example.b85.other.v0+cose".into())
            }
        }
        if altered
            .verify_detached_signature(&body, &[], |sig, tbs| key.verify(tbs, sig))
            .is_ok()
        {
            fail("the signature also verifies with the protected header changed");
        }
    }
    println!("ok   it does not verify with alg, kid or typ changed");
}
