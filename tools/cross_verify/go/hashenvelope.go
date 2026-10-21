// SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
// SPDX-License-Identifier: Apache-2.0

package main

// Verifies the RFC 9995 hash envelope BeamMCP.Signer.COSE.HashEnvelope made over the same
// message (hash-envelope.cbor), holding only the envelope and the public key until the last
// step:
//   - the carrier and the protected header are each core-deterministic CBOR;
//   - the carrier is {0: 0xFFFF0003, 1: digest, 2: [protected, {}, null, signature]};
//   - the protected header is {1: -50, 2: [258], 4: kid, 16: typ, 258: -43, 259: media type},
//     with no label 3, and the digest is 48 bytes;
//   - the signature verifies over ToBeSigned ["Signature1", protected, h'', digest], built here,
//     and not once 258 or 259 is changed;
//   - then, the preimage in hand, the digest is SHA-384 of message.bin.

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha512"
	"fmt"
)

const hashTyp = "application/vnd.example.b80.test_hash.v0+cose"

func verifyHashEnvelope(pk *mldsa.PublicKey, publicKey, message, envelope []byte) {
	c := asMap("hash envelope", canonical("hash envelope", envelope), 0, 1, 2)
	if c[0] != int64(singleSchema) {
		fail("hash envelope key 0 is %v, not 0xFFFF0003", c[0])
	}
	digest, ok := c[1].([]byte)
	sign1, ok2 := c[2].([]any)
	if !ok || !ok2 || len(sign1) != 4 {
		fail("hash envelope: key 1 is not a byte string, or key 2 not a four-element array")
	}
	protected, ok := sign1[0].([]byte)
	unprotected, ok2 := sign1[1].(map[any]any)
	signature, ok3 := sign1[3].([]byte)
	if !ok || !ok2 || len(unprotected) != 0 || sign1[2] != nil || !ok3 {
		fail("hash envelope Sign1: not [protected bstr, {}, null, signature bstr]")
	}
	fmt.Println("ok   the hash envelope is {0: 0xFFFF0003, 1: digest, 2: [protected, {}, null, signature]}, core-deterministic")

	h := asMap("hash envelope header", canonical("hash envelope header", protected), 1, 2, 4, 16, 258, 259)
	kid := sha512.Sum384(append(bytes.Clone(thumbprintHead), publicKey...))
	crit, ok := h[2].([]any)
	if h[1] != int64(-50) || !ok || len(crit) != 1 || crit[0] != int64(258) ||
		!bytes.Equal(h[4].([]byte), kid[:]) || h[16] != hashTyp || h[258] != int64(-43) ||
		h[259] != "application/json" {
		fail("hash envelope header: not {1: -50, 2: [258], 4: kid, 16: %q, 258: -43, 259: \"application/json\"}", hashTyp)
	}
	if len(digest) != 48 {
		fail("hash envelope: the payload is %d bytes, not SHA-384's 48", len(digest))
	}
	fmt.Println("ok   protected {1: -50, 2: [258], 4: kid, 16: typ, 258: -43, 259: type}, no label 3; a 48-byte digest")

	if err := mldsa.Verify(pk, toBeSigned(protected, digest), signature, nil); err != nil {
		fail("the hash envelope's signature does not verify over ToBeSigned: %v", err)
	}
	fmt.Println("ok   the signature verifies over ToBeSigned built here, holding only the digest")

	for _, changed := range []map[int64]any{
		{1: h[1], 2: h[2], 4: h[4], 16: h[16], 258: int64(-44), 259: h[259]},
		{1: h[1], 2: h[2], 4: h[4], 16: h[16], 258: h[258], 259: "application/octet-stream"},
	} {
		altered, _ := deterministic.Marshal(changed)
		if mldsa.Verify(pk, toBeSigned(altered, digest), signature, nil) == nil {
			fail("the hash envelope's signature also verifies with 258 or 259 changed")
		}
	}
	fmt.Println("ok   it does not verify with the hash algorithm or the preimage type changed")

	sum := sha512.Sum384(message)
	if !bytes.Equal(digest, sum[:]) {
		fail("the hash envelope's digest is not SHA-384 of the message")
	}
	fmt.Println("ok   with the preimage in hand: the digest is SHA-384 of the message")
}
