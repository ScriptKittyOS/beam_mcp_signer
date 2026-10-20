// SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
// SPDX-License-Identifier: Apache-2.0

package main

// Verifies the N6 carrier BeamMCP.Signer.COSE made over the same message (carrier.cbor), read
// with fxamacker/cbor, a CBOR implementation that shares nothing with the Elixir encoder:
//   - the carrier, the protected header and the body are each core-deterministic CBOR (the
//     library decodes strictly, then its own RFC 8949 §4.2.1 encoder must give back the same
//     bytes);
//   - the carrier is {0: 0xFFFF0003, 1: body, 2: [protected, {}, null, signature]};
//   - the protected header is {1: -50, 4: kid, 16: typ} and kid is SHA-384 over the RFC 9679
//     thumbprint input of the public key;
//   - the body names the message by SHA-384 and length;
//   - the signature verifies over ToBeSigned ["Signature1", protected, h'', body], built here,
//     and not once alg, kid or typ in the protected header is changed.

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha512"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const (
	singleSchema = 0xFFFF0003
	schema       = 0x85000101
	typ          = "application/vnd.example.b85.connectome.v0+cose"
)

var (
	strict = mustDec(cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
		TagsMd:      cbor.TagsForbidden,
		IntDec:      cbor.IntDecConvertSigned,
	})
	deterministic = mustEnc(cbor.CoreDetEncOptions())
	thumbprintHead = []byte{0xa3, 0x01, 0x07, 0x03, 0x38, 0x31, 0x20, 0x59, 0x0a, 0x20}
)

func mustDec(o cbor.DecOptions) cbor.DecMode {
	m, err := o.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}

func mustEnc(o cbor.EncOptions) cbor.EncMode {
	m, err := o.EncMode()
	if err != nil {
		panic(err)
	}
	return m
}

// canonical decodes b strictly into a generic value and requires the library's own
// deterministic encoding of that value to be b again.
func canonical(name string, b []byte) any {
	var v any
	if err := strict.Unmarshal(b, &v); err != nil {
		fail("%s: %v", name, err)
	}
	again, err := deterministic.Marshal(v)
	if err != nil || !bytes.Equal(again, b) {
		fail("%s: not core-deterministic CBOR", name)
	}
	return v
}

func asMap(name string, v any, keys ...int64) map[int64]any {
	m, ok := v.(map[any]any)
	if !ok || len(m) != len(keys) {
		fail("%s: not a map of %d entries", name, len(keys))
	}
	out := map[int64]any{}
	for k, val := range m {
		ki, ok := k.(int64)
		if !ok {
			fail("%s: key %v is not an integer", name, k)
		}
		out[ki] = val
	}
	for _, k := range keys {
		if _, ok := out[k]; !ok {
			fail("%s: no key %d", name, k)
		}
	}
	return out
}

func toBeSigned(protected, body []byte) []byte {
	tbs, err := deterministic.Marshal([]any{"Signature1", protected, []byte{}, body})
	if err != nil {
		fail("ToBeSigned: %v", err)
	}
	return tbs
}

func verifyCarrier(pk *mldsa.PublicKey, publicKey, message, carrierBytes []byte) {
	c := asMap("carrier", canonical("carrier", carrierBytes), 0, 1, 2)
	if c[0] != int64(singleSchema) {
		fail("carrier key 0 is %v, not 0xFFFF0003", c[0])
	}
	body, ok := c[1].([]byte)
	sign1, ok2 := c[2].([]any)
	if !ok || !ok2 || len(sign1) != 4 {
		fail("carrier: key 1 is not a byte string, or key 2 not a four-element array")
	}
	protected, ok := sign1[0].([]byte)
	unprotected, ok2 := sign1[1].(map[any]any)
	signature, ok3 := sign1[3].([]byte)
	if !ok || !ok2 || len(unprotected) != 0 || sign1[2] != nil || !ok3 {
		fail("Sign1: not [protected bstr, {}, null, signature bstr]")
	}
	fmt.Println("ok   the carrier is {0: 0xFFFF0003, 1: body, 2: [protected, {}, null, signature]}, core-deterministic")

	h := asMap("protected header", canonical("protected header", protected), 1, 4, 16)
	kid := sha512.Sum384(append(bytes.Clone(thumbprintHead), publicKey...))
	if h[1] != int64(-50) || !bytes.Equal(h[4].([]byte), kid[:]) || h[16] != typ {
		fail("protected header: not {1: -50, 4: SHA-384 thumbprint, 16: %q}", typ)
	}
	fmt.Println("ok   protected {1: -50, 4: kid, 16: typ}; kid is SHA-384 of the RFC 9679 thumbprint input")

	b := asMap("body", canonical("body", body), 0, 1, 2)
	ref := asMap("body key 2", b[2], 0, 1, 2)
	digest, ok := ref[0].([]any)
	sum := sha512.Sum384(message)
	if b[0] != int64(schema) || !ok || len(digest) != 2 || digest[0] != int64(-43) ||
		!bytes.Equal(digest[1].([]byte), sum[:]) || ref[1] != int64(len(message)) || ref[2] != "application/json" {
		fail("body: does not name the message by SHA-384 and length under schema 0x85000101")
	}
	fmt.Println("ok   the body names the message: [-43, SHA-384], its length, application/json")

	if err := mldsa.Verify(pk, toBeSigned(protected, body), signature, nil); err != nil {
		fail("the carrier's signature does not verify over ToBeSigned: %v", err)
	}
	fmt.Println("ok   the signature verifies over ToBeSigned built here")

	for _, changed := range []map[int64]any{
		{1: int64(-49), 4: h[4], 16: h[16]},
		{1: h[1], 4: append([]byte{h[4].([]byte)[0] ^ 1}, h[4].([]byte)[1:]...), 16: h[16]},
		{1: h[1], 4: h[4], 16: "application/vnd.example.b85.other.v0+cose"},
	} {
		altered, _ := deterministic.Marshal(changed)
		if mldsa.Verify(pk, toBeSigned(altered, body), signature, nil) == nil {
			fail("the signature also verifies with the protected header changed")
		}
	}
	fmt.Println("ok   it does not verify with alg, kid or typ changed")
}
