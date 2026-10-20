// SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
// SPDX-License-Identifier: Apache-2.0

// Verifies an ML-DSA-87 signature made by BeamMCP.Signer.MLDSA87 (tools/mldsa_sample.exs) with
// Go's crypto/mldsa, an implementation independent of OpenSSL's: the signature verifies over
// the message with an empty context, does not verify over the message with one bit flipped,
// and the public key is the one the seed derives (which OTP's :crypto cannot compute).
//
//	go run . <dir>
package main

import (
	"bytes"
	"crypto/mldsa"
	"fmt"
	"os"
	"path/filepath"
)

func read(dir, name string) []byte {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		fail("%s: %v", name, err)
	}
	return b
}

func fail(format string, args ...any) {
	fmt.Printf("FAIL "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) != 2 {
		fail("usage: go run . <dir>")
	}
	dir := os.Args[1]
	message, signature := read(dir, "message.bin"), read(dir, "signature.bin")
	encoded, seed := read(dir, "public_key.bin"), read(dir, "seed.bin")

	pk, err := mldsa.NewPublicKey(mldsa.MLDSA87(), encoded)
	if err != nil {
		fail("public key: %v", err)
	}
	if err := mldsa.Verify(pk, message, signature, nil); err != nil {
		fail("the signature does not verify: %v", err)
	}
	fmt.Println("ok   the signature verifies over the message (ML-DSA-87, empty context)")

	flipped := bytes.Clone(message)
	flipped[0] ^= 1
	if mldsa.Verify(pk, flipped, signature, nil) == nil {
		fail("the signature also verifies over the message with one bit flipped")
	}
	fmt.Println("ok   it does not verify over the message with one bit flipped")

	sk, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), seed)
	if err != nil {
		fail("seed: %v", err)
	}
	if !sk.PublicKey().Equal(pk) {
		fail("the public key is not the one the seed derives")
	}
	fmt.Println("ok   the public key is the one the seed derives")

	verifyCarrier(pk, encoded, message, read(dir, "carrier.cbor"))
}
