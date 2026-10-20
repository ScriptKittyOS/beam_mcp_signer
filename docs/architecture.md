<!--
SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
SPDX-License-Identifier: Apache-2.0
-->

# Architecture

Three modules, one function each, one dependency direction. Ed25519 is drawn below; ML-DSA-87
takes the same path with two keys and a check before it returns; COSE builds a statement around
the bytes and has ML-DSA-87 sign that.

```text
 host application
   |  Canonical.signature(graph, BeamMCP.Signer.Ed25519, private_key: fn -> key end, ...)
   v
 beam_mcp  (BeamMCP.Connectome.Canonical)
   |  encodes the graph to canonical bytes, then calls the signer through
   |  the BeamMCP.Signer behaviour: sign(canonical_bytes, opts)
   v
 beam_mcp_signer  (BeamMCP.Signer.Ed25519.sign/2)
   |  reads opts[:private_key] (32 bytes, or fn -> bytes end) and nothing else
   v
 Erlang/OTP :crypto.sign(:eddsa, :none, canonical_bytes, [key, :ed25519])   (OpenSSL)
   |
   v
 {:ok, 64-byte signature}  ->  placed beside the bytes by beam_mcp
```

## The parts

- **`BeamMCP.Signer.Ed25519`** (`lib/beam_mcp/signer/ed25519.ex`): implements `beam_mcp`'s
  `BeamMCP.Signer` behaviour. `sign/2` takes the canonical bytes and the host's options, reads
  the private key from `opts[:private_key]` (the 32 bytes, or a zero-arity function returning
  them, which is called once), checks it is a 32-byte binary, and returns `{:ok, signature}`,
  `{:error, :no_private_key}` or `{:error, {:private_key, :not_32_bytes}}`. Nothing it meets
  is raised, so no exception prints the options: a mistyped call is answered
  `{:error, :bad_arguments}` (so is an improper list whose end comes before a `:private_key`
  entry), a key function that raises, throws or exits is answered
  `{:error, {:private_key, :unreadable}}`, and a refusal from `:crypto` is answered
  `{:error, :crypto_refused}`.
- **`BeamMCP.Signer.MLDSA87`** (`lib/beam_mcp/signer/mldsa87.ex`): the same behaviour and the
  same rules for a key, with two: the 32-byte seed under `opts[:private_key]` and the
  2,592-byte public key under `opts[:public_key]`, each bytes or a zero-arity function called
  once. It signs with `:crypto.sign(:mldsa87, :none, canonical_bytes, {:seed, seed})`, then
  verifies the signature under the public key (`{:error, {:public_key, :does_not_verify}}`
  when the two keys are not a pair) and over bytes one bit away (`{:error,
  :self_check_failed}` when that verifies too) before returning it. The public key is the
  host's because `:crypto` derives none from a seed. On a runtime without ML-DSA-87 (OTP 27,
  or OpenSSL before 3.5) every call is `{:error, :crypto_refused}`.
- **`BeamMCP.Signer.COSE`** (`lib/beam_mcp/signer/cose.ex`): the same behaviour, MLDSA87's
  two keys read the same way (each function called once), and `opts[:issuer]`. It builds a
  statement about the canonical bytes (their SHA-384 and length, and the issuer) and a COSE
  protected header naming the algorithm (-50) and the key (its SHA-384 thumbprint, computed
  from the public key), has `BeamMCP.Signer.MLDSA87` sign and check the COSE ToBeSigned over
  them, and returns the N6 single-signer carrier. Its one `:crypto` call is SHA-384; it calls
  no signing primitive. Its encoder, `BeamMCP.Signer.COSE.CBOR` (private), writes
  deterministic CBOR under N6's rules and refuses anything else by name.
- **`beam_mcp`** (a dependency, `~> 0.7`): defines the behaviour and produces the bytes. It
  holds no key, calls no signing primitive and does not depend on this package.
- **Erlang/OTP `:crypto`**: performs Ed25519, ML-DSA-87 and SHA-384, through OpenSSL. This
  package implements no cryptography itself; the CBOR encoder is an encoding, not a primitive.

## Properties the arrangement keeps

- **The key lives with the host.** Nothing is stored between calls: no process, table,
  persistent term, application environment or file. A test checks that no state remains after
  a call.
- **One way in.** The keys have one source, the call's options; a census over both the source
  and the compiled modules holds that, and that every `:crypto` call names its algorithm and
  `:none` as literals and takes no options argument
  (`test/beam_mcp/signer/no_key_source_test.exs`).
- **Core stays keyless.** Authority (a key, a signature) is kept out of `beam_mcp` by putting
  it here, in a package a host chooses to add.

## Where to read next

`docs/assurance-case.md` (why the security requirements hold), `SECURITY.md` (what a host can
expect), and `beam_mcp`'s
[`docs/architecture.md`](https://github.com/ScriptKittyOS/beam_mcp/blob/main/docs/architecture.md)
for the bytes being signed.
