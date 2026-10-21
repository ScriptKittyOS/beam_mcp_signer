<!--
SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
SPDX-License-Identifier: Apache-2.0
-->

# beam_mcp_signer

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14775/badge)](https://www.bestpractices.dev/projects/14775)

Signers for [`beam_mcp`](https://github.com/ScriptKittyOS/beam_mcp)'s canonical connectome
bytes, through OTP's `:crypto`. Three modules, each implementing core's `BeamMCP.Signer`
behaviour (`sign/2`) and nothing else, and a fourth for artifacts too large to hold whole:

- **`BeamMCP.Signer.Ed25519`**: Ed25519 (RFC 8032), a 64-byte signature.
- **`BeamMCP.Signer.MLDSA87`**: ML-DSA-87 (FIPS 204), the post-quantum signature CNSA 2.0
  names, a 4,627-byte signature. It needs an OTP whose `:crypto` is linked to OpenSSL 3.5 or
  later; see [ML-DSA-87](#ml-dsa-87) below.
- **`BeamMCP.Signer.COSE`**: the same ML-DSA-87 signature inside COSE (RFC 9964, algorithm
  -50), with the algorithm and the key's thumbprint in the signed bytes; see [COSE](#cose)
  below.
- **`BeamMCP.Signer.COSE.HashEnvelope`** (non-claimed): a file of any size, streamed and
  signed by its SHA-384 as an RFC 9995 COSE Hash Envelope under the same ML-DSA-87. It is not
  a `BeamMCP.Signer`; see [Hash envelope](#hash-envelope-non-claimed) below.

**What the three sign.** Exactly the bytes `BeamMCP.Connectome.Canonical.encode/2` produces, as
`Canonical.signature/3` hands them over; the signature comes back beside them. Nothing else:
no envelope byte moves, no verdict or receipt is added.

## Ed25519

**Who holds the key.** The host. It passes the 32-byte Ed25519 private key on every call, as
a zero-arity function that returns it:

```elixir
{public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)   # or a key the host keeps

{:ok, %{signature: sig}} =
  BeamMCP.Connectome.Canonical.signature(graph, BeamMCP.Signer.Ed25519,
    private_key: fn -> private_key end)

true = :crypto.verify(:eddsa, :none, BeamMCP.Connectome.Canonical.encode!(graph), sig, [public_key, :ed25519])
```

**Why a function.** Options pass through the host's code and core's, and whatever prints
them (an exception raised on a mistyped call, a debug log line, a crash report) prints a key
passed as bytes, byte by byte. A function prints as `#Function<...>`. The 32 bytes themselves
are still accepted; the function is the form that nothing printed can reveal. For the same
reason nothing this module meets is raised: a mistyped call is answered
`{:error, :bad_arguments}` (so is an improper list whose end comes before a `:private_key`
entry), a key function that raises, throws or exits is answered
`{:error, {:private_key, :unreadable}}`, and a refusal from `:crypto` is answered
`{:error, :crypto_refused}`. The key function's own exception is dropped with it, so a host
that wants it logged logs it inside that function, without the key.

## ML-DSA-87

`BeamMCP.Signer.MLDSA87` signs pure ML-DSA-87 through the external interface with an empty
context: the form RFC 9964 requires for COSE (algorithm -50). The host hands in two keys,
each as bytes or, better, as a zero-arity function returning them:

```elixir
{:ok, %{signature: sig}} =
  BeamMCP.Connectome.Canonical.signature(graph, BeamMCP.Signer.MLDSA87,
    private_key: fn -> seed end, public_key: fn -> public_key end, scheme: :mldsa87)

true = :crypto.verify(:mldsa87, :none, BeamMCP.Connectome.Canonical.encode!(graph), sig, public_key)
```

- **`:private_key` is the 32-byte seed**, RFC 9964's one private-key form.
- **`:public_key` is the 2,592-byte public key** that seed derives. It is required because
  `:crypto` signs from a seed but cannot derive the public key from one. The host provisions
  the pair outside the VM and hands in both.
- **Every signature is checked before it is returned.** It must verify under the public key
  given, or the answer is `{:error, {:public_key, :does_not_verify}}` and no signature leaves
  the module: that is how a seed and a public key that are not a pair are caught. The same
  signature over bytes one bit away must not verify, or the answer is
  `{:error, :self_check_failed}`.
- **Signing is hedged.** OpenSSL draws fresh randomness for each signature, and `:crypto`
  cannot select the deterministic variant: two signatures of the same bytes differ, and both
  verify.
- **Where it runs.** OTP 28.1 or later, with `:crypto` linked to OpenSSL 3.5 or later
  (`:mldsa87 in :crypto.supports(:public_keys)`). OTP 27, or an OTP linked to an older
  OpenSSL, answers every call `{:error, :crypto_refused}`. CI runs the ML-DSA tests on the
  box leg (OTP 28.5.0.8 on Ubuntu 26.04's arm64 runner, OpenSSL 3.5.5) and fails that leg if
  `:crypto` does not offer the algorithm.
- **FIPS mode** with a provider that approves ML-DSA needs `default_properties = fips=yes` in
  OpenSSL's own configuration; OTP's `fips_mode` alone leaves the signature unavailable. No
  provider in this package's CI approves ML-DSA, so FIPS mode is not tested here.
- **Vectors.** The suite holds the runtime to NIST's ACVP and C2SP's Wycheproof ML-DSA-87
  vectors, every case `:crypto` can express (it passes no context and has no HashML-DSA or
  internal interface); the rest are counted by reason, so one that comes into reach fails the
  count until it runs.
- **Other implementations.** On every CI run, the box leg's ML-DSA-87 signature is verified by
  Go's `crypto/mldsa` and by AWS-LC (aws-lc-rs), neither of them OpenSSL; each must refuse it
  over the message with one bit flipped, and Go also confirms the public key is the one the
  seed derives (`tools/cross_verify/`).

## COSE

`BeamMCP.Signer.COSE` fixes what a raw signature cannot: `Canonical.signature/3` places
`scheme:` and `key_id:` beside the signature, asserted by the host and verified by nobody, so
swapping either leaves a raw signature valid. Here the algorithm and the key's thumbprint sit
in the COSE protected header, inside the signed bytes.

```elixir
{:ok, %{signature: carrier}} =
  BeamMCP.Connectome.Canonical.signature(graph, BeamMCP.Signer.COSE,
    private_key: fn -> seed end, public_key: fn -> public_key end, issuer: "box-17")
```

The keys are `BeamMCP.Signer.MLDSA87`'s, read the same way, and that module makes and checks
the signature. `:issuer` is required: UTF-8 text in NFC, or `{:bytes, binary}`.

What comes back is one binary, deterministic CBOR, in the form Script Kitty's systems share for
everything they sign (the N6 profile, v0; provisional until its v1):

```
{0: 0xFFFF0003,                                        ; the single-signer carrier
 1: h'<body>',
 2: [h'<protected>', {}, null, h'<signature>']}        ; COSE_Sign1, untagged, detached

protected = {1: -50,                                   ; alg: ML-DSA-87
             4: h'<48 bytes>',                         ; kid: SHA-384 COSE Key Thumbprint
             16: "application/vnd.example.b85.connectome.v0+cose"}   ; typ
body      = {0: 0x85000101,                            ; the statement's schema
             1: "<issuer>",
             2: {0: [-43, h'<SHA-384 of the canonical bytes>'], 1: <their length>,
                 2: "application/json"}}
```

**To verify**, with the canonical bytes beside the carrier and the public key from your own key
registry:

1. Decode the carrier, the protected header and the body, refusing anything that is not
   deterministic CBOR.
2. Require the protected header to be exactly `{1: -50, 4: kid, 16: typ}`, with `kid` the
   SHA-384 of `a3 01 07 03 38 31 20 59 0a 20` followed by the 2,592-byte public key (RFC 9679
   over the AKP key).
3. Verify the signature, pure ML-DSA-87 with an empty context, over
   `["Signature1", protected, h'', body]` (RFC 9052 section 4.4), the protected bytes as
   received.
4. Require the body's digest and length to be the canonical bytes'.

`tools/cross_verify/` does exactly this in Go (`fxamacker/cbor` and `crypto/mldsa`) and in Rust
(`coset`, `ciborium` and aws-lc-rs), and CI runs both on the box leg's carrier on every change.
The schema number and `typ` are provisional and change when the shared registry assigns them.
The encoder is this package's own: no Elixir library writes deterministic CBOR or COSE with
ML-DSA. It is held to RFC 8949 Appendix A and to RFC 9964 Appendix A.2, byte for byte.

## Hash envelope (non-claimed)

`BeamMCP.Signer.COSE.HashEnvelope` signs an artifact by its digest, so a 10 GB clip, tile
bundle or model file never has to be in memory whole. The host streams it in, and memory stays
one chunk and a hash state:

```elixir
{:ok, envelope} =
  BeamMCP.Signer.COSE.HashEnvelope.sign_stream(chunks,   # say, a file read 1 MiB at a time
    private_key: fn -> seed end, public_key: fn -> public_key end,
    typ: "application/vnd.example.b80.test_hash.v0+cose", preimage_type: "video/mp4")
```

`sign_digest/2` takes a digest the host already has. What comes back is the same carrier as
COSE's, with the digest as its payload:

```
{0: 0xFFFF0003, 1: h'<SHA-384 of the artifact>', 2: [h'<protected>', {}, null, h'<signature>']}

protected = {1: -50, 2: [258], 4: h'<kid>', 16: "<typ>",
             258: -43,                                 ; payload-hash-alg: SHA-384
             259: "video/mp4",                         ; preimage-content-type
             260: "<location>"}                        ; optional hint, never trusted
```

- **What it fixes.** A raw signature over a digest leaves the hash algorithm unsigned and the
  digest indistinguishable from content. Here both the hash algorithm and the preimage's type
  are in the protected header.
- **How a verifier reads it.** `crit` lists 258, so a COSE verifier that does not know hash
  envelopes refuses the signature. One that does needs only the envelope and the public key.
  It rebuilds `["Signature1", protected, h'', digest]` and verifies. When it holds the
  artifact, it also checks the digest.
- **The `typ` is the host's** and required. It is a lowercase media type ending `+cose` that
  names the kind of statement; the connectome's `typ` is refused. The preimage type is per
  artifact. `payload_hash: :sha512` gives SHA-512 (-44).
- **Non-claimed.** The signature is pure ML-DSA-87, not HashML-DSA, but no NSA, NIST or IETF
  text yet names this construction. A verified envelope is judged non-claimed, and
  `BeamMCP.Signer.COSE` stays the claimed path.
- **Tested.** CI's box leg signs a 10 GiB file, holds the VM's memory growth under 64 MiB and
  compares the digest with `sha384sum`'s. The Go and Rust verifiers read each run's envelope.
  `coset` refuses it over `crit` (it predates RFC 9995), and the Rust check confirms that
  refusal before verifying with coset's ToBeSigned.

## Any module

This package reads the key options, for COSE the issuer, and for the hash envelope its own
options listed above, and nothing else (`opts[:private_key]`, for ML-DSA-87 `opts[:public_key]`,
for COSE `opts[:issuer]`). There is no environment variable, no file and no application config.
No key, issuer or `typ` has a default.
Where the keys live between calls is the host's decision.

**Core is a separate package.** `beam_mcp` holds no key and calls no signing primitive; it is
not a dependency of this package in the other direction, and it never will be. A host that
wants signatures adds this package and attaches the module; one that does not, does not.

Apache-2.0. Erlang/OTP 27 or newer, Elixir 1.17 or newer -- the same floor as core (ML-DSA-87
as above).

**The project.** Reference documentation is on [HexDocs](https://hexdocs.pm/beam_mcp_signer).
What a host can rely on, and how to report a vulnerability: [`SECURITY.md`](SECURITY.md). Why
the security requirements hold: [`docs/assurance-case.md`](docs/assurance-case.md), with the
design in [`docs/architecture.md`](docs/architecture.md). Checking a release's signature:
[`docs/verifying-releases.md`](docs/verifying-releases.md). Contributing:
[`CONTRIBUTING.md`](https://github.com/ScriptKittyOS/beam_mcp_signer/blob/main/CONTRIBUTING.md), under the [Code of Conduct](https://github.com/ScriptKittyOS/beam_mcp_signer/blob/main/CODE_OF_CONDUCT.md). Who
decides, and what comes next: [`GOVERNANCE.md`](https://github.com/ScriptKittyOS/beam_mcp_signer/blob/main/GOVERNANCE.md),
[`docs/roadmap.md`](docs/roadmap.md). Bugs and ideas: [issues](https://github.com/ScriptKittyOS/beam_mcp_signer/issues).
