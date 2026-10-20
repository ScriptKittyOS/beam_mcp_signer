<!--
SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
SPDX-License-Identifier: Apache-2.0
-->

# beam_mcp_signer

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14775/badge)](https://www.bestpractices.dev/projects/14775)

Signers for [`beam_mcp`](https://github.com/ScriptKittyOS/beam_mcp)'s canonical connectome
bytes, through OTP's `:crypto`. Two modules, each implementing core's `BeamMCP.Signer`
behaviour (`sign/2`) and nothing else:

- **`BeamMCP.Signer.Ed25519`**: Ed25519 (RFC 8032), a 64-byte signature.
- **`BeamMCP.Signer.MLDSA87`**: ML-DSA-87 (FIPS 204), the post-quantum signature CNSA 2.0
  names, a 4,627-byte signature. It needs an OTP whose `:crypto` is linked to OpenSSL 3.5 or
  later; see [ML-DSA-87](#ml-dsa-87) below.

**What they sign.** Exactly the bytes `BeamMCP.Connectome.Canonical.encode/2` produces, as
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

## Either module

This package reads the key options and nothing else (`opts[:private_key]`, and for ML-DSA-87
`opts[:public_key]`) -- no environment variable, no file, no application config, no default.
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
