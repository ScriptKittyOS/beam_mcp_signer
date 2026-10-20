<!--
SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
SPDX-License-Identifier: Apache-2.0
-->

# Assurance case

Why this package's security requirements (`SECURITY.md`, "What you can expect") are met, and
where they stop.

## The claim

**Given a 32-byte Ed25519 private key in the call's options (or a zero-arity function returning it), `sign/2` returns a standard
Ed25519 signature over exactly the bytes given, reads the key from nowhere else, keeps no copy
of it, and returns nothing that contains it.**

**Given a 32-byte ML-DSA-87 seed and its 2,592-byte public key in the call's options (each, or
a zero-arity function returning it), `BeamMCP.Signer.MLDSA87.sign/2` returns a standard
ML-DSA-87 signature (FIPS 204, pure, empty context) over exactly the bytes given that verifies
under that public key, or no signature at all; it reads the keys from nowhere else, keeps no
copy of them, and returns nothing that contains them.**

## Threat model

The asset is the host's private key; the goal is that this package adds no way for it to be
read, kept or misused beyond the host's own call.

| threat | in scope | how it is met |
|---|---|---|
| The key read from a place the host did not choose (environment, file, config) | yes | one source, the call's options (`:private_key`, and `:public_key` for ML-DSA-87); census over source text and compiled calls |
| The key retained after the call (process state, ETS, persistent term, app env) | yes | no state; a test compares all four before and after a call |
| The key returned or placed in an error term | yes | returns are a signature or a fixed atom tuple; tests pin every error term |
| The key printed in an exception or a log line | yes | nothing `sign/2` meets is raised: a mistyped call is answered `{:error, :bad_arguments}` (so is an improper list whose end comes before a `:private_key` entry), a failing key function `{:error, {:private_key, :unreadable}}`, a refusal from `:crypto` `{:error, :crypto_refused}`; the key passed by reference prints as `#Function<...>` wherever the options are printed, core's frames included (tested through core) |
| A signature over bytes other than those given, or a non-standard signature | yes | the bytes go to `:crypto.sign/4` unaltered, with the algorithm and `:none` as literals and no options argument (census); tests verify with `:crypto.verify/5` and with core's `encode!/2` bytes |
| ML-DSA-87: a signature that does not verify under the key the host publishes (a seed and public key that are not a pair, a faulted signature) | yes | every signature is verified under the given public key, and must not verify over bytes one bit away, before it is returned; otherwise a named error and no signature |
| Weak randomness | yes | Ed25519 uses none (deterministic, RFC 8032). ML-DSA-87 is hedged: OpenSSL's DRBG supplies the per-signature `rnd`; were it constant, signing would be FIPS 204's deterministic variant, which is also approved. No key is generated here |
| The host's key storage, the node the host runs, OpenSSL defects | no | the host's and upstream's; stated in `SECURITY.md` |
| Code already running in the same BEAM node | no | the BEAM has no in-node isolation; any process there can read the host's memory |

## Trust boundaries

1. **Host to this package.** The host is trusted to supply the key and the options. This
   package trusts nothing else: it reads no ambient configuration.
2. **This package to `beam_mcp`.** Core supplies the bytes; this package signs exactly them
   and does not interpret them.
3. **This package to OpenSSL** (through OTP `:crypto`). Trusted to implement Ed25519 and
   ML-DSA-87 correctly; that trust is FIPS 186-5, RFC 8032 and FIPS 204's, not this
   project's. For ML-DSA-87 the suite holds the runtime to NIST ACVP and Wycheproof vectors,
   every case `:crypto` can express, on the CI leg that runs it.

## Secure design principles applied

| principle | here |
|---|---|
| Economy of mechanism | two modules, one public function each; remote calls `:crypto.sign/4`, and `:crypto.verify/5` for ML-DSA-87's check, pinned by census |
| Fail-safe defaults | no default key; a missing or malformed key is an error, never a signature |
| Complete mediation | the key is checked on every call; nothing is cached |
| Open design | standard Ed25519 and ML-DSA-87, verifiable by any implementation; the source is Apache-2.0 |
| Separation of privilege | the key-holding code is a separate package from the keyless core; the host opts in |
| Least privilege | no file, network, environment, OS or application-config access, held by census |
| Least common mechanism | no shared state between calls or callers |
| Psychological acceptability | named error terms a host can match and act on (each module's `sign/2` doc lists its own) |

## Common implementation weaknesses countered

| weakness | countered by |
|---|---|
| CWE-798 / CWE-321 hard-coded or default key | no default key; census over the source; the history is secret-scanned |
| CWE-522 / CWE-256 insufficiently protected credentials | nothing stored; the key's lifetime is the host's call |
| CWE-338 / CWE-330 weak randomness | Ed25519 uses none; ML-DSA-87's hedging randomness is OpenSSL's DRBG, and its failure degrades to the deterministic variant, not to a key leak |
| CWE-327 / CWE-326 broken algorithm, short key | Ed25519 with 32-byte seeds (about 128-bit security, NIST-approved in FIPS 186-5); ML-DSA-87 with 32-byte seeds (NIST security category 5, FIPS 204, the CNSA 2.0 signature) |
| CWE-347 improper signature verification | not applicable to signing; tests verify every signature with an independent call, and ML-DSA-87 verifies its own before returning it |
| CWE-209 / CWE-532 key in errors or logs | no result echoes input; no clause can raise on its arguments; the reference form keeps the bytes out of every printed term (see "Closed" below) |

## Closed: the key in an exception report (found 2026-09-23)

Before this change, a call that broke the documented types (bytes that are not a binary,
options that are not a keyword list) raised `FunctionClauseError`, and Elixir formats that
exception with the call's arguments, so the key reached whatever logged it. Measured:
`sign("bytes", %{private_key: key})` printed the 32 bytes. `beam_mcp`'s
`Canonical.signature/3` raises the same way on mistyped options, before this package is
reached. Two layers close it, both in this package:

1. `sign/2` is total. A mistyped call is answered `{:error, :bad_arguments}` (so is an
   improper list whose end comes before a `:private_key` entry), a key function that raises,
   throws or exits is answered `{:error, {:private_key, :unreadable}}`, and a refusal from
   `:crypto` is answered `{:error, :crypto_refused}`. None carries anything that was passed.
2. `:private_key` may be a zero-arity function returning the key, and the README passes it
   that way. A function prints as `#Function<...>`, so a key passed by reference cannot appear
   in an exception from core, a crash report or a log line.

What remains is stated: a host that passes the key as bytes and then calls core with mistyped
options still gets the bytes in core's exception. A test pins that fact, so it fails the day
core answers such a call instead of raising.

## How the case is kept true

CI runs the suite, the census and Credo on every push on four OTP/Elixir legs; the ML-DSA-87
tests run on the box leg, which fails if its `:crypto` does not offer the algorithm (the other
legs check the `:crypto_refused` answer instead). A change to how a key is read or returned
changes this page in the same pull request (`GOVERNANCE.md`).
