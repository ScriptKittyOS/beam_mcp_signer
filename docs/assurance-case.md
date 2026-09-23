<!--
SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
SPDX-License-Identifier: Apache-2.0
-->

# Assurance case

Why this package's security requirements (`SECURITY.md`, "What you can expect") are met, and
where they stop.

## The claim

**Given a 32-byte Ed25519 private key in the call's options, `sign/2` returns a standard
Ed25519 signature over exactly the bytes given, reads the key from nowhere else, keeps no copy
of it, and returns nothing that contains it.**

## Threat model

The asset is the host's private key; the goal is that this package adds no way for it to be
read, kept or misused beyond the host's own call.

| threat | in scope | how it is met |
|---|---|---|
| The key read from a place the host did not choose (environment, file, config) | yes | one source, `opts[:private_key]`; census over source text and compiled calls |
| The key retained after the call (process state, ETS, persistent term, app env) | yes | no state; a test compares all four before and after a call |
| The key returned or placed in an error term | yes | returns are a signature or a fixed atom tuple; tests pin every error term |
| The key printed in an exception when the call breaks the documented types | **yes, not yet met** | see "Open work" below |
| A signature over bytes other than those given, or a non-standard signature | yes | the bytes go to `:crypto.sign/4` unaltered; tests verify with `:crypto.verify/5` and with core's `encode!/2` bytes |
| Weak randomness | yes | none used: Ed25519 is deterministic (RFC 8032), no nonce or key is generated here |
| The host's key storage, the node the host runs, OpenSSL defects | no | the host's and upstream's; stated in `SECURITY.md` |
| Code already running in the same BEAM node | no | the BEAM has no in-node isolation; any process there can read the host's memory |

## Trust boundaries

1. **Host to this package.** The host is trusted to supply the key and the options. This
   package trusts nothing else: it reads no ambient configuration.
2. **This package to `beam_mcp`.** Core supplies the bytes; this package signs exactly them
   and does not interpret them.
3. **This package to OpenSSL** (through OTP `:crypto`). Trusted to implement Ed25519
   correctly; that trust is FIPS 186-5 and RFC 8032's, not this project's.

## Secure design principles applied

| principle | here |
|---|---|
| Economy of mechanism | one module, one public function, two remote calls (`:crypto.sign/4`, `Keyword.fetch/2`), pinned by census |
| Fail-safe defaults | no default key; a missing or malformed key is an error, never a signature |
| Complete mediation | the key is checked on every call; nothing is cached |
| Open design | standard Ed25519, verifiable by any implementation; the source is Apache-2.0 |
| Separation of privilege | the key-holding code is a separate package from the keyless core; the host opts in |
| Least privilege | no file, network, environment, OS or application-config access, held by census |
| Least common mechanism | no shared state between calls or callers |
| Psychological acceptability | two named error terms a host can match and act on |

## Common implementation weaknesses countered

| weakness | countered by |
|---|---|
| CWE-798 / CWE-321 hard-coded or default key | no default key; census over the source; the history is secret-scanned |
| CWE-522 / CWE-256 insufficiently protected credentials | nothing stored; the key's lifetime is the host's call |
| CWE-338 / CWE-330 weak randomness | no randomness is used |
| CWE-327 / CWE-326 broken algorithm, short key | Ed25519 only, 32-byte seeds only (about 128-bit security, NIST-approved in FIPS 186-5) |
| CWE-347 improper signature verification | not applicable to signing; tests verify every signature with an independent call |
| CWE-209 / CWE-532 key in errors or logs | met for returns; open for exceptions on misuse (below) |

## Open work

A call that breaks the documented types (bytes that are not a binary, options that are not a
keyword list) raises `FunctionClauseError`, and Elixir formats that exception with the call's
arguments, so the key can reach a crash log. `beam_mcp`'s `Canonical.signature/3` has the same
shape before it reaches this package. It needs a correctly typed call to be safe today.
Closing it is a contract decision across both packages (answer misuse with an error term that
echoes nothing, or take the key by reference so no exception can carry its bytes) and is on
`docs/roadmap.md`.

## How the case is kept true

CI runs the suite, the census and Credo on every push on three OTP/Elixir pairs; a change to how
the key is read or returned changes this page in the same pull request (`GOVERNANCE.md`).
