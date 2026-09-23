<!--
SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
SPDX-License-Identifier: Apache-2.0
-->

# Security Policy

## Reporting a vulnerability

Report privately through **[GitHub Security Advisories](https://github.com/ScriptKittyOS/beam_mcp_signer/security/advisories/new)**.
Please do not open a public issue for a suspected vulnerability. A report that cannot go
through the form goes to **ayla@scriptkittyos.com**, the maintainer, on the same commitments.

A report about `beam_mcp` itself (the protocol core, the canonical bytes) belongs to
[its policy](https://github.com/ScriptKittyOS/beam_mcp/blob/main/SECURITY.md); if you are not
sure which package it is, send it to either and it will be routed.

## What this project commits to

One person maintains this package, and these are commitments that can be kept:

- **Acknowledgement within 7 days.** If you hear nothing after 7 days, assume the report did
  not arrive and open a public issue saying only that you are waiting on a security response.
- **An assessment within 30 days** of acknowledgement: in scope or not, a rough severity, and
  an intended fix window. If it will take longer, you are told so.
- **Credit in the advisory and the changelog**, unless you ask otherwise.

No paid bounty and no guaranteed fix deadline.

## What you can expect from this package

The security requirements a host can rely on, each held by a test in `test/`:

- **The key is read from one place.** `sign/2` reads the private key from
  `opts[:private_key]` on each call and from nowhere else: no environment variable, file,
  application config, default key or store. A two-layer census holds it
  (`test/beam_mcp/signer/no_key_source_test.exs`).
- **The key does not leave in a result or an exception.** Every return value is a signature or
  a fixed error term; neither carries the key. A mistyped call is answered
  `{:error, :bad_arguments}`, never raised, because a raised `FunctionClauseError` prints its
  arguments. Passed by reference (`private_key: fn -> key end`, the README's form), the key
  cannot be printed by anything: not an exception raised earlier in core's
  `Canonical.signature/3` on a mistyped call, not a log line that inspects the options. Passed
  as bytes, the key is as safe as every piece of code that handles the options; tests pin both
  halves (`test/beam_mcp/signer/ed25519_test.exs`).
- **The signature is standard Ed25519** (RFC 8032, FIPS 186-5) over exactly the canonical bytes
  `beam_mcp` produced, computed by Erlang/OTP's `:crypto` (OpenSSL), and verifiable by any
  Ed25519 implementation.
- **No randomness is needed or used.** Ed25519 signing is deterministic; the package generates
  no key and no nonce.

What it does **not** do: store, load, rotate or protect the key between calls (the host's
decision, `docs/assurance-case.md` says why), verify signatures, or decide what a signature
authorizes.

## Severity, in this package's terms

| level | what it means here |
|---|---|
| **Critical** | On a call with the documented types: the key is read from anywhere but the call's options, or reaches a log, an error, a crash report or a return value; or a signature is produced over bytes other than those given. |
| **High** | A signature that standard Ed25519 verification rejects, or accepts over different bytes. |
| **Medium** | A documented behaviour the package does not match, with a security consequence a host can work around. |
| **Low** | Wrong error terms or documentation that could mislead. |

## CVEs

Advisories are published from this repository's GitHub Security Advisories. GitHub is a CVE
Numbering Authority for the repositories it hosts, so a CVE is requested from the advisory
draft when the defect warrants one; Critical and High always do. Published advisories reach
the GitHub Advisory Database and OSV, which `mix hex.audit` reads.

## Out of scope

- How and where the host stores the key.
- Defects in Erlang/OTP's `:crypto` or OpenSSL; report those upstream.
- `beam_mcp`'s own code; see its policy, linked above.

## Supported versions

| version | supported |
|---|---|
| `0.2.x` | yes |
| `0.1.x` | no, superseded (the key could reach an exception report; see the 0.2.0 CHANGELOG entry) |

Fixes land on the latest release.
