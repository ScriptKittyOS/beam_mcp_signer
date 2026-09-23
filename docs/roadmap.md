<!--
SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
SPDX-License-Identifier: Apache-2.0
-->

# Roadmap

What this package intends to do, and not do, over the next year (to September 2027). Dates
are not promised; the order is.

## Planned

1. **Done: the misuse path** (`docs/assurance-case.md`, "Closed"). The key passed by reference
   reaches no exception report; a mistyped call is answered, not raised.
2. **Follow `beam_mcp` to `1.0.0`.** The requirement is `~> 0.7` today; when core ships
   `1.0.0`, this package releases with a `~> 1.0` requirement, and then takes its own `1.0.0`
   once its surface (one function, four results) has stood a release unchanged.
3. **Release tooling as core has it**: the canonical tarball script (in the tree) used for
   every publish, and a build-provenance attestation on each release tag.
4. **Keep current**: security fixes on `SECURITY.md`'s commitments, dependency updates through
   Dependabot, and the OTP/Elixir pairs CI tests moved forward with `beam_mcp`'s.

## Will not do

- **Store, load, generate or rotate keys.** The host holds the key; this package reads it from
  the call's options and nowhere else. That is the package's reason to exist.
- **Implement cryptography.** Ed25519 is OTP's `:crypto`, backed by OpenSSL.
- **Verify signatures or decide what they authorize.** Verification is one standard call any
  consumer can make; authority is the consumer's.
- **Make `beam_mcp` depend on it.** The dependency runs one way.

A second algorithm is not planned; if one is ever needed it would be a separate module
implementing the same behaviour, decided in the open.

## How it changes

A change to this page is made in the pull request that changes direction, and recorded in the
CHANGELOG. Proposals are issues on the repository.
