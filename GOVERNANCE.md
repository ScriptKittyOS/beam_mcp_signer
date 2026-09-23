<!--
SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
SPDX-License-Identifier: Apache-2.0
-->

# Governance

Who decides, how a change lands, and what happens if the maintainer stops. This package is
governed exactly as [`beam_mcp`](https://github.com/ScriptKittyOS/beam_mcp) is, by the same
person; its [governance page](https://github.com/ScriptKittyOS/beam_mcp/blob/main/docs/governance.md)
and [succession page](https://github.com/ScriptKittyOS/beam_mcp/blob/main/docs/succession.md)
apply here, and this page says what is particular to this repository.

## Roles

| role | who | responsibilities |
|---|---|---|
| **Maintainer** | one person: the ScriptKittyOS organization's administrator, the hex.pm owner of `beam_mcp_signer` (account `aylacroft`), and the address in `SECURITY.md` | decides what lands and when; reviews every pull request; keeps CI green; answers security reports on `SECURITY.md`'s commitments; tags (signed) and publishes releases; keeps this page, the roadmap and the CHANGELOG true |
| **Contributor** | anyone | proposes changes by pull request under `CONTRIBUTING.md`: signed off, tested, green; reports bugs and enhancements as issues; reports vulnerabilities privately |

There is no steering group and no vote. A decision is the maintainer's and is recorded in the
tree (a CHANGELOG entry, a page, a test) or it was not made. The bus factor is one, stated
rather than hidden.

## How a change lands

1. A branch and a pull request; nothing is pushed to `main` directly.
2. CI on three OTP/Elixir pairs (the floor, the pinned line, the newest) and the DCO check.
3. The maintainer's review, then a rebase merge.
4. A release is a signed tag and a hex.pm publish by the maintainer, recorded in the
   CHANGELOG; `docs/verifying-releases.md` says how to check one.

## What is particular to this package

It is the one package of the two that handles key material, so a change to how the key is
read, used or returned is held to the key-source census and to `docs/assurance-case.md`, and
the assurance case changes in the same pull request.

## If the maintainer stops

`beam_mcp`'s succession page applies as written: the repository is public and forkable under
the organization, published releases stay on hex.pm, and a successor needs organization
ownership, `mix hex.owner add beam_mcp_signer` from the current owner (or hex.pm's support
process), and nothing else: this package holds no secret of its own.
