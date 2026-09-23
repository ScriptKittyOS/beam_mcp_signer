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
| **Maintainer** | one person: the ScriptKittyOS organization's administrator, the `full` hex.pm owner of `beam_mcp_signer` (account `aylacroft`), and the address in `SECURITY.md` | decides what lands and when; reviews every pull request; keeps CI green; answers security reports on `SECURITY.md`'s commitments; tags (signed) and publishes releases; keeps this page, the roadmap and the CHANGELOG true |
| **Continuity holders** | two people, from 2026-09-23, the same as on `beam_mcp`: `znmead`, the Maintain role on this repository; Mike Hostetler (`mikehostetler`), the Maintain role here and `maintainer` ownership of `beam_mcp_signer` on hex.pm, so he alone covers every step from issue to published release; the organization requires secure two-factor authentication | if the maintainer cannot act, keep the project going within a week between them: triage and close issues, merge pull requests once CI is green, tag (signed with their own key, announced in the CHANGELOG with its fingerprint) and publish releases; decide nothing while the maintainer can |
| **Contributor** | anyone | proposes changes by pull request under `CONTRIBUTING.md`: signed off, tested, green; reports bugs and enhancements as issues; reports vulnerabilities privately |

There is no steering group and no vote. A decision is the maintainer's and is recorded in the
tree (a CHANGELOG entry, a page, a test) or it was not made. Access is held twice; knowledge
is held once, so the bus factor is one, stated rather than hidden.

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

The continuity holders above can triage, merge and release without the maintainer.
`beam_mcp`'s succession page applies as written, including what their access does not reach:
this repository's settings, adding collaborators, and adding owners on hex.pm stay with the
maintainer (the organization's owner, the package's `full` owner), and so does the security
intake `SECURITY.md` names. The repository is public and forkable under the organization,
published releases stay on hex.pm, and this package holds no secret of its own.
