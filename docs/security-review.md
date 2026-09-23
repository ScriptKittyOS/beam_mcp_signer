<!--
SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
SPDX-License-Identifier: Apache-2.0
-->

# Security review

How a security review of this package is done, and the record of each one. A review is a
person reading the code against the package's security claims; the tests, the census and Credo
support it and do not replace it. One is done at least every five years, and before `1.0.0`.
`beam_mcp`'s own procedure
([docs/security-review.md](https://github.com/ScriptKittyOS/beam_mcp/blob/main/docs/security-review.md))
covers the bytes this package signs.

## What it is measured against

`SECURITY.md` ("What you can expect from this package") and the claim, threat model and trust
boundaries in `docs/assurance-case.md`.

## The checklist

Each item is answered with what was read, what was tried, and what was found.

1. **One source for the key.** Read `lib/beam_mcp/signer/ed25519.ex` in full. Is the key read
   from `opts[:private_key]` only? Does the census's regex and call list still describe the
   compiled module (`test/beam_mcp/signer/no_key_source_test.exs`)?
2. **Nothing kept.** No process state, table, persistent term, application environment or
   file after a call; a reference (`fn -> key end`) called once and dropped.
3. **Nothing printed.** Every result is a signature or a fixed error term; no clause can raise
   on its arguments. Try a map for the options, a non-binary for the bytes, a wrong-length key
   and a reference returning the wrong thing, and read what comes back and what a log would show.
4. **The signature.** Ed25519 over exactly the bytes given, verified independently with
   `:crypto.verify/5` and through `beam_mcp`'s canonical bytes; no prehash, no other algorithm.
5. **Randomness.** None is used; confirm that no key or nonce is generated in `lib/`.
6. **Supply chain and release.** `mix.lock` against `mix hex.audit`; the `beam_mcp` requirement;
   workflow permissions and pinned actions; a release tarball rebuilt with
   `tools/release_tarball.sh` and compared with hex.pm's checksum; the tag's signature
   (`docs/verifying-releases.md`).
7. **The pages.** Does the assurance case, `SECURITY.md` and the README still describe the code?

## After a review

Findings go through `SECURITY.md` (a private advisory where warranted), each with an issue or a
pull request. The review is recorded below in the pull request that adds the row.

## Record

| date | reviewer | commit | scope | findings |
|---|---|---|---|---|

No review has been recorded yet. The audit that found and closed the key-in-exception defect
(`docs/assurance-case.md`, "Closed") was automated-assisted groundwork for the first review, not
a review under this page's definition.
