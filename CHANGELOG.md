<!--
SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

## [Unreleased]

## [0.2.1] - 2026-09-26

A security fix: two more ways the private key could reach an exception report are closed.
Upgrade by taking the patch; the requirement `~> 0.2.0` already admits it. Core requirement
unchanged (`~> 0.7`).

### Fixed: the key no longer reaches an exception report from two option shapes

- `sign/2` read the key with `Keyword.fetch/2`, which raised with the key in view on two
  shapes: an improper list (an `ArgumentError` from `:lists.keyfind/3`, the list in its frame)
  and an entry `{:private_key, key, extra}` (a `CaseClauseError` carrying the entry). The
  options are now walked by this module: an entry that is not a `{:private_key, _}` pair is
  skipped, and an improper list whose end is reached before a `:private_key` entry is answered
  `{:error, :bad_arguments}`. The first `{:private_key, key}` entry is read, as before, so a
  key found before an improper tail still signs (0.2.0's `:lists.keyfind/3` also returned
  before reaching the tail). Found by
  the project's own security review. **How to tell whether you are affected:** only a host
  that built its options in one of those shapes, and passed the key as bytes rather than by
  reference, could have printed it.

### Fixed: a key function that raises, throws or exits is answered

- A key passed by reference is read by the host's own function, and its failure could print
  the key (a seed file read with a trailing newline and matched as 32 bytes raises a
  `MatchError` over all 33). It is now answered `{:error, {:private_key, :unreadable}}`, a new
  error term, and what the function raised, threw or exited with is dropped unread, an
  `exit/1` the function means on purpose included. **How to
  tell whether you are affected:** a host whose key function can fail sees the new term in
  place of its own exception, and logs inside the function if it needs the reason.

### Fixed: a refusal from `:crypto` is answered, never re-raised

- `:crypto.sign/4` raises when it will not sign Ed25519 (a build or FIPS provider without it,
  or no `:crypto` loaded, whose `:undef` carries the call's arguments, the key among them). It
  is now answered `{:error, :crypto_refused}`, a new error term; the reason is dropped unread.

### Changed: the bus factor is two (no code change)

- `GOVERNANCE.md`: `znmead` knows the code (the maintainer's word, 2026-09-23) and reviews pull
  requests from that date, so the bus factor is two.

## [0.2.0] - 2026-09-23

A security fix and an addition, placed at the minor (0.x): the private key no longer reaches an
exception report. Upgrade from `0.1.x` by changing the requirement to `~> 0.2.0`; pass the key as
`private_key: fn -> key end`. Core requirement unchanged (`~> 0.7`, which admits `beam_mcp`
0.7 to 0.10).

### Changed: a mistyped call is answered, never raised

- A mistyped call to `sign/2` (bytes that are not a binary, options that are not a list) is
  answered `{:error, :bad_arguments}` instead of raising `FunctionClauseError`. Found by this
  package's own audit: the raised error printed its arguments, the private key among them
  (`sign("bytes", %{private_key: key})` printed all 32 bytes). **How to tell whether you are
  affected:** only code that rescued `FunctionClauseError` from `sign/2` sees a difference;
  a call through `Canonical.signature/3` with a keyword list never reached that clause.

### Added: the key by reference

- `:private_key` may be a zero-arity function returning the 32-byte key
  (`private_key: fn -> key end`), and the README now passes it that way. Anything that prints
  the options (an exception, a log line, a crash report) prints `#Function<...>` in place of
  the key's bytes, including an exception raised in `beam_mcp`'s `Canonical.signature/3` on a
  mistyped call. A function that does not return 32 bytes is `{:error, {:private_key,
  :not_32_bytes}}`, as a key that is not 32 bytes is.

### Added: the project's pages and checks (no code change)

- `SECURITY.md` (private reporting, commitments, what a host can rely on, one known limit),
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1, CC-BY-4.0 in
  `LICENSES/`), `GOVERNANCE.md`, and `docs/`: architecture, assurance case, roadmap,
  verifying a release (the tag-signing key's fingerprint). The pages are in the docs extras.
- CI: `mix credo --strict` (Credo as a dev/test dependency; `.credo.exs` adds `UnsafeToAtom`
  and `LeakyEnvironment` on `lib/`), `mix hex.audit`, and a DCO sign-off check on every
  commit. Dependabot weekly for Mix and GitHub Actions.
- `tools/release_tarball.sh`, beam_mcp's canonical-tarball script, and `files:` in `mix.exs`
  as globs, so a release's bytes are the same on every machine.
- README: the OpenSSF Best Practices badge and links to the pages above.

### Added: gold groundwork (no code change)

- `docs/security-review.md`: how a security review of this package is done, a checklist centred
  on the key, and its record, empty until the first review. `CONTRIBUTING.md`: a code-review
  section. REUSE compliance: `.gitignore` headed, `.tool-versions`, `mix.lock` and `NOTICE`
  with `.license` sidecars, `LICENSES/Apache-2.0.txt`, and `reuse lint` in CI.

### Changed: governance (no code change)

- `GOVERNANCE.md` names two continuity holders, as on `beam_mcp`: `znmead` (the Maintain role
  on this repository) and Mike Hostetler (`maintainer` ownership on hex.pm; invited to
  Maintain), what that covers and what it does not. The bus factor stays one for knowledge.
  Mike Hostetler has since accepted Maintain here too; the organization requires secure
  two-factor authentication.

## [0.1.1] - 2026-09-19

### Changed

- The `beam_mcp` requirement is `~> 0.7` (two numbers): `0.1.0`'s `~> 0.7.0` held a host on
  core `0.7.x`, so `{:beam_mcp, "~> 0.8.0"}` beside `{:beam_mcp_signer, "~> 0.1.0"}` did not
  resolve. Core's public surface is frozen from `0.7.0` to `1.0.0` by its own rule, and this
  package uses nothing outside the `BeamMCP.Signer` behaviour and the canonical bytes, so the
  wider requirement is safe until core's `1.0.0`. No code changes.

## [0.1.0] - 2026-09-19

### Added

- `BeamMCP.Signer.Ed25519.sign/2`: Ed25519 through OTP's `:crypto` over the canonical bytes,
  with the 32-byte private key read from `opts[:private_key]` and from nowhere else. Answers
  `{:ok, signature}` (64 bytes), `{:error, :no_private_key}` or
  `{:error, {:private_key, :not_32_bytes}}`.
