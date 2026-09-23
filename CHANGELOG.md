<!--
SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

## [Unreleased]

### Changed: governance (no code change)

- `GOVERNANCE.md` names two continuity holders, as on `beam_mcp`: `znmead` (the Maintain role
  on this repository) and Mike Hostetler (`maintainer` ownership on hex.pm; invited to
  Maintain), what that covers and what it does not. The bus factor stays one for knowledge.

### Added

- `:private_key` may be a zero-arity function returning the 32-byte key
  (`private_key: fn -> key end`), and the README now passes it that way. Anything that prints
  the options (an exception, a log line, a crash report) prints `#Function<...>` in place of
  the key's bytes, including an exception raised in `beam_mcp`'s `Canonical.signature/3` on a
  mistyped call. A function that does not return 32 bytes is `{:error, {:private_key,
  :not_32_bytes}}`, as a key that is not 32 bytes is.

### Changed

- A mistyped call to `sign/2` (bytes that are not a binary, options that are not a list) is
  answered `{:error, :bad_arguments}` instead of raising `FunctionClauseError`. Found by this
  package's own audit: the raised error printed its arguments, the private key among them
  (`sign("bytes", %{private_key: key})` printed all 32 bytes). **How to tell whether you are
  affected:** only code that rescued `FunctionClauseError` from `sign/2` sees a difference;
  a call through `Canonical.signature/3` with a keyword list never reached that clause.

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

## [0.1.1] — 2026-09-19

### Changed

- The `beam_mcp` requirement is `~> 0.7` (two numbers): `0.1.0`'s `~> 0.7.0` held a host on
  core `0.7.x`, so `{:beam_mcp, "~> 0.8.0"}` beside `{:beam_mcp_signer, "~> 0.1.0"}` did not
  resolve. Core's public surface is frozen from `0.7.0` to `1.0.0` by its own rule, and this
  package uses nothing outside the `BeamMCP.Signer` behaviour and the canonical bytes, so the
  wider requirement is safe until core's `1.0.0`. No code changes.

## [0.1.0] — 2026-09-19

### Added

- `BeamMCP.Signer.Ed25519.sign/2`: Ed25519 through OTP's `:crypto` over the canonical bytes,
  with the 32-byte private key read from `opts[:private_key]` and from nowhere else. Answers
  `{:ok, signature}` (64 bytes), `{:error, :no_private_key}` or
  `{:error, {:private_key, :not_32_bytes}}`.
