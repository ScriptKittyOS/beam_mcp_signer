<!--
SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

## [Unreleased]

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
