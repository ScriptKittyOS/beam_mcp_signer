<!--
SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
SPDX-License-Identifier: Apache-2.0
-->

# beam_mcp_signer

An Ed25519 signer for [`beam_mcp`](https://github.com/ScriptKittyOS/beam_mcp)'s canonical
connectome bytes, through OTP's `:crypto`. One module, `BeamMCP.Signer.Ed25519`, implementing
core's `BeamMCP.Signer` behaviour (`sign/2`).

**What it signs.** Exactly the bytes `BeamMCP.Connectome.Canonical.encode/2` produces, as
`Canonical.signature/3` hands them over; the 64-byte signature comes back beside them. Nothing
else: no envelope byte moves, no verdict or receipt is added.

**Who holds the key.** The host. It passes the 32-byte Ed25519 private key on every call:

```elixir
{public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)   # or a key the host keeps

{:ok, %{signature: sig}} =
  BeamMCP.Connectome.Canonical.signature(graph, BeamMCP.Signer.Ed25519, private_key: private_key)

true = :crypto.verify(:eddsa, :none, BeamMCP.Connectome.Canonical.encode!(graph), sig, [public_key, :ed25519])
```

This package reads `opts[:private_key]` and nothing else -- no environment variable, no file,
no application config, no default. Where the key lives between calls is the host's decision.

**Core is a separate package.** `beam_mcp` holds no key and calls no signing primitive; it is
not a dependency of this package in the other direction, and it never will be. A host that
wants signatures adds this package and attaches the module; one that does not, does not.

Apache-2.0. Erlang/OTP 27 or newer, Elixir 1.17 or newer -- the same floor as core.
