<!--
SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
SPDX-License-Identifier: Apache-2.0
-->

# beam_mcp_signer

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14775/badge)](https://www.bestpractices.dev/projects/14775)

An Ed25519 signer for [`beam_mcp`](https://github.com/ScriptKittyOS/beam_mcp)'s canonical
connectome bytes, through OTP's `:crypto`. One module, `BeamMCP.Signer.Ed25519`, implementing
core's `BeamMCP.Signer` behaviour (`sign/2`).

**What it signs.** Exactly the bytes `BeamMCP.Connectome.Canonical.encode/2` produces, as
`Canonical.signature/3` hands them over; the 64-byte signature comes back beside them. Nothing
else: no envelope byte moves, no verdict or receipt is added.

**Who holds the key.** The host. It passes the 32-byte Ed25519 private key on every call, as
a zero-arity function that returns it:

```elixir
{public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)   # or a key the host keeps

{:ok, %{signature: sig}} =
  BeamMCP.Connectome.Canonical.signature(graph, BeamMCP.Signer.Ed25519,
    private_key: fn -> private_key end)

true = :crypto.verify(:eddsa, :none, BeamMCP.Connectome.Canonical.encode!(graph), sig, [public_key, :ed25519])
```

**Why a function.** Options pass through the host's code and core's, and whatever prints
them (an exception raised on a mistyped call, a debug log line, a crash report) prints a key
passed as bytes, byte by byte. A function prints as `#Function<...>`. The 32 bytes themselves
are still accepted; the function is the form that nothing printed can reveal. A mistyped call
to this module is answered `{:error, :bad_arguments}` rather than raised, for the same reason.

This package reads `opts[:private_key]` and nothing else -- no environment variable, no file,
no application config, no default. Where the key lives between calls is the host's decision.

**Core is a separate package.** `beam_mcp` holds no key and calls no signing primitive; it is
not a dependency of this package in the other direction, and it never will be. A host that
wants signatures adds this package and attaches the module; one that does not, does not.

Apache-2.0. Erlang/OTP 27 or newer, Elixir 1.17 or newer -- the same floor as core.

**The project.** Reference documentation is on [HexDocs](https://hexdocs.pm/beam_mcp_signer).
What a host can rely on, and how to report a vulnerability: [`SECURITY.md`](SECURITY.md). Why
the security requirements hold: [`docs/assurance-case.md`](docs/assurance-case.md), with the
design in [`docs/architecture.md`](docs/architecture.md). Checking a release's signature:
[`docs/verifying-releases.md`](docs/verifying-releases.md). Contributing:
[`CONTRIBUTING.md`](CONTRIBUTING.md), under the [Code of Conduct](CODE_OF_CONDUCT.md). Who
decides, and what comes next: [`GOVERNANCE.md`](GOVERNANCE.md),
[`docs/roadmap.md`](docs/roadmap.md). Bugs and ideas: [issues](https://github.com/ScriptKittyOS/beam_mcp_signer/issues).
