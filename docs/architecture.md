<!--
SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
SPDX-License-Identifier: Apache-2.0
-->

# Architecture

One module, one function, one dependency direction.

```text
 host application
   |  Canonical.signature(graph, BeamMCP.Signer.Ed25519, private_key: fn -> key end, ...)
   v
 beam_mcp  (BeamMCP.Connectome.Canonical)
   |  encodes the graph to canonical bytes, then calls the signer through
   |  the BeamMCP.Signer behaviour: sign(canonical_bytes, opts)
   v
 beam_mcp_signer  (BeamMCP.Signer.Ed25519.sign/2)
   |  reads opts[:private_key] (32 bytes, or fn -> bytes end) and nothing else
   v
 Erlang/OTP :crypto.sign(:eddsa, :none, canonical_bytes, [key, :ed25519])   (OpenSSL)
   |
   v
 {:ok, 64-byte signature}  ->  placed beside the bytes by beam_mcp
```

## The parts

- **`BeamMCP.Signer.Ed25519`** (`lib/beam_mcp/signer/ed25519.ex`): implements `beam_mcp`'s
  `BeamMCP.Signer` behaviour. `sign/2` takes the canonical bytes and the host's options, reads
  the private key from `opts[:private_key]` (the 32 bytes, or a zero-arity function returning
  them, which is called once), checks it is a 32-byte binary, and returns `{:ok, signature}`,
  `{:error, :no_private_key}` or `{:error, {:private_key, :not_32_bytes}}`. A mistyped call is
  answered `{:error, :bad_arguments}`, never raised, so no exception prints the options.
- **`beam_mcp`** (a dependency, `~> 0.7`): defines the behaviour and produces the bytes. It
  holds no key, calls no signing primitive and does not depend on this package.
- **Erlang/OTP `:crypto`**: performs Ed25519. This package implements no cryptography itself.

## Properties the arrangement keeps

- **The key lives with the host.** Nothing is stored between calls: no process, table,
  persistent term, application environment or file. A test checks that no state remains after
  a call.
- **One way in.** The key has one source, the call's options; a census over both the source
  and the compiled module holds that (`test/beam_mcp/signer/no_key_source_test.exs`).
- **Core stays keyless.** Authority (a key, a signature) is kept out of `beam_mcp` by putting
  it here, in a package a host chooses to add.

## Where to read next

`docs/assurance-case.md` (why the security requirements hold), `SECURITY.md` (what a host can
expect), and `beam_mcp`'s
[`docs/architecture.md`](https://github.com/ScriptKittyOS/beam_mcp/blob/main/docs/architecture.md)
for the bytes being signed.
