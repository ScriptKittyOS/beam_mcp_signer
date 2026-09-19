# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.Ed25519 do
  @moduledoc """
  Ed25519 over the canonical bytes, through OTP's `:crypto`. The one signer that holds a key,
  kept out of `beam_mcp` on purpose: core makes no signature of its own.

  The host hands the key in on every call, under `:private_key` in the options it passes to
  `BeamMCP.Connectome.Canonical.signature/3`:

      Canonical.signature(graph, BeamMCP.Signer.Ed25519, private_key: seed)

  `seed` is the 32-byte Ed25519 private key -- the second element of
  `:crypto.generate_key(:eddsa, :ed25519)`, or the private half of a key the host already
  keeps. This module reads that one option and nothing else: no environment variable, no
  file, no application config, no default key. Where the key lives between calls is the
  host's decision, made outside this package.

  The signature is the 64-byte Ed25519 signature of exactly the bytes given, unhashed (Ed25519
  hashes internally; `canonical_bytes` are what a verifier re-derives with
  `BeamMCP.Connectome.Canonical.encode/2`). A verifier checks it with
  `:crypto.verify(:eddsa, :none, canonical_bytes, signature, [public_key, :ed25519])`.
  """

  @behaviour BeamMCP.Signer

  @private_key_bytes 32

  @typedoc "The 32-byte Ed25519 private key (seed) the host hands in under `:private_key`."
  @type private_key :: <<_::256>>

  @doc """
  Signs `canonical_bytes` with the Ed25519 key at `opts[:private_key]`.

  Returns `{:ok, signature}` (64 bytes), or `{:error, :no_private_key}` when the option is
  absent, or `{:error, {:private_key, :not_32_bytes}}` when it is present with another
  shape. Every other option is the host's and is not read.
  """
  @impl BeamMCP.Signer
  @spec sign(binary(), keyword()) ::
          {:ok, binary()} | {:error, :no_private_key | {:private_key, :not_32_bytes}}
  def sign(canonical_bytes, opts) when is_binary(canonical_bytes) and is_list(opts) do
    case Keyword.fetch(opts, :private_key) do
      {:ok, key} when is_binary(key) and byte_size(key) == @private_key_bytes ->
        {:ok, :crypto.sign(:eddsa, :none, canonical_bytes, [key, :ed25519])}

      {:ok, _other} ->
        {:error, {:private_key, :not_32_bytes}}

      :error ->
        {:error, :no_private_key}
    end
  end
end
