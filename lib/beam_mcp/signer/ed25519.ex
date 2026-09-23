# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.Ed25519 do
  @moduledoc """
  Ed25519 over the canonical bytes, through OTP's `:crypto`. The one signer that holds a key,
  kept out of `beam_mcp` on purpose: core makes no signature of its own.

  The host hands the key in on every call, under `:private_key` in the options it passes to
  `BeamMCP.Connectome.Canonical.signature/3`, best as a reference:

      Canonical.signature(graph, BeamMCP.Signer.Ed25519, private_key: fn -> seed end)

  `seed` is the 32-byte Ed25519 private key -- the second element of
  `:crypto.generate_key(:eddsa, :ed25519)`, or the private half of a key the host already
  keeps. `:private_key` is either those 32 bytes or a zero-arity function returning them.
  **Pass the function.** Options travel through the host's code and core's, and anything that
  prints them -- an exception raised on a mistyped call prints its arguments, a debug log
  line, a crash report -- prints the bytes of a key passed as bytes, and `#Function<...>` for
  a key passed by reference. This module calls the function once per signature and keeps
  nothing.

  This module reads that one option and nothing else: no environment variable, no file, no
  application config, no default key. Where the key lives between calls is the host's
  decision, made outside this package.

  The signature is the 64-byte Ed25519 signature of exactly the bytes given, unhashed (Ed25519
  hashes internally; `canonical_bytes` are what a verifier re-derives with
  `BeamMCP.Connectome.Canonical.encode/2`). A verifier checks it with
  `:crypto.verify(:eddsa, :none, canonical_bytes, signature, [public_key, :ed25519])`.
  """

  @behaviour BeamMCP.Signer

  @private_key_bytes 32

  @typedoc """
  The 32-byte Ed25519 private key (seed) the host hands in under `:private_key`, or a
  zero-arity function returning it (the form that no printed term can reveal).
  """
  @type private_key :: <<_::256>> | (-> <<_::256>>)

  @doc """
  Signs `canonical_bytes` with the Ed25519 key at `opts[:private_key]`.

  Returns `{:ok, signature}` (64 bytes); `{:error, :no_private_key}` when the option is
  absent; `{:error, {:private_key, :not_32_bytes}}` when it is present and is not 32 bytes,
  or is a function that does not return 32 bytes; and `{:error, :bad_arguments}` when
  `canonical_bytes` is not a binary or `opts` is not a list. That last is an answer, not a
  raise, on purpose: a `FunctionClauseError` is printed with the call's arguments, and the
  options hold the key. No result carries any byte of what was passed. Every other option is
  the host's and is not read.
  """
  @impl BeamMCP.Signer
  @spec sign(binary(), keyword()) ::
          {:ok, binary()}
          | {:error, :no_private_key | {:private_key, :not_32_bytes} | :bad_arguments}
  def sign(canonical_bytes, opts) when is_binary(canonical_bytes) and is_list(opts) do
    case Keyword.fetch(opts, :private_key) do
      {:ok, key} -> sign_with(canonical_bytes, resolve(key))
      :error -> {:error, :no_private_key}
    end
  end

  def sign(_canonical_bytes, _opts), do: {:error, :bad_arguments}

  # A reference is called here and nowhere else, once per signature; its result is not kept.
  defp resolve(key) when is_function(key, 0), do: key.()
  defp resolve(key), do: key

  defp sign_with(canonical_bytes, key)
       when is_binary(key) and byte_size(key) == @private_key_bytes,
       do: {:ok, :crypto.sign(:eddsa, :none, canonical_bytes, [key, :ed25519])}

  defp sign_with(_canonical_bytes, _key), do: {:error, {:private_key, :not_32_bytes}}
end
