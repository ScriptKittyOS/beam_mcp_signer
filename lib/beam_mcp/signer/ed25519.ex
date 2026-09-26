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
  or is a function that does not return 32 bytes; `{:error, {:private_key, :unreadable}}` when
  it is a function that raises, throws or exits (an `exit/1` the function means on purpose
  included); and `{:error, :bad_arguments}` when `canonical_bytes` is not a binary or `opts`
  is not a list, or is an improper list whose end is reached before a `:private_key` entry (a
  `:private_key` entry found before an improper tail is read, and signs, as it did before). Those are answers, not raises, on purpose: an
  exception is printed with the values it was raised over, and the options, or the host's own
  reading of the key, hold the key. For the same reason a refusal from `:crypto` itself (an
  OpenSSL build or FIPS provider that does not offer Ed25519, or no `:crypto` loaded at all) is
  answered `{:error, :crypto_refused}`, never re-raised. No result carries any byte of what was
  passed; the cost is that the host's own exception from its key function is dropped too, so a
  host that needs it logs it inside that function. Every other option is the host's and is not
  read.
  """
  @impl BeamMCP.Signer
  @spec sign(binary(), keyword()) ::
          {:ok, binary()}
          | {:error,
             :no_private_key
             | {:private_key, :not_32_bytes | :unreadable}
             | :bad_arguments
             | :crypto_refused}
  def sign(canonical_bytes, opts) when is_binary(canonical_bytes) and is_list(opts) do
    with {:ok, key} <- fetch_key(opts),
         {:ok, bytes} <- resolve(key) do
      sign_with(canonical_bytes, bytes)
    else
      :error -> {:error, :no_private_key}
      :bad -> {:error, :bad_arguments}
      :unreadable -> {:error, {:private_key, :unreadable}}
    end
  end

  def sign(_canonical_bytes, _opts), do: {:error, :bad_arguments}

  # The first `{:private_key, key}` entry, walked here instead of by `Keyword.fetch/2`, which
  # raised with the key in view on two shapes: an improper list (an ArgumentError from
  # `:lists.keyfind/3`, the list, key and all, in its frame) and a longer tuple that starts
  # with `:private_key` (a CaseClauseError carrying that tuple). Here any entry that is not a
  # `{:private_key, _}` pair is skipped, and an improper tail reached before one is refused.
  defp fetch_key([{:private_key, key} | _]), do: {:ok, key}
  defp fetch_key([_ | rest]), do: fetch_key(rest)
  defp fetch_key([]), do: :error
  defp fetch_key(_improper_tail), do: :bad

  # A reference is called here and nowhere else, once per signature; its result is not kept.
  # What it raises, throws or exits is the host's code reading the key, and its report can
  # print the key (a MatchError on a seed file with a trailing newline prints the bytes): it
  # is answered as unreadable, the reason dropped unread. The answer is tagged, so no value the
  # function returns can be mistaken for the failure.
  defp resolve(key) when is_function(key, 0) do
    {:ok, key.()}
  catch
    _kind, _reason -> :unreadable
  end

  defp resolve(key), do: {:ok, key}

  # `:crypto` raises when OpenSSL will not sign (a build or FIPS provider without Ed25519, or
  # no `:crypto` loaded, which is `:undef` with the call's arguments, the key among them, in
  # its frame), and such a report may carry the key: answered here, the reason dropped unread.
  defp sign_with(canonical_bytes, key)
       when is_binary(key) and byte_size(key) == @private_key_bytes do
    {:ok, :crypto.sign(:eddsa, :none, canonical_bytes, [key, :ed25519])}
  catch
    _kind, _reason -> {:error, :crypto_refused}
  end

  defp sign_with(_canonical_bytes, _key), do: {:error, {:private_key, :not_32_bytes}}
end
