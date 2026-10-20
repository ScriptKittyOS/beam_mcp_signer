# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.MLDSA87 do
  @moduledoc """
  ML-DSA-87 (FIPS 204) over the canonical bytes, through OTP's `:crypto`: pure ML-DSA, the
  external interface, an empty context (the form RFC 9964 requires for COSE, algorithm -50).
  The same seam as `BeamMCP.Signer.Ed25519`, the same rules for the key, and one more option.

  The host hands in two keys on every call, in the options it passes to
  `BeamMCP.Connectome.Canonical.signature/3`, best as references:

      Canonical.signature(graph, BeamMCP.Signer.MLDSA87,
        private_key: fn -> seed end, public_key: fn -> public_key end, scheme: :mldsa87)

  `:private_key` is the 32-byte seed, RFC 9964's one private-key form. `:public_key` is the
  2,592-byte public key that seed derives. Both are required: `:crypto` signs from a seed but
  cannot derive the public key from one, so the host provisions the pair outside the VM and
  hands in both. Each is either the bytes or a zero-arity function returning them. **Pass
  functions**, for the reason `BeamMCP.Signer.Ed25519` gives: anything that prints the options
  prints the bytes of a key passed as bytes. Each function is called once per signature, and
  nothing is kept.

  This module reads those two options and nothing else: no environment variable, no file, no
  application config, no default key.

  **Every signature is checked before it is returned.** It must verify under the public key the
  host handed in, over exactly the bytes given, or the answer is
  `{:error, {:public_key, :does_not_verify}}` and no signature leaves this module: that is how a
  seed and a public key that are not a pair are caught, which `:crypto` cannot tell otherwise.
  And the same signature over the bytes with one bit flipped must not verify, or the answer is
  `{:error, :self_check_failed}`: a verifier that accepts anything would make the first check
  worthless. Two verifies per signature, the cost of returning only signatures that verify.

  **Hedged signing.** OpenSSL draws fresh randomness for every signature from its DRBG, and
  `:crypto` cannot select FIPS 204's deterministic variant: two signatures of the same bytes
  with the same key differ, and both verify. A byte-exact signature cannot be a test vector.

  The signature is 4,627 bytes. A verifier checks it with
  `:crypto.verify(:mldsa87, :none, canonical_bytes, signature, public_key)`, or with any
  FIPS 204 implementation, pure ML-DSA-87 with an empty context.

  **Where it runs.** ML-DSA-87 needs an OTP whose `:crypto` is linked to OpenSSL 3.5 or later
  (OTP 28.1 and later; OTP 27 has none). Elsewhere every call is answered
  `{:error, :crypto_refused}`, as it is in FIPS mode under a provider that does not approve
  ML-DSA. In FIPS mode under one that does, OpenSSL's configuration must itself set
  `default_properties = fips=yes`; OTP's `fips_mode` alone leaves the signature unavailable.
  """

  @behaviour BeamMCP.Signer

  @private_key_bytes 32
  @public_key_bytes 2592

  @typedoc "The 32-byte ML-DSA-87 seed, or a zero-arity function returning it."
  @type private_key :: <<_::256>> | (-> <<_::256>>)

  @typedoc "The 2,592-byte ML-DSA-87 public key, or a zero-arity function returning it."
  @type public_key :: <<_::20_736>> | (-> <<_::20_736>>)

  @doc """
  Signs `canonical_bytes` with the seed at `opts[:private_key]`, checked against the public
  key at `opts[:public_key]`.

  Returns `{:ok, signature}` (4,627 bytes) or `{:error, reason}`:

    * `:no_private_key`, `:no_public_key` -- the option is absent (the private key is
      looked for first);
    * `{:private_key, :not_32_bytes}`, `{:public_key, :not_2592_bytes}` -- present, and not
      that size, or a function returning something else;
    * `{:private_key, :unreadable}`, `{:public_key, :unreadable}` -- a function that raises,
      throws or exits;
    * `:bad_arguments` -- `canonical_bytes` is not a binary, or `opts` is not a list, or is an
      improper list whose end is reached before both keys;
    * `:crypto_refused` -- `:crypto` will not sign or verify ML-DSA-87 here;
    * `{:public_key, :does_not_verify}` -- the signature does not verify under the public key:
      the two keys are not a pair;
    * `:self_check_failed` -- the signature also verifies over different bytes.

  Answers, not raises, for `BeamMCP.Signer.Ed25519`'s reason: an exception is printed with the
  values it was raised over, and the options hold the keys. No answer carries a byte of either
  key. Every other option is the host's and is not read.
  """
  @impl BeamMCP.Signer
  @spec sign(binary(), keyword()) ::
          {:ok, binary()}
          | {:error,
             :no_private_key
             | :no_public_key
             | {:private_key, :not_32_bytes | :unreadable}
             | {:public_key, :not_2592_bytes | :unreadable | :does_not_verify}
             | :bad_arguments
             | :crypto_refused
             | :self_check_failed}
  def sign(canonical_bytes, opts) when is_binary(canonical_bytes) and is_list(opts) do
    with {:ok, seed} <- fetch_key(opts, :private_key),
         {:ok, public} <- fetch_key(opts, :public_key),
         {:ok, seed} <- read(seed, :private_key, @private_key_bytes, :not_32_bytes),
         {:ok, public} <- read(public, :public_key, @public_key_bytes, :not_2592_bytes) do
      sign_checked(canonical_bytes, seed, public)
    end
  end

  def sign(_canonical_bytes, _opts), do: {:error, :bad_arguments}

  # The first `{name, key}` entry, walked here for the reason `BeamMCP.Signer.Ed25519` walks
  # its own: `Keyword.fetch/2` raises, key in view, on an improper list.
  defp fetch_key([{name, key} | _], name), do: {:ok, key}
  defp fetch_key([_ | rest], name), do: fetch_key(rest, name)
  defp fetch_key([], :private_key), do: {:error, :no_private_key}
  defp fetch_key([], :public_key), do: {:error, :no_public_key}
  defp fetch_key(_improper_tail, _name), do: {:error, :bad_arguments}

  # A reference is called here and nowhere else, once per signature; what it raises, throws or
  # exits is the host's code reading the key, and its report can print the key: answered as
  # unreadable, the reason dropped unread.
  defp read(key, name, size, wrong_size) do
    case resolve(key) do
      {:ok, bytes} when is_binary(bytes) and byte_size(bytes) == size -> {:ok, bytes}
      {:ok, _other} -> {:error, {name, wrong_size}}
      :unreadable -> {:error, {name, :unreadable}}
    end
  end

  defp resolve(key) when is_function(key, 0) do
    {:ok, key.()}
  catch
    _kind, _reason -> :unreadable
  end

  defp resolve(key), do: {:ok, key}

  # Sign, then verify: under the host's public key over these bytes (a pair), and not over
  # bytes one bit away (a verifier that means it). `:crypto` raises where OpenSSL will not sign
  # or verify ML-DSA-87 (an OpenSSL before 3.5, OTP 27, a FIPS provider without it), with the
  # call's arguments, the seed among them, in the report: answered, the reason dropped unread.
  defp sign_checked(canonical_bytes, seed, public) do
    signature = :crypto.sign(:mldsa87, :none, canonical_bytes, {:seed, seed})

    cond do
      not :crypto.verify(:mldsa87, :none, canonical_bytes, signature, public) ->
        {:error, {:public_key, :does_not_verify}}

      :crypto.verify(:mldsa87, :none, one_bit_away(canonical_bytes), signature, public) ->
        {:error, :self_check_failed}

      true ->
        {:ok, signature}
    end
  catch
    _kind, _reason -> {:error, :crypto_refused}
  end

  # The lowest bit of the first byte flipped; the empty message has no bit, so its neighbour is
  # one zero byte.
  defp one_bit_away(<<first, rest::binary>>), do: <<Bitwise.bxor(first, 1), rest::binary>>
  defp one_bit_away(<<>>), do: <<0>>
end
