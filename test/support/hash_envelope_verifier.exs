# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.Test.HashEnvelopeVerifier do
  @moduledoc false
  # A verifier for the N6 hash-envelope entry point (v0.1 §5.4, §5.5, §5.6), for the tests only.
  # It is handed the carrier and the public key and nothing else: never the preimage. It reads
  # with the strict decoder, not the encoder under test, builds ToBeSigned itself with CBOR heads
  # written here, and answers the profile's own codes for what it refuses. A verified envelope
  # is non-claimed (§5.5), so the answer names no claim.

  import Bitwise

  alias BeamMCP.Signer.Test.StrictCBOR

  @single_schema 0xFFFF0003
  @thumbprint_prefix <<0xA3, 0x01, 0x07, 0x03, 0x38, 0x31, 0x20, 0x59, 0x0A, 0x20>>
  @required [1, 2, 4, 16, 258, 259]
  @allowed [1, 2, 4, 16, 258, 259, 260]
  @lengths %{-43 => 48, -44 => 64}
  @media ~r/\A[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\z/

  @doc "The carrier judged: `{:ok, %{digest:, payload_hash:, typ:}}`, or `{:error, code}`."
  def verify(carrier, public_key) do
    with {:ok, c} <- carrier(carrier),
         {:ok, header} <- header(c.protected),
         :ok <- payload(c.digest, header[258]),
         :ok <- kid(header[4], public_key),
         true <-
           valid?(c.protected, c.digest, c.signature, public_key) || {:error, :signature_invalid} do
      {:ok, %{digest: c.digest, payload_hash: header[258], typ: header[16]}}
    end
  end

  @doc "The carrier's protected header bytes, as received."
  def protected(carrier) do
    {:ok, c} = carrier(carrier)
    c.protected
  end

  @doc "Whether the signature verifies, with the protected bytes or the digest optionally replaced."
  def signature_valid?(carrier, public_key, replace \\ []) do
    {:ok, c} = carrier(carrier)

    valid?(
      Keyword.get(replace, :protected, c.protected),
      Keyword.get(replace, :digest, c.digest),
      c.signature,
      public_key
    )
  end

  defp carrier(bytes) do
    case StrictCBOR.decode(bytes) do
      {:ok,
       %{
         0 => @single_schema,
         1 => {:bytes, digest},
         2 => [{:bytes, protected}, unprotected, nil, {:bytes, signature}]
       } = c}
      when map_size(c) == 3 and unprotected == %{} ->
        {:ok, %{digest: digest, protected: protected, signature: signature}}

      _ ->
        {:error, :carrier_malformed}
    end
  end

  # H1 to H4, in the profile's order: decode, a map, typ first, then the label scan ascending.
  defp header(protected) do
    case StrictCBOR.decode(protected) do
      {:ok, %{16 => typ} = h} when is_binary(typ) ->
        scan(h, Enum.sort(Enum.uniq(Map.keys(h) ++ @required)))

      {:ok, %{16 => _}} ->
        {:error, :typ_unexpected}

      {:ok, %{}} ->
        {:error, :header_missing}

      _ ->
        {:error, :header_noncanonical}
    end
  end

  defp scan(h, []), do: {:ok, h}
  defp scan(h, [16 | rest]), do: scan(h, rest)

  defp scan(h, [label | rest]) do
    case label(label, Map.fetch(h, label)) do
      :ok -> scan(h, rest)
      error -> error
    end
  end

  defp label(label, :error) when label in @required, do: {:error, :header_missing}
  defp label(3, _), do: {:error, :content_type_forbidden}
  defp label(label, _) when label not in @allowed, do: {:error, :header_label_forbidden}
  defp label(1, {:ok, -50}), do: :ok
  defp label(1, {:ok, alg}) when is_integer(alg), do: {:error, :alg_not_permitted}
  defp label(2, {:ok, [258]}), do: :ok
  defp label(4, {:ok, {:bytes, kid}}) when byte_size(kid) == 48, do: :ok
  defp label(258, {:ok, alg}) when alg in [-43, -44], do: :ok
  defp label(258, {:ok, alg}) when is_integer(alg), do: {:error, :digest_alg_not_permitted}
  defp label(259, {:ok, n}) when is_integer(n) and n >= 0 and n <= 0xFFFF, do: :ok
  defp label(259, {:ok, t}) when is_binary(t), do: if(t =~ @media, do: :ok, else: invalid())

  defp label(260, {:ok, t}) when is_binary(t),
    do: if(t =~ ~r/\A[\x21-\x7e]{1,2048}\z/, do: :ok, else: invalid())

  defp label(_label, _value), do: invalid()

  defp invalid, do: {:error, :header_value_invalid}

  defp payload(digest, alg) do
    if byte_size(digest) == @lengths[alg], do: :ok, else: {:error, :digest_length_mismatch}
  end

  defp kid({:bytes, kid}, public_key) do
    if kid == :crypto.hash(:sha384, @thumbprint_prefix <> public_key),
      do: :ok,
      else: {:error, :kid_not_thumbprint}
  end

  defp valid?(protected, digest, signature, public_key) do
    tbs = <<0x84, 0x6A, "Signature1">> <> bstr(protected) <> <<0x40>> <> bstr(digest)
    :crypto.verify(:mldsa87, :none, tbs, signature, public_key)
  end

  defp bstr(b), do: head(2, byte_size(b)) <> b

  defp head(major, n) when n < 24, do: <<major::3, n::5>>
  defp head(major, n) when n < 0x100, do: <<major::3, 24::5, n>>
  defp head(major, n) when n < 0x10000, do: <<major::3, 25::5, n::16>>
  defp head(major, n) when n <= 0xFFFFFFFF, do: <<major::3, 26::5, n::32>>
  defp head(major, n) when n < 1 <<< 64, do: <<major::3, 27::5, n::64>>
end
