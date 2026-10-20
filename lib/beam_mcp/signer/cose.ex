# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.COSE do
  @moduledoc """
  The canonical bytes signed as a statement whose signed bytes name the algorithm and the key:
  ML-DSA-87 in COSE (RFC 9964, algorithm -50), in the form Script Kitty's systems share for
  everything they sign (the N6 profile, v0, provisional). The same seam as
  `BeamMCP.Signer.MLDSA87`, the same two keys, and one more option.

      Canonical.signature(graph, BeamMCP.Signer.COSE,
        private_key: fn -> seed end, public_key: fn -> public_key end, issuer: "box-17")

  **Why.** `BeamMCP.Connectome.Canonical.signature/3` places `scheme:` and `key_id:` beside a
  signature, asserted by the host and verified by nobody: swap either and a raw signature still
  verifies. Here the algorithm and the key's thumbprint are in the COSE protected header, inside
  the bytes that are signed, so a verifier that changes or misreads either finds the signature
  invalid.

  **What comes back** is one binary, the N6 single-signer carrier, deterministic CBOR:

      {0: 0xFFFF0003,                       ; the single-signer carrier
       1: h'<body>',                        ; the statement, below
       2: [h'<protected>', {}, null, h'<signature>']}   ; COSE_Sign1, untagged, detached

  * The **protected header** is `{1: -50, 4: kid, 16: typ}` and nothing else. `kid` is the
    48-byte SHA-384 COSE Key Thumbprint (RFC 9679) of the public key, computed from the key on
    every call, never taken from the host. `typ` is
    `"application/vnd.example.b85.connectome.v0+cose"`.
  * The **body** is `{0: 0x85000101, 1: issuer, 2: {0: [-43, SHA-384(canonical_bytes)],
    1: byte_size(canonical_bytes), 2: "application/json"}}`: a statement about the canonical
    bytes, naming them by SHA-384 and length. The canonical bytes themselves are not in it and
    are not changed; a verifier is handed them beside the carrier and checks the digest.
  * The **signature** is pure ML-DSA-87, empty context, over the COSE ToBeSigned
    `["Signature1", protected, h'', body]` (RFC 9052 §4.4), made and checked by
    `BeamMCP.Signer.MLDSA87`: it verifies under the public key, and not over bytes one bit away,
    or no carrier comes back.

  The schema number (block 0x85, beam_mcp's provisional block) and `typ` are provisional, and
  are re-issued when the shared registry assigns them; the profile itself is a v0 draft.

  **Options read:** `:private_key` and `:public_key`, as `BeamMCP.Signer.MLDSA87` reads them
  (each the bytes or a zero-arity function; each function called once per signature), and
  `:issuer`, the statement's issuer, required: UTF-8 text in NFC, or `{:bytes, binary}`.
  Nothing else: no environment variable, file, configuration or default.
  """

  @behaviour BeamMCP.Signer

  alias BeamMCP.Signer.COSE.CBOR
  alias BeamMCP.Signer.MLDSA87

  @single_schema 0xFFFF0003
  @schema 0x85000101
  @typ "application/vnd.example.b85.connectome.v0+cose"
  @media_type "application/json"
  @alg -50
  @sha384 -43
  # RFC 9679's thumbprint input for the AKP key {1: 7, 3: -50, -1: pub} under RFC 8949 §4.2.1:
  # this head, then the 2,592 public-key bytes (N6 profile v0 r3 §5).
  @thumbprint_prefix <<0xA3, 0x01, 0x07, 0x03, 0x38, 0x31, 0x20, 0x59, 0x0A, 0x20>>

  @doc """
  Signs `canonical_bytes` as an N6 statement in the single-signer carrier.

  Returns `{:ok, carrier}` or `{:error, reason}`: every reason `BeamMCP.Signer.MLDSA87.sign/2`
  gives, and

    * `:no_issuer` -- the option is absent;
    * `{:issuer, :invalid}` -- present, and neither UTF-8 text in NFC nor `{:bytes, binary}`.

  Answers, not raises, as `BeamMCP.Signer.MLDSA87` answers; no answer carries a key byte.
  """
  @impl BeamMCP.Signer
  @spec sign(binary(), keyword()) :: {:ok, binary()} | {:error, term()}
  def sign(canonical_bytes, opts) when is_binary(canonical_bytes) and is_list(opts) do
    with {:ok, seed} <- fetch(opts, :private_key),
         {:ok, public} <- fetch(opts, :public_key),
         {:ok, issuer} <- fetch(opts, :issuer),
         {:ok, seed} <- read(seed, :private_key),
         {:ok, public} <- read(public, :public_key),
         {:ok, body} <- body(canonical_bytes, issuer),
         {:ok, protected} <- protected(public),
         {:ok, to_be_signed} <-
           CBOR.encode(["Signature1", {:bytes, protected}, {:bytes, ""}, {:bytes, body}]),
         {:ok, signature} <-
           MLDSA87.sign(to_be_signed, private_key: seed, public_key: public) do
      CBOR.encode(%{
        0 => @single_schema,
        1 => {:bytes, body},
        2 => [{:bytes, protected}, %{}, nil, {:bytes, signature}]
      })
    end
  end

  def sign(_canonical_bytes, _opts), do: {:error, :bad_arguments}

  # The first `{name, value}` entry, walked here for the reason `BeamMCP.Signer.Ed25519` walks its
  # own: `Keyword.fetch/2` raises, key in view, on an improper list.
  defp fetch([{name, value} | _], name), do: {:ok, value}
  defp fetch([_ | rest], name), do: fetch(rest, name)
  defp fetch([], :private_key), do: {:error, :no_private_key}
  defp fetch([], :public_key), do: {:error, :no_public_key}
  defp fetch([], :issuer), do: {:error, :no_issuer}
  defp fetch(_improper_tail, _name), do: {:error, :bad_arguments}

  # A reference is called once, here, and the bytes go on to MLDSA87, which checks their sizes
  # and reads them as it reads bytes a host passes; what a function raises, throws or exits is
  # answered as unreadable, the reason dropped unread.
  defp read(key, name) when is_function(key, 0) do
    {:ok, key.()}
  catch
    _kind, _reason -> {:error, {name, :unreadable}}
  end

  defp read(key, _name), do: {:ok, key}

  defp body(canonical_bytes, issuer) do
    with {:ok, issuer} <- issuer(issuer) do
      CBOR.encode(%{
        0 => @schema,
        1 => issuer,
        2 => %{
          0 => [@sha384, {:bytes, :crypto.hash(:sha384, canonical_bytes)}],
          1 => byte_size(canonical_bytes),
          2 => @media_type
        }
      })
    end
  end

  defp issuer({:bytes, b} = issuer) when is_binary(b), do: {:ok, issuer}

  defp issuer(t) when is_binary(t) do
    case CBOR.encode(t) do
      {:ok, _} -> {:ok, t}
      {:error, _} -> {:error, {:issuer, :invalid}}
    end
  end

  defp issuer(_other), do: {:error, {:issuer, :invalid}}

  # The thumbprint needs exactly the 2,592-byte key; any other size is MLDSA87's answer to give,
  # so a key of the wrong size gets a placeholder kid here and is refused there, before signing.
  defp protected(public) when is_binary(public) and byte_size(public) == 2592,
    do: header(:crypto.hash(:sha384, @thumbprint_prefix <> public))

  defp protected(_public), do: header(<<0::384>>)

  defp header(kid), do: CBOR.encode(%{1 => @alg, 4 => {:bytes, kid}, 16 => @typ})
end
