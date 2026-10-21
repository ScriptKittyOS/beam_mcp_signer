# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.COSE do
  @moduledoc """
  The canonical bytes signed as a statement whose signed bytes name the algorithm and the key:
  ML-DSA-87 in COSE (RFC 9964, algorithm -50), in the form Script Kitty's systems share for
  everything they sign (the N6 profile, v0.1, a draft, provisional). The same seam as
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
  `:issuer`, the statement's issuer, required: text under N6's text rule (Unicode 15.0.0, no format or bidirectional controls, the NFC quick check YES, at most 65,536 bytes), or `{:bytes, binary}` of at most 65,536 bytes.
  Nothing else: no environment variable, file, configuration or default.
  """

  @behaviour BeamMCP.Signer

  alias BeamMCP.Signer.COSE.{CBOR, Keys}
  alias BeamMCP.Signer.MLDSA87

  @single_schema 0xFFFF0003
  @schema 0x85000101
  @typ "application/vnd.example.b85.connectome.v0+cose"
  @media_type "application/json"
  @alg -50
  @sha384 -43

  @doc """
  Signs `canonical_bytes` as an N6 statement in the single-signer carrier.

  Returns `{:ok, carrier}` or `{:error, reason}`: every reason `BeamMCP.Signer.MLDSA87.sign/2`
  gives, and

    * `:no_issuer` -- the option is absent;
    * `{:issuer, :invalid}` -- present, and neither of those.

  Answers, not raises, as `BeamMCP.Signer.MLDSA87` answers; no answer carries a key byte.
  """
  @impl BeamMCP.Signer
  @spec sign(binary(), keyword()) :: {:ok, binary()} | {:error, term()}
  def sign(canonical_bytes, opts) when is_binary(canonical_bytes) and is_list(opts) do
    with {:ok, seed} <- Keys.fetch(opts, :private_key, :no_private_key),
         {:ok, public} <- Keys.fetch(opts, :public_key, :no_public_key),
         {:ok, issuer} <- Keys.fetch(opts, :issuer, :no_issuer),
         {:ok, body} <- body(canonical_bytes, issuer),
         {:ok, public} <- Keys.read(public, :public_key),
         {:ok, seed} <- Keys.read(seed, :private_key),
         {:ok, kid} <- Keys.kid(public),
         {:ok, protected} <- header(kid),
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

  # The issuer first, so a key function is never called for a call that is refused anyway.
  defp body(canonical_bytes, issuer) do
    with {:ok, issuer} <- issuer(issuer),
         {:ok, digest} <- sha384(canonical_bytes) do
      CBOR.encode(%{
        0 => @schema,
        1 => issuer,
        2 => %{
          0 => [@sha384, {:bytes, digest}],
          1 => byte_size(canonical_bytes),
          2 => @media_type
        }
      })
    end
  end

  defp sha384(bytes) do
    {:ok, :crypto.hash(:sha384, bytes)}
  catch
    _kind, _reason -> {:error, :crypto_refused}
  end

  # N6's text limit (E9) for a text issuer comes with the encoder; a byte-string issuer is held to
  # the same 65,536 bytes, so a carrier stays far below the 1,048,576 bytes a decoder admits.
  defp issuer({:bytes, b} = issuer) when is_binary(b) and byte_size(b) <= 65_536,
    do: {:ok, issuer}

  defp issuer(t) when is_binary(t) do
    case CBOR.encode(t) do
      {:ok, _} -> {:ok, t}
      {:error, _} -> {:error, {:issuer, :invalid}}
    end
  end

  defp issuer(_other), do: {:error, {:issuer, :invalid}}

  defp header(kid), do: CBOR.encode(%{1 => @alg, 4 => {:bytes, kid}, 16 => @typ})
end
