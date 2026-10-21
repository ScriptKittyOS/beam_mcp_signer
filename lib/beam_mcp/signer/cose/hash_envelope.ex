# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.COSE.HashEnvelope do
  @moduledoc """
  **Non-claimed.** A large artifact signed by its digest: an RFC 9995 COSE Hash Envelope under
  ML-DSA-87 (RFC 9964, algorithm -50), in the N6 profile's single-signer carrier (v0.1,
  provisional). Its signatures are pure ML-DSA-87 from CNSA 2.0's algorithms, but no NSA, NIST
  or IETF text yet names this construction, so a verified envelope is judged non-claimed, never
  a claim. `BeamMCP.Signer.COSE` remains the claimed path, for the connectome.

      # chunks: the host's stream of the artifact, say a file read 1 MiB at a time
      HashEnvelope.sign_stream(chunks,
        private_key: fn -> seed end,
        public_key: fn -> public_key end,
        typ: "application/vnd.example.b80.test_hash.v0+cose",
        preimage_type: "video/mp4")

  **Why.** `BeamMCP.Signer.COSE.sign/2` and `BeamMCP.Signer.MLDSA87.sign/2` take one binary, so
  a 10 GB clip, tile bundle or model file would have to be held in memory whole. A raw
  signature over its digest would leave the hash algorithm unsigned, and the digest could pass
  for the content. Here the hash algorithm (label 258) and the preimage's media type (259) are
  in the protected header, inside the signed bytes, so a verifier needs only the digest and the
  signature. It is not HashML-DSA: the signature is ordinary pure ML-DSA-87, empty context, over
  the COSE ToBeSigned, whose payload happens to be a digest.

  **What comes back** is one binary, the N6 single-signer carrier, deterministic CBOR:

      {0: 0xFFFF0003,                       ; the single-signer carrier
       1: h'<digest>',                      ; the artifact's SHA-384 (or SHA-512)
       2: [h'<protected>', {}, null, h'<signature>']}   ; COSE_Sign1, untagged, detached

  * The **protected header** is `{1: -50, 2: [258], 4: kid, 16: typ, 258: -43, 259: preimage
    type}`, with `260: location` when one is given, and nothing else. `crit` (2) lists 258, so a
    COSE verifier that does not know hash envelopes refuses the signature instead of taking the
    digest for the content. Label 3 (content type) is never written (RFC 9995 §4). `kid` is the
    48-byte SHA-384 COSE Key Thumbprint (RFC 9679) of the public key, computed from the key on
    every call.
  * The **signature** is over `["Signature1", protected, h'', digest]` (RFC 9052 §4.4), made and
    checked by `BeamMCP.Signer.MLDSA87`: it verifies under the public key, and not over bytes
    one bit away, or no carrier comes back.

  **The statement's kind is the host's.** A hash envelope has no body, so its `typ` alone names
  what the statement is, and a kind belongs to the party that publishes it. So `typ` is
  required and never defaulted. It must be a lowercase media type with no parameters, ending
  `+cose`. The connectome's `typ` is refused, because that kind is signed in full by
  `BeamMCP.Signer.COSE`. The preimage's media type (259) types only the bytes hashed. It is
  given per artifact.

  **Options read:**

    * `:private_key`, `:public_key`: as `BeamMCP.Signer.MLDSA87` reads them. The public key is
      read first, before any chunk, since the kid needs it. A private key function is called
      once, after the last chunk. So a function that fetches the seed from the host's store when
      it is called keeps the seed out of the process while the stream is read; one that captures
      the seed in its closure holds it all along, as any closure does.
    * `:typ`: required, as above.
    * `:preimage_type`: required. A media type (`type/subtype`, lowercase, no parameters, at
      most 255 bytes), or a CoAP content-format number in 0..65535.
    * `:location`: optional. A hint of 1 to 2,048 printable ASCII bytes; signed, never trusted.
    * `:payload_hash`: `:sha384` (the default, -43) or `:sha512` (-44).

  Nothing else: no environment variable, file or configuration.
  """

  alias BeamMCP.Signer.COSE.{CBOR, Keys}
  alias BeamMCP.Signer.MLDSA87

  @single_schema 0xFFFF0003
  @alg -50
  @crit [258]
  @payload_hash_alg 258
  @preimage_content_type 259
  @payload_location 260
  @hashes %{sha384: {-43, 48}, sha512: {-44, 64}}
  # `BeamMCP.Signer.COSE`'s kind, signed in full: never a hash envelope.
  @full_payload_typs ["application/vnd.example.b85.connectome.v0+cose"]
  # N6 profile v0.1 §4: `type "/" subtype`, lowercase, no parameters, 1 to 255 bytes.
  @media_type ~r/\A[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\z/
  @location ~r/\A[\x21-\x7e]{1,2048}\z/

  @typedoc "A refusal. No reason carries a byte of either key."
  @type reason ::
          :no_private_key
          | :no_public_key
          | :no_typ
          | :no_preimage_type
          | {:typ, :invalid | :full_payload}
          | {:preimage_type, :invalid}
          | {:location, :invalid}
          | {:payload_hash, :invalid}
          | {:digest, :wrong_length}
          | {:stream, :not_binary | :unreadable}
          | {:private_key, :not_32_bytes | :unreadable}
          | {:public_key, :not_2592_bytes | :unreadable | :does_not_verify}
          | :bad_arguments
          | :crypto_refused
          | :self_check_failed

  @doc """
  Signs an artifact by `digest`, its SHA-384 (48 bytes) or, with `payload_hash: :sha512`, its
  SHA-512 (64 bytes), computed by the host.

  The module cannot know that the bytes are a digest of anything: only their length is checked.
  So the carrier says that the key holder asserts this digest for an artifact of this type. Where
  the artifact is to hand, `sign_stream/2` computes the digest itself.

  Returns `{:ok, carrier}` or `{:error, reason}`. The reasons are every one
  `BeamMCP.Signer.MLDSA87.sign/2` gives, and:

    * `:no_typ`, `:no_preimage_type`: the option is absent;
    * `{:typ, :invalid}`, `{:typ, :full_payload}`, `{:preimage_type, :invalid}`,
      `{:location, :invalid}`, `{:payload_hash, :invalid}`: present, and not as above;
    * `{:digest, :wrong_length}`: not the hash's length.

  Answers, not raises, as `BeamMCP.Signer.MLDSA87` answers.
  """
  @spec sign_digest(binary(), keyword()) :: {:ok, binary()} | {:error, reason()}
  def sign_digest(digest, opts) when is_binary(digest) and is_list(opts) do
    with {:ok, signer} <- prepare(opts),
         :ok <- digest_length(digest, signer.length),
         :ok <- offered() do
      sign(digest, signer)
    end
  end

  def sign_digest(_digest, _opts), do: {:error, :bad_arguments}

  @doc """
  Signs the artifact `chunks` enumerates, any `Enumerable` of binaries, hashed as it is read with
  `:crypto.hash_init/1`, `hash_update/2` and `hash_final/1`. Memory is one chunk and the hash
  state, whatever the artifact's size. The host opens the artifact, for example
  as a file streamed in 1 MiB chunks; this module opens nothing.

  Every option is judged before the first chunk is read, so a long stream is never hashed and
  then refused over an option. The reasons are `sign_digest/2`'s, except the digest length, and:

    * `{:stream, :not_binary}`: an element is not a binary; nothing after it is read;
    * `{:stream, :unreadable}`: the enumerable raised, threw or exited (a file that could not be
      read, say); the reason is dropped unread.
  """
  @spec sign_stream(Enumerable.t(), keyword()) :: {:ok, binary()} | {:error, reason()}
  def sign_stream(chunks, opts) when is_list(opts) do
    if enumerable?(chunks) do
      with {:ok, signer} <- prepare(opts),
           :ok <- offered(),
           {:ok, digest} <- hash(chunks, signer.hash) do
        sign(digest, signer)
      end
    else
      {:error, :bad_arguments}
    end
  end

  def sign_stream(_chunks, _opts), do: {:error, :bad_arguments}

  # A function is enumerable only at arity 2 (Elixir's own reducer form); any other is refused
  # here rather than raised on and answered as an unreadable stream.
  defp enumerable?(f) when is_function(f), do: is_function(f, 2)
  defp enumerable?(other), do: Enumerable.impl_for(other) != nil

  # Every option, the public key and, unless it is a function, the private key, judged before any
  # hashing. Each entry point then asks whether ML-DSA-87 is offered at all, so a runtime without
  # it refuses before the stream rather than after.
  defp prepare(opts) do
    with {:ok, seed} <- Keys.fetch(opts, :private_key, :no_private_key),
         {:ok, public} <- Keys.fetch(opts, :public_key, :no_public_key),
         {:ok, typ} <- Keys.fetch(opts, :typ, :no_typ),
         {:ok, preimage_type} <- Keys.fetch(opts, :preimage_type, :no_preimage_type),
         {:ok, location} <- Keys.fetch(opts, :location, {:default, nil}),
         {:ok, hash} <- Keys.fetch(opts, :payload_hash, {:default, :sha384}),
         {:ok, public} <- Keys.read(public, :public_key),
         :ok <- seed_size(seed),
         {:ok, {alg, length}} <- payload_hash(hash),
         {:ok, kid} <- Keys.kid(public),
         {:ok, protected} <- protected(kid, typ, preimage_type, location, alg) do
      {:ok, %{seed: seed, public: public, protected: protected, hash: hash, length: length}}
    end
  end

  # A seed handed in as bytes (or as anything but a function) is judged now; a function's result
  # is judged when it is called, after the stream.
  defp seed_size(seed) when is_function(seed, 0), do: :ok

  defp seed_size(seed) do
    with {:ok, _seed} <- Keys.read(seed, :private_key), do: :ok
  end

  defp payload_hash(hash) when is_map_key(@hashes, hash), do: {:ok, Map.fetch!(@hashes, hash)}
  defp payload_hash(_hash), do: {:error, {:payload_hash, :invalid}}

  defp digest_length(digest, length) when byte_size(digest) == length, do: :ok
  defp digest_length(_digest, _length), do: {:error, {:digest, :wrong_length}}

  defp protected(kid, typ, preimage_type, location, alg) do
    with {:ok, typ} <- typ(typ),
         {:ok, preimage_type} <- preimage_type(preimage_type),
         {:ok, header} <- location(location, base(kid, typ, preimage_type, alg)) do
      CBOR.encode(header)
    end
  end

  defp base(kid, typ, preimage_type, alg) do
    %{
      1 => @alg,
      2 => @crit,
      4 => {:bytes, kid},
      16 => typ,
      @payload_hash_alg => alg,
      @preimage_content_type => preimage_type
    }
  end

  defp typ(typ) when typ in @full_payload_typs, do: {:error, {:typ, :full_payload}}

  defp typ(typ) when is_binary(typ) do
    if media_type?(typ) and String.ends_with?(typ, "+cose"),
      do: {:ok, typ},
      else: {:error, {:typ, :invalid}}
  end

  defp typ(_typ), do: {:error, {:typ, :invalid}}

  defp preimage_type(n) when is_integer(n) and n in 0..0xFFFF, do: {:ok, n}

  defp preimage_type(t) when is_binary(t) do
    if media_type?(t), do: {:ok, t}, else: {:error, {:preimage_type, :invalid}}
  end

  defp preimage_type(_other), do: {:error, {:preimage_type, :invalid}}

  defp location(nil, header), do: {:ok, header}

  defp location(l, header) when is_binary(l) do
    if l =~ @location,
      do: {:ok, Map.put(header, @payload_location, l)},
      else: {:error, {:location, :invalid}}
  end

  defp location(_other, _header), do: {:error, {:location, :invalid}}

  defp media_type?(t), do: String.valid?(t) and t =~ @media_type

  # Where `:crypto` does not offer ML-DSA-87 (OTP 27, an OpenSSL before 3.5). MLDSA87 still
  # answers `:crypto_refused` when it is offered and then will not sign (a FIPS provider).
  defp offered do
    if :mldsa87 in :crypto.supports(:public_keys), do: :ok, else: {:error, :crypto_refused}
  end

  # The enumerable is the host's code, a file read among it: what it raises, throws or exits is
  # answered as unreadable, the reason dropped unread.
  defp hash(chunks, hash) do
    chunks
    |> Enum.reduce_while(:crypto.hash_init(hash), fn
      chunk, state when is_binary(chunk) -> {:cont, :crypto.hash_update(state, chunk)}
      _other, _state -> {:halt, :not_binary}
    end)
    |> case do
      :not_binary -> {:error, {:stream, :not_binary}}
      state -> {:ok, :crypto.hash_final(state)}
    end
  catch
    _kind, _reason -> {:error, {:stream, :unreadable}}
  end

  defp sign(digest, signer) do
    with {:ok, seed} <- Keys.read(signer.seed, :private_key),
         {:ok, to_be_signed} <-
           CBOR.encode(["Signature1", {:bytes, signer.protected}, {:bytes, ""}, {:bytes, digest}]),
         {:ok, signature} <-
           MLDSA87.sign(to_be_signed, private_key: seed, public_key: signer.public) do
      CBOR.encode(%{
        0 => @single_schema,
        1 => {:bytes, digest},
        2 => [{:bytes, signer.protected}, %{}, nil, {:bytes, signature}]
      })
    end
  end
end
