# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.COSE.HashEnvelopeTest do
  # The carrier read back by the strict decoder (test/support/strict_cbor.exs) and judged by
  # BeamMCP.Signer.Test.HashEnvelopeVerifier, which holds the carrier and the public key and
  # never the preimage, so the module is held to the N6 hash-envelope entry point (v0.1 §5.5,
  # RFC 9995) and not to itself. The key pair is ACVP's (tgId 3, tcId 51), as in cose_test.exs.
  use ExUnit.Case, async: true

  alias BeamMCP.Signer.{COSE, MLDSA87}
  alias BeamMCP.Signer.COSE.{CBOR, HashEnvelope}
  alias BeamMCP.Signer.Test.{HashEnvelopeVerifier, StrictCBOR}

  @pair "test/fixtures/mldsa87/acvp_keygen.json"
        |> File.read!()
        |> Jason.decode!()
        |> Map.fetch!("test")
  @seed Base.decode16!(@pair["seed"])
  @pub Base.decode16!(@pair["pk"])

  @typ "application/vnd.example.b80.test_hash.v0+cose"
  @thumbprint_prefix <<0xA3, 0x01, 0x07, 0x03, 0x38, 0x31, 0x20, 0x59, 0x0A, 0x20>>

  defp opts(extra \\ []) do
    Keyword.merge(
      [private_key: @seed, public_key: @pub, typ: @typ, preimage_type: "video/mp4"],
      extra
    )
  end

  defp verify(carrier), do: HashEnvelopeVerifier.verify(carrier, @pub)

  # Elements taken from the stream are counted, so a refusal can be shown to read none.
  defp counted(chunks) do
    me = self()

    Stream.map(chunks, fn chunk ->
      send(me, :chunk)
      chunk
    end)
  end

  defp mailbox do
    receive do
      message -> [message | mailbox()]
    after
      0 -> []
    end
  end

  describe "PQS-8: a large artifact, today" do
    test "no signer takes a stream: each wants the whole artifact as one binary" do
      chunks = Stream.repeatedly(fn -> "x" end) |> Stream.take(3)

      assert COSE.sign(chunks, private_key: @seed, public_key: @pub, issuer: "i") ==
               {:error, :bad_arguments}

      assert MLDSA87.sign(chunks, private_key: @seed, public_key: @pub) ==
               {:error, :bad_arguments}
    end
  end

  describe "the carrier, judged holding only the digest and the signature" do
    @describetag :mldsa87

    test "{0: 0xFFFF0003, 1: digest, 2: [protected, {}, nil, signature]}, and it verifies" do
      digest = :crypto.hash(:sha384, "a clip")
      assert {:ok, out} = HashEnvelope.sign_digest(digest, opts())
      assert {:ok, %{digest: ^digest, payload_hash: -43, typ: @typ}} = verify(out)

      {:ok, %{0 => 0xFFFF0003, 1 => {:bytes, ^digest}, 2 => sign1}} = StrictCBOR.decode(out)
      assert [{:bytes, _protected}, %{}, nil, {:bytes, signature}] = sign1
      assert byte_size(signature) == 4627
    end

    test "the protected header is {1: -50, 2: [258], 4: kid48, 16: typ, 258: -43, 259: type}, nothing else" do
      {:ok, out} = HashEnvelope.sign_digest(:crypto.hash(:sha384, "a"), opts())
      kid = :crypto.hash(:sha384, @thumbprint_prefix <> @pub)

      assert StrictCBOR.decode(HashEnvelopeVerifier.protected(out)) ==
               {:ok,
                %{
                  1 => -50,
                  2 => [258],
                  4 => {:bytes, kid},
                  16 => @typ,
                  258 => -43,
                  259 => "video/mp4"
                }}
    end

    test "the labels are in canonical order: 1, 2, 4, 16, 258, 259, 260" do
      {:ok, out} =
        HashEnvelope.sign_digest(:crypto.hash(:sha384, "a"), opts(location: "clips/17.mp4"))

      protected = HashEnvelopeVerifier.protected(out)
      # a7: seven pairs. 01 38 31: 1 => -50. 02 81 19 01 02: 2 => [258]. 04 58 30: 4 => 48 bytes.
      assert <<0xA7, 0x01, 0x38, 0x31, 0x02, 0x81, 0x19, 0x01, 0x02, 0x04, 0x58, 0x30,
               _kid::binary-48, 0x10, rest::binary>> = protected

      typ = <<0x78, byte_size(@typ)>> <> @typ
      n = byte_size(typ)

      assert <<^typ::binary-size(^n), 0x19, 0x01, 0x02, 0x38, 0x2A, 0x19, 0x01, 0x03, 0x69,
               "video/mp4", 0x19, 0x01, 0x04, 0x6C, "clips/17.mp4">> = rest
    end

    test "SHA-512 gives 258 = -44 and a 64-byte payload" do
      digest = :crypto.hash(:sha512, "a")
      {:ok, out} = HashEnvelope.sign_digest(digest, opts(payload_hash: :sha512))
      assert {:ok, %{digest: ^digest, payload_hash: -44}} = verify(out)
    end

    test "259 may be a CoAP content-format number" do
      {:ok, out} = HashEnvelope.sign_digest(:crypto.hash(:sha384, "a"), opts(preimage_type: 42))
      assert {:ok, %{259 => 42}} = StrictCBOR.decode(HashEnvelopeVerifier.protected(out))
      assert {:ok, _} = verify(out)
    end

    test "changing any protected label, or the digest, breaks the signature" do
      {:ok, out} =
        HashEnvelope.sign_digest(:crypto.hash(:sha384, "a"), opts(location: "clips/17.mp4"))

      {:ok, header} = StrictCBOR.decode(HashEnvelopeVerifier.protected(out))
      {:bytes, <<k0, kid_rest::binary>>} = header[4]

      for changed <- [
            Map.put(header, 1, -49),
            Map.delete(header, 2),
            Map.put(header, 4, {:bytes, <<Bitwise.bxor(k0, 1), kid_rest::binary>>}),
            Map.put(header, 16, "application/vnd.example.b80.other.v0+cose"),
            Map.put(header, 258, -44),
            Map.put(header, 259, "application/octet-stream"),
            Map.put(header, 260, "clips/18.mp4")
          ] do
        {:ok, protected} = CBOR.encode(changed)
        refute HashEnvelopeVerifier.signature_valid?(out, @pub, protected: protected)
      end

      <<d0, digest_rest::binary>> = :crypto.hash(:sha384, "a")

      refute HashEnvelopeVerifier.signature_valid?(out, @pub,
               digest: <<Bitwise.bxor(d0, 1), digest_rest::binary>>
             )

      assert HashEnvelopeVerifier.signature_valid?(out, @pub)
    end

    test "hedged: two carriers over one digest differ only in the signature" do
      digest = :crypto.hash(:sha384, "a")
      {:ok, one} = HashEnvelope.sign_digest(digest, opts())
      {:ok, two} = HashEnvelope.sign_digest(digest, opts())
      assert HashEnvelopeVerifier.protected(one) == HashEnvelopeVerifier.protected(two)
      refute one == two
      assert {:ok, _} = verify(one)
      assert {:ok, _} = verify(two)
    end
  end

  describe "sign_stream/2" do
    @describetag :mldsa87

    test "streamed chunks give the digest of their concatenation, under either hash" do
      chunks = for n <- [0, 1, 7, 1000, 65_536, 3], do: :crypto.strong_rand_bytes(n)
      whole = IO.iodata_to_binary(chunks)

      for {hash, alg} <- [sha384: -43, sha512: -44] do
        {:ok, streamed} =
          HashEnvelope.sign_stream(Stream.map(chunks, & &1), opts(payload_hash: hash))

        {:ok, direct} =
          HashEnvelope.sign_digest(:crypto.hash(hash, whole), opts(payload_hash: hash))

        digest = :crypto.hash(hash, whole)
        assert {:ok, %{digest: ^digest, payload_hash: ^alg}} = verify(streamed)
        assert HashEnvelopeVerifier.protected(streamed) == HashEnvelopeVerifier.protected(direct)
      end
    end

    test "a list is a stream too, and the empty stream is the empty preimage" do
      {:ok, out} = HashEnvelope.sign_stream([], opts())
      empty = :crypto.hash(:sha384, "")
      assert {:ok, %{digest: ^empty}} = verify(out)

      {:ok, out} = HashEnvelope.sign_stream(["ab", "c"], opts())
      abc = :crypto.hash(:sha384, "abc")
      assert {:ok, %{digest: ^abc}} = verify(out)
    end

    test "a file streamed in 1 MiB chunks gives the file's digest" do
      path = Path.join(System.tmp_dir!(), "hash-envelope-#{System.unique_integer([:positive])}")
      bytes = :crypto.strong_rand_bytes(3 * 1_048_576 + 17)
      File.write!(path, bytes)

      try do
        {:ok, out} = HashEnvelope.sign_stream(File.stream!(path, 1_048_576), opts())
        expected = :crypto.hash(:sha384, bytes)
        assert {:ok, %{digest: ^expected}} = verify(out)
      after
        File.rm!(path)
      end
    end

    test "the private key reference is called once, after the last chunk" do
      me = self()

      private = fn ->
        send(me, :private)
        @seed
      end

      chunks =
        Stream.map(["a", "b"], fn chunk ->
          send(me, {:chunk, chunk})
          chunk
        end)

      assert {:ok, _} = HashEnvelope.sign_stream(chunks, opts(private_key: private))
      assert mailbox() == [{:chunk, "a"}, {:chunk, "b"}, :private]
    end
  end

  describe "refusals: answered, never raised, and no key byte in any" do
    test "typ: required, a lowercase media type without parameters ending +cose, never the connectome's" do
      digest = :crypto.hash(:sha384, "a")
      assert HashEnvelope.sign_digest(digest, Keyword.delete(opts(), :typ)) == {:error, :no_typ}

      for bad <- [
            "",
            "application",
            "Application/vnd.example.b80.test_hash.v0+cose",
            "application/vnd.example.b80.test_hash.v0+cose; v=1",
            "application/vnd.example.b80.test_hash.v0+cbor",
            "application/+cose",
            "application/" <> String.duplicate("a", 127) <> "+cose",
            1,
            nil,
            {:bytes, @typ}
          ] do
        assert HashEnvelope.sign_digest(digest, opts(typ: bad)) == {:error, {:typ, :invalid}},
               inspect(bad)
      end

      assert HashEnvelope.sign_digest(
               digest,
               opts(typ: "application/vnd.example.b85.connectome.v0+cose")
             ) == {:error, {:typ, :full_payload}}
    end

    test "259: required, a media type under the profile's grammar or a uint below 65,536" do
      digest = :crypto.hash(:sha384, "a")

      assert HashEnvelope.sign_digest(digest, Keyword.delete(opts(), :preimage_type)) ==
               {:error, :no_preimage_type}

      for bad <- [
            "",
            "video",
            "Video/mp4",
            "video/mp4; codecs=avc1",
            -1,
            65_536,
            nil,
            {:bytes, "x"}
          ] do
        assert HashEnvelope.sign_digest(digest, opts(preimage_type: bad)) ==
                 {:error, {:preimage_type, :invalid}},
               inspect(bad)
      end
    end

    test "260: 1 to 2,048 printable ASCII bytes, when given" do
      digest = :crypto.hash(:sha384, "a")

      for bad <- ["", "a b", "é", String.duplicate("a", 2049), 1, {:bytes, "x"}] do
        assert HashEnvelope.sign_digest(digest, opts(location: bad)) ==
                 {:error, {:location, :invalid}},
               inspect(bad)
      end
    end

    test "payload_hash: :sha384 or :sha512, and a digest of that hash's length" do
      for bad <- [:sha256, :sha3_384, "sha384", -43] do
        assert HashEnvelope.sign_digest(:crypto.hash(:sha384, "a"), opts(payload_hash: bad)) ==
                 {:error, {:payload_hash, :invalid}}
      end

      assert HashEnvelope.sign_digest(<<0::256>>, opts()) == {:error, {:digest, :wrong_length}}

      assert HashEnvelope.sign_digest(<<0::384>>, opts(payload_hash: :sha512)) ==
               {:error, {:digest, :wrong_length}}

      assert HashEnvelope.sign_digest(:not_bytes, opts()) == {:error, :bad_arguments}
    end

    # Where ML-DSA-87 is not offered, :crypto_refused comes before the stream is read.
    @tag :mldsa87
    test "a stream element that is not a binary, or a stream that raises" do
      assert HashEnvelope.sign_stream(["a", ~c"b"], opts()) == {:error, {:stream, :not_binary}}

      raising = Stream.map([1], fn _ -> raise "the disk is gone" end)
      assert HashEnvelope.sign_stream(raising, opts()) == {:error, {:stream, :unreadable}}

      assert HashEnvelope.sign_stream("not a stream", opts()) == {:error, :bad_arguments}
      assert HashEnvelope.sign_stream(fn -> "x" end, opts()) == {:error, :bad_arguments}
      assert HashEnvelope.sign_stream([], %{}) == {:error, :bad_arguments}
    end

    test "every option is judged before the first chunk is read" do
      for {extra, reason} <- [
            {[typ: "x"], {:typ, :invalid}},
            {[preimage_type: "x"], {:preimage_type, :invalid}},
            {[location: ""], {:location, :invalid}},
            {[payload_hash: :md5], {:payload_hash, :invalid}},
            {[public_key: <<1>>], {:public_key, :not_2592_bytes}},
            {[public_key: fn -> raise "x" end], {:public_key, :unreadable}},
            {[private_key: <<1, 2>>], {:private_key, :not_32_bytes}}
          ] do
        assert HashEnvelope.sign_stream(counted(["a", "b"]), opts(extra)) == {:error, reason}
        refute_received :chunk
      end
    end

    test "the key answers are MLDSA87's" do
      digest = :crypto.hash(:sha384, "a")

      assert HashEnvelope.sign_digest(digest, Keyword.delete(opts(), :private_key)) ==
               {:error, :no_private_key}

      assert HashEnvelope.sign_digest(digest, Keyword.delete(opts(), :public_key)) ==
               {:error, :no_public_key}

      assert HashEnvelope.sign_digest(digest, [{:typ, @typ} | :improper]) ==
               {:error, :bad_arguments}
    end

    # A private key function is called after the stream, so where ML-DSA-87 is not offered the
    # early :crypto_refused comes first.
    @tag :mldsa87
    test "a private key function that raises or returns the wrong size" do
      digest = :crypto.hash(:sha384, "a")

      assert HashEnvelope.sign_digest(digest, opts(private_key: fn -> fn -> @seed end end)) ==
               {:error, {:private_key, :not_32_bytes}}

      assert HashEnvelope.sign_digest(digest, opts(private_key: fn -> raise "x" end)) ==
               {:error, {:private_key, :unreadable}}

      assert HashEnvelope.sign_digest(digest, opts(private_key: fn -> <<1>> end)) ==
               {:error, {:private_key, :not_32_bytes}}
    end

    @tag :mldsa87
    test "a public key that is not the seed's: no carrier" do
      {other, _} = :crypto.generate_key(:mldsa87, [])

      assert HashEnvelope.sign_digest(:crypto.hash(:sha384, "a"), opts(public_key: other)) ==
               {:error, {:public_key, :does_not_verify}}
    end

    @tag :no_mldsa87
    test "on a runtime without ML-DSA-87: :crypto_refused, before the first chunk" do
      assert HashEnvelope.sign_stream(counted(["a"]), opts()) == {:error, :crypto_refused}
      refute_received :chunk
    end
  end

  describe "the census" do
    test "COSE still exports only sign/2; HashEnvelope is not a BeamMCP.Signer" do
      assert COSE.__info__(:functions) == [sign: 2]
      refute BeamMCP.Signer in (HashEnvelope.module_info(:attributes)[:behaviour] || [])
      assert HashEnvelope.__info__(:functions) == [sign_digest: 2, sign_stream: 2]
    end
  end
end
