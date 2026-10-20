# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.COSETest do
  # The carrier read back by the strict decoder (test/support/strict_cbor.exs), never by the
  # module's own encoder, and its ToBeSigned rebuilt here byte by byte, so the module is held to
  # N6 (r3 §5, the publisher's answers of 2026-10-19 21:24Z and 2026-10-20 17:24Z) and not to
  # itself. RFC 9964 Appendix A.2 (test/fixtures/cose/, tools/vectors_cose.sh) holds the
  # encoder and the thumbprint input to bytes someone else published. The key pair is ACVP's
  # (tgId 3, tcId 51), as in mldsa87_test.exs.
  use ExUnit.Case, async: true

  alias BeamMCP.Connectome.{Canonical, Edge, Graph, Node}
  alias BeamMCP.Signer.{COSE, MLDSA87}
  alias BeamMCP.Signer.COSE.CBOR
  alias BeamMCP.Signer.Test.StrictCBOR

  @pair "test/fixtures/mldsa87/acvp_keygen.json"
        |> File.read!()
        |> Jason.decode!()
        |> Map.fetch!("test")
  @seed Base.decode16!(@pair["seed"])
  @pub Base.decode16!(@pair["pk"])

  @a2 "test/fixtures/cose/rfc9964_a2_ml_dsa_87.json" |> File.read!() |> Jason.decode!()

  @single_schema 0xFFFF0003
  @schema 0x85000101
  @typ "application/vnd.example.b85.connectome.v0+cose"
  # RFC 9679 over the AKP key {1: 7, 3: -50, -1: pub}, encoded under RFC 8949 §4.2.1 (r3 §5).
  @thumbprint_prefix <<0xA3, 0x01, 0x07, 0x03, 0x38, 0x31, 0x20, 0x59, 0x0A, 0x20>>

  defp opts(extra \\ []),
    do: extra ++ [private_key: @seed, public_key: @pub, issuer: "beam_mcp.test"]

  defp graph do
    srv = Node.new!(kind: :server, level: :server, identity: {:server, "srv"})
    a = Node.new!(kind: :tool, level: :server, identity: {:tool, "srv", "a"})
    b = Node.new!(kind: :tool, level: :server, identity: {:tool, "srv", "b"})
    e = Edge.new!(from: a.id, to: b.id, kind: :invoke, provenance: :declared, weight: 1)
    Graph.new!(nodes: [srv, a, b], edges: [e], schema_version: Graph.schema_version())
  end

  # CBOR heads written here, independently of the encoder under test.
  defp head(major, n) when n < 24, do: <<major::3, n::5>>
  defp head(major, n) when n < 0x100, do: <<major::3, 24::5, n>>
  defp head(major, n) when n < 0x10000, do: <<major::3, 25::5, n::16>>
  defp head(major, n), do: <<major::3, 26::5, n::32>>
  defp bstr(b), do: head(2, byte_size(b)) <> b

  defp to_be_signed(protected, payload),
    do: <<0x84, 0x6A, "Signature1">> <> bstr(protected) <> <<0x40>> <> bstr(payload)

  defp carrier(bytes) do
    {:ok, %{0 => @single_schema, 1 => {:bytes, body}, 2 => sign1} = c} = StrictCBOR.decode(bytes)
    assert map_size(c) == 3
    [{:bytes, protected}, %{} = unprotected, nil, {:bytes, signature}] = sign1
    assert unprotected == %{}
    %{body: body, protected: protected, signature: signature}
  end

  defp verify(%{body: body, protected: protected, signature: signature}),
    do: :crypto.verify(:mldsa87, :none, to_be_signed(protected, body), signature, @pub)

  test "implements BeamMCP.Signer, and only sign/2" do
    assert BeamMCP.Signer in (COSE.module_info(:attributes)[:behaviour] || [])
    assert COSE.__info__(:functions) == [sign: 2]
  end

  describe "F8: the algorithm and the key beside a signature" do
    @describetag :mldsa87

    test "today: scheme and key_id are not signed, so swapping them leaves the signature valid" do
      {:ok, result} =
        Canonical.signature(graph(), MLDSA87,
          private_key: @seed,
          public_key: @pub,
          scheme: :mldsa87,
          key_id: "k-mldsa"
        )

      swapped = %{result | scheme: :ed25519, key_id: "k-someone-else"}
      {:ok, bytes} = Canonical.encode(graph())
      assert :crypto.verify(:mldsa87, :none, bytes, swapped.signature, @pub)
    end

    test "in the carrier: changing alg, kid or typ in the protected header, or the body, breaks the signature" do
      {:ok, bytes} = Canonical.encode(graph())
      assert {:ok, out} = COSE.sign(bytes, opts())
      c = carrier(out)
      assert verify(c)

      {:ok, header} = StrictCBOR.decode(c.protected)
      <<k0, kid_rest::binary>> = elem(header[4], 1)

      for changed <- [
            Map.put(header, 1, -49),
            Map.put(header, 4, {:bytes, <<Bitwise.bxor(k0, 1), kid_rest::binary>>}),
            Map.put(header, 16, "application/vnd.example.b85.other.v0+cose")
          ] do
        {:ok, protected} = CBOR.encode(changed)
        refute verify(%{c | protected: protected})
      end

      <<b0, body_rest::binary>> = c.body
      refute verify(%{c | body: <<Bitwise.bxor(b0, 1), body_rest::binary>>})
    end
  end

  describe "the carrier" do
    @describetag :mldsa87

    test "{0: 0xFFFF0003, 1: body, 2: [protected, {}, nil, signature]}, strictly canonical" do
      {:ok, bytes} = Canonical.encode(graph())
      assert {:ok, out} = COSE.sign(bytes, opts())
      c = carrier(out)
      assert byte_size(c.signature) == 4627
      assert verify(c)
    end

    test "the protected header is {1: -50, 4: kid48, 16: typ} and nothing else" do
      {:ok, out} = COSE.sign("bytes", opts())
      c = carrier(out)
      kid = :crypto.hash(:sha384, @thumbprint_prefix <> @pub)
      assert StrictCBOR.decode(c.protected) == {:ok, %{1 => -50, 4 => {:bytes, kid}, 16 => @typ}}
    end

    test "the body names the canonical bytes by SHA-384 and length, with the host's issuer" do
      {:ok, bytes} = Canonical.encode(graph())
      {:ok, out} = COSE.sign(bytes, opts())

      assert StrictCBOR.decode(carrier(out).body) ==
               {:ok,
                %{
                  0 => @schema,
                  1 => "beam_mcp.test",
                  2 => %{
                    0 => [-43, {:bytes, :crypto.hash(:sha384, bytes)}],
                    1 => byte_size(bytes),
                    2 => "application/json"
                  }
                }}
    end

    test "an issuer given as {:bytes, b} is a byte string in the body" do
      {:ok, out} = COSE.sign("bytes", opts(issuer: {:bytes, <<1, 2, 3>>}))
      assert {:ok, %{1 => {:bytes, <<1, 2, 3>>}}} = StrictCBOR.decode(carrier(out).body)
    end

    test "hedged: two carriers over the same bytes differ only in the signature" do
      {:ok, one} = COSE.sign("bytes", opts())
      {:ok, two} = COSE.sign("bytes", opts())
      {c1, c2} = {carrier(one), carrier(two)}
      assert {c1.body, c1.protected} == {c2.body, c2.protected}
      refute c1.signature == c2.signature
      assert verify(c1) and verify(c2)
    end

    test "each key function is called once per signature" do
      me = self()

      private = fn ->
        send(me, :private)
        @seed
      end

      public = fn ->
        send(me, :public)
        @pub
      end

      assert {:ok, _} =
               COSE.sign("bytes", private_key: private, public_key: public, issuer: "i")

      assert_received :private
      assert_received :public
      refute_received :private
      refute_received :public
    end
  end

  describe "RFC 9964 Appendix A.2 (ML_DSA_87)" do
    test "SHA-256 over the thumbprint input N6 hashes reproduces the RFC's kid (RFC 9679, SHA-256)" do
      pub = Base.decode16!(@a2["raw_public_key"], case: :lower)
      {:ok, key} = @a2["key"] |> Base.decode16!(case: :lower) |> cose_key()
      assert :crypto.hash(:sha256, @thumbprint_prefix <> pub) == key.kid
      assert key.pub == pub
    end

    test "the encoder reproduces the RFC's protected header and ToBeSigned, byte for byte" do
      tbs = Base.decode16!(@a2["raw_to_be_signed"], case: :lower)
      {:ok, key} = @a2["key"] |> Base.decode16!(case: :lower) |> cose_key()

      assert {:ok, protected} = CBOR.encode(%{1 => -50, 4 => {:bytes, key.kid}})

      assert CBOR.encode([
               "Signature1",
               {:bytes, protected},
               {:bytes, ""},
               {:bytes, "hello post quantum signatures"}
             ]) == {:ok, tbs}
    end

    @tag :mldsa87
    test "the RFC's signature verifies under its key, and its all-zero seed is that key's" do
      pub = Base.decode16!(@a2["raw_public_key"], case: :lower)
      tbs = Base.decode16!(@a2["raw_to_be_signed"], case: :lower)
      sig = Base.decode16!(@a2["raw_signature"], case: :lower)
      seed = Base.decode16!(@a2["priv"], case: :lower)

      assert :crypto.verify(:mldsa87, :none, tbs, sig, pub)
      assert {:ok, _} = MLDSA87.sign(tbs, private_key: seed, public_key: pub)
    end
  end

  # The RFC's COSE_Key is a map with negative labels (-1, -2), outside N6, so it is read here by
  # hand: a5 (five pairs), 02 kid, 01 kty, 03 alg, 20 pub, 21 priv.
  defp cose_key(
         <<0xA5, 0x02, 0x58, 0x20, kid::binary-32, 0x01, 0x07, 0x03, 0x38, 0x31, 0x20, 0x59, 0x0A,
           0x20, pub::binary-2592, _priv::binary>>
       ),
       do: {:ok, %{kid: kid, pub: pub}}

  describe "refusals: answers, never raises, and no key byte in any" do
    test "no issuer, or an issuer that is neither NFC text nor {:bytes, b}" do
      assert COSE.sign("b", private_key: @seed, public_key: @pub) == {:error, :no_issuer}

      for bad <- ["é", <<0xFF>>, 1, :atom, {:bytes, 1}, nil] do
        assert COSE.sign("b", opts(issuer: bad)) == {:error, {:issuer, :invalid}}, inspect(bad)
      end
    end

    test "the key refusals are MLDSA87's, and say nothing of the key" do
      assert COSE.sign("b", issuer: "i") == {:error, :no_private_key}
      assert COSE.sign("b", private_key: @seed, issuer: "i") == {:error, :no_public_key}

      assert COSE.sign("b", private_key: <<1, 2>>, public_key: @pub, issuer: "i") ==
               {:error, {:private_key, :not_32_bytes}}

      assert COSE.sign("b", private_key: @seed, public_key: <<1>>, issuer: "i") ==
               {:error, {:public_key, :not_2592_bytes}}

      assert COSE.sign("b", private_key: fn -> raise "x" end, public_key: @pub, issuer: "i") ==
               {:error, {:private_key, :unreadable}}

      assert COSE.sign(:not_bytes, opts()) == {:error, :bad_arguments}
      assert COSE.sign("b", %{}) == {:error, :bad_arguments}
      assert COSE.sign("b", [{:issuer, "i"} | :improper]) == {:error, :bad_arguments}
    end

    @tag :mldsa87
    test "a public key that is not the seed's: no carrier" do
      {other, _} = :crypto.generate_key(:mldsa87, [])
      assert COSE.sign("b", opts(public_key: other)) == {:error, {:public_key, :does_not_verify}}
    end

    @tag :no_mldsa87
    test "on a runtime without ML-DSA-87: :crypto_refused" do
      assert COSE.sign("b", opts()) == {:error, :crypto_refused}
    end
  end
end
