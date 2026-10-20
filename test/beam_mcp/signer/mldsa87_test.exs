# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.MLDSA87Test do
  # The key pair is ACVP's ML-DSA-87 keyGen case (tgId 3, tcId 51): a published seed and the
  # public key it derives. `:crypto` derives no public key from a seed, so a pair cannot be
  # made here; a wrong public key is any other, from `:crypto.generate_key/2`.
  use ExUnit.Case, async: true

  alias BeamMCP.Connectome.{Canonical, Edge, Graph, Node}
  alias BeamMCP.Signer.MLDSA87

  @moduletag :mldsa87

  @pair "test/fixtures/mldsa87/acvp_keygen.json"
        |> File.read!()
        |> Jason.decode!()
        |> Map.fetch!("test")
  @seed Base.decode16!(@pair["seed"])
  @pub Base.decode16!(@pair["pk"])

  defp opts, do: [private_key: @seed, public_key: @pub]
  defp verify(bytes, sig), do: :crypto.verify(:mldsa87, :none, bytes, sig, @pub)

  defp graph do
    srv = Node.new!(kind: :server, level: :server, identity: {:server, "srv"})
    a = Node.new!(kind: :tool, level: :server, identity: {:tool, "srv", "a"})
    b = Node.new!(kind: :tool, level: :server, identity: {:tool, "srv", "b"})
    e = Edge.new!(from: a.id, to: b.id, kind: :invoke, provenance: :declared, weight: 1)
    Graph.new!(nodes: [srv, a, b], edges: [e], schema_version: Graph.schema_version())
  end

  test "implements BeamMCP.Signer, and only sign/2" do
    assert BeamMCP.Signer in (MLDSA87.module_info(:attributes)[:behaviour] || [])
    assert MLDSA87.__info__(:functions) == [sign: 2]
  end

  test "signs exactly the bytes given, and a verifier with the public key agrees" do
    bytes = :crypto.strong_rand_bytes(347)

    assert {:ok, sig} = MLDSA87.sign(bytes, opts())
    assert byte_size(sig) == 4627
    assert verify(bytes, sig)
    refute verify(bytes <> <<0>>, sig)

    refute :crypto.verify(
             :mldsa87,
             :none,
             bytes,
             sig,
             elem(:crypto.generate_key(:mldsa87, []), 0)
           )
  end

  test "signs the empty message too, and its self-check still has a different message to refuse" do
    assert {:ok, sig} = MLDSA87.sign("", opts())
    assert verify("", sig)
  end

  test "hedged: two signatures of the same bytes differ, and both verify" do
    assert {:ok, one} = MLDSA87.sign("abc", opts())
    assert {:ok, two} = MLDSA87.sign("abc", opts())
    assert one != two
    assert verify("abc", one) and verify("abc", two)
  end

  test "through core's seam: the signature is over encode/2's bytes and sits beside them" do
    g = graph()

    assert {:ok, %{algorithm: :sha384, signature: sig, signer: MLDSA87, scheme: :mldsa87}} =
             Canonical.signature(g, MLDSA87, opts() ++ [algorithm: :sha384, scheme: :mldsa87])

    assert verify(Canonical.encode!(g, algorithm: :sha384), sig)
  end

  test "a seed and a public key that are not a pair: refused, and no signature leaves" do
    {other, _} = :crypto.generate_key(:mldsa87, [])

    assert MLDSA87.sign("abc", private_key: @seed, public_key: other) ==
             {:error, {:public_key, :does_not_verify}}
  end

  test "the keys are not held: no process, ets, persistent_term or application state after a call" do
    before = {Process.get(), :persistent_term.get(), Application.get_all_env(:beam_mcp_signer)}
    tables = :ets.all()
    {:ok, _} = MLDSA87.sign("abc", opts())

    assert {Process.get(), :persistent_term.get(), Application.get_all_env(:beam_mcp_signer)} ==
             before

    refute Enum.any?(:ets.all() -- tables, &(:ets.info(&1, :owner) == self()))
  end

  test "both keys by reference: each function called once per signature" do
    me = self()
    seed = fn -> send(me, :seed) && @seed end
    pub = fn -> send(me, :pub) && @pub end

    assert {:ok, sig} = MLDSA87.sign("abc", private_key: seed, public_key: pub)
    assert verify("abc", sig)
    assert_received :seed
    assert_received :pub
    refute_received :seed
    refute_received :pub
  end
end
