# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.Ed25519Test do
  # Every key in this file is generated in the test process and dropped with it; none is
  # written anywhere.
  use ExUnit.Case, async: true

  alias BeamMCP.Connectome.{Canonical, Edge, Graph, Node}
  alias BeamMCP.Signer.Ed25519

  defp keypair, do: :crypto.generate_key(:eddsa, :ed25519)

  defp graph do
    srv = Node.new!(kind: :server, level: :server, identity: {:server, "srv"})
    a = Node.new!(kind: :tool, level: :server, identity: {:tool, "srv", "a"})
    b = Node.new!(kind: :tool, level: :server, identity: {:tool, "srv", "b"})
    e = Edge.new!(from: a.id, to: b.id, kind: :invoke, provenance: :declared, weight: 1)
    Graph.new!(nodes: [srv, a, b], edges: [e], schema_version: Graph.schema_version())
  end

  test "implements BeamMCP.Signer, and only sign/2" do
    assert BeamMCP.Signer in (Ed25519.module_info(:attributes)[:behaviour] || [])
    assert BeamMCP.Signer.behaviour_info(:callbacks) == [sign: 2]
    assert Ed25519.__info__(:functions) == [sign: 2]
  end

  test "signs exactly the bytes given, and a verifier with the public key agrees" do
    {pub, priv} = keypair()
    bytes = :crypto.strong_rand_bytes(347)

    assert {:ok, sig} = Ed25519.sign(bytes, private_key: priv)
    assert byte_size(sig) == 64
    assert :crypto.verify(:eddsa, :none, bytes, sig, [pub, :ed25519])
    refute :crypto.verify(:eddsa, :none, bytes <> <<0>>, sig, [pub, :ed25519])
    refute :crypto.verify(:eddsa, :none, bytes, sig, [elem(keypair(), 0), :ed25519])
  end

  test "Ed25519 is deterministic: the same bytes and key give the same signature" do
    {_pub, priv} = keypair()
    assert Ed25519.sign("abc", private_key: priv) == Ed25519.sign("abc", private_key: priv)
    assert Ed25519.sign("abc", private_key: priv) != Ed25519.sign("abd", private_key: priv)
  end

  test "through core's seam: the signature is over encode/2's bytes and sits beside them" do
    {pub, priv} = keypair()
    g = graph()

    assert {:ok, %{algorithm: :sha256, signature: sig, signer: Ed25519}} =
             Canonical.signature(g, Ed25519, private_key: priv)

    assert :crypto.verify(:eddsa, :none, Canonical.encode!(g), sig, [pub, :ed25519])

    assert {:ok, %{algorithm: :sha384, signature: sig384}} =
             Canonical.signature(g, Ed25519, private_key: priv, algorithm: :sha384)

    assert :crypto.verify(
             :eddsa,
             :none,
             Canonical.encode!(g, algorithm: :sha384),
             sig384,
             [pub, :ed25519]
           )

    assert Canonical.signature(g, Ed25519, []) == {:error, {:signer, :no_private_key}}
  end

  test "no key, no signature: the option absent, or not 32 bytes" do
    assert Ed25519.sign("abc", []) == {:error, :no_private_key}
    assert Ed25519.sign("abc", key: <<0::256>>) == {:error, :no_private_key}
    assert Ed25519.sign("abc", private_key: nil) == {:error, {:private_key, :not_32_bytes}}
    assert Ed25519.sign("abc", private_key: "short") == {:error, {:private_key, :not_32_bytes}}
    assert Ed25519.sign("abc", private_key: <<0::264>>) == {:error, {:private_key, :not_32_bytes}}

    assert Ed25519.sign("abc", private_key: ~c"not a binary") ==
             {:error, {:private_key, :not_32_bytes}}
  end

  test "reads :private_key and nothing else: other keys are neither read nor refused" do
    {pub, priv} = keypair()

    assert {:ok, sig} =
             Ed25519.sign("abc", key_id: "k1", algorithm: :sha512, private_key: priv, bogus: 1)

    assert :crypto.verify(:eddsa, :none, "abc", sig, [pub, :ed25519])
  end

  test "the key is not held: no process, ets, persistent_term or application state after a call" do
    {_pub, priv} = keypair()
    before = {Process.get(), :persistent_term.get(), Application.get_all_env(:beam_mcp_signer)}
    {:ok, _} = Ed25519.sign("abc", private_key: priv)

    assert {Process.get(), :persistent_term.get(), Application.get_all_env(:beam_mcp_signer)} ==
             before

    refute Enum.any?(:ets.all(), fn t -> :ets.info(t, :name) |> to_string() =~ ~r/signer|key/i end)
  end
end
