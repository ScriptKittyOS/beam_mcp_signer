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

  # A FunctionClauseError is printed with the call's arguments, and the options hold the key: a
  # raise here would put the key in the host's crash log. So a mistyped call is answered, never
  # raised, and the answer carries no byte of what was passed.
  test "a mistyped call is answered {:error, :bad_arguments}, never raised, and echoes nothing" do
    {_pub, priv} = keypair()

    assert Ed25519.sign("abc", %{private_key: priv}) == {:error, :bad_arguments}
    assert Ed25519.sign(:not_bytes, private_key: priv) == {:error, :bad_arguments}
    assert Ed25519.sign(~c"abc", private_key: priv) == {:error, :bad_arguments}
    assert Ed25519.sign("abc", nil) == {:error, :bad_arguments}
  end

  test "the key may be passed by reference, a zero-arity function returning it, and signs as the bytes do" do
    {pub, priv} = keypair()
    bytes = :crypto.strong_rand_bytes(211)

    assert {:ok, sig} = Ed25519.sign(bytes, private_key: fn -> priv end)
    assert {:ok, sig} == Ed25519.sign(bytes, private_key: priv)
    assert :crypto.verify(:eddsa, :none, bytes, sig, [pub, :ed25519])

    g = graph()

    assert {:ok, %{signature: through_core}} =
             Canonical.signature(g, Ed25519, private_key: fn -> priv end)

    assert :crypto.verify(:eddsa, :none, Canonical.encode!(g), through_core, [pub, :ed25519])
  end

  test "a reference that does not give 32 bytes is refused as a key that is not 32 bytes" do
    {_pub, priv} = keypair()

    for bad <- [fn -> "short" end, fn -> nil end, fn -> ~c"not a binary" end, fn _ -> priv end] do
      assert Ed25519.sign("abc", private_key: bad) == {:error, {:private_key, :not_32_bytes}}
    end
  end

  # What the reference buys, measured through core: `Canonical.signature/3` given a map for its
  # options raises in core before this package is reached, and the exception prints the options.
  # Passed by reference, the key is printed as #Function<...>; passed as bytes, the bytes are
  # printed. The second assertion is core's to change: the day core answers a mistyped call
  # instead of raising, it fails, and the README's advice can soften.
  test "passed by reference, the key reaches no exception report, even from a mistyped call into core" do
    {_pub, priv} = keypair()
    g = graph()

    report = fn opts ->
      try do
        Canonical.signature(g, Ed25519, opts)
        flunk("core answered a mistyped call; the README's advice on references can be revisited")
      rescue
        e -> Exception.format(:error, e, __STACKTRACE__)
      end
    end

    by_reference = report.(%{private_key: fn -> priv end})
    refute by_reference =~ inspect(priv, limit: :infinity)
    refute by_reference =~ priv |> :binary.bin_to_list() |> Enum.take(8) |> Enum.join(", ")

    assert report.(%{private_key: priv}) =~ inspect(priv, limit: :infinity)
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
