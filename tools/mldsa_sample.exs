# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0
#
# Writes one ML-DSA-87 signature made by BeamMCP.Signer.MLDSA87, and one N6 carrier made by
# BeamMCP.Signer.COSE, for other implementations to verify (tools/cross_verify/): the canonical
# bytes of a fixed graph, the signature over them, the carrier over them, and the key pair both
# were made with, ACVP's published keyGen case (tgId 3, tcId 51), so the
# seed is a test vector and no secret. Run on CI's box leg:
#
#   MIX_ENV=test mix run tools/mldsa_sample.exs <dir>
#
# Writes <dir>/message.bin, signature.bin, carrier.cbor, public_key.bin, seed.bin.
alias BeamMCP.Connectome.{Canonical, Edge, Graph, Node}

[dir] = System.argv()
File.mkdir_p!(dir)

pair = "test/fixtures/mldsa87/acvp_keygen.json" |> File.read!() |> Jason.decode!() |> Map.fetch!("test")
seed = Base.decode16!(pair["seed"])
public_key = Base.decode16!(pair["pk"])

srv = Node.new!(kind: :server, level: :server, identity: {:server, "srv"})
a = Node.new!(kind: :tool, level: :server, identity: {:tool, "srv", "a"})
b = Node.new!(kind: :tool, level: :server, identity: {:tool, "srv", "b"})
e = Edge.new!(from: a.id, to: b.id, kind: :invoke, provenance: :declared, weight: 1)
graph = Graph.new!(nodes: [srv, a, b], edges: [e], schema_version: Graph.schema_version())

message = Canonical.encode!(graph, algorithm: :sha384)

{:ok, %{signature: signature}} =
  Canonical.signature(graph, BeamMCP.Signer.MLDSA87,
    private_key: fn -> seed end,
    public_key: fn -> public_key end,
    algorithm: :sha384
  )

{:ok, carrier} =
  BeamMCP.Signer.COSE.sign(message,
    private_key: fn -> seed end,
    public_key: fn -> public_key end,
    issuer: "beam_mcp_signer.ci"
  )

for {name, bytes} <- [
      {"message.bin", message},
      {"signature.bin", signature},
      {"carrier.cbor", carrier},
      {"public_key.bin", public_key},
      {"seed.bin", seed}
    ] do
  File.write!(Path.join(dir, name), bytes)
  IO.puts("#{name}: #{byte_size(bytes)} bytes, sha256 #{Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)}")
end
