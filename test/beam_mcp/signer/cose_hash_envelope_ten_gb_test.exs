# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.COSE.HashEnvelopeTenGBTest do
  # A 10 GiB file signed in constant memory, and verified holding only the digest and the
  # signature. The file is sparse (no disk is written, the kernel reads it back as zeros), so
  # the test costs one SHA-384 pass in the VM and one in `sha384sum`, an implementation outside
  # it. Excluded by default; run with `mix test --only ten_gb` (CI's box leg runs it).
  use ExUnit.Case, async: false

  alias BeamMCP.Signer.COSE.HashEnvelope
  alias BeamMCP.Signer.Test.HashEnvelopeVerifier

  @moduletag :ten_gb
  @moduletag :mldsa87
  @moduletag timeout: 900_000

  @pair "test/fixtures/mldsa87/acvp_keygen.json"
        |> File.read!()
        |> Jason.decode!()
        |> Map.fetch!("test")
  @seed Base.decode16!(@pair["seed"])
  @pub Base.decode16!(@pair["pk"])

  @size 10 * 1024 * 1024 * 1024
  @chunk 1_048_576
  @growth_limit 64 * 1_048_576

  setup do
    path = Path.join(System.tmp_dir!(), "hash-envelope-10g-#{System.unique_integer([:positive])}")
    {:ok, fd} = :file.open(path, [:write, :raw])
    {:ok, @size} = :file.position(fd, @size)
    :ok = :file.truncate(fd)
    :ok = :file.close(fd)
    on_exit(fn -> File.rm(path) end)
    %{path: path}
  end

  # The VM's total memory, sampled every 50 ms until told to stop: the peak comes back.
  defp sample(peak) do
    receive do
      {:stop, from} -> send(from, {:peak, peak})
    after
      50 -> sample(max(peak, :erlang.memory(:total)))
    end
  end

  test "10 GiB through sign_stream/2: memory stays flat, and the digest is sha384sum's", %{
    path: path
  } do
    assert File.stat!(path).size == @size
    :erlang.garbage_collect()
    start = :erlang.memory(:total)
    sampler = spawn_link(fn -> sample(start) end)

    {micros, result} =
      :timer.tc(fn ->
        HashEnvelope.sign_stream(File.stream!(path, @chunk),
          private_key: @seed,
          public_key: @pub,
          typ: "application/vnd.example.b80.test_hash.v0+cose",
          preimage_type: "application/octet-stream"
        )
      end)

    send(sampler, {:stop, self()})
    assert_receive {:peak, peak}, 1_000
    assert {:ok, carrier} = result

    growth = peak - start

    IO.puts(
      "\n10 GiB: #{div(micros, 1000)} ms; VM memory at start #{start} B, peak #{peak} B, " <>
        "growth #{growth} B (limit #{@growth_limit}); carrier #{byte_size(carrier)} B"
    )

    assert growth < @growth_limit

    # The verifier holds the carrier and the public key, never the file.
    assert {:ok, %{digest: digest, payload_hash: -43}} =
             HashEnvelopeVerifier.verify(carrier, @pub)

    {out, 0} = System.cmd("sha384sum", [path])
    [hex | _] = String.split(out)
    assert Base.encode16(digest, case: :lower) == hex
  end
end
