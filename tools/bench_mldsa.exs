# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0
#
# ML-DSA-87 latency on this machine: BeamMCP.Signer.MLDSA87.sign/2 (one signature and the two
# verifies of its check) and :crypto.verify/5 alone, over a fixed input set, reported as min,
# p50, p99, p99.9 and max in microseconds with the CPU it ran on. A figure from this script
# describes the machine that printed it and no other: it is never a figure for a box it did not
# run on.
#
#   MIX_ENV=test mix run tools/bench_mldsa.exs [rounds]     (default 2000 per input size)
#
# The input set: messages of 64, 1,024, 16,384 and 262,144 bytes, each the SHA-256 counter
# stream of its size, so every run signs the same bytes; their sha256 is printed. The key pair is
# ACVP's keyGen tgId 3 tcId 51 (test/fixtures/mldsa87/acvp_keygen.json).
alias BeamMCP.Signer.MLDSA87

rounds =
  case System.argv() do
    [n] -> String.to_integer(n)
    [] -> 2000
  end

pair = "test/fixtures/mldsa87/acvp_keygen.json" |> File.read!() |> Jason.decode!() |> Map.fetch!("test")
seed = Base.decode16!(pair["seed"])
public_key = Base.decode16!(pair["pk"])
opts = [private_key: seed, public_key: public_key]

stream = fn size ->
  0
  |> Stream.iterate(&(&1 + 1))
  |> Stream.map(&:crypto.hash(:sha256, <<&1::64>>))
  |> Enum.take(div(size + 31, 32))
  |> IO.iodata_to_binary()
  |> binary_part(0, size)
end

cpu =
  case File.read("/proc/cpuinfo") do
    {:ok, info} ->
      fields = for line <- String.split(info, "\n"), [k, v] <- [String.split(line, ":", parts: 2)], do: {String.trim(k), String.trim(v)}
      get = fn key -> Enum.find_value(fields, fn {k, v} -> k == key and v end) end
      # x86_64 names its model; arm64 Linux gives only the implementer and part numbers (on
      # GitHub's arm64 runner, 0x41 and 0xd49: Arm, Neoverse N2), so those are what is printed.
      model = get.("model name") || get.("Model") || "CPU implementer #{get.("CPU implementer") || "?"}"
      part = get.("CPU part")
      "#{model}#{if part, do: ", CPU part #{part}", else: ""}; #{System.schedulers_online()} schedulers"

    _ ->
      "unknown"
  end

[{_, _, openssl}] = :crypto.info_lib()
IO.puts("machine: #{cpu}; #{:erlang.system_info(:system_architecture)}")
IO.puts("runtime: OTP #{:erlang.system_info(:otp_release)}, #{openssl}; #{rounds} rounds per size")

# The p-th percentile is the sample at index trunc(p * rounds), printed only when some sample lies
# above it: at 1,000 rounds or fewer the p99.9 index is the last sample, which is max, not p99.9,
# so it prints "-".
percentile = fn sorted, p ->
  i = trunc(p * length(sorted))
  if i < length(sorted) - 1, do: Enum.at(sorted, i), else: "-"
end

measure = fn f ->
  for _ <- 1..rounds do
    {us, _} = :timer.tc(f)
    us
  end
  |> Enum.sort()
end

report = fn label, sorted ->
  IO.puts(
    "  #{String.pad_trailing(label, 30)} min #{hd(sorted)}  p50 #{percentile.(sorted, 0.5)}  " <>
      "p99 #{percentile.(sorted, 0.99)}  p99.9 #{percentile.(sorted, 0.999)}  max #{List.last(sorted)}  (us)"
  )
end

for size <- [64, 1024, 16_384, 262_144] do
  message = stream.(size)
  {:ok, signature} = MLDSA87.sign(message, opts)
  IO.puts("#{size} bytes, sha256 #{Base.encode16(:crypto.hash(:sha256, message), case: :lower)}")
  report.("MLDSA87.sign/2 (with check)", measure.(fn -> {:ok, _} = MLDSA87.sign(message, opts) end))
  report.(":crypto.verify/5", measure.(fn -> true = :crypto.verify(:mldsa87, :none, message, signature, public_key) end))
end
