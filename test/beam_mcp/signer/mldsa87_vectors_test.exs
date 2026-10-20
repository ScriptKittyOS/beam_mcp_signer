# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.MLDSA87VectorsTest do
  # The runtime the signer stands on, held to published vectors (test/fixtures/mldsa87/, written
  # by tools/vectors_mldsa87.sh at pinned commits). `:crypto` verifies pure ML-DSA through the
  # external interface with an empty context and nothing else, so a case needing anything else
  # cannot be expressed here: each such case is counted under its reason, and the counts are
  # asserted, so a case that comes into reach (a context option in `:crypto`, for one) fails the
  # count until it is run. The signer itself never produces any of those classes.
  use ExUnit.Case, async: true

  @moduletag :mldsa87

  @dir "test/fixtures/mldsa87"
  @keygen Jason.decode!(File.read!("#{@dir}/acvp_keygen.json"))["test"]
  @acvp Jason.decode!(File.read!("#{@dir}/acvp_sigver.json"))["testGroups"]
  @wycheproof Jason.decode!(File.read!("#{@dir}/wycheproof_verify.json"))["testGroups"]

  defp hex(s), do: Base.decode16!(s, case: :mixed)

  # A key or signature of the wrong shape is a refusal by `:crypto` (it raises), which is the
  # verdict "does not verify".
  defp verifies?(msg, sig, pub) do
    :crypto.verify(:mldsa87, :none, msg, sig, pub)
  catch
    _, _ -> false
  end

  test "ACVP keyGen tgId 3 tcId 51: the expanded key re-derives the public key, and the seed signs under it" do
    pk = hex(@keygen["pk"])
    assert {^pk, _} = :crypto.generate_key(:mldsa87, [], hex(@keygen["sk"]))

    sig = :crypto.sign(:mldsa87, :none, "keygen", {:seed, hex(@keygen["seed"])})
    assert verifies?("keygen", sig, pk)
  end

  test "ACVP sigVer, ML-DSA-87: every case :crypto can express agrees; the rest are counted by reason" do
    tally =
      for group <- @acvp, tc <- group["tests"], reduce: %{} do
        acc ->
          reason =
            cond do
              group["signatureInterface"] != "external" -> :internal_interface
              group["preHash"] != "pure" -> :prehash
              (tc["context"] || "") != "" -> :context
              true -> :run
            end

          if reason == :run do
            got = verifies?(hex(tc["message"]), hex(tc["signature"]), hex(tc["pk"]))
            assert got == tc["testPassed"], "tcId #{tc["tcId"]}: #{tc["reason"]}"
          end

          Map.update(acc, reason, 1, &(&1 + 1))
      end

    assert tally == %{run: 1, context: 14, prehash: 15, internal_interface: 30}
  end

  test "Wycheproof mldsa_87_verify: every case without a context agrees; those with one are counted" do
    tally =
      for group <- @wycheproof, tc <- group["tests"], reduce: %{} do
        acc ->
          if (tc["ctx"] || "") != "" do
            Map.update(acc, :context, 1, &(&1 + 1))
          else
            got = verifies?(hex(tc["msg"]), hex(tc["sig"]), hex(group["publicKey"]))
            assert got == (tc["result"] == "valid"), "tcId #{tc["tcId"]}: #{tc["comment"]}"
            Map.update(acc, :run, 1, &(&1 + 1))
          end
      end

    assert tally == %{run: 234, context: 7}
  end
end
