# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.COSE.TextTest do
  # N6's text rule (profile v0.1 §2.4) held to the Unicode 15.0.0 data files themselves: the
  # fixtures are the files tools/unicode_tables.sh fetched and pinned, read by the tests' own
  # parser (test/support/ucd.exs), so the generated tables and the encoder's scan are each
  # checked against code that shares nothing with them.
  use ExUnit.Case, async: true

  alias BeamMCP.Signer.COSE
  alias BeamMCP.Signer.COSE.{CBOR, Unicode}
  alias BeamMCP.Signer.Test.UCD

  @pins %{
    "DerivedGeneralCategory.txt" =>
      "fe29a45c0882500e591140aaa5c4f5067e6a5d746806148af34400c48b9c06f9",
    "DerivedCombiningClass.txt" =>
      "ca54f6360cd288ad92113415bf1f77749015abe11cbd6798d21f7fa81f04205d",
    "DerivedNormalizationProps.txt" =>
      "d5687a48c95c7d6e1ec59cb29c0f2e8b052018eb069a4371b7368d0561e12a29"
  }

  defp verdict(t) do
    case CBOR.encode(t) do
      {:ok, _} -> :ok
      error -> error
    end
  end

  test "the fixtures are the pinned Unicode 15.0.0 files, and hold the profile's figures" do
    for {file, sum} <- @pins do
      bytes = File.read!(Path.join("test/fixtures/unicode", file))
      assert Base.encode16(:crypto.hash(:sha256, bytes), case: :lower) == sum, file
      assert bytes =~ "-15.0.0.txt", file
    end

    count = fn pred -> Enum.count(0..0x10FFFF, pred) end
    assert count.(&UCD.format?/1) == 170
    assert count.(&UCD.nfc_no?/1) == 1_120
    assert count.(&UCD.nfc_maybe?/1) == 111
    assert Unicode.version() == "15.0.0"
  end

  test "every code point alone: the encoder's verdict is the rule's, all 1,112,064 scalar values" do
    mismatches =
      for cp <- Enum.concat(0..0xD7FF, 0xE000..0x10FFFF),
          t = <<cp::utf8>>,
          verdict(t) != UCD.check(t),
          do: cp

    assert mismatches == [], "first: #{inspect(Enum.take(mismatches, 5), base: :hex)}"
  end

  test "sequences: the combining-class order and the first defect, over 20,000 random strings" do
    marks = for cp <- 0..0x10FFFF, UCD.ccc(cp) > 0, not UCD.unassigned?(cp), do: cp
    pool = List.to_tuple(marks ++ Enum.to_list(?a..?z) ++ [0x0915, 0x00E9, 0x212B, 0x200D])
    :rand.seed(:exsss, {58, 59, 2026})

    for _ <- 1..20_000 do
      t =
        for(_ <- 1..:rand.uniform(6), do: elem(pool, :rand.uniform(tuple_size(pool)) - 1))
        |> List.to_string()

      assert verdict(t) == UCD.check(t), inspect(t, binaries: :as_binaries)
    end
  end

  test "the floor: private use, controls and separators pass the rule (a field grammar excludes them)" do
    for t <- ["\uE000", "\u0001", "\u2028", "\u2029", "a\u0301"] do
      assert verdict(t) == UCD.check(t)
    end

    assert verdict("\uE000\u0001\u2028\u2029") == :ok
    assert verdict("\u00E9") == :ok
  end

  test "COSE's issuer: text the rule refuses, or more than 65,536 bytes either way, is no carrier" do
    for bad <- [
          "a\u202Eb",
          "\u200B",
          "\u0378",
          String.duplicate("a", 65_537),
          {:bytes, <<0::size(65_537 * 8)>>}
        ] do
      assert COSE.sign("b", private_key: <<0::256>>, public_key: <<0::20_736>>, issuer: bad) ==
               {:error, {:issuer, :invalid}}
    end
  end
end
