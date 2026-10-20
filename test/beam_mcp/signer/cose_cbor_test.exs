# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.COSE.CBORTest do
  # The encoder against bytes written here by hand, never by the encoder: RFC 8949 Appendix A's
  # rows that N6 admits, every head-length boundary, map-key order, and a refusal for each
  # thing N6 forbids. The strict decoder (test/support/strict_cbor.exs) reads every encoding
  # back without the encoder's help.
  use ExUnit.Case, async: true

  alias BeamMCP.Signer.COSE.CBOR
  alias BeamMCP.Signer.Test.StrictCBOR

  import Bitwise

  defp hex(s), do: Base.decode16!(String.replace(s, " ", ""), case: :lower)

  defp encodes(value, expected_hex) do
    expected = hex(expected_hex)
    assert CBOR.encode(value) == {:ok, expected}, "#{inspect(value)}"
    assert StrictCBOR.decode(expected) == {:ok, value}, "#{inspect(value)} does not read back"
  end

  # RFC 8949 Appendix A, Table 6: the rows inside N6 (integers in [-2^63, 2^64-1], byte and text
  # strings, arrays, maps with unsigned keys, false, true, null).
  test "RFC 8949 Appendix A: every row N6 admits, byte for byte" do
    for {value, h} <- [
          {0, "00"},
          {1, "01"},
          {10, "0a"},
          {23, "17"},
          {24, "1818"},
          {25, "1819"},
          {100, "1864"},
          {1000, "1903e8"},
          {1_000_000, "1a000f4240"},
          {1_000_000_000_000, "1b000000e8d4a51000"},
          {18_446_744_073_709_551_615, "1bffffffffffffffff"},
          {-1, "20"},
          {-10, "29"},
          {-100, "3863"},
          {-1000, "3903e7"},
          {false, "f4"},
          {true, "f5"},
          {nil, "f6"},
          {{:bytes, ""}, "40"},
          {{:bytes, <<1, 2, 3, 4>>}, "4401020304"},
          {"", "60"},
          {"a", "6161"},
          {"IETF", "6449455446"},
          {"\"\\", "62225c"},
          {"ü", "62c3bc"},
          {"水", "63e6b0b4"},
          {"\u{10151}", "64f0908591"},
          {[], "80"},
          {[1, 2, 3], "83010203"},
          {[1, [2, 3], [4, 5]], "8301820203820405"},
          {Enum.to_list(1..25), "98190102030405060708090a0b0c0d0e0f101112131415161718181819"},
          {%{}, "a0"},
          {%{1 => 2, 3 => 4}, "a201020304"}
        ] do
      encodes(value, h)
    end
  end

  test "every head takes its shortest form, at each boundary" do
    for {n, h} <- [
          {23, "17"},
          {24, "1818"},
          {255, "18ff"},
          {256, "190100"},
          {65_535, "19ffff"},
          {65_536, "1a00010000"},
          {4_294_967_295, "1affffffff"},
          {4_294_967_296, "1b0000000100000000"},
          {-24, "37"},
          {-25, "3818"},
          {-(1 <<< 63), "3b7fffffffffffffff"}
        ] do
      encodes(n, h)
    end

    encodes({:bytes, :binary.copy(<<0>>, 24)}, "5818" <> String.duplicate("00", 24))
    encodes(String.duplicate("a", 256), "790100" <> String.duplicate("61", 256))
  end

  test "map keys go in the order of their encoded bytes, whatever order they are given in" do
    encodes(%{100 => 0, 1 => 0, 24 => 0, 10 => 0, 4 => 0}, "a5 0100 0400 0a00 181800 186400")

    encodes(
      %{258 => -43, 16 => "t", 4 => {:bytes, <<9>>}, 1 => -50},
      "a4 013831 044109 106174 190102382a"
    )
  end

  # Up to 32 keys an Erlang map enumerates in key order, which for unsigned keys is already the
  # encoded order; past 32 it is a hash map, enumerated in no useful order. So the sort is only
  # seen working on a map this size.
  test "a map of more than 32 keys still goes in encoded-key order" do
    map = 0..39 |> Enum.shuffle() |> Map.new(&{&1, 0})

    expected =
      "b828" <>
        Enum.map_join(0..23, &(Base.encode16(<<&1>>, case: :lower) <> "00")) <>
        Enum.map_join(24..39, &("18" <> Base.encode16(<<&1>>, case: :lower) <> "00"))

    encodes(map, expected)
  end

  test "what N6 forbids is refused by name, and nothing is encoded" do
    for {value, reason} <- [
          {1 <<< 64, :int_out_of_range},
          {-(1 <<< 63) - 1, :int_out_of_range},
          {1.0, :float_forbidden},
          {0.0, :float_forbidden},
          {%{"a" => 1}, :key_not_uint},
          {%{-1 => 1}, :key_not_uint},
          {%{(1 <<< 32) => 1}, :key_not_uint},
          {"é", :not_nfc},
          {<<0xFF>>, :invalid_utf8},
          {:undefined, :not_encodable},
          {{:tag, 18, 1}, :not_encodable},
          {[1, 2.5], :float_forbidden},
          {%{1 => [%{2 => 1.5}]}, :float_forbidden}
        ] do
      assert CBOR.encode(value) == {:error, reason}, "#{inspect(value)}"
    end
  end

  test "the strict reader refuses what the encoder would never write" do
    for {h, reason} <- [
          {"1801", :noncanonical_or_truncated},
          {"190017", :noncanonical_or_truncated},
          {"9f01ff", :indefinite_length},
          {"d201", :tag_forbidden},
          {"f93c00", :float_or_simple_forbidden},
          {"f7", :float_or_simple_forbidden},
          {"a203040102", :noncanonical},
          {"a201010102", :duplicate_key},
          {"a1616101", :key_not_uint},
          {"6365cc81", :not_nfc},
          {"0000", :trailing_bytes},
          {"62c3", :truncated}
        ] do
      assert StrictCBOR.decode(hex(h)) == {:error, reason}, h
    end
  end
end
