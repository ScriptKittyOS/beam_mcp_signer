# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.COSE.CBOR do
  @moduledoc false
  # N6's encoding rules, the encode side only (N6 profile v0.1 §2, E1-E8, and E9's text limit):
  # RFC 8949 §4.2.1 core deterministic encoding -- every head the shortest for its argument,
  # definite lengths, map keys sorted by their encoded bytes -- narrowed to what N6 admits:
  # integers in [-2^63, 2^64-1], byte strings, text under the profile's text rule
  # (`BeamMCP.Signer.COSE.Text`: Unicode 15.0.0, no format controls, the NFC quick check YES,
  # at most 65,536 bytes), proper arrays, maps with unsigned keys below 2^32, false, true and
  # null. Everything else is refused by name and nothing is encoded: floats, tags, other simple
  # values, other keys, text the rule refuses, an improper list, any other term.
  #
  # Terms: an integer; `{:bytes, binary}` for a byte string; a binary for text; a list; a map;
  # `false`, `true`, `nil`. In-house, as N6 asks of every language; no library encodes this.

  import Bitwise

  alias BeamMCP.Signer.COSE.Text

  @type value ::
          integer()
          | {:bytes, binary()}
          | String.t()
          | [value()]
          | %{optional(non_neg_integer()) => value()}
          | boolean()
          | nil

  @type reason ::
          :int_out_of_range
          | :float_forbidden
          | :key_not_uint
          | BeamMCP.Signer.COSE.Text.reason()
          | :not_encodable

  @spec encode(term()) :: {:ok, binary()} | {:error, reason()}
  def encode(value) do
    {:ok, value |> enc() |> IO.iodata_to_binary()}
  catch
    {:refused, reason} -> {:error, reason}
  end

  defp enc(n) when is_integer(n) and n >= 0 and n < 1 <<< 64, do: head(0, n)
  defp enc(n) when is_integer(n) and n < 0 and n >= -(1 <<< 63), do: head(1, -1 - n)
  defp enc(n) when is_integer(n), do: refuse(:int_out_of_range)
  defp enc(f) when is_float(f), do: refuse(:float_forbidden)
  defp enc(false), do: <<0xF4>>
  defp enc(true), do: <<0xF5>>
  defp enc(nil), do: <<0xF6>>
  defp enc({:bytes, b}) when is_binary(b), do: [head(2, byte_size(b)), b]
  defp enc(t) when is_binary(t), do: [head(3, byte_size(t)), text(t)]
  defp enc(l) when is_list(l), do: items(l, [], 0)

  defp enc(m) when is_map(m) do
    pairs =
      m
      |> Enum.map(fn {k, v} -> {IO.iodata_to_binary(key(k)), v} end)
      |> Enum.sort_by(fn {k, _v} -> k end)

    [head(5, map_size(m)) | Enum.map(pairs, fn {k, v} -> [k, enc(v)] end)]
  end

  defp enc(_other), do: refuse(:not_encodable)

  defp key(k) when is_integer(k) and k >= 0 and k < 1 <<< 32, do: head(0, k)
  defp key(_k), do: refuse(:key_not_uint)

  # An improper list has no length to write: refused, never raised on.
  defp items([], acc, n), do: [head(4, n) | Enum.reverse(acc)]
  defp items([x | rest], acc, n), do: items(rest, [enc(x) | acc], n + 1)
  defp items(_improper_tail, _acc, _n), do: refuse(:not_encodable)

  defp text(t) do
    case Text.check(t) do
      :ok -> t
      {:error, reason} -> refuse(reason)
    end
  end

  defp head(major, n) when n < 24, do: <<major::3, n::5>>
  defp head(major, n) when n < 0x100, do: <<major::3, 24::5, n>>
  defp head(major, n) when n < 0x10000, do: <<major::3, 25::5, n::16>>
  defp head(major, n) when n < 0x100000000, do: <<major::3, 26::5, n::32>>
  defp head(major, n), do: <<major::3, 27::5, n::64>>

  defp refuse(reason), do: throw({:refused, reason})
end
