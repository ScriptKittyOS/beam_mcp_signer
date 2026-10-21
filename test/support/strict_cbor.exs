# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.Test.StrictCBOR do
  @moduledoc false
  # A strict decoder for N6's encoding rules (E1-E8, E10), for the tests only. It judges
  # canonical form as it reads -- every head the shortest for its argument, every length
  # definite, every map's keys unsigned and in ascending order of their encoded bytes, every
  # text under the profile's text rule (test/support/ucd.exs, from the Unicode data files) --
  # rather than by re-encoding with the encoder under test, so a
  # defect in that encoder cannot pass as canonical here. Values come back in the encoder's
  # own form: integers, `{:bytes, b}`, text as a binary, lists, maps, true, false, nil.

  import Bitwise

  alias BeamMCP.Signer.Test.UCD

  def decode(bytes) when is_binary(bytes) do
    case item(bytes) do
      {:ok, value, <<>>} -> {:ok, value}
      {:ok, _value, _rest} -> {:error, :trailing_bytes}
      {:error, _} = error -> error
    end
  end

  defp item(<<major::3, info::5, rest::binary>>) do
    with {:ok, arg, rest} <- argument(info, rest) do
      value(major, arg, rest)
    end
  end

  defp item(<<>>), do: {:error, :truncated}

  defp argument(info, rest) when info < 24, do: {:ok, info, rest}
  defp argument(24, <<n, rest::binary>>) when n >= 24, do: {:ok, n, rest}
  defp argument(25, <<n::16, rest::binary>>) when n > 0xFF, do: {:ok, n, rest}
  defp argument(26, <<n::32, rest::binary>>) when n > 0xFFFF, do: {:ok, n, rest}
  defp argument(27, <<n::64, rest::binary>>) when n > 0xFFFFFFFF, do: {:ok, n, rest}
  defp argument(info, _rest) when info in 24..27, do: {:error, :noncanonical_or_truncated}
  defp argument(31, _rest), do: {:error, :indefinite_length}
  defp argument(_info, _rest), do: {:error, :malformed_head}

  defp value(0, n, rest), do: {:ok, n, rest}
  defp value(1, n, _rest) when n >= 1 <<< 63, do: {:error, :int_out_of_range}
  defp value(1, n, rest), do: {:ok, -1 - n, rest}

  defp value(2, n, rest) do
    with {:ok, b, rest} <- take(rest, n), do: {:ok, {:bytes, b}, rest}
  end

  defp value(3, n, rest) do
    with {:ok, t, rest} <- take(rest, n),
         :ok <- text(t),
         do: {:ok, t, rest}
  end

  defp value(4, n, rest), do: array(n, rest, [])
  defp value(5, n, rest), do: map(n, rest, nil, %{})
  defp value(6, _n, _rest), do: {:error, :tag_forbidden}
  # Major 7: the argument has been read already, so 20, 21 and 22 arrive here as values.
  defp value(7, 20, rest), do: {:ok, false, rest}
  defp value(7, 21, rest), do: {:ok, true, rest}
  defp value(7, 22, rest), do: {:ok, nil, rest}
  defp value(7, _n, _rest), do: {:error, :float_or_simple_forbidden}

  defp text(t) do
    cond do
      not String.valid?(t) -> {:error, :invalid_utf8}
      byte_size(t) > 65_536 -> {:error, :text_too_long}
      true -> UCD.check(t)
    end
  end

  defp take(rest, n) when byte_size(rest) >= n,
    do: {:ok, binary_part(rest, 0, n), binary_part(rest, n, byte_size(rest) - n)}

  defp take(_rest, _n), do: {:error, :truncated}

  defp array(0, rest, acc), do: {:ok, Enum.reverse(acc), rest}

  defp array(n, rest, acc) do
    with {:ok, v, rest} <- item(rest), do: array(n - 1, rest, [v | acc])
  end

  defp map(0, rest, _last, acc), do: {:ok, acc, rest}

  defp map(n, rest, last, acc) do
    with {:ok, key, after_key} <- item(rest),
         :ok <- uint_key(key),
         key_bytes = binary_part(rest, 0, byte_size(rest) - byte_size(after_key)),
         :ok <- ascending(last, key_bytes),
         {:ok, v, rest} <- item(after_key) do
      map(n - 1, rest, key_bytes, Map.put(acc, key, v))
    end
  end

  defp uint_key(k) when is_integer(k) and k >= 0 and k < 1 <<< 32, do: :ok
  defp uint_key(_), do: {:error, :key_not_uint}

  defp ascending(nil, _key), do: :ok
  defp ascending(last, key) when last < key, do: :ok
  defp ascending(last, last), do: {:error, :duplicate_key}
  defp ascending(_last, _key), do: {:error, :noncanonical}
end
