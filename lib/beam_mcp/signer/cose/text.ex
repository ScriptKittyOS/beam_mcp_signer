# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.COSE.Text do
  @moduledoc false
  # N6's text rule (profile v0.1 §2.4, E8, E9's text limit), the encode side: a text string is
  # written only if it is valid UTF-8 of at most 65,536 bytes and, scanning its code points left
  # to right with `last` starting at 0, no code point is, in Unicode 15.0.0 (the tables of
  # `BeamMCP.Signer.COSE.Unicode`, never the runtime's own):
  #
  #   1. unassigned (General_Category Cn)        -> :text_unassigned
  #   2. a format control (Cf)                   -> :text_format_control
  #   3. of a nonzero combining class below last -> :not_nfc
  #   4. NFC_Quick_Check No                      -> :not_nfc
  #   5. NFC_Quick_Check Maybe                   -> :nfc_maybe
  #
  # then `last` becomes its class. The first code point that meets one gives the reason. No
  # normaliser is called: that is the rule, so the answer cannot move with the runtime's Unicode.

  import Bitwise

  alias BeamMCP.Signer.COSE.Unicode

  @max_bytes 65_536

  @type reason ::
          :invalid_utf8
          | :text_too_long
          | :text_unassigned
          | :text_format_control
          | :not_nfc
          | :nfc_maybe

  @spec check(binary()) :: :ok | {:error, reason()}
  def check(t) when byte_size(t) > @max_bytes, do: {:error, :text_too_long}

  def check(t) do
    if String.valid?(t), do: scan(t, 0), else: {:error, :invalid_utf8}
  end

  defp scan(<<>>, _last), do: :ok

  defp scan(<<cp::utf8, rest::binary>>, last) do
    ccc = ccc(cp)

    cond do
      in?(Unicode.unassigned(), cp) -> {:error, :text_unassigned}
      in?(Unicode.format(), cp) -> {:error, :text_format_control}
      ccc != 0 and ccc < last -> {:error, :not_nfc}
      in?(Unicode.nfc_no(), cp) -> {:error, :not_nfc}
      in?(Unicode.nfc_maybe(), cp) -> {:error, :nfc_maybe}
      true -> scan(rest, ccc)
    end
  end

  # Binary search over a tuple of {lo, hi} ranges sorted by lo.
  defp in?(ranges, cp), do: find(ranges, cp, 0, tuple_size(ranges) - 1) != nil

  defp ccc(cp) do
    case find(Unicode.ccc(), cp, 0, tuple_size(Unicode.ccc()) - 1) do
      {_lo, _hi, class} -> class
      nil -> 0
    end
  end

  defp find(_ranges, _cp, lo, hi) when lo > hi, do: nil

  defp find(ranges, cp, lo, hi) do
    mid = (lo + hi) >>> 1
    range = elem(ranges, mid)

    cond do
      cp < elem(range, 0) -> find(ranges, cp, lo, mid - 1)
      cp > elem(range, 1) -> find(ranges, cp, mid + 1, hi)
      true -> range
    end
  end
end
