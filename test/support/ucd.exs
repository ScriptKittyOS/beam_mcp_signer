# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.Test.UCD do
  @moduledoc false
  # The N6 text rule (profile v0.1 §2.4) for the tests only, built from the Unicode 15.0.0 data
  # files in test/fixtures/unicode/ by code written here, not by tools/unicode_tables.exs, so a
  # defect in the generator or in the encoder's scan cannot pass as the rule. Every code point's
  # properties are held in two :atomics arrays, filled once: flags (Cn, Cf, NFC_QC No, NFC_QC
  # Maybe) and the canonical combining class.

  import Bitwise

  @dir Path.expand("../fixtures/unicode", __DIR__)
  @cn 1
  @cf 2
  @qc_no 4
  @qc_maybe 8

  def load do
    flags = :atomics.new(0x110000, signed: false)
    ccc = :atomics.new(0x110000, signed: false)

    each("DerivedGeneralCategory.txt", fn cp, [cat] ->
      if cat == "Cn", do: :atomics.add(flags, cp + 1, @cn)
      if cat == "Cf", do: :atomics.add(flags, cp + 1, @cf)
    end)

    each("DerivedNormalizationProps.txt", fn
      cp, ["NFC_QC", "N"] -> :atomics.add(flags, cp + 1, @qc_no)
      cp, ["NFC_QC", "M"] -> :atomics.add(flags, cp + 1, @qc_maybe)
      _cp, _other -> :ok
    end)

    each("DerivedCombiningClass.txt", fn cp, [c] ->
      :atomics.put(ccc, cp + 1, String.to_integer(c))
    end)

    :persistent_term.put(__MODULE__, {flags, ccc})
  end

  # Every code point a data line names, one at a time.
  defp each(file, fun) do
    for line <- File.stream!(Path.join(@dir, file)),
        [data | _] = String.split(line, "#"),
        data = String.trim(data),
        data != "" do
      [range | fields] = data |> String.split(";") |> Enum.map(&String.trim/1)
      [lo, hi] = with [one] <- String.split(range, ".."), do: [one, one]

      for cp <- String.to_integer(lo, 16)..String.to_integer(hi, 16), do: fun.(cp, fields)
    end

    :ok
  end

  def flags(cp), do: :atomics.get(elem(:persistent_term.get(__MODULE__), 0), cp + 1)
  def ccc(cp), do: :atomics.get(elem(:persistent_term.get(__MODULE__), 1), cp + 1)

  def unassigned?(cp), do: (flags(cp) &&& @cn) != 0
  def format?(cp), do: (flags(cp) &&& @cf) != 0
  def nfc_no?(cp), do: (flags(cp) &&& @qc_no) != 0
  def nfc_maybe?(cp), do: (flags(cp) &&& @qc_maybe) != 0

  @doc "The rule over valid UTF-8 text: `:ok` or the profile's code for the first defect."
  def check(t), do: check(String.to_charlist(t), 0)

  defp check([], _last), do: :ok

  defp check([cp | rest], last) do
    c = ccc(cp)

    cond do
      unassigned?(cp) -> {:error, :text_unassigned}
      format?(cp) -> {:error, :text_format_control}
      c > 0 and c < last -> {:error, :not_nfc}
      nfc_no?(cp) -> {:error, :not_nfc}
      nfc_maybe?(cp) -> {:error, :nfc_maybe}
      true -> check(rest, c)
    end
  end
end
