# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.COSE.Keys do
  @moduledoc false
  # What `BeamMCP.Signer.COSE` and `BeamMCP.Signer.COSE.HashEnvelope` share: the option walk,
  # a key reference read once, and the kid (N6 profile v0.1 §5.2).

  # RFC 9679's thumbprint input for the AKP key {1: 7, 3: -50, -1: pub} under RFC 8949 §4.2.1:
  # this head, then the 2,592 public-key bytes.
  @thumbprint_prefix <<0xA3, 0x01, 0x07, 0x03, 0x38, 0x31, 0x20, 0x59, 0x0A, 0x20>>

  # The first `{name, value}` entry, walked here for the reason `BeamMCP.Signer.Ed25519` walks its
  # own: `Keyword.fetch/2` raises, key in view, on an improper list. `missing` is the answer when
  # there is none, or `{:default, value}` for an option that has one.
  def fetch([{name, value} | _], name, _missing), do: {:ok, value}
  def fetch([_ | rest], name, missing), do: fetch(rest, name, missing)
  def fetch([], _name, {:default, value}), do: {:ok, value}
  def fetch([], _name, missing), do: {:error, missing}
  def fetch(_improper_tail, _name, _missing), do: {:error, :bad_arguments}

  # A reference is called once, here, and the bytes go on to MLDSA87, which checks their sizes
  # and reads them as it reads bytes a host passes; what a function raises, throws or exits is
  # answered as unreadable, the reason dropped unread.
  def read(key, name) when is_function(key, 0) do
    {:ok, key.()}
  catch
    _kind, _reason -> {:error, {name, :unreadable}}
  end

  def read(key, _name), do: {:ok, key}

  # The thumbprint needs exactly the 2,592-byte key; any other size is MLDSA87's answer to give,
  # so a key of the wrong size gets a placeholder kid here and is refused there, before signing.
  def kid(public) when is_binary(public) and byte_size(public) == 2592,
    do: :crypto.hash(:sha384, @thumbprint_prefix <> public)

  def kid(_public), do: <<0::384>>
end
