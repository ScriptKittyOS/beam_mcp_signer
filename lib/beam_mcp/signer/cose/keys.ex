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

  # A reference is called once, here, and what it returns must be the key's bytes at their size,
  # MLDSA87's answers for anything else: a function that returns a function is refused here, not
  # resolved a second time downstream, so the kid is never computed from anything but the bytes
  # that are signed with. What a function raises, throws or exits is answered as unreadable, the
  # reason dropped unread.
  def read(key, name) do
    {size, wrong_size} = size(name)

    case resolve(key) do
      {:ok, bytes} when is_binary(bytes) and byte_size(bytes) == size -> {:ok, bytes}
      {:ok, _other} -> {:error, {name, wrong_size}}
      :unreadable -> {:error, {name, :unreadable}}
    end
  end

  defp size(:private_key), do: {32, :not_32_bytes}
  defp size(:public_key), do: {2592, :not_2592_bytes}

  defp resolve(key) when is_function(key, 0) do
    {:ok, key.()}
  catch
    _kind, _reason -> :unreadable
  end

  defp resolve(key), do: {:ok, key}

  # Over the 2,592 bytes `read/2` gave back. `:crypto` raising here (a runtime without it, a
  # provider refusing SHA-384) would print the public key in its frame: answered, dropped unread.
  def kid(public) when is_binary(public) and byte_size(public) == 2592 do
    {:ok, :crypto.hash(:sha384, @thumbprint_prefix <> public)}
  catch
    _kind, _reason -> {:error, :crypto_refused}
  end
end
