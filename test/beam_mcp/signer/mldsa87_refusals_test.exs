# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.MLDSA87RefusalsTest do
  # Every refusal that is decided before `:crypto` is reached, so these run on every leg, with
  # ML-DSA or without; and, on a runtime without it, the refusal `:crypto` itself causes.
  use ExUnit.Case, async: true

  alias BeamMCP.Signer.MLDSA87

  @seed :binary.copy(<<0xA5>>, 32)
  @pub :binary.copy(<<0x5A>>, 2592)

  test "no key, no signature: either option absent" do
    assert MLDSA87.sign("abc", []) == {:error, :no_private_key}
    assert MLDSA87.sign("abc", public_key: @pub) == {:error, :no_private_key}
    assert MLDSA87.sign("abc", private_key: @seed) == {:error, :no_public_key}
    assert MLDSA87.sign("abc", key: @seed, public_key: @pub) == {:error, :no_private_key}
  end

  test "a key of the wrong size is refused by name, the private key checked first" do
    assert MLDSA87.sign("abc", private_key: <<0::248>>, public_key: @pub) ==
             {:error, {:private_key, :not_32_bytes}}

    assert MLDSA87.sign("abc", private_key: nil, public_key: @pub) ==
             {:error, {:private_key, :not_32_bytes}}

    assert MLDSA87.sign("abc", private_key: :binary.copy(<<0>>, 4896), public_key: @pub) ==
             {:error, {:private_key, :not_32_bytes}}

    assert MLDSA87.sign("abc", private_key: @seed, public_key: <<0::8>>) ==
             {:error, {:public_key, :not_2592_bytes}}

    assert MLDSA87.sign("abc", private_key: @seed, public_key: ~c"not a binary") ==
             {:error, {:public_key, :not_2592_bytes}}

    assert MLDSA87.sign("abc", private_key: <<0>>, public_key: <<0>>) ==
             {:error, {:private_key, :not_32_bytes}}
  end

  # The host's own code reading its key may print the key in what it raises: answered, and the
  # reason dropped unread.
  test "a key function that raises, throws or exits is answered as unreadable" do
    for bad <- [
          fn -> raise "seed file: #{inspect(@seed)}" end,
          fn -> throw(@seed) end,
          fn -> exit(@seed) end
        ] do
      assert MLDSA87.sign("abc", private_key: bad, public_key: @pub) ==
               {:error, {:private_key, :unreadable}}

      assert MLDSA87.sign("abc", private_key: @seed, public_key: bad) ==
               {:error, {:public_key, :unreadable}}
    end
  end

  test "a mistyped call is answered, never raised: an exception would print the options, keys and all" do
    assert MLDSA87.sign(:not_bytes, private_key: @seed, public_key: @pub) ==
             {:error, :bad_arguments}

    assert MLDSA87.sign("abc", %{private_key: @seed}) == {:error, :bad_arguments}
    assert MLDSA87.sign("abc", [{:other, 1} | :improper]) == {:error, :bad_arguments}
    assert MLDSA87.sign("abc", [{:private_key, @seed} | :improper]) == {:error, :bad_arguments}
  end

  test "no answer carries a byte of either key" do
    answers =
      for opts <- [
            [private_key: <<1, 2, 3>>, public_key: @pub],
            [private_key: @seed, public_key: <<1, 2, 3>>],
            [private_key: fn -> raise inspect(@seed) end, public_key: @pub],
            [private_key: @seed, public_key: @pub]
          ],
          do: MLDSA87.sign("abc", opts)

    for answer <- answers, key <- [@seed, @pub, <<1, 2, 3>>] do
      refute :binary.match(:erlang.term_to_binary(answer), key) != :nomatch
    end
  end

  @tag :no_mldsa87
  test "on a runtime whose :crypto offers no ML-DSA-87, the answer is :crypto_refused" do
    refute :mldsa87 in :crypto.supports(:public_keys)
    assert MLDSA87.sign("abc", private_key: @seed, public_key: @pub) == {:error, :crypto_refused}
  end
end
