# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.NoKeySourceTest do
  # The census: each signer's keys come through its options and from nowhere else. Two layers,
  # the text under lib/ and the compiled beams' calls, so a spelling the regex misses is still
  # a call the beam shows.
  use ExUnit.Case, async: true

  alias BeamMCP.Signer.{COSE, Ed25519, MLDSA87}
  alias BeamMCP.Signer.COSE.{CBOR, HashEnvelope, Keys}

  @lib Path.wildcard(Path.expand("../../../lib/**/*.ex", __DIR__))
  @source %{
    Ed25519 => "ed25519.ex",
    MLDSA87 => "mldsa87.ex",
    COSE => "cose.ex",
    CBOR => "cbor.ex",
    Keys => "keys.ex",
    HashEnvelope => "hash_envelope.ex"
  }

  @key_source ~r/System\.(get_env|fetch_env!?|cmd)|:os\.(getenv|cmd)|Application\.(get_env|fetch_env!?|get_all_env)|File\.|Path\.expand|~\/|\.ssh|HEX_API_KEY|_KEY"|:persistent_term|:ets\.|Process\.(get|put)|Code\.eval|:init\.get_argument/

  @erlang [
    :byte_size,
    :is_binary,
    :is_list,
    # the guard on a key passed by reference: a zero-arity function, called in the module
    :is_function,
    :error,
    :==,
    :"=:=",
    :andalso,
    :and,
    :get_module_info
  ]

  # What each module may call outside itself, per remote module: the beams' whole truth, held to
  # a list. `:crypto.sign/4` and `:crypto.verify/5` are the arities with no options argument,
  # so no context string (RFC 9964: empty for ML-DSA) and no other option can reach OpenSSL.
  @allowed_calls %{
    Ed25519 => %{crypto: [sign: 4], erlang: @erlang},
    MLDSA87 => %{crypto: [sign: 4, verify: 5], erlang: @erlang}
  }

  # The first two arguments of every `:crypto` call, as literals: the algorithm, and the digest
  # type `:none`. Any other digest type makes `:crypto` sign a digest of the bytes, which for
  # ML-DSA is not HashML-DSA but pure ML-DSA over the digest.
  @crypto_args %{Ed25519 => {:eddsa, :none}, MLDSA87 => {:mldsa87, :none}}

  test "the package is the three signer modules, the hash envelope, the encoder and the key helpers, and no line under lib/ names an environment, file, config or store read" do
    assert @lib |> Enum.map(&Path.basename/1) |> Enum.sort() ==
             @source |> Map.values() |> Enum.sort()

    for path <- @lib,
        {line, n} <- File.read!(path) |> String.split("\n") |> Enum.with_index(1),
        not String.match?(line, ~r/^\s*#/),
        Regex.match?(@key_source, line) do
      flunk("#{Path.relative_to_cwd(path)}:#{n}: #{String.trim(line)}")
    end
  end

  for module <- [Ed25519, MLDSA87] do
    test "#{inspect(module)} calls only its list outside itself, :crypto with literal algorithm and :none" do
      module = unquote(module)
      forms = forms(module)

      calls =
        forms
        |> collect_remote_calls()
        |> Enum.reject(fn {m, _f, _a} -> m == module end)
        |> Enum.uniq()
        |> Enum.sort()

      unexpected =
        Enum.reject(calls, fn {m, f, a} ->
          allowed = get_in(@allowed_calls, [module, m]) || []
          if m == :erlang, do: f in allowed, else: {f, a} in allowed
        end)

      assert unexpected == [], "calls outside the list: #{inspect(unexpected)}"
      assert {:crypto, :sign, 4} in calls

      refute Enum.any?(calls, fn {m, _, _} ->
               m in [System, File, Application, Path, :os, :file, :ets, :persistent_term]
             end)

      {algorithm, digest} = @crypto_args[module]
      crypto_calls = collect_crypto_args(forms)
      assert crypto_calls != []

      for args <- crypto_calls do
        assert [{:atom, _, ^algorithm}, {:atom, _, ^digest} | _] = args
      end
    end
  end

  # The COSE module signs nothing itself: its one `:crypto` call is SHA-384 (the digest of the
  # canonical bytes), the kid is Keys' (SHA-384 too), and the signature is MLDSA87's, checked
  # there. Its encoder calls no `:crypto` and nothing outside the VM. Both lists are the beams'
  # whole truth.
  test "BeamMCP.Signer.COSE: SHA-384, the encoder, the key helpers and MLDSA87.sign/2, and no signing primitive of its own" do
    assert remote_calls(COSE) == [
             {CBOR, :encode, 1},
             {Keys, :fetch, 3},
             {Keys, :kid, 1},
             {Keys, :read, 2},
             {MLDSA87, :sign, 2},
             {:crypto, :hash, 2},
             {:erlang, :byte_size, 1},
             {:erlang, :get_module_info, 2},
             {:erlang, :is_binary, 1},
             {:erlang, :is_list, 1}
           ]

    for module <- [COSE, Keys], args <- collect_crypto_args(forms(module)) do
      assert [{:atom, _, :sha384} | _] = args
    end

    assert remote_calls(Keys) == [
             {:crypto, :hash, 2},
             {:erlang, :byte_size, 1},
             {:erlang, :get_module_info, 2},
             {:erlang, :is_binary, 1},
             {:erlang, :is_function, 2}
           ]
  end

  # The hash envelope signs nothing itself either: its `:crypto` calls hash the stream and ask
  # whether ML-DSA-87 is offered, and the signature is MLDSA87's. Held to what it may reach rather
  # than to an exact list, since the regex and map syntax compile to different helper calls
  # across the Elixir lines CI runs.
  test "BeamMCP.Signer.COSE.HashEnvelope: hashing, the encoder, the key helpers and MLDSA87.sign/2, no I/O" do
    calls = remote_calls(HashEnvelope)

    assert for({:crypto, f, a} <- calls, do: {f, a}) == [
             hash_final: 1,
             hash_init: 1,
             hash_update: 2,
             supports: 1
           ]

    assert {MLDSA87, :sign, 2} in calls
    assert {CBOR, :encode, 1} in calls

    assert for({BeamMCP.Signer.COSE.Keys, f, a} <- calls, do: {f, a}) == [
             fetch: 3,
             kid: 1,
             read: 2
           ]

    refute Enum.any?(calls, fn {m, _, _} -> m in [Ed25519, COSE] end)

    refute Enum.any?(calls, fn {m, _, _} ->
             m in [
               System,
               File,
               Application,
               Path,
               Process,
               Code,
               :os,
               :file,
               :ets,
               :persistent_term
             ]
           end)
  end

  test "BeamMCP.Signer.COSE.CBOR: pure encoding, no :crypto, no I/O" do
    calls = remote_calls(CBOR)

    assert Enum.map(calls, &elem(&1, 0)) |> Enum.uniq() |> Enum.sort() == [
             Enum,
             String,
             :erlang,
             :unicode
           ]

    assert {:unicode, :characters_to_nfc_binary, 1} in calls
    assert {String, :valid?, 1} in calls
  end

  test "Ed25519: the private key is 32 bytes, given directly or by a zero-arity reference, and the seed length is a module constant" do
    src = source(Ed25519)
    assert src =~ "@private_key_bytes 32"
    assert src =~ "byte_size(key) == @private_key_bytes"
    assert src =~ ~r/resolve\(key\) when is_function\(key, 0\) do\s+\{:ok, key\.\(\)\}/
    refute src =~ ~r/private_key:\s*<</, "a literal key under lib/"
  end

  test "MLDSA87: a 32-byte seed and a 2,592-byte public key, each given directly or by a zero-arity reference" do
    src = source(MLDSA87)
    assert src =~ "@private_key_bytes 32"
    assert src =~ "@public_key_bytes 2592"
    assert src =~ "read(seed, :private_key, @private_key_bytes, :not_32_bytes)"
    assert src =~ "read(public, :public_key, @public_key_bytes, :not_2592_bytes)"
    assert src =~ ~r/resolve\(key\) when is_function\(key, 0\) do\s+\{:ok, key\.\(\)\}/
    refute src =~ ~r/(private|public)_key:\s*<</, "a literal key under lib/"
    assert src =~ "{:seed, seed}", "signs from the seed, never from a stored expanded key"
  end

  defp remote_calls(module) do
    module
    |> forms()
    |> collect_remote_calls()
    |> Enum.reject(fn {m, _f, _a} -> m == module end)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp source(module), do: File.read!(Enum.find(@lib, &(Path.basename(&1) == @source[module])))

  defp forms(module) do
    {:ok, {^module, [abstract_code: {:raw_abstract_v1, forms}]}} =
      :beam_lib.chunks(:code.which(module), [:abstract_code])

    forms
  end

  defp collect_crypto_args(forms) do
    walk = fn
      {:call, _, {:remote, _, {:atom, _, :crypto}, {:atom, _, _}}, args}, acc, rec ->
        Enum.reduce(args, [args | acc], fn a, acc -> rec.(a, acc, rec) end)

      t, acc, rec when is_tuple(t) ->
        Enum.reduce(Tuple.to_list(t), acc, fn a, acc -> rec.(a, acc, rec) end)

      l, acc, rec when is_list(l) ->
        Enum.reduce(l, acc, fn a, acc -> rec.(a, acc, rec) end)

      _, acc, _ ->
        acc
    end

    walk.(forms, [], walk)
  end

  defp collect_remote_calls(forms) do
    walk = fn
      {:call, _, {:remote, _, {:atom, _, m}, {:atom, _, f}}, args}, acc, rec ->
        Enum.reduce(args, [{m, f, length(args)} | acc], fn a, acc -> rec.(a, acc, rec) end)

      t, acc, rec when is_tuple(t) ->
        Enum.reduce(Tuple.to_list(t), acc, fn a, acc -> rec.(a, acc, rec) end)

      l, acc, rec when is_list(l) ->
        Enum.reduce(l, acc, fn a, acc -> rec.(a, acc, rec) end)

      _, acc, _ ->
        acc
    end

    walk.(forms, [], walk)
  end
end
