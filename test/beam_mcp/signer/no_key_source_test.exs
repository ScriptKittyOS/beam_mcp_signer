# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.NoKeySourceTest do
  # The census: the key comes through `opts[:private_key]` and from nowhere else. Two layers,
  # the text under lib/ and the compiled beam's calls, so a spelling the regex misses is still
  # a call the beam shows.
  use ExUnit.Case, async: true

  @lib Path.wildcard(Path.expand("../../../lib/**/*.ex", __DIR__))

  @key_source ~r/System\.(get_env|fetch_env!?|cmd)|:os\.(getenv|cmd)|Application\.(get_env|fetch_env!?|get_all_env)|File\.|Path\.expand|~\/|\.ssh|HEX_API_KEY|_KEY"|:persistent_term|:ets\.|Process\.(get|put)|Code\.eval|:init\.get_argument/

  # What lib/ may call, per remote module: the beam's whole truth, held to a list.
  @allowed_calls %{
    :crypto => [sign: 4],
    Keyword => [fetch: 2],
    :erlang => [
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
  }

  test "the package is one module, and no line under lib/ names an environment, file, config or store read" do
    assert length(@lib) == 1

    for path <- @lib,
        {line, n} <- File.read!(path) |> String.split("\n") |> Enum.with_index(1),
        not String.match?(line, ~r/^\s*#/),
        Regex.match?(@key_source, line) do
      flunk("#{Path.relative_to_cwd(path)}:#{n}: #{String.trim(line)}")
    end
  end

  test "the compiled module calls :crypto.sign/4 and Keyword.fetch/2 and nothing else outside itself" do
    {:ok, {BeamMCP.Signer.Ed25519, [abstract_code: {:raw_abstract_v1, forms}]}} =
      :beam_lib.chunks(:code.which(BeamMCP.Signer.Ed25519), [:abstract_code])

    calls =
      forms
      |> collect_remote_calls()
      |> Enum.reject(fn {m, _f, _a} -> m == BeamMCP.Signer.Ed25519 end)
      |> Enum.uniq()
      |> Enum.sort()

    unexpected =
      Enum.reject(calls, fn {m, f, a} ->
        allowed = Map.get(@allowed_calls, m, [])
        if m == :erlang, do: f in allowed, else: {f, a} in allowed
      end)

    assert unexpected == [], "calls outside the list: #{inspect(unexpected)}"
    assert {:crypto, :sign, 4} in calls

    refute Enum.any?(calls, fn {m, _, _} ->
             m in [System, File, Application, Path, :os, :file, :ets, :persistent_term]
           end)
  end

  test "the private key is 32 bytes, given directly or by a zero-arity reference, and the seed length is a module constant" do
    src = File.read!(hd(@lib))
    assert src =~ "@private_key_bytes 32"
    assert src =~ "byte_size(key) == @private_key_bytes"
    assert src =~ "is_function(key, 0), do: key.()"
    refute src =~ ~r/private_key:\s*<</, "a literal key under lib/"
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
