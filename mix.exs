# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.Ed25519.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/ScriptKittyOS/beam_mcp_signer"

  # The same floor as beam_mcp: the behaviour this package implements lives there, and one
  # OTP line for both is one fewer thing for a host to reason about. Ed25519 in `:crypto` is
  # far older than 27; the floor is core's, not this package's.
  @otp_floor 27

  def project do
    [
      app: :beam_mcp_signer,
      version: @version,
      elixir: "~> 1.17",
      elixirc_options: [warnings_as_errors: true],
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      description:
        "Ed25519 signer for beam_mcp's canonical connectome bytes, through OTP's :crypto; the host hands the key in",
      source_url: @source_url,
      docs: [main: "readme", extras: ["README.md", "CHANGELOG.md"]],
      aliases: [check_otp: &check_otp!/1]
    ]
  end

  def application, do: [extra_applications: [:crypto]]

  defp deps do
    [
      # The behaviour, `BeamMCP.Signer`, is public in beam_mcp from 0.7.0. Three numbers, as
      # core's README asks: while core is 0.x a documented break may land at the next minor,
      # and a two-number requirement would carry this package across it. Nothing else: Ed25519
      # is OTP's.
      {:beam_mcp, "~> 0.7.0"},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      name: "beam_mcp_signer",
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url, "beam_mcp" => "https://github.com/ScriptKittyOS/beam_mcp"},
      files: ~w(lib mix.exs README.md CHANGELOG.md LICENSE NOTICE)
    ]
  end

  def otp_floor, do: @otp_floor

  def check_otp!(_args \\ []) do
    {major, _} = :erlang.system_info(:otp_release) |> to_string() |> Integer.parse()

    if major < @otp_floor do
      Mix.raise(
        "beam_mcp_signer requires Erlang/OTP #{@otp_floor} or newer (beam_mcp's floor); found OTP #{major}."
      )
    end

    :ok
  end
end
