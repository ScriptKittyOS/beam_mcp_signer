# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

defmodule BeamMCP.Signer.Ed25519.MixProject do
  use Mix.Project

  @version "0.1.1"
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
      docs: [
        main: "readme",
        extras: [
          "README.md",
          "CHANGELOG.md",
          "SECURITY.md",
          "docs/architecture.md",
          "docs/assurance-case.md",
          "docs/roadmap.md",
          "docs/verifying-releases.md"
        ]
      ],
      aliases: [check_otp: &check_otp!/1]
    ]
  end

  def application, do: [extra_applications: [:crypto]]

  defp deps do
    [
      # The behaviour, `BeamMCP.Signer`, is public in beam_mcp from 0.7.0 and frozen from
      # there: core's own rule says its public surface does not move again before 1.0.0, and
      # this package touches nothing but that behaviour and `Canonical.signature/3`'s bytes.
      # So two numbers here, on purpose: the requirement spans core's 0.7, 0.8 and any 0.9,
      # stops at 1.0.0, and a host is not held on the previous core minor by this package
      # (0.1.0's `~> 0.7.0` did exactly that at core's 0.8.0). Nothing else: Ed25519 is OTP's.
      {:beam_mcp, "~> 0.7"},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      name: "beam_mcp_signer",
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url, "beam_mcp" => "https://github.com/ScriptKittyOS/beam_mcp"},
      # Globs, not a directory: a directory in `files:` is walked in readdir order, which differs
      # between filesystems, so the tarball would be the machine's (tools/release_tarball.sh).
      files: ~w(lib/**/*.ex mix.exs README.md CHANGELOG.md LICENSE NOTICE)
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
