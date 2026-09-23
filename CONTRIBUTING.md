<!--
SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
SPDX-License-Identifier: Apache-2.0
-->

# Contributing

Issues and pull requests are welcome on
[GitHub](https://github.com/ScriptKittyOS/beam_mcp_signer). A pull request is the only way a
change reaches `main`; it is rebased, never merged, so the history stays linear. The
maintainer reviews and decides (`GOVERNANCE.md`).

## Getting set up

```sh
git clone https://github.com/ScriptKittyOS/beam_mcp_signer && cd beam_mcp_signer
asdf install            # the Erlang/OTP and Elixir versions .tool-versions pins (any manager that reads it works)
mix deps.get
mix test
```

Erlang/OTP 27 or newer and Elixir 1.17 or newer, the same floor as `beam_mcp`. CI runs
`mix format --check-formatted`, `mix compile --warnings-as-errors`, `mix credo --strict`,
`mix hex.audit` and `mix test` on three OTP/Elixir pairs; run the same before you push.

## The rules, all enforced

1. **Sign off every commit.** `git commit -s` adds the `Signed-off-by` line, certifying the
   [Developer Certificate of Origin](https://developercertificate.org/): you wrote the change or
   have the right to submit it under this project's licence. CI fails a pull request with a
   commit that lacks it.
2. **No tool-attribution trailers.** A commit message says what changed and why it is believed
   correct.
3. **CI must be green.** Warnings are errors; there is no baseline to hold.
4. **Tests arrive with behaviour.** Every change that adds or changes behaviour adds tests for
   it to the automated suite, in the same pull request. A bug fix carries a regression test
   that was seen failing before the fix, and the commit message shows the failure. A change to
   how the key is read or returned also keeps the key-source census
   (`test/beam_mcp/signer/no_key_source_test.exs`) red when the rule is broken: plant the
   break, show it red, restore it.

## Coding style

The Elixir community's: the output of `mix format` (this repository's `.formatter.exs`) and
[Credo](https://hexdocs.pm/credo/) in `--strict` mode, which implement the
[Elixir Style Guide](https://github.com/christopheradams/elixir_style_guide), plus the security
warnings `.credo.exs` enables. CI enforces both. `beam_mcp`'s
[`CONVENTIONS.md`](https://github.com/ScriptKittyOS/beam_mcp/blob/main/CONVENTIONS.md) records
the wider rules both packages are developed under.

## Conduct

Participation is under the [Code of Conduct](CODE_OF_CONDUCT.md) (the Contributor Covenant,
version 2.1).

## Reporting a vulnerability

Not in an issue. See `SECURITY.md`.
