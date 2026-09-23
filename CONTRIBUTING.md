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

## Code review

**How it is done.** Every change reaches `main` through a pull request, the maintainer's
included, rebased after CI is green on all three OTP/Elixir pairs. The reviewer reads the diff,
the commit messages and the CI results, and runs the suite locally for any change under `lib/`.

**What must be checked.**
- The change does what its message says, and nothing else.
- New or changed behaviour has tests; a fix has a test that was seen failing first.
- **The key:** it is read from `opts[:private_key]` and nowhere else; no result, error term or
  raise carries it; nothing is kept after the call. The key-source census
  (`test/beam_mcp/signer/no_key_source_test.exs`) still passes for the right reason, and a
  change to how the key is handled is shown red against a planted break.
- `SECURITY.md`, `docs/assurance-case.md` and the README change with the behaviour they describe.
- Sign-off on every commit, no attribution trailers, no key or secret in the diff.

**What is acceptable.** All of the above hold, CI is green, and the reviewer can say why the
change is correct; otherwise it is sent back with the reason. **Who reviews:** the maintainer
reviews every pull request; the continuity holders in `GOVERNANCE.md` may review as well. A
review by a person other than the author on at least half of all changes is the project's aim;
the pull requests show who reviewed each one.

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
