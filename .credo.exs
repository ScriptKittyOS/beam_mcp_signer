# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0
#
# Credo's defaults, plus the two security-relevant warnings its defaults leave off, on the code
# that ships (lib/), as in beam_mcp: UnsafeToAtom (atoms from input exhaust the atom table) and
# LeakyEnvironment (a spawned command inheriting the environment, secrets included).
%{
  configs: [
    %{
      name: "default",
      checks: %{
        extra: [
          {Credo.Check.Warning.UnsafeToAtom, [files: %{included: ["lib/"]}]},
          {Credo.Check.Warning.LeakyEnvironment, [files: %{included: ["lib/"]}]}
        ]
      }
    }
  ]
}
