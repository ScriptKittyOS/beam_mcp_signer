# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0

# ML-DSA-87 needs an OTP whose `:crypto` is linked to OpenSSL 3.5 or later. Where it is offered,
# the tests tagged `:mldsa87` run and the ones tagged `:no_mldsa87` (the refusal a runtime
# without it answers) do not; elsewhere the other way round. With MLDSA_REQUIRED=1 (CI's box
# leg) a runtime without it is refused here, so that leg cannot pass by excluding the tests.
mldsa87? = :mldsa87 in :crypto.supports(:public_keys)

if System.get_env("MLDSA_REQUIRED") == "1" and not mldsa87? do
  raise "MLDSA_REQUIRED=1 and this runtime's :crypto does not offer mldsa87: refused"
end

# The 10 GiB test (cose_hash_envelope_ten_gb_test.exs) runs only when asked for: `--only ten_gb`.
ExUnit.start(exclude: [:ten_gb | if(mldsa87?, do: [:no_mldsa87], else: [:mldsa87])])

Code.require_file("support/ucd.exs", __DIR__)
BeamMCP.Signer.Test.UCD.load()
Code.require_file("support/strict_cbor.exs", __DIR__)
Code.require_file("support/hash_envelope_verifier.exs", __DIR__)
