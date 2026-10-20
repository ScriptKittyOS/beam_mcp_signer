#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0
#
# Writes the ML-DSA-87 test vectors under test/fixtures/mldsa87/ from their published sources,
# each fetched at a pinned commit and refused unless its sha256 is the one recorded here. The
# sources hold every parameter set; only ML-DSA-87 is kept, so the fixtures stay small and a
# rerun writes the same bytes. Run by hand when a pin moves; the suite reads only the output.
#
#   ACVP-Server (NIST; NIST-Software):  ML-DSA-keyGen-FIPS204, tgId 3 tcId 51
#                                       ML-DSA-sigVer-FIPS204, every ML-DSA-87 group
#   Wycheproof (C2SP; Apache-2.0):      testvectors_v1/mldsa_87_verify_test.json, whole
set -euo pipefail
root=$(git rev-parse --show-toplevel)
out="$root/test/fixtures/mldsa87"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

acvp=975de31eb83d87039ec88934fdc47d8c312b892d
wycheproof=7a325932231bd7a724c791c8b0d65ea4d6d2f435

fetch() { # url, file, sha256
  curl -sSfo "$work/$2" "$1"
  echo "$3  $work/$2" | sha256sum -c --quiet - || { echo "$2: sha256 differs from the pin; refused"; exit 1; }
}

fetch "https://raw.githubusercontent.com/usnistgov/ACVP-Server/$acvp/gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json" \
  keygen.json e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf
fetch "https://raw.githubusercontent.com/usnistgov/ACVP-Server/$acvp/gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json" \
  sigver.json 47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437
fetch "https://raw.githubusercontent.com/C2SP/wycheproof/$wycheproof/testvectors_v1/mldsa_87_verify_test.json" \
  wycheproof.json 54adffe10f6dad7941ffd97f77ad4e5c85cb3a54d44cf5ce1c95cb1757b9ba14

mkdir -p "$out"
jq -c --arg src "usnistgov/ACVP-Server@$acvp gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json" \
  '{source: $src, filtered: "tgId 3 (ML-DSA-87), tcId 51",
    test: (.testGroups[] | select(.tgId == 3 and .parameterSet == "ML-DSA-87") | .tests[] | select(.tcId == 51))}' \
  "$work/keygen.json" > "$out/acvp_keygen.json"
jq -c --arg src "usnistgov/ACVP-Server@$acvp gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json" \
  '{source: $src, filtered: "the ML-DSA-87 groups", testGroups: [.testGroups[] | select(.parameterSet == "ML-DSA-87")]}' \
  "$work/sigver.json" > "$out/acvp_sigver.json"
jq -c --arg src "C2SP/wycheproof@$wycheproof testvectors_v1/mldsa_87_verify_test.json" \
  '{source: $src, filtered: "none (compacted)"} + .' "$work/wycheproof.json" > "$out/wycheproof_verify.json"

for f in "$out"/*.json; do echo "$(sha256sum "$f" | cut -c1-64)  ${f#"$root"/}"; done
