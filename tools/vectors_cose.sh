#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0
#
# Writes test/fixtures/cose/rfc9964_a2_ml_dsa_87.json from RFC 9964 itself: Appendix A.2,
# Figure 8 (ML_DSA_87), fetched from rfc-editor.org and refused unless its sha256 is the one
# recorded here. The figure's hex strings wrap across lines and page breaks; this joins them
# and keeps the fields the suite reads (the `_diag` renderings are dropped). Run by hand; the
# suite reads only the output.
#
#   RFC 9964 (IETF Trust; code components under the Revised BSD License, TLP section 4.e)
set -euo pipefail
root=$(git rev-parse --show-toplevel)
out="$root/test/fixtures/cose"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl -sSfo "$work/rfc9964.txt" https://www.rfc-editor.org/rfc/rfc9964.txt
echo "8c42035b948301b197d431de8b3f40019bdaa3bb40150dc523306923948f34cf  $work/rfc9964.txt" |
  sha256sum -c --quiet - || { echo "rfc9964.txt: sha256 differs from the pin; refused"; exit 1; }

# Figure 8 is the last JSON object before its caption: from the "{" that opens it to the "}"
# that closes it, page headers, footers and form feeds removed, continuation lines joined.
awk '/^A\.2\.  COSE$/ {a2 = 1} a2' "$work/rfc9964.txt" | tr -d '\f' |
  grep -v '^RFC 9964 \|^Prorock & Steele\|^ *$' |
  awk '/Figure 7: ML_DSA_65/ {f8 = 1; next} f8 && /^\{/ {on = 1}
       on { if ($0 ~ /^  "/ || $0 ~ /^[{}]/) printf "\n%s", $0; else { gsub(/^ +/, ""); printf "%s", $0 } }
       on && /^\}/ {exit}' > "$work/figure8.json"

mkdir -p "$out"
jq -c '{source: "RFC 9964 Appendix A.2, Figure 8 (ML_DSA_87); rfc-editor.org/rfc/rfc9964.txt, sha256 8c42035b948301b197d431de8b3f40019bdaa3bb40150dc523306923948f34cf",
        priv, key, raw_public_key, raw_to_be_signed, raw_signature, sign1}' \
  "$work/figure8.json" > "$out/rfc9964_a2_ml_dsa_87.json"
jq -r '"public key \(.raw_public_key | length / 2) bytes, signature \(.raw_signature | length / 2) bytes, ToBeSigned \(.raw_to_be_signed | length / 2) bytes"' \
  "$out/rfc9964_a2_ml_dsa_87.json"
