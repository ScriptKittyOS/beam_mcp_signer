#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0
#
# The Unicode 15.0.0 tables the N6 text rule needs (profile v0.1 §2.4): fetches the three data
# files from unicode.org, refuses each unless its sha256 is the one recorded here, keeps them in
# test/fixtures/unicode/ (the suite's own parser reads them there, independently of the
# generator), and writes lib/beam_mcp/signer/cose/unicode.ex from them
# (tools/unicode_tables.exs). Run by hand; the suite reads only the outputs. The pinned version
# is the profile's: raising it is a profile change, not a refresh.
#
#   Unicode 15.0.0 data files (Unicode, Inc.; Unicode License v3)
set -euo pipefail
root=$(git rev-parse --show-toplevel)
out="$root/test/fixtures/unicode"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

base=https://www.unicode.org/Public/15.0.0/ucd
while read -r sum path; do
  name=$(basename "$path")
  curl -sSfo "$work/$name" "$base/$path"
  echo "$sum  $work/$name" | sha256sum -c --quiet - || { echo "$name: sha256 differs from the pin; refused"; exit 1; }
done <<'PINS'
fe29a45c0882500e591140aaa5c4f5067e6a5d746806148af34400c48b9c06f9 extracted/DerivedGeneralCategory.txt
ca54f6360cd288ad92113415bf1f77749015abe11cbd6798d21f7fa81f04205d extracted/DerivedCombiningClass.txt
d5687a48c95c7d6e1ec59cb29c0f2e8b052018eb069a4371b7368d0561e12a29 DerivedNormalizationProps.txt
PINS

mkdir -p "$out"
cp "$work"/*.txt "$out/"
elixir "$root/tools/unicode_tables.exs" "$out" "$root/lib/beam_mcp/signer/cose/unicode.ex"
