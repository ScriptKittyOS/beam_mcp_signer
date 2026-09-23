#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0
#
# The release tarball, built the one way that gives the same bytes on every machine.
#
#     tools/release_tarball.sh <ref> <out.tar>             build; print the checksum
#     tools/release_tarball.sh <ref> <out.tar> --publish   the same, then `mix hex.publish` FROM
#                                                          THAT TREE, so what is published is
#                                                          what was built and attested
#
# WHY A SCRIPT. `mix hex.build` packages the working tree as it lies: each entry carries the
# file's on-disk mode (umask 002 gives 664, umask 022 gives 644 -- two checksums for one commit),
# and a directory named in `files:` is walked in readdir order (fixed by globs in mix.exs). So
# the bytes are made canonical by construction: the tree is `git archive`'d at the ref with
# `tar.umask=022` (every regular file 644, and only tracked files), extracted, the lock's
# dependencies resolved, and built there. The publisher runs it with --publish; anyone runs it
# to reproduce a release's checksum. The same script as beam_mcp's tools/release_tarball.sh,
# where the measurements behind it are recorded (docs/provenance.md there).
#
# What it does not do: pin Hex. Needs bash, git, and sha256sum or shasum.
set -euo pipefail
ref=${1:?ref (a tag or commit)}; out=${2:?output tarball path}; publish=${3:-}
[ -z "$publish" ] || [ "$publish" = "--publish" ] || { echo "third argument is --publish or nothing" >&2; exit 2; }
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
root=$(git rev-parse --show-toplevel)
work=$(mktemp -d "${TMPDIR:-/tmp}/beam_mcp_signer-release.XXXXXX"); trap 'rm -rf "$work"' EXIT
git -C "$root" -c tar.umask=022 archive --format=tar "$ref" | tar -xp -C "$work"
cd "$work"
mix deps.get >/dev/null
mix hex.build -o "$out" | tee "$work/build.out"
sha=$(sha256 "$out")
grep -q "Package checksum: ${sha}" "$work/build.out" \
  || { echo "the tarball's sha256 ${sha} is not the checksum hex printed" >&2; exit 1; }
echo "release tarball ${out}: sha256 ${sha} (= hex's package checksum) from ${ref} = $(git -C "$root" rev-parse "${ref}^{commit}")"
if [ "$publish" = "--publish" ]; then
  mix hex.publish
fi
