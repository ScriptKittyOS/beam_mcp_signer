<!--
SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
SPDX-License-Identifier: Apache-2.0
-->

# Verifying a release

## The tag's signature

Every release tag (`v0.1.0` on) is an annotated tag signed with the maintainer's OpenPGP key,
the same key that signs `beam_mcp`'s tags. It is published on the maintainer's GitHub account,
and its fingerprint is:

```text
24FE 4F05 E3E8 EC26 1462  A0C7 82A6 7035 D628 7F15
```

```sh
curl -fsSL https://github.com/HackTuah.gpg | gpg --import
gpg --fingerprint 24FE4F05E3E8EC261462A0C782A67035D6287F15   # compare with the line above
git clone https://github.com/ScriptKittyOS/beam_mcp_signer && cd beam_mcp_signer
git tag -v v0.2.0                                             # "Good signature" or it did not verify
```

The private key is held on the maintainer's own machine, not on GitHub or hex.pm. If it is
ever replaced, this page and the CHANGELOG say so in the same commit, with the new
fingerprint.

## The package bytes

hex.pm serves the package over HTTPS, and `mix` checks each download against the checksum in
`mix.lock`. To rebuild the tarball from a tag and compare:

```sh
tools/release_tarball.sh "v${v}" "beam_mcp_signer-${v}.tar"   # prints the tarball's sha256
```

The script builds from `git archive` of the tag (tracked files only, every file mode 644) so
two machines produce the same bytes. A release published with the script (`--publish`) has
the checksum hex.pm shows; `0.1.0` and `0.1.1` were built from a working tree before the
script existed, and are verified by their signed tags only.
