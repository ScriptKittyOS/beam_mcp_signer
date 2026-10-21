<!--
SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

## [Unreleased]

## [0.3.0] - 2026-10-21

Three modules added, ML-DSA-87 among them; nothing an `0.2` host calls changes. `Ed25519` and
core's `BeamMCP.Signer` behaviour are as they were, so moving is the requirement alone:
`{:beam_mcp_signer, "~> 0.3"}`. Core requirement unchanged (`~> 0.7`). ML-DSA-87 needs an OTP
whose `:crypto` is linked to OpenSSL 3.5 or later; elsewhere its modules answer
`{:error, :crypto_refused}` and `Ed25519` is unaffected.

- **Provisional formats.** `BeamMCP.Signer.COSE` and `BeamMCP.Signer.COSE.HashEnvelope` write the
  shared N6 profile (v0.1, a draft). Its schema numbers and `typ` values are provisional, and a
  change to them comes in a new version of this package.
- **Non-claimed.** The hash envelope is not a claimed path under CNSA 2.0 (see its entry).
- **Pre-release review.** Two independent lanes read every module added since 0.2.1, one on key
  handling and error surfaces, one on encoding and cryptographic correctness. They are recorded
  here; they are not a review under `docs/security-review.md`, which a person does. Fixed in this
  release:
  - A key function that returned a function was resolved twice. COSE then computed the kid from
    the placeholder and returned a carrier with a 48-byte zero kid. Every key read now requires
    the key's bytes at their size (`{:public_key, :not_2592_bytes}`), so the kid is always the
    signing key's thumbprint.
  - Text followed the runtime's NFC normaliser, not N6's text rule. The rule is now Unicode
    15.0.0 tables embedded in the package, from `tools/unicode_tables.sh`. Format and
    bidirectional controls, unassigned code points and NFC quick-check MAYBE are refused, and no
    normaliser is called. An issuer such as `"a\u202Eb"` was signed and is now
    `{:issuer, :invalid}`. Text is at most 65,536 bytes, and so is a byte-string issuer.
  - The issuer is judged before either key function is called. A `:crypto` refusal while
    hashing the kid or the canonical bytes is answered `:crypto_refused`, not raised with the
    public key in the frame.
  - An improper list given to the encoder is refused, not raised on.
  - `sign_stream/2` refuses a function that is not an enumerable (`:bad_arguments`).
  - Documented: `sign_digest/2` cannot know its 48 bytes are a digest; one key per scheme;
    "the seed is not held through the stream" holds only for a key function that fetches the
    seed when it is called.
  - Tests: the census bars the process dictionary, ports and `binary_to_term` in every module.
    The 10 GiB test also bounds the VM's peak RSS (VmHWM, reset before the stream), with no
    sampling gap.

### Added: `BeamMCP.Signer.COSE.HashEnvelope`, large artifacts signed by their digest (non-claimed)

- A new public module, outside core's `BeamMCP.Signer` behaviour, which is unchanged; `COSE`
  still exports only `sign/2`. `sign_stream/2` hashes any enumerable of binaries with
  `:crypto.hash_init/update/final`, so memory is one chunk whatever the size.
  `sign_digest/2` takes a digest the host already has.
- **Output:** the N6 single-signer carrier, with the digest as its payload, signed as an RFC 9995
  COSE Hash Envelope under ML-DSA-87. The protected header is `{1: -50, 2: [258], 4: kid,
  16: typ, 258: -43 | -44, 259: preimage type, ? 260: location}`; label 3 is never written.
- **Why:** a raw signature over a digest leaves the hash algorithm unsigned and the digest
  indistinguishable from content. Here both are in the signed bytes, and `crit` makes a verifier
  that does not know hash envelopes refuse.
- **Options:** the two keys, read as `MLDSA87` reads them (the seed function is called after
  the last chunk); `:typ` and `:preimage_type` (required); `:location` (optional);
  `:payload_hash` (`:sha384`, the default, or `:sha512`). Every option is judged before the
  first chunk is read. New errors: `:no_typ`, `{:typ, :invalid | :full_payload}`,
  `:no_preimage_type`, `{:preimage_type, :invalid}`, `{:location, :invalid}`,
  `{:payload_hash, :invalid}`, `{:digest, :wrong_length}`, `{:stream, :not_binary |
  :unreadable}`.
- **Non-claimed:** the signature is pure ML-DSA-87, not HashML-DSA, but no NSA, NIST or IETF text
  yet names the construction, so it is not a claimed path.
- **Tests:** a 10 GiB file (sparse), signed on CI's box leg (`mix test --only ten_gb`), with the
  VM's memory growth held under 64 MiB and the digest held to `sha384sum`'s; a test-side
  verifier that holds only the envelope and the public key. CI's Go and Rust cross-verify jobs
  read the box leg's envelope. coset 0.4.2 refuses it over `crit` [258] (it predates RFC 9995),
  and the Rust check asserts that refusal, then verifies with coset's ToBeSigned.
- `BeamMCP.Signer.COSE`: the option walk, the key read and the kid moved to a private
  `BeamMCP.Signer.COSE.Keys`, shared with the hash envelope; its answers do not change.

### Added: `BeamMCP.Signer.COSE`, ML-DSA-87 in COSE with the algorithm and key signed

- A third module implementing core's `BeamMCP.Signer` behaviour, unchanged. It returns
  deterministic CBOR, the N6 single-signer carrier: an untagged, detached COSE_Sign1 (RFC 9052,
  RFC 9964 algorithm -50) whose protected header is `{1: -50, 4: kid, 16: typ}`, over a
  statement that names the canonical bytes by SHA-384 and length, with the host's issuer. The
  `kid` is the key's SHA-384 COSE Key Thumbprint (RFC 9679), computed from the public key.
- **Why:** `Canonical.signature/3` places `scheme:` and `key_id:` beside a raw signature,
  unsigned; swapping either leaves the signature valid. Here both are inside the signed bytes.
- **Options:** `BeamMCP.Signer.MLDSA87`'s two keys, read the same way, and `:issuer`
  (required; text under N6's text rule or `{:bytes, binary}`, each at most 65,536 bytes). New
  errors: `:no_issuer`, `{:issuer, :invalid}`;
  every other answer is `MLDSA87`'s, which makes and checks the signature.
- **Provisional:** the statement's schema number (0x85000101) and `typ`
  (`application/vnd.example.b85.connectome.v0+cose`) are provisional, as is the N6 profile
  (v0.1, a draft); they change when the shared registry assigns them.
- **Encoder:** the package's own (private), deterministic CBOR under N6's rules, refusing
  floats, tags, other simple values, non-integer keys and non-NFC text by name. Held to RFC 8949
  Appendix A and RFC 9964 Appendix A.2 byte for byte (`tools/vectors_cose.sh` writes the A.2
  fixture from the RFC); a strict reader in the tests checks every encoding without it.
- **Other implementations:** CI's cross-verify job also reads the box leg's carrier with Go
  (fxamacker/cbor, `crypto/mldsa`) and Rust (coset, ciborium, aws-lc-rs), each building
  ToBeSigned itself; each refuses the signature with the algorithm, key or `typ` changed.
- `mldsa87_test.exs`: a key-reference test's `send(...) && key` became two expressions, which
  Elixir 1.20's type checker no longer warns about.

### Added: `BeamMCP.Signer.MLDSA87`, an ML-DSA-87 signer

- A second module implementing core's `BeamMCP.Signer` behaviour, unchanged: ML-DSA-87
  (FIPS 204), pure, external interface, empty context, the form RFC 9964 requires for COSE.
  `Ed25519` is untouched.
- **Two keys on every call:** the 32-byte seed under `:private_key` and its 2,592-byte public
  key under `:public_key`, each as bytes or a zero-arity function. The public key is required
  because `:crypto` cannot derive one from a seed.
- **Every signature is checked before it is returned:** it must verify under the given public
  key (`{:error, {:public_key, :does_not_verify}}` otherwise, so a seed and public key that
  are not a pair produce no signature) and must not verify over bytes one bit away
  (`{:error, :self_check_failed}` otherwise).
- **Hedged signing:** two signatures of the same bytes differ.
- **Where it runs:** OTP 28.1 or later with `:crypto` linked to OpenSSL 3.5 or later. Elsewhere,
  OTP 27 included, every call answers `{:error, :crypto_refused}`; the package's floor stays
  OTP 27 for Ed25519.
- **Tests:** the ML-DSA-87 tests run on CI's box leg, which fails if `:crypto` lacks the
  algorithm. The suite holds the runtime to NIST ACVP and Wycheproof ML-DSA-87 vectors, every
  case `:crypto` can express, and counts the rest by reason (`tools/vectors_mldsa87.sh` writes
  the fixtures at pinned commits). A new CI job verifies the box leg's signature with Go's
  `crypto/mldsa` and aws-lc-rs (`tools/cross_verify/`); it is the seventh required check.
- **Docs:** the README, `SECURITY.md`, the assurance case, the architecture page, the security
  review checklist and the roadmap describe both modules.

### Changed: a test of Ed25519's "nothing kept" claim

- `ed25519_test.exs` looked for an ETS table named like "signer" or "key" after a call; with
  more test files compiling, ExUnit's per-module tables (named after the test modules) matched.
  It now compares the tables before and after the call and refuses any new one owned by the
  calling process, which is what a table made by the call would be.

### Added: build provenance for each release

- `.github/workflows/provenance.yml`: on a release tag, CI builds the tarball with
  `tools/release_tarball.sh`, attests its digest (SLSA build provenance), and verifies the
  attestation against what hex.pm serves. A manual run takes a published tag, so `0.2.1` is
  attested after its release. `docs/verifying-releases.md` gives the command.

### Changed: `main` is protected by a ruleset (no code change)

- `GOVERNANCE.md`: how a change lands is now enforced on `main` (pull requests only, rebase
  merges, linear history, the five checks required, no bypass), where it had been practice.

## [0.2.1] - 2026-09-26

A security fix: two more ways the private key could reach an exception report are closed.
Upgrade by taking the patch; the requirement `~> 0.2.0` already admits it. Core requirement
unchanged (`~> 0.7`).

### Fixed: the key no longer reaches an exception report from two option shapes

- `sign/2` read the key with `Keyword.fetch/2`, which raised with the key in view on two
  shapes: an improper list (an `ArgumentError` from `:lists.keyfind/3`, the list in its frame)
  and an entry `{:private_key, key, extra}` (a `CaseClauseError` carrying the entry). The
  options are now walked by this module: an entry that is not a `{:private_key, _}` pair is
  skipped, and an improper list whose end is reached before a `:private_key` entry is answered
  `{:error, :bad_arguments}`. The first `{:private_key, key}` entry is read, as before, so a
  key found before an improper tail still signs (0.2.0's `:lists.keyfind/3` also returned
  before reaching the tail). Found by
  the project's own security review. **How to tell whether you are affected:** only a host
  that built its options in one of those shapes, and passed the key as bytes rather than by
  reference, could have printed it.

### Fixed: a key function that raises, throws or exits is answered

- A key passed by reference is read by the host's own function, and its failure could print
  the key (a seed file read with a trailing newline and matched as 32 bytes raises a
  `MatchError` over all 33). It is now answered `{:error, {:private_key, :unreadable}}`, a new
  error term, and what the function raised, threw or exited with is dropped unread, an
  `exit/1` the function means on purpose included. **How to
  tell whether you are affected:** a host whose key function can fail sees the new term in
  place of its own exception, and logs inside the function if it needs the reason.

### Fixed: a refusal from `:crypto` is answered, never re-raised

- `:crypto.sign/4` raises when it will not sign Ed25519 (a build or FIPS provider without it,
  or no `:crypto` loaded, whose `:undef` carries the call's arguments, the key among them). It
  is now answered `{:error, :crypto_refused}`, a new error term; the reason is dropped unread.

### Changed: the bus factor is two (no code change)

- `GOVERNANCE.md`: `znmead` knows the code (the maintainer's word, 2026-09-23) and reviews pull
  requests from that date, so the bus factor is two.

## [0.2.0] - 2026-09-23

A security fix and an addition, placed at the minor (0.x): the private key no longer reaches an
exception report. Upgrade from `0.1.x` by changing the requirement to `~> 0.2.0`; pass the key as
`private_key: fn -> key end`. Core requirement unchanged (`~> 0.7`, which admits `beam_mcp`
0.7 to 0.10).

### Changed: a mistyped call is answered, never raised

- A mistyped call to `sign/2` (bytes that are not a binary, options that are not a list) is
  answered `{:error, :bad_arguments}` instead of raising `FunctionClauseError`. Found by this
  package's own audit: the raised error printed its arguments, the private key among them
  (`sign("bytes", %{private_key: key})` printed all 32 bytes). **How to tell whether you are
  affected:** only code that rescued `FunctionClauseError` from `sign/2` sees a difference;
  a call through `Canonical.signature/3` with a keyword list never reached that clause.

### Added: the key by reference

- `:private_key` may be a zero-arity function returning the 32-byte key
  (`private_key: fn -> key end`), and the README now passes it that way. Anything that prints
  the options (an exception, a log line, a crash report) prints `#Function<...>` in place of
  the key's bytes, including an exception raised in `beam_mcp`'s `Canonical.signature/3` on a
  mistyped call. A function that does not return 32 bytes is `{:error, {:private_key,
  :not_32_bytes}}`, as a key that is not 32 bytes is.

### Added: the project's pages and checks (no code change)

- `SECURITY.md` (private reporting, commitments, what a host can rely on, one known limit),
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1, CC-BY-4.0 in
  `LICENSES/`), `GOVERNANCE.md`, and `docs/`: architecture, assurance case, roadmap,
  verifying a release (the tag-signing key's fingerprint). The pages are in the docs extras.
- CI: `mix credo --strict` (Credo as a dev/test dependency; `.credo.exs` adds `UnsafeToAtom`
  and `LeakyEnvironment` on `lib/`), `mix hex.audit`, and a DCO sign-off check on every
  commit. Dependabot weekly for Mix and GitHub Actions.
- `tools/release_tarball.sh`, beam_mcp's canonical-tarball script, and `files:` in `mix.exs`
  as globs, so a release's bytes are the same on every machine.
- README: the OpenSSF Best Practices badge and links to the pages above.

### Added: gold groundwork (no code change)

- `docs/security-review.md`: how a security review of this package is done, a checklist centred
  on the key, and its record, empty until the first review. `CONTRIBUTING.md`: a code-review
  section. REUSE compliance: `.gitignore` headed, `.tool-versions`, `mix.lock` and `NOTICE`
  with `.license` sidecars, `LICENSES/Apache-2.0.txt`, and `reuse lint` in CI.

### Changed: governance (no code change)

- `GOVERNANCE.md` names two continuity holders, as on `beam_mcp`: `znmead` (the Maintain role
  on this repository) and Mike Hostetler (`maintainer` ownership on hex.pm; invited to
  Maintain), what that covers and what it does not. The bus factor stays one for knowledge.
  Mike Hostetler has since accepted Maintain here too; the organization requires secure
  two-factor authentication.

## [0.1.1] - 2026-09-19

### Changed

- The `beam_mcp` requirement is `~> 0.7` (two numbers): `0.1.0`'s `~> 0.7.0` held a host on
  core `0.7.x`, so `{:beam_mcp, "~> 0.8.0"}` beside `{:beam_mcp_signer, "~> 0.1.0"}` did not
  resolve. Core's public surface is frozen from `0.7.0` to `1.0.0` by its own rule, and this
  package uses nothing outside the `BeamMCP.Signer` behaviour and the canonical bytes, so the
  wider requirement is safe until core's `1.0.0`. No code changes.

## [0.1.0] - 2026-09-19

### Added

- `BeamMCP.Signer.Ed25519.sign/2`: Ed25519 through OTP's `:crypto` over the canonical bytes,
  with the 32-byte private key read from `opts[:private_key]` and from nowhere else. Answers
  `{:ok, signature}` (64 bytes), `{:error, :no_private_key}` or
  `{:error, {:private_key, :not_32_bytes}}`.
