#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sudo Apt Holdings LLC
# SPDX-License-Identifier: Apache-2.0
#
# Prints the OpenSSL that `:crypto` is linked to and whether it offers ML-DSA-87. With
# MLDSA_REQUIRED=1 a runtime that does not offer it is refused by name, so a leg that must run
# ML-DSA cannot pass without it. ML-DSA arrived in OpenSSL 3.5; an OTP linked to an older
# libcrypto (Ubuntu 24.04's 3.0.13, which builds.hex.pm's OTPs link there) has none. Run by
# every leg of CI's test job (.github/workflows/ci.yml); the box leg sets MLDSA_REQUIRED=1.
#
# Not a FIPS-mode check: in FIPS mode OTP leaves `mldsa87` out of `crypto:supports/1` while
# the algorithm still works, so a check meant for that mode signs and verifies a known answer
# instead. No leg here runs in FIPS mode.
set -euo pipefail
# The application is started first (a bare module load logs a fips_mode report on some
# runtimes), and only the tagged line is read, so nothing else the runtime prints is parsed.
line=$(erl -noshell -eval '
  {ok, _} = application:ensure_all_started(crypto),
  [{_, _, Lib}] = crypto:info_lib(),
  Offered = lists:member(mldsa87, proplists:get_value(public_keys, crypto:supports())),
  io:format("mldsa_offered: ~s ~s~n", [Offered, Lib]),
  halt().' | sed -n 's/^mldsa_offered: //p')
offered=${line%% *}
lib=${line#* }
echo "crypto linked to $lib; mldsa87 offered: $offered"
if [ "${MLDSA_REQUIRED:-0}" = "1" ] && [ "$offered" != "true" ]; then
  echo "this leg must offer mldsa87 (MLDSA_REQUIRED=1), and its OTP's libcrypto does not; refused"
  exit 1
fi
