#!/usr/bin/env sh
# Generate a disposable local-software signing identity for an explicitly
# requested cryptographic performance run. Never use this identity for real data.
set -eu

output="${1:?usage: generate-test-pkcs12.sh OUTPUT.p12}"
: "${CHANCELA_PERF_PKCS12_PASSPHRASE:?set CHANCELA_PERF_PKCS12_PASSPHRASE}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 \
  -subj "/CN=Chancela Ephemeral Performance Identity" \
  -keyout "$work/key.pem" -out "$work/cert.pem" >/dev/null 2>&1
# `chancela-signing` intentionally uses the bounded pure-Rust `p12` reader. Pin
# this disposable fixture to that reader's supported PKCS#12 profile instead of
# inheriting OpenSSL 3's PBES2/AES + SHA-256 defaults. This is test-fixture
# compatibility only; never use this legacy profile for real certificate export.
openssl pkcs12 -export \
  -keypbe PBE-SHA1-3DES \
  -certpbe PBE-SHA1-3DES \
  -macalg sha1 \
  -inkey "$work/key.pem" -in "$work/cert.pem" \
  -name "Chancela ephemeral performance identity" \
  -passout env:CHANCELA_PERF_PKCS12_PASSPHRASE \
  -out "$output"
chmod 600 "$output"
echo "generated disposable PKCS#12 fixture: $output"
