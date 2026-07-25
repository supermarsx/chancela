#!/usr/bin/env sh
# Generate a disposable local-software signing identity for an explicitly
# requested cryptographic performance run. Never use this identity for real data.
set -eu

output="${1:?usage: generate-test-pkcs12.sh OUTPUT.p12}"
passphrase="${CHANCELA_PERF_PKCS12_PASSPHRASE:?set CHANCELA_PERF_PKCS12_PASSPHRASE}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 \
  -subj "/CN=Chancela Ephemeral Performance Identity" \
  -keyout "$work/key.pem" -out "$work/cert.pem" >/dev/null 2>&1
openssl pkcs12 -export \
  -inkey "$work/key.pem" -in "$work/cert.pem" \
  -name "Chancela ephemeral performance identity" \
  -passout "pass:${passphrase}" \
  -out "$output"
chmod 600 "$output"
echo "generated disposable PKCS#12 fixture: $output"
