# Testing `chancela-tsa`

RFC 3161 timestamp client (spec 04, SIG-22). All default tests are offline and run in CI on
Windows/macOS/Linux — no network is touched.

## Default (offline) tests — `cargo test -p chancela-tsa`

`tests/roundtrip.rs` builds a `TimeStampReq`, replays a real `TimeStampResp` through
`MockTsaTransport`, and verifies the token. `tests/path.rs` covers the offline TSA certificate-path
validator used by the signing trust report. Coverage:

- `built_request_matches_real_openssl_query_byte_for_byte` — our `TimeStampReq` encoder produces
  byte-for-byte the same DER as `openssl ts -query` for the same digest/nonce.
- `verify_real_fixture_response` — a real OpenSSL response verifies: PKIStatus granted, imprint,
  policy, serial, `genTime`; because this fixture has no embedded signer certificate, the CMS
  signature-value check is not possible for this token.
- `client_round_trip_via_mock_transport` — full `TsaClient::stamp` over the mock transport.
- Negative paths: imprint mismatch, nonce mismatch, unaccepted qualified policy, `certReq` with no
  embedded cert, truncated response, and a `genTime`-tampered token failing the `message-digest`
  signed-attribute binding check.
- Offline certificate-path validation: accepted leaf-to-anchor paths, rejected unknown anchors, and
  rejected invalid or incomplete path material.

## Fixtures — provenance

`fixtures/openssl_sha256_abc.tsq` (request) and `fixtures/openssl_sha256_abc.tsr` (response) are the
published RFC 3161 test vectors from the `x509-tsp` 0.1 crate's own unit tests, produced by OpenSSL:

```
# request over SHA-256("abc"), nonce 0x314CFCE4E0651827
openssl ts -query -data abc.txt -sha256 -out openssl_sha256_abc.tsq
# reply signed by an ec384 TSA key under policy 1.2.3.4.1
openssl ts -reply -queryfile openssl_sha256_abc.tsq \
    -signer ec384-tsa-key.crt -inkey ec384-tsa-key.pem \
    -out openssl_sha256_abc.tsr -config tsa.cnf
```

The token covers `SHA-256("abc") = ba7816bf…15ad`, `genTime = 2023-06-07T11:26:26Z`, serial `04`,
policy `1.2.3.4.1`. `certReq` was unset, so the response embeds no signing certificate. Using a real
OpenSSL response (rather than something we synthesised) proves this client parses real-world TSA
output, not just its own encoder.

## Verification boundary (read this)

`verify_response` checks the token's **structure and its binding to the requested digest**:

- PKIStatus is granted/grantedWithMods;
- the encapsulated content is a `TSTInfo`;
- the message imprint is SHA-256 over exactly the requested digest;
- the nonce echoes the request;
- the `content-type` signed attribute is `id-ct-TSTInfo` and the `message-digest` signed attribute
  equals SHA-256 of the encapsulated `TstInfo` (so the signature commits to this exact token);
- the TSA policy OID satisfies the `QualifiedTimestampPolicy` hook (SIG-22);
- when the token embeds the TSA signer certificate referenced by `SignerInfo.sid`, the CMS
  signature value is verified for the supported RSA/P-256 timestamp-signature algorithms.

Certificate trust is a separate boundary:

- **Qualified-status** of the signing TSA (is it a currently-granted qualified TSA?) is a trusted-list
  decision owned by `chancela-tsl`.
- **Offline TSA certificate-path validation** is exposed by `validate_tsa_certificate_path` and is
  covered in this crate, but it requires authenticated anchors from the caller.
- **Timestamp trust reporting** is assembled by `chancela-signing`, which combines a verified token,
  QTST lookup evidence from `chancela-tsl`, accepted policy OIDs, and the offline path validator.

This crate does not make product B-LT/B-LTA, legal qualification, or probative-value claims. It
provides the technical verification pieces consumed by higher layers.

## Live TSA test — `network-tests` + `#[ignore]` (never in CI)

`tests/live_tsa.rs` is double-gated: it only compiles under `--features network-tests` and is also
`#[ignore]`d. It POSTs to a real RFC 3161 TSA.

```sh
export CHANCELA_TSA_URL="http://timestamp.example-qtsa.pt/tsa"   # a qualified TSA endpoint
cargo test -p chancela-tsa --features network-tests -- --ignored live_tsa_stamps_a_digest
```

Requires network access and a reachable TSA. Some public TSAs require the `Content-Type:
application/timestamp-query` header (set by `HttpTsaTransport`) and may rate-limit.
