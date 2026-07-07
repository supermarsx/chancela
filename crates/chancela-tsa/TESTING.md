# Testing `chancela-tsa`

RFC 3161 timestamp client (spec 04, SIG-22). All default tests are offline and run in CI on
Windows/macOS/Linux — no network is touched.

## Default (offline) tests — `cargo test -p chancela-tsa`

`tests/roundtrip.rs` builds a `TimeStampReq`, replays a real `TimeStampResp` through
`MockTsaTransport`, and verifies the token. Coverage:

- `built_request_matches_real_openssl_query_byte_for_byte` — our `TimeStampReq` encoder produces
  byte-for-byte the same DER as `openssl ts -query` for the same digest/nonce.
- `verify_real_fixture_response` — a real OpenSSL response verifies: PKIStatus granted, imprint,
  policy, serial, `genTime`.
- `client_round_trip_via_mock_transport` — full `TsaClient::stamp` over the mock transport.
- Negative paths: imprint mismatch, nonce mismatch, unaccepted qualified policy, `certReq` with no
  embedded cert, truncated response, and a `genTime`-tampered token failing the `message-digest`
  signed-attribute binding check.

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

This crate has **no asymmetric-crypto dependency** (`rsa`/`p256`/`ecdsa`) — deliberately, per
`.orchestration/plans/t4.md` §2.1. `verify_response` therefore checks the token's **structure and
its binding to the requested digest**:

- PKIStatus is granted/grantedWithMods;
- the encapsulated content is a `TSTInfo`;
- the message imprint is SHA-256 over exactly the requested digest;
- the nonce echoes the request;
- the `content-type` signed attribute is `id-ct-TSTInfo` and the `message-digest` signed attribute
  equals SHA-256 of the encapsulated `TstInfo` (so the signature commits to this exact token);
- the TSA policy OID satisfies the `QualifiedTimestampPolicy` hook (SIG-22).

It does **not** verify the TSA's asymmetric signature value, nor validate the TSA certificate chain.
That split is intentional in this task's design:

- **Qualified-status** of the signing TSA (is it a currently-granted qualified TSA?) is a trusted-list
  decision owned by `chancela-tsl`.
- The **CMS signature-value** cryptographic check belongs to the crypto layer
  (`chancela-cades` / `chancela-signing`), which carries `rsa`/`p256`.

If a future task wants full signature verification inside `chancela-tsa`, add `rsa` + `p256` +
`ecdsa` (+ `p384` to also verify the ec384 fixture) to this crate's manifest and extend
`verify::verify_response`; the signed-attribute binding computed here is exactly the precondition a
signature check consumes. This is flagged to the coordinator for `t4-e8`/`t4-e9`.

## Live TSA test — `network-tests` + `#[ignore]` (never in CI)

`tests/live_tsa.rs` is double-gated: it only compiles under `--features network-tests` and is also
`#[ignore]`d. It POSTs to a real RFC 3161 TSA.

```sh
export CHANCELA_TSA_URL="http://timestamp.example-qtsa.pt/tsa"   # a qualified TSA endpoint
cargo test -p chancela-tsa --features network-tests -- --ignored live_tsa_stamps_a_digest
```

Requires network access and a reachable TSA. Some public TSAs require the `Content-Type:
application/timestamp-query` header (set by `HttpTsaTransport`) and may rate-limit.
