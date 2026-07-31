# chancela-cmd — testing

Chave Móvel Digital (AMA SCMD `AppSCMDService`) qualified remote-signature JSON/REST client.
Produces a `chancela_cades::RawSignature`; CMS/CAdES assembly happens in `chancela-cades` /
`chancela-signing`.

## Default (offline, CI) — mock round trip

```
cargo test -p chancela-cmd
```

All default tests run with **no network**, driven by `MockScmdTransport` (canned JSON
responses in `fixtures/`):

- `tests/mock_flow.rs`
  - `full_request_otp_retrieve_round_trip` — the SIG-02 flow end to end:
    `GetCertificate` → `SCMDSign` (dispatches OTP, returns `ProcessId`) → `ValidateOtp`
    (returns the raw RSA-PKCS#1 v1.5 signature), assembled into a `RawSignature` with the
    certificate chain. Also asserts the ApplicationId is sent **raw** (never base64), the
    mobile is space-stripped before encryption, the hash is the 51-byte DigestInfo, and the
    `ProcessId` is threaded into `ValidateOtp`.
  - `otp_bytes_are_never_the_signature_artifact` — SIG-02 invariant: the OTP is a
    possession-factor **confirmation step**, never the signature. The artifact is the
    256-byte qualified RSA signature.
  - `scmd_sign_error_maps_to_service_status` — `Code 401` (bad PIN) → `CmdError::ServiceStatus`.
  - `otp_rejection_maps_to_error` — `Status.Code 402` (bad OTP) → `CmdError::OtpRejected`.
  - `get_certificate_without_a_pem_payload_is_a_parse_error` — a `{"d":null}` response →
    `CmdError::ResponseParse` (the JSON service has no SOAP `<Fault>`).
  - `missing_action_response_is_transport_error`, `preprod_config_is_cleartext_prod_requires_cert`.
- In-module unit tests: JSON request build + response parsing incl. the `{"d":...}` unwrap and
  the integer-array signature (`src/wire.rs`), field encryption cleartext + RSA-encrypt/decrypt
  round trip (`src/field_encryption.rs`).
- `tests/conformance_vectors.rs` — **golden conformance vectors** pinning request construction and
  response parsing byte-for-byte to the exact bytes recov-pt produces/consumes for the same
  **synthetic** inputs (all-zero GUID ApplicationId, `+351000000000`, `000000` PIN/OTP, the public
  empty-string SHA-256 as the signed digest). Each vector cites the recov-pt source line it pins
  (`GetCertificate` = `cmd_verify.rs:1096-1099`; `SCMDSign` = `cmd_challenge.rs:85-112`;
  `ValidateOtp` = `cmd_challenge.rs:139-164`) and includes the negative cases recov-pt enforces: a
  base64 signature rejected, out-of-range signature bytes rejected, a non-"200" `Code` surfaced,
  the numeric-`Code` rejection, and both `{"d":...}` wrapper forms. **These prove Chancela
  constructs/parses exactly as recov-pt does; they do NOT prove AMA accepts the bodies end to end —
  only the live round trip below does.**

Fixtures are checked in and contain **only public** certificates (a self-signed test CA, a
leaf "CITIZEN SIGNATURE" cert signed by it, and a self-signed AMA field-encryption cert). No
private keys are checked in; the RSA encrypt/decrypt test generates an ephemeral key in-process.

## Network tests (real AMA preprod) — never in CI

Double-gated: the `network-tests` feature **and** `#[ignore]`.

```
cargo test -p chancela-cmd --features network-tests -- --ignored
```

Prerequisites (see `tests/network.rs`):

- `CHANCELA_CMD_ENV=preprod`
- `CHANCELA_CMD_APPLICATION_ID=<opaque AMA-assigned string>` — obtained via AMA
  integration/certification (contact `eid@ama.pt`).
- `CHANCELA_CMD_HTTP_BASIC_USERNAME=<AMA-issued BasicAuth username>` and
  `CHANCELA_CMD_HTTP_BASIC_PASSWORD=<AMA-issued BasicAuth password>` — optional where AMA
  permits unauthenticated preprod calls; required for PROD real HTTP transport.
- `CHANCELA_CMD_TEST_PHONE=+351 XXXXXXXXX` — a phone registered for CMD in preprod.
- `CHANCELA_CMD_AMA_CERT_PEM=<path>` (optional preprod; **required for PROD**) — a file holding
  AMA's field-encryption key, as either a `-----BEGIN CERTIFICATE-----` block or the bare
  `-----BEGIN PUBLIC KEY-----` block inside it. Only the RSA key is used, so the two are
  interchangeable; the variable keeps its `_CERT_` name because renaming a documented deployment
  variable would break existing installations.

Two `#[ignore]`d network tests live in `tests/network.rs`:

- `preprod_get_certificate` — the low-risk probe: `GetCertificate` only. Proves BasicAuth + field
  encryption + certificate retrieval against the live endpoint. **No signature is produced.**
- `preprod_full_sign_round_trip` — the ONE call that confirms the round trip end to end:
  `GetCertificate` → `SCMDSign` → `ValidateOtp` → a real 256-byte RSA signature.

  > ⚠️ **`preprod_full_sign_round_trip` PERFORMS A REAL QUALIFIED SIGNATURE.** Confirming the OTP
  > makes AMA produce a genuine qualified electronic signature under the citizen's CMD key over the
  > digest the test submits. Run it only with a preprod **test** citizen and a throwaway digest.

  A full `SCMDSign` → `ValidateOtp` cannot be non-interactive: `ValidateOtp` needs the OTP a human
  receives on the registered device *after* `SCMDSign`. The test therefore blocks on an interactive
  OTP read from stdin — which is also why it cannot complete by accident. Run it with a TTY:

  ```
  export CHANCELA_CMD_ENV=preprod
  export CHANCELA_CMD_APPLICATION_ID=<AMA-issued ApplicationId>
  export CHANCELA_CMD_HTTP_BASIC_USERNAME=<...>   # if AMA requires it
  export CHANCELA_CMD_HTTP_BASIC_PASSWORD=<...>   # if AMA requires it
  export CHANCELA_CMD_AMA_CERT_PEM=<path to AMA field-encryption key PEM>
  export CHANCELA_CMD_TEST_PHONE="+351 XXXXXXXXX"  # a preprod-registered CMD phone
  export CHANCELA_CMD_TEST_PIN=<the citizen's CMD signature PIN>
  cargo test -p chancela-cmd --features network-tests -- --ignored --nocapture \
      preprod_full_sign_round_trip
  ```

  The test calls `GetCertificate`, then `SCMDSign` (AMA dispatches the OTP), then prompts `OTP: `.
  Type the OTP received on the device. **Success** = a 256-byte RSA-2048 signature and a non-empty
  leaf certificate (both asserted). None of `CHANCELA_CMD_TEST_PIN` or the OTP is logged.

## Environment / config (pinned, plan §2.3)

| Var | Meaning | Default |
|---|---|---|
| `CHANCELA_CMD_ENV` | `preprod` \| `prod` | `preprod` |
| `CHANCELA_CMD_APPLICATION_ID` | opaque AMA ApplicationId (sent RAW on the wire, never base64) | required |
| `CHANCELA_CMD_HTTP_BASIC_USERNAME` | AMA-issued HTTP BasicAuth username for real transport | none (required for PROD) |
| `CHANCELA_CMD_HTTP_BASIC_PASSWORD` | AMA-issued HTTP BasicAuth password for real transport | none (required for PROD) |
| `CHANCELA_CMD_AMA_CERT_PEM` | path to AMA field-encryption key PEM (`CERTIFICATE` or `PUBLIC KEY`) | none (cleartext preprod) |

## Field encryption (PROD) — status & caveat

The newer SCMD spec requires the mobile number, PIN, and OTP to be RSA-encrypted with AMA's
public key before being placed in the request. That key is accepted either inside a certificate
or on its own as a `PUBLIC KEY` block — only the key is used, and the two forms provably build the
same encryptor. This is implemented as
`FieldEncryptor::AmaRsa` (RSA PKCS#1 v1.5 + base64), config-gated: **preprod runs cleartext**,
**PROD requires** `CHANCELA_CMD_AMA_CERT_PEM`, `CHANCELA_CMD_HTTP_BASIC_USERNAME`, and
`CHANCELA_CMD_HTTP_BASIC_PASSWORD` for real HTTP transport (a PROD transport config without
them is rejected).

Because this crate does not pull a `getrandom`-enabled RNG, the encryption entry points take a
caller-supplied `rand_core::CryptoRngCore` (re-exported as `chancela_cmd::rand_core`).

**Risk #6 (spec drift):** the exact encrypted-field set and encoding are anchored to SCMD
v1.6 and MUST be re-verified against the certified `doc-CMD-assinatura` spec, and the SOAP
contract (namespaces, SOAPAction, message shapes) confirmed against `?wsdl`, before PROD use.

## Phase-2 (not implemented here)

- `CCMovelMultipleSign` batch signing (single-sign only for now).
- PROD certification against the certified spec version.
