# chancela-cmd — testing

Chave Móvel Digital (AMA SCMD) qualified remote-signature SOAP client. Produces a
`chancela_cades::RawSignature`; CMS/CAdES assembly happens in `chancela-cades` /
`chancela-signing`.

## Default (offline, CI) — mock round trip

```
cargo test -p chancela-cmd
```

All default tests run with **no network**, driven by `MockScmdTransport` (canned SOAP
responses in `fixtures/`):

- `tests/mock_flow.rs`
  - `full_request_otp_retrieve_round_trip` — the SIG-02 flow end to end:
    `GetCertificate` → `CCMovelSign` (dispatches OTP, returns `ProcessId`) → `ValidateOtp`
    (returns the raw RSA-PKCS#1 v1.5 signature), assembled into a `RawSignature` with the
    certificate chain. Also asserts the ApplicationId is base64'd, the hash is carried, and
    the `ProcessId` is threaded into `ValidateOtp`.
  - `otp_bytes_are_never_the_signature_artifact` — SIG-02 invariant: the OTP is a
    possession-factor **confirmation step**, never the signature. The artifact is the
    256-byte qualified RSA signature.
  - `ccmovel_sign_error_maps_to_service_status` — `Code 401` (bad PIN) → `CmdError::ServiceStatus`.
  - `otp_rejection_maps_to_error` — `Status.Code 402` (bad OTP) → `CmdError::OtpRejected`.
  - `soap_fault_surfaces_as_error` — a SOAP `<Fault>` → `CmdError::SoapFault`.
  - `missing_action_response_is_transport_error`, `preprod_config_is_cleartext_prod_requires_cert`.
- In-module unit tests: SOAP envelope build + local-name response parsing (`src/soap.rs`),
  field encryption cleartext + RSA-encrypt/decrypt round trip (`src/field_encryption.rs`).

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
- `CHANCELA_CMD_AMA_CERT_PEM=<path>` (optional preprod; **required for PROD**) — AMA's
  field-encryption certificate PEM.

A full `CCMovelSign` → `ValidateOtp` cannot be fully automated: `ValidateOtp` needs the OTP a
human receives on the registered device. The provided network test exercises `GetCertificate`
only.

## Environment / config (pinned, plan §2.3)

| Var | Meaning | Default |
|---|---|---|
| `CHANCELA_CMD_ENV` | `preprod` \| `prod` | `preprod` |
| `CHANCELA_CMD_APPLICATION_ID` | opaque AMA ApplicationId (base64'd on the wire) | required |
| `CHANCELA_CMD_HTTP_BASIC_USERNAME` | AMA-issued HTTP BasicAuth username for real transport | none (required for PROD) |
| `CHANCELA_CMD_HTTP_BASIC_PASSWORD` | AMA-issued HTTP BasicAuth password for real transport | none (required for PROD) |
| `CHANCELA_CMD_AMA_CERT_PEM` | path to AMA field-encryption cert PEM | none (cleartext preprod) |

## Field encryption (PROD) — status & caveat

The newer SCMD spec requires the mobile number, PIN, and OTP to be RSA-encrypted with AMA's
public certificate before being placed in the request. This is implemented as
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
