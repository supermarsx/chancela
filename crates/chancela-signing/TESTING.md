# Testing `chancela-signing`

This crate is the signature **orchestration middleware**. All of its tests are **offline and
deterministic** — there are no hardware or network tests here (those live in the leaf crates
`chancela-smartcard` / `chancela-cmd` / `chancela-tsl` / `chancela-tsa`). Everything runs in CI on
all three OS with no card reader and no network.

## Run

```
cargo test -p chancela-signing
cargo clippy -p chancela-signing --all-targets -- -D warnings
cargo fmt -p chancela-signing --check
```

## What the tests cover

- `src/lib.rs` unit tests (5): the preserved vocabulary invariants — family serde round-trip, the
  SIG-02 "only Qualified is a qualified signature" invariant, Manual-is-not-qualified, the B-LTA
  archival default, and the `chancela_tsl::QualifiedStatus → TrustedListStatus` 1:1 mapping.
- `tests/envelope_flows.rs` (14): the orchestration behaviour with a **shape-only**
  [`MockProvider`] and a `StaticTrustPolicy` — serial vs parallel completion and slot ordering,
  already-signed / out-of-range rejection, the **trusted-list policy gate** (withdrawn and unknown
  issuers are refused; granted is recorded on the artifact), missing-issuer handling, family
  mismatch, provider failure surfacing, manual-scan recording and path enforcement, the **SIG-02
  OTP-labelling invariant** (a `CmdProvider` reports `Qualified`, never `OtpConfirmation`, and the
  OTP is confirmed exactly once), XAdES/ASiC unavailable-format reporting in signing and
  validation, and supported-format input-mismatch reporting.
- `tests/roundtrip.rs` (7): **cryptographic round-trips** driving a real in-test key through the
  pipeline — detached CAdES-B (RSA + P-256), PAdES-B-B, PAdES-B-T (timestamp embedded from the
  bundled `chancela-tsa` OpenSSL fixture), detached-CAdES timestamp as external evidence, a
  tamper-detection negative, and a two-signatory serial envelope with a granted policy gate. Each
  produced artifact is re-validated via `validate_signature`.

## Fixtures & keys

- `fixtures/mock_signer_rsa.der` — a self-signed **public** RSA-2048 certificate used by
  `MockProvider::deterministic_rsa` for shape-only signing (`assemble_cades_b` only *parses* the
  certificate). **No private key is checked in** (plan §6).
- The cryptographic round-trip mints an ephemeral RSA-2048 / P-256 key and a self-signed
  certificate **in-test** (mirroring `chancela-cades/src/tests.rs`); nothing is persisted. This is
  why `rsa`, `p256`, `der`, `spki`, and `x509-cert` are **`[dev-dependencies]`** — no production
  code path uses them.

## Scope notes / phase-2 seams

- **Detached CAdES-B-T:** when a TSA is supplied for a detached-CAdES slot, the timestamp token is
  attached to the artifact as external archival evidence and the profile stays honestly at **B-B**.
  Embedding the timestamp as an in-CMS `id-aa-signatureTimeStampToken` unsigned attribute (true
  CAdES-B-T) is a phase-2 seam — it needs the `cms`/`der` surgery `chancela-pades` already performs
  for PDFs. PAdES-B-T is fully implemented (SIG-22).
- **Profiles B-LT / B-LTA:** requests for long-term profiles reach at most **B-T**; LT/LTA
  enrichment (DSS/VRI, archival document timestamps, revocation) is phase-2, tracked by
  `chancela-pades` (`PadesError::LongTermNotImplemented`). The artifact records the profile
  *actually reached*, never the requested one.
- **XAdES / ASiC formats:** recognised by the vocabulary (SIG-20) but unavailable in this crate;
  `sign_slot` and `validate_signature` return `SigningError::UnsupportedFormat` for them.
- **Smartcard issuer certificate:** a Cartão de Cidadão presents only the leaf, so
  `SmartcardProvider::issuer_certificate_der` returns `None`; a trust-policy gate over a smartcard
  slot therefore requires the issuing-CA certificate to be supplied out-of-band (a configured CA
  bundle), else `SigningError::MissingIssuerCertificate`.
- **EU DSS validation-sidecar cross-check (SIG-23):** the native `validate_signature` path produces
  the SIG-24 report; the DSS sidecar cross-check remains a documented phase-2 seam.

## Cross-crate capability matrix (t4 program) — honest per-layer status

This is the whole-program status across all seven t4 crates, as proven by the Phase-E
verification on this box (`.orchestration/logs/t4-e9.md`). "Mock-verified" = green in CI on all
three OS with **no hardware and no network**. "Gated" = double-gated (`hardware-tests` /
`network-tests` feature **and** `#[ignore]`); compiles in CI but never runs there. "Phase-2" = not
implemented; a typed stub or documented seam.

| Layer | Mock-verified NOW (in CI) | Hardware/network-gated (not in CI) | Phase-2 (not implemented) |
|---|---|---|---|
| **cades** | detached CAdES-B build + validate round-trips, RSA-PKCS1-SHA256 and ECDSA-P256-SHA256; message-digest + ESSCertIDv2 signed attrs; tamper → fail | — | CAdES-LT/LTA enrichment; enveloping (non-detached) variant |
| **smartcard** | signer-selection (signature vs authentication cert by CKA_LABEL), CC v1 RSA / CC v2 P-256 branching, ECDSA→DER re-encode, `detect()` no-panic — via `MockToken` | real-card `sign_digest`, real PC/SC reader enumeration (`hardware-tests`) | SCAP professional attributes (SIG-04) |
| **cmd** | full `get_certificate → request_signature (CCMovelSign) → confirm_otp (ValidateOtp) → RawSignature` via `MockScmdTransport`; SIG-02 OTP-as-confirmation labelling; error/OTP-rejection/SOAP-fault paths; field-encryptor preprod-cleartext vs PROD-cert gating | preprod SCMD calls (`network-tests`, needs AMA ApplicationId) | multiple-sign batch; **PROD field-encryption re-verification against certified `doc-CMD-assinatura` (contract anchored to v1.6)**; PROD certification |
| **tsl** | ETSI TS 119 612 parse + qualified-status query + cache staleness on bundled fixture (granted / withdrawn / unknown issuer) | live PT TSL fetch (`network-tests`) | **TSL XML-DSig signature validation (SIG-11)** — typed stub `SignatureValidationNotImplemented` |
| **tsa** | RFC 3161 build-request / parse-response / verify via `MockTsaTransport` — structural + imprint + nonce + signed-attribute (content-type/message-digest) binding | live TSA stamp (`network-tests`, `CHANCELA_TSA_URL`) | **TSA asymmetric signature-value + cert-chain verification** — tsa carries no `rsa`/`p256`/`ecdsa`, so it does not verify the token's signature crypto (boundary; the computed binding is that check's precondition) |
| **pades** | PAdES-B-B + PAdES-B-T sign / validate / tamper-detect on a fixture PDF (RSA + ECDSA); ByteRange excludes `/Contents` exactly | — | **PAdES-LT/LTA (SIG-21 archival default)** — typed stub `LongTermNotImplemented`. Input limits: classic xref only, no pre-existing AcroForm |
| **signing** | `SignerProvider` orchestration; serial/parallel envelope + slot order; trusted-list policy gate (withdrawn/unknown refused); TSA wiring; `validate_signature` → SIG-24 report; `CmdProvider` driven end-to-end through the pipeline to `assemble_cades_b` | end-to-end with real providers (inherits smartcard/cmd/tsl/tsa gates) | in-CMS detached-CAdES-B-T embedding; **EU DSS validation-sidecar cross-check (SIG-23)** |

**Honest boundary on the CMD full chain.** The `get_certificate → … → RawSignature →
assemble_cades_b` chain is exercised end-to-end through `CmdProvider` + `MockScmdTransport`
(`tests/envelope_flows.rs::cmd_otp_is_a_confirmation_step_never_the_signature`, which produces a
non-empty CMS). The final **`validate_cades_b` cryptographic** leg is **not** run over the CMD
mock's signature, because `MockScmdTransport` returns a *canned fixture* signature that cannot
verify against the certificate by construction. The `assemble_cades_b → validate_cades_b`
cryptographic round-trip is instead proven with **real in-test keys** via `MockProvider` over the
identical pipeline code path (`tests/roundtrip.rs::cades_detached_round_trip_rsa` / `_ecdsa`).
