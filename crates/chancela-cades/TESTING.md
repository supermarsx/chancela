# Testing `chancela-cades`

`chancela-cades` is the self-contained crypto foundation of the signature subsystem. It has
**no hardware or network dependencies** — every test is offline, deterministic, and runs in CI on
all three OS. There are therefore **no `hardware-tests` / `network-tests` feature gates and no
`#[ignore]`d tests** in this crate.

## Running

```sh
cargo test  -p chancela-cades
cargo clippy -p chancela-cades --all-targets -- -D warnings
cargo fmt    -p chancela-cades --check
```

Test keys and certificates are generated **ephemerally in-test** (RSA-2048 and NIST P-256); no
private keys are checked in (`.orchestration/plans/t4.md` §6). Because integration tests under
`tests/` only see dev-dependencies, the tests live in-crate (`src/tests.rs`, `#[cfg(test)]`) so
they can reach the crate's own crypto deps (`rsa`, `p256`, `x509-cert`, `der`).

## What the tests cover

| Test | Asserts |
|---|---|
| `rsa_roundtrip_validates` | RSA-PKCS1-SHA256 build → validate round-trip (CC v1 / CMD profile). |
| `ecdsa_roundtrip_validates` | ECDSA-P256-SHA256 build → validate round-trip (CC v2 profile). |
| `signed_attributes_digest_is_deterministic` | Identical inputs yield an identical signed-attrs digest (so the digest the signer signs matches what `assemble_cades_b` embeds). |
| `tampered_content_digest_is_rejected` | Validating against a different content digest fails with `MessageDigestMismatch`. |
| `corrupted_signature_is_rejected` | A flipped signature byte fails validation. |
| `cades_signing_time_mismatch_breaks_signature` | CAdES only: assembling with a signing-time other than the one signed breaks the signature. Pinned to `Cades` — under `Pades` the attributes don't vary with time, so this would be vacuous there (see next). |
| `pades_profile_omits_the_cms_signing_time_attribute` | ETSI EN 319 142-1 V1.2.1 Table 1: `SignedAttrsProfile::Pades` never emits `signing-time`; the instant lives in the PDF `/M` entry instead. |
| `cades_profile_keeps_the_cms_signing_time_attribute` | `SignedAttrsProfile::Cades` still emits `signing-time`, for CAdES/ASiC, which has nowhere else to carry the claimed instant. |
| `pades_attributes_do_not_vary_with_time` | Under `Pades`, changing the instant changes nothing about the signed attributes — the property that makes `cades_signing_time_mismatch_breaks_signature` vacuous there, asserted directly instead of assumed. |
| `digest_and_assembly_agree_byte_for_byte_in_both_profiles` | The lockstep invariant: for both profiles, `signed_attributes_digest`'s digest is exactly SHA-256 of the DER `SET OF` that `assemble_cades_b` actually embeds, and the assembled signature validates end to end. |
| `profile_mismatch_between_digest_and_assembly_is_rejected` | Signing under one profile and assembling under the other must fail closed in both directions — the gate that catches a mis-threaded `SignedAttrsProfile`. |
| `signer_cert_mismatch_is_rejected` | A signature made by key A embedded with cert B fails with `SignatureVerification`. |
| `ess_certid_v2_binds_the_signing_certificate` | The `signing-certificate-v2` (ESSCertIDv2) attribute carries `SHA-256(signing cert)`, with the SHA-256 `hashAlgorithm` omitted (canonical DER default). |
| `outer_content_type_is_signed_data` | The emitted `ContentInfo` is `id-signedData`. |

## Scope and phase-2 notes

- **Profile:** detached CAdES-B only (content-type, message-digest, signing-certificate-v2,
  plus `signing-time` under `SignedAttrsProfile::Cades` only — PAdES omits it per ETSI EN
  319 142-1 V1.2.1 Table 1, since the PDF Signature Dictionary `/M` entry already carries the
  instant). This is the pinned §2.2 contract (`signed_attributes_digest`, `assemble_cades_b`,
  `validate_cades_b`); the profile must be identical at both calls or `validate_cades_b` rejects
  the signature (see `SignedAttrsProfile` doc comment in `src/builder.rs`). Enveloping CAdES and
  CAdES-LT/LTA enrichment are **phase-2** (see `.orchestration/plans/t4.md` §7).
- **Trust is out of scope.** A successful `validate_cades_b` means the signature is
  cryptographically valid over the given content digest and carries well-formed CAdES-B signed
  attributes — **not** that the signer is trusted. Chain building and qualified-status resolution
  belong to the caller via `chancela-tsl`.
- **Signature-algorithm identifiers:** RSA uses `rsaEncryption` on emit and additionally accepts
  `sha256WithRSAEncryption` on validation; ECDSA uses `ecdsa-with-SHA256`. RSA verification builds
  the SHA-256 `DigestInfo` explicitly (the `sha2/oid` feature is not enabled in the workspace).
