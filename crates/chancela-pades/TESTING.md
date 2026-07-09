# Testing — chancela-pades

PAdES-B-B / B-T PDF signing, local caller-supplied DSS/VRI append/reporting, and structural
validation (spec 04, SIG-21/22/24).

## Run

```sh
cargo test  -p chancela-pades
cargo clippy -p chancela-pades --all-targets -- -D warnings
cargo fmt   -p chancela-pades --check
```

All tests are **offline and deterministic**. There are no hardware or network tests and no
feature gates: signing keys/certificates are generated ephemerally in-test (no private keys are
checked in), and the B-T signature timestamp is driven from `chancela-tsa`'s bundled OpenSSL
RFC 3161 fixture via `MockTsaTransport::from_fixture()`. DSS tests use caller-supplied synthetic
DER fixtures only; they do not fetch, freshness-check, or trust-validate OCSP/CRL data.

## What the tests cover

| Test | Asserts |
|---|---|
| `base_pdf_is_parseable` | the hand-authored minimal base PDF loads in `lopdf` |
| `rsa_sign_validates` / `ecdsa_sign_validates` | full B-B round-trip: sign → validate, both CAdES profiles (RSA-PKCS1-SHA256, ECDSA-P256-SHA256); embedded CMS verifies via `chancela_cades::validate_cades_b`; signing-certificate-v2 present; signing-time preserved |
| `byte_range_excludes_exactly_the_contents_placeholder` | the `/ByteRange` starts at 0, its two ranges bracket exactly the `<...>` `/Contents` hex placeholder, and the second range ends at EOF |
| `tampered_byte_in_range_fails_validation` | flipping a covered byte (in range 1) yields `CadesError::MessageDigestMismatch` |
| `tampered_byte_after_gap_fails_validation` | flipping a covered byte in range 2 fails validation |
| `sign_options_are_emitted` | `/T`, `/Reason`, `/M` strings from `SignOptions` land in the signed bytes |
| `b_t_signature_timestamp_embeds_and_validates` | `add_signature_timestamp` inserts the `id-aa-signatureTimeStampToken` unsigned attribute; the signature still validates and the ByteRange is unchanged |
| `dss_revision_appends_to_b_t_and_reports_counts_hashes` | `add_dss_revision` appends a deterministic `/DSS` + `/VRI` incremental update from caller-supplied DER evidence; validation still succeeds and reports certificate, OCSP, CRL, VRI, and evidence hashes |
| `dss_revision_keeps_signed_revision_tamper_detection` | tampering with the original signed revision still fails validation even when a later DSS revision remains parseable |
| `empty_dss_evidence_is_rejected` / `existing_dss_is_rejected_in_this_slice` | local DSS append rejects missing revocation material and pre-existing DSS dictionaries rather than implying merge support |
| `validation_rejects_unsigned_pdf` | an unsigned PDF returns `PadesError::NoSignature` |
| `pdf::pdf_tests::*` | low-level helpers: hex, DER TLV length, `startxref` scan, dictionary serialization |

## Design (why the ByteRange arithmetic is robust)

Signing appends a **classic incremental update** (hand-serialized, not driven through `lopdf`'s
writer) so the exact byte layout — and therefore the `/ByteRange` offsets — is under our control:

1. `/Contents` is a fixed-size (`MAX_CONTENTS_BYTES` = 16 KiB) zero-filled hex placeholder, and
   `/ByteRange` is a fixed-width `[0 0000000000 0000000000 0000000000]` placeholder. Both are
   written **before** offsets are known.
2. The full document (`original ++ incremental section`) is assembled, then the `<` / `>` of
   `/Contents` are located and the ByteRange is patched **in place at fixed width** (no offset
   shifts).
3. SHA-256 is taken over the two covered ranges (everything except `<...>`), handed to the signing
   callback, and the returned CMS is hex-filled into the placeholder.

B-T (`add_signature_timestamp`) parses the signed PDF, SHA-256s the CMS signature value, obtains an
RFC 3161 token, inserts it as a CMS **unsigned** attribute, and re-embeds the CMS into the same
placeholder. Because `/Contents` is excluded from the ByteRange, the B-B signature is unaffected.

## Input requirements (phase-1)

`sign_pdf` supports the PDFs Chancela generates. The input must:

- use a **classic cross-reference table** (not an xref stream) — else `MalformedStructure`;
- **not already carry an AcroForm** — else `MalformedStructure`;
- have an inline `/Annots` array on its first page (or none) — an indirect `/Annots` returns
  `MalformedStructure`.

Broader inputs (xref streams, existing forms, multi-signature) are a documented follow-up.

## Explicit phase-2 follow-ups

- **Production-grade PAdES-B-LT / B-LTA legal LTV** (SIG-21 archival default): local,
  caller-supplied DSS/VRI append and reporting exists and is tested, but live OCSP/CRL fetching,
  revocation freshness and trust validation, existing-DSS merge, multi-signature VRI handling, and
  archive document timestamps (`/DocTimeStamp`) remain gaps. `PadesError::
  LongTermNotImplemented` remains reserved for long-term profile entry points that are not part of
  this local DSS slice.
- **TSA signature-value verification inside B-T**: `chancela-tsa` verifies the timestamp token
  structurally and by imprint binding, not its asymmetric signature (see that crate's TESTING.md).
  Full trust evaluation is `chancela-signing`'s job.
