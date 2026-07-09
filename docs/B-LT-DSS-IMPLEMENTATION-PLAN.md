# PAdES B-LT / DSS Local Implementation Plan

Updated 2026-07-09. This is an implementation plan, not a claim of production
long-term validation.

## Current State

- `chancela-pades` supports PAdES B-B and B-T.
- `chancela-signing` can orchestrate CC, CMD, CSC, mock signing, TSL gates, and
  B-T timestamping.
- `chancela-api` persists one signed document per act, with signed PDF bytes,
  signer certificate, trust-list status, and an optional timestamp token.
- Signature evidence currently reports unsigned, B-B, or B-T and explicitly
  marks DSS/revocation, B-LT, and B-LTA as not implemented.
- Archive packages preserve signed PDFs, signing JSON, signer certificate, and
  timestamp sidecars when present, but do not report embedded DSS/VRI evidence.

## Smallest Credible Local Slice

Implement fixture-fed, caller-supplied DSS embedding and reporting:

- Add a PAdES DSS/VRI incremental update from supplied DER blobs.
- Detect and report embedded DSS revocation evidence.
- Allow validation where the signature ByteRange covers the signed revision and
  a later DSS incremental update exists.
- Surface technical evidence as B-LT-local only when a B-T timestamp and DSS
  OCSP/CRL material are present.
- Add archive evidence JSON fields for DSS/VRI, OCSP/CRL counts, and evidence
  hashes.

No live OCSP/CRL fetch, no live QTSP dependency, no B-LTA archival document
timestamp, and no legal sufficiency claim in this slice.

## Implementation Targets

- `crates/chancela-pades/src/lib.rs`: export new DSS types/functions.
- `crates/chancela-pades/src/dss.rs` or `sign.rs`: add `DssEvidence`,
  `DssReport`, and `add_dss_revision(signed_pdf, evidence)`.
- `crates/chancela-pades/src/pdf.rs`: add deterministic incremental object,
  stream, and xref helpers if the current writer cannot express DSS objects.
- `crates/chancela-pades/src/validate.rs`: report DSS presence, revocation
  counts/hashes, and signed-revision length while keeping crypto validation over
  the original ByteRange.
- `crates/chancela-pades/src/error.rs`: add DSS-specific errors.
- `crates/chancela-signing/src/pipeline.rs`: add a thin attach-DSS wrapper.
- `crates/chancela-signing/src/validate.rs`: add DSS/revocation report fields.
- `crates/chancela-api/src/signature.rs`: update final signed PDF validation
  and evidence classification.
- `crates/chancela-api/src/archive_package.rs`: add DSS/VRI evidence reporting
  to package sidecars.

## Test Strategy

- Use checked-in public DER fixtures only: signer/issuer certificates, one OCSP
  response, and one CRL. Do not check in private keys.
- PAdES round-trip: B-T PDF -> DSS revision -> validates, reports VRI/OCSP/CRL
  counts, deterministic bytes, and covered-byte tampering still fails.
- Signing round-trip: B-T + DSS reports timestamp and revocation evidence.
- API status: unsigned, B-B, B-T, and B-T + DSS classify distinctly.
- Archive package: evidence JSON reports embedded DSS/VRI and remains
  byte-deterministic.

## Remaining Blockers

Production B-LT legal sufficiency still needs authoritative revocation-data
acquisition/freshness, responder and certificate-chain validation, TSL/QTSP
policy validation, TSA signature-chain validation, interoperability validation,
multi-signature/existing-DSS merge behavior, and B-LTA archival timestamping.
