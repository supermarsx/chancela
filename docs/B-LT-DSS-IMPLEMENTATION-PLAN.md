# PAdES B-LT / DSS Local Status

Updated 2026-07-09. This records the implemented local DSS slice and the
remaining production B-LT/B-LTA gaps. It is not a claim of legal long-term
validation.

## Current State

- `chancela-pades` supports PAdES B-B and B-T.
- `chancela-pades` can append a deterministic `/DSS` + `/VRI` incremental
  update from caller-supplied DER certificate, OCSP, and CRL evidence.
- Existing DSS dictionaries are merged deterministically: existing evidence
  stream references are preserved, new evidence is deduplicated by SHA-256 of
  the stream content, and the target VRI is keyed from the selected signature.
- DSS/VRI entries can carry `/TU` validation-time metadata supplied by the
  validated revocation path.
- `chancela-pades` can inspect embedded DSS/VRI evidence and report
  certificate, OCSP, CRL, VRI, `/TU`, and evidence hash counts.
- `chancela-signing` has technical CRL+OCSP revocation evidence collection:
  URI discovery, bounded/mocked HTTP transport, CRL freshness/issuer/signature
  checks, OCSP request/response/status/freshness/responder checks, and DSS-ready
  evidence records.
- `chancela-tsa` now covers RFC 3161 token binding plus TSA signer/path
  foundations, while TSL catalog/search surfaces TSA/QTST records and blocking
  analysis.
- Validation keeps checking the signed revision covered by the signature
  ByteRange while allowing a later DSS incremental update to exist.
- Empty DSS revocation evidence is rejected rather than overclaiming support.
- Higher layers surface embedded DSS/VRI counts and hashes as local technical
  evidence only, not as a production B-LT or legal LTV claim.

## Implemented Local Slice

The implemented slice is fixture-fed and caller-supplied:

- The caller supplies complete DER blobs; Chancela preserves and reports them.
- The PDF layer creates the DSS/VRI objects deterministically in an incremental
  revision and merges with existing DSS evidence by content hash.
- The validated revocation provider can collect CRL and OCSP evidence through
  bounded transports and pass validation time through to PAdES `/TU` metadata.
- Reports distinguish unsigned, B-B, B-T, and B-T plus local DSS evidence.
- Archive evidence can include embedded DSS/VRI counts and hashes when those
  bytes are present.

This proves technical evidence attachment/reporting and offline-validation
mechanics only. It does not prove production source configuration, QTSP policy
acceptance, legal long-term validation, or B-LT/B-LTA sufficiency.

## Tested Coverage

- PAdES round-trip: B-T PDF -> DSS revision -> validates, reports VRI/OCSP/CRL
  counts, `/TU` metadata, evidence hashes, and produces deterministic bytes.
- Signed-revision tamper detection: covered-byte tampering still fails after a
  later DSS revision is appended.
- Guardrails: empty revocation evidence is rejected, while pre-existing DSS
  dictionaries are merged/deduplicated instead of overwriting evidence.
- Signing/API/archive evidence paths report embedded DSS/VRI material as local
  technical evidence.

## Remaining Blockers

Production-grade PAdES B-LT/B-LTA and legal LTV still need:

- production OCSP/CRL source configuration and operating policy;
- end-to-end QTSP/TSL policy decisions for the signing and timestamping context;
- multi-signature VRI handling;
- interoperability validation against external validators;
- B-LTA archive document timestamps (`/DocTimeStamp`) and timestamp renewal
  policy.

Until those gaps are closed, Chancela must describe the implemented feature as
local caller-supplied DSS/VRI preservation and reporting, not production B-LT,
B-LTA, or legal long-term validation.
