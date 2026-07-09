# PAdES B-LT / DSS Local Status

Updated 2026-07-09. This records the implemented local DSS slice and the
remaining production B-LT/B-LTA gaps. It is not a claim of legal long-term
validation.

## Current State

- `chancela-pades` supports PAdES B-B and B-T.
- `chancela-pades` can append a deterministic `/DSS` + `/VRI` incremental
  update from caller-supplied DER certificate, OCSP, and CRL evidence.
- `chancela-pades` can inspect embedded DSS/VRI evidence and report
  certificate, OCSP, CRL, VRI, and evidence hash counts.
- Validation keeps checking the signed revision covered by the signature
  ByteRange while allowing a later DSS incremental update to exist.
- Empty DSS evidence and PDFs that already contain a DSS dictionary are
  rejected in this local slice.
- Higher layers surface embedded DSS/VRI counts and hashes as local technical
  evidence only, not as a production B-LT or legal LTV claim.

## Implemented Local Slice

The implemented slice is fixture-fed and caller-supplied:

- The caller supplies complete DER blobs; Chancela preserves and reports them.
- The PDF layer creates the DSS/VRI objects deterministically in an incremental
  revision.
- Reports distinguish unsigned, B-B, B-T, and B-T plus local DSS evidence.
- Archive evidence can include embedded DSS/VRI counts and hashes when those
  bytes are present.

This proves local evidence attachment/reporting mechanics only. It does not
prove that the revocation material was authoritative, fresh, trusted, or legally
sufficient.

## Tested Coverage

- PAdES round-trip: B-T PDF -> DSS revision -> validates, reports VRI/OCSP/CRL
  counts and evidence hashes, and produces deterministic bytes.
- Signed-revision tamper detection: covered-byte tampering still fails after a
  later DSS revision is appended.
- Guardrails: empty revocation evidence and pre-existing DSS dictionaries are
  rejected instead of silently overclaiming support.
- Signing/API/archive evidence paths report embedded DSS/VRI material as local
  technical evidence.

## Remaining Blockers

Production-grade PAdES B-LT/B-LTA and legal LTV still need:

- live OCSP/CRL acquisition from authoritative sources;
- revocation freshness checks;
- OCSP/CRL responder trust and certificate-chain validation;
- TSL/QTSP policy validation and TSA signature-chain validation;
- merging with existing DSS dictionaries;
- multi-signature VRI handling;
- interoperability validation against external validators;
- B-LTA archive document timestamps (`/DocTimeStamp`) and timestamp renewal
  policy.

Until those gaps are closed, Chancela must describe the implemented feature as
local caller-supplied DSS/VRI preservation and reporting, not production B-LT,
B-LTA, or legal long-term validation.
