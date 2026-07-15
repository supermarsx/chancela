# PAdES B-LT / DSS Local Status

Updated 2026-07-15. This records the implemented local DSS/archive-timestamp
slice, the new offline full-chain LTV *verifier*, and the remaining production
B-LT/B-LTA gaps. It is not a claim of legal long-term validation.

## Validation vs. issuance boundary (read first)

Keep two axes crisp:

- **Offline vs. online.** `chancela-pades` is a leaf crate: it verifies only the
  material already embedded in the PDF, with no network and no trust anchors. It
  now offers an offline full-chain LTV *verifier* (see below). The *live*
  population of that material — fetching and validating OCSP/CRL, building the
  signer chain to a live TSL anchor — is done online by `chancela-signing`
  (`dss_collect`) and `chancela-tsl` (LOTL/certpath). `chancela-pades` never
  fetches, never anchors trust, and must not depend on `chancela-tsl`.
- **Validation vs. issuance.** Everything above is *validation*. Qualified
  *issuance* (a private key + qualified certificate, and qualified timestamps)
  remains external to Chancela — it is conferred by a QTSP (via CMD/SCMD, a CSC
  v2 QTSP, or a CC smartcard) and a qualified TSA endpoint, not by this code.

The offline verifier reports embedded LTV *completeness*, not a qualified-status
or legal long-term-validation conclusion.

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
- `chancela-api` exposes
  `POST /v1/acts/{id}/signature/archive-timestamp/append` for an explicit
  caller-supplied RFC 3161 `/DocTimeStamp` token. The API validates the
  existing signed PDF, appends the timestamp as an incremental update, then
  requires the appended document timestamp imprint to bind to the PDF
  ByteRange before persisting updated signed-PDF bytes and digest.
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
- `chancela-pades` now exposes an **offline full-chain LTV verifier**
  (`verify_ltv_offline` -> `LtvVerificationReport`). With no network and using
  only embedded material, it: (a) reuses `validate_pdf_signature` to locate and
  cryptographically verify the signer's own CMS signature and read the embedded
  signer certificate; (b) walks the embedded `/DSS /Certs` and **rebuilds the
  signer certificate chain** by issuer/subject-name plus key-identifier linkage,
  requiring each selected issuer to be a CA, and reports the chain length and
  whether it terminates in a self-issued root **present among the embedded
  certs** (internal consistency + coverage, explicitly **not** a trust-anchor
  claim — anchoring stays online in `chancela-tsl`); (c) confirms each non-root
  link is **covered** by an embedded OCSP response (SHA-256 `CertID` matching the
  link's issuer name/key hash + serial) or CRL (issuer match + serial not
  listed), reporting per-link `uncovered_links`; and (d) verifies the
  `/DocTimeStamp` **renewal chain** is contiguous (each archive timestamp's RFC
  3161 imprint validates over its `/ByteRange`, which covers the prior revision
  including its DSS, and each successive timestamp covers strictly more of the
  file). It does **not** fetch revocation, does **not** cryptographically
  re-verify each CA link's signature, and does **not** anchor trust.

## Implemented Local Slice

The implemented slice is fixture-fed and caller-supplied:

- The caller supplies complete DER blobs; Chancela preserves and reports them.
- The PDF layer creates the DSS/VRI objects deterministically in an incremental
  revision and merges with existing DSS evidence by content hash.
- The validated revocation provider can collect CRL and OCSP evidence through
  bounded transports and pass validation time through to PAdES `/TU` metadata.
- The caller can explicitly append a local archive document timestamp token to
  an existing signed PDF. Chancela validates the resulting `/DocTimeStamp`
  imprint binding and records `B-LTA-local` / `technical_evidence_only` when the
  embedded evidence stack is present.
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
- API archive-timestamp append: caller-supplied valid `/DocTimeStamp` evidence
  is persisted as local technical evidence; stale/mismatched tokens are
  rejected without changing the signed-PDF digest or appending an event; sealed
  acts without a signed PDF return `409`.
- Offline full-chain LTV verifier: a two-level chain (root CA -> CA-issued
  signer leaf) with a complete embedded `/DSS` (chain certs + matching OCSP or
  CRL per link) reports `verified_offline = true` with all links covered; a DSS
  whose embedded OCSP names a different serial reports the signer link in
  `uncovered_links` with `verified_offline = false`; a `/DocTimeStamp` renewal
  over the DSS revision reports a contiguous renewal chain; and a signed PDF with
  no embedded `/DSS` is not verified offline.

## Remaining Blockers

The offline verifier closes the "does the embedded LTV material hang together
offline?" question inside `chancela-pades`. Production-grade PAdES B-LT/B-LTA and
legal LTV still need work that lives **outside** this leaf crate:

- live B-LT *population*: fetching + validating OCSP/CRL and building the signer
  chain to a live TSL anchor (`chancela-signing` `dss_collect` + `chancela-tsl`
  LOTL/certpath), then embedding that material via `add_dss_revision*`;
- production OCSP/CRL source configuration and operating policy;
- cryptographic CA-link signature re-verification and **trust anchoring** to a
  verified LOTL/TSL (online; `chancela-tsl` — deliberately not in the leaf
  verifier);
- end-to-end QTSP/TSL policy decisions for the signing and timestamping context;
- qualified *issuance*: qualified certificate + key and qualified timestamps
  from an external QTSP/TSA (CMD/SCMD, CSC v2, or CC smartcard) — cannot be
  closed in-repo;
- interoperability validation against external validators;
- production B-LTA timestamp renewal policy and provider/trust operating
  controls.

Until those gaps are closed, Chancela must describe the implemented feature as
local caller-supplied DSS/VRI plus `/DocTimeStamp` preservation, reporting, and
**offline embedded-completeness verification** — not production B-LT, B-LTA, live
trust anchoring, or legal long-term validation.
