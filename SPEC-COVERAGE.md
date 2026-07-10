# Chancela - Spec Coverage

*Updated 2026-07-10 through committed implementation snapshot `8f5319fb5166b60ff99f312091ca3ee2868faf56`,
refreshing the `cfcb3d9` baseline and the prior `4566715` coverage point
with commits through that snapshot:
`f312669` remote-signing TSA test isolation, `d9a1891` SBOM package linkage,
`968e4e7` template family metadata drift guards, `6d68052` imported-document
review guardrails, `2da82c2` AMA/CMD evidence-pack check mode, `0ef8447`
missing-attendance dashboard reminders, `225f5c6` external signer identity
evidence requirements, `5021110` AI human-review UI, `21e76a4` web hook lint
hygiene, `d8ab33a` written-resolution evidence advisory, `ec28083` local PAdES
LTV renewal planning, `09af410` retention workflow blockers, and `4566715`
tagged-PDF structural self-checks; then `46d3133` documentation refresh,
`451d618` API-exposed local PAdES renewal planning, `831ad65` attendance/import
guardrail alerts in the web UI, `02f0876` tighter tagged-PDF structural
self-checks, `3f29557` explicit retention review workflow state, `3ba0222`
multi-signature local PAdES renewal-policy modeling, `8082479` clippy-hygiene
cleanup, `0e2953a` local PKCS#12 software-certificate signing, and `4e83180`
repo-level lint/format restoration; then `c0cadf5` web local PKCS#12 signing UI,
`5507f67` TSL XML-DSig hardening, `829c035` bounded retention execution evidence,
`f300e65` notification-popup browser E2E hardening, `696d145` PDF accessibility
self-check depth, `b801d43` SQLCipher key-rotation preflight/evidence,
`dbca58a` XAdES/ASiC structured unsupported-profile diagnostics, `5c4d34f`
erasure DSR preflight evidence, `f281fb8` expanded recent-landed checkpoint
coverage, `0e8f601` imported-document review notification/export browser E2E,
`0a61bce` MCP spec-coverage resource and compliance prompt, `5966a17`
paper-book canonical-conversion preflight evidence, and `270400f` MCP/import
review checkpoint pinning, then `a2099bb` template law-reference UI surfacing
and `13955be` API data key-rotation preflight exposure; then `2d0e2c6`
recent-spec checkpoint pinning, `34ef9d6` web data key-rotation preflight UI,
`af4e8e1` API guardrail acknowledgements, `6138e53` web imported-document
acknowledgement UI, `01768a3`/`58b81cd` storage UI polish, `55203ca`
dashboard subtabs, `dac2178` icon-only notification controls, `4376b34`
desktop database-key protection defaults, and `a168af3` official signed-PDF
handoff import UI; then `c8a8cfe` notification filter icon-only subtabs and
`76f335a` CLI database-encryption key-env parity, `3082721` deeper template
catalog metadata drift checks, and `024cb2a` guarded SQLCipher rekey execution
plus paper-book OCR draft/review UI, then `4f4b093` MCP paper-book OCR review
prompt and `a54b006` browser data-key rotation execution E2E, then `dc7bf0f`
API multi-signature renewal-plan status/reporting, then `779586b` privacy
breach/transfer review-evidence receipts, then `396901f` web multi-signature
renewal-plan evidence surfacing, `c5a72a5` runtime external-validator metadata
attachment for document bundles/archive packages, and `5d183fa` tooltip-backed
subnav overflow arrows, then `de8939d` entity chronology UI plus PDF validator
JSON report copy/save actions, `bae206b` TSL/TSA identifier lookup filters,
`c6b5fe9` chronology/trust lookup checkpoint pinning, `401acad` web TSL/TSA
identifier lookup controls, `fe6ccf8` external-validator report metadata
capture/list API, and `d57c24d` entity chronology plus PDF validator browser
E2E coverage, then `b7ebfd4` durable external-validator report metadata
sidecars, `7ba67eb` static live-provider assurance gating, `2f74edb`
Ferramentas external-validator report metadata management, and `8f5319f`
settings.read-gated raw external-validator technical metadata downloads.
Earlier coverage text remains prior snapshot context. All top-level spec areas remain **PARTIAL**.
This is an implementation and test coverage snapshot, not a legal certification,
not production CMD approval, not DRE verification promotion, not full PDF/UA
delivery, and not a claim that qualified-trust production operation, live
provider validity, provider credentials, authority approval, release
signing/notarization/attestation, live SQLCipher encryption/rotation/migration
across all builds, legal document acceptance, signed-PDF legal validity, or
destructive GDPR erasure is complete.*

Status vocabulary:
**IMPLEMENTED** (landed and verifiable), **PARTIAL** (usable slice landed but
the spec requirement is not complete), **STUB** (shape exists, behavior deferred),
**MISSING** (no implementation), **N/A-v1** (deliberately deferred).

The old exact requirement counts are intentionally not carried forward: the recent
batch changed enough surfaces that the counts need a full line-by-line re-audit before
being useful. The matrix below records the current factual coverage and the remaining
blockers.

Implementation checkpoints covered here:

- `8f5319f` keeps Signatures/Documents **PARTIAL**: `GET
  /v1/external-validator-reports/{case_id}/{validator_family}` now lets
  `settings.read` actors download the validated raw technical metadata JSON for
  one safe external-validator report identity. Unsafe identities, malformed
  persisted sidecars, duplicate report identities, and ambiguous suggested paths
  fail closed; this is technical metadata access only, not legal validity,
  trust-list validation, live provider validity, credentials handling, or
  authority approval.
- `2f74edb` keeps Signatures/Documents/UX **PARTIAL**: Ferramentas now exposes an
  external-validator report metadata panel under the PDF tools surface, with raw
  selected JSON upload to `/v1/external-validator-reports`, redacted list and
  storage/malformed/duplicate summary counts, and client-generated metadata
  summary save actions that omit raw report bytes. This is technical metadata UI
  only, not legal validity, trust-list validation, live provider validity,
  credentials handling, or authority approval.
- `7ba67eb` keeps CI/Architecture **PARTIAL**: `npm run
  check:live-provider-assurance` statically checks that live CMD, CSC/QTSP, TSA,
  and smartcard test seams remain feature-gated, ignored/manual, documented as
  no-CI/operator-controlled, and compiled in CI with `cargo test ... --no-run`.
  This is static/compile-time assurance only, not live provider validity,
  credentials, network/hardware execution, or authority approval.
- `b7ebfd4` keeps Signatures/Documents **PARTIAL**: data-dir mode now persists
  external-validator report metadata as durable sidecars, reloads those sidecars
  after restart, and counts malformed sidecars without trusting or listing them.
  The list response exposes storage, malformed, duplicate-path, and redacted
  summary evidence only; it does not claim legal validity, trust-list validation,
  live provider validity, credentials, or authority approval.
- `d57c24d` keeps Entity/Documents/UX/CI **PARTIAL**: browser E2E now covers
  route-stubbed entity chronology rows, copyable Mermaid graph source, PDF
  validator technical JSON copy/download, and fail-closed refusal paths that hide
  JSON actions. This is focused route-stubbed regression coverage, not exhaustive
  browser coverage, validator authority, or legal validation.
- `fe6ccf8` keeps Signatures/Documents **PARTIAL**: `/v1/external-validator-reports`
  now accepts operator-supplied technical report metadata, validates technical-only
  scope, safe archive paths, lowercase SHA-256 values, and no legal-validity claim,
  and lists redacted metadata summaries. This is runtime metadata capture/listing,
  not durable raw report storage, trust-list validation, legal validity, or a
  qualified-signature decision.
- `401acad` keeps Signatures/Trust/UX **PARTIAL**: Ferramentas TSL/TSA catalog
  controls now expose identifier lookup fields for certificate SHA-256, SKI,
  subject/provider/service/supply-point hints, and TSA/QTST records, passing
  `identifier=` to the existing catalog/search APIs and rendering matched or empty
  states. This is read-only technical lookup UI, not a trust/legal validity
  decision.
- `bae206b` keeps Signatures/Trust **PARTIAL**: TSL/TSA projected records now
  support deterministic technical identifier lookup for complete certificate
  SHA-256 fingerprints, SKIs, subject/provider/service/supply-point hints, and
  TSA/QTST records, with partial or malformed fingerprint-like input returning
  Unknown/no loose inference. Catalog endpoints expose this through
  `identifier=` filters. This is catalog lookup only, not a trust/legal validity
  decision.
- `de8939d` keeps Entity/UX/Documents **PARTIAL**: entity detail pages now expose
  the existing backend chronology endpoint as a localized chronology table plus
  copyable Mermaid graph sources, and the PDF validator can copy or save the
  technical JSON validation report while hiding report actions on fail-closed
  refusals. These are operator visibility/export improvements, not legal
  certification or a broader validator authority claim.
- `5d183fa` keeps UX **PARTIAL**: shared subtab overflow arrows remain icon-only
  and now expose the same accessible names through tooltip labels while still
  hiding unusable edges. This is navigation polish only, not a new workflow.
- `c5a72a5` keeps Signatures/Documents **PARTIAL**: runtime-supplied
  external-validator technical metadata can now be matched to observed canonical
  or signed PDF SHA-256 values, attached to document-bundle evidence indexes, and
  packaged into archive `evidence/external-validators/*.json` members plus
  `evidence/index.json`. Invalid, overclaiming, duplicate-path, traversal, and
  non-JSON metadata is ignored. This is technical metadata preservation only, not
  trust-list validation, legal validity, or a qualified-signature decision.
- `396901f` keeps Signatures/UX **PARTIAL**: the signing panel now surfaces an
  available multi-signature local renewal plan from signature evidence status,
  including signature counts, local evidence gaps, and the next technical action.
  It stays quiet when unavailable and keeps production LTV/legal claims false.
- `1d6ccdc` keeps AI/MCP **PARTIAL**: MCP draft responses now expose explicit
  pending/accepted/rejected human-verification status values, a pending checkpoint
  envelope, and false legal-validity flags. This is metadata for human review, not
  a persisted acceptance/rejection workflow or legal certification.
- `e6517f6` keeps Template Catalog **PARTIAL**: authored catalog tests now validate
  required metadata, duplicate template IDs, rule-pack law-reference anchors,
  derived template law references, and non-blank law-reference fields. This is
  regression coverage for catalog metadata, not legal review or exhaustive statute
  mapping.
- `a6e0cfe` keeps Data/Architecture **PARTIAL**: key-ops status now serializes a
  secret-free backup/export-restore migration plan with evidence and non-destructive
  steps, and startup errors point operators to restoring and verifying the ledger.
  It still does not execute migration, prove encryption, or rotate keys.
- `0d38f92` keeps Legal/Data Lifecycle **PARTIAL**: retention execution requests are
  now persisted to `privacy-retention-executions.json` in data-dir mode and listed
  through `GET /v1/privacy/retention-executions` for privacy-manage actors. They
  remain audit-only records with `would_execute: false`, not deletion, anonymization,
  archival execution, or GDPR erasure.
- `fc0d541` keeps Signatures/Documents/Workflows **PARTIAL**: an external invite
  accept response can include a signed PDF upload that is locally screened for PAdES
  structure, ByteRange coverage, and sealed-PDF prefix match, then preserved as
  `ExternalSignerHandoff` / `ExternalSignedPdfTechnicalEvidence`. Trust-list,
  qualified-signature, and legal-validity claims remain explicitly false/not
  performed.
- `5f55141` keeps Signatures/Documents **PARTIAL**: validator corpus scripts now
  build archive-ready external-validator report evidence metadata attachments and
  an evidence JSON index from recorded sidecars. This is technical report metadata,
  not legal validity, trust-list validation, or a qualified-signature decision.
- `de9302e` keeps Documents/Data **PARTIAL**: imported documents now carry stored
  operator review status, reviewer/time/note metadata, and a review endpoint while
  retaining original bytes. Review records workflow decisions only; they do not run
  OCR, convert to PDF/A, replace canonical documents, or claim legal acceptance.
- `5c15008` keeps Signatures/UX **PARTIAL**: browser E2E now covers an external
  signer invite on an already signed act, proving the public tracking flow does not
  fetch or expose the signed PDF and remains working-copy/tracking-only.
- `c54fc0e` keeps AI/MCP/Architecture **PARTIAL**: MCP now advertises and serves a
  read-only `chancela://mcp/status` resource with operability metadata, no API-key
  material, and no integration API health probe.
- `291dfd2` keeps Documents/Workflows **PARTIAL**: paper-book OCR draft review
  evidence now exposes explicit false `canonical_act_created`,
  `canonical_document_created`, and `signature_created` fields and keeps review
  notes out of ledger payloads. It is OCR-review metadata, not canonical conversion.
- `1a75083` keeps CI/Release **PARTIAL**: `docs/CI-E2E-HARDENING-PLAN.md` was
  refreshed for the then-current CI shape, SQLCipher feature lane, web coverage
  command, and focused MCP status checks. This is planning/checklist coverage, not
  a fresh full-green release claim.
- `fb7d11e` keeps Documents/UX **PARTIAL**: the web document panel can display and
  submit imported-document review status/note updates. It is an operator review UI
  for non-canonical evidence, not OCR, conversion, legal acceptance, or PDF/A
  replacement.
- `7267040` keeps AI/MCP **PARTIAL**: MCP prompt discovery now exposes a static
  `draft_minutes_human_review_checklist` prompt. The checklist is guidance-only,
  accepts no caller arguments, performs no hidden provider calls, does not sign or
  seal anything, and creates no legal validity.
- `696913f` keeps Signatures/Documents **PARTIAL**: archive packages now include
  a technical `evidence/index.json`, document-bundle validation reports now expose
  `validation_report.evidence_index`, and validator-corpus evidence attachments
  describe archive-package and document-bundle indexing metadata. These are
  technical metadata indexes only, not legal validity, trust-list validation,
  qualified-signature validation, DGLAB certification, or authority acceptance.
- `696a887` keeps Documents/UX/CI **PARTIAL**: focused browser E2E now route-stubs
  an imported-document review flow and checks conservative non-canonical evidence
  messaging plus review PATCH behavior. This is regression coverage for the review
  UI contract, not exhaustive browser coverage, OCR, conversion, legal acceptance,
  or PDF/A replacement.
- `8a79478` keeps Data/Documents **PARTIAL**: retained-export cleanup now accepts
  export-only dry-run, minimum-age, and keep-latest guardrails with API regression
  tests, while rejecting those policy options for crash cleanup. These controls are
  retained-export cleanup policy guardrails only; they are not GDPR erasure, legal
  disposal approval, physical deletion guarantees beyond the existing bounded
  cleanup behavior, or complete data-lifecycle automation.
- `9997162` keeps Architecture/Release **PARTIAL**: Docker release-trust metadata
  checks now require stronger production-mode anchors such as image/artifact
  digests, HTTPS workflow/run URLs, signing identity or certificate fingerprints,
  and attestation predicate metadata. This validates declared metadata only; it
  does not verify an actual registry push, image signature, attestation, or release
  trust chain.
- `35f54d6` keeps AI/MCP/Workflows **PARTIAL**: AI-origin draft provenance can be
  persisted on acts, MCP draft tools inject non-authoritative provenance, and the
  TextApproved-to-Signing transition is blocked until a human review decision is
  recorded as accepted. The accepted/rejected state is a durable human-review gate
  only; it is not legal validity, an AI quality assessment, or a full provenance UI
  panel.
- `f312669` keeps Signatures/CI **PARTIAL**: focused remote-signing API tests now
  clear configured TSA providers while exercising legacy TSA URL failure paths, so
  trust-provider isolation is deterministic. This is test hygiene only, not live TSA
  operation or provider certification.
- `d9a1891` keeps Architecture/Release **PARTIAL**: CycloneDX SBOM checks can be
  tied to a release package's path, size, and SHA-256, and CI self-tests the
  package-linkage validator. This is metadata linkage/regression coverage, not a
  signed, attested, notarized, or reproducible release chain.
- `968e4e7` keeps Template Catalog **PARTIAL**: catalog metadata tests now catch
  family drift between template ID prefixes, rule-pack IDs, and signature-policy
  hints. This guards local catalog consistency only; it does not verify legal
  wording, thresholds, or law-source authority.
- `6d68052` keeps Documents **PARTIAL**: imported-document validation, stored views,
  and ledger/review payloads now expose guardrails that original bytes remain
  non-canonical evidence, canonical PDF/A records are not replaced, signed artifacts
  are not created/validated, and OCR/conversion output is not promoted. These are
  review guardrails only, not OCR, conversion, legal acceptance, or signed-import
  validation.
- `2da82c2` keeps Signatures/Compliance **PARTIAL**: the AMA/CMD evidence-pack
  generator has a read-only `--check` mode validating deterministic generated files,
  claim-boundary fields, official-source metadata, placeholder evidence slots, and
  implementation evidence-map file references. The pack remains draft repository
  evidence only, not AMA/SCMD approval or legal certification.
- `0ef8447` keeps Workflows/UX **PARTIAL**: dashboard reminders now surface open
  pre-signing acts dated within the work-queue window that lack an attendance
  reference and either presence counts or structured attendees. The reminder is
  advisory workflow hygiene, not legal-calendar completeness or proof of attendance.
- `225f5c6` keeps Signatures **PARTIAL**: external-signing envelopes can require
  identity-evidence categories such as contact control, provider identity assertion,
  government ID check, or representative capacity before a slot is marked signed.
  These are recorded workflow evidence requirements only; they do not assert legal
  identity, representative authority, qualified status, or legal effect.
- `5021110` keeps AI/UX/Workflows **PARTIAL**: the Ata editor renders AI provenance
  and human-review status, lets authorized operators record accept/reject decisions,
  and disables the move to Signing while AI-assisted text is pending or rejected.
  The UI records the existing human-review gate only; it is not AI-quality review,
  legal certification, or final-minute acceptance.
- `21e76a4` keeps UX/CI **PARTIAL**: the follow-up and imported-document review
  panels were adjusted to clear hook dependency lint warnings. This is lint hygiene
  for existing UI behavior, not new compliance coverage.
- `d8ab33a` keeps Legal/Workflows **PARTIAL**: written-resolution acts now warn
  when no signatory slots or digested attachments are bound as evidence, with Pending
  legal-basis metadata. This is an advisory prompt to retain and bind evidence, not
  threshold proof, participant validation, or legal acceptance.
- `ec28083` keeps Signatures/Documents **PARTIAL**: `chancela-pades` reports a
  local technical LTV renewal plan from already-inspected signature timestamp, DSS
  revocation evidence, `/TU`, and DocTimeStamp imprint signals. It does not fetch
  revocation data, validate trust, decide renewal deadlines, or claim B-LT/B-LTA or
  legal LTV sufficiency.
- `09af410` keeps Legal/Data Lifecycle **PARTIAL**: retention execution records now
  include operator workflow status, blockers, required approvals, and next steps for
  missing/stale/mismatched policies, legal holds, destructive-action requests, and
  manual review. This remains non-executing audit/review evidence with
  `would_execute: false`.
- `4566715` keeps Documents **PARTIAL**: the PDF self-check now validates the
  bounded tagged-PDF structure more deeply, including `MarkInfo`, `StructTreeRoot`,
  `RoleMap`, `ParentTree`, page `StructParents`, MCID coverage, and MCR/ParentTree
  consistency. This is a structural self-check for the local writer shape, not
  PDF/UA certification or broad accessibility validation.
- `46d3133` keeps all top-level areas **PARTIAL**: this tracker was refreshed
  after the prior compliance wave. It changed documentation coverage wording only,
  not implementation status.
- `451d618` keeps Signatures/Documents **PARTIAL**: the API signature validation
  response can surface local technical PAdES renewal-plan evidence from already
  inspected signature/DSS/DocTimeStamp signals. It is local planning metadata only,
  not revocation fetching, trust validation, renewal execution, legal LTV
  sufficiency, or B-LT/B-LTA qualification.
- `831ad65` keeps UX/Workflows/Documents **PARTIAL**: dashboard notifications and
  document-panel UI now surface missing-attendance reminders and imported-document
  guardrail alerts with route actions and localized copy. These are advisory
  operator alerts, not attendance proof, meeting legality, canonical conversion,
  signed-import validation, or legal acceptance.
- `02f0876` keeps Documents **PARTIAL**: tagged-PDF self-checks now also validate
  RoleMap standard-role mappings, struct-element role mapping, and marked-content
  scope rules. This tightens local writer regression checks but still is not
  PDF/UA delivery, accessibility certification, or broad validator conformance.
- `3f29557` keeps Legal/Data Lifecycle **PARTIAL**: retention execution records now
  expose `execution_intent`, `execution_status`, `operator_review_decision`, and
  normalized `audit_evidence`. The records remain review/audit workflow evidence
  only, with no deletion, anonymization, retention execution, legal disposal
  approval, or GDPR erasure.
- `3ba0222` keeps Signatures/Documents **PARTIAL**: `chancela-pades` can model
  per-signature local renewal gaps, DSS VRI/TU inputs, and caller-supplied renewal
  deadline classification across multiple PDF signatures. This is local planning
  from supplied policy and observed technical evidence only; it does not infer legal
  deadlines, fetch revocation material, validate trust, execute renewal, or claim
  PAdES B-LT/B-LTA sufficiency.
- `8082479` keeps Architecture/CI **PARTIAL**: current clippy warnings were cleared
  in API, document self-check, trust, recovery, and related code paths. This is
  maintainability hygiene, not new compliance scope or release assurance.
- `0e2953a` keeps Signatures/Documents **PARTIAL**: the API now exposes a desktop
  local PKCS#12/PFX software-certificate signing flow for sealed acts, using
  transient PFX/passphrase inputs, persisting the signed PDF plus public certificate
  evidence, and labelling the result as `AdvancedLocalTechnicalEvidence`. It is
  advanced local technical evidence only, with no trusted-list lookup, qualified
  remote/CMD status, legal qualification, or production qualified-signature claim.
- `4e83180` keeps Architecture/CI **PARTIAL**: repo-level rust lint, web lint, and
  format checks were restored to green by removing stale clippy lifetime/format
  warnings and applying Prettier to already-existing web files. This is
  maintainability hygiene, not implementation of a new product/legal requirement.
- `c0cadf5` keeps Signatures/UX **PARTIAL**: the web signing panel now exposes the
  local PKCS#12/PFX software-certificate flow backed by the API endpoint, keeps
  PFX/passphrase inputs transient, labels the result as local technical evidence,
  and carries localized copy plus SigningPanel/i18n regression tests. This is UI
  access to advanced local evidence only, not CMD, qualified remote signing, or a
  legal-validity claim.
- `5507f67` keeps Signatures/Trust **PARTIAL**: TSL XML-DSig validation now
  fail-closes on malformed base64, unsupported signature/canonicalization/transform
  metadata, multiple references, digest tampering, `SignedInfo` tampering, and
  signature-value tampering, with `TslClient` downgrade coverage. It verifies only
  the supported minimal RSA-SHA256 shape against the embedded signer certificate;
  signer trust anchoring, certificate path/revocation policy, complete C14N, ECDSA,
  and `URI="#id"` references remain incomplete.
- `829c035` keeps Legal/Data Lifecycle **PARTIAL**: retention execution requests can
  now record bounded archive/no-action execution evidence with target evidence,
  approval metadata, idempotent repeat detection, acted/skipped targets, reason
  codes, and persisted history. Destructive delete/anonymize and full GDPR erasure
  remain blocked and explicitly false.
- `f300e65` keeps UX/CI **PARTIAL**: browser E2E now covers notification popup
  portal/z-index placement, outside-click closing, action routing to Arquivo, and
  read-state/count updates. This broadens focused browser coverage but is not an
  exhaustive UX matrix.
- `696d145` keeps Documents **PARTIAL**: the local PDF writer/self-check now emits
  and validates catalog `/ViewerPreferences /DisplayDocTitle true`, page `/Tabs /S`
  structure-order navigation, UTF-8 `/Lang`, and XMP title/language consistency.
  `pdf_ua_claimed` remains false; this is not PDF/UA certification.
- `b801d43` keeps Data/Architecture **PARTIAL**: `chancela-store` now exposes a
  secret-free SQLCipher key-rotation preflight and feature-gated rekey execution
  evidence with post-rekey integrity checking. It does not execute plaintext
  migration, expose keys, or prove production at-rest encryption on this build.
- `dbca58a` keeps Signatures **PARTIAL**: XAdES signing/validation and ASiC-XAdES
  containers now fail with structured `UnsupportedSignatureProfile` evidence, and
  ASiC profile inspection reports bounded CAdES candidates plus unsupported member
  blockers. XAdES/ASiC-XAdES generation and validation remain unimplemented.
- `5c4d34f` keeps Legal/Data Lifecycle **PARTIAL**: erasure DSR completion now
  records immutable-ledger blockers, mutable-sidecar preflight plans, idempotency
  behavior, and explicit false destructive/full-erasure flags. It is preflight
  evidence only; no redaction, anonymization, deletion, or full erasure is executed.
- `f281fb8` keeps Architecture/CI **PARTIAL**: the recent-landed checkpoint now
  runs focused paper-import, archive evidence, local PKCS#12, bounded retention,
  TSL XML-DSig, web dashboard/signing/i18n, validator-corpus, and desktop lockfile
  checks. This is focused regression coverage, not an exhaustive release gate.
- `0e8f601` keeps UX/Documents **PARTIAL**: browser E2E now covers a dashboard
  imported-document review notification, navigation to the act, conservative review
  submission, notification dismissal, and canonical PDF export staying on the act
  document endpoint rather than imported bytes. This is one focused regression, not
  broad imported-document workflow coverage.
- `0a61bce` keeps AI/MCP **PARTIAL**: MCP now exposes a local
  `chancela://mcp/spec-09-coverage` resource and a static
  `compliance_pack_gap_review` prompt for DSR/retention/archive/signature evidence
  review. Both are offline/no-secret/no-provider-call guidance surfaces, not AI
  quality, legal-validity, or provider readiness claims.
- `5966a17` keeps Documents/Workflows **PARTIAL**: paper-book import validation and
  preservation reports now include canonical-conversion preflight evidence with
  `not_attempted`/`blocked`/`allowed` status, named blockers, and explicit false
  canonical/signature/legal-validity flags. It does not run OCR, create canonical
  acts/documents, sign artifacts, or accept legacy paper evidence legally.
- `270400f` keeps Architecture/CI **PARTIAL**: the recent-landed checkpoint now also
  pins MCP resource/prompt tests, paper-import preflight markers, and static browser
  markers for imported-document review notification/export coverage. Browser E2E
  execution remains in the browser lane; this is still focused checkpoint coverage.
- `a2099bb` keeps Template Catalog/UX **PARTIAL**: the Minutas web catalog now
  searches and renders bounded `law_references` with source/citation/article
  metadata, Pending/Verified badges, and a caveat for pending references. This is
  operator traceability, not legal verification or exhaustive statutory mapping.
- `13955be` keeps Data/Architecture **PARTIAL**: the API now exposes
  `POST /v1/data/key-rotation/preflight` as a `settings.manage@Global`-gated,
  secret-free, read-only readiness check over the store-level SQLCipher
  key-rotation preflight. It does not execute rotation, expose key material,
  provide a completed UI workflow, or migrate plaintext stores.
- `2d0e2c6` keeps Architecture/CI **PARTIAL**: the recent-landed checkpoint and
  CI notes were pinned to the then-current spec-tracker additions. This is
  focused regression selection and documentation only, not a full release gate or
  certification claim.
- `34ef9d6` keeps Data/UX **PARTIAL**: Data Management now exposes a web
  data-key rotation preflight that submits replacement-key material only to the
  read-only API preflight, renders returned readiness/evidence, and clears
  entered secrets after success or failure. It still does not execute key
  rotation, migrate plaintext stores, prove production SQLCipher encryption, or
  persist submitted keys.
- `af4e8e1` keeps Documents/Signatures/Legal **PARTIAL**: imported-document
  terminal review transitions and official signed-PDF handoff imports now require
  explicit guardrail acknowledgements before recording conservative review or
  technical signed-artifact evidence. The acknowledgements record operator
  awareness of boundaries only; they do not create canonical records, validate
  legal signature status, or complete legal acceptance.
- `6138e53` keeps Documents/UX **PARTIAL**: the web document panel now displays
  imported-document canonical/signed-artifact guardrails and disables terminal
  review submission until the operator acknowledges the required checklist. This
  is UI enforcement for preservation boundaries, not OCR, conversion, PDF/A
  replacement, signed-import validation, or legal acceptance.
- `01768a3`/`58b81cd` keep UX/Data **PARTIAL**: the Data Management storage view
  now separates filesystem and SQLite logical usage, tightens storage-breakdown
  rows, and keeps permission/status probes readable. This is storage UI polish and
  does not broaden cleanup, deletion, migration, encryption, or retention
  execution semantics.
- `55203ca` keeps UX/Workflows **PARTIAL**: the dashboard is split into Stats,
  Activity, Current, Queue, and Events subtabs with localized labels, preserving
  existing reminder/activity/archive evidence while improving scanability. It
  does not add legal-calendar completeness, attendance proof, archival proof, or
  broader dashboard workflow depth.
- `dac2178` keeps UX **PARTIAL**: notification popup/list action controls are now
  icon-only buttons with accessible names and tooltip labels, covered by focused
  web tests. This is ergonomics/accessibility polish for existing triage actions,
  not new notification semantics or workflow completion proof.
- `4376b34` keeps Data/Architecture/Desktop **PARTIAL**: SQLCipher-enabled
  desktop builds now default to a fresh random SQLCipher key protected by the
  current-user OS provider, DPAPI on Windows, with explicit
  `CHANCELA_DB_KEY`/`CHANCELA_DB_KEY_FILE` overrides still available. Durable
  non-SQLCipher desktop startup fails closed unless
  `CHANCELA_DESKTOP_ALLOW_PLAINTEXT_DB=1` is set for an explicit local
  development/no-SQLCipher run. This does not prove this host's SQLCipher
  feature lane, execute plaintext migration, or complete production at-rest
  encryption operations.
- `a168af3` keeps Signatures/UX **PARTIAL**: the web signing panel can import a
  PDF already signed through an official Autenticacao.gov/provider handoff by
  submitting the signed PDF plus optional client-declared provider/source
  context after guardrail acknowledgement. It collects no PIN, OTP, credential,
  or passphrase, and stores technical signed-PDF evidence only; it does not
  perform trust-list validation, claim qualified status, or complete legal
  signing acceptance.
- `c8a8cfe` keeps UX **PARTIAL**: notification-page filter subtabs can render as
  icon-only controls with accessible names and tooltip labels, and the page test
  now pins the absence of visible filter labels. This is navigation polish only,
  not a new alert/workflow semantic.
- `76f335a` keeps Data/Architecture **PARTIAL**: the CLI now resolves
  `CHANCELA_DB_KEY` / `CHANCELA_DB_KEY_FILE` through the same database-encryption
  config path as server startup and fails closed without SQLCipher instead of
  creating a plaintext store when keyed env vars are configured. It adds CLI
  tests for direct keys, key files, ambiguous sources, and secret non-leakage,
  but it does not prove live SQLCipher on this host, execute plaintext migration,
  or expose a production key-rotation operation.
- `3082721` keeps Template Catalog **PARTIAL**: local catalog metadata tests now
  also catch template-id/asset-stem drift, missing `/vN` suffixes, empty authored
  blocks, id-derived stage drift, duplicate/out-of-order channels, and scoped
  channel drift. This is local catalog consistency only, not legal review of
  template text, thresholds, channels, or cited law.
- `024cb2a` keeps Data/Architecture/Documents/Workflows/UX **PARTIAL**: the API
  now exposes a guarded `POST /v1/data/key-rotation` SQLCipher rekey execution
  for already-open keyed durable stores, with interactive-session
  `settings.manage` gating, plaintext-store refusal, and secret-free evidence
  surfaced in Data Management. The web book detail page also lists, creates, and
  reviews preserved paper-book OCR drafts as auxiliary non-canonical metadata,
  with contract and focused UI coverage. This is not live host SQLCipher proof,
  plaintext migration, OCR execution, canonical conversion, a signature, or legal
  acceptance.

---

## Current Status By Spec

| Spec area | Status | Current working-tree coverage | Remaining local work | External / legal blockers |
|---|---|---|---|---|
| spec/01 Product Scope (SCP) | PARTIAL | One Rust core still drives server, web, Docker, and Tauri desktop. Durable mode exists through `CHANCELA_DATA_DIR`; in-memory mode is explicit on `/health`, and Settings now exposes storage mode/data-folder/usage telemetry from `/v1/data/status` plus bounded crash-report/retained-export cleanup through `/v1/data/cleanup`. | Mobile companion remains deferred; edition packaging still needs signed/notarized publication hardening. | None specific. |
| spec/02 Legal & Compliance (LEG) | PARTIAL | Compliance gates, rule-pack failures with structured legal-basis references, written-resolution evidence advisories with Pending legal-basis metadata, DRE/EUR-Lex law corpus authenticity gating, legal-threshold placeholders, bounded template law-reference exposure from rule-pack IDs and threshold references, bounded corpus citation resolution that preserves Verified/Pending status, recovery/audit trails, step-up controls, delegation evidence fields, required guardrail acknowledgements for imported-document terminal review and official signed-PDF handoff imports, guest/minimal redaction for entity/registry/book/act/imported-document metadata reads, backend DSR user export, tracked DSR request lifecycle with data-dir JSON durability, erasure DSR preflight evidence with immutable-ledger blockers, mutable-sidecar plans, idempotency guard, and explicit false destructive/full-erasure flags, bounded DSR execution evidence, user-management DSR UI, processor/DPIA compliance registers, privacy breach-playbook and transfer-control registers with settings UI and data-dir JSON durability, non-executing breach review/drill and transfer-control review evidence receipts with false authority-notified/subjects-notified/transfer-approved/data-transfer-executed flags, a persisted retention-policy register with non-destructive dry-run reports, persisted/listable audit-only retention execution-request evidence with review-only intent/status fields, operator decisions, blockers/required approvals/next steps, and guarded non-destructive archive disposal execution evidence with ledger audit exist. DRE-sourced law, copied corpus citations, template law references, imported-document acknowledgements, official handoff acknowledgements, and privacy review receipts remain Pending/fail-closed legal boundaries unless authoritative evidence and legal review are present. | Actual physical deletion, destructive/automated GDPR erasure beyond preflight/evidence, mutable-sidecar redaction/anonymization execution, complete per-family legal packs, privacy/redaction/data lifecycle coverage beyond the current read-redaction, register, and review-receipt slices, broader incident/notification/transfer-control automation beyond non-executing review receipts, broader retention/disposal policy automation beyond the current blocker/approval/next-step evidence, written-resolution evidentiary capture beyond warning prompts, exhaustive/verified template/citation law mapping, and legally verified threshold values remain local product work. | Authoritative DRE text/PDF access is needed to mark PT law corpus entries Verified; legal review is needed before replacing threshold placeholders with numbers or treating template/citation references as complete/authoritative. |
| spec/03 Entity Profiles (ENT) | PARTIAL | Five families are modeled; profile/rule-pack binding exists, statute overlays feed compliance findings, bounded capital/permilage weighted tally and quorum consistency checks exist where complete attendance weights are captured, condominium data-quality warnings catch missing meeting time, contradictory attendance counts, and impossible permilagem values/totals, template assets now cover commercial companies, condominiums, associations, foundations, and cooperatives across many stages, and entity detail pages can display imported-registry chronology events plus copyable Mermaid graph sources from the backend chronology endpoint with focused browser E2E coverage. | Deeper family-specific rule packs, groups, legally exhaustive weighted-voting policies, broader calendar preset depth, and richer chronology visualization beyond technical table/source display remain incomplete. | Legal review of non-CSC packs and thresholds. |
| spec/04 Signatures & Trust (SIG) | PARTIAL | CMD, CC, generic CSC remote-signing, local soft-cert/PKCS#12 provider status, and a desktop-gated local PKCS#12/PFX software-certificate signing flow are exposed in the signing/API layers; PAdES/CAdES signing, bounded single-payload ASiC-S/CAdES container creation and validation, bounded ASiC-E/CAdES manifest container creation and validation for payload digest binding, ASiC profile inspection for bounded CAdES candidates and unsupported member-shape blockers, structured `UnsupportedSignatureProfile` diagnostics for direct XAdES and ASiC-XAdES, signed-document persistence, provider listing/status metadata, TSL XML-DSig validation/catalog status/search plus strict identifier lookup for complete certificate SHA-256 fingerprints, SKIs, subject/provider/service/supply-point hints, and TSA/QTST records, TSA diagnostics/search plus Ferramentas TSL/TSA identifier lookup controls, B-T timestamping when configured, local PAdES DSS/VRI append/reporting with existing-DSS merge/dedupe and `/TU` metadata, DocTimeStamp parsing/imprint evidence in signature/archive reports, local PAdES LTV renewal-plan reporting from already inspected technical evidence including API exposure, multi-signature local renewal-plan reporting in arbitrary-PDF validation, act signature status, and web signing evidence UI, per-signature DSS/VRI coverage and local evidence gaps, and caller-supplied deadline classification, a gated local arbitrary-PDF/PAdES validation endpoint with Ferramentas UI and focused browser E2E for JSON copy/download fail-closed behavior, additive settings for multiple TSL sources and TSA providers, operational selection of configured TSL/TSA providers in trust refresh/catalog, signing trust-policy selection, and timestamping selection/reporting, external-validator corpus sidecars with strict technical-only status transitions, raw-report preservation metadata, archive-ready evidence attachment metadata projection, validator-corpus evidence-indexing metadata for archive package `evidence/index.json` plus document-bundle `validation_report.evidence_index`, runtime external-validator technical metadata attachment into archive package members/`evidence/index.json` plus document-bundle indexes when metadata matches observed canonical/signed PDF hashes, `/v1/external-validator-reports` capture/list APIs for operator-supplied technical metadata summaries, and `GET /v1/external-validator-reports/{case_id}/{validator_family}` settings.read-gated raw technical metadata downloads that fail closed for unsafe, malformed, duplicate, or ambiguous identities, technical timestamp-trust diagnostics with persistence when validator inputs are available, technical CRL+OCSP revocation evidence collection, API/archive embedded DSS/VRI reporting, precise local B-LT/B-LTA technical evidence status with legal flags kept false, signature evidence status reporting/UI, fail-closed trust checks with CMD/CC/TSA failure-matrix tests and isolated legacy-TSA provider fixtures, external-signer invitation tracking/UI, token lookup/respond safe working-copy access, optional signed-PDF upload on accepted invite responses stored as `ExternalSignerHandoff` / `ExternalSignedPdfTechnicalEvidence`, official signed-PDF handoff import guardrail acknowledgements plus a web upload flow before technical signed-artifact evidence is recorded, with no PIN/OTP/passphrase collection, gated external-signing envelope APIs with required identity-evidence categories, a Ferramentas external-signing workflow tool with redacted invite listings, status summaries, same-origin token-link handling, public envelope lookup, browser E2E proving signed-invite tracking does not expose signed PDFs, and a generated AMA/CMD evidence-pack scaffold plus read-only pack check mode with no-approval-claim templates are present. | SCAP attributes, XAdES generation/validation, ASiC-XAdES execution beyond structured unsupported diagnostics, ASiC-E profiles beyond the bounded single-manifest CAdES digest-binding path, multiple ASiC-E signatures/manifests/extensions beyond structured blockers, production/legal PAdES or ASiC B-LT/B-LTA completion or claim, embedded LT/LTA evidence, policy-driven local LTV renewal execution or legally derived deadline decisions, external-signer legal/qualified completion beyond invite/uploaded signed-PDF and workflow identity-evidence records, official signed-PDF handoff legal completion beyond technical upload/import evidence and acknowledgements, multi-signature VRI/archive timestamp renewal execution depth beyond local planning/reporting, broader durable/raw operator capture/storage of real external-validator reports beyond the validated technical metadata capture/list/download boundary, broader provider-management policy automation and trust-list lookup UI depth beyond current catalog/search/identifier surfaces, controlled live provider/hardware integration depth, and production AMA/CMD authority approval remain incomplete. API signing, arbitrary-PDF validation, local PKCS#12/PFX signing, external-signing workflow tracking/uploaded evidence, official signed-PDF handoff imports, external signer identity evidence requirements, PAdES LTV renewal plans including multi-signature local renewal reports, validator report evidence metadata/indexing and capture/list/download APIs, archive package `evidence/index.json`, document-bundle `validation_report.evidence_index`, ASiC profile reports, TSL/TSA identifier lookup, and AMA/CMD evidence-pack generation/checking are technical/operational evidence flows, not claims that every seal, uploaded PDF, invite response, official handoff, ASiC container, validator report, evidence index, identity assertion, renewal plan, local software-certificate signature, trust-list match, or CMD integration is qualified/legal-valid, trust-list validated, or authority-approved. | Live CMD requires AMA/SCMD credentials, prod cert, and authority onboarding/approval. Live CSC/QTSP requires provider onboarding and credentials. CC requires card, reader, and Autenticacao.gov middleware. Production TSL/TSA/revocation use requires production network configuration, valid source material, and policy/legal review; path-backed TSA providers and unsupported timestamp digests block deterministically rather than falling back to fake live signing. |
| spec/05 Data Model / Roles (DAT/ROL) | PARTIAL | SQLite-backed durable store, multi-chain ledger, recovery/degraded mode, data-folder permission/usage telemetry with SQLite logical usage estimates including privacy retention-execution sidecars, secret-free database key-ops status/preflight for key config, build capability, database-header format, plaintext-to-encrypted migration refusal, structured non-destructive export/restore migration-plan guidance, secret-free store/API SQLCipher key-rotation preflight evidence with a web Data Management preflight UI that clears submitted secrets, a `settings.manage` + interactive-session guarded API/web SQLCipher rekey execution path for already-open keyed stores that refuses plaintext stores and returns only secret-free execution evidence, feature-gated store rekey execution evidence without key serialization, SQLCipher-enabled desktop default key resolution through a fresh random key protected by the current-user OS provider, DPAPI on Windows, while non-SQLCipher desktop durable startup fails closed unless `CHANCELA_DESKTOP_ALLOW_PLAINTEXT_DB=1` is explicitly set for a local development/no-SQLCipher run, and CLI durable-store commands now honor `CHANCELA_DB_KEY` / `CHANCELA_DB_KEY_FILE` through the same key config path while failing closed without SQLCipher and without leaking key material, plus `settings.manage`-gated maintenance cleanup for crash reports and retained exports, users, complete seeded role catalog, scoped RBAC, delegations with `starts_at`/`legal_basis`, sessions, API-key principals, guest/minimal read redaction for entity, registry, book, act, and imported-document metadata, step-up re-auth, password/recovery controls with hardened verifier-storage regression tests, retention execution records with review-only intent, workflow status, operator review decision, blockers, required approvals, and normalized audit evidence, breach/transfer review receipts embedded in privacy sidecars with audit events and sensitive-note/false-completion rejection, erasure DSR preflight evidence with false full-erasure flags, and guarded non-destructive archive disposal execution evidence with ledger audit are implemented. | Tenant/group model, broader privacy/redaction lifecycle beyond read-response redaction and erasure preflight, live SQLCipher/at-rest DB encryption proof on this host, production encryption migration/export-restore workflow, plaintext-to-encrypted migration execution, production key-secret update/rotation runbooks beyond the current already-open-store rekey execution, ZK, sync/connectors, actual physical deletion, broader retention/disposal and incident/transfer control automation beyond recorded blockers/manual-review evidence, GDPR erasure execution, and complete data lifecycle policies remain. | None specific beyond legal review for access/redaction policies. |
| spec/06 Workflows (WFL) | PARTIAL | Book/act lifecycle, sealing with structured rule-pack/profile metadata and explicit UI acknowledgement before sealing non-blocking compliance warnings, written-resolution missing-evidence advisories, retification, document generation, closed-book read-only enforcement for pre-existing act patch/advance/seal/archive/convening-dispatch mutations, convening `evidence_reference` capture in act editing/patching, qualified-signature status, dashboard data organized into subtabs for fiscal-year-aware profile-derived annual-calendar reminders with i18n-backed alert copy, actionable open-follow-up reminders, missing-attendance work-queue reminders for open pre-signing acts with notification routes, compact activity summaries, recent events, and active legal-hold/sealed-not-archived archive lifecycle alerts with advisory next steps, imported-document terminal review transitions gated on guardrail acknowledgement, backup/restore, book import/export, historical paper-book validation plus non-canonical preservation/list/download with source page/original-number range metadata, continuation recommendations, canonical-conversion preflight evidence with explicit false creation/legal-validity flags, paper-book OCR draft list/create/review UI for auxiliary non-canonical metadata with acknowledgement copy and false canonical/signature/legal flags, start-over/reset workflows, bounded external-signer invite links with token-gated safe working copies, external-signing envelope identity-evidence requirements, accepted-invite signed-PDF technical evidence upload, and official handoff signed-PDF technical import from the signing panel are present. | Full legal-calendar preset depth, OCR execution and reviewed canonical conversion execution workflows beyond auxiliary OCR draft metadata/preflight evidence for preserved paper-book packages, external signer legal/qualified completion beyond technical evidence upload and identity-evidence records, official signed-PDF handoff legal completion beyond guardrailed technical import, richer dashboard feeds beyond the current subtabs/reminders/activity/archive lifecycle/attendance alert slices, actual attendance proof beyond advisory reminders, and family-specific workflow depth remain. | Provider credentials for live qualified signing. |
| spec/07 Architecture (ARC) | PARTIAL | Durable store, hot backup/restore, encrypted backup envelopes, recovery mode, `/api/v1` integration alias with JSON 404 namespace guards, persisted API-key lifecycle with bearer principal resolution, HTTP rate limiting, and attenuation tests for creator downgrade/deactivation/scope loss, MCP stdio server with tools, resources, static prompt discovery, a secret-free `chancela://mcp/status` operability resource, and a local `chancela://mcp/spec-09-coverage` coverage-boundary resource, platform service status/control endpoints with settings-backed API/MCP desired state, strict app/API/MCP log-level policy, audit tail, `/v1/platform/logs?service_id=&level=&tail=` for a bounded API-owned structured platform log tail gated by `settings.read`, data-dir persistence to `platform-logs.json` when `CHANCELA_DATA_DIR` is configured with a 512-entry bound and in-memory fallback otherwise, structured log entries from platform service status/control paths, honest supervisor/restart-required outcomes, data status/cleanup endpoints, Docker build/runtime smoke, persistent container data path, hardened Docker Compose deployment profiles, release version-consistency guard, tag/manual package-artifact workflow, package manifests/checksums with package artifact integrity checking, release-trust metadata validation for package declarations and local/production Docker declarations with stricter production Docker metadata anchors, package `sourceProvenance` manifest validation against current `HEAD`, web unit-test coverage thresholds in CI, web hook-dependency lint hygiene for follow-up/import-review panels, CI dependency SBOM generation/checking with release-package path/size/SHA-256 linkage and self-tests, report-only npm/Cargo/Docker vulnerability artifacts with an enforced manual mode, Docker OCI metadata/security artifacts, a documented SQLCipher Windows feature lane, feature-gated SQLCipher keyed-open foundation, optional `CHANCELA_DB_KEY` / `CHANCELA_DB_KEY_FILE` startup wiring that fails closed when unsupported/invalid for API and CLI durable-store opens, secret-free key-ops status with operator action text and startup refusal for direct plaintext-to-encrypted keyed open, structured export/restore migration-plan guidance, secret-free store/API/web key-rotation preflight plus a guarded API/web rekey execution route for already-open keyed stores and feature-gated SQLCipher rekey evidence, SQLCipher-enabled desktop embedded API default key resolution through an OS-protected random key with a fail-closed non-SQLCipher plaintext dev opt-in, an expanded recent-landed checkpoint for PKCS#12, official signature guardrail acknowledgements, desktop encryption provider markers, retention, TSL hardening, MCP resource/prompt coverage, recovery/document/dashboard/notification UI coverage, imported-document, data-key-rotation, and entity chronology/PDF-validator static browser markers, trust identifier UI markers, external-validator metadata API tests, validator corpus, CLI encrypted-key environment coverage, and desktop lockfile checks, and Tauri desktop shell are in tree. | Sync, storage connectors, HA profiles, real supervisor-backed API/MCP process lifecycle, supervisor-forwarded MCP process logs, historical stdout/stderr tailing, broader durable/live structured log sinks and reload/process logging beyond the API-owned tail, live SQLCipher encryption verification on this host, executed plaintext-to-encrypted migration/export-restore flow, production operator key-secret rotation/update workflows beyond current already-open-store rekey execution, sidecar encryption strategy, repo-level ZK, coverage thresholds beyond web unit tests, broader browser E2E coverage, live provider/hardware integration tests beyond compile-only seams, actual release signing/notarization, actual Docker image signing/attestation and registry-publication verification beyond SBOM/package metadata-anchor checks, production-grade HA/orchestration profiles, and mobile builds remain. | SQLCipher feature verification on this Windows host is blocked by vendored OpenSSL requiring a Windows-compatible Perl rather than the available Cygwin Perl. |
| spec/08 Documents & Archive (DOC) | PARTIAL | Template rendering, frozen `DocumentModel`, deterministic PDF/A-2u writer with embedded fonts and ToUnicode maps, conservative accessibility/PDF-UA blocker reporting without false PDF/UA identification, report-side alt-text/decorative metadata modeling, minimal tagged PDF structure with MCIDs, `StructTreeRoot`, `RoleMap`, `ParentTree`, page `StructParents`, structure-order `/Tabs /S`, catalog `/ViewerPreferences /DisplayDocTitle true`, `MarkInfo` true, artifact marking, XMP title/language consistency checks, and deeper structural self-checks for ParentTree/MCID/MCR consistency plus RoleMap/marked-content scope validation, seal/book document generation, render-context exposure for convening `evidence_reference`, document bundle endpoint with structured technical validation reports for consistency/fixity/canonical-PDF/signed-document evidence, `validation_report.evidence_index`, and explicit non-certification flags, signed-document endpoint, external-invite uploaded signed-PDF technical evidence and official handoff imported signed-PDF technical evidence served through the signed-document path, Arquivo PDF/A export from ledger filters, working-copy Markdown/TXT/HTML/RTF/ODT/DOCX exports with API matrix coverage and browser export/save E2E coverage, read-only candidate import validation with fixity, preservation-review policy metadata and explicit canonical-record/signed-artifact/OCR-promotion guardrails for imported-document candidates and stored imported documents, persisted imported-document operator review state/notes with required guardrail acknowledgements for terminal review transitions, web review controls, acknowledgement UI, and guardrail alerts that retain original bytes only, focused browser regression coverage for conservative imported-document review messaging/PATCH behavior plus notification-to-review/canonical-export behavior, legacy DOC/OLE-CFB recognition, signed-PDF/PAdES structural status, local arbitrary-PDF signature validation for structure/ByteRange/PAdES/DSS/DocTimeStamp evidence plus local technical LTV renewal-plan reporting, multi-signature local renewal-plan reports, caller-supplied deadline classification, and focused browser E2E for PDF validator JSON copy/download fail-closed behavior, persisted non-canonical imported-document evidence including legacy DOC bytes with retained bytes/metadata-only ledger events and UI, expanded imported-document evidence families, guest redaction for imported-document filename/digest/importer/download metadata, web pre-persistence import validation evidence/refusal findings for legacy DOC/OLE-CFB candidates, historical paper-book validation plus persisted non-canonical package preservation/list/download with source page/original-number range metadata, canonical-conversion preflight evidence, paper-book OCR draft metadata and web review UI with explicit false canonical/signature/legal fields plus a contract fixture for the draft shape, retained-export maintenance cleanup with export-only dry-run/minimum-age/keep-latest guardrails, deterministic internal preservation ZIPs with archive evidence reports including DocTimeStamp/imprint evidence and a technical archive package `evidence/index.json`, archive package tamper-failure tests, validator corpus raw-report sidecar preservation metadata, evidence attachment metadata projection, evidence-indexing metadata, runtime external-validator technical metadata attachments that are matched by observed PDF SHA-256 and packaged/indexed with traversal/overclaiming/duplicate-path guards, `/v1/external-validator-reports` capture/list APIs for redacted technical metadata summaries, and `GET /v1/external-validator-reports/{case_id}/{validator_family}` settings.read-gated raw technical metadata downloads that fail closed for unsafe, malformed, duplicate, or ambiguous identities, inventory preflight/self-validation, DGLAB-aligned internal preservation metadata with explicit non-certification flags, export-time legal-hold marking, persisted book-level legal hold, disposal eligibility/dry-run status, dashboard archive lifecycle alerts for active holds and sealed-not-archived acts, and guarded non-destructive disposal execution evidence are implemented. | Deeper imported-document preservation review workflow beyond the current status/note decisions, acknowledged guardrail checklist, and focused browser regressions, OCR execution, full PDF/UA delivery beyond minimal tagged structure and bounded structural self-checks including semantic role coverage, complete non-text alt/decorative coverage, and external validator certification, richer structure trees/tagging/role maps/marked artifacts, canonical conversion/PDF/A generation beyond preflight evidence or legal acceptance for legacy DOC/paper-book evidence, production/legal signed-import validation beyond local structural/PAdES checks and technical uploaded/imported evidence, policy-driven PAdES LTV renewal execution beyond local single/multi-signature planning reports, durable/full operator capture/replay of real external-validator reports beyond current validated technical metadata capture/list/download APIs, official DGLAB interchange/certification, retained-export policy depth beyond the current cleanup guardrails, actual physical deletion, broader disposal/retention policy automation, GDPR erasure linkage, and legal acceptance/certification remain incomplete. | Legal review of generated template content/thresholds. |
| spec/09 AI & MCP (AI) | PARTIAL | MCP server and API bridge exist, with tools mapped to `/api/v1` including Mermaid chronology, working-copy, archive package, ledger archive, trust catalog, law tools, exact AI-11 `prepare_archive_export` and `validate_signature_bundle` tools, `draft_minutes`, and AI-11 compatibility aliases (`list_companies`, `get_company_timeline`, `search_legal_texts`); live API bearer tests cover the bridge. MCP now requires both the local MCP switch and a tenant AI gate (`settings.ai.enabled` / `CHANCELA_AI_ENABLED`), advertises tools/resources/prompts, exposes a secret-free `chancela://mcp/status` resource, exposes a local `chancela://mcp/spec-09-coverage` resource with AI-10/11/12 coverage boundaries, exposes static `draft_minutes_human_review_checklist` and `compliance_pack_gap_review` prompts, and exposes `paper_book_ocr_canonical_review` for paper-book OCR/canonical-conversion evidence review; these prompts accept no arguments and perform no hidden calls. Draft tools return an explicit non-authoritative `ai_draft` provenance envelope with top-level `source_provenance`, statement-source entries, human verification required, allowed pending/accepted/rejected checkpoint vocabulary, and fail closed on sealed/non-draft API shapes. MCP draft-act/draft-minutes calls also inject bounded `ai_provenance` into the act draft request, and the act API persists that provenance with a human-verification record; AI-assisted acts cannot advance from TextApproved to Signing until human review is recorded as accepted. The Ata editor now surfaces the AI provenance/human-review status, records accept/reject decisions through the existing review endpoint, and disables the Signing transition while review is pending or rejected. `validate_signature_bundle` wraps the existing signature endpoint as technical evidence only with no legal-validation claim, and the web settings/platform surface can manage the tenant gate and display AI/MCP assurances for gates, API-key RBAC, draft status, and signature-bundle scope without exposing secrets. Law corpus search/browse endpoints and registry import support provenance-adjacent workflows. | AI drafting/extraction/comparison/summarization depth, workflow-level provenance panels beyond MCP output/status/spec-coverage resources/static prompts and the act human-review gate panel, richer MCP prompt/resource breadth beyond the current bounded review prompts, non-stdio MCP transports, and any assessment of AI quality or legal validity remain. | None specific. |
| spec/10 UX & Design (UX) | PARTIAL | Web shell, 14-locale i18n runtime and catalog completeness checks, onboarding/auth gate, password-policy checklist, settings, Settings-only users/RBAC/delegation/API-key/recovery/privacy/UI platform-operations UI with AI/MCP assurance copy, settings-managed app/API/MCP logging controls, Data Management storage telemetry, cleanup UI, storage-breakdown polish, read-only data key-rotation preflight UI that clears entered secrets, guarded rekey execution UI that asks for the replacement key again and clears it after success/error, focused browser E2E for the guarded data-key rotation execution path, privacy breach-playbook and transfer-control register panels with operator evidence capture and readable non-notification/non-approval summaries, Ata editor convening evidence-reference controls plus AI human-review status/accept/reject controls that block Signing until accepted, law corpus citation pin/copy shelf preserving Verified/Pending labels, imported-document evidence UI including pre-persistence validation/refusal evidence for non-canonical legacy DOC/OLE-CFB imports, operator review status/note controls, visible guardrail alerts, and a required guardrail acknowledgement checkbox before terminal review submission, focused browser regression coverage for imported-document review conservative messaging/status-note submission plus notification routing/dismissal/canonical PDF export, paper-book import list/download UI plus per-import OCR draft list/create/review controls with explicit auxiliary/non-canonical acknowledgement copy, document preview, PDF/Markdown/TXT/HTML/RTF/ODT/DOCX working-copy downloads with browser export/save E2E coverage, signature evidence with local B-LT/B-LTA technical labels plus multi-signature local renewal-plan evidence, official signed-PDF handoff import UI with required guardrail acknowledgement and no secret-factor fields, external-invite UI, external-invite landing page, Ferramentas external-signing workflow tool, browser E2E for signed-act external invite boundaries, dashboard subtabs for stats/activity/current work/queue/events, dashboard reminders/work queue with localized alert keys, missing-attendance act reminders routed from notifications, active legal-hold and sealed-not-archived alerts, and activity-summary polish, persisted notification triage with icon-only read/dismiss/acknowledge/restore/route controls plus icon-only notification filter subtabs and tooltip-backed subtab overflow arrows that keep accessible names and tooltips, explicit seal-warning acknowledgement modal, compliance source/reference rendering, registered-entity primary filters that wrap without horizontal scrolling, collapsed accordion-style advanced filters that expand into wrapped multi-line controls, fixed/clamped registered-entity table cells with up-to-two-line text where needed, concise Type/Last Activity visible summaries with tooltips, entity chronology table plus copyable Mermaid graph sources with focused browser E2E coverage, improved template primary/advanced filters, template law-reference search/rendering with Pending/Verified badges, Arquivo UI, Trust/TSL/TSA catalog UI with identifier lookup controls and truncated/copyable digests, a PDF signature validator tool UI with copy/save technical JSON report actions plus focused browser E2E coverage, bundled PDF fonts, button hover/leather active states, hook-dependency lint hygiene in follow-up/import-review panels, and desktop window controls/smoke coverage are present. | Mobile UX, PDF/UA delivery beyond the bounded tagged-structure slice, broader dashboard workflow depth beyond the current subtabs/reminders/activity/archive lifecycle/attendance alert slices, broader table ergonomics beyond the entities/templates/storage/paper-import slices, broader imported-document browser coverage beyond the focused review/notification-export regressions, broader official-handoff browser coverage beyond the focused SigningPanel unit flow, broader AI provenance experience beyond the human-review gate panel, broader trust-list lookup UI depth beyond existing catalog/search/identifier surfaces, and broader legal-source/provenance linking beyond the citation shelf and template catalog remain. | None specific. |
| spec/11 Template Catalog (TPL) | PARTIAL | `chancela-templates` loads 83 JSON template assets; API exposes `GET /v1/templates`, previews, on-demand generation, seal/book hooks, catalog summary metadata for channels, signature policy hints, rule-pack IDs, and bounded `law_references` derived from rule-pack IDs plus threshold references, with Pending status and source provenance. Template tests now validate required authored asset metadata, duplicate IDs, rule-pack law-reference anchors, derived law-reference presence, family-binding drift across template ID prefixes/rule-pack IDs/signature-policy hints, asset-stem versus template-id drift, missing `/vN` suffixes, empty authored blocks, id-derived stage drift, duplicate/out-of-order channels, and scoped telematic/written-resolution channel drift without claiming legal authority. The web catalog can search/filter by those metadata and law-reference fields, keeps search/family/stage as primary controls, moves locale/channel/signature/rule-pack filters into a collapsed advanced area, and shows metadata plus compact law-source badges in summary/detail views. | Template market parity, legally verified threshold values, broader statute-overlay depth, exhaustive/verified law-reference mapping, and full family/rule-pack semantic validation beyond local metadata/family-binding/channel drift guards are not complete. | Legal review before any template wording, law reference, or threshold is treated as authoritative. |

---

## Recent Coverage Added

- **Raw external-validator technical metadata download:** `GET
  /v1/external-validator-reports/{case_id}/{validator_family}` returns the
  validated raw technical metadata JSON for one safe report identity to
  `settings.read` actors. The route fails closed for unsafe identities,
  malformed persisted sidecars, duplicate report identities, and ambiguous
  suggested paths, with API coverage for persisted downloads, reader access,
  malformed-sidecar refusal, and duplicate-identity conflict. This is technical
  metadata access only, not legal validity, trust-list validation, live provider
  validity, credentials handling, or authority approval.
- **Ferramentas external-validator report metadata management:** the PDF tools
  surface now includes an external-validator report metadata panel that uploads
  selected JSON as raw text, lists redacted metadata summaries with storage,
  malformed-sidecar, and duplicate-path counts, and saves a client-generated
  metadata summary without raw report bytes. This is technical metadata handling
  only, not legal validity, trust-list validation, live provider validity,
  credentials, or authority approval.
- **Live-provider assurance static gate:** CI now runs `npm run
  check:live-provider-assurance`, which verifies that live CMD, CSC/QTSP, TSA,
  and smartcard seams remain feature-gated, ignored/manual, documented with
  no-CI/operator boundaries, and compiled with `cargo test ... --no-run`. This
  is static/compile-time assurance only; it does not run live providers, prove
  live provider validity, use credentials, or record authority approval.
- **Durable external-validator metadata sidecars:** `GET/POST
  /v1/external-validator-reports` now persists bounded technical metadata JSON
  as data-dir sidecars, reloads those sidecars after restart, counts malformed
  sidecars without trusting them, and still returns only redacted summary
  metadata. This is durable technical metadata evidence, not legal validity,
  trust-list validation, live provider validity, credentials, or authority
  approval.
- **Web TSL/TSA identifier lookup controls:** Ferramentas now exposes technical
  identifier lookup fields for TSL services and TSA/QTST records, wiring
  `identifier=` into the catalog requests and rendering matched/empty states.
  This is read-only catalog lookup UI, not legal trust validation.
- **External-validator report metadata API validation:** `GET/POST
  /v1/external-validator-reports` accepts bounded operator-supplied technical
  metadata JSON, rejects legal overclaims, unsafe paths, and bad SHA-256 values,
  and lists redacted summaries. These validation boundaries feed the durable
  sidecars above; they are technical metadata only, not raw report replay,
  legal validator acceptance, trust-list validation, live provider validity,
  credentials, or authority approval.
- **Chronology and PDF validator browser E2E:** Playwright coverage now route-stubs
  entity chronology rows, copyable Mermaid sources, PDF validator JSON copy/save,
  and fail-closed refusal behavior that hides JSON actions. This is focused browser
  regression coverage, not exhaustive UX or validator authority coverage.
- **Privacy breach/transfer review evidence receipts:** breach playbooks now record
  review/drill receipts and transfer controls record review receipts in their existing
  privacy sidecars, with audit events, contract fixtures, and Settings UI capture.
  Receipt outputs keep `authority_notified`, `subjects_notified`, `transfer_approved`,
  and `data_transfer_executed` false; true notification/approval/execution/completion
  claims and sensitive receipt notes are rejected without mutation. This is evidence
  that an operator reviewed a playbook/control, not incident notification, transfer
  approval, data-transfer execution, or legal compliance certification.
- **Multi-signature local PAdES renewal-plan reporting:** arbitrary-PDF signature
  validation and act signature status now expose a `multi_signature_local_renewal_plan`
  object with signature count, per-signature DSS/VRI coverage, VRI key hash, local
  evidence gap indexes, and the next local technical action. The report keeps
  production long-term-profile and legal LTV flags false. This is already-inspected
  local technical evidence reporting only, not DSS/VRI mutation, archive timestamp
  renewal execution, trust-policy acceptance, or a legal B-LT/B-LTA claim.
- **Browser data-key rotation execution coverage:** a focused Playwright route-stubbed
  regression now covers the Data Management flow from ready key-rotation preflight
  evidence to the guarded execution form, verifies execution sends only the
  replacement key, and checks that entered secrets are cleared after success. This
  is browser-path regression coverage with secret-free fixtures, not live SQLCipher
  proof, plaintext migration, or production key-rotation certification.
- **MCP paper-book OCR review prompt:** MCP prompt discovery now includes a static
  `paper_book_ocr_canonical_review` prompt for human review of paper-book OCR and
  canonical-conversion evidence gaps. It accepts no caller arguments, performs no
  hidden provider/API calls, and makes no signing, canonical-record, legal-validity,
  or authority-acceptance claim.
- **Guarded SQLCipher rekey execution:** the API now exposes
  `POST /v1/data/key-rotation` for an already-open keyed durable store, gated to
  interactive `settings.manage` sessions. It accepts only a replacement key,
  refuses plaintext stores before attempting rekey, redacts request debug output,
  and returns secret-free execution evidence to Data Management. This is
  execution for the already-open SQLCipher store path only; it is not live
  SQLCipher proof on this host, plaintext migration, operator secret rotation
  runbook completion, or production at-rest encryption certification.
- **Paper-book OCR draft review UI:** preserved paper-book imports now expose
  non-authoritative OCR draft list/create/review controls in the book detail
  page, with explicit acknowledgement that the draft is auxiliary and does not
  create a canonical act, canonical document, signature, or legal validity. A
  contract fixture pins the OCR draft response shape. This does not execute OCR
  or promote OCR text to canonical records.
- **Template catalog metadata drift depth:** catalog tests now catch asset-stem
  drift, missing template version suffixes, empty authored blocks, id-derived
  stage drift, duplicate/out-of-order channels, and scoped channel drift for
  telematic and written-resolution templates. This remains local metadata
  consistency coverage only.
- **CLI database-encryption key parity:** the host CLI now opens durable stores
  through the shared database-encryption config, honoring `CHANCELA_DB_KEY` and
  `CHANCELA_DB_KEY_FILE` for operational commands. Default non-SQLCipher builds
  fail closed without creating a plaintext database when keyed env vars are set,
  reject ambiguous key sources before store open, and keep key material out of
  stdout/stderr. This is CLI parity with API key resolution, not live SQLCipher
  proof, migration execution, or production key-rotation execution.
- **Notification filter icon-only subtabs:** the notification page now renders
  its filter subtabs as compact icon-only controls with accessible names and
  tooltip labels, and the page test pins that the labels are not visible text.
  This is UX/accessibility polish for existing notification filters only.
- **Desktop database-key protection default:** SQLCipher-enabled desktop builds
  now resolve a durable database key by creating or loading a fresh random
  SQLCipher key protected by the current-user OS provider, DPAPI on Windows.
  Explicit `CHANCELA_DB_KEY` / `CHANCELA_DB_KEY_FILE` overrides remain available
  for operator/test configuration. Non-SQLCipher desktop durable startup fails
  closed unless `CHANCELA_DESKTOP_ALLOW_PLAINTEXT_DB=1` is explicitly set for a
  local development/no-SQLCipher run. The local SQLCipher feature check is still
  blocked on this host by vendored OpenSSL expecting a Windows-compatible Perl
  rather than the available Cygwin Perl, so this is not a verified production
  at-rest encryption claim.
- **Official signed-PDF handoff import UI:** the Signing panel now offers an
  official Autenticacao.gov/provider handoff import path for a PDF already
  signed outside Chancela. The form sends the PDF, optional client-declared
  provider/source/filename context, and required guardrail acknowledgements to
  the existing technical evidence endpoint while collecting no PIN, OTP,
  credential, or passphrase. It stores signed-PDF technical evidence only; it
  does not perform trust-list validation, claim qualified status, or complete
  legal signing acceptance.
- **Web data key-rotation preflight:** Data Management now has a read-only
  key-rotation preflight form backed by `POST /v1/data/key-rotation/preflight`.
  It submits replacement-key material only for readiness checks, renders the
  returned non-secret evidence, and clears entered secrets after both successful
  and failed requests. It does not execute SQLCipher rotation, migrate plaintext
  stores, persist submitted keys, or prove production at-rest encryption.
- **Guardrail acknowledgements:** imported-document terminal review transitions
  and official signed-PDF handoff imports now require explicit acknowledgement of
  the required guardrail IDs. The resulting evidence records that operators saw
  the canonical-record, signed-artifact, OCR/promotion, trust-list, qualified
  signature, and legal-completion boundaries; it does not create canonical
  records, validate legal signature status, or complete legal acceptance.
- **Imported-document acknowledgement UI:** the document panel renders
  canonical-record and signed-artifact guardrails, lists the preservation
  checklist, and keeps terminal review submission disabled until the operator
  acknowledges the required guardrails. This is workflow UI enforcement for
  non-canonical evidence only, not OCR, conversion, PDF/A replacement,
  signed-import validation, or legal acceptance.
- **Storage status UI polish:** Data Management separates filesystem usage from
  SQLite logical usage, tightens storage rows, and keeps permission/status probes
  readable across empty and warning states. This improves operator scanability
  only; it does not expand cleanup targets, deletion guarantees, encryption,
  migration, or retention execution.
- **Dashboard subtabs:** the dashboard now organizes metrics, recent activity,
  current books/acts, reminders, and raw event rows into localized subtabs. This
  improves dashboard navigation while preserving the existing advisory status of
  reminders, archive alerts, and activity evidence.
- **Notification icon-only controls:** notification popup/list actions now use
  icon-only controls with accessible labels and tooltip text, with focused unit
  coverage. This is accessibility/ergonomics polish for existing read, dismiss,
  acknowledge, restore, and route actions, not new workflow semantics.
- **Local PKCS#12 software-certificate signing:** the desktop-gated API flow
  `POST /v1/acts/{id}/signature/local/pkcs12/sign` can sign a sealed act with a
  transient encrypted PFX/passphrase request, persist the resulting signed PDF and
  public certificate evidence, and report `AdvancedLocalTechnicalEvidence`. This
  is advanced local technical evidence only; it performs no trusted-list lookup,
  does not become CMD/remote qualified signing, and does not claim legal
  qualification or legal status. The web signing panel now exposes this flow with
  transient file/passphrase handling, localized warnings, and regression coverage.
- **TSL XML-DSig trust-gate hardening:** `chancela-tsl` now rejects unsupported or
  malformed XML-DSig shapes that the minimal verifier cannot check, and tests
  digest/`SignedInfo`/signature-value tampering plus `TslClient` downgrade behavior.
  This improves technical trust-list evidence, but it still does not authenticate
  the TSL signer certificate against EU LOTL/national trust anchors or perform full
  certificate path/revocation/policy validation.
- **Bounded retention execution evidence:** non-destructive retention policies can
  now record bounded archive/no-action execution evidence with approvals,
  acted/skipped targets, reason codes, next steps, and idempotent repeat detection.
  Destructive delete/anonymize, physical deletion, disposal approval, and GDPR
  erasure remain outside this slice and are explicitly blocked/false.
- **Notification popup browser hardening:** Playwright now covers the notification
  popup as real browser UI for portal/z-index behavior, outside-click closing,
  action routing, and read-state count updates.
- **API-exposed and multi-signature PAdES renewal planning:** signature validation
  can now surface local PAdES renewal-plan evidence, and `chancela-pades` models
  per-signature DSS VRI/TU gaps plus caller-supplied renewal deadline
  classification across multiple signatures. This is local planning from observed
  technical evidence and caller policy only; it does not fetch revocation data,
  validate trust, infer legal deadlines, execute renewal, or claim B-LT/B-LTA/legal
  LTV sufficiency.
- **Web attendance/import guardrail alerts:** dashboard notifications now route
  missing-attendance reminders to the relevant act/book/entity, and the document
  panel surfaces imported-document guardrail alerts. These are advisory UI cues
  only; they do not prove attendance, meeting legality, canonical conversion,
  signed-import validity, or legal acceptance.
- **Retention review workflow state:** retention execution records now expose
  review-only intent, execution status, operator review decision, and normalized
  audit evidence fields. The records remain review/evidence artifacts; no
  retention execution, anonymization, deletion, disposal approval, or GDPR erasure
  is performed.
- **Tighter tagged-PDF self-checks:** local structural checks now validate
  standard RoleMap targets, struct-element role mapping, and marked-content scope
  rules in addition to the earlier ParentTree/MCID/MCR checks. This is regression
  coverage for the local tagged-PDF writer shape, not PDF/UA delivery or
  accessibility certification.
- **Clippy hygiene:** the current clippy warning set was cleared across API,
  document self-check, trust, recovery, and related code. This is maintainability
  hygiene only, not new spec coverage or release assurance.
- **SBOM package linkage:** `scripts/release-supply-chain.mjs` can now validate a
  generated CycloneDX SBOM against a specific release package path, byte size, and
  SHA-256, and CI runs the self-test. This links declared SBOM metadata to a local
  package artifact only; it is not package signing, notarization, attestation,
  registry publication, or reproducible-build proof.
- **Imported-document guardrails:** imported-document validation reports, stored
  views, ledger payloads, and review events now expose canonical-record,
  signed-artifact, and OCR/conversion-promotion guardrails. They keep preserved
  bytes non-canonical and do not replace canonical PDF/A records, create signed
  artifacts, run OCR, promote conversion output, or claim legal acceptance.
- **AMA/CMD evidence-pack check:** the AMA/CMD generator now has a read-only
  `--check` mode that validates deterministic generated files, claim-boundary
  fields, official-source metadata, placeholder evidence slots, implementation
  evidence-map references, and unresolved template tokens. The generated pack is
  still draft repository evidence only, not AMA/SCMD approval or legal compliance.
- **Dashboard missing-attendance reminder:** `GET /v1/dashboard` now adds advisory
  work-queue reminders for open pre-signing acts whose meeting date is due soon or
  overdue and whose attendance reference plus presence counts/structured attendees
  are missing, and web notifications can now route those reminders to the relevant
  act/book/entity. This is workflow hygiene only; it does not prove attendance or
  legal meeting validity.
- **External signer identity evidence:** external-signing envelope slots can declare
  required identity evidence categories, and a signed transition must include
  matching evidence references. These are recorded workflow controls, not legal
  identity, representative authority, qualified-signature status, or legal effect.
- **AI human-review UI:** the Ata editor displays AI provenance and human-review
  status, records accept/reject decisions, and disables the move to Signing until
  the persisted human-review gate is accepted. This surfaces the existing review
  control; it does not assess AI quality, certify legal validity, or accept draft
  text as final minutes by itself.
- **Web lint hygiene:** the follow-up and imported-document review panels were
  adjusted to clear hook dependency lint warnings while preserving their existing
  behavior. This is maintainability/regression hygiene, not new compliance scope.
- **Written-resolution evidence advisory:** rule packs now warn when a written
  resolution has no signatory slots or digested attachment bound into the record,
  with Pending legal-basis metadata. The warning prompts evidence capture; it does
  not prove thresholds, participant coverage, written consent validity, or legal
  acceptance.
- **PAdES local LTV renewal plan:** `chancela-pades` now reports a local technical
  renewal checklist from already-inspected signature timestamp, DSS revocation
  evidence, `/TU`, and DocTimeStamp imprint binding signals, and the API can
  expose that plan in signature validation responses. The multi-signature model can
  classify caller-supplied technical renewal deadlines and per-signature local
  evidence gaps. It does not fetch revocation evidence, validate trust, infer legal
  deadlines, execute renewal, or claim B-LT/B-LTA/legal LTV sufficiency.
- **Retention workflow blockers:** retention execution records now include workflow
  status, review-only intent, operator review decision, normalized audit evidence,
  blockers, required approvals, and next-step text for missing/stale/mismatched
  policies, legal holds, destructive-action requests, and manual review. They
  remain audit/review records with `would_execute: false`; no deletion,
  anonymization, disposal, retention execution, or GDPR erasure is performed.
- **Tagged-PDF structural self-check:** the PDF self-check now validates the bounded
  tagged-PDF structure more deeply, including `MarkInfo`, `StructTreeRoot`,
  `RoleMap`, `ParentTree`, page `StructParents`, MCID coverage, and MCR/ParentTree
  consistency, then further checks RoleMap standard-role mappings, struct-element
  role mapping, and marked-content scope rules. This catches local writer drift but
  is not PDF/UA certification or general accessibility conformance.
- **Template family metadata drift guard:** catalog tests now detect family drift
  between template ID prefixes, rule-pack IDs, and signature-policy hints. This
  protects local catalog consistency only; it is not legal review of template text,
  thresholds, or cited law.
- **Remote-signing TSA provider isolation:** focused remote-signing tests now clear
  configured TSA provider arrays while exercising legacy TSA URL failure paths. This
  keeps deterministic test coverage honest; it is not live TSA provider validation.
- **Bounded ASiC-S signing support:** `chancela-signing` can now create and validate bounded
  single-payload ASiC-S/CAdES containers for the supported local signing envelope path. This is not
  XAdES, arbitrary ASiC profile processing, embedded LT/LTA evidence, or a legal
  qualified-signature claim.
- **Bounded ASiC-E/CAdES manifest support:** `chancela-signing` can now create and validate a
  bounded ASiC-E ZIP shape with one ASiCManifest, one referenced detached CAdES signature over that
  manifest, and SHA-256 `DataObjectReference` checks against the packaged payload members. This is
  CAdES-backed manifest support only; it is not XAdES, ASiC-XAdES, multiple signatures, manifest
  extensions, embedded LT/LTA evidence, ETSI profile completeness, or legal validity assessment.
- **Legacy Word import validation evidence in the web UI:** the document import panel now calls
  `/v1/documents/import/validate` before persistence and renders validation evidence or safe
  refusal findings for legacy `.doc`/OLE-CFB candidates with localized copy. The flow still treats
  legacy Word files as preserved non-canonical evidence only; it does not execute macros, convert to
  canonical PDF/A, or assert legal acceptance.
- **Bounded tagged PDF structure:** `chancela-doc` now emits a minimal tagged structure for generated
  PDFs: MCIDs, `StructTreeRoot`, `RoleMap`, `ParentTree`, page `StructParents`, `MarkInfo` true, and
  artifact marking. The accessibility report still keeps `pdf_ua_claimed: false` and the
  `limited_tagged_structure` blocker, so this is a technical accessibility slice rather than PDF/UA
  delivery or certification.
- **Data storage visibility and bounded cleanup:** `GET /v1/data/status` reports the current
  persistence mode, configured data folder, directory existence/type, read/create/write/delete
  permission probes, durable SQLite open state, schema/ledger counters, and filesystem plus SQLite
  logical usage breakdowns. `POST /v1/data/cleanup` is gated by `settings.manage` and performs
  maintenance cleanup for crash reports and retained exports only, reporting requested/skipped
  targets and byte counts without broad deletion semantics. Retained-export cleanup now has
  export-only dry-run, minimum-age, and keep-latest policy controls; those options are rejected for
  crash cleanup. Data Management renders the same status with refresh, copy-path, scan-error,
  browser-safe open-folder-disabled states, and cleanup controls. This does not add durable log
  retention, SQLCipher production enablement, storage migration tooling, arbitrary deletion, GDPR
  erasure, legal disposal approval, legal retention execution, physical deletion guarantees beyond
  the bounded cleanup behavior, or complete data lifecycle automation.
- **Local PDF signature validator endpoint:** `POST /v1/signature/pdf/validate` accepts a bounded
  raw PDF or JSON/base64 envelope and returns local technical evidence: file SHA-256/size,
  PDF-structure markers, signature and ByteRange signals, PAdES/CAdES validation where available,
  DSS/VRI/OCSP/CRL/certificate evidence counts/hashes, DocTimeStamp imprint checks, and explicit
  trust/revocation/qualification sections marked not performed. The endpoint is gated by
  `act.read@Global`, fails closed on declared digest/size mismatches, persists no uploaded bytes, and
  does not claim AMA validation, legal effect, qualified status, or live TSL/TSA/revocation checks.
- **PDF validator tool UI:** Ferramentas now has a `Validador PDF` sub-tab that reads an uploaded
  PDF in the browser, computes a declared SHA-256 and byte length when possible, calls
  `/v1/signature/pdf/validate`, and renders a readable local-evidence report covering structure,
  PAdES/CAdES, ByteRange, DSS/VRI, DocTimeStamp, trust, revocation, qualification, and findings.
  Digest/size backend refusals are surfaced as a safe refusal. The UI copy is explicit that this is
  technical local validation only, not AMA/legal/qualified validation.
- **Operational trust-provider selection:** Settings serializes and validates additive
  `signing.tsl_sources` and `signing.tsa_providers` arrays while preserving the legacy
  `signing.tsl_url` and `signing.tsa_url` fields. Enabled TSL sources are now selected for trust
  refresh/catalog views and signing trust-policy construction before the legacy fallback. The
  enabled default TSA provider is selected for timestamping and surfaced in TSA catalog/reporting
  before the legacy fallback. Selection reports configured/enabled/disabled counts and keeps
  deterministic blockers honest: path-backed TSA providers require a future local replay/signing
  implementation, and unsupported timestamp digests block instead of silently producing fake live
  timestamp evidence. This still does not claim production legal trust completion.
- **Template filter ergonomics and wording:** the Minutas catalog now keeps search/family/stage in a
  compact primary filter row and moves locale/channel/signature/rule-pack filters into a
  collapsed-by-default advanced area. The PT source catalog also replaces the awkward
  `Todo o registo` filter label with `Qualquer estado`.
- **Button state and storage-tab polish:** web styling now applies broader button hover and leather
  active states, and the Data Management storage tab has tighter spacing around telemetry and
  maintenance controls. This is UX polish only; it does not expand functional compliance coverage.
- **Platform operations and logging policy:** Settings now carries an additive `platform` section
  with strict app/API/MCP log levels, per-service overrides, API/MCP desired state, last-action
  metadata, and an audit tail. `/v1/platform/services` reports API and MCP status plus limitations,
  `/v1/platform/services/{id}/actions/{action}` records start/stop/restart desired state with
  audit evidence, and `/v1/platform/logs?service_id=&level=&tail=` returns the newest bounded
  API-owned structured platform log tail with strict `settings.read` access and service/level/tail
  validation. When `CHANCELA_DATA_DIR` is configured, the API-owned tail is persisted to
  `platform-logs.json` and bounded to 512 entries; otherwise the in-memory fallback remains.
  Platform status reads and control requests add structured API log entries. The web Settings
  `Operações` tab exposes the same status, log controls, and action buttons, plus an AI/MCP
  assurance panel for managers covering dual gates, API-key RBAC, non-authoritative draft output,
  and technical-only signature-bundle scope without exposing secrets. This is honest
  desired-state/control evidence plus an API-owned log tail only: it is not historical
  stdout/stderr, does not include MCP child-process logs unless forwarded as structured API events,
  and is not a complete durable/live structured sink or reload/process logging pipeline.
- **Entity list ergonomics:** registered-entity filters now keep search/family/type in a compact
  primary area that wraps instead of forcing horizontal scroll, and move the rest into a collapsed
  accordion-style advanced filter area that expands into wrapped multi-line controls. The table uses
  fixed layout and clamped cells so verbose values do not overflow; long text can occupy up to two
  lines, while Type and Last Activity render shorter visible summaries with full tooltips.
- **Template catalog metadata:** `/v1/templates` now exposes each template summary's supported
  meeting channels, signature-policy hint, and rule-pack ID. The web catalog filters/searches those
  fields, renders badges and detail rows for operators, and keeps the 14-locale catalog matrix in
  sync. This improves discoverability but does not make template wording or thresholds legally
  authoritative.
- **Template law references:** templates and `/v1/templates` summaries now expose bounded
  `law_references` derived from rule-pack IDs and threshold references, including source
  provenance and Pending status. The mapping improves operator traceability, but it is not
  exhaustive, does not mark DRE material Verified, and is not a legal review of the template text,
  threshold value, or referenced law.
- **Template law-reference UI:** the Minutas catalog now includes law-reference source, citation,
  article, verification, and threshold metadata in its search index and renders compact legal-source
  badges with Pending/Verified status and caveats. This is a usability surface for existing
  provenance only; it does not promote references to legally verified status.
- **Law citation resolver and corpus citation shelf:** `POST /v1/law/citations/resolve`
  normalizes up to 32 selected corpus article references into copyable citation metadata gated by
  `law.read@Global`. The resolver carries `verification`, `source_complete`, source URL/digest
  fields where available, and an explicit legal notice; the Legislação reader can pin/copy those
  citations while keeping Pending entries visibly pending. This is reference assistance only: it
  does not persist legal bases, certify the copied citations, promote DRE-sourced articles to
  Verified, or replace official publication/legal review.
- **Document bundle validation report:** `GET /v1/acts/{id}/document/bundle` now returns a
  structured technical validation report instead of a placeholder: route/document consistency,
  canonical PDF structure markers, SHA-256 fixity, attachment digest coverage, signed-document
  linkage/evidence when present, and explicit non-certification flags. It is local technical
  evidence only and does not claim PDF/A certification, qualified-signature validity, production
  LTV, DGLAB certification, or trust-provider validation.
- **PDF accessibility metadata and bounded tagging model:** the PDF/A writer's accessibility report
  accepts an explicit report-side alternate-text/decorative-artifact model and generated PDFs now
  include a minimal tagged structure with MCIDs, structure tree, role map, parent tree, page parent
  mapping, MarkInfo, and artifact marking. This narrows the previous accessibility gap, but still
  does not emit PDF/UA identification metadata, keeps `pdf_ua_claimed: false`, and reports the
  structure as limited rather than certified PDF/UA delivery.
- **Password hardening:** `GET /v1/session/password-policy` exposes the server-authoritative rules
  and password-setting paths enforce them: minimum length, character classes, username/common
  password checks, repeat/sequence checks, Argon2 verifiers, sign-in backoff, one-time recovery
  phrases, and step-up composition for destructive actions. Onboarding and user-management UI now
  consume this policy.
- **Arquivo backend and UI:** `GET /v1/ledger/archive/document` renders a filtered ledger chain
  archive as PDF/A-2u without mutating state. The web ledger page lets the operator select chain and
  scope filters and download the same archive document.
- **Archive evidence and working copies:** `GET /v1/books/{id}/archive/package` now streams a
  deterministic internal preservation ZIP with manifest fixity, metadata sidecars, signed-document
  sidecars, timestamp-token evidence when present, DocTimeStamp validation/imprint evidence where
  present, and per-document evidence reports instead of placeholder validation slots. Full external
  validator inputs are still reported as not persisted unless a later flow records them.
  `?legal_hold=true&legal_hold_reason=...` marks that generated
  package as non-disposable and adds `evidence/legal-hold.json`; this is explicit export-time
  evidence, not persisted legal-hold state. `GET /v1/acts/{id}/document/working-copy` exports
  non-evidentiary Markdown, TXT, HTML, RTF, or deterministic ODT for review without mutating the
  preserved PDF/A or ledger, and the web document panel exposes these separately from the official
  PDF/A and DOCX downloads.
- **Archive integrity preflight:** archive package export and disposal dry-run now validate the
  preservation inventory before producing package members: duplicate or non-canonical document IDs,
  path-like metadata, missing PDF bytes, wrong PDF profile/header, digest mismatches, mismatched
  signed-document links, empty signature/certificate/timestamp material, and impossible signed-time
  metadata are refused. Generated ZIP bytes are self-validated with the archive manifest validator
  before being returned.
- **DGLAB-aligned preservation metadata:** internal archive manifests now include structured producer
  and preservation-interchange metadata, deterministic ordering, and validation for missing/blank
  metadata, unsafe members, duplicate IDs, and tampered package members. The manifest explicitly
  records `official_dglab_interchange: false` and `dglab_certification_claimed: false`; this is not
  an official DGLAB package or certification claim.
- **Trust/TSL/TSA catalog API and UI:** `GET /v1/trust/status`,
  `/catalog?search=&identifier=&limit=`, `/providers/{id}`, `/services/{id}`, and
  `/tsa?search=&identifier=&limit=` expose read-only trust status from cached XML, a configured
  enabled TSL source, or the bundled fixture. Ferramentas shows TSL source/staleness/XML-DSig
  status, provider/service search, technical identifier lookup controls, CA/QC/qualified/trusted
  flags, plus selected TSA configuration, runtime selection diagnostics, offline fixture probe
  diagnostics, timestamp-token metadata, and searchable TSA/QTST records. The parser/search slice preserves
  localized and duplicate names, service history, service supply points, revoked-like statuses, and
  malformed raw status dates for diagnostics; search is token-aware and accent-folded. Live TSA
  timestamping happens only when a signing flow explicitly requests it, and catalog fixture evidence
  is not a legal trust source.
- **Trust structured analysis:** TSL and TSA catalog queries now accept structured filters for
  service type, status, history, supply points, and strict technical identifiers. Provider/service detail exposes analysis counts,
  duplicate-service names, raw dates, history records, and supply-point evidence; TSA records expose
  policy/trust analysis plus blocking reasons so operators can distinguish advisory fixture data
  from a trusted qualified timestamp source.
- **API-key lifecycle and integration API:** `/api/v1/*` is mounted as an alias of `/v1/*`. Bearer
  keys are read from `Authorization: Bearer chk_...`, may not be mixed with web sessions, and resolve
  through the same RBAC permission gate as sessions. The lifecycle is implemented with
  `apikeys.json` persistence, `GET/POST /v1/api-keys`, `DELETE /v1/api-keys/{id}`,
  `POST /v1/api-keys/{id}/rotate`, shown-once create/rotate secrets, audit ledger events,
  per-key HTTP token-bucket enforcement, settings UI, and API/MCP bearer tests.
- **Roles, delegations, guest/minimal redaction:** The seeded role catalog now covers Owner, Gestor,
  Signatário, Leitor, Platform Administrator, Tenant Administrator, Auditor, Guest, and API Client.
  Delegations carry `starts_at` and optional `legal_basis` evidence, persist to `delegations.json`,
  and remain non-redelegable. Minimal guest/read-only callers now get redacted entity and registry
  views plus book purpose/signatory/predecessor metadata, act free text/participant/evidence
  metadata, and imported-document filename/digest/importer/download metadata. This is read-response
  minimization, not anonymization, erasure, or full privacy lifecycle completion.
- **Privacy/DSR backend lifecycle:** `GET /v1/privacy/users/{id}/export` returns a user-scoped,
  non-secret JSON export with metadata, safe account fields, role assignments, and authored ledger
  event references. It is gated by `user.manage@Global` and explicitly excludes credential
  verifiers, recovery phrases, API-key secrets, bearer tokens, and attestation private keys.
  `POST|GET /v1/privacy/users/{id}/dsr-requests` plus complete/status-transition routes track
  export, rectification, erasure, and restriction requests with timestamps, actors, optional
  operator reasons, bounded execution evidence (`outcome`, execution actor/time, notes, affected
  record summaries, retention/legal-basis reviews), fail-closed transitions, JSON sidecar
  durability for restart/restore, and audit ledger events. Sensitive credential markers in
  execution evidence are rejected before mutation/audit. Erasure completion now has an explicit
  immutable-ledger blocker and mutable-sidecar preflight plan, with idempotency evidence and false
  destructive/full-erasure flags. The settings-only user management surface exposes create, list,
  complete, and non-rendered JSON export download actions to `user.manage` operators.
- **Processor/DPIA compliance registers:** `GET|POST|PATCH /v1/privacy/processors` and
  `GET|POST|PATCH /v1/privacy/dpias` maintain processor and DPIA registers under the privacy
  module, with data-dir JSON sidecar durability for restart/restore. They are gated by
  `user.manage@Global` or `settings.manage@Global`, enforce strict `risk_level` and `status`
  values, sanitize list output, and append audit ledger events.
  The settings privacy tab adds search/filtering plus create/edit/status/risk controls and only
  loads the registers for operators with the matching permissions.
- **Breach playbook and transfer-control registers:** `GET|POST|PATCH
  /v1/privacy/breach-playbooks` and `GET|POST|PATCH /v1/privacy/transfer-controls` maintain
  bounded privacy-control registers with JSON sidecar durability, strict risk/status validation,
  sensitive-credential marker rejection, review-only evidence receipts, create/update audit events,
  contract fixtures, and Settings privacy-tab create/edit/filter/evidence controls. These are
  register and review surfaces only; they do not execute an incident response, notify an authority
  or data subject, approve an international transfer, perform a data transfer, or certify GDPR
  compliance.
- **Retention policy register:** `GET|POST|PATCH /v1/privacy/retention-policies` and
  `POST /v1/privacy/retention-policies/dry-run` maintain bounded retention policy records with
  JSON sidecar durability, strict enum validation, sensitive-marker rejection, and create/update
  audit events. Dry-run reports only applicability and always returns `would_execute: false`;
  deletion/anonymization/archival execution remains out of scope. The dry-run surface now accepts an
  optional execution request and records an audit-only execution evidence object with actor,
  requested policy, matched-record summary, legal-hold blockers, operator notes/evidence, and
  `would_execute: false`; destructive, stale, missing-policy, and legal-hold cases remain blocked.
  Execution request evidence is now also persisted to `privacy-retention-executions.json` in
  data-dir mode and listed through `GET /v1/privacy/retention-executions` for authorized
  operators. This is retention execution history only: it still performs no deletion,
  anonymization, archive disposal, or legal-retention certification.
- **Persisted book legal hold:** `GET|PUT|DELETE /v1/books/{id}/legal-hold` stores book-level legal
  hold metadata (`reason`, `actor`, `set_at`) through the existing durable book aggregate and appends
  ledger events on set/clear. Archive packages automatically include active persisted holds in
  retention metadata and evidence sidecars, while the export-time hold option remains available.
- **Archive disposal dry-run and execution evidence:** `GET|POST
  /v1/books/{id}/archive/disposal` reports disposal eligibility and produces a guarded dry-run
  `would_delete` manifest. `dry_run=false` now records a guarded non-destructive execution record
  plus ledger audit event for an eligible closed book under a matching active archive retention
  policy. Execution blocks on active legal-hold policy/book state, degraded or in-memory runtime,
  open book chains, unsealed acts, missing preserved documents, mismatched/missing policy, and
  repeated execution. The record marks source records/package members as disposal evidence only,
  reports `physical_deletion_performed: false`, and performs no physical deletion.
- **Document import validation and persistence:** `POST /v1/documents/import/validate` accepts raw
  bytes or a JSON/base64 envelope and returns a read-only structural report with declared/detected
  content type, byte size, SHA-256 digest, fixity checks against declared size/digest,
  PDF/PDF-A-ish markers, legacy OLE-CFB/`.doc` recognition, signed-PDF/ByteRange signals,
  signed-PDF status (`unsigned`, `structurally_signed`, `valid_pades_b`, `invalid`,
  `indeterminate`), ByteRange digest/coverage metadata, and whether the candidate can be accepted as
  a non-canonical import. The report now includes a preservation policy object with review state,
  operator-review requirement, OCR-review requirement for image evidence, original-byte preservation
  status, canonical-conversion status, and false canonical/acceptance flags. Malformed/truncated
  ByteRange data, duplicate ByteRange markers, ambiguous OLE/PDF claims, invalid PAdES/CAdES
  validation, and declared size/digest mismatches fail closed. Legacy DOC imports are accepted only
  as preserved non-canonical evidence: no macro execution, conversion, or canonical PDF/A generation
  is performed. `POST /v1/documents/import`,
  `GET /v1/documents/imported`, `GET /v1/documents/imported/{id}`, and
  `GET /v1/documents/imported/{id}/bytes` persist and expose validated non-canonical imported
  evidence through store schema v5. The `document.imported` ledger event carries metadata only; raw
  bytes remain in the store. Stored imported-document views and ledger metadata carry the same
  preservation-review policy and still mark `canonical_conversion_performed`,
  `canonical_pdfa_generated`, and `legal_acceptance_claimed` false. The document panel now validates
  candidates before persistence, renders legacy DOC/OLE-CFB evidence or refusal findings, exposes
  import/list/metadata/original-byte download controls, and keeps all copy explicit that imported
  documents are non-canonical evidence. Focused browser E2E route-stubs the imported-document review
  flow and pins the conservative review messaging plus review PATCH request/response behavior; a
  second focused browser regression covers dashboard notification routing, review submission,
  notification dismissal, and canonical act-PDF export staying separate from imported bytes. This
  does not replace preserved canonical documents, run OCR, convert legacy Word/image/text/bundle
  files, create PDF/A, or prove legal/signature validity.
- **Historical paper-book validation and preservation:** `POST /v1/books/paper-import/validate`
  returns a read-only report for historical paper-book scans/packages, checking identity metadata,
  date span, page count, source page range, optional original ata-number range, optional digest,
  source filename, and notes. `POST /v1/books/paper-import` re-runs validation and fixity checks,
  preserves PDF/ZIP/octet-stream package bytes in the durable store, appends a metadata-only
  `paper_book_import.preserved` ledger event, and records the import as non-canonical evidence with
  explicit linking metadata plus a continuation recommendation, but no legal, signature-validity,
  qualified-signature, or canonical minutes claim. `GET /v1/books/paper-import[?book_ref=...]`,
  `GET /v1/books/paper-import/{id}`, and `GET /v1/books/paper-import/{id}/bytes` list metadata,
  read metadata, and download retained bytes explicitly. The web book detail flow exposes the same
  list/download surface. Validation/preservation reports now include bounded canonical-conversion
  preflight evidence with explicit `not_attempted`/`blocked`/`allowed` status, named blockers, and
  false canonical-act/document/signature/legal-validity flags. OCR execution, reviewed canonical
  conversion execution, and legal acceptance remain follow-up work.
- **Closed-book act immutability:** The act mutation API now explicitly rejects patch, advance,
  seal, archive, and convening-dispatch requests for acts whose owning book is no longer open. The
  focused API tests verify open-book behavior still works, closed-book mutations return conflict,
  and failed mutations do not append ledger events or persist state across reload.
- **Convening evidence reference path:** the core `Convening` model, DTO/API patch shape, durable
  act JSON store, document rendering context, and Ata editor now carry `evidence_reference` as a
  bounded operator reference to external proof such as a document id, archive path, or tracking set.
  The field preserves the reference through editing and rendering context, but it does not ingest,
  validate, certify, or retain the underlying evidence object by itself.
- **External signer invitation tracking:** sealed acts can create/list/revoke external signer
  invite records under `/v1/acts/{id}/signature/external-invites`. Tokens are returned exactly once,
  stored hashed/redacted, and audit events are appended; this is tracking/envelope infrastructure,
  not completed remote signing. Unauthenticated token-body lookup/respond endpoints expose only safe
  invite/act/document metadata while the token is live, record accepted/declined acknowledgement
  events, and never return token material or canonical PDF/signed-PDF downloads. A token-body-only
  public endpoint can return a non-canonical Markdown working copy for sealed acts; it is explicitly
  non-evidentiary and not a qualified signature. The signing panel exposes create/list/revoke plus
  one-time token display, and `/assinatura-externa` is the token landing page.
- **External invite signed-PDF technical evidence:** accepted external invite responses can now
  carry an optional base64 signed PDF. The API requires the act to be sealed, validates the upload
  as a signed PAdES PDF, checks it is bound to the sealed PDF bytes, stores the exact signed bytes
  through the signed-document path as `ExternalSignerHandoff` /
  `ExternalSignedPdfTechnicalEvidence`, and exposes `signed_artifact` to the token holder plus the
  ordinary signature status/download endpoints. The status remains technical evidence only:
  `trusted_list_status` stays null, qualified/legal status is not claimed, and
  `require_qualified_for_seal` still keeps finalization non-qualified.
- **External signing workflow tool:** Ferramentas now includes an External Signing tool at
  `/ferramentas?tool=external-signing` for operational tracking. It lists redacted invite records,
  summarizes response/status state, handles same-origin token links, looks up public envelope
  metadata, and uses localized copy. This is still invite/envelope tracking and safe working-copy
  access, not legal signing completion, qualified-signature validation, or canonical signed-PDF
  delivery.
- **AMA/CMD evidence pack generator:** `docs/compliance/ama-cmd` now includes a generator,
  source metadata, templates, and generated pack material for collecting implementation evidence,
  authority-review notes, application/certificate placeholders, app-video evidence, and test
  evidence. The generated material is deliberately framed with no-approval-claim wording; it is
  not production CMD approval, a legal certification, or proof that AMA/SCMD credentials and
  production certificates are available.
- **Signing trust failure matrix:** API tests now cover fail-closed CMD/CC/TSA trust and
  timestamping cases, including path-backed or unsupported timestamp inputs. This improves
  regression coverage for deterministic trust failures; it does not exercise live CMD, physical CC
  hardware, or production QTSP/TSA operation.
- **Signature evidence status:** `GET /v1/acts/{id}/signature` includes a structured `evidence`
  object that distinguishes unsigned, PAdES B-B, timestamped B-T, local B-LT-style technical
  evidence, and local B-LTA-style DocTimeStamp evidence states, including partial local evidence
  cases. It reports timestamp presence, inspects embedded DSS/VRI evidence when present, reports
  OCSP/CRL/certificate/VRI counts and SHA-256 hashes, reports embedded DocTimeStamp
  validation/imprint binding, maps persisted technical timestamp-trust diagnostics when validator
  inputs were stored with the signed artifact, and keeps `production_b_lt_status: "not_claimed"`,
  `legal_b_lt_claimed: false`, `legal_b_lta_claimed: false`, and `live_revocation_fetching: false`
  instead of implying legal long-term validation. The signing panel shows the same evidence as
  technical status only.
- **Local DSS/VRI and revocation core:** `chancela-pades` can append deterministic `/DSS` + `/VRI`
  incremental revisions from caller-supplied DER evidence, reject empty revocation evidence,
  merge/dedupe pre-existing DSS streams by content hash, write `/TU` validation-time metadata, and
  report OCSP, CRL, certificate, VRI, `/TU`, and evidence hash counts while validating the signed
  revision separately from later DSS bytes. `chancela-signing` exposes the low-level attach/report
  path plus technical CRL+OCSP evidence collection with bounded transports, freshness/status,
  issuer/responder trust, and signature checks. The API plus archive evidence reports surface
  embedded DSS/VRI counts/hashes as technical evidence. This remains non-production-LTV: no
  production B-LT/B-LTA legal sufficiency claim, no multi-signature renewal execution beyond local
  evidence-gap planning, and no archive document timestamp chain.
- **DocTimeStamp and validator corpus:** `chancela-pades` includes deterministic technical
  DocTimeStamp fixtures plus imprint-binding validation, including the future-DocTimeStamp corpus
  case. `docs/fixtures/validator-corpus` tracks generated PDFs, expected EU DSS/Adobe sidecars, and
  pending/recorded external-validator status. `scripts/record-validator-sidecar.mjs` records raw
  operator validator reports with source filename, byte length, SHA-256 hash, media type,
  preservation actor/time, evidence scope, and status transition metadata; the validation script
  enforces technical-only `legal_validity_assessment: not_assessed` sidecars and preserves raw
  report material without transcribing a broader legal pass/fail claim. The same validator-corpus
  evidence metadata now declares archive package `evidence/index.json` and document-bundle
  `validation_report.evidence_index` indexing locations for external-validator report metadata.
  These fixtures and indexes improve technical interoperability evidence but do not replace live
  qualified validation, trust-list validation, legal acceptance, or authority approval.
- **Signing provider status and XAdES/ASiC honesty:** settings now include read-only provider-mode
  metadata for CMD/SCMD, CC, CSC/QTSP, and local PKCS#12 so operators can distinguish configured,
  blocked, and local-only paths without entering secrets in the UI. The desktop-gated API can also
  sign a sealed act with transient local PKCS#12/PFX inputs and stores only the signed PDF plus
  public certificate evidence. `chancela-signing` now has focused signing/validation tests and docs
  that keep XAdES unsupported while recognizing the bounded ASiC-S/CAdES and ASiC-E/CAdES manifest
  slices. Local PKCS#12 signing is advanced local technical evidence only, not CMD, not a remote
  qualified provider flow, not trust-list validation, and not legal qualified-signature status.
  ASiC-XAdES, XAdES generation/validation, ASiC-E profiles beyond one CAdES-signed manifest binding
  payload digests, embedded LT/LTA evidence, and legal qualified-signature claims remain explicitly
  out of scope.
- **CMD legal integration position:** `docs/CMD-LEGAL-INTEGRATION.md` records the current product
  stance: Chancela can integrate with CMD/CC/QTSP flows without itself becoming the qualified trust
  provider, but cannot honestly create handwritten-equivalent qualified signatures without the
  provider/certificate/hardware/onboarding requirements those flows depend on.
- **Office and working-copy exports:** `GET /v1/acts/{id}/document/office` returns a
  deterministic DOCX working copy for sealed acts with a non-evidentiary warning and
  preserved-document metadata. `GET /v1/acts/{id}/document/working-copy?format=md|txt|html|rtf|odt`
  provides non-evidentiary review copies, with ODT emitted as a deterministic minimal
  OpenDocument Text ZIP using fixed member timestamps. The stored PDF/A or signed PDF remains the
  canonical record, and the document panel exposes DOCX, Markdown, TXT, HTML, RTF, and ODT downloads
  beside the official PDF/A download with localized labels and warning copy. API tests now cover the
  working-copy export matrix, and browser E2E covers the export/save flow for repeated canonical
  PDF/A download, separate review-copy downloads, preservation ZIP, signing fallback UI, and ledger
  archive PDF/A export.
- **Imported document evidence families:** the imported-document contract/API/UI test surface now
  distinguishes additional evidence families for retained bytes, metadata-only records, and signed
  PDF/PAdES structural status. These are preservation/evidence classifications, not legal
  acceptance of non-canonical files or production signed-import validation.
- **Dashboard reminders:** `GET /v1/dashboard` includes advisory annual-calendar reminders from
  encoded profile calendar presets. Commercial SA/Lda-like entities, associations, foundations, and
  cooperatives are covered where a profile preset defines a fiscal-year offset; unsupported or stale
  profile data emits no false reminder. Due dates use the entity's recorded fiscal-year end when
  valid, fall back explicitly to the default calendar-year model when absent/invalid, clamp leap-day
  edge cases deterministically, suppress reminders when a sealed/archive act already provides a
  recent calendar signal, and now carry i18n keys so the web notification/dashboard copy is resolved
  through the locale catalog. The reminder remains advisory and bounded by current calendar preset
  data.
- **Dashboard activity summaries:** the dashboard now presents more concise visible activity
  summaries, with localized copy and regression coverage for the summary rendering. This improves
  scanning of existing workflow signals; it is not a complete dashboard analytics or operational
  reporting layer.
- **Dashboard archive lifecycle alerts:** `GET /v1/dashboard` now emits active legal-hold
  (`book.legal_hold.active`) and sealed-not-archived (`act.archive.pending`) alerts with category,
  severity, target links, i18n keys, and recommended next steps; the web work queue renders them as
  localized routed items. These are advisory operational prompts to review a hold or archive a
  sealed act when preservation evidence is ready, not legal certification, disposal approval, or
  proof of archive completion.
- **Notification triage and seal acknowledgement:** `GET/PATCH /v1/notifications/triage` persists
  dashboard-derived notification triage per actor in `notification-triage.json` when a data dir is
  configured. The web bell and notifications page now merge dashboard alerts/reminders with
  read/dismissed/acknowledged state, hide resolved items from active views, provide a resolved tab,
  and keep a local-storage fallback for older/missing backends. The ata editor no longer sends an
  implicit warning acknowledgement on clean seals; non-blocking compliance warnings require an
  explicit modal checkbox before the seal request carries `acknowledge_warnings: true`.
- **Compliance source references:** the compliance panel now renders existing source/reference
  metadata on rule findings and convening/statute advisories. `http`/`https` references open as
  external links; structured legal references and unsafe/non-http URL values remain inert text. The
  UI does not fabricate source metadata or mark pending law as verified.
- **DRE corpus guard:** DRE-sourced Portuguese law entries remain Pending unless the repository has
  complete authoritative source text/PDF evidence. The guard prevents accidental presentation of
  partial resolver metadata as verified law text; authoritative DRE exports or equivalent source
  capture are still required before the pending entries can be promoted.
- **Settings-only user management:** the standalone `/utilizadores*` screens now redirect into
  `Configurações -> Utilizadores`, preserving create/edit/access deep-link state. Settings is the
  single canonical user-management surface.
- **Registry chronology:** the registry import layer exposes deterministic chronology events and
  Mermaid shareholders/organs/relationships views for imported extracts. This covers the current
  relationship-graph slice; richer visual editing and source-linked compliance remain future work.
- **MCP tool coverage:** The stdio MCP catalog includes read/write-controlled `/api/v1` tools for
  entity/book/act operations, the `draft_minutes` alias to the draft-act API, Mermaid chronology
  graphs, document preview and working-copy export, book preservation packages, ledger PDF/A archive
  export, exact AI-11 `prepare_archive_export`, technical-only `validate_signature_bundle`,
  TSL trust search/detail, law search, and compatibility aliases for company timeline/legal-text
  terminology. The draft tool uses closed-schema argument validation before any HTTP call; it
  creates only a draft record and does not generate legal text. Successful MCP draft calls are
  wrapped in a non-authoritative provenance envelope (`ai_draft`) with human verification required,
  top-level `source_provenance`, per-field statement-source entries, source endpoint/tool, actor,
  allowed checkpoint statuses (`pending_human_verification`, `accepted_by_human`,
  `rejected_by_human`), timestamp, and null model/provider placeholders; sealed or non-draft API shapes are refused
  instead of presented as drafts. MCP draft calls now inject bounded act-level `ai_provenance`;
  the API persists that provenance, records accepted/rejected human-review decisions through a
  ledgered endpoint, and blocks AI-assisted acts from advancing to Signing until human review is
  accepted. The Ata editor now surfaces that review gate. This is a durable human-review gate and
  provenance injection path only, not legal validity, AI-quality review, or a complete provenance
  experience. The signature-bundle tool wraps the existing signature status endpoint as technical
  evidence only and refuses to claim legal validation. The server is still off by default and now
  additionally refuses to serve unless the tenant AI gate is enabled; settings UI exposes that
  default-off tenant gate to managers. MCP also exposes a local spec-09 coverage resource, a
  compliance-pack gap-review prompt for human review of DSR, retention, archive, and signature
  evidence, and a paper-book OCR canonical-review prompt for OCR/canonical-conversion evidence
  gaps; all remain static/offline review aids with no provider calls or legal-validity claim.
- **E2E / CI / desktop coverage:** CI now includes multi-OS Rust format/clippy/tests, web
  format/lint/tests/build on Node 20 and 24, web unit tests with enforced Vitest/V8 coverage
  thresholds, composed server E2E, opt-in Playwright browser E2E with artifacts, Docker server image
  build on main, and opt-in Windows Tauri desktop smoke with artifacts. API tests now cover the
  working-copy export matrix, archive package tamper failures, hardened password verifier storage,
  signing trust failure cases, and focused multi-signature renewal-plan reporting. A separate tag/manual
  release workflow builds Linux/Windows/macOS package artifacts and uploads package
  manifests/checksums without claiming signing/notarization. Local scripts include
  `npm run test:e2e`, `npm run check:versions`, Docker smoke, and `apps/desktop` smoke helpers.
  Static-serving E2E now covers encoded/odd API paths so integration clients receive JSON 404s
  rather than the SPA shell. Archive package E2E now covers persisted legal hold after restart and
  blocked disposal with no partial state change. Browser E2E now covers disabled pre-seal document
  downloads, repeated canonical PDF/A download, separate non-evidentiary Markdown/TXT/HTML/RTF/ODT/DOCX
  working-copy downloads, preservation ZIP download, signing fallback UI, ledger archive PDF/A export,
  signed-act external invite boundaries, a focused route-stubbed imported-document review
  regression, and a route-stubbed Data Management data-key rotation execution flow. The web
  browser lane also now has route-stubbed entity chronology and PDF-validator JSON copy/download
  coverage. The web
  production build explicitly splits stable React/router/query/Tauri vendor chunks from the app
  bundle, keeping the main application chunk under the default Vite large-chunk warning threshold.
  Current audit caveats remain: browser E2E is not exhaustive, coverage thresholds outside the web
  unit-test lane are not broadly enforced, live signature/provider seams are compile-only, release
  packages are not signed or notarized, and Docker images are not signed or attested.
- **Docker deployment profiles:** the Docker compose/deployment material now distinguishes local,
  demo, and reverse-proxy/TLS-facing profile guidance with persistent data paths and smoke-script
  hardening. These are deployment profiles and checks, not HA architecture, managed operations, or
  signed/attested image publication.
- **Recent-landed checkpoint:** `npm run test:checkpoint:recent-landed` and the GitHub Actions
  `recent-landed` job pin the cross-cutting recent work: paper import API tests including
  canonical-conversion preflight markers, archive package and DocTimeStamp evidence tests, local
  PKCS#12 API signing tests, multi-signature PAdES renewal-plan API tests, bounded retention execution tests, privacy breach/transfer review-receipt tests, TSL XML-DSig hardening tests, MCP
  resource/prompt tests, web contract/client/dashboard/ferramentas/signing/i18n/trust tests,
  external-validator report metadata API tests including data-dir sidecar reload, settings.read raw
  metadata download, malformed sidecar refusal, duplicate-identity conflict, and malformed sidecar
  counting, the static live-provider assurance gate, notification-popup browser coverage,
  static imported-document review notification/export browser markers, static data-key rotation
  execution browser markers, static entity chronology/PDF-validator browser markers, trust
  identifier UI markers, external-validator metadata panel/client/i18n markers, validator corpus
  sidecar validation, CLI encrypted-key environment tests, and desktop lockfile metadata. The static
  mode catches accidental removal of the mapped files and fixture markers without running the full
  commands.
- **Release trust metadata guard:** `scripts/check-release-trust.mjs` validates explicit package
  `releaseTrust` metadata and Docker signing-status metadata in the current `unsigned-dev` /
  `local-ci` paths and in production declarations, with a CI self-test and release/Docker workflow
  checks that reject production signing, notarization, publication, or attestation claims without
  matching metadata anchors. Docker production metadata must include anchors such as image/artifact
  digests, HTTPS workflow/run URLs, signing identity or certificate fingerprint, and attestation
  predicate metadata. This guards metadata honesty only; it does not sign, notarize, attest,
  publish, verify a registry push, or prove artifact provenance.
- **Package source provenance guard:** `scripts/package.sh` and `scripts/package.ps1` now write
  `manifest.sourceProvenance` with commit SHA, source-tree state, and `buildMode=release`.
  `scripts/check-package-artifacts.mjs` requires that provenance, mirrors it against
  `manifest.gitCommit`, and rejects fixture/package manifests whose commit does not match current
  `HEAD`; `scripts/check-release-trust.mjs` also cross-checks release summary `source.sha` against
  the manifest. This is source-traceability metadata only; it does not sign, attest, notarize,
  publish, or prove a clean-room/reproducible build.
- **Release and store hardening foundations:** packaging now stages `manifest.json` and `SHA256SUMS`
  with artifact metadata/checksums, checks generated package artifact integrity, and includes the
  host CLI plus operator scripts when present.
  CI now generates and validates a CycloneDX dependency SBOM from npm/Cargo lockfiles, can bind
  SBOM metadata to a release package path/size/SHA-256 with a self-tested checker, uploads npm/Cargo
  advisory reports, can make scans blocking on manual `enforce_security_scans=true` dispatches, and
  records Docker image inspect/Syft/Trivy/signing-status artifacts without claiming registry
  publication, signing, attestation, or notarization.
  `chancela-store` has a feature-gated SQLCipher keyed-open foundation with typed unavailable and
  rejected-key errors while preserving default plaintext behavior. API/server startup now resolves
  `CHANCELA_DB_KEY` / `CHANCELA_DB_KEY_FILE`, rejects ambiguous/empty/unreadable key config without
  logging secrets, refuses configured encryption on no-SQLCipher builds before creating a plaintext
  database, and preserves plaintext startup when unset. The store now exposes a secret-free key-ops
  status/preflight that classifies configured/empty/missing key state, SQLCipher build availability,
  database file header format, the bounded operation plan, rotation readiness only for the
  non-plaintext `OpenEncryptedStore` plan, and operator action text without exposing key material.
  Store/API startup use that preflight to refuse direct plaintext-to-encrypted keyed open and point
  operators toward an explicit backup/export-restore migration path. The key-ops status now also
  serializes a non-secret `migration_plan` with evidence and ordered non-destructive
  backup/export, fresh encrypted-store, restore/verify, and cutover-hold steps. The store crate also
  exposes secret-free SQLCipher key-rotation preflight plus feature-gated rekey execution evidence
  with post-rekey integrity checking, and the API exposes a `settings.manage@Global`-gated
  `POST /v1/data/key-rotation/preflight` route that returns only readiness evidence and redacts
  submitted keys from debug output, and the web Data Management panel can run that read-only
  preflight while clearing entered secrets. This is a guard, status, operator-plan, web/API
  preflight, and store-level evidence surface only: it does not prove live production SQLCipher
  encryption, host decryptability, completed execution rotation operations, completed at-rest
  encryption, or plaintext migration. Plaintext-to-encrypted migration execution, production
  rotation workflow, and sidecar encryption remain follow-up work.

---

## Remaining Blockers

### Local product work

- Legal/product depth: per-family rule-pack completeness, legally verified
  threshold values, exhaustive/verified template/citation law references, guest/privacy redaction
  coverage beyond the current read-response slices, destructive/automated DSR execution workflows
  beyond erasure preflight and bounded evidence, and DPIA/breach/transfer-control documentation
  depth.
- Data lifecycle/storage: the cleanup endpoint covers crash reports and retained exports only, with
  retained-export dry-run/minimum-age/keep-latest guardrails, and archive disposal execution is
  non-destructive evidence only; actual physical deletion, broader retention/disposal policy
  automation, GDPR erasure, export-retention policy controls beyond the current cleanup guardrails,
  incident-response/transfer-control automation beyond registers, executed storage
  migration/export-restore and production key-secret rotation tooling beyond the current key-ops
  guard/plan plus web/API/CLI/store preflight/key-env support and already-open-store rekey evidence, and
  legal-hold/disposal operator workflows beyond the dashboard advisory prompts and current
  retention blocker/approval records remain implementable next slices before any data-lifecycle
  compliance claim.
- Documents/archive: deeper imported-document preservation-review workflow depth beyond the current
  bounded status/note transition and acknowledged guardrail checklist, production/legal signed-import validation
  beyond the local structural/PAdES checks and technical uploaded evidence, full PDF/UA delivery
  beyond the bounded tagged-structure slice, `DisplayDocTitle`, `/Tabs /S`, XMP checks, and
  structural self-check, richer structure trees/tagging/role maps/marked artifacts, OCR execution
  and reviewed canonical/legal conversion beyond preflight evidence for preserved legacy DOC and
  historical paper-book evidence, official DGLAB
  interchange/certification, actual physical deletion, broader disposal/retention policy
  automation, GDPR erasure linkage, legal acceptance/certification, and long-term signature evidence
  packaging/renewal execution beyond the implemented sidecars, archive package
  `evidence/index.json`, document-bundle `validation_report.evidence_index`, local PAdES renewal
  plans, and technical metadata projections.
- Trust/signing depth: production/legal B-LT/B-LTA, XAdES/ASiC-XAdES execution beyond structured
  unsupported-profile diagnostics, ASiC-E coverage beyond the bounded CAdES-signed
  manifest/digest-binding path, embedded ASiC LT/LTA evidence,
  PKCS#11/operator certificate workflows, multi-signature/archive timestamp renewal depth and
  policy-driven LTV renewal timing, production provider-management flows, actual operator validator
  report collection for the corpus, populated runtime evidence-index attachments beyond the declared
  external-validator metadata paths, AMA/CMD production approval beyond generated/checkable
  evidence-pack material, and external signer legal completion beyond invite/envelope tracking,
  uploaded technical signed-PDF evidence, and identity-evidence records.
- Workflow breadth: legal-calendar preset depth beyond the advisory dashboard reminder, OCR
  execution and canonical-conversion flows for preserved paper-book packages beyond current
  non-authoritative OCR draft metadata/review UI and preflight evidence,
  written-resolution evidence capture beyond the advisory warning, external signer
  document-gated/legal completion flows, dashboard
  depth beyond the current reminders/activity/archive/attendance alert slices, groups/tenancy,
  sync/connectors, live SQLCipher/at-rest DB encryption verification plus migration operations and
  production key-secret rotation operations beyond current key-env/preflight support and already-open-store rekey evidence, ZK, HA, and mobile builds.
- AI feature layer: drafting/extraction/compare/summarize, workflow-level provenance panels beyond
  the MCP envelope/source-provenance object, act human-review gate panel, status/spec-coverage
  resources, static human-review/compliance/paper-book prompts, and settings/platform assurance panel, broader
  MCP prompt/resource coverage, additional MCP transports, and any legal-validity or AI-quality
  assessment.
- CI/release assurance: broaden browser E2E for critical workflows beyond the current focused
  signed-invite, export/save, imported-document review/notification-export, notification-popup, and
  data-key rotation execution regressions, add or explicitly waive coverage thresholds beyond the web unit-test lane, convert
  compile-only live signature seams into controlled integration lanes where credentials/hardware
  exist, harden package provenance beyond manifest/checksum/source metadata, SBOM package-linkage
  checks, and release-trust metadata-anchor guards, move Docker profiles toward production HA/ops
  where required,
  sign/notarize release packages, and sign/attest Docker images with verified publication evidence.

### External / provider / legal blockers

- **CMD:** production use depends on AMA/SCMD onboarding credentials, the prod field-encryption
  certificate, and authority approval. The generated evidence pack and offline tests do not prove
  live SCMD operation or production CMD approval.
- **CSC/QTSP:** the generic CSC v2 adapter and API route exist, but each provider still requires
  sandbox/prod onboarding, client credentials or user authorization, credential selection, and live
  provider testing.
- **CC:** production use requires physical Cartao de Cidadao, reader, and Autenticacao.gov
  middleware on the operator machine.
- **TSL/TSA:** trust refresh/catalog, signing trust-policy selection, and timestamping
  selection/reporting now consume configured enabled TSL/TSA entries with legacy fallbacks, but
  production trust operation still needs valid live source material, production network
  configuration, signer-certificate trust anchoring to EU LOTL or national trust anchors, certificate
  path/revocation/policy validation, and policy/legal review. TSA diagnostics use an offline fixture
  probe unless a signing flow explicitly requests a timestamp. Path-backed TSA providers,
  unsupported timestamp digests, and XML-DSig shapes outside the supported minimal verifier remain
  deterministic blockers, not fake live signing. The bundled fixture is advisory and must not be
  treated as legal trust completion.
- **Law/legal review:** PT DRE corpus entries need authoritative source text/PDF extraction before
  they can be marked Verified; the current guard intentionally keeps incomplete DRE captures
  Pending, including when those articles are copied through the citation shelf. Generated
  templates, exposed template/citation law references, and threshold values need legal review before
  they are treated as authoritative or complete.
- **Qualified-signature requirements:** CMD/legal-signature copy must stay explicit that there is no
  legal shortcut around qualified provider, qualified certificate, hardware, and onboarding
  requirements.
- **Release trust chain:** package manifests, checksums, integrity checks, and release-trust
  metadata validation are not signing or notarization; Docker profiles, OCI metadata, and
  signing-status metadata-anchor checks are not image signing or attestation and do not verify an
  actual registry push. Release packages are not signed/notarized and Docker images are not
  signed/attested until the workflows have production signing identities, registry publication, and
  verified artifact provenance.

---

## Do Not Overstate

- Chancela helps produce compliant evidence; it does not create legal validity or replace provider
  credentials, qualified-trust onboarding, or legal review.
- A qualified signature artifact can be produced through configured providers, but the repository
  does not include AMA/QTSP credentials, physical CC hardware, or live-provider legal onboarding.
- CMD/CC/CSC flows do not bypass qualified provider/certificate requirements; production legal
  validity still depends on the appropriate qualified trust service and certificate context.
- Local PKCS#12/PFX signing is advanced local software-certificate technical evidence only. It is
  not CMD, not remote qualified signing, not trusted-list validation, not legal qualification, and
  not proof of handwritten-equivalent legal status.
- The generated AMA/CMD evidence pack and its read-only check mode are documentation/review
  scaffolding for collecting and validating local pack material; they are not production CMD
  approval, legal certification, or proof of live AMA/SCMD credentials.
- The Trust/TSL catalog is a visibility surface, not a purchase workflow and not proof of qualified
  trust production readiness.
- External signing workflow screens, public envelope lookup, and identity-evidence requirements are
  operational tracking/control surfaces; accepted/declined invite responses, identity evidence
  references, and uploaded signed PDFs are not legal signing completion, legal identity proof,
  representative-authority proof, trust-list validation, or qualified-signature validation.
- MCP draft human-verification states are exposed in output envelopes, and AI-origin act drafts now
  have persisted provenance plus accepted/rejected human-review decisions that gate the Signing
  transition, with the Ata editor surfacing that gate. That gate records human review only; it is
  not legal certification, AI output-quality validation, a provider call, hidden signing/trust
  operation, a complete provenance experience, or acceptance of draft text as final minutes. The MCP
  status and spec-coverage resources are local snapshots, and the MCP human-review, compliance,
  and paper-book OCR prompts are static guidance.
- Local B-LT/B-LTA labels and local LTV renewal plans report technical evidence observed in the
  file, including multi-signature DSS/VRI coverage, per-signature evidence gaps, and caller-supplied deadline classification where
  configured; they are not production or legal long-term-validation claims, legally derived
  renewal-deadline decisions, renewal execution, or trust-policy determinations.
- Bounded ASiC-E/CAdES support signs and validates one ASiCManifest/digest-binding container shape;
  it is not XAdES, ASiC-XAdES, embedded LT/LTA evidence, broad ETSI profile completeness, or legal
  validity assessment.
- Template law references are bounded Pending provenance links derived from current rule-pack and
  threshold metadata; they are not exhaustive, legally verified, or a substitute for reviewing the
  generated template wording.
- Template catalog metadata validation is regression coverage for required fields, duplicate IDs,
  family-binding drift, id/stage/channel consistency, and law-reference anchors; it is not legal
  review of template wording, thresholds, channel permissibility, or cited law.
- The law citation resolver and corpus pin/copy UI preserve corpus verification status; copied
  Pending citations are not DRE-verified law text, legal bases, or legal advice.
- Guest/minimal redaction hides selected read-response metadata for current entity, registry, book,
  act, and imported-document views; it is not full anonymization, destructive erasure, or
  certification of access-control/privacy policy completeness.
- Database key-ops status/preflight is a secret-free configuration/build/header classification and
  startup guard with web/API/CLI/store key-env/preflight/rekey evidence. The API/web execution path
  is limited to an already-open keyed SQLCipher store and refuses plaintext stores. It does not prove
  live production SQLCipher encryption, host decryptability, plaintext migration, production secret
  rotation runbooks, completed at-rest encryption certification, or conversion of plaintext SQLite
  stores into encrypted stores.
- The database key migration plan is operator guidance attached to key-ops status; it does not run
  backup/export-restore, verify a live encrypted restore, provide production operator rotation
  flows, or retire plaintext data.
- Erasure DSR completion is bounded preflight evidence with immutable-ledger blockers,
  mutable-sidecar planning, and explicit false destructive/full-erasure flags. It is not GDPR
  erasure, anonymization, physical deletion, redaction execution, or full data-subject erasure.
- Imported-document preservation review policy, UI controls, guardrail acknowledgements, and
  guardrail fields record review requirements, reviewer metadata, and conservative
  original-byte/canonical-conversion decisions for non-canonical evidence. They do not run OCR,
  convert documents to PDF/A, create canonical records, create or validate signed artifacts, certify
  legal acceptance, or validate legal effect.
- Paper-book OCR draft review metadata and UI record non-authoritative review status and explicit
  false canonical/signature/legal flags. They do not execute OCR, create canonical minutes, create
  documents, sign anything, or accept historical scans as legally converted digital records.
- Paper-book canonical-conversion preflight evidence classifies whether an operator-supplied
  evidence set is missing, blocked, or sufficient for a later draft step. It does not execute OCR,
  convert paper/legacy evidence into canonical minutes, create documents, sign artifacts, certify
  legal acceptance, or claim legal validity.
- Validator corpus sidecars, projected evidence metadata, archive package `evidence/index.json`,
  document-bundle `validation_report.evidence_index`, evidence-indexing metadata, and
  settings.read-gated raw technical metadata downloads preserve technical external report context
  and paths only. They are not live trust-list decisions, legal validity conclusions, qualified
  signature validation, DGLAB certification, or authority acceptance.
- Accessibility metadata, bounded tagged structure, `DisplayDocTitle`, `/Tabs /S`, XMP consistency
  checks, and structural self-checks are not PDF/UA delivery; the writer still keeps
  `pdf_ua_claimed: false` and reports limited tagged structure rather than certification.
- Privacy breach-playbook and transfer-control registers plus review receipts are operator
  tracking/control evidence; they do not execute incident response, perform authority/data-subject
  notification, approve or execute transfers, or certify GDPR compliance.
- Data cleanup is bounded storage maintenance for crash reports and retained exports. Retained-export
  dry-run, minimum-age, and keep-latest options are policy controls for that cleanup target only.
  Guarded archive disposal execution is non-destructive ledger/audit evidence only; these surfaces
  are not GDPR erasure, legal disposal approval, legal retention certification, certification of
  data-lifecycle compliance, or physical deletion guarantees beyond the existing bounded cleanup
  behavior.
- Retention execution history, review-only intent/status fields, workflow blockers, required
  approvals, operator decisions, and audit evidence record requests, outcomes, and operator next
  steps for audit/review; they are not retention execution, anonymization, physical deletion, legal
  disposal approval, or GDPR erasure.
- Dashboard legal-hold, sealed-not-archived, and missing-attendance alerts are advisory operational
  next steps; they do not certify legal-hold handling, approve disposal, prove archival completion,
  prove attendance, or validate meeting legality.
- The persisted platform log tail covers API-owned structured events only and is bounded to 512
  entries; it is not stdout/stderr capture, MCP child-process logging, complete historical logging,
  or a general observability sink.
- CI and E2E coverage improve release confidence, the recent-landed checkpoint has broader
  cross-cutting coverage, and web unit tests now enforce coverage thresholds, but the current
  browser suite is not exhaustive, the signed-invite/export/save/imported review/notification-popup
  browser slices are focused regressions, and other lanes do not have broad coverage thresholds.
- Written-resolution evidence warnings are advisory prompts to bind signatory slots or digested
  attachments; they are not proof of written consent, quorum, vote threshold, participant identity,
  or legal acceptance.
- SBOMs, SBOM package linkage, checksums, package manifests, source provenance metadata,
  release-trust metadata validation, Docker signing-status metadata-anchor checks, and Docker OCI
  metadata are not
  substitutes for package signing, notarization, Docker signing, attestation, registry-publication
  verification, or reproducible-build proof; package artifact integrity checks and metadata guards
  are regression checks, not a release trust chain.
- Docker deployment profiles are operational configuration examples, not HA, managed production
  operations, image signing, or attestation.
- `/api/v1` API keys are an implemented integration feature, but a bearer key is still an
  attenuated RBAC principal, not an interactive user session or step-up credential.
