# Chancela - Spec Coverage

*Updated 2026-07-11 through committed implementation snapshot `3e72e087b27aa22ef97d13e1dc003fb0a4c110ea`,
refreshing the `cfcb3d9` baseline, the prior `4566715` coverage point,
and the `c66ea3f`/`5fcaedd` checkpoint snapshot
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
settings.read-gated raw external-validator technical metadata downloads, then
`b43a82e` validator report persistence checkpoint pinning, `9f5b19f`
structured chronology graphs, `98c5d67` raw external-validator download
checkpoint pinning, `ee85a34` dashboard notification icon-only actions,
`cf34a65` mapped inter-word PDF spaces, `66f7b71` executable local paper-book
OCR API, `f2a7242` caller-supplied archive timestamp append API, and `9654eb3`
web local OCR run UI, then `c66ea3f` decomposed PDF/UA blocker reporting,
then `5fcaedd` recent checkpoint refresh, `6eecdc5` notification action
icon-only hardening, `80e83d5` written-resolution evidence status binding,
`ed2a72c` compact validator-report actions, `2451730` paper-book OCR review
browser E2E workflow coverage, `b73de07` declared signer-capacity evidence
preservation, and `246238e` web retention-policy dry-run exposure, followed
by the `10c7403`/`1a99b05` checkpoint refreshes and `259d5ab` accepted
paper-book OCR drafting checkpoint, then `e2ff840` ASiC
structural diagnostics, `bcfa718` dashboard summary polish, and `3426669`
entity single-line rows/filter overflow hardening, then `b1a0683` checkpoint
refresh, `e76a18b` API-owned platform log threshold enforcement,
`f58019c` paper-import clippy cleanup, `c864315` compact notification and
storage settings UI, `5a79f1e` honest platform service-control/logging
contracts, `a5353d6` encrypted package-build defaults, and `3f19872` books
filter/table density hardening, then `386ed95` CI/E2E hardening-plan refresh,
`11eb777` PDF table structure semantics, `e294f0a` export save-prompt routing,
`bc1e15f` dashboard dates tab split, and `e4107ee` platform service-control UI
clarification, then `938b61e` notification popup footer icon-only hardening,
`ff953c5` user/onboarding/act-signatory email field capture, `5aad733`
compact Data Management cleanup controls, and `fa57352` settings-backed
trust-source provider management, then `c3d874b` trust catalog hash display,
`fdb9376` decorative content accounting, `ff1823a` export save cancellation
coverage, `2ffae33` dashboard metric density, and `2187a67` SQLite logical
table usage exposure, followed by `fd70ca0` browser export-save gate unblock
and `c1c57fe` web SQLite table-usage surfacing, then `76fc229` keyed PAdES VRI
`/TU` evidence and `2c88b90` compact notifications/entity filter hardening,
followed by the `35f341d` checkpoint refresh, `5db121a` compact template
filters, and `3e72e08` compliance review tooling, plus working-tree
PAdES DSS caller validation-time attachment, PDF/UA report version 6
structural-depth evidence, retention due-candidate duplicate review-only guard
and queued-status surfacing,
external-validator raw-report attachment hardening including the explicit
Ferramentas raw-report file upload UI, and template
representation/proxy, book-transport, dispatch-proof, and attendance-list
catalog assets, plus working-tree web hot-backup creation UI, backup
recovery-drill receipt API/UI/contract coverage, workflow reminder policy
default/UI/dashboard/year-boundary coverage alignment, and CAE obtainer status
documentation cleanup, plus bounded TSL XML-DSig same-document
`URI="#id"` fragment resolution and bounded P-256 ECDSA-SHA256 verification
for raw XML-DSig `r||s` signatures against the embedded signer certificate,
plus bounded BookDetail paper-book OCR conversion-dossier UI guardrails, CSC
quota division/unification template parity, and all-family standalone
agenda-item templates with 101 total / 41 CSC catalog counts, Pending
law-reference boundaries, and CSC delegation/revocation proposed-resolution
templates, plus bounded structured
platform-log forwarding through `POST /v1/platform/logs/forwarded` with
sanitized denied/rejected/suppressed failure audits, plus
data-status filesystem classification for `platform-logs.json` and
`backup-recovery-drills.json`, a read-only local DGLAB interchange manifest API
endpoint and BookDetail JSON download action, richer Ata editor AI
statement-source provenance rendering, and local
retained-export cleanup dry-run planning plus post-act template sealed-provenance
semantic lint, local `POST /v1/signature/asic/inspect` ASiC inspection plus
decompression-bound ASiC ZIP guardrails, and release workflow static assurance
for the unsigned/local-only trust posture plus production package
manifest-required validation, plus MCP workflow provenance review prompt/resource
guidance and draft-vs-signed comparison review aid, dashboard guest
recent-events redaction, generated-document by-id download routing,
retention due-candidate prior bounded execution projection, automatic
condominium absent-owner communication generation with pending dispatch
evidence status, settings.read-gated raw external-validator raw-report byte downloads,
imported-document review receipt rendering, and trust catalog identifier-match
explanations, plus release clean-source provenance gating, seeded role-drift
diagnostics, archive readability/ZK caveat metadata, template family/channel
rule guards, and MCP discoverability updates for trust-catalog filters and
redacted external-validator report summaries.
Earlier coverage text remains prior snapshot context. All top-level spec areas remain **PARTIAL**.
This is an implementation and test coverage snapshot, not a legal certification,
not production CMD approval, not DRE verification promotion, not full PDF/UA
delivery, and not a claim that qualified-trust production operation, live
provider validity, provider credentials, authority approval, release
signing/notarization/attestation, live SQLCipher encryption/rotation/migration
across all builds, SQLCipher hardware-derived key fallback/default completion,
legal document acceptance, signed-PDF legal validity, destructive retention
execution, or destructive GDPR erasure is complete.*

Status vocabulary:
**IMPLEMENTED** (landed and verifiable), **PARTIAL** (usable slice landed but
the spec requirement is not complete), **STUB** (shape exists, behavior deferred),
**MISSING** (no implementation), **N/A-v1** (deliberately deferred).

The old exact requirement counts are intentionally not carried forward: the recent
batch changed enough surfaces that the counts need a full line-by-line re-audit before
being useful. The matrix below records the current factual coverage and the remaining
blockers.

Implementation checkpoints covered here:

- Working tree keeps Architecture/Data/Roles/CI **PARTIAL**: `POST
  /v1/platform/logs/forwarded` now accepts supervisor- or operator-forwarded
  structured platform log entries into the existing platform log ring. The route
  is gated by non-meta `platform.logs.write@Global`; fresh seeded roles grant it
  only to Owner and Platform Administrator, while API Client does not receive it
  by default. Existing persisted non-Owner seeded roles are not forcibly
  reconciled on load, so older customized Platform Administrator roles may need
  an explicit admin role update after upgrade. The handler reuses existing
  threshold evaluation, global/service `off` suppression, data-dir persistence,
  512-entry retention, and `GET /v1/platform/logs` tail behavior. The request
  schema accepts only `service_id`, a non-`off` `level`, `target`, `message`,
  and optional bounded JSON `context`; it rejects unknown services, unknown
  fields, raw `stdout`/`stderr` fields, blank or oversized service/target/message
  values, blank/oversized/deep context, and stream or secret-like context keys.
  Accepted and retained forwarded entries append exactly one sanitized
  `platform.log.forwarded.accepted` ledger event with only the retained log
  id/seq/timestamp, service_id, level, target, message length/SHA-256, context
  key count, and context serialized size when context is present. Authenticated
  RBAC denial appends one sanitized `platform.log.forwarded.denied` route
  outcome audit, authenticated malformed JSON and rejected structured payloads
  append sanitized `platform.log.forwarded.rejected` reason-code audits, and
  threshold/global/service `off` suppression appends sanitized
  `platform.log.forwarded.suppressed` digest-only audits. Missing or invalid
  bearer requests remain unaudited. These audit events carry no raw body,
  message, context keys, parse errors, stdout, stderr, tokens, secrets, or user
  strings. Internal logging callers still ignore the returned `Option`,
  preserving threshold-suppression and non-failing semantics. This is structured
  ingress into the bounded API-owned log tail plus bounded accepted/failure
  audit markers only: it does not add process lifecycle control,
  stdout/stderr tailing or capture, production supervisor/SIEM/HA/observability
  guarantees, a generalized observability sink, log retention/deletion
  semantics, or a legal/compliance claim.
- Working tree keeps Data/Architecture/CI **PARTIAL**: data-status filesystem
  telemetry now classifies `platform-logs.json` under `platform_logs` and
  `backup-recovery-drills.json` under `backup_recovery_drills`, while preserving
  the existing durable data-folder permission/status behavior and filesystem
  usage basis. Focused API/static markers pin the root-classifier mapping and
  the `/v1/data/status` filesystem concern rows for those sidecars. This is
  storage telemetry classification only; it does not add deletion, retention
  execution, legal archive/custody proof, or lifecycle-policy semantics.
- Working tree keeps Data/Documents/UX/CI **PARTIAL**: `POST
  /v1/data/cleanup` export dry-runs now compute `would_delete_files`,
  `would_delete_directories`, and `would_delete_bytes` while keeping
  `deleted_files`, `deleted_directories`, and `deleted_bytes` at zero and
  leaving retained-export files and directories in place. The export cleanup
  policy fields remain export-only: `dry_run`, `minimum_age_days`, and
  `keep_latest` are still rejected for the crash cleanup target and other
  non-export targets. Settings Data Management now uses a preview-only exports
  request of `{ target: "exports", dry_run: true, minimum_age_days: 30,
  keep_latest: 5 }` and renders the resulting plan with explicit copy that no
  files were removed. This is retained-export cleanup planning and UI preview
  only; it is not GDPR erasure, legal disposal, anonymization/redaction
  completion, retention execution, or a deletion/legal-effect claim.
- Working tree keeps Documents/Workflows/UX/CI **PARTIAL**: accepted
  paper-book OCR drafts can now create/list metadata-only, non-canonical
  conversion dossiers through `POST
  /v1/books/paper-import/{id}/ocr-drafts/{draft_id}/conversion-dossier` and
  `GET /v1/books/paper-import/{id}/conversion-dossiers`. The dossier requires
  an accepted matching draft, stores accepted-review metadata/digests/page spans
  only, returns an existing dossier for idempotent duplicate creation without
  another ledger event, and keeps raw OCR text out of API responses and ledger
  events. BookDetail now lists existing dossier metadata and exposes creation
  only for accepted OCR drafts without an existing dossier, keeps the mutable
  draft-act creation action separate, renders the no-claim flags and notice, has
  no automatic dossier POST, and does not call document, signature, seal, or
  archive endpoints from the dossier UI. Act, canonical-act, canonical-minutes,
  document, signed-document, archive-package, PDF/A, PDF/UA, signature, seal,
  and legal-validity flags stay false. This remains bounded review metadata
  evidence only; canonical paper-book conversion is not implemented.
- Working tree keeps Signatures/Workflows/UX/CI **PARTIAL**: SigningPanel now
  lists per-act workflow-only external-signing envelopes with order policy, slot
  labels/statuses, identity requirements, completion summary, blocking slots,
  and the backend no-legal/no-qualified notice. Operators can create
  workflow-only external-signing envelopes with order policy and signer slots.
  External signer invites can optionally link to an existing envelope slot by
  `external_envelope_id` plus `external_slot_id`; leaving the slot unselected
  preserves the tracking-only payload. Invite creation initiates the slot
  through the existing envelope order policy: later sequential slots fail with
  409 and no token or stored invite, while the first sequential slot and
  parallel slots are allowed and marked initiated. The web form renders those
  sequential linked-slot 409s as safe operational messages without raw
  backend/token-like detail and clears the warning after slot selection changes.
  Create/list/public lookup expose redacted `external_envelope` workflow/slot
  metadata, and Ferramentas maps `workflow: external_envelope` to a localized
  label in rows and token lookup. Invite accept/decline remains tracking-only
  audit state; it does not sign or complete envelopes/slots, perform provider
  signing, collect PIN/OTP/passphrases, capture evidence, expose public token
  material, provide slot signing, provide envelope completion UI, or claim
  legal/QES/qualified status. Provider-backed signing, evidence capture,
  document-gated completion, legal completion, and qualified status remain
  incomplete.
- Working tree keeps Signatures/Documents/CI **PARTIAL**: local PAdES DSS
  attach now accepts an optional caller-supplied `validation_time`, validates it
  as RFC 3339, writes local DSS VRI `/TU` metadata from caller-supplied evidence,
  and reports the resulting local renewal-plan transition from missing DSS
  validation time to document-timestamp and monitor states when local evidence is
  present. Malformed `validation_time` is rejected without digest or audit-event
  mutation. This is caller/local technical evidence only: it does not fetch live
  OCSP, CRL, TSA, or TSL material, does not claim legal B-LT/B-LTA, production
  long-term profile, QES, qualified status, legal LTV, or trust-provider
  acceptance.
- Working tree keeps Documents/CI **PARTIAL**: PDF accessibility report JSON
  version 6 now includes structural-depth evidence and bounded topology facts
  for the local tagged-PDF profile while retaining the version 5 writer-owned
  decorative-artifact accounting for the fixed header rule, explicit horizontal
  rules, vote-table header/footer rules, and signature blank lines. Page breaks
  stay excluded from decorative-artifact accounting because they do not emit
  writer-owned drawing artifacts. `LimitedTaggedStructure` remains
  machine-visible, `pdf_ua_claimed` stays false, and generated PDFs still emit no
  PDF/UA certification claim or `pdfuaid` metadata. This is local reporting and
  bounded self-check evidence only, not PDF/UA conformance, external validator
  certification, legal/reader acceptance, or complete accessibility delivery.
- Working tree keeps Data/Architecture/UX/Workflows/CI **PARTIAL**: Data
  Management now exposes a `data.backup`-gated hot-backup creation action backed
  by `POST /v1/backup`, posts no request body, disables itself when the instance
  is not using an open durable store, refreshes recovery/data status after
  success, and renders only a bounded non-secret manifest summary: backup path,
  created timestamp, total bytes, file count/bytes, store schema version, ledger
  length, and ledger verification status. The API/store restore preflight path
  verifies the archive manifest, every manifest-listed member digest, and ledger
  integrity in an isolated snapshot, then cleans up the temporary preflight copy
  without swapping the live DB, staging sidecars, appending `ledger.restored`, or
  reloading live state. `POST`/`GET /v1/backup/recovery-drills` now records an
  operator-triggered, preflight-only receipt from that path, persists only
  bounded sidecar evidence (archive reference, preflight ok/ready/encrypted,
  ledger verified, manifest counts/bytes/schema/ledger length, and optional
  operator notes/custody location), and rejects true overclaim flags for
  `restore_executed`, `live_db_swapped`, `sidecars_staged`,
  `ledger_restored_appended`, `data_deleted`, `offsite_custody_proven`, and
  `legal_archive_certified`. The web UI exposes bounded manifest/evidence before
  any destructive restore path, handles null preflight manifests safely, and adds
  an explicit Data Management recovery-drill action that posts to the receipt
  route, preserves passphrase bytes exactly on submit, clears the passphrase
  afterward, and does not call live restore. Focused `GestaoDadosSection`,
  `LivrosIntegridadeSection`, and contract tests pin operation discoverability,
  durable-store gating, failure surfacing, status invalidation, nullable
  manifest handling, optional `operator_notes` / `custody_location` receipt keys
  as permitted-but-not-required, overclaim false flags, no live restore call, and
  redaction of arbitrary/secret-like backend fields plus per-file names, digests,
  app version details, and passphrases from the DOM. The CAE obtainer module
  documentation also drops stale skeleton-status wording in favor of the current
  bounded implementation/unavailable-source status. This is operator UI,
  non-destructive restore preflight and recovery-drill receipt evidence,
  acceptance-cleanup, and regression coverage only; it is not restore execution,
  production backup policy, RPO/RTO certification, disaster-recovery readiness,
  off-site custody proof, encryption proof, legal archive certification, or new
  CAE provider/legal behavior.
- Working tree keeps Template Catalog/UX/CI **PARTIAL**: the embedded template
  catalog now loads 101 JSON template assets (101 total / 41 CSC), including
  standalone
  `procuracao-representacao/v1` instruments for commercial companies,
  condominiums, associations, foundations, and cooperatives. The company asset
  also covers the `carta de representacao` use case for sociedades anonimas
  when applicable. It also adds `ponto-ordem-trabalhos/v1` Convocatoria
  standalone agenda-item templates for all five supported families and
  `termo-transporte/v1` book-continuation terms
  for condominiums, associations, foundations, and cooperatives, bringing that
  book-lifecycle instrument to every supported family. It now also includes
  `csc-ata-divisao-quotas/v1` and `csc-ata-unificacao-quotas/v1`, matching the
  sibling CSC quota Ata assets for physical/hybrid/telematic/written-resolution
  channels, `QualifiedPreferred` signature-policy hint, `csc-art63/v2`
  rule-pack binding, and the unresolved
  `csc.deliberacao.maioria_qualificada` threshold marker. It also includes
  `csc-ata-delegacao-poderes/v1` and `csc-ata-revogacao-poderes/v1` as CSC Ata
  proposed-resolution text templates for delegation and revocation of powers;
  they bind `csc-art63/v2`, render the proposed resolution text, and introduce
  no new threshold marker. The representation
  assets are bound to `Convocatoria` and physical/hybrid/telematic channels; the
  transport terms are channel-neutral `TermoEncerramento` assets. All derive
  family rule-pack law references and signature policy hints. Catalog tests
  render every family representation and transport asset. The metadata guard now
  also requires authored `BlockSpec` template strings for `Certidao` and
  `Extrato` assets to reference sealed-act provenance fields `ata_number` and
  `payload_digest`, with whole-catalog and synthetic missing-binding regression
  coverage at test/build time only. All six notice
  templates (`csc` AG/gerencia, condominium, association, foundation, and
  cooperative) now render TPL-20 recipient dispatch proof from
  `convening.recipients` including recipient, dispatch channel, reference, and
  dispatch date. All five attendance-list templates render structured
  `attendees` rows with in-person/represented/absent status and proxy names,
  while the CSC list now surfaces captured capital weight and the condominium
  list retains permilagem rendering. The recent-landed static checkpoint pins
  the 101-asset census, 41 CSC count, agenda-item IDs/rendering, all-family
  dispatch-proof rendering, all-family attendance-list rendering, CSC quota
  Pending law-reference markers, and CSC delegation/revocation asset/rendering
  markers. This narrows template parity and evidence-rendering
  gaps only; law references stay Pending/non-authoritative, no DRE verification
  or legally verified threshold value is added, asset wording is unchanged, no
  external registry/provider or signing-process behavior is added, and
  wording, law references, thresholds, channel suitability, sealed-act
  provenance semantics beyond the local reference guard, transport legal effect,
  quota legal sufficiency, delegation/revocation authority verification or
  legal sufficiency, registry submission, agenda-item legal sufficiency, and
  legal sufficiency of dispatch/attendance proof still need legal review before
  being treated as authoritative.
- Working tree keeps Signatures/Documents/UX/CI **PARTIAL**:
  external-validator report metadata can now optionally carry bounded,
  digest-verified raw report bytes, including explicit Ferramentas file
  selection/upload for the raw report. File selection computes a local safe
  summary (filename, content type, byte size, SHA-256, and operator/browser
  provenance) and does not upload automatically. The existing manual JSON
  metadata path still works; when the operator submits with a selected raw
  report, the UI sends `raw_report.content_base64` with `content_type`,
  `size_bytes`, `sha256`, and a safe `source_filename` when available. The API
  accepts embedded `raw_report.content_base64` only when declared size and
  SHA-256 match, rejects mismatches fail-closed, keeps list/create responses
  free of inline raw bytes, exposes raw-report summaries in web/API contracts,
  and projects raw-report evidence into document-bundle indexes plus archive
  package members under
  `evidence/external-validators/{case_id}-{validator_family}-raw-report.{extension}`
  when bytes are verified. The recent-landed static checkpoint now pins the raw
  report parser, upload bounds, byte redaction, archive-package embedding,
  document-bundle indexing, file-selection/no-auto-upload UI, submit payload,
  summary-only rendering, and no-claim notice markers. UI and response rendering
  show only filename/type/size/digest/provenance summaries and never raw report
  contents. This is technical preservation/fixity evidence only, not
  external-validator legal acceptance, legal validation, certification,
  PDF/UA/PAdES certification, compliance proof, trust-list validation, full
  report replay, provider validity, or authority approval.
- Working tree keeps Signatures/Documents/API/CI **PARTIAL**: `GET
  /v1/external-validator-reports/{case_id}/{validator_family}/raw-report` now
  lets `settings.read` actors download only retained raw external-validator
  report bytes for one safe report identity, with `Content-Type` and attachment
  `Content-Disposition` headers. Missing reports, metadata-only/manifest-only
  raw-report summaries, and sidecars without retained bytes return 404; unsafe
  identities, malformed sidecars, and duplicate or ambiguous identities fail
  closed. List/create responses remain redacted and do not expose
  `content_base64`; the Ferramentas UI still never renders raw report bytes and
  upload remains explicit. This is technical byte preservation/access only: no
  auto-upload, validator legal acceptance, legal validation, certification,
  trust claim, external-validation claim, provider approval, or UI raw rendering
  is implemented.
- Working tree keeps AI/MCP/Architecture/CI **PARTIAL**: MCP now advertises the
  static `workflow_provenance_review_checklist` prompt and the read-only
  `chancela://mcp/workflow-provenance-review` resource. Both are offline review
  aids with no caller arguments, no bridge/API/provider calls, no secrets, and
  explicit false legal-validity, source-certification, provider, trust,
  external, archive-certification, and signature-qualification claim flags. This
  is human review guidance only, not workflow completion, AI completion, MCP
  completion, source certification, trust validation, or a provider/legal claim.
- Working tree keeps AI/MCP/Architecture/CI **PARTIAL**: MCP also advertises the
  static `draft_signed_comparison_review_checklist` prompt and read-only
  `chancela://mcp/draft-signed-comparison-review` resource. The resource is
  local JSON only, covers document identifiers, digests, text/version
  differences, mismatch triage, and human-review notes, accepts only `uri` with
  no arguments or extra params, makes no
  bridge/API/provider calls, exposes no secrets, and keeps legal-validity,
  source-certification, trust, external-validation, archive-certification, and
  signature-qualification claims false. The spec-09 MCP coverage payload still
  leaves `ai_01_claimed` and `full_ai_mcp_completion_claimed` false, so this is
  static review aid coverage only, not AI completion, MCP completion, automated
  comparison, source certification, trust validation, external validation, or
  signature qualification.
- Working tree keeps Data/Roles/Workflows/CI **PARTIAL**: `GET /v1/dashboard`
  now returns `recent_events: []` for guest/minimal redaction callers while
  Owner and `Leitor` sessions keep the recent ledger-event feed. Guest remains
  forbidden from `GET /v1/ledger/events`, and the slice adds no permission
  grants or broader privacy/anonymization completion claim.
- Working tree keeps Data/Archive/UX/API/CI **PARTIAL**: the general Arquivo
  page now reads ledger rows from additive `GET /v1/ledger/events/page` instead
  of loading the whole bare-array feed, while `GET /v1/ledger/events` remains
  bare-array compatible. The paged route is newest-first by default, returns a
  numeric `next_cursor`/`before_seq` cursor, and normalizes page limits to
  default 100, minimum 1, and maximum 250. Server-backed filters are shared by
  the paged list and archive export for chain, scope/search, kind, actor, date
  range, and page/export limit. The web Arquivo UI uses Livro-style filters,
  an icon-only clear-filters button with tooltip/accessibility label, and an
  export format selector for canonical PDF/A plus JSON, TXT, CSV, and HTML
  audit/interchange exports using the active filters. API and web tests pin a
  1000+ event first page, cursor load-more, numeric cursor typing, serialized
  filters, shared list/export limit normalization, and filtered export formats.
  This is bounded archive browsing/export UX and API coverage only: it does not
  prove persistent-store boot-time SQL paging, make non-PDF/A exports preserved
  evidence, or complete legal archive certification/compliance.
- Working tree keeps Documents/Workflows/API/CI **PARTIAL**: on-demand generated
  post-act documents now return `/v1/documents/generated/{document_id}` and can
  be downloaded by their own generated document id in durable and in-memory
  modes. The route inherits `act.read` from the owning act, and the canonical
  `/v1/acts/{act_id}/document` route remains the sealed Ata target for signing
  and bundles. Sealing a condominium act with absent attendees now also
  generates `condominio-comunicacao-ausentes/v1` automatically alongside the
  Ata, leaves the canonical act document as the Ata, makes the communication
  retrievable by generated document id in durable and in-memory modes, and emits
  `document.generated` payload/header evidence with dispatch status
  `required_pending`, `evidence_attached=false`, and
  `dispatch_completed=false`, including server E2E re-checks after restart.
  This is generated-document retrieval and pending-dispatch evidence only: no
  signing, bundle, template, threshold, law, provider, registry, dispatch-sent
  proof, dispatch completion, legal sufficiency, or legal-effect claim is
  added.
- Working tree keeps Documents/Archive/API/CI **PARTIAL**: `GET
  /v1/books/{id}/archive/local-dglab-interchange-manifest`, gated by
  `book.export@Book`, returns a deterministic local
  `LocalDglabInterchangeManifest` scaffold with schema/profile
  `chancela-local-dglab-interchange-manifest/v1`. It is built from an already
  validated internal `PackageManifest`, mirrors package/provenance/
  classification/rights/language/retention/fixity/file-entry metadata,
  deterministically sorts file entries by package path, validates back against
  the source manifest, and rejects unsafe paths, blanks, mismatches, unsorted
  entries, and any true official-DGLAB/certification/approval/legal-archive/
  destructive-disposal claim flags. Focused API tests pin permission gating,
  deterministic JSON, no ZIP sidecar member, package validation change,
  persisted package bytes, ledger event, or persisted manifest bytes. BookDetail
  exposes a direct save action that calls that GET endpoint and saves
  `application/json` with a `.json` filename while keeping the preservation ZIP
  and export paths untouched. This is local scaffold metadata JSON only: no
  official DGLAB export, government filing, import path, disposal execution,
  DGLAB certification, legal archival certification, PDF/A/PAdES/PDF-UA
  certification, authority approval, or legal archive acceptance is implemented.
- Working tree keeps Signatures/Trust/CI **PARTIAL**: the TSL XML-DSig verifier
  now resolves bounded same-document `URI="#id"` references when a unique
  matching element is present in the supported minimal TSL shape, and rejects
  missing, duplicate, external, or unsupported fragment targets instead of
  silently validating the wrong bytes. It also verifies bounded P-256
  ECDSA-SHA256 XML-DSig signatures only when the signer certificate is embedded
  in `KeyInfo` and the signature value is the XML-DSig fixed-width raw `r||s`
  form; DER-encoded ECDSA values remain rejected. This narrows the prior TSL
  fixture gap only; it is not real C14N, signer trust anchoring, certificate
  path/revocation policy validation, multiple-reference support, transform-chain
  support, broad ECDSA/XML-DSig profile support, legal trust certification, or
  proof that the embedded signer is trusted.
- Working tree keeps Signatures/Documents/CI **PARTIAL**: `POST
  /v1/signature/asic/inspect` exposes read-only local technical ASiC profile
  inspection for a base64 ASiC ZIP with optional filename, declared size, and
  declared SHA-256. The endpoint validates JSON/base64 decoding, declared
  fixity, readable ZIP shape, and unsafe member paths before reporting profile
  shape, bounded profile, stable blockers, member paths, manifest diagnostics,
  signature diagnostics, and conservative no-claim fields. It runs local CAdES
  cryptographic validation only when the package is blocker-free and matches the
  bounded ASiC-S/CAdES single-payload or ASiC-E/CAdES single-manifest candidate
  shapes. ASiC-XAdES and direct XAdES remain structured unsupported diagnostics:
  XAdES validation is not performed. ASiC ZIP processing now enforces both
  per-member and aggregate actual decompressed-size caps across payloads,
  manifests, CAdES signatures, XAdES signatures, unsupported `META-INF`
  members, and other non-directory members, so underdeclared ZIP entries cannot
  bypass inspection blockers. This is local technical inspection only: no
  signing, storage, archive mutation, live provider call, TSA/TSL/OCSP/CRL
  fetching, trust anchoring, XAdES validation, legal validity, QES,
  B-LT/B-LTA, eIDAS legal-effect, or production ASiC compliance claim is
  implemented.
- Working tree keeps Signatures/Trust/UX/CI **PARTIAL**: identifier-filtered
  TSL/TSA catalog rows can now include optional `identifier_match` explanations
  for the technical field that matched. The API omits `identifier_match` when no
  identifier filter is used and preserves strict lookup behavior for complete
  certificate SHA-256 fingerprints/SKIs without loose partial-hash inference.
  Ferramentas renders "Matched by technical catalog identifier only" on matched
  rows/details, keeps digest display truncated, and copies full SHA-256/SKI
  values. This is technical catalog identifier explanation only, not legal
  validity, certificate trust, provider approval, external validation,
  qualified-status, or trust-list certification.
- Working tree keeps Documents/UX/CI **PARTIAL**: imported-document metadata now
  includes a derived `Recibo de revisão` panel built from the existing imported
  document view fields. Pending documents show `Sem recibo de revisão` and no
  fake reviewer/time/note/guardrail receipt; reviewed documents show status,
  reviewer, time, note, required and acknowledged guardrails, and explicit
  no-claim rows for OCR, conversion, canonical PDF/A replacement, signed PDF
  artifact, and legal acceptance. The UI uses the existing imported-document
  view/review mutation only and tests block accidental bytes, archive,
  signed-document, external-validator, trust, conversion, or OCR calls. This is
  review metadata display only; no OCR, conversion, PDF/A replacement, signed
  artifact creation/validation, new route/schema/mutation/download, or legal
  acceptance claim is implemented.
- `3e72e08` keeps Legal/Data/Signatures/Documents/UX/CI **PARTIAL**:
  opening/closing termo signatories now accept structured name/capacity/email
  records through the legacy `required_signatories` write field while exposing
  additive `required_signatory_records_*` read fields and legacy fallback
  compatibility. Settings now shows a retention execution review queue backed by
  `/v1/privacy/retention-executions` filters and the persisted
  `retention.executions.json` fixture, while keeping destructive disposal and
  erasure flags false. Backend data status now reports non-secret
  `database_encryption` key-source/preflight evidence and a fail-closed
  `hardware_derived_fallback` selector/status. The Ferramentas PDF verifier now
  renders DSS/VRI `/TU`, DocTimeStamp validation, per-signature local renewal
  gaps, and explicit no-live-trust/no-legal-LTV fields. This is review/status/UI
  evidence only, not destructive retention execution, hardware-derived key
  custody, production SQLCipher migration/rotation completion, live trust
  validation, qualified-signature validity, or legal LTV/legal-effect
  certification.
- Working tree keeps Legal/Data Lifecycle/UX/CI **PARTIAL**: the API now exposes
  read-only `GET /v1/privacy/retention-due-candidates` for closed-book
  archive/document candidates based on active retention policies, closing date
  plus supported `PnY`/`PnM`/`PnD` retention periods, legal-hold blockers,
  required approval metadata, unsupported-period findings, and explicit false
  destructive/full-erasure flags. Settings renders the due-candidate scanner
  report through the privacy retention panel without creating execution,
  disposal, or erasure records on page load, and each candidate row now has an
  explicit operator-triggered review request that calls the retention dry-run
  endpoint with an `execution_request`, forced/default `review_only`, then
  refreshes due-candidate and execution-history queries after an execution record
  is returned. Duplicate `review_only` requests for the same candidate/policy
  reuse the existing `awaiting_review` execution, including the concurrent
  duplicate guard, and add no extra execution record or ledger event.
  Due-candidate GET remains read-only while surfacing existing queued review
  status/id/time, and Settings shows queued review status/id/time instead of
  posting again. Due-candidate reads can also project safe prior bounded
  `executed` archive/no-action evidence for the same candidate and policy,
  requiring internal bounded-executor evidence, acted targets, and false
  destructive-disposal/full-erasure flags; the projection is read-only,
  side-effect free, uses canonical bounded `prior_execution.next_step` text
  instead of persisted free-form text, and Settings shows bounded evidence while
  suppressing duplicate review actions only for projected rows. This is
  non-destructive review/scanner UI evidence only: it does not dispose, erase,
  delete, anonymize, redact, mutate legal holds or retention policies, resolve
  candidates, approve legal disposal, or perform legal completion.
- `5db121a` keeps Template Catalog/UX/CI **PARTIAL**: the Minutas catalog now
  keeps search/family/stage in a compact primary filter row, moves
  locale/channel/signature/rule-pack into a collapsed advanced details area, and
  pins no-overflow CSS with focused `TemplatesCatalogPage` assertions for
  collapsed state, primary-field count, clear behavior, and responsive grid
  sizing. This is template browsing ergonomics and regression coverage only, not
  template legal review, verified threshold values, full template-market parity,
  or exhaustive law-reference mapping.
- `2c88b90` keeps UX/Workflows/CI **PARTIAL**: the Notifications page now uses
  compact list rows, folds status/type tags into the notification title, and
  preserves icon-only controls, while the bell badge has explicit
  z-index/pointer-events coverage. Registered-entity primary filters now stay
  compact and nowrap on desktop, wrap on mobile, and keep advanced filters on a
  no-overflow grid. Focused worker validations reported 20 notification tests,
  4 export-save browser-gate Chromium tests, 21 entities tests, plus
  prettier/eslint/diff checks. This is notification/entity UI hardening only,
  not new notification semantics, legal notice delivery, workflow completion,
  or mobile UX completion.
- `76fc229` keeps Signatures/Documents/CI **PARTIAL**: PAdES DSS reports now
  expose `vri_tu_keys`, API signature/PDF validation payloads include keyed TU
  evidence, and multi-signature renewal planning checks
  `has_vri_tu_for_key` for the specific VRI key instead of treating any `/TU`
  as sufficient. Focused worker validations reported `cargo fmt`,
  `cargo test -p chancela-pades`, `cargo test -p chancela-api pdf_signature`,
  `cargo test -p chancela-api signature_evidence_status`,
  `cargo check -p chancela-signing`, `cargo check -p chancela-api`, and
  `git diff --check`. This is local technical evidence/planning only, not
  production PAdES-LT/LTA renewal execution, live revocation validation,
  qualified signature operation, provider approval, or legal validity
  certification.
- `c1c57fe` keeps UX/Data/CI **PARTIAL**: Data Management now renders
  `sqlite_logical` per-table payload rows separately from aggregate logical
  usage, with optional `DataUsageConcern.kind` contract tolerance, test fixture
  rows marked `sqlite_logical_table`, and compact
  `data-status-sqlite-table-list` / `data-status-sqlite-table-row` CSS and DOM
  coverage. Focused `GestaoDadosSection` tests pin the visible table names,
  row-count/byte cells, and removal of redundant "SQLite table ..." labels. This
  is web telemetry presentation only, not physical SQLite page accounting,
  storage quota enforcement, live SQLCipher proof, migration execution, erasure,
  or data-lifecycle certification.
- `fd70ca0` keeps CI/UX **PARTIAL**: books and entity CSS assertion tests no
  longer statically import `node:fs`; they dynamically import it inside the
  runtime-only CSS checks so the browser export-save Playwright bundle is not
  blocked by Node-only test imports. The focused books/entities unit tests,
  eslint/prettier, and
  `npm run test:browser --workspace apps/web -- e2e/export-save-hardening.spec.ts`
  passed for 4 Chromium tests after this unblock. This is browser-test gate
  hygiene only, not new product behavior, export semantics, archive legality,
  or broader browser coverage.
- `2187a67` keeps Data/Architecture/CI **PARTIAL**: data-status SQLite logical
  usage now includes per-table logical payload entries such as
  `sqlite_table_events`, with row counts, estimated bytes, and
  `sqlite_logical_payload` basis preserved in the API response. Focused tests
  pin `sqlite_logical_usage_includes_per_table_payload_stats` and the durable
  data-status payload no longer emits the old "sqlite logical usage not
  reported" placeholder. This is read-only storage telemetry only, not physical
  SQLite page accounting, live SQLCipher encryption proof, storage quota
  enforcement, migration execution, GDPR erasure, or data-lifecycle
  certification.
- `2ffae33` keeps UX/Workflows/CI **PARTIAL**: the six primary dashboard metric
  cards now carry a compact `desktop-six` density marker and tighter summary CSS
  so they remain scannable as one desktop row, with focused `DashboardPage`
  coverage for the card order and marker. This is dashboard density regression
  coverage only, not new analytics, workflow semantics, legal-calendar proof,
  attendance proof, or dashboard completion.
- `ff1823a` keeps UX/Documents/CI **PARTIAL**: focused browser E2E now covers a
  sealed-act PDF export where the browser save picker is cancelled, keeps the
  visible `Guardar cancelado` result, preserves the suggested filename/options,
  prevents browser-download fallback, and records no state mutation. This is
  export cancellation hardening only, not a new document format, signing,
  notarization, archive legality, or filesystem policy guarantee.
- `fdb9376` keeps Documents/CI **PARTIAL**: PDF accessibility non-text
  accounting counts only blocks that the writer emits as decorative artifacts,
  including header rule, explicit rule, vote-table rule, and signature-line
  targets, so page breaks no longer require decorative artifact entries.
  Focused tests pin
  `accessibility_page_breaks_do_not_require_decorative_accounting` and the
  `emits_decorative_artifact_block` boundary. This is local accounting honesty
  only, not full PDF/UA delivery, complete non-text modeling, external
  validation, or legal document acceptance.
- `c3d874b` keeps UX/Signatures/Trust/CI **PARTIAL**: the Ferramentas trust
  catalog now groups provider/service/TSA result lists with labelled result
  groups, keeps accepted TSA hashes in the dedicated `trust-accepted-hash`
  wrapper, and pins `Registos TSA` list grouping plus truncated/copyable digest
  behavior in focused web tests. This is trust-catalog presentation/accessibility
  hardening only, not live trust-source validation, production TSA operation,
  provider onboarding, or qualified-trust legal completion.
- `fa57352` keeps UX/Signatures/Trust/CI **PARTIAL**: Settings can now manage
  multiple TSL source URLs and TSA provider entries with localized labels and
  focused tests for rendering, autosave, default TSA selection, and legacy
  settings payload defaults. This is settings-backed provider configuration
  coverage only; backend/runtime source resolution and status, live TSL/TSA
  reachability, production trust-policy execution, and legal trust completion
  remain partial.
- `5aad733` keeps UX/Data/CI **PARTIAL**: Data Management storage and cleanup
  rows are denser and more scannable, with compact cleanup labels, descriptions,
  metrics, and retained-export cleanup coverage that preserves the crash cleanup
  target boundary. Focused tests pin the cleanup-row DOM/target behavior. This
  is storage-maintenance UI hardening only, not deeper per-table payload
  statistics, broader backend storage telemetry, physical deletion guarantees,
  GDPR erasure, or data-lifecycle certification.
- `ff953c5` keeps UX/Data/Workflows/CI **PARTIAL**: the web first-run
  onboarding flow, Settings user create/edit screens, and Ata signatory editor
  now capture optional email fields through existing backend contracts and patch
  bodies, with focused tests for first-user creation, user create/edit, and act
  signatory email round-trip. Book opening/closing signatory requirements remain
  string-only because the backend contract still lacks structured signatory
  email fields there. This is web capture and regression coverage only, not
  email verification, notification delivery, identity proof, or complete
  signatory modeling.
- `938b61e` keeps UX/CI **PARTIAL**: the notification popup footer "Ver todas"
  action is now an icon-only tooltip-backed link with an accessible name,
  matching the existing notification popup action pattern. The focused
  `NotificationBell` test now asserts the footer link through the shared
  icon-only control helper. This is notification-popup accessibility and
  consistency coverage only, not broader notification/dashboard UX completion,
  new notification semantics, workflow completion, or legal notice validation.
- `e4107ee` keeps UX/Architecture/CI **PARTIAL**: the platform operations UI now
  renders only backend-reported meaningful service-control actions, separates
  action-capability limitations from general service limitations, and displays
  the effective app/API/MCP logging level so global `off` visibly overrides
  stale service overrides. Focused Settings tests pin the API self-control and
  MCP supervisor-required boundaries. This is control/status presentation and
  regression coverage only, not supervisor-backed lifecycle control,
  stdout/stderr tailing, MCP process logging, or durable observability.
- `bc1e15f` keeps UX/Workflows/CI **PARTIAL**: dashboard dated reminders now
  live in a dedicated `Datas` tab, with the current-work tab focused on open
  books and act-state summaries. Tests pin the subtab order and keep dated
  reminder sorting/deduplication coverage on the new tab. This is navigation and
  information-density hardening only, not deeper legal-calendar proof,
  attendance evidence, workflow completion, or new reminder semantics.
- `e294f0a` keeps UX/Documents/Archive/CI **PARTIAL**: user-owned exports now
  route through the shared save helper with desktop/browser save-prompt support
  where available, visible cancellation handling, and safe browser-download
  fallback for unavailable or failed direct save APIs. Focused tests cover act
  PDF, working-copy, ledger PDF/A, book bundle, preservation package, and
  paper-import package export paths while preserving canonical/non-canonical
  filenames. This is export ergonomics and regression coverage only, not a new
  archive format, legal evidence upgrade, signing, notarization, or filesystem
  policy guarantee.
- `11eb777` keeps Documents/CI **PARTIAL**: generated PDF key/value and vote
  tables now use bounded table structure roles with Table/TR/TH/TD semantics,
  RoleMap targets point custom table roles at `Table`, and the accessibility
  report no longer lists local table semantics as PDF/UA blockers. Tests pin the
  structure tree and deterministic accessibility JSON while `pdf_ua_claimed`
  remains false. This is local table-structure semantics only, not full PDF/UA
  delivery, external validator certification, complete non-text content
  coverage, or legal document acceptance.
- `386ed95` keeps CI/Release **PARTIAL**: `docs/CI-E2E-HARDENING-PLAN.md` was
  refreshed for the then-current CI shape through `783538c`, including
  SQLCipher package-build defaults, platform service/logging boundaries,
  export/save prompt expectations, local LTV planning honesty, and recent
  focused check bullets. This is checklist and checkpoint metadata, not a fresh
  full-green release claim, release signing/notarization, image attestation, or
  live-provider coverage.
- `3f19872` keeps UX/CI **PARTIAL**: the books page now uses compact primary
  filters for search/state/type, keeps activity/date filters in a collapsed
  advanced accordion, and renders books in a fixed-layout table with truncating
  cells plus icon-only open actions. Focused tests pin the DOM and CSS
  no-horizontal-overflow contracts. This is books-list ergonomics only, not
  broader workflow completion, archive legality, or full table ergonomics
  across every app surface.
- `a5353d6` keeps Architecture/Data/Release/CI **PARTIAL**: release workspace
  builds, Docker server builds, and desktop package builds now opt into the
  existing SQLCipher feature by default, with a static CI metadata gate that
  guards those defaults and keeps dev/test plaintext paths explicit. Local
  validation captured Cargo metadata for server/CLI and desktop SQLCipher
  features plus a Windows SQLCipher compile with Strawberry Perl pinned. This
  is encrypted-build wiring and compile evidence only; it does not embed or
  derive a hardware-ID master key, execute plaintext-to-encrypted migration,
  define production key custody, or prove a deployed operator configuration.
- `5a79f1e` keeps Architecture/UX/CI **PARTIAL**: platform service status and
  control contracts now distinguish the running API process, unknown external
  MCP stdio runtime, unsupported API self-control, and supervisor-required MCP
  desired-state changes. API-owned platform logging uses the shared effective
  threshold model where global `off` suppresses all service logs, otherwise
  service overrides are true per-service overrides, and tests cover persistence,
  audit, sidecar suppression, and secret-free control logs. This remains
  settings-backed desired state and bounded API-owned structured logging only,
  not supervisor-backed process lifecycle, stdout/stderr tailing, MCP process
  logs, or general observability.
- `c864315` keeps UX/Data/CI **PARTIAL**: notification popup rows are denser,
  fold type/status tags into compact title text, preserve icon-only tooltip
  controls, and keep popup layering above the page; Data Management now surfaces
  a top-level storage/permission summary, cleaner permission probes, compact
  cleanup rows, and variant-tinted disabled/leather button states. Focused tests
  and lint cover the touched notification/storage paths. This is UI
  ergonomics/accessibility hardening only, not new alert semantics, native
  folder-opening support, or backend storage lifecycle expansion.
- `f58019c` keeps Architecture/CI **PARTIAL**: the paper-book import package
  extension helper was simplified to satisfy clippy after the accepted OCR
  draft-to-mutable-draft work. This is maintainability hygiene only; it does not
  change OCR behavior, canonical-conversion status, legal validity, logging
  behavior, or release assurance.
- `e76a18b` keeps Architecture/UX/CI **PARTIAL**: API-owned structured platform
  log recording now respects the effective logging threshold before retaining or
  persisting an entry, using service overrides when present and otherwise the
  stricter global/area level. Regression tests cover global-floor and area
  thresholds, service overrides that lower a service threshold or turn it off,
  and persisted settings suppressing API-owned endpoint log entries without
  creating a sidecar. Contract and Settings copy now describe the surface as an
  API-owned structured bounded tail. This is threshold enforcement for
  API-owned structured events only, not stdout/stderr tailing, MCP child-process
  logs, supervisor lifecycle control, complete historical logging, or a general
  observability sink.
- `3426669` keeps Entity/UX/CI **PARTIAL**: registered-entity filters now carry
  an explicit `entities-filters` wrapper with clipped horizontal overflow, and
  registered-entity tables pin fixed-layout, single-line truncating cells with
  tooltips while keeping the icon-only action column separate. Default and
  enriched entity-table tests assert truncating cell classes, single-line
  `.truncate`/`.entity-cell-line` content, action-cell separation, and CSS
  no-overflow rules. This is table ergonomics and regression coverage only, not
  a legal registry certificate, richer entity modeling, broader table coverage,
  or authority-approved registry presentation.
- `bcfa718` keeps UX/Workflows/CI **PARTIAL**: the dashboard current-work summary
  now caps open books to the five newest, caps dated reminders to the five
  earliest after dedupe, reports hidden-item counts, tightens dashboard summary
  spacing, and keeps work-queue icon tooltips left-positioned. This is dashboard
  presentation and regression coverage only, not new legal-calendar semantics,
  attendance proof, workflow completion, operational analytics, or legal notice
  validation.
- `e2ff840` keeps Signatures/Documents/CI **PARTIAL**: ASiC profile inspection
  exposes structural profile-shape, per-manifest diagnostics, per-signature
  diagnostics, and stable blocker IDs for unsupported or inconsistent ASiC
  member shapes such as missing manifest-referenced signatures, unreferenced
  signatures, and manifest digest mismatches; current endpoint coverage layers
  those diagnostics into a read-only local `/v1/signature/asic/inspect` report
  for base64 ASiC ZIP inputs with declared fixity checks and bounded local CAdES
  validation only for blocker-free ASiC-S/CAdES or ASiC-E/CAdES candidates.
  ASiC-XAdES remains structured unsupported evidence with no XAdES validation,
  and tests prove diagnostics do not relax extraction/validation refusal or
  decompression-size blockers. This is technical diagnostics only, not XAdES
  generation or validation, CAdES trust validation, LTV evidence, legal
  validity, qualified status, production ASiC compliance, or authority approval.
- `259d5ab` keeps Workflows/Documents/UX/CI **PARTIAL**: an accepted
  paper-book OCR draft can now be copied into one new mutable `Draft` act
  through `POST
  /v1/books/paper-import/{id}/ocr-drafts/{draft_id}/canonical-draft`. The path
  requires the source draft to be accepted, persisted, digest-plus-text rather
  than digest-only, and linked to an open target book with `act.draft`
  permission; unreviewed/rejected/superseded drafts, closed books, and
  digest-only accepted drafts fail without creating an act or ledger event. OCR
  text is copied only into draft deliberations as a drafting aid, while the
  ledger event records only metadata/digest/presence flags and explicitly keeps
  raw OCR text out. The book detail UI exposes the action for accepted drafts
  and reports that no canonical document, PDF/A, signature, seal, or legal
  validity was created. This is a mutable drafting aid and regression coverage
  only, not canonical minutes conversion, authoritative OCR text, document
  generation, signing, sealing, OCR accuracy certification, legal acceptance, or
  legal validity.
- `246238e` keeps Legal/Data Lifecycle/UX/CI **PARTIAL**: Settings >
  Privacidade now exposes the existing retention-policy register as a list,
  create, patch, filter, status, and dry-run UI, with retention copy added across
  the locale catalog. The focused Settings test covers list/create/patch/dry-run
  behavior and asserts the UI sends only retention-policy register or dry-run
  requests, with no execution/delete/anonymize endpoint call and no execution,
  delete, or anonymize payload markers. This is operator visibility and
  regression coverage only, not destructive retention execution, deletion,
  anonymization, GDPR erasure, legal default schedules, legal disposal approval,
  or legal certification.
- `b73de07` keeps Signatures/Trust/Documents **PARTIAL**: CMD, CSC remote,
  local PKCS#12, and official signed-PDF handoff paths can now preserve
  request/operator-declared signer-capacity evidence through pending sessions,
  signed-document storage, status views, responses, and audit/event payloads.
  The evidence is explicitly declared/requested only with
  `verification_status: "not_checked_by_scap"` and
  `status_scope: "declared_capacity_evidence_only"`; it is not SCAP,
  representative-authority, qualified-signature, or legal-capacity verification.
- `2451730` keeps Workflows/Documents/UX/CI **PARTIAL**: focused browser E2E now
  covers preserving a paper-book package as non-canonical evidence, creating and
  accepting an auxiliary OCR draft only after acknowledgement, refusing an
  unconfigured local OCR run without creating a draft, and reloading/downloading
  the preserved package separately from OCR review metadata. This is workflow
  regression coverage only, not canonical OCR conversion, PDF/A creation,
  signing, OCR accuracy certification, legal acceptance, or legal validity.
- `ed2a72c` keeps UX/Signatures/Documents **PARTIAL**: Ferramentas PDF validator
  JSON copy/save actions and external-validator metadata summary saves are now
  compact icon actions with accessible labels and explicit metadata-only status
  copy. This is presentation and regression hardening for local technical JSON
  reports only, not validator authority, legal validity, trust-list validation,
  or authority approval.
- `80e83d5` keeps Legal/Workflows/Documents **PARTIAL**: written-resolution
  evidence can be patched onto acts, reported in act/compliance views as
  missing/referenced-only/bound-present status, and bound into the seal digest
  when present. This records operator-supplied checklist references/digests and
  status only; it is not proof of written consent, quorum, participant identity,
  legal acceptance, or full written-resolution completion.
- `6eecdc5` keeps UX **PARTIAL**: notification popup and notification page
  route/read/acknowledge/dismiss/restore controls are pinned as icon-only
  tooltip-backed actions with accessible names. This is interaction consistency
  and accessibility regression coverage only, not new notice semantics.
- `c66ea3f` keeps Documents/Architecture **PARTIAL**: the PDF accessibility
  report now decomposes PDF/UA blockers into local heading hierarchy, role-map,
  table/vote-table semantics, artifact-marking, and non-text-content accounting
  facts, emits deterministic report JSON version 5 with writer-owned decorative
  artifact counters, and retains focused tests for no-PDF/UA-claim behavior.
  This is technical blocker explanation only, not
  PDF/UA certification, semantic completeness, external validator approval, or
  legal document acceptance.
- `9654eb3` keeps Workflows/Documents/UX **PARTIAL**: the book detail page can
  run the configured local OCR endpoint for a preserved paper-book import,
  confirms the auxiliary non-canonical boundary before submission, posts no body,
  surfaces completion/failure status, and displays the resulting unreviewed OCR
  draft when one is created. This is operator-triggered local OCR UI only, not
  authoritative text extraction, canonical minutes conversion, PDF/A creation,
  signing, legal acceptance, or OCR accuracy certification.
- `f2a7242` keeps Signatures/Documents **PARTIAL**: `POST
  /v1/acts/{id}/signature/archive-timestamp/append` accepts caller-supplied RFC
  3161 token bytes for an already signed act, appends a local `/DocTimeStamp`
  revision, validates the resulting incremental update, updates the signed-PDF
  bytes, and records a distinct audit event while keeping production/legal B-LTA
  flags false. This is local technical evidence mutation only, not provider-driven
  renewal, production B-LTA, legal validity, trust-policy approval, or authority
  approval.
- `66f7b71` keeps Workflows/Documents **PARTIAL**: `POST
  /v1/books/paper-import/{id}/ocr/run` runs an operator-configured local OCR
  command, captures bounded stdout as an unreviewed auxiliary OCR draft on
  success, records failed/missing/degraded status without creating a draft, and
  persists status/draft metadata with explicit false canonical/signature/legal
  fields. This is executable local OCR evidence only, not authoritative OCR
  conversion, canonical-act creation, canonical-document creation, signing, or
  legal validity.
- `cf34a65` keeps Documents **PARTIAL**: the deterministic PDF writer now emits
  mapped Unicode space glyphs between styled word fragments and wrapped
  key/value words, and the accessibility report exposes
  `inter_word_spaces_emitted` while keeping `pdf_ua_claimed` false. This improves
  technical text extraction/accessibility evidence only; it is not PDF/UA
  certification or a claim of canonical OCR/text conversion.
- `ee85a34` keeps UX **PARTIAL**: dashboard work-queue and archive notification
  affordances now use tooltip-backed icon-only links with accessible names while
  preserving the existing routes. This is dashboard ergonomics/accessibility
  polish only, not new workflow or legal-notice semantics.
- `98c5d67` keeps CI/Architecture **PARTIAL**: the recent-landed static checkpoint
  now pins the settings.read-gated raw external-validator metadata download route,
  authz classification, persisted download coverage, malformed-sidecar refusal,
  duplicate-identity refusal, and safe identity helper markers. This is a static
  regression map for technical metadata access only, not live validator authority,
  legal validity, credentials handling, or authority approval.
- `9f5b19f` keeps Entity/Documents **PARTIAL**: registry chronology output now
  includes deterministic structured graph bundles for shareholders, organs, and
  relationship stubs, with stable node/edge IDs, source inscription/date
  provenance, and warnings when no relationship evidence exists. This is parsed
  registry visualization evidence only, not a legal registry certificate, ownership
  determination, or authority-approved graph.
- `b43a82e` keeps CI/Architecture **PARTIAL**: the recent-landed static checkpoint
  pins durable external-validator report metadata sidecar persistence/reload,
  malformed-sidecar counting, and related API regression markers. This is static
  checkpoint coverage for already technical metadata sidecars only, not legal
  validator acceptance, trust-list validation, live provider validity, credentials,
  or authority approval.
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
  tests, reports dry-run `would_delete_*` counters while keeping every
  `deleted_*` counter at zero, and rejects those policy options for crash
  cleanup. Settings Data Management uses the dry-run path as a preview-only
  retained-export action and states that no files were removed. These controls
  are retained-export cleanup planning guardrails only; they are not GDPR
  erasure, legal disposal approval, anonymization/redaction completion, physical
  deletion guarantees beyond the existing bounded cleanup behavior, or complete
  data-lifecycle automation.
- `9997162` keeps Architecture/Release **PARTIAL**: Docker release-trust metadata
  checks now require stronger production-mode anchors such as image/artifact
  digests, HTTPS workflow/run URLs, signing identity or certificate fingerprints,
  and attestation predicate metadata. This validates declared metadata only; it
  does not verify an actual registry push, image signature, attestation, or release
  trust chain.
- Working tree keeps Architecture/Release/CI **PARTIAL**:
  `scripts/check-release-trust.mjs self-test` now statically verifies workflow
  wiring for the unsigned/local-only trust posture. It pins the CI metadata lane
  release-trust self-test, SBOM package-linkage self-test, and package
  provenance fixture checks; the Docker job's no-push/local-load posture,
  `local-ci` trust status, `--expect-mode local-ci`, and nested
  `releaseTrust.imagePublication/signing/notarization/attestation.status`
  context; and the release workflow package-integrity step,
  `releaseTrust.mode = unsigned-dev`, `attestation.status = not_attested`,
  `--expect-mode unsigned-dev`, and SBOM package linkage. Production package
  validation now also requires `--manifest` whenever either the package metadata
  mode or the expected mode is `production`, with self-tests covering both
  signals independently. This is static workflow/package metadata assurance
  only; it does not add signing, notarization, attestation, registry publishing,
  or production trust claims.
- `35f54d6` keeps AI/MCP/Workflows **PARTIAL**: AI-origin draft provenance can be
  persisted on acts, MCP/API draft creation carries deterministic
  `ai_provenance.statement_sources[]` rows, MCP draft tools inject
  non-authoritative provenance, and the TextApproved-to-Signing transition is
  blocked until a human review decision is recorded as accepted. Unsafe row-level
  human-verified, authoritative-source, and legal-validity claims are ignored and
  clamped false when accepted/rendered. The accepted/rejected state is a durable
  human-review gate only; it is not legal validity, an AI quality assessment, or
  a full provenance UI panel.
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
- Current working-tree workflow reminder policy keeps Workflows/UX/CI
  **PARTIAL**: settings now include `workflow.reminders` with `enabled`,
  `dashboard_limit`, `due_soon_days`, `attendance_lookahead_days`, and source
  toggles for `profile_calendar`, `act_follow_ups`, and `attendance_hygiene`.
  Defaults preserve the prior generated dashboard behavior: enabled, limit 5,
  45-day due-soon status, 45-day attendance lookahead, and all three sources
  enabled. The dashboard reads the policy only for the existing local advisory
  reminder families; `enabled=false` suppresses reminder feed/cards without
  removing other dashboard data, and source toggles suppress only their
  matching local family. Gestão exposes compact controls for those fields, and
  reminder status now uses absolute calendar-day deltas across year boundaries.
  This is policy/default/UI/checkpoint coverage only, not full reminder or
  calendar completion.
- `225f5c6` keeps Signatures **PARTIAL**: external-signing envelopes can require
  identity-evidence categories such as contact control, provider identity assertion,
  government ID check, or representative capacity before a slot is marked signed.
  These are recorded workflow evidence requirements only; they do not assert legal
  identity, representative authority, qualified status, or legal effect.
- `5021110` keeps AI/UX/Workflows **PARTIAL**: the Ata editor renders AI provenance
  and human-review status including persisted deterministic statement-source rows,
  lets authorized operators record accept/reject decisions, and disables the move
  to Signing while AI-assisted text is pending or rejected. The UI records the
  existing human-review gate only; it is not AI-quality review, legal
  certification, authoritative-source certification, or final-minute acceptance.
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
  signature-value tampering, with `TslClient` downgrade coverage, and the working
  tree adds bounded same-document `URI="#id"` fragment resolution for unique
  supported targets plus bounded P-256 ECDSA-SHA256 verification for raw
  XML-DSig `r||s` signatures. It verifies only the supported minimal
  RSA-SHA256/P-256-ECDSA-SHA256 shapes against the embedded signer certificate;
  signer trust anchoring, certificate path/revocation policy, complete C14N,
  multiple-reference support, transform-chain support, broad ECDSA/XML-DSig
  profile support, and legal trust certification remain incomplete.
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
  ASiC profile inspection reports bounded CAdES candidates plus unsupported
  member blockers. The local inspection endpoint preserves that boundary:
  ASiC-XAdES is reported as unsupported diagnostics and `xades_validation_performed`
  stays false. XAdES/ASiC-XAdES generation and validation remain unimplemented.
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
| spec/01 Product Scope (SCP) | PARTIAL | One Rust core still drives server, web, Docker, and Tauri desktop. Durable mode exists through `CHANCELA_DATA_DIR`; in-memory mode is explicit on `/health`, and Settings now exposes storage mode/data-folder/usage telemetry from `/v1/data/status`, hot-backup creation from the Data Management panel, preflight-only backup recovery-drill receipts, plus bounded crash-report/retained-export cleanup through `/v1/data/cleanup`, including retained-export dry-run planning counters, with compact cleanup rows in the web Data Management panel. | Mobile companion remains deferred; edition packaging still needs signed/notarized publication hardening. | None specific. |
| spec/02 Legal & Compliance (LEG) | PARTIAL | Compliance gates, rule-pack failures with structured legal-basis references, written-resolution evidence advisories with Pending legal-basis metadata plus operator-supplied checklist/digest status binding into act/compliance views and seal digests, DRE/EUR-Lex law corpus authenticity gating, legal-threshold placeholders, bounded template law-reference exposure from rule-pack IDs and threshold references, bounded corpus citation resolution that preserves Verified/Pending status, recovery/audit trails, step-up controls, delegation evidence fields, required guardrail acknowledgements for imported-document terminal review and official signed-PDF handoff imports, guest/minimal redaction for entity/registry/book/act/imported-document metadata reads, backend DSR user export, tracked DSR request lifecycle with data-dir JSON durability, erasure DSR preflight evidence with immutable-ledger blockers, mutable-sidecar plans, idempotency guard, and explicit false destructive/full-erasure flags, bounded DSR execution evidence, user-management DSR UI, processor/DPIA compliance registers, privacy breach-playbook and transfer-control registers with settings UI and data-dir JSON durability, non-executing breach review/drill and transfer-control review evidence receipts with false authority-notified/subjects-notified/transfer-approved/data-transfer-executed flags, a persisted retention-policy register with non-destructive dry-run reports, persisted/listable audit-only retention execution-request evidence with review-only intent/status fields, operator decisions, blockers/required approvals/next steps, read-only due-candidate scanner rows plus a Settings row-level review-only dry-run `execution_request` action, duplicate `review_only` reuse of existing awaiting-review executions without extra execution records or ledger events, and guarded non-destructive archive disposal execution evidence with ledger audit exist. DRE-sourced law, copied corpus citations, template law references, imported-document acknowledgements, official handoff acknowledgements, written-resolution evidence status, and privacy review receipts remain Pending/fail-closed legal boundaries unless authoritative evidence and legal review are present. | Actual physical deletion, destructive/automated GDPR erasure beyond preflight/evidence, mutable-sidecar redaction/anonymization execution, complete per-family legal packs, privacy/redaction/data lifecycle coverage beyond the current read-redaction, register, and review-receipt slices, broader incident/notification/transfer-control automation beyond non-executing review receipts, broader retention/disposal policy automation beyond the current scanner/review-request/blocker/approval/next-step evidence and without candidate resolution, written-resolution evidentiary completion beyond operator-supplied checklist/digest status binding, exhaustive/verified template/citation law mapping, and legally verified threshold values remain local product work. | Authoritative DRE text/PDF access is needed to mark PT law corpus entries Verified; legal review is needed before replacing threshold placeholders with numbers or treating template/citation references as complete/authoritative. |
| spec/03 Entity Profiles (ENT) | PARTIAL | Five families are modeled; profile/rule-pack binding exists, statute overlays feed compliance findings, bounded capital/permilage weighted tally and quorum consistency checks exist where complete attendance weights are captured, condominium data-quality warnings catch missing meeting time, contradictory attendance counts, and impossible permilagem values/totals, template assets now cover commercial companies, condominiums, associations, foundations, and cooperatives across many stages, and entity chronology responses expose imported-registry chronology events, copyable Mermaid graph sources, and deterministic structured graph bundles for shareholders, organs, and relationship stubs with source provenance plus focused browser E2E coverage for the visible chronology/Mermaid surface. | Deeper family-specific rule packs, groups, legally exhaustive weighted-voting policies, broader calendar preset depth, and richer chronology visualization beyond technical table/Mermaid/source-linked graph evidence remain incomplete. | Legal review of non-CSC packs and thresholds. |
| spec/04 Signatures & Trust (SIG) | PARTIAL | CMD, CC, generic CSC remote-signing, local soft-cert/PKCS#12 provider status, and a desktop-gated local PKCS#12/PFX software-certificate signing flow are exposed in the signing/API layers; PAdES/CAdES signing, bounded single-payload ASiC-S/CAdES container creation and validation, bounded ASiC-E/CAdES manifest container creation and validation for payload digest binding, read-only local `POST /v1/signature/asic/inspect` ASiC profile inspection for base64 ZIP inputs with declared fixity, base64, malformed-ZIP, unsafe-path, profile-shape, bounded-profile, blocker, member-path, manifest-diagnostic, signature-diagnostic, no-claim, and decompression-bound coverage, local CAdES validation only for blocker-free bounded ASiC-S/CAdES or ASiC-E/CAdES candidates, structured unsupported diagnostics for direct XAdES and ASiC-XAdES with no XAdES validation, signed-document persistence including request/operator-declared signer-capacity evidence preserved as `not_checked_by_scap` / `declared_capacity_evidence_only`, provider listing/status metadata, TSL XML-DSig validation/catalog status/search with bounded same-document `URI="#id"` fragment resolution for unique supported targets, bounded raw P-256 ECDSA-SHA256 XML-DSig verification against the embedded signer certificate, plus strict identifier lookup for complete certificate SHA-256 fingerprints, SKIs, subject/provider/service/supply-point hints, and TSA/QTST records, TSA diagnostics/search plus Ferramentas TSL/TSA identifier lookup controls, B-T timestamping when configured, local PAdES DSS/VRI append/reporting with existing-DSS merge/dedupe, caller-supplied `validation_time` validation/refusal, and `/TU` metadata, DocTimeStamp parsing/imprint evidence in signature/archive reports, caller-supplied local `/DocTimeStamp` archive timestamp append for existing signed PDFs with production/legal B-LTA flags false, local PAdES LTV renewal-plan reporting from already inspected technical evidence including API exposure, document timestamp monitor states, multi-signature local renewal-plan reporting in arbitrary-PDF validation, act signature status, and web signing evidence UI, per-signature DSS/VRI coverage and local evidence gaps, and caller-supplied deadline classification, a gated local arbitrary-PDF/PAdES validation endpoint with Ferramentas UI and focused browser E2E for JSON copy/download fail-closed behavior, additive settings for multiple TSL sources and TSA providers, operational selection of configured TSL/TSA providers in trust refresh/catalog, signing trust-policy selection, and timestamping selection/reporting, external-validator corpus sidecars with strict technical-only status transitions, raw-report preservation metadata plus bounded digest-verified raw report byte attachments, archive-ready evidence attachment metadata projection, validator-corpus evidence-indexing metadata for archive package `evidence/index.json` plus document-bundle `validation_report.evidence_index`, runtime external-validator technical metadata and verified raw-report attachment projection into archive package members/`evidence/index.json` plus document-bundle indexes when metadata matches observed canonical/signed PDF hashes, `/v1/external-validator-reports` capture/list APIs for operator-supplied technical metadata summaries, and `GET /v1/external-validator-reports/{case_id}/{validator_family}` settings.read-gated raw technical metadata downloads that fail closed for unsafe, malformed, duplicate, or ambiguous identities, technical timestamp-trust diagnostics with persistence when validator inputs are available, technical CRL+OCSP revocation evidence collection, API/archive embedded DSS/VRI reporting, precise local B-LT/B-LTA technical evidence status with legal flags kept false, signature evidence status reporting/UI, fail-closed trust checks with CMD/CC/TSA failure-matrix tests and isolated legacy-TSA provider fixtures, external-signer invitation tracking/UI with per-act workflow-only envelope list/create surfaces showing order policy, slot status/identity requirements, completion and backend no-legal/no-qualified notices, optional external-envelope/slot links that send linked IDs only when selected and initiate allowed slots under sequential/parallel order policy while later sequential slots fail with 409 through safe UI messaging, token lookup/respond safe working-copy access, optional signed-PDF upload on accepted invite responses stored as `ExternalSignerHandoff` / `ExternalSignedPdfTechnicalEvidence`, official signed-PDF handoff import guardrail acknowledgements plus a web upload flow before technical signed-artifact evidence is recorded, with no PIN/OTP/passphrase collection, gated external-signing envelope APIs with required identity-evidence categories, a Ferramentas external-signing workflow tool with redacted invite listings, status summaries, localized `external_envelope` labels, same-origin token-link handling, public envelope lookup, browser E2E proving signed-invite tracking does not expose signed PDFs, and a generated AMA/CMD evidence-pack scaffold plus read-only pack check mode with no-approval-claim templates are present. | SCAP attributes, representative-authority verification beyond declared/requested signer-capacity preservation, XAdES generation/validation, ASiC-XAdES execution beyond structured unsupported diagnostics, ASiC inspection beyond the read-only local technical endpoint and bounded CAdES candidate validation, ASiC-E profiles beyond the bounded single-manifest CAdES digest-binding path, multiple ASiC-E signatures/manifests/extensions beyond structured blockers, real C14N, TSL signer trust anchoring and certificate path/revocation/policy validation, multiple-reference XML-DSig support, transform-chain support, broad ECDSA support beyond raw P-256 XML-DSig signatures, broader XML-DSig profile coverage, legal trust certification, production/legal PAdES or ASiC B-LT/B-LTA completion or claim, embedded LT/LTA evidence, policy-driven local LTV renewal execution or legally derived deadline decisions, external-signer legal/qualified completion beyond workflow-only envelope list/create, invite/envelope-slot tracking, uploaded signed-PDF technical evidence, and workflow identity-evidence records, official signed-PDF handoff legal completion beyond technical upload/import evidence and acknowledgements, multi-signature VRI/archive timestamp renewal execution depth beyond local planning/reporting and caller-supplied token append, broader durable/raw operator capture/storage of real external-validator reports beyond the bounded metadata capture/list/download and verified raw-report attachment boundary, broader provider-management policy automation and trust-list lookup UI depth beyond current catalog/search/identifier surfaces, controlled live provider/hardware integration depth, and production AMA/CMD authority approval remain incomplete. API signing, arbitrary-PDF validation, local PKCS#12/PFX signing, external-signing workflow tracking/uploaded evidence, official signed-PDF handoff imports, declared signer-capacity preservation, external signer identity evidence requirements, PAdES LTV renewal plans including multi-signature local renewal reports, caller-supplied local archive timestamp append, validator report evidence metadata/indexing/capture/list/download APIs plus bounded verified raw-report attachments, archive package `evidence/index.json`, document-bundle `validation_report.evidence_index`, ASiC inspection/profile reports, bounded TSL XML-DSig same-document fragment handling, bounded raw P-256 ECDSA-SHA256 XML-DSig verification, TSL/TSA identifier lookup, and AMA/CMD evidence-pack generation/checking are technical/operational evidence flows, not claims that every seal, uploaded PDF, invite response, linked slot, workflow-only envelope, official handoff, ASiC container, validator report, evidence index, identity assertion, declared capacity, renewal plan, archive timestamp append, local software-certificate signature, trust-list match, XML-DSig reference, ECDSA signature, or CMD integration is qualified/legal-valid, trust-list validated, production B-LTA, SCAP-checked, representative-authority verified, or authority-approved. | Live CMD requires AMA/SCMD credentials, prod cert, and authority onboarding/approval. Live CSC/QTSP requires provider onboarding and credentials. CC requires card, reader, and Autenticacao.gov middleware. Production TSL/TSA/revocation use requires production network configuration, valid source material, trust anchoring, real canonicalization, and policy/legal review; path-backed TSA providers, unsupported timestamp digests, DER ECDSA signatures, and XML-DSig shapes outside the supported minimal verifier block deterministically rather than falling back to fake live signing. |
| spec/05 Data Model / Roles (DAT/ROL) | PARTIAL | SQLite-backed durable store, multi-chain ledger, recovery/degraded mode, data-folder permission/usage telemetry with SQLite logical usage estimates including privacy retention-execution sidecars, `data.backup`-gated hot-backup creation UI that posts no body and renders only a bounded non-secret manifest summary, secret-free database key-ops status/preflight for key config, build capability, database-header format, plaintext-to-encrypted migration refusal, structured non-destructive export/restore migration-plan guidance, secret-free store/API SQLCipher key-rotation preflight evidence with a web Data Management preflight UI that clears submitted secrets, a `settings.manage` + interactive-session guarded API/web SQLCipher rekey execution path for already-open keyed stores that refuses plaintext stores and returns only secret-free execution evidence, feature-gated store rekey execution evidence without key serialization, SQLCipher-enabled desktop default key resolution through a fresh random key protected by the current-user OS provider, DPAPI on Windows, while non-SQLCipher desktop durable startup fails closed unless `CHANCELA_DESKTOP_ALLOW_PLAINTEXT_DB=1` is explicitly set for a local development/no-SQLCipher run, and CLI durable-store commands now honor `CHANCELA_DB_KEY` / `CHANCELA_DB_KEY_FILE` through the same key config path while failing closed without SQLCipher and without leaking key material, plus `settings.manage`-gated maintenance cleanup for crash reports and retained exports, including export-only dry-run plan counters with zero deleted counters, users with optional email capture, complete seeded role catalog with fresh `platform.logs.write@Global` defaulting only to Owner and Platform Administrator while API Client does not receive it by default, scoped RBAC, delegations with `starts_at`/`legal_basis`, sessions, API-key principals, guest/minimal read redaction for entity, registry, book, act, and imported-document metadata, step-up re-auth, password/recovery controls with hardened verifier-storage regression tests, retention execution records with review-only intent, workflow status, operator review decision, blockers, required approvals, normalized audit evidence, due-candidate scanner rows, review-only candidate dry-run request records, duplicate/concurrent review-only reuse of existing awaiting-review records without extra records or ledger events, breach/transfer review receipts embedded in privacy sidecars with audit events and sensitive-note/false-completion rejection, erasure DSR preflight evidence with false full-erasure flags, and guarded non-destructive archive disposal execution evidence with ledger audit are implemented. | Tenant/group model, broader privacy/redaction lifecycle beyond read-response redaction and erasure preflight, live SQLCipher/at-rest DB encryption proof on this host, production encryption migration/export-restore workflow, plaintext-to-encrypted migration execution, production key-secret update/rotation runbooks beyond the current already-open-store rekey execution, existing persisted non-Owner seeded roles are not forcibly reconciled on load so older customized Platform Administrator roles may need explicit admin update after upgrade, ZK, sync/connectors, actual physical deletion, broader retention/disposal and incident/transfer control automation beyond due-candidate scanner rows, recorded blockers, and manual-review evidence, GDPR erasure execution, and complete data lifecycle policies remain. | None specific beyond legal review for access/redaction policies. |
| spec/06 Workflows (WFL) | PARTIAL | Book/act lifecycle, sealing with structured rule-pack/profile metadata and explicit UI acknowledgement before sealing non-blocking compliance warnings, written-resolution missing-evidence advisories plus operator-supplied checklist/digest status binding into compliance views and seal digests, retification, document generation, closed-book read-only enforcement for pre-existing act patch/advance/seal/archive/convening-dispatch mutations, convening `evidence_reference` capture in act editing/patching, optional act signatory email capture through existing act patch contracts, qualified-signature status, dashboard data organized into subtabs for fiscal-year-aware profile-derived annual-calendar reminders with i18n-backed alert copy, actionable open-follow-up reminders, missing-attendance work-queue reminders for open pre-signing acts with notification routes, compact activity summaries, recent events, and active legal-hold/sealed-not-archived archive lifecycle alerts with advisory next steps, dashboard work-queue/archive notification actions rendered as icon-only accessible links, imported-document terminal review transitions gated on guardrail acknowledgement, backup/restore with web hot-backup creation from durable storage, book import/export, historical paper-book validation plus non-canonical preservation/list/download with source page/original-number range metadata, continuation recommendations, canonical-conversion preflight evidence with explicit false creation/legal-validity flags, paper-book OCR draft list/create/review UI plus operator-triggered local OCR run flow for auxiliary non-canonical metadata with acknowledgement copy and false canonical/signature/legal flags, accepted-OCR-draft metadata-only conversion dossier API/store flow plus BookDetail UI that lists existing dossiers, gates creation to accepted drafts without an existing dossier, performs no automatic dossier POST, keeps mutable draft-act creation separate, hides raw OCR text, avoids document/signature/seal/archive calls, and keeps false act/document/PDF-A/PDF-UA/signature/seal/legal-validity flags, plus the existing bounded mutable-draft drafting aid where present and focused browser E2E workflow coverage, start-over/reset workflows, bounded external-signer invite links with optional external-envelope/slot binding, workflow-only envelope list/create UI with order policy and signer slots, existing order-policy initiation, safe sequential-slot conflict messaging, token-gated safe working copies, external-signing envelope identity-evidence requirements, accepted-invite signed-PDF technical evidence upload, and official handoff signed-PDF technical import from the signing panel are present. | Full legal-calendar preset depth, broader OCR execution/review operations and reviewed canonical conversion execution workflows beyond the operator-configured auxiliary OCR draft path, metadata-only conversion-dossier API/store/UI, and any bounded mutable-draft drafting aid for preserved paper-book packages, written-resolution legal/evidentiary completion beyond operator-supplied status binding, external signer legal/qualified completion beyond workflow-only envelope list/create, invite/envelope-slot tracking, technical evidence upload, and identity-evidence records, official signed-PDF handoff legal completion beyond guardrailed technical import, richer dashboard feeds beyond the current subtabs/reminders/activity/archive lifecycle/attendance alert slices, actual attendance proof beyond advisory reminders, and family-specific workflow depth remain. | Provider credentials for live qualified signing. |
| spec/07 Architecture (ARC) | PARTIAL | Durable store, hot backup/restore with a Data Management backup mutation and non-secret manifest UI, encrypted backup envelopes, recovery mode, `/api/v1` integration alias with JSON 404 namespace guards, persisted API-key lifecycle with bearer principal resolution, HTTP rate limiting, and attenuation tests for creator downgrade/deactivation/scope loss, MCP stdio server with tools, resources, static prompt discovery, a secret-free `chancela://mcp/status` operability resource, and a local `chancela://mcp/spec-09-coverage` coverage-boundary resource, platform service status/control endpoints with settings-backed API/MCP desired state, strict app/API/MCP log-level policy with threshold enforcement for API-owned structured log emission using global/area levels and per-service overrides, audit tail, `/v1/platform/logs?service_id=&level=&tail=` for a bounded API-owned structured platform log tail gated by `settings.read`, `POST /v1/platform/logs/forwarded` for structured forwarded log ingress gated by non-meta `platform.logs.write@Global`, strict forwarded payload validation for known services, non-`off` levels, bounded target/message/context, unknown-field refusal, raw `stdout`/`stderr` field refusal, and secret-like context-key refusal, data-dir persistence to `platform-logs.json` when `CHANCELA_DATA_DIR` is configured with a 512-entry bound and in-memory fallback otherwise, threshold-filtered structured log entries from platform service status/control paths and accepted forwarded entries with global/service `off` suppression, sanitized `platform.log.forwarded.accepted` ledger events only for accepted and retained forwarded entries, no ledger event for forwarded entries suppressed by global/service `off`, invalid requests, or auth failures, honest supervisor/restart-required outcomes, data status/cleanup endpoints, Docker build/runtime smoke, persistent container data path, hardened Docker Compose deployment profiles, release version-consistency guard, tag/manual package-artifact workflow, package manifests/checksums with package artifact integrity checking, release-trust metadata validation for package declarations and local/production Docker declarations with stricter production Docker metadata anchors, package `sourceProvenance` manifest validation against current `HEAD`, web unit-test coverage thresholds in CI, web hook-dependency lint hygiene for follow-up/import-review panels, CI dependency SBOM generation/checking with release-package path/size/SHA-256 linkage and self-tests, report-only npm/Cargo/Docker vulnerability artifacts with an enforced manual mode, Docker OCI metadata/security artifacts, SQLCipher release/Docker/desktop package-build defaults with a static CI guard, a documented SQLCipher Windows feature lane, feature-gated SQLCipher keyed-open foundation, optional `CHANCELA_DB_KEY` / `CHANCELA_DB_KEY_FILE` startup wiring that fails closed when unsupported/invalid for API and CLI durable-store opens, secret-free key-ops status with operator action text and startup refusal for direct plaintext-to-encrypted keyed open, structured export/restore migration-plan guidance, secret-free store/API/web key-rotation preflight plus a guarded API/web rekey execution route for already-open keyed stores and feature-gated SQLCipher rekey evidence, SQLCipher-enabled desktop embedded API default key resolution through an OS-protected random key with a fail-closed non-SQLCipher plaintext dev opt-in, an expanded recent-landed checkpoint for PKCS#12, official signature guardrail acknowledgements, desktop encryption provider markers, retention, TSL hardening, MCP resource/prompt coverage, recovery/document/dashboard/notification/books UI coverage, imported-document, data-key-rotation, hot-backup UI, entity chronology/PDF-validator static browser markers, structured registry chronology graph markers, mapped PDF space markers, PDF/UA blocker decomposition/table-structure markers, export save-prompt markers, dashboard dates-tab markers, notification footer icon-only markers, platform operations UI markers, hardening-plan head markers, archive timestamp append markers, paper OCR API/UI/contract markers plus accepted OCR conversion-dossier metadata markers, trust identifier UI markers, external-validator metadata API/download durability markers, validator corpus, CAE obtainer status-doc cleanup, CLI encrypted-key environment coverage, encrypted-build-defaults static checks, and desktop lockfile checks, and Tauri desktop shell are in tree. | Sync, storage connectors, HA profiles, real supervisor-backed API/MCP process lifecycle, production supervisor-forwarded process integration, historical stdout/stderr tailing or capture, broader durable/live structured log sinks and reload/process logging beyond the threshold-filtered API-owned tail and accepted-entry audit marker, production supervisor/SIEM/HA/observability guarantees, generalized observability sinks, forwarded-log retention/deletion semantics beyond the 512-entry tail bound, deployed SQLCipher encryption verification with operator keys, executed plaintext-to-encrypted migration/export-restore flow, production operator key-secret rotation/update workflows beyond current already-open-store rekey execution, sidecar encryption strategy, repo-level ZK, coverage thresholds beyond web unit tests, broader browser E2E coverage, live provider/hardware integration tests beyond compile-only seams, actual release signing/notarization, actual Docker image signing/attestation and registry-publication verification beyond SBOM/package metadata-anchor checks, production-grade HA/orchestration profiles, and mobile builds remain. | Local Windows SQLCipher feature compile now passes when native Strawberry Perl is pinned; production encryption still depends on operator key custody and deployment configuration. |
| spec/08 Documents & Archive (DOC) | PARTIAL | Template rendering, frozen `DocumentModel`, deterministic PDF/A-2u writer with embedded fonts, ToUnicode maps, mapped Unicode inter-word spaces for styled/wrapped word fragments, decomposed accessibility/PDF-UA blocker reporting without false PDF/UA identification, report-side alt-text/decorative metadata modeling, heading-hierarchy facts, role-map coverage, bounded Table/TR/TH/TD semantics for key/value and vote tables, artifact-marking counts, non-text-content accounting, deterministic accessibility JSON version 6 with structural-depth evidence, bounded local topology facts, and writer-owned decorative artifact accounting for the header rule, explicit rules, vote-table rules, and signature lines while excluding page breaks, minimal tagged PDF structure with MCIDs, `StructTreeRoot`, `RoleMap`, `ParentTree`, page `StructParents`, structure-order `/Tabs /S`, catalog `/ViewerPreferences /DisplayDocTitle true`, `MarkInfo` true, artifact marking, XMP title/language consistency checks, and deeper structural self-checks for ParentTree/MCID/MCR consistency plus RoleMap/marked-content scope validation and bounded local table topology, seal/book document generation, render-context exposure for convening `evidence_reference`, document bundle endpoint with structured technical validation reports for consistency/fixity/canonical-PDF/signed-document evidence, `validation_report.evidence_index`, and explicit non-certification flags, signed-document endpoint, external-invite uploaded signed-PDF technical evidence and official handoff imported signed-PDF technical evidence served through the signed-document path, caller-supplied local `/DocTimeStamp` archive timestamp append for existing signed PDFs with production/legal B-LTA flags false, Arquivo PDF/A export from ledger filters, working-copy Markdown/TXT/HTML/RTF/ODT/DOCX exports with API matrix coverage and browser export/save E2E coverage, read-only candidate import validation with fixity, preservation-review policy metadata and explicit canonical-record/signed-artifact/OCR-promotion guardrails for imported-document candidates and stored imported documents, persisted imported-document operator review state/notes with required guardrail acknowledgements for terminal review transitions, web review controls, acknowledgement UI, and guardrail alerts that retain original bytes only, focused browser regression coverage for conservative imported-document review messaging/PATCH behavior plus notification-to-review/canonical-export behavior, legacy DOC/OLE-CFB recognition, signed-PDF/PAdES structural status, local arbitrary-PDF signature validation for structure/ByteRange/PAdES/DSS/DocTimeStamp evidence plus local technical LTV renewal-plan reporting, multi-signature local renewal-plan reports, caller-supplied deadline classification, and focused browser E2E for PDF validator JSON copy/download fail-closed behavior, persisted non-canonical imported-document evidence including legacy DOC bytes with retained bytes/metadata-only ledger events and UI, expanded imported-document evidence families, guest redaction for imported-document filename/digest/importer/download metadata, web pre-persistence import validation evidence/refusal findings for legacy DOC/OLE-CFB candidates, historical paper-book validation plus persisted non-canonical package preservation/list/download with source page/original-number range metadata, canonical-conversion preflight evidence, paper-book OCR draft metadata plus operator-configured local OCR run/status evidence and web review/run UI with explicit false canonical/signature/legal fields plus contract fixtures for draft and run shapes, accepted-OCR-draft conversion dossiers that store metadata only, return duplicates idempotently, create no act/document/PDF-A/PDF-UA/signature/seal/legal claim, keep raw OCR text out of responses and ledger payloads, and are listed/created from BookDetail only as bounded no-claim dossier metadata with no document/signature/seal/archive calls, plus the existing bounded mutable-draft helper where present, retained-export maintenance cleanup with export-only dry-run/minimum-age/keep-latest guardrails, deterministic internal preservation ZIPs with archive evidence reports including DocTimeStamp/imprint evidence and a technical archive package `evidence/index.json`, archive package tamper-failure tests, validator corpus raw-report sidecar preservation metadata, evidence attachment metadata projection, evidence-indexing metadata, runtime external-validator technical metadata attachments and bounded digest-verified raw report bytes that are matched by observed PDF SHA-256 and packaged/indexed with traversal/overclaiming/duplicate-path/fixity guards, `/v1/external-validator-reports` capture/list APIs for redacted technical metadata summaries, and `GET /v1/external-validator-reports/{case_id}/{validator_family}` settings.read-gated raw technical metadata downloads that fail closed for unsafe, malformed, duplicate, or ambiguous identities, inventory preflight/self-validation, DGLAB-aligned internal preservation metadata with explicit non-certification flags, read-only `GET /v1/books/{id}/archive/local-dglab-interchange-manifest` local scaffold JSON gated by `book.export@Book` with deterministic false official/certification/approval/legal-archive/destructive flags and no ZIP member, persisted bytes, ledger event, package validation change, import, or disposal path, export-time legal-hold marking, persisted book-level legal hold, disposal eligibility/dry-run status, dashboard archive lifecycle alerts for active holds and sealed-not-archived acts, and guarded non-destructive disposal execution evidence are implemented. | Deeper imported-document preservation review workflow beyond the current status/note decisions, acknowledged guardrail checklist, and focused browser regressions, broader OCR execution/review operations beyond the operator-configured local auxiliary draft path, metadata-only conversion-dossier API/store/UI, and mutable drafting aid, full PDF/UA delivery beyond mapped spaces, minimal tagged structure, decomposed blocker reporting, version 6 structural-depth evidence, and bounded structural/topology self-checks including semantic role coverage, complete non-text alt/decorative coverage, and external validator certification, richer structure trees/tagging/role maps/marked artifacts, canonical conversion/PDF/A generation beyond preflight evidence, metadata-only dossiers, or mutable drafting aid for legacy DOC/paper-book evidence, production/legal signed-import validation beyond local structural/PAdES checks and technical uploaded/imported evidence, policy-driven PAdES LTV renewal execution beyond local single/multi-signature planning reports and caller-supplied local archive timestamp append, durable/full operator capture/replay of real external-validator reports beyond current bounded validated metadata capture/list/download and digest-verified raw-report attachment APIs, official DGLAB interchange/certification/government filing/legal archival certification beyond the read-only local manifest scaffold, retained-export policy depth beyond the current cleanup guardrails, actual physical deletion, broader disposal/retention policy automation, GDPR erasure linkage, and legal acceptance/certification remain incomplete. | Legal review of generated template content/thresholds. |
| spec/09 AI & MCP (AI) | PARTIAL | MCP server and API bridge exist, with tools mapped to `/api/v1` including Mermaid chronology, working-copy, archive package, ledger archive, trust catalog, law tools, exact AI-11 `prepare_archive_export` and `validate_signature_bundle` tools, `draft_minutes`, and AI-11 compatibility aliases (`list_companies`, `get_company_timeline`, `search_legal_texts`); live API bearer tests cover the bridge. MCP now requires both the local MCP switch and a tenant AI gate (`settings.ai.enabled` / `CHANCELA_AI_ENABLED`), advertises tools/resources/prompts, exposes a secret-free `chancela://mcp/status` resource, exposes a local `chancela://mcp/spec-09-coverage` resource with AI-10/11/12 coverage boundaries, exposes static `draft_minutes_human_review_checklist` and `compliance_pack_gap_review` prompts, exposes `paper_book_ocr_canonical_review` for paper-book OCR/canonical-conversion evidence review, and exposes the static `draft_signed_comparison_review_checklist` prompt plus `chancela://mcp/draft-signed-comparison-review` resource for draft/signed identifier, digest, text/version, mismatch, and reviewer-note review; these prompts accept no arguments, the draft-signed resource rejects extra params, and they perform no hidden calls. Draft tools return an explicit non-authoritative `ai_draft` provenance envelope with top-level `source_provenance`, deterministic statement-source entries, human verification required, allowed pending/accepted/rejected checkpoint vocabulary, and fail closed on sealed/non-draft API shapes. MCP draft-act/draft-minutes calls also inject bounded `ai_provenance.statement_sources[]` rows into the act draft request, and the act API persists those rows with a human-verification record while clamping unsafe row-level human-verified, authoritative-source, and legal-validity claims false; AI-assisted acts cannot advance from TextApproved to Signing until human review is recorded as accepted. The Ata editor now surfaces the AI provenance/human-review status and renders the persisted statement-source rows, records accept/reject decisions through the existing review endpoint, and disables the Signing transition while review is pending or rejected. `validate_signature_bundle` wraps the existing signature endpoint as technical evidence only with no legal-validation claim, and the web settings/platform surface can manage the tenant gate and display AI/MCP assurances for gates, API-key RBAC, draft status, and signature-bundle scope without exposing secrets. Law corpus search/browse endpoints and registry import support provenance-adjacent workflows. | AI drafting/extraction/summarization depth, workflow-level provenance panels beyond MCP output/status/spec-coverage resources/static prompts and the act human-review gate panel with statement-source rows, richer MCP prompt/resource breadth beyond the current bounded review prompts, non-stdio MCP transports, live AI provider calls, AI-01 full completion, and any assessment of AI quality, legal validity, or authoritative-source certification remain. | None specific. |
| spec/10 UX & Design (UX) | PARTIAL | Web shell, 14-locale i18n runtime and catalog completeness checks, onboarding/auth gate with optional first-user email capture, password-policy checklist, settings, Settings-only users/RBAC/delegation/API-key/recovery/privacy/UI platform-operations UI with AI/MCP assurance copy, backend-limited service-control action presentation, effective app/API/MCP log-level summaries, settings-managed app/API/MCP logging controls, Data Management storage telemetry, hot-backup creation action with durable-store gating and a non-secret manifest result, compact cleanup UI rows, storage-breakdown polish, read-only data key-rotation preflight UI that clears entered secrets, guarded rekey execution UI that asks for the replacement key again and clears it after success/error, focused browser E2E for the guarded data-key rotation execution path, privacy breach-playbook and transfer-control register panels with operator evidence capture and readable non-notification/non-approval summaries, plus a retention due-candidate table with an explicit review-only request action, Ata editor convening evidence-reference and signatory-email controls plus AI human-review status/accept/reject controls that block Signing until accepted, law corpus citation pin/copy shelf preserving Verified/Pending labels, imported-document evidence UI including pre-persistence validation/refusal evidence for non-canonical legacy DOC/OLE-CFB imports, operator review status/note controls, visible guardrail alerts, and a required guardrail acknowledgement checkbox before terminal review submission, focused browser regression coverage for imported-document review conservative messaging/status-note submission plus notification routing/dismissal/canonical PDF export, paper-book import list/download UI plus per-import OCR draft list/create/review controls, local OCR run confirmation/status flow with explicit auxiliary/non-canonical acknowledgement copy, accepted-draft metadata-only conversion-dossier list/create UI that hides raw OCR text, requires operator action, suppresses duplicate/non-accepted creation, renders no-claim flags/notice, and avoids document/signature/seal/archive calls, and accepted-draft "Criar rascunho de ata" action/result copy that links to the mutable draft act while showing no PDF/A/signature/seal/legal-validity creation, document preview, save-prompt-routed PDF/Markdown/TXT/HTML/RTF/ODT/DOCX working-copy and canonical export downloads with browser export/save E2E coverage, signature evidence with local B-LT/B-LTA technical labels plus multi-signature local renewal-plan evidence, official signed-PDF handoff import UI with required guardrail acknowledgement and no secret-factor fields, external-invite UI with optional envelope-slot selection that preserves tracking-only payloads when unselected and renders safe sequential 409 messages, SigningPanel workflow-only external-signing envelope list/create UI with order policy, slot labels/statuses, identity requirements, completion summary, and backend no-legal/no-qualified notice, external-invite landing page, Ferramentas external-signing workflow tool with localized external-envelope workflow labels, browser E2E for signed-act external invite boundaries, dashboard subtabs for stats/activity/current work/dates/queue/events, dashboard reminders/work queue with localized alert keys, current-work summary caps and hidden-count reporting, missing-attendance act reminders routed from notifications, active legal-hold and sealed-not-archived alerts, activity-summary polish, and icon-only dashboard work-queue/archive action links, persisted notification triage with icon-only read/dismiss/acknowledge/restore/route controls plus icon-only notification filter subtabs and tooltip-backed subtab overflow arrows that keep accessible names and tooltips, explicit seal-warning acknowledgement modal, compliance source/reference rendering, registered-entity primary filters that wrap without horizontal scrolling and clip overflow, collapsed accordion-style advanced filters that expand into wrapped multi-line controls, fixed registered-entity table cells with single-line truncation and tooltips, concise Type/Last Activity visible summaries with tooltips, entity chronology table plus copyable Mermaid graph sources with focused browser E2E coverage, improved template primary/advanced filters, template law-reference search/rendering with Pending/Verified badges, Arquivo UI, Trust/TSL/TSA catalog UI with identifier lookup controls and truncated/copyable digests, a PDF signature validator tool UI with copy/save technical JSON report actions plus focused browser E2E coverage, bundled PDF fonts, button hover/leather active states, hook-dependency lint hygiene in follow-up/import-review panels, and desktop window controls/smoke coverage are present. | Mobile UX, broader paper-book canonical-conversion UX beyond the current OCR draft/run, metadata-only dossier, and mutable draft-aid surfaces, external-signing provider-backed signing/evidence/completion UX beyond the current workflow-only list/create and tracking surfaces, PDF/UA delivery beyond the bounded tagged-structure, structural-depth, and topology-check slice, broader dashboard workflow depth beyond the current subtabs/reminders/activity/archive lifecycle/attendance alert slices, broader table ergonomics beyond the entities/templates/storage/paper-import slices, broader imported-document browser coverage beyond the focused review/notification-export regressions, broader official-handoff browser coverage beyond the focused SigningPanel unit flow, broader AI provenance experience beyond the human-review gate panel, broader trust-list lookup UI depth beyond existing catalog/search/identifier surfaces, and broader legal-source/provenance linking beyond the citation shelf and template catalog remain. | None specific. |
| spec/11 Template Catalog (TPL) | PARTIAL | `chancela-templates` loads 101 JSON template assets (101 total / 41 CSC), including standalone procuração / instrument of representation templates for commercial companies, condominiums, associations, foundations, and cooperatives, with the company variant also carrying the sociedade anonima carta de representacao wording boundary when applicable, plus five `ponto-ordem-trabalhos/v1` Convocatoria standalone agenda-item templates for CSC, condominium, association, foundation, and cooperative families, family-spanning `termo-transporte` book-continuation templates for every supported family, plus `csc-ata-divisao-quotas/v1`, `csc-ata-unificacao-quotas/v1`, `csc-ata-delegacao-poderes/v1`, and `csc-ata-revogacao-poderes/v1`. The quota templates match sibling CSC quota channels, `csc-art63/v2` rule-pack binding, `QualifiedPreferred` signature-policy hint, and Pending majority-threshold law references; delegation/revocation templates render proposed resolution text only and add no threshold marker. API exposes `GET /v1/templates`, previews, on-demand generation, seal/book hooks, catalog summary metadata for channels, signature policy hints, rule-pack IDs, and bounded `law_references` derived from rule-pack IDs plus threshold references, with Pending status and source provenance. Template tests now validate required authored asset metadata, duplicate IDs, rule-pack law-reference anchors, derived law-reference presence, family-binding drift across template ID prefixes/rule-pack IDs/signature-policy hints, asset-stem versus template-id drift, missing `/vN` suffixes, empty authored blocks, id-derived stage drift, duplicate/out-of-order channels, scoped telematic/written-resolution channel drift, the 101-asset census, 41 CSC count, all-family agenda-item rendering, CSC quota division/unification Pending law-reference parity, CSC delegation/revocation asset/rendering coverage, representation/proxy rendering across all supported families, book-transport rendering across all supported families, all-family notice-template rendering of TPL-20 dispatch proof fields, and all-family attendance-list rendering of structured attendee/proxy evidence with CSC capital and condominium permilagem weighting markers without claiming legal authority. The web catalog can search/filter by those metadata and law-reference fields, keeps search/family/stage as primary controls, moves locale/channel/signature/rule-pack filters into a collapsed advanced area, and shows metadata plus compact law-source badges in summary/detail views. | Template market parity beyond the current family-spanning local assets, legally verified or guessed threshold values, broader statute-overlay depth, external registry/provider integration, signing-process behavior, authority verification for delegation/revocation, registry submission, exhaustive/verified law-reference mapping, full family/rule-pack semantic validation beyond local metadata/family-binding/channel drift guards, and legal sufficiency checks for quota, delegation/revocation, agenda-item wording, dispatch, or attendance proof are not complete. | Legal review before any template wording, law reference, threshold, dispatch proof, attendance proof, book-transport effect, quota effect, delegation/revocation effect, agenda-item effect, signing-process effect, external registry/provider effect, or other legal effect is treated as authoritative. |

Recovery/backup matrix note: the current recovery-drill receipt slice belongs to
the Data, Architecture, Workflow, UX, and Legal/Compliance boundaries as bounded
preflight receipt evidence. It does not reduce the remaining PARTIAL status for
destructive restore success, live DB swap, sidecar staging, ledger restore
append, off-site custody proof, RPO/RTO certification, production backup policy,
or legal archive certification.

Current matrix alignment note: the `platform_logs` and
`backup_recovery_drills` data-status categories are Data/Architecture telemetry
only; the local `LocalDglabInterchangeManifest` scaffold is Documents/Archive
metadata-only coverage; and the richer Ata editor statement-source provenance
rendering plus the MCP draft-vs-signed comparison prompt/resource are AI/UX
human-review coverage. Guest dashboard recent-event redaction is read-response
redaction only. Generated-document by-id downloads are Documents/Workflow
plumbing for non-Ata generated rows only. Retained-export cleanup dry-run
planning is Data/Documents/UX preview coverage only, and the post-act
`Certidao`/`Extrato` sealed-provenance lint is Template Catalog/CI
test/build-time coverage only. These keep the affected top-level
areas **PARTIAL** and do not add deletion/retention execution, official DGLAB
interchange/certification/approval, legal archive custody, model accuracy,
legal advice, source certification, new provider/network behavior, non-stdio MCP
transport, unreviewed finalization, hidden signing/API/provider calls, DRE
verification, verified law references, legal thresholds, anonymization/redaction
completion, GDPR erasure, permission grants, signing/bundle mutation, registry
behavior, legal disposal, or legal-effect claims.

---

## Recent Coverage Added

- **Release clean-source provenance gate:** `check-package-artifacts
  --require-clean-source` now fails package manifests whose
  `manifest.sourceProvenance.sourceTreeState` is `dirty` or `unknown`; the
  release workflow runs package integrity with that flag; and the
  release-trust self-test statically guards the release workflow wiring. This is
  source-state release hygiene only, not signing, notarization, attestation,
  registry publication, trust validation, or reproducible-build proof.
- **Seeded role drift diagnostic:** `GET /v1/roles` now returns read-only
  `seeded_role_drift.missing_default_permissions` and
  `requires_manual_review` diagnostics for editable seeded roles whose persisted
  permissions lag the current default seed. The RBAC UI renders a manual-review
  warning and missing permission list. This reports drift only; it does not
  auto-reconcile roles, grant permissions, or weaken authorization checks.
- **Archive readability/ZK caveat metadata:** internal archive manifests now
  carry manifest-only `readability_caveats`, reject unknown caveat fields, keep
  all overclaim flags false, and default old v1 manifests conservatively when
  the caveat block is absent. This metadata includes no keys, decryption
  material, connectors, custody proof, ZK repository guarantee, GDPR shortcut,
  external import verification, or legal archive certification.
- **Template family/channel rule guard:** template metadata validation now emits
  test-only `FamilyChannelMismatch` issues for family/channel drift, while
  preserving narrow current-catalog compatibility carve-outs for existing
  authored assets. This is local catalog regression coverage only; it does not
  change asset wording, legal thresholds, providers, law references, or legal
  effect.
- **MCP discoverability updates:** `search_trust_catalog` now advertises
  structured filters for search, identifier, service type, status, history,
  supply point, and limit; `list_external_validator_reports` is a read-only
  `settings.read` tool with a closed no-arg schema that returns the redacted
  summary list route. MCP does not expose raw report routes,
  `content_base64`, upload fields, provider calls, legal validation, trust
  validation, or certification claims.
- **Web hot-backup creation UI:** Data Management now offers a `Criar backup`
  action that calls `POST /v1/backup` only for durable-store instances and shows
  the returned manifest summary without echoing arbitrary backend fields, per-file
  names, digests, app version, or secret-like payload data. Focused tests cover
  the operation list, durable-store gating, success/failure rendering, status
  invalidation, and redaction boundaries. The restore preflight surface is
  read-only: API/store verify the archive manifest, member digests, and isolated
  snapshot ledger integrity, while the web UI shows bounded manifest/evidence
  before any destructive restore execution. Data Management also exposes an
  explicit recovery-drill action that posts to `POST /v1/backup/recovery-drills`
  and records a preflight-only custody receipt retrievable through `GET
  /v1/backup/recovery-drills`. The receipt persists only bounded sidecar evidence
  (archive reference, preflight ok/ready/encrypted, ledger verified, manifest
  counts/bytes/schema/ledger length, optional operator notes/custody location),
  and the web contract checker treats `operator_notes` / `custody_location` as
  optional wire keys matching the API contract. The UI clears the transient
  passphrase after submit while preserving exact bytes in the request, handles
  null manifest evidence safely, rejects true overclaim
  flags, and keeps restore/live-swap/sidecar/ledger-append/deletion/custody/legal
  certification flags false. The related CAE obtainer status comment was also
  updated as acceptance cleanup so it no longer describes implemented Rev.3/Rev.4
  obtain logic as a skeleton. This is UI/status/documentation hygiene,
  non-destructive restore preflight evidence, and bounded recovery-drill receipt
  evidence only, not restore execution, destructive restore success, live DB
  swap, sidecar staging, ledger restore append, RPO/RTO certification,
  production backup policy, DR readiness, backup custody proof, encryption
  proof, legal archive certification, or new CAE provider behavior.
- **Trust-source provider management:** Settings now exposes settings-backed
  management for multiple TSL sources and TSA providers, with localized labels
  and focused `SettingsPage` coverage for rendering, autosave, default TSA
  selection, and older settings payload defaults. Backend/runtime source
  resolution/status and production trust validation remain partial.
- **Compact Data Management cleanup controls:** the Data Management storage
  panel now renders crash-report and retained-export cleanup as compact rows
  with tighter descriptions, metrics, and action placement. Tests pin both
  cleanup targets, including retained-export cleanup not mutating the crash
  target boundary. This is UI density/regression coverage only, not deeper
  backend per-table payload statistics or broader data-lifecycle automation.
- **User and signatory email capture:** onboarding first-user creation, Settings
  user create/edit, and the Ata signatory editor now expose optional email fields
  and send them through existing backend contracts. Book opening/closing termo
  signatories now accept structured name/capacity/email records through the
  legacy-compatible `required_signatories` write shape, expose
  `required_signatory_records_abertura` / `required_signatory_records_encerramento`
  for readers, and fall back to structured records generated from legacy strings
  when no structured data exists. This is field capture and compatibility
  modeling only, not email verification, identity proof, signature authority, or
  notification delivery.
- **Notification footer icon-only action:** the notification popup footer
  "Ver todas" link now uses the same icon-only, tooltip-backed accessible control
  pattern as the popup item actions, with focused `NotificationBell` coverage.
  This is popup action consistency/accessibility hardening only, not broader
  notification/dashboard workflow depth or new notice semantics.
- **Platform service-control UI clarification:** the Settings platform operations
  surface now hides non-meaningful desired-state action buttons, still lists the
  backend's unsupported/restart/supervisor-required action capabilities, and
  shows effective per-service log levels with global-off suppression. This is
  UI honesty and regression coverage only, not real process supervision,
  stdout/stderr capture, MCP process log forwarding, or historical log storage.
- **Dashboard dates tab:** dated reminders are split out of current work into a
  dedicated dashboard `Datas` tab, while current work keeps open-book and
  act-state summaries. Tests pin the subtab order and date-reminder
  sorting/deduplication on the new tab. This is dashboard navigation hardening
  only, not legal-calendar validation or workflow completion proof.
- **Export save prompts:** act PDF and working-copy exports, ledger archive
  PDF/A, book bundles, preservation packages, and paper-import package downloads
  now use the shared save helper with desktop/browser save prompts where
  available, cancellation reporting, and safe browser-download fallback. This is
  user-owned file export ergonomics only, not a new evidentiary format, signing,
  notarization, or archive legality claim.
- **PDF table structure semantics:** the PDF writer now emits bounded
  Table/TR/TH/TD structure roles for key/value and vote tables, maps the custom
  table roles to `Table`, and clears the local table-semantics blocker facts in
  the accessibility report while keeping `pdf_ua_claimed` false. This is a local
  table-structure slice, not full PDF/UA delivery or external certification.
- **CI/E2E hardening-plan refresh:** the hardening plan was refreshed with the
  current CI shape, SQLCipher package defaults, platform/logging boundaries,
  export/save prompt expectations, and focused check history. It remains an
  operating checklist, not a full release-candidate green-run claim.
- **Books filter/table density hardening:** the books page now has compact
  primary filters, a collapsed advanced filter area, no-horizontal-overflow CSS
  contracts, fixed-layout truncating rows, and icon-only open actions. This is
  focused list ergonomics and regression coverage only.
- **Encrypted package-build defaults:** release workspace builds, the Docker
  server image, and desktop package builds now opt into existing SQLCipher
  features by default, with `npm run check:encrypted-build-defaults` guarding the
  scripts. Validation includes SQLCipher Cargo metadata and a Windows compile
  with native Strawberry Perl pinned. This does not create a hardware-ID-derived
  master key or solve production key custody/migration.
- **Platform service controls and log thresholds:** platform APIs now expose
  honest desired-state service controls, explicit unsupported/supervisor-required
  outcomes, platform service/control contract fixtures, persisted audit evidence,
  and a shared API-owned logging threshold model with global-off suppression and
  true per-service overrides. `POST /v1/platform/logs/forwarded` now adds
  bounded structured log ingress into that same tail under
  `platform.logs.write@Global`, with fresh seeded permission coverage limited to
  Owner and Platform Administrator and API Client excluded by default. Accepted
  retained forwards append sanitized `platform.log.forwarded.accepted` ledger
  events, while global/service `off` suppression, invalid requests, and auth
  failures append none. This is not process supervision, stdout/stderr capture,
  stdout/MCP log tailing, production observability, generalized SIEM/HA
  observability, log retention/deletion semantics, or a legal/compliance claim.
- **Compact notifications and storage settings:** notification popup entries are
  shorter and denser with title-line tags, robust layering, and icon-only
  actions, while Data Management exposes summary storage/permission status,
  cleaner permission rows, compact cleanup rows, and theme-colored disabled
  button textures. This is UI polish and focused regression coverage only.
- **Entity single-line rows and filter overflow hardening:** registered-entity
  filters now sit inside an overflow-clipped wrapper, and the registered-entity
  table uses fixed single-line truncation for default and enriched rows while
  preserving a separate icon-only action column. Unit tests pin the CSS no-overflow
  rules and assert tooltip-backed truncating cells. This is UX regression coverage
  only, not legal registry certification or a complete table-ergonomics program.
- **Dashboard summary caps and polish:** the dashboard current-work tab now shows
  the five newest open books, the five earliest dated reminders after dedupe, and
  hidden-item counts, with denser summary styling and left-positioned work-queue
  tooltips. This is presentation/regression hardening for existing dashboard data,
  not legal-calendar validation, attendance proof, workflow completion, or new
  notice semantics.
- **Local ASiC inspection and structural diagnostics:** `POST
  /v1/signature/asic/inspect` accepts a base64 ASiC ZIP plus optional filename,
  declared size, and declared SHA-256, then returns local technical profile
  shape, bounded profile, blockers, member paths, manifest diagnostics,
  signature diagnostics, no-claim fields, and local CAdES validation only for
  blocker-free bounded ASiC-S/CAdES or ASiC-E/CAdES candidates. ASiC-XAdES
  reports structured unsupported diagnostics and performs no XAdES validation.
  The ZIP reader now accounts actual decompressed member and aggregate sizes for
  payloads, manifests, CAdES signatures, XAdES signatures, unsupported
  `META-INF`, and other non-directory members, so underdeclared entries still
  produce blockers. This is technical diagnostics only, not signing, storage,
  archive mutation, XAdES validation, CAdES trust validation, live provider or
  trust-network use, LTV evidence, legal validity, qualified status, production
  ASiC compliance, or authority approval.
- **Accepted paper-book OCR conversion dossier:** accepted OCR draft review
  metadata can now be recorded as a metadata-only, non-canonical conversion
  dossier through `POST
  /v1/books/paper-import/{id}/ocr-drafts/{draft_id}/conversion-dossier` and
  listed through `GET /v1/books/paper-import/{id}/conversion-dossiers`. The API
  requires an accepted matching draft, refuses unaccepted/superseded/mismatched
  cases without mutation, stores only review metadata/digests/page spans, returns
  the existing dossier on duplicate creation without a second ledger event, and
  keeps raw OCR text out of responses and ledger events. The response and ledger
  keep act/document/PDF-A/PDF-UA/signature/seal/legal-validity creation and
  claim flags false. BookDetail lists existing metadata-only dossiers and allows
  operator-triggered creation only for accepted OCR drafts without an existing
  dossier, keeps mutable draft-act creation separate, renders the no-claim flags
  and notice, hides raw OCR text, performs no automatic dossier POST, and does
  not call document, signature, seal, or archive endpoints from that UI. This is
  review metadata only, not authoritative OCR text, not canonical minutes
  conversion, not document generation, not signing/sealing, not OCR accuracy
  certification, and not legal acceptance or legal validity.
- **Declared signer-capacity evidence preservation:** CMD, CSC remote, local
  PKCS#12, and official signed-PDF handoff signing/import paths now preserve
  request/operator-declared signer capacity through pending CMD sessions,
  signed-document storage, status views, responses, and audit/event payloads.
  The preserved evidence is explicitly `not_checked_by_scap` and
  `declared_capacity_evidence_only`; it is not SCAP verification,
  representative-authority proof, qualified-signature validation, authority
  approval, or legal-capacity verification.
- **Written-resolution evidence status binding:** written-resolution evidence
  can now be patched as structured checklist references/digests, reported in
  act/compliance views as missing/referenced-only/bound-present status, and
  included in the seal digest when present. This is operator-supplied evidence
  status and digest binding only, not proof of written consent, quorum, vote
  threshold, participant identity, or legal acceptance.
- **Paper-book OCR browser workflow regression:** focused browser E2E now covers
  preserving a paper-book package as non-canonical evidence, requiring explicit
  acknowledgement before auxiliary OCR draft creation/review, refusing an
  unconfigured local OCR run without creating a draft, and keeping preserved
  package download separate after reload. This is workflow coverage only, not
  canonical OCR conversion, PDF/A generation, signing, OCR accuracy
  certification, or legal validity.
- **Compact validator and notification actions:** Ferramentas validator report
  actions now use compact icon controls for local technical JSON copy/save and
  metadata-only summary save actions, while notification popup/page actions are
  pinned as icon-only tooltip-backed route/read/acknowledge/dismiss/restore
  controls. This is UI consistency/accessibility hardening only, not new legal
  notice or validator-authority semantics.
- **PDF/UA blocker decomposition:** the PDF accessibility report now breaks its
  no-PDF/UA position into machine-readable local facts for heading hierarchy,
  role-map coverage, key/value and vote-table semantics, layout artifact
  marking, and caller-supplied non-text content accounting. The deterministic
  JSON report is versioned as `5` and accounts for writer-owned decorative
  artifacts including the header rule, explicit rules, vote-table rules, and
  signature lines while excluding page breaks; focused tests keep
  `pdf_ua_claimed` false plus the absence of PDF/UA identification metadata and
  `pdfuaid`. This is blocker
  explanation and regression evidence only, not PDF/UA certification, semantic
  completeness, external validator approval, or legal document acceptance.
- **Web local OCR run UI:** the book detail page now lets an operator run the
  configured local OCR endpoint for a preserved paper-book package after an
  explicit non-canonical confirmation. The UI posts no request body, renders
  completion/failure status, refetches the import/draft lists, and displays any
  unreviewed auxiliary OCR draft. This is local OCR workflow UI only, not
  authoritative OCR conversion, canonical minutes creation, PDF/A generation,
  signing, legal acceptance, or OCR accuracy certification.
- **Caller-supplied archive timestamp append API:** `POST
  /v1/acts/{id}/signature/archive-timestamp/append` accepts caller-supplied RFC
  3161 token bytes for an existing signed PDF, appends a local `/DocTimeStamp`
  revision, validates the resulting incremental update, updates the signed-PDF
  digest/bytes, and records a separate
  `document.signature.archive_timestamp_appended` audit event. It rejects stale
  tokens and keeps production/legal B-LTA flags false. This is local technical
  evidence mutation only, not provider-driven renewal, production B-LTA,
  trust-policy approval, legal validity, or authority approval.
- **Executable local paper-book OCR API:** `POST
  /v1/books/paper-import/{id}/ocr/run` executes an operator-configured local OCR
  command for preserved paper-book evidence, captures bounded stdout, stores an
  unreviewed non-authoritative OCR draft on success, and records failed,
  missing-config, or degraded outcomes without creating canonical records. The
  response and stored draft keep canonical-act, canonical-document, signature, and
  legal-validity flags false.
- **Mapped inter-word PDF spaces:** the PDF writer now emits actual mapped Unicode
  space glyphs between styled word fragments and wrapped key/value words, and
  the accessibility report exposes `inter_word_spaces_emitted` while keeping
  `pdf_ua_claimed` false. This is technical text/accessibility evidence only,
  not PDF/UA certification, semantic-tag completeness, or canonical OCR/text
  conversion.
- **Dashboard notification icon-only actions:** dashboard work-queue and archive
  notification affordances now use icon-only links with accessible names and
  tooltip labels, with unit coverage proving the route labels are not duplicated
  as visible button text. This is ergonomic/accessibility polish for existing
  dashboard actions only.
- **Structured chronology graph bundles:** entity chronology responses now include
  deterministic structured graph data alongside the existing Mermaid strings for
  shareholders, organs, and relationship stubs. The graph nodes/edges carry stable
  machine categories and source inscription/date provenance, and empty
  relationship graphs include warnings instead of fabricated edges. This is parsed
  registry visualization evidence only, not legal registry certification or an
  authority-approved ownership/relationship determination.
- **Raw external-validator technical metadata download checkpoint:** `GET
  /v1/external-validator-reports/{case_id}/{validator_family}` returns the
  validated raw technical metadata JSON for one safe report identity to
  `settings.read` actors. The route fails closed for unsafe identities,
  malformed persisted sidecars, duplicate report identities, and ambiguous
  suggested paths, with API coverage for persisted downloads, reader access,
  malformed-sidecar refusal, duplicate-identity conflict, and recent-landed
  static markers for the route/authz/helper coverage. This is technical metadata
  access only, not legal validity, trust-list validation, live provider validity,
  credentials handling, or authority approval.
- **Ferramentas external-validator report metadata management:** the PDF tools
  surface now includes an external-validator report metadata panel that uploads
  selected JSON as raw text, optionally lets the operator select a separate raw
  external-validator report file, computes only a local safe summary on
  selection, and sends the raw file only on explicit upload through backend
  `raw_report.content_base64` with content type, byte size, SHA-256, and safe
  source filename. It lists redacted metadata/raw-report summaries with storage,
  malformed-sidecar, and duplicate-path counts, renders only filename/type/size/
  digest/provenance summaries, and saves a client-generated metadata summary
  without raw report bytes. This is technical metadata/evidence handling only,
  not legal validation, external certification, PDF/UA certification, PAdES
  certification, compliance proof, trust-list validation, live provider
  validity, credentials, or authority approval.
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
  telematic and written-resolution templates. The current guard also requires
  `Certidao`/`Extrato` authored `BlockSpec` template references to
  `ata_number` and `payload_digest`. This remains local metadata and
  post-act provenance-reference consistency coverage only, not asset wording
  review or legal-effect validation.
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
  The working tree also adds bounded same-document `URI="#id"` fragment resolution
  for unique supported TSL targets and fail-closed handling for missing, duplicate,
  external, or unsupported fragment references, plus bounded P-256 ECDSA-SHA256
  verification when the signer certificate is embedded and the XML-DSig signature
  value is raw fixed-width `r||s`. DER ECDSA signatures are rejected. This improves
  technical trust-list evidence, but it still does not authenticate the TSL signer
  certificate against EU LOTL/national trust anchors, perform real C14N, support
  multiple references, support transform chains, complete broad ECDSA/XML-DSig
  profile validation, or perform full certificate path/revocation/policy validation
  or legal trust certification.
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
- **PAdES local LTV renewal plan:** `chancela-pades` reports a local technical
  renewal checklist from already-inspected signature timestamp, DSS revocation
  evidence, DSS `/TU`, and DocTimeStamp imprint binding signals, and the API can
  expose that plan in signature validation responses. Local DSS attach now also
  accepts caller-supplied `validation_time`, writes it as DSS VRI `/TU` metadata
  from caller-supplied evidence, rejects malformed time, and advances local
  renewal planning from missing validation time to document timestamp or monitor
  states when the bounded evidence is present. The multi-signature model can
  classify caller-supplied technical renewal deadlines and per-signature local
  evidence gaps. It does not fetch live revocation or trust material, validate
  trust, infer legal deadlines, execute renewal, or claim B-LT/B-LTA, production
  long-term profile, legal LTV, QES, or qualified status.
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
  manifest, and SHA-256 `DataObjectReference` checks against the packaged payload members. The
  local inspection endpoint can recognize and technically validate that bounded CAdES candidate
  when it has no blockers. This is CAdES-backed manifest support only; it is not XAdES,
  ASiC-XAdES validation, multiple signatures, manifest extensions, embedded LT/LTA evidence, ETSI
  profile completeness, production ASiC compliance, or legal validity assessment.
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
  export-only dry-run, minimum-age, and keep-latest policy controls; dry-run reports
  `would_delete_files`, `would_delete_directories`, and `would_delete_bytes` while every
  `deleted_*` counter stays zero, and those options are rejected for crash cleanup. Data Management
  renders the same status with refresh, copy-path, scan-error, browser-safe open-folder-disabled
  states, and cleanup controls, and the retained-export action posts the preview-only
  `{ target: "exports", dry_run: true, minimum_age_days: 30, keep_latest: 5 }` payload with
  explicit no-files-removed copy. This does not add durable log
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
  PAdES/CAdES, ByteRange, DSS/VRI including keyed `/TU` values, DocTimeStamp validation details,
  per-signature local renewal gaps, trust, revocation, qualification, and findings. Digest/size
  backend refusals are surfaced as a safe refusal. The UI copy is explicit that this is technical
  local validation only, not AMA/live-trust/legal/qualified validation or a legal LTV claim.
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
  collapsed-by-default advanced area with overflow-clipped wrappers and responsive grid sizing.
  Focused tests pin collapsed state, primary-field count, clear behavior, and CSS no-overflow
  declarations. The PT source catalog also replaces the awkward `Todo o registo` filter label with
  `Qualquer estado`.
- **Button state and storage-tab polish:** web styling now applies broader button hover and leather
  active states, and the Data Management storage tab has tighter spacing around telemetry and
  maintenance controls. This is UX polish only; it does not expand functional compliance coverage.
- **Platform operations and logging policy:** Settings now carries an additive `platform` section
  with strict app/API/MCP log levels, per-service overrides, API/MCP desired state, last-action
  metadata, and an audit tail. `/v1/platform/services` reports API and MCP status plus limitations,
  `/v1/platform/services/{id}/actions/{action}` records start/stop/restart desired state with
  audit evidence, and `/v1/platform/logs?service_id=&level=&tail=` returns the newest bounded
  API-owned structured platform log tail with strict `settings.read` access and service/level/tail
  validation. `POST /v1/platform/logs/forwarded` accepts bounded structured forwarded entries
  under non-meta `platform.logs.write@Global`, rejects unknown services, `off`, unknown fields,
  raw `stdout`/`stderr` fields, blank or oversized values/context, and stream or secret-like
  context keys, and then writes accepted entries through the same ring, retention, persistence,
  and GET tail behavior. API-owned structured entries are recorded only when the emitted level passes the
  effective service/global/area threshold. When `CHANCELA_DATA_DIR` is configured, the API-owned
  tail is persisted to `platform-logs.json` and bounded to 512 entries; otherwise the in-memory
  fallback remains. Platform status reads, control requests, and forwarded entries add structured API
  log entries only when those thresholds allow them, and global/service `off` suppresses forwarded
  entries too. Accepted retained forwarded entries append a sanitized
  `platform.log.forwarded.accepted` ledger event containing only retained log
  id/seq/timestamp, service_id, level, target, message length/SHA-256, context
  key count, and context serialized size; no raw message/context/stdout/stderr/
  body/secrets are written to the ledger event. Authenticated RBAC-denied,
  malformed, rejected structured, and threshold-suppressed forwarded requests
  append sanitized denied/rejected/suppressed route-outcome audits with no raw
  body, message, context keys, parse errors, stdout, stderr, tokens, secrets, or
  user strings; missing or invalid bearer requests remain unaudited. Internal
  platform logging callers continue to ignore the returned `Option` from the log
  writer. The web Settings
  `Operações` tab exposes the same status, log controls, and action buttons, plus an AI/MCP
  assurance panel for managers covering dual gates, API-key RBAC, non-authoritative draft output,
  and technical-only signature-bundle scope without exposing secrets. This is honest
  desired-state/control evidence plus an API-owned log tail only: it is not historical
  stdout/stderr, does not tail or capture stdout/stderr, does not control process lifecycle, does
  not add a production supervisor/SIEM/HA/observability guarantee, and is not a complete durable/live
  structured sink, generalized observability sink, reload/process logging pipeline, log
  retention/deletion policy, or legal/compliance claim.
- **Entity list ergonomics:** registered-entity filters now keep search/family/type in a compact
  primary area that wraps instead of forcing horizontal scroll, and move the rest into a collapsed
  accordion-style advanced filter area that expands into wrapped multi-line controls. The table uses
  fixed layout and single-line truncating cells so verbose values do not overflow; long text is
  kept to one line with full tooltips, while Type and Last Activity render shorter visible
  summaries.
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
- **Local DGLAB interchange scaffold:** `chancela-archive` can derive a
  metadata-only `LocalDglabInterchangeManifest` from an existing
  `PackageManifest` using schema/profile
  `chancela-local-dglab-interchange-manifest/v1`. The scaffold is deterministic,
  sorted, validated against the source manifest, and keeps official-DGLAB,
  certification, approval, legal-archive, and destructive-disposal flags false.
  It is not written as a ZIP sidecar and does not add API/UI/import/disposal or
  certification behavior.
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
  operators. Settings > Privacidade now exposes policy list/create/patch/filter/status controls and
  a dry-run form using the same policy and dry-run endpoints; locale coverage includes the retention
  labels and non-destructive boundary copy, and focused tests assert no execution, delete, or
  anonymize endpoint/payload is sent by the UI flow. `GET
  /v1/privacy/retention-due-candidates` now adds a read-only scanner for closed-book
  archive/document candidates, matching active retention policies against closing date plus
  supported `PnY`/`PnM`/`PnD` periods, surfacing legal-hold blockers, required approvals,
  unsupported-period findings, and explicit `would_execute: false`,
  `destructive_disposal_completed: false`, and `full_erasure_completed: false` flags. Settings
  renders those candidates on page load without creating retention execution, disposal, or erasure
  records, and an explicit row action can request review by posting a dry-run
  `execution_request` with forced/default `review_only` and refreshing the due-candidate and
  execution-history queries once the execution record is returned. Duplicate `review_only`
  requests for the same candidate/policy reuse the existing `awaiting_review` execution, including
  concurrent duplicate guards, without adding another execution record or ledger event; the
  due-candidate GET remains read-only and the UI shows queued review status/id/time instead of
  posting again. Due-candidate reads can also project prior safe bounded
  `executed` archive/no-action evidence for the same candidate/policy without
  writing records or audit events, only when the internal result keeps
  `bounded_executor: true`, acted targets, and false destructive/full-erasure
  flags; projected `prior_execution.next_step` is canonical bounded text, not
  persisted free-form text, and the UI suppresses duplicate review actions only
  for projected rows. This is retention register, dry-run, due-candidate
  scanner, review-request, and execution-history evidence only: it still
  performs no deletion, anonymization, redaction completion, archive disposal,
  destructive GDPR erasure, legal completion, legal-retention certification,
  legal default scheduling, legal disposal approval, policy or legal-hold
  mutation, candidate resolution, or disposal execution.
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
  false canonical-act/document/signature/legal-validity flags. Accepted OCR draft conversion dossiers
  add API/store and BookDetail metadata-only evidence for accepted drafts with idempotent duplicate
  creation, no raw OCR text in API responses, ledger events, or dossier UI, and false
  act/document/PDF-A/signature/seal/legal flags. Broader OCR execution/review, reviewed canonical
  paper-book conversion execution, and legal acceptance remain follow-up work.
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
  not completed remote signing. Invite creation can optionally link a record to an existing external
  signing envelope slot with `external_envelope_id` and `external_slot_id`, initiating allowed slots
  through the existing order policy: later sequential slots fail with 409 and no token or stored
  invite, while the first sequential slot and parallel slots are allowed and marked initiated. The
  SigningPanel form sends those linked IDs only when a slot is selected and keeps the payload
  tracking-only when it is not; sequential 409 conflicts render as safe operational copy without raw
  backend/token-like detail and are cleared after slot selection changes. Unauthenticated token-body
  lookup/respond endpoints expose only safe invite/act/document metadata
  plus redacted linked-envelope/slot metadata while the token is live, record accepted/declined
  acknowledgement events, and never return token material or canonical PDF/signed-PDF downloads. The
  acknowledgement response remains tracking-only and does not sign or complete envelopes/slots or
  claim legal/qualified status. A token-body-only public endpoint can return a non-canonical Markdown
  working copy for sealed acts; it is explicitly non-evidentiary and not a qualified signature. The
  signing panel exposes create/list/revoke plus one-time token display, per-act workflow-only
  envelope list/create controls with order policy and signer slots, slot labels/statuses, identity
  requirements, completion summary, and backend no-legal/no-qualified notice; `/assinatura-externa`
  is the token landing page.
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
  summarizes response/status state, maps `workflow: external_envelope` to a localized external
  envelope label in rows and token lookup, handles same-origin token links, looks up public envelope
  metadata, and uses localized copy. This is still invite/envelope tracking and safe working-copy
  access, not legal signing completion, qualified-signature validation, public token exposure, or
  canonical signed-PDF delivery.
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
  slices. The API-level ASiC inspection route is also local technical evidence only: it can inspect
  member shape, blockers, and bounded CAdES cryptographic validity, but ASiC-XAdES remains
  unsupported and no XAdES validation is performed. Local PKCS#12 signing is advanced local
  technical evidence only, not CMD, not a remote
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
  data. Settings now expose the bounded `workflow.reminders` policy for existing local advisory
  reminder families: default enabled behavior preserves the prior limit 5 / due-soon 45 /
  attendance-lookahead 45 output, `enabled=false` suppresses reminder feed/cards without breaking
  other dashboard data, source toggles suppress only profile-calendar, act-follow-up, or
  attendance-hygiene reminders respectively, and status classification uses absolute calendar-day
  deltas across year boundaries. The Gestão controls are compact operator policy controls; they do
  not create external delivery, legal-calendar authority, attendance proof, workflow completion, or
  legal sufficiency.
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
  PKCS#12 API signing tests, multi-signature PAdES renewal-plan API tests, bounded retention execution tests, Settings retention policy list/create/patch/dry-run UI markers and non-destructive payload assertions, privacy breach/transfer review-receipt tests, TSL XML-DSig hardening tests including bounded same-document `URI="#id"` fragment markers and raw P-256 ECDSA-SHA256 `r||s` signature markers, MCP
  resource/prompt tests, API dashboard reminder policy/default/source-toggle/window/year-boundary
  tests, web contract/client/settings-default/dashboard/ferramentas/signing/i18n/trust tests,
  external-signing envelope UI/link-safety tests,
  backup recovery-drill receipt API tests plus Data Management, restore-modal, and contract
  checks for bounded receipts, nullable manifests, optional operator notes/custody location keys,
  exact transient passphrase submit/clear behavior, false overclaim flags, and no live restore call from the drill action,
  external-validator report metadata API tests including data-dir sidecar reload, settings.read raw
  metadata download, settings.read raw-report byte download with attachment headers, manifest-only
  404, malformed/unsafe/duplicate fail-closed behavior, and malformed sidecar counting, the static
  live-provider assurance gate, notification-popup browser coverage,
  static imported-document review notification/export browser markers, static data-key rotation
  execution browser markers, static entity chronology/PDF-validator browser markers, trust
  identifier UI and identifier-match explanation markers, external-validator metadata/raw-upload
  panel/client/i18n markers, PDF table-structure
  semantics markers, export save-prompt markers, dashboard dates-tab markers, platform operations
  UI/effective-log markers, notification footer icon-only markers, user/onboarding/act
  signatory email markers, compact data-cleanup row markers, retained-export dry-run
  `would_delete_*`/zero-`deleted_*` and preview-only payload markers, Settings trust-source
  provider/i18n markers, compact template filter DOM/CSS/test markers, post-act template
  sealed-provenance semantic lint markers, structured book termo
  signatory contracts, retention execution review-queue/client/fixture markers, database
  encryption key-source and fail-closed hardware-fallback status markers, backup recovery-drill
  route/contract/optional-key/overclaim/no-mutation/exact-passphrase markers, imported-document
  review receipt UI/no-fake-receipt/no-extra-route markers, MCP workflow provenance review
  prompt/resource markers, MCP draft-vs-signed comparison review prompt/resource
  markers, dashboard guest `recent_events: []` redaction markers,
  generated-document by-id download route markers, external-signing
  envelope UI/safe-409/Ferramentas label markers, PDF verifier DSS/VRI
  `/TU` plus local renewal/no-live-trust/no-legal-claim UI markers, hardening-plan head markers,
  validator corpus sidecar validation, CLI encrypted-key environment tests, and desktop lockfile
  metadata. The static
  mode catches accidental removal of the mapped files and fixture markers without running the full
  commands.
- **Release trust metadata guard:** `scripts/check-release-trust.mjs` validates explicit package
  `releaseTrust` metadata and Docker signing-status metadata in the current `unsigned-dev` /
  `local-ci` paths and in production declarations, with a CI self-test and release/Docker workflow
  checks that reject production signing, notarization, publication, or attestation claims without
  matching metadata anchors. The self-test now also statically verifies that the CI metadata lane
  runs release-trust, SBOM package-linkage, and package provenance checks; the Docker job remains
  no-push/local-load with `local-ci` trust status and `--expect-mode local-ci`; and the release
  workflow runs package integrity, `releaseTrust.mode = unsigned-dev`,
  `attestation.status = not_attested`, `--expect-mode unsigned-dev`, and SBOM package linkage.
  Production package validation requires `--manifest` when either the package mode or expected
  mode is `production`, and the self-test covers those two signals independently.
  Docker production metadata must include anchors such as image/artifact digests, HTTPS
  workflow/run URLs, signing identity or certificate fingerprint, and attestation predicate
  metadata. This guards metadata honesty and static workflow wiring only; it does not sign,
  notarize, attest, publish, verify a registry push, or prove artifact provenance.
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
  preflight while clearing entered secrets. API data status also exposes a non-secret
  `database_encryption` object with key-source classification and a `hardware_derived_fallback`
  status that is explicitly unavailable and fail-closed if requested. This is a guard, status, operator-plan, web/API
  preflight, and store-level evidence surface only: it does not prove live production SQLCipher
  encryption, host decryptability, hardware-derived key custody/defaults, completed execution
  rotation operations, completed at-rest encryption, or plaintext migration. Plaintext-to-encrypted
  migration execution, production rotation workflow, and sidecar encryption remain follow-up work.

---

## Remaining Blockers

### Local product work

- Legal/product depth: per-family rule-pack completeness, legally verified
  threshold values, exhaustive/verified template/citation law references, guest/privacy redaction
  coverage beyond the current read-response slices, destructive/automated DSR execution workflows
  beyond erasure preflight and bounded evidence, and DPIA/breach/transfer-control documentation
  depth.
- Data lifecycle/storage: the cleanup endpoint covers crash reports and retained exports only, with
  retained-export dry-run/minimum-age/keep-latest guardrails and dry-run `would_delete_*` planning
  counters that leave `deleted_*` at zero, and archive disposal execution is
  non-destructive evidence only; the web hot-backup button creates and displays a manifest, and the
  recovery-drill receipt route records preflight-only bounded evidence, but neither proves restore
  success, custody policy, RPO/RTO, production backup policy, or legal archive certification; deeper backend per-table payload statistics, actual physical deletion, broader retention/disposal policy
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
  structural self-check plus mapped spaces, table-structure semantics, and decomposed blocker reports, richer
  structure trees/tagging/role maps/marked artifacts, broader OCR execution/review
  operations and reviewed canonical/legal conversion beyond the
  operator-configured local auxiliary OCR draft path, metadata-only accepted-draft
  conversion dossiers, bounded mutable drafting aid where present, and preflight
  evidence for preserved legacy DOC and historical paper-book evidence, official DGLAB
  interchange/certification, actual physical deletion, broader disposal/retention policy
  automation, GDPR erasure linkage, legal acceptance/certification, and long-term signature evidence
  packaging/renewal execution beyond the implemented sidecars, archive package
  `evidence/index.json`, document-bundle `validation_report.evidence_index`, local PAdES renewal
  plans, caller-supplied local archive timestamp append, technical metadata projections, and
  bounded digest-verified raw external-validator report attachments.
- Trust/signing depth: production/legal B-LT/B-LTA, XAdES/ASiC-XAdES execution beyond structured
  unsupported diagnostics, ASiC inspection beyond the local read-only technical endpoint,
  ASiC-E coverage beyond the bounded CAdES-signed manifest/digest-binding path, embedded ASiC
  LT/LTA evidence,
  PKCS#11/operator certificate workflows, multi-signature/archive timestamp renewal depth beyond
  caller-supplied local timestamp append and policy-driven LTV renewal timing, production
  provider-management flows, actual operator validator
  report collection for the corpus, populated runtime evidence-index attachments beyond the bounded
  external-validator metadata/raw-report attachment paths, AMA/CMD production approval beyond generated/checkable
  evidence-pack material, and external signer legal completion beyond invite/envelope-slot
  tracking, uploaded technical signed-PDF evidence, and identity-evidence records.
- Workflow breadth: legal-calendar preset depth beyond the advisory dashboard reminder, broader OCR
  execution/review and canonical-conversion flows for preserved paper-book packages beyond current
  operator-configured local OCR run, non-authoritative OCR draft metadata/review UI,
  metadata-only accepted-draft conversion dossiers, any accepted-draft mutable drafting aid,
  focused browser workflow regression, and preflight evidence, written-resolution legal/evidentiary
  completion beyond operator-supplied checklist/digest status binding, external signer
  provider-backed envelope signing/evidence capture and document-gated/legal completion flows, dashboard
  depth beyond the current reminders/activity/archive/attendance alert slices, groups/tenancy,
  broader signatory identity/authority workflows beyond the current act and structured
  book-term capture fields, sync/connectors, live SQLCipher/at-rest DB encryption verification plus migration operations and
  production key-secret rotation operations beyond current key-env/preflight support and already-open-store rekey evidence, ZK, HA, and mobile builds.
- AI feature layer: drafting/extraction/compare/summarize, workflow-level provenance panels beyond
  the MCP envelope/source-provenance object, act human-review gate panel with deterministic
  statement-source rows, status/spec-coverage resources, static human-review/compliance/paper-book
  prompts, and settings/platform assurance panel, broader MCP prompt/resource coverage, additional
  MCP transports, live AI provider calls, broader extraction/compare/summarize, and any
  legal-validity, authoritative-source certification, or AI-quality assessment.
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
  deterministic blockers, not fake live signing; bounded same-document `URI="#id"` handling does
  not change the absence of real C14N, signer trust anchoring, multiple-reference support, ECDSA
  wiring, or legal trust certification. The bundled fixture is advisory and must not be treated as
  legal trust completion.
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
  trust production readiness. Identifier-match notes explain which technical catalog field matched
  a strict identifier-filtered row and keep full hash/SKI copy actions available; they are not legal
  validity, certificate trust, provider approval, external validation, or qualified-status claims.
- External signing workflow screens, workflow-only envelope list/create UI, optional linked invite
  envelope slots, initiated slot states, public envelope lookup, and identity-evidence requirements
  are operational tracking/control surfaces; accepted/declined invite responses, identity evidence
  references, and uploaded signed PDFs are not envelope/signature completion, legal signing
  completion, slot signing, legal identity proof, representative-authority proof, trust-list
  validation, or qualified-signature validation.
- MCP draft human-verification states are exposed in output envelopes, and AI-origin act drafts now
  have persisted provenance with deterministic `ai_provenance.statement_sources[]` rows plus
  accepted/rejected human-review decisions that gate the Signing transition, with the Ata editor
  surfacing that gate, grouped statement-source counts by `source_type`, row
  path/type/label/status, conservative false/no-claim flags, and missing/null
  fallback labels. Unsafe statement-row human-verified, authoritative-source,
  and legal-validity claims are clamped false. That gate records human review
  only; it is not legal certification, AI output-quality or model-accuracy
  validation, authoritative-source certification, a provider call, hidden
  signing/trust operation, automated draft-vs-signed comparison execution, a
  complete provenance experience, or acceptance of draft text as final minutes.
  The MCP status and spec-coverage resources are local snapshots, and the MCP
  human-review, compliance, paper-book OCR, workflow provenance review, and
  draft-vs-signed comparison review prompts/resources are static offline
  guidance with no bridge/API/provider calls, no secrets, and no legal,
  source-certification, provider, trust, external-validation,
  signature-qualification, AI-01/full AI completion, AI-completion, or
  MCP-completion claim.
- Declared/requested signer-capacity evidence is preserved as
  `not_checked_by_scap` and `declared_capacity_evidence_only`; it is not SCAP
  verification, representative-authority proof, qualified-signature validation,
  authority approval, or legal-capacity verification.
- Local B-LT/B-LTA labels, caller-supplied local DSS validation-time `/TU` attach,
  caller-supplied local archive timestamp append, and local LTV renewal plans
  report or mutate technical evidence observed in the file, including
  multi-signature DSS/VRI coverage, per-signature evidence gaps, local
  `/DocTimeStamp` presence, document-timestamp monitor state, and
  caller-supplied deadline classification where configured; they do not fetch
  live OCSP/CRL/TSA/TSL material and are not production or legal
  long-term-validation claims, legally derived renewal-deadline decisions,
  provider-driven renewal, production B-LT/B-LTA, QES, qualified status, or
  trust-policy determinations.
- Bounded ASiC-E/CAdES support signs and validates one ASiCManifest/digest-binding container shape;
  it is not XAdES, ASiC-XAdES validation, embedded LT/LTA evidence, broad ETSI profile completeness,
  production ASiC compliance, or legal validity assessment.
- `POST /v1/signature/asic/inspect` is a read-only local technical inspection endpoint for a
  caller-supplied base64 ASiC ZIP. It validates declared fixity, base64, readable ZIP structure, and
  unsafe member paths; reports profile shape, bounded profile, blockers, member paths, manifest and
  signature diagnostics; and runs local CAdES cryptographic validation only for blocker-free bounded
  ASiC-S/CAdES or ASiC-E/CAdES candidates. ASiC-XAdES receives structured unsupported diagnostics
  and `xades_validation_performed: false`. The endpoint and ASiC ZIP reader do not sign, store,
  mutate archives, call live providers, fetch TSA/TSL/OCSP/CRL material, anchor trust, validate
  XAdES, certify legal validity, claim QES, claim B-LT/B-LTA, decide eIDAS legal effect, or certify
  production ASiC compliance.
- ASiC structural diagnostics expose member-shape classifications, manifest/signature diagnostics,
  blocker IDs, and actual decompressed-size blockers so operators/tests can understand why a package
  is outside the bounded slice. They do not validate XAdES, establish CAdES trust, fetch or prove LTV
  evidence, certify broad ASiC profile compliance, or create legal/qualified-signature validity.
- Template law references are bounded Pending provenance links derived from current rule-pack and
  threshold metadata; they are not exhaustive, legally verified, or a substitute for reviewing the
  generated template wording.
- Template catalog metadata validation is regression coverage for required fields, duplicate IDs,
  family-binding drift, family/channel compatibility, id/stage/channel
  consistency, law-reference anchors, and post-act
  `Certidao`/`Extrato` references to sealed-act `ata_number` / `payload_digest`; it is not legal
  review of template wording, thresholds, channel permissibility, cited law, or legal effect.
- The law citation resolver and corpus pin/copy UI preserve corpus verification status; copied
  Pending citations are not DRE-verified law text, legal bases, or legal advice.
- Guest/minimal redaction hides selected read-response metadata for current entity, registry, book,
  act, imported-document views, and dashboard recent events; it is not full
  anonymization, destructive erasure, a permission grant, or certification of
  access-control/privacy policy completeness.
- Seeded role drift diagnostics report missing default permissions for manual
  review only. They do not auto-reconcile persisted editable roles, grant
  permissions, bypass role-management checks, or loosen authorization.
- Database key-ops status/preflight is a secret-free configuration/build/header classification and
  startup guard with web/API/CLI/store key-env/preflight/rekey evidence. The API/web execution path
  is limited to an already-open keyed SQLCipher store and refuses plaintext stores. It does not prove
  live production SQLCipher encryption, host decryptability, plaintext migration, production secret
  rotation runbooks, completed at-rest encryption certification, or conversion of plaintext SQLite
  stores into encrypted stores.
- The database key migration plan is operator guidance attached to key-ops status; it does not run
  backup/export-restore, verify a live encrypted restore, provide production operator rotation
  flows, or retire plaintext data.
- Restore preflight and backup recovery-drill receipts are non-destructive
  archive screening/receipt evidence: API/store verify the archive manifest,
  member digests, and ledger integrity in an isolated snapshot, the receipt route
  records only bounded sidecar evidence, and the web surfaces expose only bounded
  manifest/evidence before destructive restore. They do not execute restore,
  swap the live DB, stage/replace sidecars, append ledger restore events, delete
  data, prove off-site custody, certify RPO/RTO or production backup policy,
  prove backup encryption custody, establish disaster-recovery readiness, provide
  legal archive acceptance, or certify data-lifecycle compliance.
- Archive readability/ZK caveat metadata is manifest-only conservative status.
  It includes no decryption keys or materials, no connector/import proof, no
  custody proof, no ZK repository guarantee, no GDPR-obligation removal, and no
  legal archive certification.
- Erasure DSR completion is bounded preflight evidence with immutable-ledger blockers,
  mutable-sidecar planning, and explicit false destructive/full-erasure flags. It is not GDPR
  erasure, anonymization, physical deletion, redaction execution, or full data-subject erasure.
- Imported-document preservation review policy, UI controls, guardrail acknowledgements, guardrail
  fields, and the derived `Recibo de revisão` panel record review requirements, reviewer metadata,
  and conservative original-byte/canonical-conversion decisions for non-canonical evidence. Pending
  rows do not invent receipt metadata. These surfaces do not run OCR, convert documents to PDF/A,
  create canonical records, create or validate signed artifacts, add routes/schema/mutations/downloads,
  certify legal acceptance, or validate legal effect.
- Paper-book local OCR run, OCR draft review metadata, accepted-draft conversion
  dossiers, any accepted-draft-to-act drafting aid, UI, and focused browser
  workflow coverage record bounded command status and non-authoritative
  review/drafting evidence with explicit false canonical/signature/legal flags.
  The conversion-dossier path is metadata-only and keeps raw OCR text out of API
  responses and ledger events; duplicate creation is idempotent. Any mutable
  drafting aid remains non-authoritative. These paths do not create canonical
  minutes, create canonical documents or PDF/A, sign or seal anything, certify
  OCR accuracy, or accept historical scans as legally converted digital records.
- Paper-book canonical-conversion preflight evidence classifies whether an operator-supplied
  evidence set is missing, blocked, or sufficient for a later draft step. The
  accepted-draft conversion dossier is metadata-only, and any accepted-draft
  mutable act path remains only a drafting aid; neither path executes
  authoritative OCR, converts paper/legacy evidence into canonical minutes,
  creates canonical documents, signs artifacts, certifies legal acceptance, or
  claims legal validity.
- Validator corpus sidecars, projected evidence metadata, archive package `evidence/index.json`,
  document-bundle `validation_report.evidence_index`, evidence-indexing metadata,
  settings.read-gated raw technical metadata downloads, and settings.read-gated raw-report byte
  downloads preserve technical external report context, paths, and retained bytes only. List/create
  responses stay redacted and the web UI does not render raw report bytes. They are not live
  trust-list decisions, legal validity conclusions, qualified signature validation, DGLAB
  certification, external-validation certification, provider approval, or authority acceptance.
- MCP external-validator report discovery is limited to the redacted summary
  list route with a closed no-argument schema. It does not expose raw report
  downloads, `content_base64`, upload payloads, provider execution, legal
  validation, trust validation, or certification claims.
- The local DGLAB interchange manifest endpoint and BookDetail save action are
  read-only metadata-only JSON projections from an existing Chancela
  `PackageManifest`. They are not an official DGLAB interchange package/export,
  not a government filing, not a DGLAB approval/certification workflow, not
  PDF/A/PAdES/PDF-UA certification, not legal archival certification, not a ZIP
  sidecar/import path, not package validation change, not persisted package
  bytes, not a ledger event, and not disposal execution.
- Accessibility metadata, mapped inter-word spaces, PDF table-structure
  semantics, decomposed PDF/UA blocker reports, version 6 structural-depth
  evidence, bounded topology self-checks, bounded tagged structure,
  `DisplayDocTitle`, `/Tabs /S`, and XMP consistency checks are not PDF/UA
  delivery; the writer still keeps `pdf_ua_claimed: false`, keeps
  `LimitedTaggedStructure` machine-visible, emits no `pdfuaid` metadata, and
  reports local blocker facts rather than conformance, external-validator
  certification, or legal/reader acceptance.
- Privacy breach-playbook and transfer-control registers plus review receipts are operator
  tracking/control evidence; they do not execute incident response, perform authority/data-subject
  notification, approve or execute transfers, or certify GDPR compliance.
- Data cleanup is bounded storage maintenance for crash reports and retained exports. Retained-export
  dry-run, minimum-age, and keep-latest options are policy controls for that cleanup target only; the
  dry-run surface reports `would_delete_*` planning counters and zero `deleted_*` counters, and the
  Settings preview states that no files were removed. Guarded archive disposal execution is
  non-destructive ledger/audit evidence only; these surfaces are not GDPR erasure, legal disposal
  approval, anonymization/redaction completion, legal retention certification, certification of
  data-lifecycle compliance, or physical deletion guarantees beyond the existing bounded cleanup
  behavior.
- Data-status filesystem categories for `platform-logs.json` and
  `backup-recovery-drills.json` are telemetry labels for usage/status display.
  They do not change cleanup targets, execute retention, delete files, prove
  legal custody, or certify data-lifecycle compliance.
- Retention due-candidate scanner rows, review-only `execution_request` records,
  retention execution history, workflow blockers, required approvals, operator
  decisions, and audit evidence record requests, outcomes, and operator next
  steps for audit/review. Duplicate `review_only` requests reuse queued
  `awaiting_review` evidence and queued-review status surfacing only. Projected
  prior bounded archive/no-action executions on due-candidate rows are read-only
  internal evidence projections gated by false destructive/full-erasure flags
  and canonical bounded next-step text; they are not retention execution,
  candidate resolution, anonymization, redaction completion, physical deletion,
  policy or legal-hold mutation, legal disposal approval, or GDPR erasure.
- Dashboard legal-hold, sealed-not-archived, and missing-attendance alerts are advisory operational
  next steps; they do not certify legal-hold handling, approve disposal, prove archival completion,
  prove attendance, or validate meeting legality.
- Workflow reminder settings are bounded local dashboard policy controls over existing advisory
  reminder families only; they do not add legal-calendar rules, law-source authority, threshold
  verification, external delivery/email/ICS/CalDAV/webhook, workflow completion, attendance proof,
  compliance gates, or legal sufficiency.
- Dashboard summary caps, hidden-item counts, and registered-entity single-line/no-overflow table
  rules are UX regression boundaries only; they do not add workflow/legal semantics, certify entity
  registry facts, or make the dashboard/table coverage exhaustive.
- The persisted platform log tail covers threshold-filtered API-owned structured events and bounded
  `POST /v1/platform/logs/forwarded` structured entries only, with sanitized
  `platform.log.forwarded.accepted` ledger events only for accepted retained
  forwarded entries, and is bounded to 512 entries; it is not stdout/stderr
  capture or tailing, MCP child-process logging, complete historical logging,
  supervisor lifecycle evidence, a production supervisor/SIEM/HA guarantee,
  audit coverage for suppressed/invalid/auth-failed forwarded attempts, a
  generalized observability sink, log retention/deletion semantics, or a
  legal/compliance claim.
- CI and E2E coverage improve release confidence, the recent-landed checkpoint has broader
  cross-cutting coverage, and web unit tests now enforce coverage thresholds, but the current
  browser suite is not exhaustive, the signed-invite/export/save/imported review/notification-popup
  browser slices are focused regressions, static checkpoint markers are deletion/rename guards, and
  other lanes do not have broad coverage thresholds.
- Written-resolution evidence warnings, checklist/digest status, and seal-digest
  binding are operator-supplied evidence records only; they are not proof of
  written consent, quorum, vote threshold, participant identity, or legal
  acceptance.
- SBOMs, SBOM package linkage, checksums, package manifests, source provenance metadata,
  clean-source provenance gates, release-trust metadata validation, Docker signing-status metadata-anchor checks, and Docker OCI
  metadata are not
  substitutes for package signing, notarization, Docker signing, attestation, registry-publication
  verification, or reproducible-build proof; package artifact integrity checks and metadata guards
  are regression checks, not a release trust chain.
- Docker deployment profiles are operational configuration examples, not HA, managed production
  operations, image signing, or attestation.
- `/api/v1` API keys are an implemented integration feature, but a bearer key is still an
  attenuated RBAC principal, not an interactive user session or step-up credential.
