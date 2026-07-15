# `contracts/` — canonical wire fixtures

Each file here is one **canonical example** of a Chancela API wire shape: usually a real,
parseable JSON document with representative values (real enum encodings, ISO `YYYY-MM-DD` dates,
RFC 3339 timestamps, 64-hex digests, UUID ids), and occasionally a raw text export fixture for
non-JSON endpoints. They exist so a shape change breaks a test on **whichever side moved**,
asserted from both ends:

- **Server side** — the Rust E2E harness (`crates/chancela-server/tests/e2e_contracts.rs`, t15-e1)
  drives the real server binary over HTTP and asserts each **live** response _shape-matches_ its
  fixture here (recursive key-set + JSON-type match over real wire bytes — not just serde). Drift
  in a handler/DTO (a renamed, added, removed, or retyped field) fails that test.
- **Client side** — a vitest suite (`apps/web/src/contracts/`, t15-e3) feeds each fixture through
  the real client `parseResponse`/DTO path (mocked `fetch` returning the fixture) and asserts it
  deserialises into the correct typed shape. Drift in the TS types fails that test.

The harness's matcher checks the **shape**, not exact scalar values (ids/timestamps/digests are
volatile); the journey tests in the same harness pin the load-bearing _values_ (enum encodings,
counts, state transitions). Together they pin both shape and semantics.

## Inventory

| Fixture                                | Pins the wire shape of                                                                     | Frozen § it derives from                                           |
| -------------------------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| `entity.json`                          | core `Entity` — `POST/GET /v1/entities`                                                    | t5 §2.3                                                            |
| `book.json`                            | `BookView` (open book) — `POST/GET /v1/books`                                              | t5 §2.4                                                            |
| `act.sealed.json`                      | `ActView` (sealed ata) — `GET /v1/acts/{id}`                                               | t5 §2.5                                                            |
| `act.working-copy.md`                  | Markdown working-copy export — `GET /v1/acts/{id}/document/working-copy`                   | DOC-02 working-copy export                                         |
| `ledger.events.json`                   | `[LedgerEventView]` — `GET /v1/ledger/events`                                              | t5 §2.6                                                            |
| `dashboard.json`                       | `DashboardResponse` — `GET /v1/dashboard`                                                  | t5 §2.7                                                            |
| `dashboard.guest.json`                 | guest/minimal-redacted `DashboardResponse` — `GET /v1/dashboard` with empty recent events   | dashboard read-redaction                                           |
| `settings.json`                        | `Settings` — `GET/PUT /v1/settings`                                                        | t8 §2.8 (`t8-e1.md`)                                               |
| `platform.services.json`               | `PlatformServicesResponse` — `GET /v1/platform/services`                                   | platform service status/control                                    |
| `platform.control.json`                | `PlatformControlResponse` — `POST /v1/platform/services/{id}/actions/{action}`             | platform service desired-state control                             |
| `platform.logs.json`                   | `PlatformLogsResponse` — `GET /v1/platform/logs`                                           | API-owned structured platform log tail                             |
| `registry.extract.json`                | `RegistryExtractView` — `GET /v1/entities/{id}/registry`                                   | t11 §2.7 (`t11-e2.md`) + t14 §2.7 (`t14-e3.md`, role-tagged `cae`) |
| `cae.entry.json`                       | `CaeEntryView` (single-code, with hierarchy) — `GET /v1/cae/{code}`                        | t14 §2.7 (`t14-e3.md`)                                             |
| `cae.catalog.json`                     | `CaeCatalogView` — `GET /v1/cae` (no-search metadata)                                      | t14 §2.7/§2.8 (`t14-e3.md`)                                        |
| `tsl.catalog.json`                     | `TslCatalogView` — `GET /v1/trust/catalog` (offline TSL status/catalog)                    | spec/04 SIG-10..13                                                 |
| `tsa.status.json`                      | `TsaCatalogView` — `GET /v1/trust/tsa` (offline TSA diagnostics/catalog)                   | spec/04 SIG-22                                                     |
| `law.manifest.json`                    | `[LawEntryView]` — `GET /v1/law` (law archive manifest + store state)                      | t27 §law-v1 (`t27-e1.md`), spec/09 AI-20..22                       |
| `user.json`                            | `UserView` — `POST/GET /v1/users`                                                          | t14 §2.8 (`t14-e3.md`)                                             |
| `session.json`                         | `SessionView` (populated) — `GET /v1/session`                                              | t14 §2.8 (`t14-e3.md`)                                             |
| `session.password-policy.json`         | `PasswordPolicyView` — `GET /v1/session/password-policy`                                   | t68 password policy                                                |
| `privacy.processors.json`              | `[ProcessorRecordView]` — `GET /v1/privacy/processors`                                     | privacy/compliance registers                                       |
| `privacy.dpias.json`                   | `[DpiaRecordView]` — `GET /v1/privacy/dpias`                                               | privacy/compliance registers                                       |
| `privacy.dpia-template.json`           | `DpiaTemplateView` — `GET /v1/privacy/dpia-template`                                       | static local/offline DPIA guidance template                        |
| `privacy.breach-playbooks.json`        | `[BreachPlaybookView]` — `GET /v1/privacy/breach-playbooks`                                | privacy breach playbook evidence register                          |
| `privacy.transfer-controls.json`       | `[TransferControlView]` — `GET /v1/privacy/transfer-controls`                              | privacy transfer-control evidence register                         |
| `retention.policies.json`              | `[RetentionPolicyView]` — `GET /v1/privacy/retention-policies`                             | privacy retention policy register                                  |
| `retention.due-candidates.json`        | `RetentionDueCandidatesReport` — `GET /v1/privacy/retention-due-candidates`                | read-only retention due-candidate scan                             |
| `retention.candidate-resolutions.json` | `[RetentionCandidateResolutionRecord]` — `GET /v1/privacy/retention-candidate-resolutions` | evidence-only candidate disposition register                       |
| `retention.executions.json`            | `[RetentionExecutionRecord]` — `GET /v1/privacy/retention-executions`                      | retention execution evidence register                              |
| `paper-book.import.json`               | `PaperBookImportReport` — `POST /v1/books/paper-import/validate`                           | historical paper-book import validation                            |
| `templates.json`                       | `[TemplateSummary]` — `GET /v1/templates` merged built-in + user-authored catalog          | wp23 user-template management                                      |
| `template.summary.json`                | `TemplateSummary` — `POST/PUT /v1/templates[/{id}]` user-authored template response        | wp23 user-template management                                      |
| `template.import-verdict.json`         | `TemplateImportVerdict` — `POST /v1/templates/import?dry_run=true`                         | wp23 user-template management                                      |
| `template.export.json`                 | Authored template JSON — `GET /v1/templates/{id}/export`                                   | wp23 user-template management                                      |
| `api-key.list.json`                    | `[ApiKeyView]` — `GET /v1/api-keys`                                                        | integration API-key lifecycle                                      |
| `api-key.create.json`                  | `ApiKeyCreated` — `POST /v1/api-keys` one-time secret response                             | integration API-key lifecycle                                      |
| `api-key.revoke.json`                  | `ApiKeyView` — `DELETE /v1/api-keys/{id}` metadata-only response                           | integration API-key lifecycle                                      |
| `api-key.rotate.json`                  | `ApiKeyCreated` — `POST /v1/api-keys/{id}/rotate` one-time replacement secret response     | integration API-key lifecycle                                      |
| `sync.handoff-preflight.json`          | `SyncHandoffPreflightReport` — `GET /v1/sync/handoff-preflight` local evidence report      | local sync/handoff preflight readiness, no active sync/connector   |

## Enum encodings (bare variant names, pinned by the contract)

- `EntityKind`: `SociedadeAnonima`, `SociedadePorQuotas`, … · `EntityFamily`: `CommercialCompany`, …
- `BookKind`: `AssembleiaGeral`, … · `BookState`: `Open`, `Closed` · `ClosingReason`: `BookFull`, …
- `ActState`: `Draft`, `Review`, `Convened`, `Deliberated`, `TextApproved`, `Signing`, `Sealed`, … ·
  `MeetingChannel`: `Physical`, `Telematic`, `Hybrid`
- `NumberingScheme`: `Sequential`, `LooseLeaf` · `Locale`: `pt-PT`, `en-US` ·
  `ThemeMode`: `system`/`light`/`dark` (lowercase) · `SignatureFamily`: `CartaoCidadao`, …
- CAE `CaeLevel`: `Seccao`/`Divisao`/`Grupo`/`Classe`/`Subclasse` · `CaeRevision`: `Rev3`/`Rev4` ·
  `CaeOrigin`: `Embedded`/`Cache` · `CaeRole`: `Principal`/`Secundario`
- TSL trust catalog: `TslSourceKind` `Cache`/`Fixture` · `TslSignatureStatus` `Valid`/`Invalid` ·
  `TslServiceStatusKind` `Granted`/`Withdrawn`/`Other`
- TSA diagnostics: `TsaStatusKind` `Ready`/`Unconfigured`/`Error` · `TsaProbeKind` `Fixture` ·
  `TsaProbeStatus` `Passed`/`Failed`

## Security invariants the fixtures encode

- `RegistryProvenanceView.access_code_masked` is the **only** form of the código de acesso on the
  wire (`****-****-NNNN`); the full code appears in no fixture and in no live response.
- `UserView` / `SessionView` never carry `password_hash` (a reserved phase-2 field, server-side only).
- API-key list/revoke responses carry metadata only; create/rotate fixtures are the only API-key
  fixtures with one-time plaintext examples, and no fixture carries `key_hash`.
