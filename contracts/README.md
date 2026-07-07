# `contracts/` — canonical wire fixtures

Each file here is one **canonical example** of a Chancela API wire shape: a real, parseable JSON
document with representative values (real enum encodings, ISO `YYYY-MM-DD` dates, RFC 3339
timestamps, 64-hex digests, UUID ids). They exist so a shape change breaks a test on **whichever
side moved**, asserted from both ends:

- **Server side** — the Rust E2E harness (`crates/chancela-server/tests/e2e_contracts.rs`, t15-e1)
  drives the real server binary over HTTP and asserts each **live** response *shape-matches* its
  fixture here (recursive key-set + JSON-type match over real wire bytes — not just serde). Drift
  in a handler/DTO (a renamed, added, removed, or retyped field) fails that test.
- **Client side** — a vitest suite (`apps/web/src/contracts/`, t15-e3) feeds each fixture through
  the real client `parseResponse`/DTO path (mocked `fetch` returning the fixture) and asserts it
  deserialises into the correct typed shape. Drift in the TS types fails that test.

The harness's matcher checks the **shape**, not exact scalar values (ids/timestamps/digests are
volatile); the journey tests in the same harness pin the load-bearing *values* (enum encodings,
counts, state transitions). Together they pin both shape and semantics.

## Inventory

| Fixture | Pins the wire shape of | Frozen § it derives from |
|---|---|---|
| `entity.json` | core `Entity` — `POST/GET /v1/entities` | t5 §2.3 |
| `book.json` | `BookView` (open book) — `POST/GET /v1/books` | t5 §2.4 |
| `act.sealed.json` | `ActView` (sealed ata) — `GET /v1/acts/{id}` | t5 §2.5 |
| `ledger.events.json` | `[LedgerEventView]` — `GET /v1/ledger/events` | t5 §2.6 |
| `dashboard.json` | `DashboardResponse` — `GET /v1/dashboard` | t5 §2.7 |
| `settings.json` | `Settings` — `GET/PUT /v1/settings` | t8 §2.8 (`t8-e1.md`) |
| `registry.extract.json` | `RegistryExtractView` — `GET /v1/entities/{id}/registry` | t11 §2.7 (`t11-e2.md`) + t14 §2.7 (`t14-e3.md`, role-tagged `cae`) |
| `cae.entry.json` | `CaeEntryView` (single-code, with hierarchy) — `GET /v1/cae/{code}` | t14 §2.7 (`t14-e3.md`) |
| `cae.catalog.json` | `CaeCatalogView` — `GET /v1/cae` (no-search metadata) | t14 §2.7/§2.8 (`t14-e3.md`) |
| `law.manifest.json` | `[LawEntryView]` — `GET /v1/law` (law archive manifest + store state) | t27 §law-v1 (`t27-e1.md`), spec/09 AI-20..22 |
| `user.json` | `UserView` — `POST/GET /v1/users` | t14 §2.8 (`t14-e3.md`) |
| `session.json` | `SessionView` (populated) — `GET /v1/session` | t14 §2.8 (`t14-e3.md`) |

## Enum encodings (bare variant names, pinned by the contract)

- `EntityKind`: `SociedadeAnonima`, `SociedadePorQuotas`, … · `EntityFamily`: `CommercialCompany`, …
- `BookKind`: `AssembleiaGeral`, … · `BookState`: `Open`, `Closed` · `ClosingReason`: `BookFull`, …
- `ActState`: `Draft`, `Review`, `Convened`, `Deliberated`, `TextApproved`, `Signing`, `Sealed`, … ·
  `MeetingChannel`: `Physical`, `Telematic`, `Hybrid`
- `NumberingScheme`: `Sequential`, `LooseLeaf` · `Locale`: `pt-PT`, `en-US` ·
  `ThemeMode`: `system`/`light`/`dark` (lowercase) · `SignatureFamily`: `CartaoCidadao`, …
- CAE `CaeLevel`: `Seccao`/`Divisao`/`Grupo`/`Classe`/`Subclasse` · `CaeRevision`: `Rev3`/`Rev4` ·
  `CaeOrigin`: `Embedded`/`Cache` · `CaeRole`: `Principal`/`Secundario`

## Security invariants the fixtures encode

- `RegistryProvenanceView.access_code_masked` is the **only** form of the código de acesso on the
  wire (`****-****-NNNN`); the full code appears in no fixture and in no live response.
- `UserView` / `SessionView` never carry `password_hash` (a reserved phase-2 field, server-side only).
