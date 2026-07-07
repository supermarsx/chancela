# Chancela — Spec Coverage

*Consolidated from six independent, source-verified coverage audits (auditors t28-a1…a6,
2026-07-07), each of which read the actual implementation at `main` (6af18ea) file-by-line
rather than trusting doc comments. This document merges their findings into one committable
map of where the product stands against `spec/01`…`spec/11`, and a ranked program for the
next epoch.*

Status vocabulary (normalized across the six audits):
**IMPLEMENTED** (landed & verifiable) · **PARTIAL** (seam or subset landed, core requirement
unmet) · **STUB** (explicit phase-2 stub in code/docs) · **MISSING** (no implementation) ·
**N/A-v1** (deliberately deferred, with citation).

---

## 1. Executive summary

Across the eleven spec documents there are **164 numbered requirements**. Verified status:

| Status | Count | Share |
|---|---:|---:|
| IMPLEMENTED | 35 | 21% |
| PARTIAL | 56 | 34% |
| STUB | 4 | 2% |
| MISSING | 65 | 40% |
| N/A-v1 | 4 | 2% |
| **Total** | **164** | 100% |

(The SCP-D1…D6 architecture-default decision table is tracked separately in §2 and is not
part of the 164.)

**One-sentence verdict per spec document:**

- **spec/01 Product Scope (SCP):** the three run-modes and the single reused Rust core are real
  and honest about legal-evidence-not-validity; the act lifecycle exists but its signing/export
  tails are unwired, and the default embedded encrypted store (SCP-D1) was not adopted.
- **spec/02 Legal & Compliance (LEG):** the compliance-gate mechanics (rule-pack trait, blocking
  vs advisory seal gate, recorded overrides) are correct and well-tested, but GDPR-by-design
  (LEG-10..13) is essentially unimplemented and only one commercial rule pack exists.
- **spec/03 Entity Profiles (ENT):** all five families and their types are modeled as enums, but
  the *profile* abstraction the whole spec rests on (ENT-02/03) does not exist — one CSC rule pack
  is applied to every family, so four of five families have a legally wrong compliance gate.
- **spec/04 Signatures & Trust (SIG):** a complete, well-factored signing library with correct
  evidentiary labeling exists — and sits **entirely outside the product**; no production crate
  depends on `chancela-signing`, so sealing an act produces no signature, timestamp, or report.
- **spec/05 Data Model & Roles (DAT/ROL):** the lower data tree (entity→book→act) and the
  append-only hash-chained ledger are real and tamper-tested; tenancy/groups, per-scope chain
  fan-out, and the *entire* RBAC/delegation layer (ROL) are absent — the code is candidly
  "attribution, not access control".
- **spec/06 Workflows (WFL):** the book/act lifecycle, sealing with a compliance gate, and the
  retificação chain are genuinely done; templates, real signature collection, reminders/legal
  calendar, historical paper-book import, and a configurable dashboard are missing.
- **spec/07 Architecture (ARC):** a well-built *stateless scaffold*, not a *system of record* —
  the compute plane (core + Axum + Tauri) is real and reused, but the **entire data plane lives
  in memory and is destroyed on every restart**; sync, backup, and ZK encryption are absent.
- **spec/08 Documents & Archive (DOC):** a compliance/crypto substrate exists, but there is **no
  document layer** — nothing renders a PDF from an ata, export packaging is a `NotImplemented`
  stub, and the chronology/provenance graph is unbuilt.
- **spec/09 AI & MCP (AI):** the AI feature layer and MCP server are absent; the one strong
  surface is the read-only registry certidão import (AI-30/31).
- **spec/10 UX & Design (UX):** theme, accessibility posture, and legal-warning copy are real and
  good; localization is enum-only (no i18n runtime), fonts are system stacks not bundled, and
  mobile does not exist.
- **spec/11 Template Catalog (TPL):** ~0% built — there is no template concept in the code; a
  single free-text ata editor stands in for the entire five-family × five-stage catalog.

**The honest headline.** The **integrity spine is real and tested**: the book/act lifecycle, the
seal with its blocking/advisory compliance gate and recorded-override path, the append-only
hash-chained ledger with genuine tamper detection, differentiated signatory capacities, and a
faithful CSC art. 63.º rule pack — all riding one shared Rust core across desktop, server, and
browser exactly as the architecture demands. Nothing is faked and the phase order is respected.
But four large layers are the next epoch: a **system-of-record persistence layer** (today every
entity, book, sealed ata, and the ledger itself evaporate on restart), **templates and document
generation** (no PDF is ever produced from an ata), the **signing wire** (a complete crypto stack
built but unplugged), and **per-family legal packs** (one CSC pack incorrectly gates condominiums,
associations, foundations, and cooperatives). The product today can author and seal a compliant
single-tenant ata — it cannot yet survive a reboot, template a document, enforce a role, or
collect a real signature.

---

## 2. Coverage matrix

Every numbered requirement, its verified status, the load-bearing evidence the auditors opened,
and the gap + effort (S ≤1d · M few days · L week+/new subsystem).

### spec/01 — Product Scope (SCP)

| ID | Title | Status | Evidence | Gap / effort |
|---|---|---|---|---|
| SCP-01 | Full act lifecycle | PARTIAL | `act.rs:52` `ActState` Draft→…→Sealed→Archived; `acts.rs` drives it | Signing is a state flag, export stubbed, register/report absent. **M–L** |
| SCP-02 | Five families first-class | PARTIAL | `entity.rs:193` `EntityFamily`, `:213` `EntityKind` | Only CSC has a rule pack; no profiles/templates for the other four. **L** |
| SCP-03 | One Rust core + rule packs | IMPLEMENTED | `chancela-core` leaf crate reused by desktop `lib.rs:237` + server | — |
| SCP-10 | Three run-modes | IMPLEMENTED | Tauri embedded server; `docker/`; `apps/web` | Caveat: domain state in-memory (SCP-D1) |
| SCP-11 | Online = packaging change | IMPLEMENTED | `desktop/src-tauri/src/lib.rs:11-19,237` embeds Axum in-process | — |
| SCP-20 | Single MIT codebase, edition flags | IMPLEMENTED | Single Cargo workspace; `license.md` MIT; `embedded-server` feature | Edition flags coarse (one feature) |
| SCP-21 | Mobile Companion subset | N/A-v1 | Mobile icons only; no build (SCP-D5) | **L** when scheduled |
| SCP-30 | Phase order (CSC first) | PARTIAL | Phase 1 in progress; QES crates not wired; chronology/archive incomplete | Phase-1 tail unfinished. **L** |
| SCP-40 | No validity claim; produce evidence | IMPLEMENTED | Evidence-first hash-chained ledger; no validity copy | Honored by construction |
| SCP-41 | No registry filings in v1 | IMPLEMENTED | `chancela-registry` reads certidão only; no filing endpoint | — |

**SCP-D1…D6 architecture defaults** — D1 embedded encrypted append-only store: **NOT ADOPTED**
(state is `Arc<RwLock<HashMap>>`, only settings/users persist as plain JSON) · D2 native
validation + optional DSS sidecar: **PARTIAL** (native crates present, no sidecar, not wired) ·
D3 repo-level ZK: **N/A-v1** · D4 OCR off by default: **N/A-v1** · D5 mobile review/sign first:
**N/A-v1** · D6 trust from TSL + admin purchase catalog: **PARTIAL** (TSL default present, no
purchase-URL catalog).

### spec/02 — Legal & Compliance (LEG)

| ID | Title | Status | Evidence | Gap / effort |
|---|---|---|---|---|
| LEG-01 | Compliance engine gates finalize | IMPLEMENTED | `rules.rs:58-64` trait; `seal.rs:147-157` blocks on Error | — |
| LEG-02 | Versioned rule packs per family | PARTIAL | `rules.rs:78` `"csc-art63/v1"`; wired unconditionally `acts.rs:220` | No per-family dispatch. **M–L** |
| LEG-03 | CSC art.63 min field list | PARTIAL | `rules.rs:86-146` checks ~5 of ~11 elements | Missing mesa/agenda/votes/statements; `Act` lacks fields. **M–L** |
| LEG-04 | Telematic + art.377 evidence | PARTIAL | `act.rs:40-49` channel; single free-text `telematic_evidence` | Not the three art.377 sub-elements; SA-only check. **M** |
| LEG-05 | Blocking vs advisory + recorded override | IMPLEMENTED | `rules.rs:16-22` `Severity`; `seal.rs:149-157,181` acknowledged warnings | — |
| LEG-06 | Rule-pack version in sealed metadata | IMPLEMENTED (coarse) | `seal.rs:169` embeds `rule_pack.id()` in justification | Substring not structured field. **S** to harden |
| LEG-10 | GDPR by design (10 sub-items) | PARTIAL | Only legal-hold/retention scaffolded in stub `chancela-archive` | 8 of 10 sub-items absent. **L** |
| LEG-11 | DPIA template ships | MISSING | Not found | **S–M** (doc) |
| LEG-12 | Security of processing (art.32) | MISSING | No encryption-at-rest / incident tooling | **L** |
| LEG-13 | ZK ≠ removes GDPR duties (doc) | MISSING | Not present | **S** (doc) |
| LEG-20 | Import certidão by access code | IMPLEMENTED (core) | Full pipeline `chancela-registry` code/transport/parse/model | Associated docs not imported (HTML only). **M** |
| LEG-21 | Foundations via equivalent service | PARTIAL | `model.rs:18` `Fundacao`; reuses commercial transport | No distinct foundation service path. **S–M** |
| LEG-22 | Provenance stored + feeds chronology | PARTIAL | `model.rs:76-94` `RegistryProvenance` complete | Chronology-graph feed not built (DOC-30..32). **M** |

### spec/03 — Entity Profiles (ENT)

| ID | Title | Status | Evidence | Gap / effort |
|---|---|---|---|---|
| ENT-01 | Families & types offered | IMPLEMENTED | `entity.rs:192-236` 5 families + 10 kinds | — |
| ENT-02 | Profile binds contents/channels/sig/template/calendar/registry | MISSING | No `Profile` object; only enum + one pack | Central abstraction absent. **L** |
| ENT-03 | Statute overlay (quorum/majorities/convocation) | MISSING | Only doc-comment aspiration `entity.rs:210` | Blocks assoc & coops. **L** |
| ENT-C1 | Six selectable CSC types | IMPLEMENTED | `entity.rs:214-226` | — |
| ENT-C2 | CSC art.63 enforced pre-seal | PARTIAL | Pack + seal gate | Inherits LEG-03 depth gap. **M–L** |
| ENT-C3 | SA per-GM ata + art.376 preset | MISSING | Nothing enforces per-GM; no calendar preset | **M** |
| ENT-C4 | Telematic GM w/ art.377 evidence | PARTIAL | `rules.rs:149-164` SA+telematic note | Single-string evidence. **M** |
| ENT-C5 | Written-resolution channel + template/evidence | PARTIAL | `act.rs:47-48` variant exists | Pack ignores it; no template/rules. **M** |
| ENT-C6 | Loose-leaf anti-falsification; docs = proof | PARTIAL | Hash-chain gives sequencing; `book.rs:65-72` declared | Page mechanics + proof label unbuilt. **M** |
| ENT-C7 | Groups: shared templates + cross-entity dashboards | MISSING | No group/holding concept | **M–L** |
| ENT-D1 | Dedicated condominium profile | MISSING | `Condominio` enum only | No profile/pack/templates. **L** |
| ENT-D2 | Condo pack: vote-result summary | MISSING | Falls through to CSC pack | **M** |
| ENT-D3 | Condo signature policy (QES/handwritten) | MISSING | Signing primitives exist, not bound | **M** |
| ENT-D4 | Email agreement declarations as annexes | MISSING | No email-declaration attachment kind | **M** |
| ENT-D5 | Remote/hybrid assemblies w/ evidence | PARTIAL | `Hybrid`/`Telematic` exist | No condo participation evidence. **M** |
| ENT-D6 | Signatory roles + fraction/permilage weighting | PARTIAL | `SignatoryCapacity` roles present | No fraction/permilage, no vote weighting. **M** |
| ENT-A1 | Associação + statute subtypes | PARTIAL | `Associacao` `entity.rs:231` | Subtypes need statute layer. **M** |
| ENT-A2 | Mandatory contents from CC + statutes | MISSING | No association rule pack | **M** |
| ENT-A3 | Association templates (GA/direção/…) | MISSING | No templates | **M–L** |
| ENT-F1 | Fundação board + supervisory minutes | PARTIAL | `Fundacao` `entity.rs:233` | No board/minute model or pack. **M** |
| ENT-F2 | Registry via foundation certificate | PARTIAL | Inherits LEG-21 | **S–M** |
| ENT-K1 | Cooperativa distinct type + minutes | PARTIAL | `Cooperativa` `entity.rs:235` | No pack/minute model. **M** |
| ENT-K2 | Cooperative voting (1-member-1-vote) | MISSING | Needs statute layer + voting model | **M** |

### spec/04 — Signatures & Trust (SIG)

| ID | Title | Status | Evidence | Gap / effort |
|---|---|---|---|---|
| SIG-01 | Four signing families, correct labeling | PARTIAL | `signing/lib.rs:57,144`; real smartcard/CMD/manual providers | No soft-cert (PKCS#12) provider; nothing wired to seal. **M**/**L** |
| SIG-02 | OTP never a qualified signature | IMPLEMENTED | `lib.rs:156,162`; tests | Enforced by construction |
| SIG-03 | Prominent manual-signature warning | IMPLEMENTED | `lib.rs:168`; UI `AtaEditorPage.tsx:491-497` | — |
| SIG-04 | Professional/representative attrs via SCAP | MISSING | No SCAP anywhere; capacity is free-text label | **L** |
| SIG-10 | Registry driven by GNS TSL / EU LOTL | IMPLEMENTED | `chancela-tsl` source/parse/query, fixture-tested | — |
| SIG-11 | Ingest signed TSL, validate its signature, cache | STUB | Cache/status done; `validate_tsl_signature` → `NotImplemented` | XML-DSig verify unbuilt → gate not prod-safe. **M** |
| SIG-12 | Discovery / policy-config / buy-certificate | MISSING | Only a bare `tsl_url` field; no catalog | **L** |
| SIG-13 | PT TSL entries resolved at runtime | IMPLEMENTED | Structural resolution from parsed list | — |
| SIG-14 | Default endpoints pre-configured, admin-editable | IMPLEMENTED | `settings.rs:145,152`; UI settings; no phone-home | — |
| SIG-20 | PAdES / XAdES / CAdES / ASiC | PARTIAL | PAdES + detached CAdES real; XAdES/ASiC vocabulary stubs | Two format subsystems unbuilt. **L** |
| SIG-21 | Baseline B-B/B-T/B-LT/B-LTA (LTA default) | PARTIAL | B-B/B-T built; LT/LTA not | Archival default aspirational. **L** |
| SIG-22 | Seal checkpoints w/ qualified timestamp | PARTIAL | `chancela-tsa` complete + in pipeline | Seal flow never calls it. **M** |
| SIG-23 | Validation cross-checks TSL; native or DSS | STUB | Native validator exists; DSS sidecar phase-2 seam | Depends on SIG-11. **L**/**M** |
| SIG-24 | Every sealed act embeds a validation report | PARTIAL | `validate.rs:17,42` generator exists | No sealed act embeds one — dead code. **M** |
| SIG-30 | External signers by secure link | MISSING | No invite/secure-link surface | **L** |
| SIG-31 | Serial AND parallel signing orders | PARTIAL | `lib.rs:175` engine supports both | Envelope not persisted/wired to acts. **M** |

### spec/05 — Data Model (DAT)

| ID | Title | Status | Evidence | Gap / effort |
|---|---|---|---|---|
| DAT-01 | Hierarchical tenancy-aware model | PARTIAL | Entity→Book→Act built; envelope/ledger/archive types | Platform + Tenant layers absent. **L** |
| DAT-02 | User↔companies; entity↔books; act↔artifacts | PARTIAL | Multiple books/entity; act→attachments | User↔company membership + groups absent. **M–L** |
| DAT-03 | Groups: shared libraries + cross-entity dashboards | MISSING | No group type; single global dashboard | **L** |
| DAT-04 | Books carry lifecycle + termos; sealed abertura = genesis | IMPLEMENTED | `book.rs:52,80,110`; `seal.rs:92` genesis | — |
| DAT-05 | Registry data distinct-but-linked w/ provenance | PARTIAL | `registry/model.rs:97,77` rich extract + provenance | Statutes/associated docs not separate linked records. **M** |
| DAT-10 | Every mutation → ledger event | IMPLEMENTED | `ledger/lib.rs:78`; every API mutation appends | — |
| DAT-11 | Hash chains per company, per book, globally | PARTIAL | One global chain w/ tamper detection `lib.rs:260` | Per-scope fan-out not materialized. **M** |
| DAT-12 | Sealed acts append-only; corrections = new acts | IMPLEMENTED | `act.rs:195,270`; `acts.rs:82` rejects PATCH; retifies | — |

### spec/05 — Roles / Access Control (ROL)

| ID | Title | Status | Evidence | Gap / effort |
|---|---|---|---|---|
| ROL-01 | RBAC + attribute constraints | MISSING | `users.rs:1-13` "attribution, not access control" | No RBAC engine. **L** |
| ROL-02 | 11 default roles | MISSING | No `Role` enum | **M** enum / **L** enforcement |
| ROL-03 | Permission scopes | MISSING | None | Depends on ROL-01. **L** |
| ROL-04 | Differentiated signatory capacities | IMPLEMENTED | `act.rs:104,124` exactly the 7 capacities | The one ROL req met (it's evidence) |
| ROL-05 | Guests subject to field-level redaction | MISSING | No guest role, no redaction | **M** |
| ROL-10 | Delegation first-class | MISSING | No delegation type | **L** |
| ROL-11 | Delegation records basis/scope/dates + in trail | MISSING | Same as ROL-10 | **L** |

### spec/06 — Workflows (WFL)

| ID | Title | Status | Evidence | Gap / effort |
|---|---|---|---|---|
| WFL-01 | Main lifecycle draft→…→archive→register/report | PARTIAL | `act.rs:52` + `advance_act` through Sealed→Archived | Sign=flag; sync/export/register absent. **M–L** |
| WFL-02 | Templates/attach/collect signatures/channels/warnings | PARTIAL | Attachments, capacities, channel, warnings present | Templates, real collection, external links MISSING. **L** |
| WFL-10 | Book lifecycle via termos, sealed | IMPLEMENTED | `book.rs:147`; `seal.rs:92`; tests | — |
| WFL-11 | Termo de abertura + genesis of chain | IMPLEMENTED | `book.rs:80`; `seal.rs:108` genesis | — |
| WFL-12 | Sequential ata number; loose-leaf paging | PARTIAL | `book.rs:198` numbering at seal | Loose-leaf paging STUB. **M** |
| WFL-13 | Termo de encerramento; closed read-only; successor | IMPLEMENTED | `book.rs:110,186,163`; `books.rs:50` | — |
| WFL-14 | No ata outside open book; multiple books/organ | IMPLEMENTED | `acts.rs:36` rejects; `book.rs:41 BookKind` | — |
| WFL-15 | Historical paper-book import (digitization) | MISSING | No import workflow | Real onboarding gap. **L** |
| WFL-20 | Seal an ata; append-only frozen set | IMPLEMENTED | `seal.rs:121` freezes; payload digest in ledger | Validation report not yet in set |
| WFL-21 | Correction = new act (retificação chain) | IMPLEMENTED | `act.rs:168`; `acts.rs:47` | — |
| WFL-22 | Seal records rule-pack versions + report + timestamp | PARTIAL | Rule-pack id recorded `seal.rs:169` | Report + qualified timestamp not recorded. **M** |
| WFL-23 | Manual-sign SIG-03 warning + original-ref metadata | MISSING | No seal-time warning; no original-ref field | **M** |
| WFL-30 | Full Portuguese template catalog (spec 11) | MISSING | No template engine anywhere | Largest feature gap. **L** |
| WFL-31 | Compliance from law/statutes, never template | IMPLEMENTED | `rules.rs` computes from act+entity | Architecturally honored |
| WFL-32 | Template libraries shareable + versioned | MISSING | No templates | Depends on WFL-30 + DAT-03. **L** |
| WFL-33 | Documents chained across act lifecycle | PARTIAL | Attachments + retificação link | No certidão/registry-package chaining. **M** |
| WFL-40 | Configurable dashboard, eleven feeds | PARTIAL | `dashboard.rs` ~2 of 11 feeds, not configurable | **M–L** |
| WFL-41 | Reminders engine (event + calendar) | MISSING | No engine | **L** |
| WFL-42 | Legal-calendar presets (art.376) | MISSING | No presets | Depends on WFL-41. **M** |

### spec/07 — Architecture (ARC)

| ID | Title | Status | Evidence | Gap / effort |
|---|---|---|---|---|
| ARC-01 | Single Rust domain core | IMPLEMENTED | `chancela-core` sole domain crate, reused | Diffing/templates thin |
| ARC-02 | Thin API (transport/authn/authz/streaming) | PARTIAL | Axum thin; but authn/authz attribution-only, no streaming | **M–L** |
| ARC-03 | Offline runs real in-process server | IMPLEMENTED | `desktop/lib.rs:99-132` ephemeral loopback | — |
| ARC-04 | Tauri v2 one codebase incl. mobile | PARTIAL | Desktop real; mobile scaffold only | **L** |
| ARC-10 | Local-first with selective sync | MISSING | In-memory; no local store, no sync | Biggest gap. **L** |
| ARC-11 | Append-only event sourcing as canonical | PARTIAL | Ledger exists but canonical state is mutable maps, volatile | **L** |
| ARC-12 | Event envelope + per-scope + global chains | PARTIAL | Envelope correct, `verify()` detects tamper; single global Vec | Fan-out + durability missing. **M** |
| ARC-13 | Finalization checkpoint w/ qualified timestamp | MISSING | `chancela-tsa` built, not depended on; local clock only | **M** once persistence lands |
| ARC-14 | Embedded relational store, encrypted pages, event tables | MISSING | None; 3 plaintext JSON side-files | Top data-loss risk. **L** |
| ARC-20 | Sync AND backup as separate configurable targets | MISSING | Neither exists | LEG-12 unsatisfiable. **L** |
| ARC-21 | Storage connectors (Graph/Drive/WebDAV/SMB/…) | MISSING | Zero connectors | **L** |
| ARC-30 | Zero-knowledge encryption (opt-in) | MISSING | No ZK mode | **L** |
| ARC-31 | BYOK / hardware unseal / split-key recovery | MISSING | Smartcard signs, doesn't unseal | **L** |
| ARC-32 | Legal-archive readability mode | MISSING | No ZK material bundle | **L** |
| ARC-33 | LEG-13 ZK caveat in UI/docs | MISSING | Absent (moot until ZK) | **S** |
| ARC-40 | Publish app + worker + optional sidecar images | PARTIAL | App image CI-built; worker/sidecar missing; nothing pushed | **M** |
| ARC-41 | Runtime hardening + supply-chain (sign/SBOM/scan) | PARTIAL | Runtime hardening strong; no cosign/syft/trivy | **M** |
| ARC-42 | Single-node + HA + Enterprise profiles | PARTIAL | Single-node compose only | **M–L** |

### spec/08 — Documents & Archive (DOC)

| ID | Title | Status | Evidence | Gap / effort |
|---|---|---|---|---|
| DOC-01 | Evidence PDF / PAdES / PDF-A | PARTIAL | PAdES-B-B/B-T of existing PDF; no PDF generated, no PDF/A | **L** |
| DOC-02 | Working exports (DOCX/ODT/RTF/HTML/TXT/MD) | MISSING | No conversion pipeline | **M–L** |
| DOC-03 | Sealed act preserves signed PDF+report+manifest+source | PARTIAL | Metadata/refs/digest in ledger; no signed PDF/report bundle | Rides on signing wire. **M** |
| DOC-10 | Import office/PDF/image/ZIP/XML/CSV/email | MISSING | Only registry HTML import; attachments are label+digest | **M–L** |
| DOC-11 | Validate signed PDFs/envelopes on import | PARTIAL | Validators exist at crate level, not wired to import | **M** |
| DOC-12 | OCR / content extraction | MISSING | None (SCP-D4 off by default) | N/A-v1-adjacent. **L** |
| DOC-20 | Export package (ingestible, checksums) | STUB | `build_package` → `NotImplemented`; shapes only | **M–L** |
| DOC-21 | DGLAB preservation/migration | STUB | `PreservationLevel` enum only | **M** |
| DOC-22 | Retention / legal hold at package level | PARTIAL | `is_disposable()` honors legal_hold in stub | No real package. **M** |
| DOC-30 | Registry content → normalized event timeline | PARTIAL | Inscriptions parsed to structured payloads; not normalized | **M** |
| DOC-31 | Mermaid diagrams | MISSING | None | **M** |
| DOC-32 | Explainable provenance graph | MISSING | Provenance data exists; no graph | **M–L** |

### spec/09 — AI & MCP (AI)

| ID | Title | Status | Evidence | Gap / effort |
|---|---|---|---|---|
| AI-01 | AI features (draft/extract/compare/summarize/multilingual) | MISSING | No AI anywhere | Phase-2. **L** |
| AI-02 | Provenance panels (law/cert/registry/records/AI) | MISSING | No AI drafts to annotate | **M** |
| AI-03 | Human verification checkpoint before signing | MISSING | No AI-generated acts | **M** |
| AI-04 | AI disableable per tenant | MISSING | No AI, no toggle | **S** once AI exists |
| AI-10 | MCP server | MISSING | No `chancela-mcp` crate | **M** shell |
| AI-11 | Read-only / write-controlled split honoring ROL | MISSING | No MCP + no ROL scope model | Blocked on ROL. **M–L** |
| AI-12 | MCP auth as API Client role + audit ledger | MISSING | No API-Client role; ledger half exists | **M** |
| AI-20 | Ingest DR + EUR-Lex into search index | MISSING | No ingestion/index; t24 shipped curated static seed | **L** |
| AI-21 | Law shelf: search/filters/pins/citation insertion | MISSING | t24 delivers curated extracts + links, no search/insert | **L** |
| AI-22 | Rule packs link findings to law-shelf entries | MISSING | `rule_id` + message string; no shelf link | **M** |
| AI-30 | Certidão import feeds chronology + prefills onboarding | PARTIAL | Prefill DONE & strong; chronology GRAPH missing (DOC-30) | **M** |
| AI-31 | Registry imports read-only in v1 | IMPLEMENTED | `registry/lib.rs` "consult, never file" | — |

### spec/10 — UX & Design (UX)

| ID | Title | Status | Evidence | Gap / effort |
|---|---|---|---|---|
| UX-01 | Dark-green editorial theme, light+dark | IMPLEMENTED | `theme.css` token system, full light+dark | — |
| UX-02 | Theme on a11y-aware system, not a skin | PARTIAL | CSS-custom-property token layer, self-described placeholder | **M** |
| UX-03 | Bundled open-licensed fonts, no runtime fetch | PARTIAL | No runtime fetch ✓; but system stacks, not bundled | Bundling unmet. **S–M** |
| UX-04 | Conservative doc typography, theme-independent | PARTIAL | Print CSS forces serif/black-on-white | No PDF/A system yet. **M** |
| UX-10 | Accessibility-aware | IMPLEMENTED | `:focus-visible`, aria roles, reduced-motion | Minor: no skip-link |
| UX-11 | PDF/UA-aligned accessible delivery | N/A-v1 | No document generation yet | Pending DOC |
| UX-20 | 14 BCP-47 locales, localizable chrome | PARTIAL | 14-locale enum + selector; no i18n runtime (chrome hardcoded PT) | Queued t19-e3a/b/c. **M–L** |
| UX-21 | Legal terms not machine-localized; PT-PT authoritative | PARTIAL | No translations/templates → no risk yet | Pending i18n+templates |
| UX-30 | Mobile: review/approval/signing/triage/lookup | MISSING | No Tauri mobile targets | **L** |
| UX-31 | Mobile drafting limited; archive desktop-only | N/A-v1 | No mobile build | Moot for v1 |
| UX-40 | Signature-type labeling per SIG-02 | IMPLEMENTED | `signatureFamilyLabels` clean; no OTP conflation | — |
| UX-41 | Manual-signature SIG-03 warning | IMPLEMENTED | `AtaEditorPage.tsx:492` InlineWarning | — |
| UX-42 | Working-copy exports labeled per DOC-02 | N/A-v1 | No export generation | Pending doc generation |
| UX-43 | Findings cite legal basis + link to law shelf | PARTIAL | Legal basis in plain language ✓; no shelf link | Blocked on AI-21/22. **M** |

### spec/11 — Template Catalog (TPL)

| ID | Title | Status | Evidence | Gap / effort |
|---|---|---|---|---|
| TPL-01 | Templates by stage + family | MISSING | No template concept | **L** |
| TPL-02 | Document chaining (convocatória→…→certidão) | MISSING | Ledger chains sealed acts only | **L** |
| TPL-03 | Typed fields bound to model, generated from records | MISSING | Ata free-typed | **L** |
| TPL-04 | Template declares signature policy + compliance gate | MISSING | Pack exists for acts, not template-bound | **M** |
| TPL-10 | Termo abertura/encerramento per family/organ | PARTIAL (data only) | `TermoDeAbertura` sealed data object; no rendering | **M** |
| TPL-11 | Termos follow seal-and-chain | PARTIAL | Book genesis seals; no termo documents | **M** |
| TPL-20 | Convocatória deadlines + proof of dispatch | MISSING | — | **M** |
| TPL-30 | Act template bound to family rule pack | MISSING | One generic CSC pack | **M** |
| TPL-31 | Market parity (atas.pt / mibfer.pt union) | MISSING | Zero act templates | **L** |
| TPL-40 | Certidão / extrato from sealed acts, signable | MISSING | No certidão generation | **M–L** |
| TPL-41 | Condominium absent-owner communication | MISSING | — | **M** |
| TPL-50 | Coverage matrix (5 families × ~6 stages) | MISSING | ~30 cells effectively empty | **L** |

---

## 3. Ranked implementation backlog

One deduplicated program, ranked by **data-loss risk > legal correctness > core product value >
breadth**, clustered into waves. Each item lists effort, dependencies, and the spec IDs it closes.

**Already in flight or queued** (from `.orchestration/state.md`, so the backlog does not
double-count): **t19-e2** (UI theming/skeleton loaders/icons — queued), **t19-e3a/e3b/e3c** (i18n
runtime + translations — queued; the UX-20/21 work) · **t21-e3** (structured-inscription web
surface — queued; feeds AI-30/DOC-30 data, not the graph) · **t23** (in-app CAE obtainer engine —
in flight; tooling, not a numbered spec req) · **t24** (Legislação law shelf — ✅ done; a curated
static seed of AI-20/21, *not* the search index) · **t25-web** (NIPC override tickbox — queued) ·
**t26** (crash handling + safe mode — queued; resilience, not a numbered spec req). No t27/t29
exist yet. None of these deliver a *Wave A–D* item; Wave E localization/law-shelf overlaps t19-e3
and t24 as noted.

### Wave A — Foundation: durable system of record

The single load-bearing gap: today a restart destroys every entity, book, sealed ata, and the
ledger itself. Everything else in the product stands on closing this.

- **A1. Embedded durable store for entity/book/act/ledger.** Persist the domain state and the
  hash chain behind the existing `AppState::with_data_dir` / `from_env` seam (the JSON-file seam
  is already there; the `chancela-data` volume + `CHANCELA_DATA_DIR` env are plumbed and waiting).
  All core types already derive serde with round-trip tests. — **L** · depends: nothing · closes
  **ARC-10, ARC-11, ARC-14, SCP-D1**.
- **A2. Persist per-scope hash chains.** Materialize per-company and per-book chains alongside the
  global one (the crate docs already say this fan-out is "layered on by callers" — build that
  caller). — **M** · depends: A1 · closes **DAT-11, ARC-12**.
- **A3. At-rest encryption for the store.** Encrypted pages so durable corporate records are not
  written plaintext to disk/cloud (design this *with* A1, not after). — **M–L** · depends: A1 ·
  closes the encryption half of **ARC-14**; groundwork for **ARC-30/31**.
- **A4. Backup/restore escape hatch.** Minimum export-to-target + restore path — the manual
  survival hatch for the store and the CNPD/EDPB restoration obligation. — **M** · depends: A1 ·
  closes **ARC-20** (backup half), **LEG-12** (restore capability); groundwork for **ARC-21**.

### Wave B — Legal correctness

Make the compliance gate right for all five families and deepen the flagship pack.

- **B1. Per-family rule-pack dispatch.** Route each entity family to its own pack instead of
  wiring `CscArt63RulePack` unconditionally (`acts.rs:220`) — today four of five families have a
  legally wrong gate. — **M** · depends: nothing · closes **LEG-02**; enables B2/B4.
- **B2. Complete the CSC art.63 pack + act model fields.** Add `Act` fields and checks for the
  mesa (president/secretaries), agenda (ordem de trabalhos), submitted-document references,
  structured voting results, member statements, and meeting *time* — the pack checks ~5 of ~11
  today. — **M–L** · depends: nothing (parallel to B1) · closes **LEG-03, ENT-C2**; deepens WFL-20.
- **B3. Condominium pack + profile (ENT-D).** Vote-result summary with fraction/permilage
  weighting, email-agreement annexes, condo signature policy — a named target market (DL 268/94)
  with only enum names today. — **M–L** · depends: B1 · closes **ENT-D1/D2/D4/D6** (D3/D5 partial).
- **B4. Statute-overlay layer (ENT-03) + profile binding (ENT-02).** The abstraction all of
  spec 03 rests on: quorum/majorities/convocation overlay with an audit trail, and a `Profile`
  binding contents/channels/signature/template/calendar/registry. Unblocks associations and
  cooperatives. — **L** · depends: B1 · closes **ENT-02, ENT-03**; enables ENT-A/F/K packs.
- **B5. GDPR-by-design layer (LEG-10..13).** Tenant isolation, access scoping, guest redaction,
  DSR workflows, RoPA/processor registry, DPIA + ZK-caveat docs. Deeply entangled with tenancy
  (DAT-01) and RBAC (ROL). — **L** · depends: A1, Wave-E RBAC · closes **LEG-10/11/12/13, ROL-05**.

### Wave C — Product: templates & documents

The headline conveniences, and the prerequisite for the signing wire.

- **C1. Template catalog engine (TPL).** Typed fields bound to the data model, per-family ×
  per-stage catalog, template-declared signature policy + compliance gate, document chaining,
  shareable/versioned libraries. The largest single feature gap by user value. — **L** · depends:
  B1/B4 (packs bind to templates) · closes **TPL-01..04/10/11/20/30/31/40/41/50, WFL-30/32/33**.
- **C2. Document / PDF generation (DOC-01/03).** A deterministic server-side act→PDF renderer
  (does not exist today; a stated prerequisite of the signing wire) + PDF/A profile + the DOC-03
  preservation bundle. Without this the PAdES stack has nothing to sign end-to-end. — **L** ·
  depends: C1 (renders templates) · closes **DOC-01, DOC-03**; unlocks Wave D.
- **C3. Export/archive packaging (DOC-20/21/22).** Turn the `build_package` → `NotImplemented`
  stub into a real ingestible package with checksums, DGLAB migration, package-level legal hold.
  — **M–L** · depends: C2, A4 · closes **DOC-20/21/22, UX-11/42**.

### Wave D — Signing epic

Plug the complete-but-unwired crypto stack into the seal. **Do not start before SIG-11.**

- **D1. SIG-11 — validate the TSL's own XML-DSig signature.** Native XML-DSig verify so the trust
  policy gate is production-safe. Prerequisite for a trustworthy signing wire. — **M** · depends:
  nothing · closes **SIG-11**; unblocks D2.
- **D2. Wire `chancela-signing` into the seal flow.** An application-service layer beside
  `chancela-api` that builds a `SignatureEnvelope` from the act's signatory slots, persists it on
  the act (a data-model change), drives `sign_slot` per signatory with real providers, adds a
  signing sub-phase for multi-session collection, and seals binding the *signed* content. — **L**
  (multi-crate epic) · depends: C2 (PDF renderer), D1, A1 (persist envelope) · closes **SIG-01
  end-to-end, SIG-31**; enables SIG-22/24.
- **D3. Qualified timestamp on seal + validation report (SIG-22/24, ARC-13).** Call the existing
  `chancela-tsa` client and `validate_signature` generator at seal time and embed both. — **M** ·
  depends: D2 · closes **SIG-22, SIG-24, ARC-13, WFL-22/23**.
- **D4. Soft-cert (PKCS#12) provider + SCAP attributes (SIG-01 3rd family, SIG-04).** — **L** ·
  depends: D2 · closes **SIG-04**; completes SIG-01. *(SIG-12 provider discovery/buy UI and
  SIG-30 external-signer links are breadth — see Wave E.)*

### Wave E — Breadth

- **E1. RBAC + delegation (ROL-01/02/03/10/11).** The 11 default roles, permission scopes, and
  first-class revocable delegation-as-evidence. Also unblocks AI-11/12 and LEG-10 access scoping.
  — **L** · depends: DAT-01 tenancy · closes **ROL-01/02/03/10/11**.
- **E2. Tenancy + groups (DAT-01/02/03, ENT-C7).** Platform/Tenant layers, user↔company
  membership, groups with shared libraries + cross-entity dashboards. — **L** · closes
  **DAT-01/02/03, ENT-C7**.
- **E3. Reminders engine + legal-calendar presets + real dashboard (WFL-40/41/42, ENT-C3).**
  The "never miss the art. 376.º annual meeting" value proposition; dashboard from ~2 → 11 feeds.
  — **M–L** · depends: A1 · closes **WFL-40/41/42, ENT-C3**.
- **E4. Chronology graph (DOC-30/31/32, AI-30).** Normalize parsed inscriptions into an event
  timeline + Mermaid + explainable provenance graph. Data groundwork already landed (t21). —
  **M–L** · depends: nothing (data exists) · closes **DOC-30/31/32**; completes AI-30.
- **E5. Localization runtime (UX-20/21, UX-03).** i18n framework + translations (queued as
  t19-e3a/b/c) and bundled open-licensed fonts. — **M–L** · in flight · closes **UX-20/21, UX-03**.
- **E6. Law-shelf search + citation (AI-20/21/22, UX-43).** Ingest DR + EUR-Lex into a search
  index over t24's curated seed; link rule-pack findings to entries. — **L** · depends: t24 (done)
  · closes **AI-20/21/22, UX-43**.
- **E7. MCP server (AI-10/11/12).** Small shell over the clean API; 3 of 5 read-only tools map to
  landed handlers, the rest and the write-controlled tools gate on E1 (RBAC) and earlier waves. —
  **M** · depends: E1 · closes **AI-10/11/12**.
- **E8. Historical paper-book import (WFL-15).** Digitized termos/atas as archived records with
  original-ref metadata, preserving numbering — a real onboarding blocker for legacy livros. —
  **L** · depends: A1, C3 · closes **WFL-15, WFL-23** original-ref half.
- **E9. Import/convert pipeline + validation-on-import (DOC-02/10/11).** Working-copy exports and
  generic document import with signature validation. — **M–L** · closes **DOC-02/10/11**.
- **E10. Supply-chain + deploy breadth (ARC-40/41/42, ARC-21).** Worker/sidecar images, cosign +
  SBOM + trivy, HA/Enterprise profiles, storage connectors. — **M–L** · closes **ARC-21/40/41/42**.
- **E11. AI feature layer (AI-01/02/03/04).** Drafting/extraction/comparison/summarization with
  provenance panels, a human-verification checkpoint, and a per-tenant toggle. — **L** · depends:
  C1, E6.

---

## 4. Deliberate deferrals (N/A-v1)

These are choices, not omissions — each is cited to a design decision:

- **Mobile companion app (SCP-21, ARC-04 mobile, UX-30/31).** Deferred by **SCP-D5** (mobile
  review/sign first, when scheduled). Tauri mobile icons exist but no build target. Desktop +
  web only for v1.
- **Repository-level zero-knowledge encryption (ARC-30..33, SCP-D3).** Deferred by **SCP-D3** as
  opt-in/later. Field-level encryption of access codes exists (`field_encryption.rs`); repo-level
  ZK is not v1. *(Note: at-rest store encryption in Wave A3 is a different, non-deferred item.)*
- **DSS validation sidecar (SIG-23 sidecar path, SCP-D2).** Deferred by **SCP-D2** — the native
  Rust validator is the v1 path; the DSS sidecar is a documented phase-2 seam the architecture
  admits either way.
- **OCR / content extraction (DOC-12, SCP-D4).** Deferred by **SCP-D4** (OCR modular, off by
  default). No OCR anywhere, matching the decision.
- **AI drafting / generation / MCP (AI-01..12).** Phase-2 per the plan; the read-only registry
  import (AI-30/31) is the one AI-adjacent surface intentionally shipped. Backlogged as E6/E7/E11
  rather than deferred outright, but not v1.
- **PDF/UA + working-copy export labeling (UX-11/42).** N/A-v1 only because document generation
  itself does not exist yet (Wave C); they become live requirements the moment C2/C3 land.
