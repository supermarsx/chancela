# Chancela — Portugal-Compliant Corporate Acts Ledger and Archive

**Specification index.** The product is a Portugal-first records, signing, governance,
archive, workflow, and compliance platform for Portuguese collective entities, with the
**livro de atas** and related **atos societários** as the center of gravity. It runs as an
offline desktop monolith, a self-hosted client-server deployment, and a browser deployment —
all backed by the same Rust domain core and the same legal rule packs.

The specification is broken down by application scope. Each document contains numbered
requirements using RFC 2119 keywords (**MUST** / **SHOULD** / **MAY**) plus its legal
grounding.

## Documents

| # | Document | Scope | Requirement prefix |
|---|---|---|---|
| 01 | [Product scope and editions](spec/01-product-scope.md) | Vision, product category, deployment editions, roadmap, open decisions | `SCP` |
| 02 | [Legal and compliance baseline](spec/02-legal-compliance.md) | Portuguese legal framing, compliance engine, GDPR/privacy | `LEG` |
| 03 | [Entity type profiles](spec/03-entity-profiles.md) | Per-entity rule packs: commercial companies, condominiums, associations, foundations, cooperatives | `ENT` |
| 04 | [Identity, signatures, and trust services](spec/04-signatures-trust.md) | Signing families (CC, CMD, QTSP certificates, manual), trusted list, signature formats, evidentiary model | `SIG` |
| 05 | [Data model and access control](spec/05-data-model-roles.md) | Tenancy hierarchy, roles, permissions, delegation | `DAT` / `ROL` |
| 06 | [Workflows and lifecycle](spec/06-workflows.md) | Draft-to-archive lifecycle, sealing, templates, dashboards, reminders | `WFL` |
| 07 | [Technical architecture](spec/07-architecture.md) | Rust core, Axum API, Tauri clients, event ledger, sync/backup, encryption, Docker | `ARC` |
| 08 | [Documents, archive, and exports](spec/08-documents-archive.md) | Authoring/evidence/archive formats, import/export, preservation packages, chronology graph | `DOC` |
| 09 | [AI, MCP, and integrations](spec/09-ai-mcp.md) | AI-assisted drafting, MCP server, legal-text library, registry integration | `AI` |
| 10 | [UX, design system, and localization](spec/10-ux-design.md) | Visual direction, themes, typography, accessibility, i18n, mobile scope | `UX` |
| 11 | [Template catalog (end-to-end)](spec/11-template-catalog.md) | Full document chain: book termos, convocatórias, proxies, attendance, act templates per entity family, certidões and notifications | `TPL` |

## Glossary

| Term | Meaning |
|---|---|
| Ata | Formal minutes of a deliberative meeting; primary legal evidence of resolutions |
| Livro de atas | The legally significant book of minutes kept per entity |
| Ato societário | A corporate act (resolution, appointment, capital change, etc.) |
| Convocatória | Formal meeting notice/summons |
| Termo de abertura | Formal instrument opening a livro de atas; in digital books, the genesis of the book's hash chain |
| Termo de encerramento | Formal instrument closing a livro de atas |
| Certidão de ata | Certified copy of a sealed ata for third parties |
| CSC | Código das Sociedades Comerciais (Portuguese Companies Code) |
| CC | Cartão de Cidadão (Citizen Card, carries qualified signature certificate) |
| CMD | Chave Móvel Digital (state-run remote qualified signature and authentication) |
| SCAP | Sistema de Certificação de Atributos Profissionais (professional attribute certification) |
| QTSP | Qualified Trust Service Provider under eIDAS |
| TSL | Trusted Service List (Portuguese national trusted list, published by GNS) |
| GNS | Gabinete Nacional de Segurança (eIDAS supervisory body in Portugal) |
| Certidão permanente | Permanent online registry certificate, consulted by access code |
| Seal / finalize | The act of locking an ata so it becomes append-only evidence |

## Reading order

Start with 01 (what we are building and in which editions), then 02–03 (the legal ground
truth that everything else serves), then 04 (signatures, the hardest compliance surface),
then 05–08 (how the system is structured), then 09–10, and 11 for the full
document-chain catalog referenced throughout.

## Core principle

The platform **helps produce compliant records; it does not create legal validity** out of
an invalid meeting, missing powers, or a defective corporate process. Every feature must
preserve the distinction between **substantive validity** (a matter of law and fact) and
**documentary evidence** (what the software can actually strengthen).
