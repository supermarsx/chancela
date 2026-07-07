# 05 — Data Model and Access Control

Requirement prefixes: `DAT` (data model), `ROL` (roles/permissions)

## 1. Tenancy hierarchy

- **DAT-01** The data model MUST be hierarchical and tenancy-aware:

```
Platform
└── Tenant
    └── Company / Entity
        └── Book (one per organ; opened by termo de abertura,
            │     closed by termo de encerramento — WFL-10..15)
            └── Meeting / Act (sequentially numbered within the book)
                ├── Document set
                ├── Signature envelope
                ├── Registry / ledger event(s)
                └── Archive package
```

- **DAT-02** The model MUST support: one user in multiple companies; one company in a
  group; one entity with multiple books; one act producing several artifacts (draft text,
  attendance list, attachments, signed final PDF/A, validation report, export package).
- **DAT-03** Groups of companies MUST be supported with **shared template libraries** and
  **cross-entity dashboards**, while each entity keeps its own legal books and audit trail.
- **DAT-04** Books MUST carry their lifecycle state (created / open / closed) and their
  termo instruments as first-class records; the sealed termo de abertura is the genesis
  event of the book's hash chain (WFL-11, DAT-11).
- **DAT-05** Registry data (statutes, associated electronic documents, legal-entity
  records from the certidão permanente) MUST be modeled as distinct-but-linked records with
  provenance, matching how the registry services themselves separate them.

## 2. Roles (RBAC + attribute constraints)

- **ROL-01** The role model MUST combine **RBAC** with **attribute-based constraints**
  (entity scope, book scope, time bounds, legal capacity).
- **ROL-02** Default roles MUST include: Platform Administrator, Tenant Administrator,
  Company Owner, Corporate Secretary, Legal Counsel, Records Manager, Signatory, Reviewer,
  Auditor, Guest, and API Client.
- **ROL-03** Permission scopes MUST include: company, book, act, folder, template library,
  archive, and integration.
- **ROL-04** Signatory roles on an act MUST be differentiated (chair, secretary, member,
  manager, administrator, attorney, condo owner, …) because the signer's capacity is part
  of the evidence (see SIG-04).
- **ROL-05** Guests MUST be subject to field-level redaction (LEG-10).

## 3. Delegation as evidence

- **ROL-10** Delegation MUST be first-class, not a cosmetic convenience: temporary and
  revocable delegation of signing, review, and management rights.
- **ROL-11** Each delegation MUST record: legal basis, scope, start/end dates, grantor,
  grantee, and revocation status — and MUST appear in the evidentiary trail, because
  Portuguese qualified-signature law attaches significance to representation and powers
  (DL 12/2021).

## 4. Audit and event integrity

- **DAT-10** Every meaningful mutation MUST generate a **ledger event** containing actor,
  justification, timestamp, entity scope, prior event hash, and payload digest.
- **DAT-11** Cryptographic hash chains MUST be maintained per company, per book, and
  globally, so tampering with sequence or content is detectable
  (details in [07 — Architecture](07-architecture.md)).
- **DAT-12** Sealed acts are **append-only**: text, attachments, signatory list,
  validation report, and event hash become immutable; corrections are new acts referencing
  the earlier one (see WFL-20).
