# 06 — Workflows and Lifecycle

Requirement prefix: `WFL`

## 1. Act lifecycle

- **WFL-01** The main business workflow MUST be:

```
draft → review → convene → deliberate → approve text → sign → seal/finalize
      → archive → [sync/export] → [register/report]
```

- **WFL-02** Within that lifecycle the product MUST support:
  - creating minutes from **templates** or from prior acts;
  - attaching convocatórias, agendas, proxy documents, attendance lists, reports, exhibits;
  - collecting signatures from one or many signatories, serial or parallel (SIG-31);
  - differentiated signatory roles (ROL-04);
  - inviting external signers by secure link with strict expiration and identity
    requirements (SIG-30);
  - capturing the **meeting channel**: physical, hybrid, telematic, or written resolution
    (with the art. 377.º evidence set for telematic — LEG-04);
  - compliance warnings when finalizing with missing mandatory content, missing signatures,
    inconsistent representation, or a signature type unsupported for the intended legal
    effect (LEG-05).

## 2. Book lifecycle (livro de atas)

An ata never exists in isolation: it belongs to a **book** with a formal opening and
closing. Legal grounding: Código Comercial escrituração provisions as simplified by
DL 76-A/2006 (books are opened and closed with **termos de abertura e de encerramento**
signed by the entity's management, without mandatory external legalization); CSC art. 63.º
loose-leaf anti-falsification logic; DL 268/94 for the condominium livro de atas.

- **WFL-10** Books MUST have an explicit lifecycle: **created → open → closed**. A book is
  created with a **termo de abertura** and closed with a **termo de encerramento**; both
  are formal instruments generated from templates (TPL-10/11) and sealed like acts.
- **WFL-11** The **termo de abertura** MUST record at minimum: entity identification
  (name, NIPC, seat); book type and purpose (e.g., livro de atas da assembleia geral,
  livro de atas da gerência/administração, livro de atas do condomínio); the numbering
  scheme; the opening date; and the signatures required by the entity profile (management,
  administrator). For **digital books**, the sealed termo de abertura is the **genesis
  event of the book's hash chain** (DAT-11) — the digital equivalent of the paper book's
  anti-falsification function.
- **WFL-12** Every ata MUST carry a **sequential number within its book** (ata n.º N),
  assigned at sealing and never reused. Loose-leaf mode MUST additionally implement page
  numbering and chaining per CSC art. 63.º (ENT-C6).
- **WFL-13** The **termo de encerramento** MUST record: the number of atas (and pages,
  where applicable) contained, the closing reason (book full, entity dissolved, migration
  to a successor book), the closing date, and the required signatures. A closed book is
  read-only; a successor book's termo de abertura MUST reference its predecessor.
- **WFL-14** An ata MUST NOT be created outside an open book. Multiple books per entity
  are supported (one per organ — assembleia geral, gerência/administração, conselho
  fiscal — per the entity profile).
- **WFL-15** **Historical paper books** MUST be importable via a digitization workflow:
  scanned termos and atas enter as archived records with original-reference metadata
  (where the paper original is kept), preserving the original numbering; the digital book
  then continues the sequence from the imported state.

## 3. Sealing ("finalize and lock")

- **WFL-20** The product MUST support sealing an ata (UI terms: **"finalize and lock"** or
  **"seal the act"**). Once sealed, the act is append-only: textual payload, attachments,
  signatory list, validation report, and event hash can no longer be edited (DAT-12).
- **WFL-21** Any later correction MUST be a **new act** that references the sealed one
  (retificação chain). This reflects CSC art. 63.º anti-falsification logic and the
  integrity presumptions of qualified signatures/timestamps.
- **WFL-22** Sealing MUST record: compliance rule-pack versions (LEG-06), the
  signature-validation report (SIG-24), and optionally a qualified timestamp (SIG-22).
- **WFL-23** Manual-signature sealing MUST show the SIG-03 warning and capture
  original-reference metadata (where the paper original is kept).

## 4. Templates

- **WFL-30** The product MUST ship the full end-to-end Portuguese template catalog defined
  in [11 — Template catalog](11-template-catalog.md), covering book instruments,
  pre-meeting documents, in-meeting documents, act templates per entity family, and
  post-act instruments — not only the minutes themselves.
- **WFL-31** Compliance logic MUST always be driven by law and the entity's statutes, never
  by the template itself: templates are conveniences, rule packs are authority.
- **WFL-32** Template libraries MUST be shareable across a group (DAT-03) and versioned.
- **WFL-33** Documents generated across one act's lifecycle MUST be **chained**: the ata
  references its convocatória, attendance list, and proxies; certidões and extracts
  reference the sealed ata; registry packages reference everything they contain (TPL-02).

## 5. Dashboard and reminders

- **WFL-40** The dashboard MUST be configurable and include at minimum: overdue signatures;
  unsigned drafts; acts awaiting validation; approaching annual meetings; unarchived
  originals; certificate expiry; failed sync jobs; pending backups; legal-hold items;
  chronologies of shareholders/managers; unresolved compliance warnings.
- **WFL-41** The reminders engine MUST support event-based reminders and calendar rules,
  with per-tenant and per-company policies.
- **WFL-42** Reminders MUST ship with **legal-calendar presets** (not empty): e.g., the
  CSC art. 376.º annual-meeting window for sociedades anónimas and recurring
  accounts-approval workflows.
