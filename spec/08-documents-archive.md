# 08 — Documents, Archive, and Exports

Requirement prefix: `DOC`

## 1. Format tiers

The document layer MUST distinguish **authoring formats**, **evidence formats**, and
**archive formats**.

- **DOC-01** Evidence: the primary final format MUST be **PDF with PAdES signatures**;
  preservation profile defaults to **PDF/A**. Recommended: **PDF/A-2u or PDF/A-3u** for
  signed outputs today; **PDF/UA**-aligned generation where accessible delivery is
  required; optional **PDF/A-4** for specific modern workflows.
- **DOC-02** Working exports: **DOCX, ODT, RTF, HTML, TXT, Markdown** (plus legacy DOC
  import) through a conversion pipeline. The UI MUST explicitly label these as **working
  copies**, not the legally preserved signed originals.
- **DOC-03** A sealed act MUST always preserve: the final signed PDF; the
  signature-validation report; structured metadata; the attachments manifest; and the
  original editable source when available. Convenience format and evidentiary record serve
  different purposes and MUST never be conflated.

## 2. Import

- **DOC-10** Import MUST accept: office documents, PDFs, images, ZIP-based bundles, XML,
  CSV, and email attachments used as supporting records.
- **DOC-11** The validation subsystem MUST validate signed PDFs and detached evidence
  envelopes on import (linking into SIG-23/24).
- **DOC-12** OCR/content extraction per SCP-D4: modular, off by default for sensitive
  tenants; prefer native text extraction.

## 3. Archive and export packages

- **DOC-20** The archive subsystem MUST generate an **export package** ingestible by other
  archival or document-management systems, including: checksums, provenance, rights
  metadata, language metadata, signing evidence, and retention instructions.
- **DOC-21** Preservation design follows DGLAB long-term digital preservation guidance:
  plan for preservability and controlled migration from the outset; maintain integrity and
  usability over time.
- **DOC-22** Retention schedules and legal holds (LEG-10) apply at the archive-package
  level; a package under legal hold MUST NOT be deletable through any retention rule.

## 4. Chronology and relationship intelligence

A major product differentiator.

- **DOC-30** Imported registry content (certidão permanente, articles/statutes) MUST be
  parsed into a normalized **event timeline**: constitutions, quota transfers, capital
  changes, management appointments and cessations, seat changes, object changes,
  dissolutions, and other acts.
- **DOC-31** From that graph the app MUST generate **Mermaid** diagrams for shareholders,
  managers, delegated powers, and inter-company relationships.
- **DOC-32** The chronology feature MUST be a native, **explainable** graph feature that
  works with or without AI assistance: every node/edge traces back to a source record
  (registry import, sealed act, or user entry) with provenance.
