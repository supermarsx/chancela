# Working-Copy Document Exports

Chancela exposes deterministic working copies for a sealed act's preserved document. These are convenience exports for review and drafting only; the stored PDF/A or signed PDF remains the canonical record.

## Working Copies

`GET /v1/acts/{id}/document/working-copy` returns Markdown by default. The same endpoint also accepts `?format=txt`, `?format=html`, `?format=rtf`, and `?format=odt`.

- Authorization: same read gate as `GET /v1/acts/{id}/document` (`act.read` for the act's book).
- Artifacts:
  - Markdown: `text/markdown; charset=utf-8`, named `act-{id}-working-copy.md`.
  - TXT: `text/plain; charset=utf-8`, named `act-{id}-working-copy.txt`.
  - HTML: `text/html; charset=utf-8`, named `act-{id}-working-copy.html`.
  - RTF: `application/rtf`, named `act-{id}-working-copy.rtf`.
  - ODT: `application/vnd.oasis.opendocument.text`, named `act-{id}-working-copy.odt`.
- Scope: read-only. The endpoint does not write document rows, alter preserved PDF/A bytes, or append ledger events.
- Availability: `404` when no preserved document exists. `409` when a preserved row exists but the editable document model cannot be rebuilt.
- Determinism: ODT is emitted as a minimal OpenDocument Text zip with stored members and fixed member timestamps, using the existing zip tooling. It contains `mimetype`, `content.xml`, `styles.xml`, `meta.xml`, and `META-INF/manifest.xml`.
- Evidentiary warning: every working-copy export embeds or starts with a non-evidentiary warning and includes preserved-document metadata, including the preserved PDF digest.

## Office Working Copy

`GET /v1/acts/{id}/document/office` returns a deterministic DOCX working copy for a sealed act's preserved document.

- Authorization: same read gate as `GET /v1/acts/{id}/document` (`act.read` for the act's book).
- Artifact: `application/vnd.openxmlformats-officedocument.wordprocessingml.document`, named `act-{id}-office-working-copy.docx`.
- Scope: read-only. The endpoint does not write document rows, alter preserved PDF/A bytes, or append ledger events.
- Availability: `404` when no preserved document exists. `409` when a preserved row exists but the editable document model cannot be rebuilt.
- Evidentiary warning: the DOCX embeds a non-evidentiary warning and preserved-document metadata. The stored PDF/A or signed PDF remains the canonical record.
