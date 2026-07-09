# Working-Copy Document Exports

Chancela exposes deterministic working copies for a sealed act's preserved document. These are convenience exports for review and drafting only; the stored PDF/A or signed PDF remains the canonical record.

## Text Working Copies

`GET /v1/acts/{id}/document/working-copy` returns Markdown by default. The same endpoint also accepts `?format=txt` and `?format=html`.

- Authorization: same read gate as `GET /v1/acts/{id}/document` (`act.read` for the act's book).
- Artifacts:
  - Markdown: `text/markdown; charset=utf-8`, named `act-{id}-working-copy.md`.
  - TXT: `text/plain; charset=utf-8`, named `act-{id}-working-copy.txt`.
  - HTML: `text/html; charset=utf-8`, named `act-{id}-working-copy.html`.
- Scope: read-only. The endpoint does not write document rows, alter preserved PDF/A bytes, or append ledger events.
- Availability: `404` when no preserved document exists. `409` when a preserved row exists but the editable document model cannot be rebuilt.
- Evidentiary warning: every text export starts with a non-evidentiary working-copy warning and includes preserved-document metadata, including the preserved PDF digest.

## Office Working Copy

`GET /v1/acts/{id}/document/office` returns a deterministic DOCX working copy for a sealed act's preserved document.

- Authorization: same read gate as `GET /v1/acts/{id}/document` (`act.read` for the act's book).
- Artifact: `application/vnd.openxmlformats-officedocument.wordprocessingml.document`, named `act-{id}-office-working-copy.docx`.
- Scope: read-only. The endpoint does not write document rows, alter preserved PDF/A bytes, or append ledger events.
- Availability: `404` when no preserved document exists. `409` when a preserved row exists but the editable document model cannot be rebuilt.
- Evidentiary warning: the DOCX embeds a non-evidentiary warning and preserved-document metadata. The stored PDF/A or signed PDF remains the canonical record.
