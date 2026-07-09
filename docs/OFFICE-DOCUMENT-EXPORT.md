# Office Document Export

`GET /v1/acts/{id}/document/office` returns a deterministic DOCX working copy for a sealed act's preserved document.

- Authorization: same read gate as `GET /v1/acts/{id}/document` (`act.read` for the act's book).
- Artifact: `application/vnd.openxmlformats-officedocument.wordprocessingml.document`, named `act-{id}-office-working-copy.docx`.
- Scope: read-only. The endpoint does not write document rows, alter preserved PDF/A bytes, or append ledger events.
- Availability: `404` when no preserved document exists. `409` when a preserved row exists but the editable document model cannot be rebuilt.
- Evidentiary warning: the DOCX embeds a non-evidentiary warning and preserved-document metadata. The stored PDF/A or signed PDF remains the canonical record.
