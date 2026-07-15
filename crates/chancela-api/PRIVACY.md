# Privacy Compliance API

This backend slice keeps DSR requests plus GDPR processor and DPIA registers under
`AppState`. In pure in-memory mode they reset with the process; when a data directory
is configured they are loaded from and written through to `privacy-dsr-requests.json`,
`privacy-processors.json`, and `privacy-dpias.json` using the same
missing/malformed-tolerant JSON sidecar pattern as users, roles, delegations, API keys,
and settings.
Every accepted DSR create/complete and register create/update is still appended to the
ledger. Rejected DSR execution attempts fail before mutation and do not append an audit
event.

## Authorization

DSR export and request lifecycle routes require `user.manage@Global`.

Processor and DPIA register routes require either `user.manage@Global` or
`settings.manage@Global`.

## Routes

- `GET /v1/privacy/processors`
- `POST /v1/privacy/processors`
- `PATCH /v1/privacy/processors/{id}`
- `GET /v1/privacy/dpias`
- `POST /v1/privacy/dpias`
- `PATCH /v1/privacy/dpias/{id}`
- `GET /v1/privacy/users/{id}/export`
- `GET /v1/privacy/users/{id}/dsr-requests`
- `POST /v1/privacy/users/{id}/dsr-requests`
- `POST /v1/privacy/users/{user_id}/dsr-requests/{request_id}/complete`
- `PATCH /v1/privacy/dsr-requests/{id}`
- `POST /v1/privacy/dsr-requests/{id}/complete`
- `POST /v1/privacy/users/{user_id}/dsr-requests/{request_id}/erasure/preflight`
- `POST /v1/privacy/users/{user_id}/dsr-requests/{request_id}/erasure/approve`
- `POST /v1/privacy/users/{user_id}/dsr-requests/{request_id}/erasure/execute`

## Destructive erasure (right to erasure, Art. 17) — wp26-gdpr

Erasure DSRs run a **destructive** workflow that physically deletes the subject's live
personal data and cryptographically destroys any at-rest-encrypted subject PII, while
**never mutating the append-only ledger**. Because the ledger stores only
`payload_digest` and pseudonymous references (a subject UUID scope, an `actor` slug),
deleting the store-side rows/blobs cannot break `Ledger::verify()`; the erasure is
proven instead by appending exactly one `subject.erased` attestation event, so
`verify()` advances from `Ok(n)` to `Ok(n + 1)` with tamper-evidence intact.

**Backup policy — crypto-erase-first (locked).** Erasable subject PII is encrypted under
a per-subject Data Encryption Key (DEK) wrapped by the internally-derived root
(`secretstore` XChaCha20-Poly1305 / HKDF-SHA256 core). Erasure destroys the wrapped DEK
(zeroes `subject_keys.wrapped_dek`, sets `erased_at`) and then `VACUUM`s, so every
ciphertext copy — live rows **and** any backup that holds them — becomes cryptographically
irrecoverable at once. There is no backup-window carve-out. The API never claims a backup
is erased before the DEK that unlocks it is destroyed.

### Workflow: request → preflight → approve → execute → attest → verify

1. **Preflight** (`.../erasure/preflight`) enumerates every concrete target into exactly
   two buckets — **erasable** (rows/blobs/keys to destroy, with collection + count) and
   **retained** (Art. 17(3) carve-outs, each with a legal-basis reason) — counts the
   subject's ledger events, checks legal holds, and returns a **preflight digest** binding
   the exact plan. Status is `blocked_immutable_ledger` for the ledger carve-out, or
   `ready_for_approval` when erasable targets exist and no blocking hold applies. Output is
   evidence only; nothing is destroyed.
2. **Approve** (`.../erasure/approve`) is the destructive gate: requires
   `user.manage@Global`, enforces **dual control** (the approver must be a principal
   distinct from the requester), and requires an explicit typed confirmation echoing the
   subject id and the fresh preflight digest, plus an explicit legal-hold/carve-out
   acknowledgement. Records `requested_by` + `approved_by`.
3. **Execute** (`.../erasure/execute`) re-checks the preflight digest still matches (anti
   TOCTOU — rejects if the store changed since preflight), then in **one transaction**
   (all-or-rollback): `DELETE`s the erasable rows, destroys the subject DEK, and appends
   the `subject.erased` event. `VACUUM` runs post-commit (SQLite `VACUUM` cannot run inside
   a transaction). On any pre-commit error the ledger snapshot and transaction roll back and
   nothing is destroyed.
4. **Attest / mark.** The DSR record is set `full_erasure_completed: true`,
   `destructive_mutation_completed: true`, the `subject.erased` event id is recorded, and
   the outcome stays capped at `partially_fulfilled` — the retained ledger/audit carve-outs
   are lawful retention under Art. 17(3), not an incomplete erasure.

### `subject.erased` ledger event

Kind `subject.erased` (constant in `chancela-ledger`), stamped on a keyword `user:{uuid}`
scope so it lives on the **Application** chain (no genesis-kind constraint; no WFL-11
entanglement). Its digested, retained-as-JSON payload records: `subject_id`,
`dsr_request_id`, `requested_by`, `approved_by`, `executed_by`, `executed_at`, `technique`
(`crypto_erase` / `physical_delete` / `vacuum`), erased `targets` (collection/action/count),
`dek_destroyed`, `retained_carveouts` (collection + legal_basis), `pre_erasure_ledger_head`,
and `ledger_event_count_matched`. New `actor` stamping uses the subject **UUID**, not a
username slug, so it does not re-introduce attributable PII once the users row is gone.

### Retained carve-outs (NOT erased — documented Art. 17(3) basis)

- **The append-only ledger events** — they hold no payload PII; retained for tamper-evidence
  and defence of legal claims. A historic `actor`/`justification` is a lawful retention, never
  rewritten in place.
- **The DSR request audit trail** (create/complete events + the `subject.erased` attestation)
  — proving the erasure happened is itself an accountability obligation (Art. 5(2)).
- **Sealed legal records with independent statutory retention** — `acts` (sealed minutes),
  `books` + the *termo de abertura* genesis, and `signed_documents`/`documents` that are the
  canonical legal instruments. These are business records of the organisation (examples use the
  fictional *Encosto Estratégico Lda*), retained under Art. 17(3)(b); surfaced in the preflight
  as blockers with a legal-basis reason, never silently skipped.
- **Legal-hold targets** — a legal hold blocks erasure of the held records (reuses the retention
  legal-hold blocker model).

DSR records use `request_type`, `status`, `created_at`, `created_by`, and, once
completed, `completed_at`, `completed_by`, `outcome`, `executed_at`, and
`executed_by`. `reason`, `completion_reason`, `execution_notes`,
`retention_review`, and `legal_basis_review` are optional, trimmed operator context
fields; missing fields in older sidecars are tolerated. Accepted DSR `request_type`
values are `export`, `rectification`, `erasure`, and `restriction`. Accepted DSR
`status` values are `pending` and `completed`; the only mutation transition is
`pending` to `completed`.

Completion bodies may include:

- `outcome`: `fulfilled`, `partially_fulfilled`, `rejected`, or `no_action_required`
  (`fulfilled` is used for legacy empty completion bodies).
- `execution_notes`: up to 4096 characters.
- `affected_records`: up to 32 summary objects with `collection`, `action`, and
  `count`; an empty list is valid when no records were changed.
- `retention_review` and `legal_basis_review`: up to 2048 characters each.

Execution evidence is non-destructive: it records the operator's outcome and bounded
summary only. The execution fields reject known sensitive credential field markers such
as `password_hash` and `api_key_secret`; ledger event responses continue to expose only
payload digests, never DSR payload bodies.

Create and patch bodies use `purpose`, `legal_basis`, `data_categories`,
`subprocessors`, `risk_level`, and `status`. Processor records use `name`; DPIA records
use `title`.

Accepted `risk_level` values are `low`, `medium`, `high`, and `critical`.
Accepted `status` values are `draft`, `active`, `under_review`, and `retired`.
Unknown status or risk values return `422` and do not mutate the register or append an
update audit event.
