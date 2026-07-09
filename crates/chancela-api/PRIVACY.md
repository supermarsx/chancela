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
