# Authorization changes & upgrade notes

Permissions are compile-time verbs — adding one is a reviewed code change — but **which** verbs a
role grants is data that lives in your instance's `roles.json`. That split is why a release can
narrow a route immediately while leaving your stored roles untouched, and it is the source of every
surprise on this page.

Read this before upgrading if you run anything other than a fresh install.

---

## Release 26.2 — legal hold, trust-list import, and step-up

Three tightenings. Two of them **remove access that existing roles have today**.

### What changed, in one table

| Route | Was | Is now |
| --- | --- | --- |
| `PUT`/`DELETE /v1/books/{id}/legal-hold` | `book.export@Book` | `legal_hold.manage@Book` |
| `POST /v1/books/{id}/archive/disposal` with `dry_run: false` | `book.export@Book` | `book.export` **and** `legal_hold.manage@Book` |
| `POST /v1/trust/refresh` (trusted-service list import) | `cae.refresh@Global` | `trust.manage@Global` |
| `POST /v1/ledger/recovery/restore` | `ledger.recover@Global` | …**and step-up re-auth** |
| `POST /v1/books/{id}/start-over` | `book.start_over@Book` | …**and step-up re-auth** |
| `POST /v1/data/key-rotation` | `settings.manage@Global` + interactive session | …**and step-up re-auth** |
| `POST /v1/privacy/.../erasure/execute` | `user.manage@Global` | …**and step-up re-auth** |

Reads are unchanged. `GET /v1/books/{id}/legal-hold` still answers to `book.export`, and the trust
catalog (`/v1/trust/status`, `/v1/trust/catalog`, `/v1/trust/providers/…`, `/v1/trust/services/…`)
still answers to `cae.read`. Seeing a hold or reading the trust list was never the risk; setting,
releasing, and importing were.

### Who loses what

**Legal hold.** `book.export` is held by 9 of the 15 seeded roles, because exporting is meant to be
broad. That meant an **Auditor** and an **API Client** could release the hold that is the only thing
standing between a book and disposal. On upgrade these seeded roles keep `book.export` and lose the
ability to set or release a hold, and to record an archive-disposal **execution**:

> Gestor · Company Owner · Corporate Secretary · Records Manager · Tenant Administrator ·
> Auditor · API Client

The disposal **dry-run** is unaffected — it stays a review step on `book.export`.

**Trust-list import.** `cae.refresh` gates the CAE economic-activity reference table. The trusted-
service list is not reference data: it decides *which signatures the product will consider valid*.
On upgrade these seeded roles keep `cae.refresh` and lose `POST /v1/trust/refresh`:

> Gestor · Company Owner

**Step-up.** Any script or integration that posts to the four step-up routes must now send a
`reauth` object (`{"reauth": {"password": "…"}}` or `{"reauth": {"recovery_phrase": "…"}}`). An
operator who holds **neither** a password nor a recovery phrase is unaffected — their authenticated
session is already the strongest proof they can offer, and it satisfies step-up. A credentialed
operator who sends nothing gets `403`.

### Why the upgrade does not lock you out — and where it does not help

Two rules in the role loader decide what your instance looks like after the upgrade, and they
behave differently:

1. **The Owner (`Proprietário`) is re-forced to the canonical all-permissions definition on every
   startup.** Its permission-set is locked so a tampered `roles.json` can never weaken the
   escalation ceiling. So the Owner gains `legal_hold.manage` and `trust.manage` **automatically**.
   There is never a moment when nobody can manage a legal hold or import a trust list.

2. **Every other seeded role is inserted only when it is absent.** They are editable, so the loader
   will not clobber a customised one — which also means it will not *update* one. On an existing
   install, your stored `Platform Administrator` and `Legal Counsel` rows already exist, so they do
   **not** pick up the new verbs on their own, even though the shipped seed defaults now include
   them.

The asymmetry is the whole point of this section: **the route-side change takes effect immediately
for everyone, while the code-side seed change does not retroactively widen — or narrow — a deployed
`roles.json`.** Right after the upgrade the set of principals who can manage a legal hold is
*exactly the Owners*, on every pre-existing install, regardless of what the seed defaults say.

### Restoring access deliberately

Use the seeded-drift reconciliation path. It is idempotent, **only ever adds** permissions, never
touches the Owner, and appends a `role.seeded_drift_reconciled` event to the ledger.

```
GET  /v1/roles/{id}/seeded-drift-reconciliation   # dry-run: what would be added
POST /v1/roles/{id}/seeded-drift-reconciliation   # apply
```

Run it for `Platform Administrator` to grant `legal_hold.manage` + `trust.manage`, and for
`Legal Counsel` to grant `legal_hold.manage`. Review the `GET` first: if you have customised those
roles, reconciliation will also restore any *other* seeded defaults they are missing.

!!! warning "Only an Owner can perform this particular reconciliation"

    Reconciliation requires `role.manage@Global` **and** satisfies the subset invariant against the
    proposed permission-set — you cannot grant a role a permission you do not yourself hold. Because
    a Platform Administrator does not yet hold `legal_hold.manage` or `trust.manage`, it cannot
    reconcile itself into holding them. Sign in as an Owner.

To give the verbs to a role that is **not** a seeded holder — say you want your Records Manager to
keep setting holds — reconciliation will not do it (it only restores seeded defaults). Edit the role
directly, again as an Owner:

```
PATCH /v1/roles/{id}   { "permissions": [ …existing…, "legal_hold.manage" ] }
```

### If you would rather not adopt the change

There is no configuration flag that reverts the route guards; the verbs are compile-time. The
supported way to keep a role working exactly as before is the `PATCH` above — grant it
`legal_hold.manage` and/or `trust.manage` explicitly. Doing so is a deliberate, ledgered act, which
is the point: the old behaviour was an accident of verb reuse, not a decision anyone recorded.

### New audit event

A trusted-service list import now appends `trust.tsl.imported` to the application audit chain,
carrying the source, outcome, validation result and resulting service counts. **Refused imports are
recorded too** — a fail-closed import that preserved the previous cache is exactly the event an
incident review needs to see. Before this release a TSL import was the only critical mutation in the
product that left no ledger entry at all.
