# Record deletion (design decision)

> **Status.** This is a recorded design decision, not a proposal, and **no code implements it yet**.
> Two questions remain with the product owner and are marked
> [AWAITING DECISION](#what-is-decided-and-what-is-still-open) below. One of them — whether a deleted
> record is hidden from listings or shown struck through in place — **decides between
> [Option B and Option C](#options-considered)**, so this document must not be read as if B were
> already chosen. Everything else here is settled, and the findings that forced it are facts about
> the current tree, verified in code and cited by file and line.

## The request

> *"admin should be able to mark books, entities and acts as deleted but always keep the registry and
> ensure the chain of trust isn't broken in the process"*

So: a **tombstone, not an erasure**. The record survives, the ledger stays verifiable, and an
administrator can mark a book, an entity or an act as deleted.

## Vocabulary: two obvious words are already taken

Neither collision is cosmetic; both would land on the subject where precision matters most.

**"Archived" is unavailable for acts.** `ActState::Archived`
(`crates/chancela-core/src/act.rs:69-70`) means *archived into a preservation package*. It is
reachable only from `Sealed` (`act.rs:1405-1413`), and `archive_act`
(`crates/chancela-api/src/acts.rs:1531`) refuses unless the act's full digital-signature evidence
tuple revalidates against the stored canonical and signed PDF (`acts.rs:1557-1599`). That is a
**promotion into preservation, the opposite of a retirement**. Extending the `archived` vocabulary
downward from entities would have given one word two opposite meanings on the act.

**"Tombstone" is unavailable as a shipped name.** The codebase already uses it for a *fail-closed
search-projection marker* installed before a destructive store transaction
(`crates/chancela-api/src/search.rs:1351`, `crates/chancela-store/src/lib.rs:113`). The word is used
in this document as a concept, but the field, the events and the operator copy use **deleted**.

Settled names: field `deleted_at`, events `*.deleted` / `*.restored`, permissions `entity.delete` /
`book.delete` / `act.delete`.

## The hazard that decided this design — and why it does not arise

This is the single most important section. **The temptation it guards against is obvious and the
failure it would cause is invisible.**

`Book::close` deliberately overwrites the closing termo's `ata_count`
(`crates/chancela-core/src/book.rs:539`), so that — in its own words — *"the closing instrument
cannot understate how many atas the book holds"*. That termo is then co-signed and PAdES-sealed. The
stated concern was therefore: if marking an act deleted removes it from that count, a sealed
instrument asserts a false fact while its signature stays cryptographically valid — a validly-signed
false fact, which is worse than an invalid signature and which nothing downstream can detect.

**It does not arise, because the value written is not a count of extant acts.**

`Book::close` writes `self.last_ata_number`, and `last_ata_number` is a **monotonic counter whose
only writer is `self.last_ata_number += 1`** in `assign_next_ata_number` (`book.rs:552`). All 32
occurrences of the field across the workspace were checked — `books.rs:722-723,792`,
`dashboard.rs:561,564,1078`, `dto.rs:520,559,3346`, `entities.rs:1251`, `termo.rs:1364,1581`,
`chancela-action-center/src/lib.rs:936`, `chancela-search-projection/src/lib.rs:193` — and **every
one is a read**. Nothing anywhere recomputes it by enumerating acts.

`TermoDeEncerramento` (`crates/chancela-core/src/termo.rs:1178-1191`) carries `ata_count`,
`pages_used_at_close`, signatories and body, and **no per-act enumeration**, so there is nothing else
in the sealed instrument for a deletion to contradict.

> **The rule this becomes.** `ata_count` and `pages_used_at_close` are attested quantities derived
> from monotonic counters. **No deletion-aware recount may ever be introduced**, and a deleted act
> keeps its consumed ata number and its consumed pages. A future change that "surely should not count
> deleted atas" would silently falsify every already-sealed termo de encerramento. This must be
> pinned by a test asserting `last_ata_number` is unchanged across a delete/restore round trip, and
> named in a comment at `book.rs:539`.

This is the same class of reasoning that keeps `book.reopen` unbuildable
(`crates/chancela-authz/src/permission_description.rs:48-65`): the verb is not merely unbuilt, it is
unrepresentable without contradicting a signed document.

## What each sealed instrument attests

Verified at the payload construction sites, because the design turns on these being true.

| Event | Payload | Site |
| --- | --- | --- |
| `book.opened` (genesis) | `TermoDeAbertura` **only** | `chancela-core/src/seal.rs:264-268`, appended at `:282` |
| `book.closed` | `TermoDeEncerramento` **only** | `chancela-api/src/books.rs:924-929` |
| `act.sealed` | `SealedActPayload { ActPayload, seal_metadata }` — a curated struct, not `Act` | `chancela-core/src/seal.rs:131-193, 379-391` |

**`Book` is never a ledger payload.** Adding a field to it moves no digest, past or future. The book
subject is the cheapest of the three to build.

**`Entity` and `Act` are payloads** for their non-seal events: `entity.created` / `entity.updated` /
`entity.archived` (`entities.rs:493-525`), and `act.drafted` (`acts.rs:137`), `act.advanced`
(`:553`), `act.ai_human_verification` (`:931`), `act.archived` (`:1608`), `convening.dispatched`
(`:1694`) — each serializing the whole aggregate. For those two the new field must follow the pattern
`Entity::archived_at` already establishes (`chancela-core/src/entity.rs:341-365`): `Option<T>` with
`skip_serializing_if = "Option::is_none"`, so an untouched subject stays **byte-identical** and no
future digest of one moves.

`ActPayload` is a hand-written struct, so a new `Act` field does not reach the seal preimage unless
someone adds it there. That absence should be asserted by a test rather than left to inspection.

**One constraint this places elsewhere.** `TermoDeAbertura` carries the entity's `name`, `nipc` and
`seat` and *is* the `book.opened` genesis preimage. Party identity resolves
`act.book_id → Book.termo_abertura → TermoDeAbertura`, and `preview_document` deliberately resolves
names through an **unfiltered** `entities.get`. Deletion state must never enter that lookup, for the
same reason archiving does not — the day it does, a sealed act loses the ability to name who was in
the room.

## Ground truth per subject

### Entity — substantially built, and unreachable by any operator

Built: `Entity::archived_at` with `archive()` / `unarchive()` (`entity.rs:341-471`); `POST
/v1/entities/{id}/archive` and `/unarchive` on `Permission::EntityArchive` (`entities.rs:418-455`);
the `entity.archived` / `entity.unarchived` events (`entities.rs:512, 521`); a tri-state
`ArchivedFilter` of `include|exclude|only` on both list endpoints (`entities.rs:329-381`);
`ConfirmationAction::EntityArchive` at floor `Confirm`, class `Consequential`
(`chancela-api/src/confirmation.rs:411, 479-484`); four mint-paths refusing on an archived entity
plus a content freeze; and `EntityView.archived_at` + `archived` (`chancela-api/src/dto.rs:341-350`),
pinned in `contracts/entity.json:43-44`.

**None of it has a web surface.** `apps/web/src/api/client.ts` has no `archiveEntity` or
`unarchiveEntity` — its entity block is lines 992-1000 and 1538-1544. The web `Entity` interface
(`apps/web/src/api/types.ts:468-493`) has **no `archived_at`**, so the client silently drops the
field the server sends. `EntitiesPage` carries no archive control and no badge. This is tracked
separately from this design; it is recorded here because a reader comparing "what exists" against
"what an operator can do" will otherwise conclude the flow works.

**What deletion would add.** Archiving is a **write gate** — it stops new authorship and freezes
content. It is explicitly *not* a read gate: `entities.rs:342` states the default filter returns
*"Every entity, archived or not"*. Deletion is a **read gate**. The two are orthogonal and stack:
deleted implies archived.

### Book — nothing resembling this exists

`BookState` is `{ Created, Open, Closed }` (`book.rs:64-71`) and nothing else. `close_book` is
one-way. `set_legal_hold` / `clear_legal_hold` exist (`books.rs:1155, 1214`). `start_over_book`
(`chancela-api/src/bundles.rs:471`) retires a book and mints a **successor** — irreversible, floored
at `ConfirmWithReauthAndPhrase`, and the wrong shape for this. `Permission::BookReopen` is a phantom
verb (`chancela-authz/src/permission.rs:82-84`).

A book created in error — wrong entity, wrong kind — has **no exit today**. This is the strongest
case of the three and, because `Book` is not a ledger payload, the cheapest to build.

### Act — the word is taken, the capability is absent

Covered under [Vocabulary](#vocabulary-two-obvious-words-are-already-taken). `ActRevert` and
`ActReopen` move an act backward through its lifecycle but never retire it from view.

## Options considered

**Option A — extend `archived` down to books and acts.** Rejected: it collides irreparably on acts,
and entity archiving deliberately hides nothing, so it does not answer the request at all.

**Option B — one deletion concept across all three.** `deleted_at: Option<OffsetDateTime>` on
`Entity`, `Book` and `Act`, all `skip_serializing_if`; paired `*.deleted` / `*.restored` events
following the established convention (`role.deleted`, `template.deleted`,
`template.version.deleted`, `zk.repository.deleted`) and the archive/unarchive precedent of a
separate event in each direction. *Cost:* entities carry two lifecycle flags. That is honest — one
gates writes, one gates reads — but the UI must render two distinct badges and never conflate them.
Deleting implies archiving; **restoring does not auto-unarchive**, because restoring visibility is
not restoring authorship, and granting both silently would be a transformation the operator never
asked for.

**Option C — books and acts only; entities keep `archived`.** Declines a third of the request, but
becomes correct if deleted records are shown struck through in place rather than hidden — because
then entity-delete adds almost nothing over entity-archive, and shipping a third entity lifecycle
flag that changes nothing an operator can see would be worse than not shipping it.

**Which of B and C applies is [AWAITING DECISION](#what-is-decided-and-what-is-still-open).**

## The visibility rule

**A deletion hides a subject from cross-cutting lists. It never hides an act from its own book's ata
sequence.**

- **Default listings** (`/v1/entities`, `/v1/books`, `/v1/acts`, search): deleted rows **excluded by
  default**, with a tri-state `deleted=include|exclude|only` filter. This is deliberately the
  **inverse** default from `ArchivedFilter`, whose default is `include`. Document that at both sites,
  or the next reader files it as a bug.
- **A book's own ata list:** deleted acts are **always shown, struck through, ata number intact**. An
  ata n.º 7 that silently vanishes from a sequence of 12 is an unexplained gap; a marked one is a
  record.
- **Countable:** yes, everywhere a count is attested. Never removed from `last_ata_number`,
  `pages_used`, or `pages_remaining`.
- **Archive package: add no `deleted` filter.** `load_book_archive_inventory`
  (`chancela-api/src/archive_package.rs:1139-1143`) enumerates every act of the book with no state
  filter, and `included_acts` (`:959-963`) filters only on having a preserved document. A deleted act
  keeps its PDF/A, its signature chain and its `metadata/*.json` sidecar inside the package. **This
  is what makes "the signed PDF/A is the canonical evidentiary unit" true rather than asserted.**
- **Resolution by id is never filtered.** A sealed act's `retifies` link and a termo's party name must
  keep resolving to a deleted subject.
- **Search projection:** `guest_act_value` in `chancela-search-projection/src/lib.rs` serializes the
  whole `Act`, so a new field lands in the guest projection automatically. Decide its redaction
  explicitly — deletion state is not personal data, so the recommendation is to leave it visible —
  rather than letting it arrive by accident.

## Legal hold, cascade, reversibility

**Legal hold blocks, loudly.** A hold today blocks act reopen (`acts.rs:678` — *"a held book's acts
must not move"*) and disposal execution (`archive_package.rs:1236`). Consistent with that: a book
under hold refuses its own deletion, refuses the deletion of any of its acts, and refuses the
deletion of its entity. A hold exists to preserve a record as-is for a proceeding; hiding it from the
people running that proceeding is the exact failure mode the control exists to prevent. The refusal
is a `409` naming the book, the hold reason and the remedy — the shape `ensure_entity_not_archived`
(`books.rs:97-106`) already uses, never a silent no-op. **Restore is never blocked by a hold**, the
same asymmetry `unarchive` already has.

**Cascade: inherited visibility, not cascaded state.** Only the addressed subject gets a `deleted_at`.
A book whose entity is deleted is hidden from default listings *by inheritance*, with its own
`deleted_at` staying `None`; restoring the entity restores everything without needing to remember
which children were individually marked. Cascading real state would emit a ledger write per child
from one click and destroy the ability to tell what the operator actually chose. Refusing outright is
defensible in principle but would make the entity case useless, since every real entity has books.

**Reversible, with its own appended event.** `entities.rs:426-441` already made this argument for
archiving and it transfers unchanged: irreversibility buys integrity only where reversal would
rewrite the record, and a deletion touches no sealed content, so it would purchase nothing and cost
recoverability. The round trip leaves strictly *more* audit record, never less. Same verb in both
directions — the authority to hide is the authority to unhide — and `*.restored` carries no
confirmation floor, because granting visibility back is not the dangerous direction.

## Permission and confirmation

**Three verbs: `entity.delete`, `book.delete`, `act.delete`.** The blast radii genuinely differ: one
hides an entire legal person, one hides a single row. A single `record.delete` would save three
entries each in `permission_description.rs`, the two `permissionDescriptionsFallback.ts` maps and the
seeded-role decision, at the price of handing everyone who can hide a mistaken draft the ability to
hide a company. All three must ship `Enforced`; `no_verb_ships_as_reachable_unchecked` fails the
suite otherwise, and `book.reopen` is the standing example of what a phantom verb costs.

**Floor: `ConfirmWithReauth` (T2), all three.** This is the tier definition read literally
(`confirmation.rs:333`): *"removes access/authority **or hides evidentiary state**, or is
multi-subject"*. `ActArchive` already sits at T2 for a weaker reason (`confirmation.rs:369`). Not T3:
nothing is destroyed and it is reversible, and T3 phrases are priced for the irreversible — spending
one here devalues `ENCERRAR LIVRO`.

**Consequence class: `Consequential`, not `Destructive`**, following the `EntityArchive` reasoning at
`confirmation.rs:479-484` verbatim — reversible, removes no record, leaves sealed acts naming their
parties. Here it does double duty: labelling this `Destructive` would *reinforce* the false belief the
next section is about. The copy carries that weight instead.

The existing engine covers this fully — three variants across `ConfirmationAction` / `ALL` /
`as_str` / `floor` / `consequence`, three entries in the route-guard map and in `authz.rs`'s route
table, and the reusable `GuardedActionModal` + `useGuardedActionPolicy` on the client.

## The RGPD distinction, unsoftened

The product already has a **real erasure**, and this feature is not it.
`ConfirmationAction::PrivacyErasureExecute` and `chancela-ledger`'s `SUBJECT_ERASED_KIND`
(`crates/chancela-ledger/src/lib.rs:1119`) destroy the subject's per-subject DEK and vacuum the
store, making at-rest ciphertext irrecoverable. That path is scoped to a **data subject**, and its own
preflight lists sealed acts, books and signed documents as **lawfully-retained GDPR Art. 17(3)
carve-outs whose remedy is annotation, never deletion** (`chancela-api/src/privacy.rs:7609,
7627-7636, 7799-7836`; `chancela-ledger/src/lib.rs:1121-1134`).

**An administrator who marks an entity deleted and believes they have discharged an erasure request
will be wrong, and nothing in the current copy would correct them.** Portuguese commercial-records
law requires retention and this design deliberately keeps everything, so the gap is real and
permanent, not a temporary shortfall.

The recommendation — **the wording itself is the product owner's call**, see below — is to label the
action *"Marcar como eliminado"*, badge the row *"Eliminado"*, and have the confirmation modal state
in one sentence that no data is erased and that erasure of personal data is a separate operation
under Privacidade. *"Eliminar"* alone is the dangerous word; *"Ocultar"* is accurate but understates
it into a display toggle.

Whichever word is chosen has to be **the same word** on the button, the row badge, the confirmation
modal, the ledger event label in all 14 locales, and the permission description. A modal that
explains the nuance does not help in the two places an auditor actually reads — the ledger label and
the permission description — because those carry the bare verb alone.

## Blast radius, and the gates that catch a half-landing

Files: `chancela-core/{entity,book,act}.rs` and its `lib.rs` re-exports;
`chancela-api/{entities,books,acts,confirmation,authz,dto}.rs` and the `lib.rs` router;
`chancela-authz/{permission,permission_description}.rs`; `contracts/entity.json`,
`contracts/book.json`; and on the web `types.ts`, `client.ts`, `ledgerEventLabels.ts`,
`permissionDescriptionsFallback.ts`, the locale catalogs and the three list pages.

Gates that fail on a partial landing, each pinning something real:

- `confirmation.rs::tests::all_is_complete` — every variant listed in `ALL`.
- The completeness rule that the guarded-route set and the action-map key set must be **equal**, so a
  variant minted without its route, or a route without its variant, trips the same assertion.
- `phrase_exists_exactly_for_the_phrase_floor` and `floors_are_not_uniform`.
- `permission_description::no_verb_ships_as_reachable_unchecked`.
- `apps/web/src/api/labels.test.ts`, which greps the crates for emitted ledger kinds and fails on any
  kind lacking a pt-PT `enum.ledgerEventKind.*` label. It also asserts
  `LABELLED_LEDGER_EVENT_KINDS.size` against a floor, which must be raised with the additions.
- `chancela-core/tests/back_compat.rs` — fixtures written before the field must still read back.
- `chancela-core/tests/entity_archive_freeze.rs` and `seal_preimage_freeze.rs`, which are the
  templates for the byte-identity tests this needs.

The only real type gate on the web is `cd apps/web && npm run typecheck`; `npx tsc --noEmit` is a
no-op here, because `apps/web/tsconfig.json` sets `"files": []`.

## What is decided, and what is still open

**Decided:**

- A **sealed** act may be marked deleted. Restricting to unsealed drafts would decline the actual
  case — a book carrying a sealed act created in error — and the deletion touches no sealed content,
  keeps the ata number, and keeps the PDF/A and signature chain in the archive package.
- **Inherited visibility, not cascaded state**: children of a deleted subject are hidden by
  inheritance and keep `deleted_at: None`.
- **Three permissions**, `entity.delete` / `book.delete` / `act.delete`, all shipping `Enforced`.
- Floor `ConfirmWithReauth`, consequence class `Consequential`.
- Reversible, via a separately appended `*.restored` event carrying no floor.
- Legal hold blocks deletion in all three directions and never blocks restore.
- No deletion-aware recount of `ata_count` or `pages_used_at_close`, ever.
- No `deleted` filter in the archive package.
- The names: `deleted_at`, `*.deleted` / `*.restored`, and not "archived" or "tombstone".

**Awaiting the product owner:**

- **Hidden from default listings, or struck through in place?** This decides
  [Option B against Option C](#options-considered). Struck-through removes the tri-state filter's
  reason to exist, reduces the surface to a badge plus the ledger events, and makes entity-delete
  near-redundant with the entity-archive that already exists.
- **The operator-facing word.** *"Eliminar"* matches the request but describes something the feature
  does not do; *"Marcar como eliminado"* describes what it does. The choice binds the button, the
  badge, the modal, the ledger label in all 14 locales and the permission description together, per
  [the RGPD section](#the-rgpd-distinction-unsoftened).
