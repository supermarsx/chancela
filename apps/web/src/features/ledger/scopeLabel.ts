/**
 * Turning a ledger event's `scope` into something a person can read.
 *
 * ## What the field actually is
 *
 * `events.scope` is a `/`-joined **path of `type:id` segments**, built as a plain string in the
 * API and stored verbatim (`crates/chancela-store/src/schema.rs`, `events.scope TEXT NOT NULL`).
 * Three shapes occur on the wire:
 *
 * 1. **Discriminated segments** — `tenant:{uuid}`, `entity:{uuid}`, `book:{uuid}`, `act:{uuid}`,
 *    `user:{uuid}`, `role:{uuid}`, `delegation:{uuid}`, `repository:{uuid}`, `archive:{uuid}`,
 *    `imported-document:{id}`, `paper-book-import:{id}`, composed into paths like
 *    `tenant:{t}/entity:{e}/book:{b}/act:{a}`. The prefixes are additive and optional, so
 *    `entity:{e}/book:{b}` and `book:{b}/act:{a}` and bare `act:{a}` all occur.
 * 2. **Keyword segments with no id at all** — `settings`, `law`, `cae`, `platform`, `backup`,
 *    `email`, `provider_credentials`, `api-key`, `user`, `global`, `book_archive`, `trust`,
 *    `recovery`. These do **not** all appear as inline literals: `email` and
 *    `provider_credentials` hide behind a `const AUDIT_SCOPE` (`smtp_settings.rs`,
 *    `provider_credentials_write.rs`) and `recovery` behind `RECOVERY_SCOPE`
 *    (`chancela-ledger/src/lib.rs`), so any grep-driven inventory of this set undercounts — as
 *    the first pass at this file did. A keyword segment is a path segment like any other, so
 *    `backup/archive` (`lib.rs`) parses as two of them rather than falling through.
 * 3. **A bare UUID with no discriminator** — this is the defect the user reported. It is emitted
 *    by `entity.statute_updated` (`crates/chancela-api/src/entities.rs`, `next.id.to_string()`)
 *    and by `registry.imported` / `registry.auto_update.attempted`
 *    (`crates/chancela-api/src/registry.rs`, `&eid.to_string()`), and in every case it is an
 *    **entity id** — but nothing on the wire says so.
 *
 * ## Why a static catalog cannot solve this
 *
 * A UUID is a reference to a record, not an enum variant, so the friendly name has to be
 * *resolved*. The event payload cannot supply it: `LedgerEventView` carries only
 * `payload_digest`, never the payload, so unlike the reminder rows in `dashboardSourceLabels.ts`
 * (which prefer an authored `preset_label` already on the payload) there is no name to prefer
 * here. Only the *type* half is a closed set, and that half lives in
 * `src/i18n/ledgerScopeLabels.ts`.
 *
 * ## Authorization
 *
 * Resolution deliberately reads **only the viewer's own permission-filtered list endpoints**
 * (`GET /v1/entities`, `GET /v1/books`), each of which filters per row on `entity.read@Entity` /
 * `book.read@Book` server-side. So a name can only ever appear here if the viewer could already
 * read it on the Entidades page: naming a scope reveals nothing new. Anything outside those lists
 * stays an id. See `useLedgerScopeNames` for the rest of that argument.
 *
 * ## Honesty rules
 *
 * A name is never invented, and nothing is silently dropped: an **unmapped keyword token** is
 * printed beside the generic type label rather than being swallowed by it, so this catalog falling
 * behind the API costs a nicer word and never a fact.
 *
 * A name is never invented. An unresolved id keeps its **type label** and an abbreviation, and the
 * exact untouched scope string is carried in the tooltip by the caller — never blank, never
 * `undefined`, never a bare UUID standing alone. A bare UUID that does *not* match a readable
 * entity is labelled with the generic `unknown` type rather than being asserted to be an entity.
 */
import type { LedgerScopeLabels } from '../../i18n/ledgerScopeLabels';
import { LABELLED_LEDGER_SCOPE_TYPES } from '../../i18n/ledgerScopeLabels';

/** The i18n key for a scope-type token, falling back to the generic label for anything unmapped. */
export function scopeTypeKey(token: string | null): keyof LedgerScopeLabels {
  if (token && LABELLED_LEDGER_SCOPE_TYPES.has(token)) {
    return `enum.ledgerScopeType.${token}` as keyof LedgerScopeLabels;
  }
  return 'enum.ledgerScopeType.unknown';
}

/** What the renderer needs about one `/`-separated piece of a scope. */
export interface ScopeSegment {
  /** The wire type token (`entity`, `settings`, …), or `null` when the segment declared none. */
  token: string | null;
  /** The record id half, or `null` for a keyword segment that carries no id. */
  id: string | null;
  /** The resolved record name, or `null` when it could not be resolved. Never invented. */
  name: string | null;
}

/** Name lookups over records the viewer is already authorized to read. `null` ⇒ not resolvable. */
export interface ScopeNameLookup {
  entity: (id: string) => string | null;
  book: (id: string) => string | null;
}

const NO_NAMES: ScopeNameLookup = { entity: () => null, book: () => null };

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The bare keyword `user` scope is the user-administration surface (`users.rs` appends
 * `user.created` etc. against the literal `"user"`), which is a different thing from
 * `user:{uuid}` — one specific person. Same token, two meanings, so the keyword form is
 * re-pointed at its own label rather than reading as "Utilizador".
 */
function keywordToken(raw: string): string {
  return raw === 'user' ? 'user_accounts' : raw;
}

/**
 * Split a raw scope into segments and resolve what can be resolved.
 *
 * An empty or whitespace-only scope yields a single unknown segment carrying the raw string, so
 * the renderer always has something honest to draw.
 */
export function parseScope(raw: string, names: ScopeNameLookup = NO_NAMES): ScopeSegment[] {
  const parts = raw.split('/').filter((part) => part !== '');
  if (parts.length === 0) return [{ token: null, id: raw, name: null }];

  return parts.map((part) => {
    const colon = part.indexOf(':');
    if (colon > 0) {
      const token = part.slice(0, colon);
      const id = part.slice(colon + 1);
      return { token, id, name: resolveName(token, id, names) };
    }
    // No discriminator. A UUID here is an entity id by every current emit site, but that is a
    // convention rather than a contract — so it is only *called* an entity when the viewer's own
    // entity list confirms it. An unmatched UUID stays generically labelled rather than mislabelled.
    if (UUID_RE.test(part)) {
      const name = names.entity(part);
      return name === null
        ? { token: null, id: part, name: null }
        : { token: 'entity', id: part, name };
    }
    return { token: keywordToken(part), id: null, name: null };
  });
}

function resolveName(token: string, id: string, names: ScopeNameLookup): string | null {
  if (token === 'entity') return names.entity(id);
  if (token === 'book') return names.book(id);
  // tenant / act / user / role / delegation / repository / archive have no client-side list the
  // viewer is already entitled to, so they keep their id. See the API-gap note in the task log.
  return null;
}

/** First eight characters plus an ellipsis — an abbreviation, never presentable as a name. */
export function abbreviateId(id: string): string {
  return id.length > 8 ? `${id.slice(0, 8)}…` : id;
}
