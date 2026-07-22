/**
 * The Arquivo's `Âmbito` column: a ledger scope rendered as `Tipo — Nome` instead of a raw id.
 *
 * See `scopeLabel.ts` for what the field is and why a static catalog cannot name it. This module
 * holds the two halves that need React: the name lookup, and the cell.
 *
 * ## The authorization argument, in full
 *
 * Resolving an id to a name *reveals* that name, so the question is whether the Arquivo is
 * readable more widely than the records it scopes. It is not, but the reasoning matters:
 *
 * - The ledger read path requires `ledger.read` at **`Scope::Global`**
 *   (`crates/chancela-api/src/ledger.rs`, `arquivo.rs`), and `Scope::Global` is documented as
 *   "the only scope that satisfies a `Global` check" (`chancela-authz/src/scope.rs`) — an
 *   entity- or tenant-scoped grant does not reach it. So every Arquivo viewer is already an
 *   instance-wide reader of the event stream.
 * - Nevertheless this component does **not** rely on that. It resolves names only through
 *   `GET /v1/entities` and `GET /v1/books`, which filter *per row* on
 *   `authz.permits(EntityRead, scope_of_entity(..))` and `authz.permits(BookRead, scope_of_book(..))`
 *   (`entities.rs::list_entities`, `books.rs::list_books`). A name therefore appears here only if
 *   the viewer could already read it elsewhere in the app.
 *
 * That second point is what makes this safe against the one case the first does not cover: a
 * **custom** role (roles are authorable) holding `ledger.read` without `entity.read`. Every
 * *seeded* role that carries `ledger.read` also carries `entity.read` and `book.read` in the same
 * permission set, hence at the same scope — but a hand-built role need not, and resolving from a
 * source that ignored the viewer's permissions would leak names to exactly that principal. Reading
 * the viewer's own filtered lists makes the leak structurally impossible rather than merely
 * unlikely, so no server change is required to ship this safely.
 *
 * ## Cost
 *
 * Two list queries for the whole table, not one per row. Both use the shared `keys.entities` /
 * `keys.books()` query keys, so they deduplicate with the same lists fetched anywhere else in the
 * session, and both are skipped entirely when the viewer holds no such permission at any scope.
 */
import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';
import { api } from '../../api/client';
import { keys } from '../../api/hooks';
import type { BookView, Entity } from '../../api/types';
import { useT, type TFunction } from '../../i18n';
import { TooltipText } from '../../ui';
import { usePermissions } from '../session/permissions';
import {
  abbreviateId,
  parseScope,
  scopeTypeKey,
  type ScopeNameLookup,
  type ScopeSegment,
} from './scopeLabel';

/** A book's own words first; its kind is the honest fallback when no purpose was recorded. */
function bookName(book: BookView, t: TFunction): string | null {
  const purpose = book.purpose?.trim();
  if (purpose) return purpose;
  return book.kind ? t(`enum.bookKind.${book.kind}`) : null;
}

/**
 * Name lookups drawn from the viewer's own permission-filtered lists. Returns `null` for anything
 * the viewer cannot read, anything deleted, and anything still loading — all of which render as a
 * labelled id rather than as a guess.
 */
export function useLedgerScopeNames(): ScopeNameLookup {
  const t = useT();
  const { canAny } = usePermissions();
  const entities = useQuery({
    queryKey: keys.entities,
    queryFn: () => api.listEntities(),
    enabled: canAny('entity.read'),
  });
  const books = useQuery({
    queryKey: keys.books(),
    queryFn: () => api.listBooks(),
    enabled: canAny('book.read'),
  });

  const entityNames = useMemo(() => {
    const map = new Map<string, string>();
    for (const entity of (entities.data ?? []) as Entity[]) {
      if (entity?.id && entity.name) map.set(entity.id, entity.name);
    }
    return map;
  }, [entities.data]);

  const bookNames = useMemo(() => {
    const map = new Map<string, string>();
    for (const book of (books.data ?? []) as BookView[]) {
      if (!book?.id) continue;
      const name = bookName(book, t);
      if (name) map.set(book.id, name);
    }
    return map;
  }, [books.data, t]);

  return useMemo(
    () => ({
      entity: (id: string) => entityNames.get(id) ?? null,
      book: (id: string) => bookNames.get(id) ?? null,
    }),
    [bookNames, entityNames],
  );
}

/**
 * One segment as `Tipo — Nome`, or just `Tipo` for a keyword scope that carries no id.
 *
 * The one case worth spelling out: a keyword token this catalog does **not** know. The API grows
 * scope types faster than any hand-maintained list follows them (`trust` and `recovery` were both
 * missed on the first pass, and two more hide behind `const AUDIT_SCOPE` rather than an inline
 * literal), so an unmapped token must never disappear behind the generic `Âmbito` label — it is
 * printed beside it. An incomplete catalog then costs a nicer word, never a fact.
 */
function segmentLabel(segment: ScopeSegment, t: TFunction): string {
  const key = scopeTypeKey(segment.token);
  const typeLabel = t(key);
  if (segment.id !== null) return `${typeLabel} — ${segment.name ?? abbreviateId(segment.id)}`;
  if (key === 'enum.ledgerScopeType.unknown' && segment.token) {
    return `${typeLabel} — ${segment.token}`;
  }
  return typeLabel;
}

/**
 * The most specific segment of a scope as a **plain string** — `Tipo — Nome`, or a bare type
 * label for a keyword scope. For compact one-line surfaces (the dashboard's `Atividade recente`
 * feed) that fold the scope into a sentence via i18n interpolation rather than rendering the full
 * {@link LedgerScopeCell} with its tooltip and muted parent context. Same resolution, translated
 * type labels, and honest fallback (an unresolved id becomes `Tipo — 0a20de34…`, never a bare
 * UUID and never blank) as the cell.
 */
export function scopeSummaryLabel(scope: string, names: ScopeNameLookup, t: TFunction): string {
  const segments = parseScope(scope, names);
  return segmentLabel(segments[segments.length - 1], t);
}

/**
 * One chain membership (the `Cadeias` column) rendered as a friendly label, resolving `company:`
 * and `book:` ids to the names the viewer may already read and falling back to an abbreviated id —
 * never a bare `company:{uuid}`.
 *
 * The **chains vocabulary is not the scope vocabulary**, so this cannot go through {@link parseScope}:
 * a per-entity book-action chain is `company:{id}` where a scope would say `entity:{id}`
 * (`chancela-ledger/src/lib.rs`, `ChainId::Company`), and the two id-less keyword chains are
 * `global` (the primary spine every event shares) and `application` (the application-audit chain) —
 * neither of which any scope emits. Everything else (`book:{id}`, `tenant:{id}`) shares the token.
 *
 * No new i18n: the id-less labels and the `Entidade {id}` / `Livro {id}` frames already exist in
 * every locale under `ledger.chain.*` (they name the chain FILTER on the Arquivo page), so the same
 * strings name the chain here — the only change is passing a resolved name where the filter passes a
 * short id. An unmapped chain kind (`tenant:`, or anything the API adds next) keeps its raw token
 * with an abbreviated id rather than being mislabelled; the exact chain id is in the tooltip either
 * way, since it is the value the `?chain=` filter and every export use.
 */
export function chainSummaryLabel(chain: string, names: ScopeNameLookup, t: TFunction): string {
  if (chain === 'global') return t('ledger.chain.global');
  if (chain === 'application') return t('ledger.chain.application');
  const colon = chain.indexOf(':');
  if (colon > 0) {
    const kind = chain.slice(0, colon);
    const id = chain.slice(colon + 1);
    if (kind === 'company')
      return t('ledger.chain.company', { id: names.entity(id) ?? abbreviateId(id) });
    if (kind === 'book') return t('ledger.chain.book', { id: names.book(id) ?? abbreviateId(id) });
    return `${kind}:${abbreviateId(id)}`;
  }
  return chain;
}

/**
 * One scope, rendered as the most specific segment (`Tipo — Nome`) followed by whatever parent
 * segments actually resolved to a name, muted.
 *
 * The em dash is punctuation joining two independent noun phrases, not a sentence — no
 * substituted value is ever the subject of an inflected word, which is TRANSLATIONS.md rules 1
 * and 3 satisfied by construction.
 *
 * The **exact, unmodified scope string** is the tooltip label, and `TooltipText` is reachable by
 * keyboard as well as hover, so an auditor can always recover the identifier the export and the
 * `?scope=` filter use.
 */
export function LedgerScopeCell({ scope, names }: { scope: string; names: ScopeNameLookup }) {
  const t = useT();
  const segments = parseScope(scope, names);
  const primary = segmentLabel(segments[segments.length - 1], t);
  // Parent segments earn their space only when they say something: a resolved name, or a keyword
  // that names itself (`backup/archive`). An unresolved parent id is noise here and is already in
  // the tooltip.
  const context = segments
    .slice(0, -1)
    .filter((segment) => segment.name !== null || segment.id === null)
    .map((segment) => segmentLabel(segment, t))
    .join(' · ');

  return (
    <TooltipText label={scope} className="ledger-scope">
      <span>{primary}</span>
      {context ? <span className="muted"> · {context}</span> : null}
    </TooltipText>
  );
}
