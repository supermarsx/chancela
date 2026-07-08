/**
 * The Global / Entity / Book scope picker (t64-E6) — the shared control behind every scoped
 * RBAC action (role assignment, delegation grant). It emits a {@link PermissionScope} that
 * maps byte-for-byte onto the server's `ScopeInput` tagged union
 * (`{"kind":"global"|"entity"|"book","id"?}`) and onto the E5 `CanScope`, so a caller can gate
 * the surrounding affordance with `useCan(perm, scope)` and send the same value on the wire.
 *
 * Narrowing is honest and server-enforced: a Global grant covers everything, an Entity grant
 * covers that entity and its books, a Book grant covers only itself. The picker only chooses
 * the target; the server re-checks the actor actually holds the authority there.
 */
import { useEffect, useMemo } from 'react';
import { useEntities, useBooks } from '../../api/hooks';
import { useT } from '../../i18n';
import { Field, Select } from '../../ui';
import type { PermissionScope } from '../../api/types';

/** The three scope kinds, in the order the selector offers them. */
type ScopeKind = PermissionScope['kind'];

export function ScopePicker({
  value,
  onChange,
  idPrefix,
  disabled,
}: {
  value: PermissionScope;
  onChange: (scope: PermissionScope) => void;
  idPrefix: string;
  disabled?: boolean;
}) {
  const t = useT();
  const entities = useEntities();
  const books = useBooks();

  const kindOptions: { value: ScopeKind; label: string }[] = [
    { value: 'global', label: t('rbac.scope.global') },
    { value: 'entity', label: t('rbac.scope.entity') },
    { value: 'book', label: t('rbac.scope.book') },
  ];

  const entityList = useMemo(() => entities.data ?? [], [entities.data]);
  const bookList = useMemo(() => books.data ?? [], [books.data]);

  // Once the target list resolves, backfill a concrete id if the current scope has none or a
  // stale one (e.g. Entity was picked before the list loaded). No-op once the id is valid, so
  // it never loops. Keeps the emitted scope always sendable when a target exists.
  useEffect(() => {
    if (
      value.kind === 'entity' &&
      entityList.length > 0 &&
      !entityList.some((e) => e.id === value.id)
    ) {
      onChange({ kind: 'entity', id: entityList[0].id });
    } else if (
      value.kind === 'book' &&
      bookList.length > 0 &&
      !bookList.some((b) => b.id === value.id)
    ) {
      onChange({ kind: 'book', id: bookList[0].id });
    }
  }, [value, entityList, bookList, onChange]);

  // Switching kind resets to the first available target (or an empty id, which the server
  // rejects — the surrounding submit stays disabled until a real target is chosen).
  function setKind(kind: ScopeKind) {
    if (kind === 'global') onChange({ kind: 'global' });
    else if (kind === 'entity') onChange({ kind: 'entity', id: entityList[0]?.id ?? '' });
    else onChange({ kind: 'book', id: bookList[0]?.id ?? '' });
  }

  const desc =
    value.kind === 'global'
      ? t('rbac.scope.global.desc')
      : value.kind === 'entity'
        ? t('rbac.scope.entity.desc')
        : t('rbac.scope.book.desc');

  return (
    <div className="stack--tight">
      <Field label={t('rbac.scope.label')} htmlFor={`${idPrefix}-kind`} hint={desc}>
        <Select
          id={`${idPrefix}-kind`}
          value={value.kind}
          disabled={disabled}
          onChange={(e) => setKind(e.target.value as ScopeKind)}
          options={kindOptions}
        />
      </Field>

      {value.kind === 'entity' ? (
        <Field label={t('rbac.scope.entity.pick')} htmlFor={`${idPrefix}-entity`}>
          <Select
            id={`${idPrefix}-entity`}
            value={value.id}
            disabled={disabled}
            onChange={(e) => onChange({ kind: 'entity', id: e.target.value })}
            options={entityList.map((en) => ({ value: en.id, label: en.name }))}
          />
        </Field>
      ) : null}

      {value.kind === 'book' ? (
        <Field label={t('rbac.scope.book.pick')} htmlFor={`${idPrefix}-book`}>
          <Select
            id={`${idPrefix}-book`}
            value={value.id}
            disabled={disabled}
            onChange={(e) => onChange({ kind: 'book', id: e.target.value })}
            options={bookList.map((b) => ({
              value: b.id,
              label: b.purpose ?? b.id,
            }))}
          />
        </Field>
      ) : null}
    </div>
  );
}

/** A short human label for a scope, for read-only display in tables (uses the loaded entity/
 *  book caches to resolve a name, falling back to the id). */
export function useScopeLabel(): (scope: PermissionScope) => string {
  const t = useT();
  const entities = useEntities();
  const books = useBooks();
  return (scope: PermissionScope) => {
    if (scope.kind === 'global') return t('rbac.scope.global');
    if (scope.kind === 'entity') {
      const name = (entities.data ?? []).find((e) => e.id === scope.id)?.name;
      return `${t('rbac.scope.entity')}: ${name ?? scope.id}`;
    }
    const purpose = (books.data ?? []).find((b) => b.id === scope.id)?.purpose;
    return `${t('rbac.scope.book')}: ${purpose ?? scope.id}`;
  };
}
