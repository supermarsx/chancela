/**
 * t64-E5 web permissions context: the client-side mirror of the server's scope narrowing,
 * the disable-with-explanation gate controls, and honest 403 rendering.
 *
 *  - an Owner (all perms @ global) sees every action ENABLED;
 *  - a Leitor sees writes DISABLED-with-explanation and reads enabled;
 *  - a scoped Gestor is enabled WITHIN its scope and disabled OUTSIDE it (and a scoped
 *    grant never satisfies a Global check — upward scope-escape is impossible);
 *  - a 403 renders an honest "sem permissão", not a raw error.
 */
import { afterEach, describe, it, expect, vi } from 'vitest';
import { cleanup, render, screen, fireEvent } from '@testing-library/react';
import { QueryClient } from '@tanstack/react-query';
import type { PermissionGrant } from '../../api/types';
import { ApiError } from '../../api/client';
import { keys } from '../../api/hooks';
import { ErrorNote } from '../../ui';
import {
  GateButton,
  StaticPermissionsProvider,
  cachedScopeParent,
  grantCoversScope,
  scopeAct,
  scopeArchive,
  scopeBook,
  scopeEntity,
  scopeFolder,
  scopeGlobal,
  scopeIntegration,
  scopeRepository,
  scopeTemplateLibrary,
  scopeTenant,
  type CanScope,
  type BookEntityResolver,
  type PermissionsContextValue,
  type ScopeParentResolver,
} from './permissions';

afterEach(() => cleanup());

const grant = (permission: string, scope: PermissionGrant['scope']): PermissionGrant => ({
  permission,
  scope,
  source: 'role',
});

/** Build the context value from a grant list, mirroring the real provider exactly. */
function valueFromGrants(
  grants: PermissionGrant[],
  bookEntity: BookEntityResolver = () => undefined,
): PermissionsContextValue {
  return {
    can: (permission, scope: CanScope = scopeGlobal) =>
      grants.some((g) => g.permission === permission && grantCoversScope(g, scope, bookEntity)),
    canAny: (permission) => grants.some((g) => g.permission === permission),
    grants,
    ready: true,
  };
}

function renderGate(
  grants: PermissionGrant[],
  props: { perm: string; scope?: CanScope; anyScope?: boolean; onClick?: () => void },
  bookEntity?: BookEntityResolver,
) {
  return render(
    <StaticPermissionsProvider value={valueFromGrants(grants, bookEntity)}>
      <GateButton
        perm={props.perm}
        scope={props.scope}
        anyScope={props.anyScope}
        onClick={props.onClick}
      >
        Ação
      </GateButton>
    </StaticPermissionsProvider>,
  );
}

describe('grantCoversScope — narrowing-only (mirrors chancela-authz::scope_covers)', () => {
  const noBooks: BookEntityResolver = () => undefined;

  it('a global grant covers ANY target', () => {
    const g = grant('x', { kind: 'global' });
    expect(grantCoversScope(g, scopeGlobal, noBooks)).toBe(true);
    expect(grantCoversScope(g, scopeEntity('E1'), noBooks)).toBe(true);
    expect(grantCoversScope(g, scopeBook('B1'), noBooks)).toBe(true);
  });

  it('a scoped grant NEVER satisfies a global check (no upward escape)', () => {
    expect(grantCoversScope(grant('x', { kind: 'entity', id: 'E1' }), scopeGlobal, noBooks)).toBe(
      false,
    );
    expect(grantCoversScope(grant('x', { kind: 'book', id: 'B1' }), scopeGlobal, noBooks)).toBe(
      false,
    );
  });

  it('an entity grant covers that entity and its books, not another entity/book', () => {
    const g = grant('x', { kind: 'entity', id: 'E1' });
    const books: BookEntityResolver = (b) => (b === 'B1' ? 'E1' : b === 'B2' ? 'E2' : undefined);
    expect(grantCoversScope(g, scopeEntity('E1'), books)).toBe(true);
    expect(grantCoversScope(g, scopeEntity('E2'), books)).toBe(false);
    expect(grantCoversScope(g, scopeBook('B1'), books)).toBe(true); // B1 ∈ E1
    expect(grantCoversScope(g, scopeBook('B2'), books)).toBe(false); // B2 ∈ E2
    expect(grantCoversScope(g, scopeBook('B?'), books)).toBe(false); // unknown book (fail-closed)
  });

  it('a book grant covers only that exact book', () => {
    const g = grant('x', { kind: 'book', id: 'B1' });
    expect(grantCoversScope(g, scopeBook('B1'), noBooks)).toBe(true);
    expect(grantCoversScope(g, scopeBook('B2'), noBooks)).toBe(false);
    expect(grantCoversScope(g, scopeEntity('E1'), noBooks)).toBe(false);
  });

  it('walks tenant → entity → book → act only through authoritative parents', () => {
    const parents = new Map<string, CanScope>([
      ['entity:E1', scopeTenant('T1')],
      ['book:B1', scopeEntity('E1')],
      ['act:A1', scopeBook('B1')],
    ]);
    const parent: ScopeParentResolver = (scope) =>
      parents.get(scope.kind === 'global' ? 'global' : `${scope.kind}:${scope.id}`);

    expect(grantCoversScope(grant('x', scopeTenant('T1')), scopeAct('A1'), noBooks, parent)).toBe(
      true,
    );
    expect(grantCoversScope(grant('x', scopeEntity('E1')), scopeAct('A1'), noBooks, parent)).toBe(
      true,
    );
    expect(grantCoversScope(grant('x', scopeBook('B1')), scopeAct('A1'), noBooks, parent)).toBe(
      true,
    );
    expect(grantCoversScope(grant('x', scopeTenant('T2')), scopeAct('A1'), noBooks, parent)).toBe(
      false,
    );
  });

  it('supports every frozen resource leaf and remains narrowing-only', () => {
    const leaves = [
      scopeAct('A1'),
      scopeFolder('F1'),
      scopeTemplateLibrary('L1'),
      scopeArchive('AR1'),
      scopeIntegration('I1'),
      scopeRepository('R1'),
    ];
    for (const leaf of leaves) {
      expect(grantCoversScope(grant('x', leaf), leaf, noBooks)).toBe(true);
      const other = { ...leaf, id: `${leaf.id}-other` };
      expect(grantCoversScope(grant('x', leaf), other, noBooks)).toBe(false);
      expect(grantCoversScope(grant('x', leaf), scopeGlobal, noBooks)).toBe(false);
    }
  });

  it('fails closed for unknown parents, malformed scopes, and cyclic parent graphs', () => {
    const cycle: ScopeParentResolver = (scope) =>
      scope.kind === 'folder' && scope.id === 'F1'
        ? scopeFolder('F2')
        : scope.kind === 'folder' && scope.id === 'F2'
          ? scopeFolder('F1')
          : undefined;
    expect(grantCoversScope(grant('x', scopeEntity('E1')), scopeFolder('F1'), noBooks, cycle)).toBe(
      false,
    );
    expect(
      grantCoversScope(
        grant('x', scopeEntity('E1')),
        scopeFolder('unknown'),
        noBooks,
        () => undefined,
      ),
    ).toBe(false);

    const malformedGrant = grant('x', { kind: 'future_scope', id: 'X' } as never);
    const malformedTarget = { kind: 'act', id: '' } as CanScope;
    expect(grantCoversScope(malformedGrant, scopeAct('A1'), noBooks)).toBe(false);
    expect(grantCoversScope(grant('x', scopeGlobal), malformedTarget, noBooks)).toBe(false);
  });
});

describe('cachedScopeParent — authoritative query-cache relations', () => {
  it('resolves single-resource entity, book, and act parent hops', () => {
    const qc = new QueryClient();
    qc.setQueryData(keys.entity('E1'), { id: 'E1', tenant_id: 'T1' });
    qc.setQueryData(keys.book('B1'), { id: 'B1', entity_id: 'E1' });
    qc.setQueryData(keys.act('A1'), { id: 'A1', book_id: 'B1' });

    expect(cachedScopeParent(qc, scopeEntity('E1'))).toEqual(scopeTenant('T1'));
    expect(cachedScopeParent(qc, scopeBook('B1'))).toEqual(scopeEntity('E1'));
    expect(cachedScopeParent(qc, scopeAct('A1'))).toEqual(scopeBook('B1'));
  });

  it('resolves list DTOs and denies unknown/unsupported resource parents', () => {
    const qc = new QueryClient();
    qc.setQueryData(keys.entities, [{ id: 'E2', tenant_id: 'T2' }]);
    qc.setQueryData(keys.books(), [{ id: 'B2', entity_id: 'E2' }]);
    qc.setQueryData(keys.bookActs('B2'), [{ id: 'A2', book_id: 'B2' }]);

    expect(cachedScopeParent(qc, scopeEntity('E2'))).toEqual(scopeTenant('T2'));
    expect(cachedScopeParent(qc, scopeBook('B2'))).toEqual(scopeEntity('E2'));
    expect(cachedScopeParent(qc, scopeAct('A2'))).toEqual(scopeBook('B2'));
    expect(cachedScopeParent(qc, scopeBook('missing'))).toBeUndefined();
    expect(cachedScopeParent(qc, scopeFolder('F1'))).toBeUndefined();
  });
});

describe('GateButton — disable-with-explanation', () => {
  const OWNER: PermissionGrant[] = [
    grant('entity.create', { kind: 'global' }),
    grant('entity.read', { kind: 'global' }),
  ];
  const LEITOR: PermissionGrant[] = [grant('entity.read', { kind: 'global' })];

  it('an Owner sees the action ENABLED and clickable', () => {
    const onClick = vi.fn();
    renderGate(OWNER, { perm: 'entity.create', onClick });
    const btn = screen.getByRole('button', { name: 'Ação' });
    expect(btn.getAttribute('aria-disabled')).toBeNull();
    fireEvent.click(btn);
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it('a Leitor sees a write DISABLED with an honest tooltip and an inert click', () => {
    const onClick = vi.fn();
    renderGate(LEITOR, { perm: 'entity.create', onClick });
    const btn = screen.getByRole('button', { name: 'Ação' });
    expect(btn.getAttribute('aria-disabled')).toBe('true');
    // The honest explanation is present (W1 tooltip bubble is always mounted).
    expect(screen.getByRole('tooltip').textContent).toContain('Sem permissão para esta ação');
    fireEvent.click(btn);
    expect(onClick).not.toHaveBeenCalled();
  });

  it('a Leitor still passes read checks (reads are not gated away)', () => {
    renderGate(LEITOR, { perm: 'entity.read' });
    const btn = screen.getByRole('button', { name: 'Ação' });
    expect(btn.getAttribute('aria-disabled')).toBeNull();
  });
});

describe('GateButton — scoped Gestor (enabled within scope, disabled outside)', () => {
  // "Gestor" of Encosto Estratégico Lda only: book.open @ entity(E1).
  const GESTOR_E1: PermissionGrant[] = [grant('book.open', { kind: 'entity', id: 'E1' })];
  const books: BookEntityResolver = (b) => (b === 'B1' ? 'E1' : undefined);

  it('enabled inside the granted entity and its book', () => {
    renderGate(GESTOR_E1, { perm: 'book.open', scope: scopeEntity('E1') }, books);
    expect(screen.getByRole('button', { name: 'Ação' }).getAttribute('aria-disabled')).toBeNull();
  });

  it('disabled outside the granted entity', () => {
    renderGate(GESTOR_E1, { perm: 'book.open', scope: scopeEntity('E2') }, books);
    expect(screen.getByRole('button', { name: 'Ação' }).getAttribute('aria-disabled')).toBe('true');
  });

  it('disabled for a Global check (a scoped grant cannot satisfy Global)', () => {
    renderGate(GESTOR_E1, { perm: 'book.open', scope: scopeGlobal }, books);
    expect(screen.getByRole('button', { name: 'Ação' }).getAttribute('aria-disabled')).toBe('true');
  });

  it('anyScope enables a list-level create button for a scoped holder', () => {
    renderGate(GESTOR_E1, { perm: 'book.open', anyScope: true }, books);
    expect(screen.getByRole('button', { name: 'Ação' }).getAttribute('aria-disabled')).toBeNull();
  });
});

describe('honest 403 handling', () => {
  it('ErrorNote renders "sem permissão" for a 403 ApiError, not the raw message', () => {
    render(<ErrorNote error={new ApiError(403, { error: 'forbidden internal detail' })} />);
    expect(screen.getByText('Não tem permissão para realizar esta operação.')).toBeTruthy();
    expect(screen.queryByText('forbidden internal detail')).toBeNull();
  });

  it('ErrorNote still renders a non-403 error message verbatim', () => {
    render(<ErrorNote error={new ApiError(500, { error: 'boom' })} />);
    expect(screen.getByText('boom')).toBeTruthy();
  });
});
