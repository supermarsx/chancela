/**
 * The LIVE `PermissionsProvider`, the one `app/providers` mounts.
 *
 * `permissions.test.tsx` proves the scope algebra and the gate controls, but it feeds them through
 * `valueFromGrants` — a hand-written mirror of the provider, declared to match it "exactly". A
 * mirror is only ever as true as the day it was written: every assertion in that file would still
 * pass if the real provider stopped consulting the query cache for parent scopes, or decided gates
 * before the session had resolved. This file drives the real component.
 *
 * The two properties that matter are both refusals:
 *   - nothing is granted until the session has actually answered (`ready`), so a gate is never
 *     decided from an empty grant list that is merely still loading;
 *   - a scoped grant reaches a child scope ONLY through a parent relation the query cache can
 *     prove. An unproven relation denies.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { PermissionGrant } from '../../api/types';
import { ApiError } from '../../api/client';
import { keys } from '../../api/hooks';
import {
  GateButtonLink,
  PermissionsProvider,
  isPermissionError,
  scopeAct,
  scopeBook,
  scopeEntity,
  scopeGlobal,
  scopeTenant,
  usePermissions,
  type CanScope,
} from './permissions';

const grant = (permission: string, scope: PermissionGrant['scope']): PermissionGrant => ({
  permission,
  scope,
  source: 'role',
});

/** A probe that reports the provider's answers as data attributes, one per checked scope. */
function Probe({ checks }: { checks: { id: string; perm: string; scope?: CanScope }[] }) {
  const { can, canAny, ready, grants } = usePermissions();
  return (
    <ul>
      <li data-testid="ready">{String(ready)}</li>
      <li data-testid="grant-count">{String(grants.length)}</li>
      {checks.map((check) => (
        <li key={check.id} data-testid={check.id}>
          {`${String(can(check.perm, check.scope))}/${String(canAny(check.perm))}`}
        </li>
      ))}
    </ul>
  );
}

/** `true/true` reads as "granted at this scope / holds the permission somewhere". */
function answer(id: string): string {
  return screen.getByTestId(id).textContent ?? '';
}

interface SessionFixture {
  permissions: PermissionGrant[];
  /** Seed the cache instead of leaving the query in flight. */
  resolved?: boolean;
}

function renderProvider(
  session: SessionFixture,
  checks: { id: string; perm: string; scope?: CanScope }[],
  seed?: (qc: QueryClient) => void,
) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  if (session.resolved !== false) {
    qc.setQueryData(keys.session, {
      user: { username: 'amelia.marques' },
      permissions: session.permissions,
    });
  }
  seed?.(qc);
  // A never-settling fetch: the seeded cache is the whole source of truth, and an unseeded
  // provider therefore stays genuinely loading.
  vi.stubGlobal('fetch', (() => new Promise<Response>(() => {})) as typeof fetch);
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <PermissionsProvider>
          <Probe checks={checks} />
        </PermissionsProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return qc;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('PermissionsProvider — the live one', () => {
  it('grants nothing, and is not ready, while the session is still in flight', () => {
    renderProvider({ permissions: [], resolved: false }, [{ id: 'read', perm: 'entity.read' }]);

    // `ready` is the flag a gate must consult: an empty grant list during load is indistinguishable
    // from a genuinely permission-less user, and deciding on it flickers actions in and out.
    expect(answer('ready')).toBe('false');
    expect(answer('read')).toBe('false/false');
  });

  it('is ready with no grants for a resolved anonymous session', () => {
    renderProvider({ permissions: [] }, [{ id: 'read', perm: 'entity.read' }]);

    expect(answer('ready')).toBe('true');
    expect(answer('grant-count')).toBe('0');
    expect(answer('read')).toBe('false/false');
  });

  it("takes its grants from the session's own embedded permission list", () => {
    renderProvider({ permissions: [grant('entity.read', { kind: 'global' })] }, [
      { id: 'read', perm: 'entity.read' },
      { id: 'write', perm: 'entity.update' },
    ]);

    expect(answer('grant-count')).toBe('1');
    expect(answer('read')).toBe('true/true');
    expect(answer('write')).toBe('false/false');
  });

  it('walks an entity grant down to a book ONLY through a cached relation', () => {
    renderProvider(
      { permissions: [grant('act.create', scopeEntity('E1'))] },
      [
        { id: 'in-scope', perm: 'act.create', scope: scopeBook('B1') },
        { id: 'unproven', perm: 'act.create', scope: scopeBook('B-unknown') },
      ],
      (qc) => qc.setQueryData(keys.book('B1'), { id: 'B1', entity_id: 'E1' }),
    );

    expect(answer('in-scope')).toBe('true/true');
    // The book whose owner nothing proves is denied. A wider grant is never guessed from an id.
    expect(answer('unproven')).toBe('false/true');
  });

  it('walks the full tenant → entity → book → act chain from the cache', () => {
    renderProvider(
      { permissions: [grant('act.update', scopeTenant('T1'))] },
      [{ id: 'act', perm: 'act.update', scope: scopeAct('A1') }],
      (qc) => {
        qc.setQueryData(keys.act('A1'), { id: 'A1', book_id: 'B1' });
        qc.setQueryData(keys.book('B1'), { id: 'B1', entity_id: 'E1' });
        qc.setQueryData(keys.entity('E1'), { id: 'E1', tenant_id: 'T1' });
      },
    );

    expect(answer('act')).toBe('true/true');
  });

  it('never lets a scoped grant satisfy a global check, however deep the cache goes', () => {
    renderProvider(
      { permissions: [grant('book.close', scopeEntity('E1'))] },
      [
        { id: 'global', perm: 'book.close', scope: scopeGlobal },
        { id: 'other-entity', perm: 'book.close', scope: scopeEntity('E2') },
      ],
      (qc) => qc.setQueryData(keys.entity('E1'), { id: 'E1', tenant_id: 'T1' }),
    );

    // `canAny` is deliberately scope-blind — it is what a list-level "create" affordance reads —
    // and it must not be mistaken for a global grant by `can`.
    expect(answer('global')).toBe('false/true');
    expect(answer('other-entity')).toBe('false/true');
  });
});

describe('isPermissionError', () => {
  it('is true only for a 403 from the API, never for a 401 or a transport failure', () => {
    expect(isPermissionError(new ApiError(403, { error: 'forbidden' }))).toBe(true);
    // A 401 is a stale session, handled by clearing the token and routing to sign-in — showing
    // "sem permissão" for it would send the operator hunting for a role they already have.
    expect(isPermissionError(new ApiError(401, { error: 'unauthenticated' }))).toBe(false);
    expect(isPermissionError(new ApiError(500, { error: 'boom' }))).toBe(false);
    expect(isPermissionError(new Error('network down'))).toBe(false);
    expect(isPermissionError(null)).toBe(false);
  });
});

describe('GateButtonLink', () => {
  function renderLink(permissions: PermissionGrant[]) {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    qc.setQueryData(keys.session, { user: { username: 'amelia.marques' }, permissions });
    vi.stubGlobal('fetch', (() => new Promise<Response>(() => {})) as typeof fetch);
    return render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <PermissionsProvider>
            <GateButtonLink perm="book.create" to="/books/new">
              Novo livro
            </GateButtonLink>
          </PermissionsProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );
  }

  it('navigates for a holder of the permission', () => {
    renderLink([grant('book.create', { kind: 'global' })]);

    const link = screen.getByRole('link', { name: 'Novo livro' });
    expect(link.getAttribute('href')).toBe('/books/new');
  });

  it('renders an inert, explained control — never a live link — for someone who may not act', () => {
    renderLink([grant('book.read', { kind: 'global' })]);

    expect(screen.queryByRole('link')).toBeNull();
    const blocked = screen.getByRole('button', { name: 'Novo livro' });
    // Focusable and hoverable (so the explanation is reachable by keyboard) but inert, and
    // carrying no destination at all: you cannot navigate to an action you may not perform.
    expect(blocked.getAttribute('aria-disabled')).toBe('true');
    expect(blocked.getAttribute('data-gated')).toBe('true');
    expect(blocked.getAttribute('href')).toBeNull();
    expect(blocked.hasAttribute('disabled')).toBe(false);
  });
});
