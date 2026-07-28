/**
 * The política de retenção record page (t55-e4) —
 * `/settings/privacy/retention-policies/{new,:id}`.
 *
 * The scaffold's own pieces (the four states of the shell, the seed-once draft) are covered by
 * `PrivacyRecordPage.test.tsx`. Covered HERE is what is specific to this page, and both specifics
 * are things that fail silently:
 *
 * 🔴 **The verb is `retention.manage`, not `privacy.manage`.** That difference is the whole point
 * of the t27 granular split: someone trusted to author the RGPD registers is not thereby trusted to
 * schedule the disposal of records. Inheriting the section's gate would reopen exactly that hole,
 * and no test that merely grants everything would ever notice. So the gate is asserted against a
 * principal holding `privacy.manage` and nothing else.
 *
 * 🔴 **An edit route must never seed the form with `EMPTY_RETENTION_FORM`.** A placeholder seed
 * paints a blank form on a real policy's address; the operator edits it; the save writes a NEW
 * policy while the original — with its own schedule and disposal action — stands untouched and
 * still live. On a retention register that is a compliance failure, and it passes every test that
 * only checks "a form rendered" or "a mutation fired". The two observable halves are asserted
 * below: an unresolved edit route offers NOTHING to type into, and a resolved one PATCHES the id
 * in the address without creating anything.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import type { RetentionPolicyView } from '../../../api/types';
import { renderWithProviders } from '../../../test/utils';
import { permissionsValue, StaticPermissionsProvider } from '../../session/permissions';
import { RetentionPolicyPage } from './RetentionPolicyPage';

const hooks = vi.hoisted(() => ({
  policies: { data: [] as unknown[], isLoading: false, error: null as unknown },
  create: { mutateAsync: vi.fn(), isPending: false },
  patch: { mutateAsync: vi.fn(), isPending: false },
  /** Records whether the list query was enabled, so the gate can be proved to fail closed. */
  enabled: vi.fn(),
  /**
   * Re-renders the page as if the list query had just settled. Flipping the fields above changes
   * what the mocked hook returns, but nothing tells React to ask again — and the moment the list
   * settles is precisely where the edit→create bug lives, so it has to be reachable from a test.
   */
  settle: (() => {}) as () => void,
}));

vi.mock('../../../api/hooks', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../api/hooks')>();
  const { useReducer } = await import('react');
  return {
    ...actual,
    usePrivacyRetentionPolicies: (enabled: boolean) => {
      hooks.enabled(enabled);
      const [, bump] = useReducer((n: number) => n + 1, 0);
      hooks.settle = bump as unknown as () => void;
      return hooks.policies;
    },
    useCreatePrivacyRetentionPolicy: () => hooks.create,
    usePatchPrivacyRetentionPolicy: () => hooks.patch,
  };
});

const navigate = vi.hoisted(() => vi.fn());
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => navigate };
});

const policy: RetentionPolicyView = {
  id: 'retention-1',
  name: 'Arquivo de livros encerrados',
  scope: 'book_archive',
  category: 'documents',
  schedule_id: 'legal-10y',
  retention_period: 'P10Y',
  legal_basis: 'Lei do registo comercial',
  disposal_action: 'archive',
  status: 'suspended',
  active: false,
  notes: 'Revisão jurídica manual',
  created_at: '2026-07-01T09:00:00Z',
  created_by: 'amelia.marques',
  updated_at: '2026-07-02T09:00:00Z',
  updated_by: 'amelia.marques',
};

/**
 * Mount the page behind a real route so `useParams` resolves the id from the address.
 *
 * `can` defaults to the granular verb the page actually needs. Passing a different predicate is
 * how the two neighbouring principals below are expressed.
 */
function renderAt(
  path: string,
  can: (permission: string) => boolean = (p) => p === 'retention.manage',
) {
  return renderWithProviders(
    <StaticPermissionsProvider value={permissionsValue(can)}>
      <Routes>
        <Route path="/settings/privacy/retention-policies/new" element={<RetentionPolicyPage />} />
        <Route path="/settings/privacy/retention-policies/:id" element={<RetentionPolicyPage />} />
      </Routes>
    </StaticPermissionsProvider>,
    [path],
  );
}

/** The six fields the form requires before it will submit. */
function fillRequired(overrides: Record<string, string> = {}) {
  const values: Record<string, string> = {
    'Nome da política': 'Arquivo de livros encerrados',
    Âmbito: 'book_archive',
    Categoria: 'documents',
    'Identificador do calendário': 'legal-10y',
    'Período de retenção': 'P10Y',
    'Base legal': 'Lei do registo comercial',
    ...overrides,
  };
  for (const [label, value] of Object.entries(values)) {
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
  }
}

beforeEach(() => {
  hooks.policies.data = [];
  hooks.policies.isLoading = false;
  hooks.policies.error = null;
  for (const m of [hooks.create, hooks.patch]) {
    m.mutateAsync.mockReset().mockResolvedValue({});
    m.isPending = false;
  }
  hooks.enabled.mockReset();
  navigate.mockReset();
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('the create route', () => {
  it('seeds an empty form and creates, titled as a complete pt-PT sentence', async () => {
    renderAt('/settings/privacy/retention-policies/new');

    expect(
      screen.getByRole('heading', { level: 1, name: 'Nova política de retenção' }),
    ).toBeTruthy();
    expect((screen.getByLabelText('Nome da política') as HTMLInputElement).value).toBe('');

    fillRequired();
    fireEvent.click(screen.getByRole('button', { name: 'Criar registo' }));

    await waitFor(() => {
      expect(hooks.create.mutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'Arquivo de livros encerrados',
          schedule_id: 'legal-10y',
          retention_period: 'P10Y',
        }),
      );
    });
    expect(hooks.patch.mutateAsync).not.toHaveBeenCalled();
    await waitFor(() => expect(navigate).toHaveBeenCalledWith('/settings/privacy'));
  });

  it('will not submit until the schedule the disposal depends on is named', () => {
    renderAt('/settings/privacy/retention-policies/new');
    fillRequired({ 'Identificador do calendário': '' });
    expect(
      (screen.getByRole('button', { name: 'Criar registo' }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(hooks.create.mutateAsync).not.toHaveBeenCalled();
  });

  it('keeps the form open and says why when the write is refused', async () => {
    hooks.create.mutateAsync.mockRejectedValueOnce(new Error('escrita recusada'));
    renderAt('/settings/privacy/retention-policies/new');

    fillRequired();
    fireEvent.click(screen.getByRole('button', { name: 'Criar registo' }));

    expect(await screen.findByText('escrita recusada')).toBeTruthy();
    expect((screen.getByLabelText('Nome da política') as HTMLInputElement).value).toBe(
      'Arquivo de livros encerrados',
    );
    expect(navigate).not.toHaveBeenCalled();
  });
});

describe('the edit route', () => {
  it('seeds from the policy the address names and PATCHES it', async () => {
    hooks.policies.data = [policy];
    renderAt('/settings/privacy/retention-policies/retention-1');

    expect(
      screen.getByRole('heading', { level: 1, name: 'Editar política de retenção' }),
    ).toBeTruthy();
    expect((screen.getByLabelText('Nome da política') as HTMLInputElement).value).toBe(
      'Arquivo de livros encerrados',
    );
    // The status enum is this register's own, and the seed carries the record's value, not a default.
    expect((screen.getByLabelText('Estado') as HTMLSelectElement).value).toBe('suspended');

    fireEvent.change(screen.getByLabelText('Período de retenção'), { target: { value: 'P7Y' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar alterações' }));

    await waitFor(() => {
      expect(hooks.patch.mutateAsync).toHaveBeenCalledWith({
        id: 'retention-1',
        body: expect.objectContaining({
          retention_period: 'P7Y',
          status: 'suspended',
          active: false,
        }),
      });
    });
    // 🔴 THE FAILURE THIS PAGE EXISTS TO PREVENT: an edit that quietly creates a SECOND policy and
    // leaves the original live, still disposing of records on its own schedule.
    expect(hooks.create.mutateAsync).not.toHaveBeenCalled();
  });

  it('renders NO form while the list is still resolving, so nothing empty can be typed into', () => {
    hooks.policies.isLoading = true;
    renderAt('/settings/privacy/retention-policies/retention-1');

    // Nothing empty is on screen to type into while the record is still being resolved.
    //
    // ⚠️ On its own this assertion does NOT prove the draft hook received `null` — verified by
    // mutation: seeding `EMPTY_RETENTION_FORM` here leaves this case GREEN, because the shell
    // renders the skeleton on `state === 'loading'` and never reaches the form either way. The
    // case below is the one that actually kills that mutant; this one only covers the paint.
    expect(screen.queryByLabelText('Nome da política')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Guardar alterações' })).toBeNull();
    // The header is already painted, so the page is not a blank screen while it waits.
    expect(
      screen.getByRole('heading', { level: 1, name: 'Editar política de retenção' }),
    ).toBeTruthy();
  });

  it('seeds from the record when the list resolves AFTER the first paint', async () => {
    // 🔴 THE REGRESSION GUARD for the edit→create bug, and the only case that kills it.
    //
    // `usePrivacyRecordDraft` installs the FIRST non-null seed it is handed and ignores every
    // later one — it has to, or a background refetch would discard what the operator has typed.
    // So handing it `EMPTY_RETENTION_FORM` as a placeholder while the list is in flight does not
    // merely paint a blank form for an instant: it POISONS the draft permanently. The list then
    // settles, the shell flips to `ready`, and the operator gets a blank form sitting on a real
    // policy's address, with the record's own schedule, period and legal basis nowhere on screen.
    // Whatever they type is then written over that live policy.
    //
    // Every other case in this file stays green under that mutation, because they each observe
    // one side of the transition and never the transition itself. This one crosses it.
    hooks.policies.isLoading = true;
    hooks.policies.data = [];
    renderAt('/settings/privacy/retention-policies/retention-1');
    expect(screen.queryByLabelText('Nome da política')).toBeNull();

    hooks.policies.isLoading = false;
    hooks.policies.data = [policy];
    act(() => hooks.settle());

    const name = (await screen.findByLabelText('Nome da política')) as HTMLInputElement;
    expect(name.value).toBe('Arquivo de livros encerrados');
    // The record's own values, not the enum defaults `EMPTY_RETENTION_FORM` would have carried.
    expect((screen.getByLabelText('Período de retenção') as HTMLInputElement).value).toBe('P10Y');
    expect((screen.getByLabelText('Estado') as HTMLSelectElement).value).toBe('suspended');
  });

  it('names the register on a stale id instead of falling through to a create form', () => {
    hooks.policies.data = [policy];
    renderAt('/settings/privacy/retention-policies/politica-desaparecida');

    expect(
      screen.getByText('Não foi encontrada nenhuma política de retenção com este identificador.'),
    ).toBeTruthy();
    expect(screen.queryByLabelText('Nome da política')).toBeNull();
    expect(screen.getByRole('link', { name: 'Voltar à privacidade' })).toBeTruthy();
  });

  it('surfaces a list-query failure rather than an empty form', () => {
    hooks.policies.error = new Error('política indisponível');
    renderAt('/settings/privacy/retention-policies/retention-1');

    expect(screen.getByText('política indisponível')).toBeTruthy();
    expect(screen.queryByLabelText('Nome da política')).toBeNull();
  });
});

describe('the permission gate — retention.manage, NOT privacy.manage', () => {
  it('refuses a principal who manages the privacy registers but not retention', () => {
    // 🔒 REGRESSION GUARD for the t27 granular split. This principal can author every other RGPD
    // register; scheduling disposal is a separate grant, and this page is the one that must say so.
    hooks.policies.data = [policy];
    renderAt('/settings/privacy/retention-policies/retention-1', (p) => p === 'privacy.manage');

    expect(screen.getByText('Sem permissão')).toBeTruthy();
    expect(screen.queryByLabelText('Nome da política')).toBeNull();
    // Not even the list query runs: no authoring read, no draft, no late POST.
    expect(hooks.enabled).toHaveBeenCalledWith(false);
  });

  it('admits a principal who holds retention.manage and nothing else', () => {
    hooks.policies.data = [policy];
    renderAt('/settings/privacy/retention-policies/retention-1', (p) => p === 'retention.manage');

    expect(screen.queryByText('Sem permissão')).toBeNull();
    expect(screen.getByLabelText('Nome da política')).toBeTruthy();
    expect(hooks.enabled).toHaveBeenCalledWith(true);
  });

  it('fails closed for a principal holding neither', () => {
    renderAt('/settings/privacy/retention-policies/new', () => false);
    expect(screen.getByText('Sem permissão')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Criar registo' })).toBeNull();
  });
});

describe('the exits', () => {
  it('offers cancel twice — header and form footer — both as addresses, not buttons', () => {
    renderAt('/settings/privacy/retention-policies/new');
    const cancels = screen.getAllByRole('link', { name: 'Cancelar' });
    expect(cancels.length).toBe(2);
    for (const link of cancels) {
      expect(link.getAttribute('href')).toBe('/settings/privacy');
    }
    // `cancelTo`, not `onCancel`: a page's cancel is a navigation the guard can challenge.
    expect(screen.queryByRole('button', { name: 'Cancelar' })).toBeNull();
  });

  it('leads back through the section and the tab, in that order', () => {
    const view = renderAt('/settings/privacy/retention-policies/new');
    const crumbs = within(view.container.querySelector('.page-header') as HTMLElement).getAllByRole(
      'link',
    );
    expect(crumbs.map((a) => a.getAttribute('href'))).toEqual([
      '/settings',
      '/settings/privacy',
      '/settings/privacy',
    ]);
  });
});
