/**
 * The record page for a controlo de transferência (t55-e3).
 *
 * The shell's four states and the seed-once draft are covered by `PrivacyRecordPage.test.tsx`.
 * What is covered HERE is the wiring, and the one genuinely dangerous failure it can hide:
 *
 * 🔴 **An edit route must never seed the form with `EMPTY_TRANSFER_FORM`.** If it does, the page
 * paints a blank form on a real record's address; the operator edits it; and the save writes a NEW
 * controlo while the original stands untouched. On a RGPD Cap. V transfer register that is a
 * data-protection failure, and it passes every test that only checks "the form rendered" or "a
 * mutation fired". So the tests below assert the two observable halves of it: an unresolved edit
 * route shows NO form at all, and a resolved one PATCHES the id in the address.
 *
 * The body-shape assertions moved here from `PrivacyComplianceSection.test.tsx` with the form.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import type { TransferControlView } from '../../../api/types';
import { hasUnsavedChanges } from '../../../hooks/useUnsavedChanges';
import { renderWithProviders } from '../../../test/utils';
import { permissionsValue, StaticPermissionsProvider } from '../../session/permissions';
import { TransferControlPage } from './TransferControlPage';

const hooks = vi.hoisted(() => ({
  transfers: { data: [] as unknown[], isLoading: false, error: null as unknown },
  create: { mutateAsync: vi.fn(), isPending: false },
  patch: { mutateAsync: vi.fn(), isPending: false },
  /** Records whether the list query was enabled, so the permission gate can be proved fail-closed. */
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
    usePrivacyTransferControls: (enabled: boolean) => {
      hooks.enabled(enabled);
      const [, bump] = useReducer((n: number) => n + 1, 0);
      hooks.settle = bump as unknown as () => void;
      return hooks.transfers;
    },
    useCreatePrivacyTransferControl: () => hooks.create,
    usePatchPrivacyTransferControl: () => hooks.patch,
  };
});

const navigate = vi.hoisted(() => vi.fn());
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => navigate };
});

const transfer: TransferControlView = {
  id: 'transfer-1',
  name: 'Acesso de apoio no Reino Unido',
  purpose: 'Investigação de casos',
  legal_basis: 'Contrato',
  data_categories: ['Mensagens de apoio'],
  recipient: 'Encosto Estratégico Lda',
  destination_country: 'Reino Unido',
  transfer_mechanism: 'Decisão de adequação',
  safeguards: ['Acesso limitado ao pedido'],
  risk_level: 'medium',
  status: 'retired',
  review_notes: 'Revisão trimestral',
  evidence_receipts: [],
  advisory_review: {
    status: 'no_receipt',
    next_review_due_at: '2027-07-01',
    days_until_due: 350,
    review_interval_days: 365,
    receipt_count: 0,
    review_receipt_count: 0,
    drill_receipt_count: 0,
    local_advisory_only: true,
    authority_notification_claimed: false,
    subject_notification_claimed: false,
    transfer_approval_claimed: false,
    transfer_execution_claimed: false,
    external_delivery_configured: false,
    legal_completion_claimed: false,
  },
  created_at: '2026-07-01T09:00:00Z',
  created_by: 'amelia.marques',
  updated_at: '2026-07-02T09:00:00Z',
  updated_by: 'amelia.marques',
};

/** Mount the page behind a real route so `useParams` resolves the id from the address. */
function renderAt(path: string, allowed = true) {
  const routes = (
    <Routes>
      <Route path="/settings/privacy/transfer-controls/new" element={<TransferControlPage />} />
      <Route path="/settings/privacy/transfer-controls/:id" element={<TransferControlPage />} />
    </Routes>
  );
  return renderWithProviders(
    allowed ? (
      routes
    ) : (
      <StaticPermissionsProvider value={permissionsValue(() => false)}>
        {routes}
      </StaticPermissionsProvider>
    ),
    [path],
  );
}

const REQUIRED: [string, string][] = [
  ['Nome do controlo', 'Apoio a incidentes nos EUA'],
  ['Finalidade', 'Resposta a incidentes'],
  ['Base legal', 'CCT'],
  ['Categorias de dados', 'Mensagens de apoio'],
  ['Destinatário', 'Encosto Estratégico Lda'],
  ['País de destino', 'Estados Unidos'],
  ['Mecanismo de transferência', 'CCT 2021'],
  ['Salvaguardas', 'MFA, âmbito do pedido'],
];

beforeEach(() => {
  hooks.transfers.data = [];
  hooks.transfers.isLoading = false;
  hooks.transfers.error = null;
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
  it('seeds an empty form and refuses to submit until every required field is there', async () => {
    renderAt('/settings/privacy/transfer-controls/new');

    expect(
      screen.getByRole('heading', { level: 1, name: 'Novo controlo de transferência' }),
    ).toBeTruthy();
    expect((screen.getByLabelText('Nome do controlo') as HTMLInputElement).value).toBe('');

    const create = screen.getByRole('button', { name: 'Criar registo' }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);

    for (const [label, value] of REQUIRED) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    }
    fireEvent.click(create);

    await waitFor(() => {
      expect(hooks.create.mutateAsync).toHaveBeenCalledWith({
        name: 'Apoio a incidentes nos EUA',
        purpose: 'Resposta a incidentes',
        legal_basis: 'CCT',
        data_categories: ['Mensagens de apoio'],
        recipient: 'Encosto Estratégico Lda',
        destination_country: 'Estados Unidos',
        transfer_mechanism: 'CCT 2021',
        safeguards: ['MFA', 'âmbito do pedido'],
        risk_level: 'medium',
        status: 'draft',
        // Untouched optional fields are ABSENT from the body, not empty strings.
        review_notes: undefined,
        evidence_receipt: undefined,
      });
    });
    expect(hooks.patch.mutateAsync).not.toHaveBeenCalled();
    await waitFor(() => expect(navigate).toHaveBeenCalledWith('/settings/privacy'));
  });

  it('files the evidence receipt as a local operator note, claiming nothing', async () => {
    // 🔒 The receipt records that the operator reviewed the control locally. It must never read as
    // an approval of the transfer, nor as evidence that data was actually transferred.
    renderAt('/settings/privacy/transfer-controls/new');

    for (const [label, value] of REQUIRED) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    }
    fireEvent.change(screen.getByLabelText('Notas de evidência'), {
      target: { value: '  Comprovativo de revisão  ' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Criar registo' }));

    await waitFor(() => {
      expect(hooks.create.mutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({
          evidence_receipt: {
            notes: 'Comprovativo de revisão',
            transfer_approved: false,
            data_transfer_executed: false,
          },
        }),
      );
    });
  });

  it('keeps the form open and says why when the write is refused', async () => {
    hooks.create.mutateAsync.mockRejectedValueOnce(new Error('escrita recusada'));
    renderAt('/settings/privacy/transfer-controls/new');

    for (const [label, value] of REQUIRED) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    }
    fireEvent.click(screen.getByRole('button', { name: 'Criar registo' }));

    expect(await screen.findByText('escrita recusada')).toBeTruthy();
    expect((screen.getByLabelText('Nome do controlo') as HTMLInputElement).value).toBe(
      'Apoio a incidentes nos EUA',
    );
    expect(navigate).not.toHaveBeenCalled();
  });
});

describe('the edit route', () => {
  it('seeds from the record the address names and PATCHES it', async () => {
    hooks.transfers.data = [transfer];
    renderAt('/settings/privacy/transfer-controls/transfer-1');

    expect(
      screen.getByRole('heading', { level: 1, name: 'Editar controlo de transferência' }),
    ).toBeTruthy();
    expect((screen.getByLabelText('Nome do controlo') as HTMLInputElement).value).toBe(
      'Acesso de apoio no Reino Unido',
    );

    fireEvent.change(screen.getByLabelText('Salvaguardas'), {
      target: { value: 'Acesso limitado ao pedido\nMFA' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar alterações' }));

    await waitFor(() => {
      expect(hooks.patch.mutateAsync).toHaveBeenCalledWith({
        id: 'transfer-1',
        body: expect.objectContaining({
          safeguards: ['Acesso limitado ao pedido', 'MFA'],
          review_notes: 'Revisão trimestral',
        }),
      });
    });
    // 🔴 THE FAILURE THIS PAGE EXISTS TO PREVENT.
    expect(hooks.create.mutateAsync).not.toHaveBeenCalled();
  });

  it('renders NO form while the list is still resolving, so nothing empty can be typed into', () => {
    hooks.transfers.isLoading = true;
    renderAt('/settings/privacy/transfer-controls/transfer-1');

    // Nothing empty is on screen to type into while the record is still being resolved.
    //
    // ⚠️ On its own this assertion does NOT prove the draft hook received `null` — verified by
    // mutation: seeding `EMPTY_TRANSFER_FORM` here leaves this case GREEN, because the shell
    // renders the skeleton on `state === 'loading'` and never reaches the form either way. The
    // case below is the one that actually kills that mutant; this one only covers the paint.
    expect(screen.queryByLabelText('Nome do controlo')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Criar registo' })).toBeNull();
    expect(
      screen.getByRole('heading', { level: 1, name: 'Editar controlo de transferência' }),
    ).toBeTruthy();
  });

  it('seeds from the record when the list resolves AFTER the first paint', async () => {
    // 🔴 THE REGRESSION GUARD for the edit→create bug, and the only case here that kills it.
    //
    // `usePrivacyRecordDraft` installs the FIRST non-null seed it is handed and ignores every
    // later one — it has to, or a background refetch would discard what the operator has typed.
    // So handing it `EMPTY_TRANSFER_FORM` as a placeholder while the list is in flight does not
    // merely paint a blank form for an instant: it POISONS the draft permanently. The list then
    // settles, the shell flips to `ready`, and the operator gets a blank form on a real controlo's
    // address — its recipient, destination country, transfer mechanism and safeguards nowhere on
    // screen — reading CLEAN, because the placeholder became the baseline too. Since `editing` is
    // true, saving then PATCHes those blanks over the live record: the RGPD Cap. V transfer
    // control is not duplicated, it is WIPED.
    //
    // Every other case in this file stays green under that mutation, because they each observe one
    // side of the transition and never the transition itself. This one crosses it, and asserts the
    // record's OWN values — presence of a form after the transition proves nothing, since the
    // poisoned draft renders a form too.
    hooks.transfers.isLoading = true;
    hooks.transfers.data = [];
    renderAt('/settings/privacy/transfer-controls/transfer-1');
    expect(screen.queryByLabelText('Nome do controlo')).toBeNull();

    hooks.transfers.isLoading = false;
    hooks.transfers.data = [transfer];
    act(() => hooks.settle());

    const name = (await screen.findByLabelText('Nome do controlo')) as HTMLInputElement;
    expect(name.value).toBe('Acesso de apoio no Reino Unido');
    expect((screen.getByLabelText('Destinatário') as HTMLInputElement).value).toBe(
      'Encosto Estratégico Lda',
    );
    expect((screen.getByLabelText('País de destino') as HTMLInputElement).value).toBe(
      'Reino Unido',
    );
    expect((screen.getByLabelText('Mecanismo de transferência') as HTMLInputElement).value).toBe(
      'Decisão de adequação',
    );
    expect((screen.getByLabelText('Salvaguardas') as HTMLTextAreaElement).value).toBe(
      'Acesso limitado ao pedido',
    );
    // The record's own status, not the `draft` default `EMPTY_TRANSFER_FORM` carries.
    expect((screen.getByLabelText('Estado') as HTMLSelectElement).value).toBe('retired');
    // The draft is also CLEAN, so a seeded edit page does not challenge the operator's first exit.
    // Note this line does NOT discriminate the mutant — a poisoned draft is clean too, because the
    // placeholder became the baseline. It is here as a correctness claim, not as the guard.
    expect(hasUnsavedChanges()).toBe(false);
  });

  it('names the register on a stale id instead of falling through to a create form', () => {
    hooks.transfers.data = [transfer];
    renderAt('/settings/privacy/transfer-controls/controlo-desaparecido');

    expect(
      screen.getByText(
        'Não foi encontrado nenhum controlo de transferência com este identificador.',
      ),
    ).toBeTruthy();
    expect(screen.queryByLabelText('Nome do controlo')).toBeNull();
    expect(screen.getByRole('link', { name: 'Voltar à privacidade' })).toBeTruthy();
  });

  it('surfaces a list-query failure rather than an empty form', () => {
    hooks.transfers.error = new Error('registo indisponível');
    renderAt('/settings/privacy/transfer-controls/transfer-1');

    expect(screen.getByText('registo indisponível')).toBeTruthy();
    expect(screen.queryByLabelText('Nome do controlo')).toBeNull();
  });
});

describe('the permission gate', () => {
  it('fails closed on privacy.manage, because a direct URL bypasses the list affordances', () => {
    hooks.transfers.data = [transfer];
    renderAt('/settings/privacy/transfer-controls/transfer-1', false);

    expect(screen.getByText('Sem permissão')).toBeTruthy();
    expect(screen.queryByLabelText('Nome do controlo')).toBeNull();
    expect(hooks.enabled).toHaveBeenCalledWith(false);
  });
});

describe('the exits', () => {
  it('offers cancel twice — in the header and in the form footer — both as addresses', () => {
    renderAt('/settings/privacy/transfer-controls/new');
    const cancels = screen.getAllByRole('link', { name: 'Cancelar' });
    expect(cancels.length).toBe(2);
    for (const link of cancels) {
      expect(link.getAttribute('href')).toBe('/settings/privacy');
    }
    expect(screen.queryByRole('button', { name: 'Cancelar' })).toBeNull();
  });

  it('leads back through the section and the tab, in that order', () => {
    const view = renderAt('/settings/privacy/transfer-controls/new');
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
