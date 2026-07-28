/**
 * The record page for a procedimento de resposta a violações de dados pessoais (t55-e3).
 *
 * The shell's four states and the seed-once draft are covered by `PrivacyRecordPage.test.tsx`.
 * What is covered HERE is the wiring between them, which is where the one genuinely dangerous
 * failure lives:
 *
 * 🔴 **An edit route must never seed the form with `EMPTY_BREACH_FORM`.** If it does, the page
 * paints a blank form on a real record's address; the operator edits it; and the save writes a NEW
 * procedimento while the original stands untouched. On a compliance register that is a
 * data-protection failure, and it passes every test that only checks "the form rendered" or "a
 * mutation fired". So the tests below assert the two observable halves of it: an unresolved edit
 * route shows NO form at all, and a resolved one PATCHES the id in the address rather than
 * creating anything.
 *
 * The body-shape assertions (list trimming, optional-field semantics, the local-only evidence
 * receipt) moved here from `PrivacyComplianceSection.test.tsx` along with the form itself.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import type { BreachPlaybookView } from '../../../api/types';
import { hasUnsavedChanges } from '../../../hooks/useUnsavedChanges';
import { renderWithProviders } from '../../../test/utils';
import { permissionsValue, StaticPermissionsProvider } from '../../session/permissions';
import { BreachPlaybookPage } from './BreachPlaybookPage';

const hooks = vi.hoisted(() => ({
  breaches: { data: [] as unknown[], isLoading: false, error: null as unknown },
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
    usePrivacyBreachPlaybooks: (enabled: boolean) => {
      hooks.enabled(enabled);
      const [, bump] = useReducer((n: number) => n + 1, 0);
      hooks.settle = bump as unknown as () => void;
      return hooks.breaches;
    },
    useCreatePrivacyBreachPlaybook: () => hooks.create,
    usePatchPrivacyBreachPlaybook: () => hooks.patch,
  };
});

const navigate = vi.hoisted(() => vi.fn());
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => navigate };
});

const breach: BreachPlaybookView = {
  id: 'breach-1',
  title: 'Comprometimento de contas',
  scope: 'serviço de identidade',
  detection_channels: ['SIEM', 'apoio ao cliente'],
  containment_steps: ['Revogar sessões', 'repor credenciais'],
  notification_roles: ['EPD'],
  authority_notification_window: '72 horas quando aplicável',
  subject_notification_guidance: 'Notificar apenas após revisão humana do risco',
  risk_level: 'critical',
  status: 'active',
  review_notes: 'Simulacro anual',
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
      <Route path="/settings/privacy/breach-playbooks/new" element={<BreachPlaybookPage />} />
      <Route path="/settings/privacy/breach-playbooks/:id" element={<BreachPlaybookPage />} />
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

beforeEach(() => {
  hooks.breaches.data = [];
  hooks.breaches.isLoading = false;
  hooks.breaches.error = null;
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
  it('seeds an empty form and refuses to submit until the four required fields are there', async () => {
    renderAt('/settings/privacy/breach-playbooks/new');

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'Novo procedimento de resposta a violações de dados pessoais',
      }),
    ).toBeTruthy();
    expect((screen.getByLabelText('Título do playbook') as HTMLInputElement).value).toBe('');

    const create = screen.getByRole('button', { name: 'Criar registo' }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);

    for (const [label, value] of [
      ['Título do playbook', '  Fuga de ficheiros  '],
      ['Âmbito', '  ficheiros  '],
      ['Canais de deteção', 'DLP, aviso do utilizador'],
      ['Passos de contenção', 'Desativar ligação\nRodar credencial'],
    ] as [string, string][]) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    }
    fireEvent.change(document.getElementById('privacy-breach-new-risk')!, {
      target: { value: 'high' },
    });
    fireEvent.change(document.getElementById('privacy-breach-new-status')!, {
      target: { value: 'under_review' },
    });
    fireEvent.click(create);

    await waitFor(() => {
      expect(hooks.create.mutateAsync).toHaveBeenCalledWith({
        title: 'Fuga de ficheiros',
        scope: 'ficheiros',
        detection_channels: ['DLP', 'aviso do utilizador'],
        containment_steps: ['Desativar ligação', 'Rodar credencial'],
        notification_roles: [],
        // An untouched optional field is ABSENT from the body, not an empty string: the server
        // must be able to tell "not stated" from "stated as nothing".
        authority_notification_window: undefined,
        subject_notification_guidance: undefined,
        risk_level: 'high',
        status: 'under_review',
        review_notes: undefined,
        evidence_receipt: undefined,
      });
    });
    // Nothing is patched on a create route, whatever else happens.
    expect(hooks.patch.mutateAsync).not.toHaveBeenCalled();
    await waitFor(() => expect(navigate).toHaveBeenCalledWith('/settings/privacy'));
  });

  it('files the evidence receipt as a local operator note, claiming nothing', async () => {
    // 🔒 The receipt is the operator's own record that a drill happened. It must never read as a
    // notification to the supervisory authority or to the data subjects.
    renderAt('/settings/privacy/breach-playbooks/new');

    for (const [label, value] of [
      ['Título do playbook', 'Fuga de ficheiros'],
      ['Âmbito', 'ficheiros'],
      ['Canais de deteção', 'DLP'],
      ['Passos de contenção', 'Desativar ligação'],
      ['Tipo de evidência', 'drill'],
      ['Notas de evidência', '  Apenas simulacro do operador.  '],
    ] as [string, string][]) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    }
    fireEvent.click(screen.getByRole('button', { name: 'Criar registo' }));

    await waitFor(() => {
      expect(hooks.create.mutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({
          evidence_receipt: {
            evidence_type: 'drill',
            notes: 'Apenas simulacro do operador.',
            authority_notified: false,
            subjects_notified: false,
          },
        }),
      );
    });
  });

  it('keeps the form open and says why when the write is refused', async () => {
    hooks.create.mutateAsync.mockRejectedValueOnce(new Error('escrita recusada'));
    renderAt('/settings/privacy/breach-playbooks/new');

    for (const [label, value] of [
      ['Título do playbook', 'Fuga de ficheiros'],
      ['Âmbito', 'ficheiros'],
      ['Canais de deteção', 'DLP'],
      ['Passos de contenção', 'Desativar ligação'],
    ] as [string, string][]) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    }
    fireEvent.click(screen.getByRole('button', { name: 'Criar registo' }));

    expect(await screen.findByText('escrita recusada')).toBeTruthy();
    // The operator's eleven fields survive a refusal, and the page does not navigate away.
    expect((screen.getByLabelText('Título do playbook') as HTMLInputElement).value).toBe(
      'Fuga de ficheiros',
    );
    expect(navigate).not.toHaveBeenCalled();
  });
});

describe('the edit route', () => {
  it('seeds from the record the address names and PATCHES it', async () => {
    hooks.breaches.data = [breach];
    renderAt('/settings/privacy/breach-playbooks/breach-1');

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'Editar procedimento de resposta a violações de dados pessoais',
      }),
    ).toBeTruthy();
    expect((screen.getByLabelText('Título do playbook') as HTMLInputElement).value).toBe(
      'Comprometimento de contas',
    );

    fireEvent.change(screen.getByLabelText('Funções notificadas'), {
      target: { value: 'EPD, Responsável de segurança' },
    });
    fireEvent.change(screen.getByLabelText('Tipo de evidência'), { target: { value: 'review' } });
    fireEvent.change(screen.getByLabelText('Notas de evidência'), {
      target: { value: '  Revisto localmente  ' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar alterações' }));

    await waitFor(() => {
      expect(hooks.patch.mutateAsync).toHaveBeenCalledWith({
        id: 'breach-1',
        body: expect.objectContaining({
          notification_roles: ['EPD', 'Responsável de segurança'],
          evidence_receipt: {
            evidence_type: 'review',
            notes: 'Revisto localmente',
            authority_notified: false,
            subjects_notified: false,
          },
        }),
      });
    });
    // 🔴 THE FAILURE THIS PAGE EXISTS TO PREVENT: an edit that quietly creates a second record
    // and leaves the original untouched.
    expect(hooks.create.mutateAsync).not.toHaveBeenCalled();
  });

  it('renders NO form while the list is still resolving, so nothing empty can be typed into', () => {
    hooks.breaches.isLoading = true;
    renderAt('/settings/privacy/breach-playbooks/breach-1');

    // Nothing empty is on screen to type into while the record is still being resolved.
    //
    // ⚠️ On its own this assertion does NOT prove the draft hook received `null` — verified by
    // mutation: seeding `EMPTY_BREACH_FORM` here leaves this case GREEN, because the shell renders
    // the skeleton on `state === 'loading'` and never reaches the form either way. The case below
    // is the one that actually kills that mutant; this one only covers the paint.
    expect(screen.queryByLabelText('Título do playbook')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Criar registo' })).toBeNull();
    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'Editar procedimento de resposta a violações de dados pessoais',
      }),
    ).toBeTruthy();
  });

  it('seeds from the record when the list resolves AFTER the first paint', async () => {
    // 🔴 THE REGRESSION GUARD for the edit→create bug, and the only case here that kills it.
    //
    // `usePrivacyRecordDraft` installs the FIRST non-null seed it is handed and ignores every
    // later one — it has to, or a background refetch would discard what the operator has typed.
    // So handing it `EMPTY_BREACH_FORM` as a placeholder while the list is in flight does not
    // merely paint a blank form for an instant: it POISONS the draft permanently. The list then
    // settles, the shell flips to `ready`, and the operator gets a blank form sitting on a real
    // procedimento's address — its detection channels, containment steps and notification window
    // nowhere on screen — reading CLEAN, because the placeholder became the baseline too. Since
    // `editing` is true, saving then PATCHes those blanks over the live record: the compliance
    // record is not duplicated, it is WIPED.
    //
    // Every other case in this file stays green under that mutation, because they each observe
    // one side of the transition and never the transition itself. This one crosses it, and asserts
    // the record's OWN values — presence of a form after the transition proves nothing, since the
    // poisoned draft renders a form too.
    hooks.breaches.isLoading = true;
    hooks.breaches.data = [];
    renderAt('/settings/privacy/breach-playbooks/breach-1');
    expect(screen.queryByLabelText('Título do playbook')).toBeNull();

    hooks.breaches.isLoading = false;
    hooks.breaches.data = [breach];
    act(() => hooks.settle());

    const title = (await screen.findByLabelText('Título do playbook')) as HTMLInputElement;
    expect(title.value).toBe('Comprometimento de contas');
    expect((screen.getByLabelText('Âmbito') as HTMLInputElement).value).toBe(
      'serviço de identidade',
    );
    expect((screen.getByLabelText('Canais de deteção') as HTMLTextAreaElement).value).toBe(
      'SIEM\napoio ao cliente',
    );
    expect(
      (screen.getByLabelText('Janela de notificação à autoridade') as HTMLInputElement).value,
    ).toBe('72 horas quando aplicável');
    // The record's own enums, not the defaults `EMPTY_BREACH_FORM` carries (`high` / `draft`).
    expect((screen.getByLabelText('Risco') as HTMLSelectElement).value).toBe('critical');
    expect((screen.getByLabelText('Estado') as HTMLSelectElement).value).toBe('active');
    // The draft is also CLEAN, so a seeded edit page does not challenge the operator's first exit.
    // Note this line does NOT discriminate the mutant — a poisoned draft is clean too, because the
    // placeholder became the baseline. It is here as a correctness claim, not as the guard.
    expect(hasUnsavedChanges()).toBe(false);
  });

  it('names the register on a stale id instead of falling through to a create form', () => {
    hooks.breaches.data = [breach];
    renderAt('/settings/privacy/breach-playbooks/procedimento-desaparecido');

    expect(
      screen.getByText(
        'Não foi encontrado nenhum procedimento de resposta a violações de dados pessoais com este identificador.',
      ),
    ).toBeTruthy();
    expect(screen.queryByLabelText('Título do playbook')).toBeNull();
    expect(screen.getByRole('link', { name: 'Voltar à privacidade' })).toBeTruthy();
  });

  it('surfaces a list-query failure rather than an empty form', () => {
    hooks.breaches.error = new Error('registo indisponível');
    renderAt('/settings/privacy/breach-playbooks/breach-1');

    expect(screen.getByText('registo indisponível')).toBeTruthy();
    expect(screen.queryByLabelText('Título do playbook')).toBeNull();
  });
});

describe('the permission gate', () => {
  it('fails closed on privacy.manage, because a direct URL bypasses the list affordances', () => {
    hooks.breaches.data = [breach];
    renderAt('/settings/privacy/breach-playbooks/breach-1', false);

    expect(screen.getByText('Sem permissão')).toBeTruthy();
    expect(screen.queryByLabelText('Título do playbook')).toBeNull();
    // Not even the list query runs: no authoring read, no draft, no late POST.
    expect(hooks.enabled).toHaveBeenCalledWith(false);
  });
});

describe('the exits', () => {
  it('offers cancel twice — in the header and in the form footer — both as addresses', () => {
    renderAt('/settings/privacy/breach-playbooks/new');
    const cancels = screen.getAllByRole('link', { name: 'Cancelar' });
    expect(cancels.length).toBe(2);
    for (const link of cancels) {
      expect(link.getAttribute('href')).toBe('/settings/privacy');
    }
    // A page's cancel is an address, never a button — that is what lets the unsaved-changes guard
    // challenge it and what makes it middle-clickable.
    expect(screen.queryByRole('button', { name: 'Cancelar' })).toBeNull();
  });

  it('leads back through the section and the tab, in that order', () => {
    const view = renderAt('/settings/privacy/breach-playbooks/new');
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
