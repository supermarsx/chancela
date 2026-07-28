/**
 * The two register-shaped record pages (t55-e2): the registo de atividades de tratamento and the
 * AIPD.
 *
 * The scaffold's own pieces — the four states of the shell, the seed-once draft — are covered by
 * `PrivacyRecordPage.test.tsx`. What is covered HERE is the wiring between them, which is where the
 * one genuinely dangerous failure lives:
 *
 * 🔴 **An edit route must never seed the form with `EMPTY_FORM`.** If it does, the page paints a
 * blank form on a real record's address; the operator edits it; and the save writes a NEW record
 * while the original stands untouched. On a compliance register that is a data-protection failure,
 * and it passes every test that only checks "the form rendered" or "a mutation fired". So the tests
 * below assert the two observable halves of it: an unresolved edit route shows NO form at all, and a
 * resolved one PATCHES the id in the address rather than creating anything.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import type { DpiaRecordView, ProcessorRecordView } from '../../../api/types';
import { renderWithProviders } from '../../../test/utils';
import { permissionsValue, StaticPermissionsProvider } from '../../session/permissions';
import { DpiaRecordPage, ProcessorRecordPage } from './RegisterRecordPage';

const hooks = vi.hoisted(() => {
  const query = () => ({ data: [] as unknown[], isLoading: false, error: null as unknown });
  const mutation = () => ({ mutateAsync: vi.fn(), isPending: false });
  return {
    processors: query(),
    dpias: query(),
    createProcessor: mutation(),
    patchProcessor: mutation(),
    createDpia: mutation(),
    patchDpia: mutation(),
    /** Records which list query was enabled, so the permission gate can be proved to fail closed. */
    enabled: vi.fn(),
  };
});

vi.mock('../../../api/hooks', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../api/hooks')>();
  return {
    ...actual,
    usePrivacyProcessors: (enabled: boolean) => {
      hooks.enabled('processors', enabled);
      return hooks.processors;
    },
    usePrivacyDpias: (enabled: boolean) => {
      hooks.enabled('dpias', enabled);
      return hooks.dpias;
    },
    useCreatePrivacyProcessor: () => hooks.createProcessor,
    usePatchPrivacyProcessor: () => hooks.patchProcessor,
    useCreatePrivacyDpia: () => hooks.createDpia,
    usePatchPrivacyDpia: () => hooks.patchDpia,
  };
});

const navigate = vi.hoisted(() => vi.fn());
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => navigate };
});

const processor: ProcessorRecordView = {
  id: 'processor-1',
  name: 'Encosto Estratégico Lda',
  purpose: 'Alojamento na UE',
  legal_basis: 'Contrato',
  data_categories: ['Identificação', 'Contacto'],
  subprocessors: ['Amélia Marques'],
  risk_level: 'low',
  status: 'draft',
  created_at: '2026-07-01T09:00:00Z',
  created_by: 'amelia.marques',
  updated_at: '2026-07-02T09:00:00Z',
  updated_by: 'amelia.marques',
};

const dpia: DpiaRecordView = {
  id: 'dpia-1',
  title: 'Definição de perfis de risco elevado',
  purpose: 'Pontuação de risco',
  legal_basis: 'Interesse legítimo',
  data_categories: ['Comportamento'],
  subprocessors: [],
  risk_level: 'high',
  status: 'active',
  evidence_receipts: [],
  advisory_review: {
    status: 'current',
    last_reviewed_at: '2026-07-01T10:00:00Z',
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
    authority_filing_claimed: false,
    legal_acceptance_claimed: false,
    legal_certification_claimed: false,
    external_delivery_claimed: false,
    completion_claimed: false,
    compliance_certification_claimed: false,
  },
  created_at: '2026-07-01T09:00:00Z',
  created_by: 'amelia.marques',
  updated_at: '2026-07-02T09:00:00Z',
  updated_by: 'amelia.marques',
};

/** Mount a page behind a real route so `useParams` resolves the id from the address. */
function renderAt(path: string, allowed = true) {
  const routes = (
    <Routes>
      <Route path="/settings/privacy/processors/new" element={<ProcessorRecordPage />} />
      <Route path="/settings/privacy/processors/:id" element={<ProcessorRecordPage />} />
      <Route path="/settings/privacy/dpias/new" element={<DpiaRecordPage />} />
      <Route path="/settings/privacy/dpias/:id" element={<DpiaRecordPage />} />
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
  for (const query of [hooks.processors, hooks.dpias]) {
    query.data = [];
    query.isLoading = false;
    query.error = null;
  }
  for (const m of [hooks.createProcessor, hooks.patchProcessor, hooks.createDpia, hooks.patchDpia]) {
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
  it('seeds an empty form and creates, naming the register in pt-PT', async () => {
    renderAt('/settings/privacy/processors/new');

    expect(
      screen.getByRole('heading', { level: 1, name: 'Novo registo de atividades de tratamento' }),
    ).toBeTruthy();
    expect((screen.getByLabelText('Nome do processador') as HTMLInputElement).value).toBe('');

    for (const [label, value] of [
      ['Nome do processador', 'Encosto Estratégico Lda'],
      ['Finalidade', 'Alojamento'],
      ['Base legal', 'Contrato'],
      ['Categorias de dados', 'Identificação'],
    ] as [string, string][]) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    }
    fireEvent.click(screen.getByRole('button', { name: 'Criar registo' }));

    await waitFor(() => {
      expect(hooks.createProcessor.mutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'Encosto Estratégico Lda',
          data_categories: ['Identificação'],
        }),
      );
    });
    // Nothing is patched on a create route, whatever else happens.
    expect(hooks.patchProcessor.mutateAsync).not.toHaveBeenCalled();
    await waitFor(() => expect(navigate).toHaveBeenCalledWith('/settings/privacy'));
  });

  it('titles the AIPD as a complete sentence of its own, not an interpolated noun', () => {
    renderAt('/settings/privacy/dpias/new');
    expect(screen.getByRole('heading', { level: 1, name: 'Nova AIPD' })).toBeTruthy();
  });

  it('files the DPIA evidence receipt in the create body, claiming nothing', async () => {
    // This body shape used to be asserted from the settings tab, back when the editor was a modal
    // living inside it. The form moved here, so the assertion moved with it. The six completion
    // flags matter: an operator's local drill receipt must not read as an authority filing, a
    // legal certification or a completed DPIA.
    renderAt('/settings/privacy/dpias/new');

    for (const [label, value] of [
      ['Título da DPIA', 'AIPD de entrada biométrica'],
      ['Finalidade', 'Entrada segura no edifício'],
      ['Base legal', 'Interesse legítimo'],
      ['Categorias de dados', 'Identificação\nDados biométricos'],
      ['Subprocessadores', 'Encosto Estratégico Lda'],
      ['Tipo de evidência', 'drill'],
      ['Notas de evidência', 'Apenas simulacro do operador.'],
    ] as [string, string][]) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    }
    fireEvent.click(screen.getByRole('button', { name: 'Criar registo' }));

    await waitFor(() => {
      expect(hooks.createDpia.mutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'AIPD de entrada biométrica',
          purpose: 'Entrada segura no edifício',
          legal_basis: 'Interesse legítimo',
          data_categories: ['Identificação', 'Dados biométricos'],
          subprocessors: ['Encosto Estratégico Lda'],
          status: 'draft',
          evidence_receipt: {
            evidence_type: 'drill',
            notes: 'Apenas simulacro do operador.',
            authority_filing_completed: false,
            legal_review_accepted: false,
            legal_certification_completed: false,
            external_delivery_completed: false,
            dpia_completed: false,
            compliance_certification_completed: false,
          },
        }),
      );
    });
  });

  it('keeps the form open and says why when the write is refused', async () => {
    hooks.createDpia.mutateAsync.mockRejectedValueOnce(new Error('escrita recusada'));
    renderAt('/settings/privacy/dpias/new');

    for (const [label, value] of [
      ['Título da DPIA', 'Perfis'],
      ['Finalidade', 'Pontuação'],
      ['Base legal', 'Consentimento'],
      ['Categorias de dados', 'Comportamento'],
    ] as [string, string][]) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    }
    fireEvent.click(screen.getByRole('button', { name: 'Criar registo' }));

    expect(await screen.findByText('escrita recusada')).toBeTruthy();
    // The operator's nine fields survive a refusal, and the page does not navigate away.
    expect((screen.getByLabelText('Título da DPIA') as HTMLInputElement).value).toBe('Perfis');
    expect(navigate).not.toHaveBeenCalled();
  });
});

describe('the edit route', () => {
  it('seeds from the record the address names and PATCHES it', async () => {
    hooks.dpias.data = [dpia];
    renderAt('/settings/privacy/dpias/dpia-1');

    expect(screen.getByRole('heading', { level: 1, name: 'Editar AIPD' })).toBeTruthy();
    expect((screen.getByLabelText('Título da DPIA') as HTMLInputElement).value).toBe(
      'Definição de perfis de risco elevado',
    );

    fireEvent.change(screen.getByLabelText('Finalidade'), {
      target: { value: 'Pontuação revista' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar alterações' }));

    await waitFor(() => {
      expect(hooks.patchDpia.mutateAsync).toHaveBeenCalledWith({
        id: 'dpia-1',
        body: expect.objectContaining({ purpose: 'Pontuação revista' }),
      });
    });
    // 🔴 THE FAILURE THIS PAGE EXISTS TO PREVENT: an edit that quietly creates a second record
    // and leaves the original untouched.
    expect(hooks.createDpia.mutateAsync).not.toHaveBeenCalled();
  });

  it('files a review receipt on patch, still claiming nothing', async () => {
    hooks.dpias.data = [dpia];
    renderAt('/settings/privacy/dpias/dpia-1');

    fireEvent.change(screen.getByLabelText('Notas de evidência'), {
      target: { value: 'Revisão local de seguimento.' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar alterações' }));

    await waitFor(() => {
      expect(hooks.patchDpia.mutateAsync).toHaveBeenCalledWith({
        id: 'dpia-1',
        body: expect.objectContaining({
          evidence_receipt: {
            evidence_type: 'review',
            notes: 'Revisão local de seguimento.',
            authority_filing_completed: false,
            legal_review_accepted: false,
            legal_certification_completed: false,
            external_delivery_completed: false,
            dpia_completed: false,
            compliance_certification_completed: false,
          },
        }),
      });
    });
  });

  it('patches the OTHER register through its own mutation, never the DPIA one', async () => {
    // The two pages are one module behind a `kind` discriminant. A crossed wire here would send a
    // processor edit to `/v1/privacy/dpias`, so both halves are driven, not just one.
    hooks.processors.data = [processor];
    renderAt('/settings/privacy/processors/processor-1');

    expect((screen.getByLabelText('Nome do processador') as HTMLInputElement).value).toBe(
      'Encosto Estratégico Lda',
    );
    fireEvent.change(screen.getByLabelText('Base legal'), { target: { value: 'Consentimento' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar alterações' }));

    await waitFor(() => {
      expect(hooks.patchProcessor.mutateAsync).toHaveBeenCalledWith({
        id: 'processor-1',
        body: expect.objectContaining({ legal_basis: 'Consentimento' }),
      });
    });
    expect(hooks.patchDpia.mutateAsync).not.toHaveBeenCalled();
    expect(hooks.createProcessor.mutateAsync).not.toHaveBeenCalled();
  });

  it('renders NO form while the list is still resolving, so nothing empty can be typed into', () => {
    hooks.processors.isLoading = true;
    renderAt('/settings/privacy/processors/processor-1');

    // 🔴 REGRESSION GUARD for the edit→create bug. Handing `EMPTY_FORM` to the draft hook as a
    // placeholder here would paint a blank form on a real record's address, and the save would
    // write a NEW record. The page must show the operator nothing to type into until the record
    // it is addressing has actually resolved.
    expect(screen.queryByLabelText('Nome do processador')).toBeNull();
    expect(screen.getByRole('heading', { level: 1, name: 'Editar registo de atividades de tratamento' })).toBeTruthy();
  });

  it('names the register on a stale id instead of falling through to a create form', () => {
    hooks.dpias.data = [dpia];
    renderAt('/settings/privacy/dpias/dpia-desaparecida');

    expect(
      screen.getByText('Não foi encontrada nenhuma AIPD com este identificador.'),
    ).toBeTruthy();
    expect(screen.queryByLabelText('Título da DPIA')).toBeNull();
    expect(screen.getByRole('link', { name: 'Voltar à privacidade' })).toBeTruthy();
  });

  it('surfaces a list-query failure rather than an empty form', () => {
    hooks.processors.error = new Error('registo indisponível');
    renderAt('/settings/privacy/processors/processor-1');

    expect(screen.getByText('registo indisponível')).toBeTruthy();
    expect(screen.queryByLabelText('Nome do processador')).toBeNull();
  });
});

describe('the permission gate', () => {
  it('fails closed on privacy.manage, because a direct URL bypasses the list affordances', () => {
    hooks.dpias.data = [dpia];
    renderAt('/settings/privacy/dpias/dpia-1', false);

    expect(screen.getByText('Sem permissão')).toBeTruthy();
    expect(screen.queryByLabelText('Título da DPIA')).toBeNull();
    // Not even the list query runs: no authoring read, no draft, no late POST.
    expect(hooks.enabled).toHaveBeenCalledWith('dpias', false);
  });
});

describe('the DPIA-only evidence block', () => {
  it('is present on the AIPD and absent from the registo de atividades de tratamento', () => {
    renderAt('/settings/privacy/dpias/new');
    expect(screen.getByLabelText('Tipo de evidência')).toBeTruthy();

    cleanup();
    renderAt('/settings/privacy/processors/new');
    expect(screen.queryByLabelText('Tipo de evidência')).toBeNull();
  });
});

describe('the exits', () => {
  it('offers cancel twice — in the header and in the form footer — both as addresses', () => {
    renderAt('/settings/privacy/dpias/new');
    const cancels = screen.getAllByRole('link', { name: 'Cancelar' });
    expect(cancels.length).toBe(2);
    for (const link of cancels) {
      expect(link.getAttribute('href')).toBe('/settings/privacy');
    }
  });

  it('leads back through the section and the tab, in that order', () => {
    const view = renderAt('/settings/privacy/processors/new');
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
