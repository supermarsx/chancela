/**
 * The DPIA guidance MODEL editor at `/settings/privacy/dpia-template/edit`.
 *
 * Four things are load-bearing here, and each has a failure mode that passes a naive
 * "the form rendered" test:
 *
 * 🔴 **The shipped body must seed TRANSLATED.** Its wire copy is English and the guidance panel
 *    resolves the stable ids through the catalog, so a Portuguese reader sees Portuguese. Seeding
 *    the form from the raw wire would hand that reader an English form the moment they clicked
 *    Edit — the copy they were reading would silently vanish.
 *
 * 🔴 **An operator body must NOT go through the catalog.** Its ids were typed here. One that
 *    happened to collide with a shipped id would render the shipped Portuguese string in place of
 *    what the operator wrote, so their edit would appear to have done nothing.
 *
 * 🔒 **`no_claims` must never leave this page.** The 28 flags name legal claims the product does
 *    not make. `PutDpiaTemplateBody` has no such member and the server refuses one; the test below
 *    asserts the actual bytes the client sends carry none.
 *
 * 🔴 **Reset is offered only when there is an override to discard**, and it goes through a
 *    confirmation naming what is replaced.
 *
 * Assertions are on catalog KEYS and on wire values, never on translated substrings: the pt-PT
 * wording of this register has already moved once (DPIA→AIPD) with no change to the page.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import type {
  DpiaTemplateNoClaims,
  DpiaTemplateView,
  PutDpiaTemplateBody,
} from '../../../api/types';
import { dpiaTemplateEditorPtPT } from '../../../i18n/dpiaTemplateEditorFallback';
import { ptPT } from '../../../i18n/locales/pt-PT';
import { renderWithProviders } from '../../../test/utils';
import { permissionsValue, StaticPermissionsProvider } from '../../session/permissions';
import { DpiaTemplatePage } from './DpiaTemplatePage';

const hooks = vi.hoisted(() => ({
  template: {
    data: null as unknown,
    isLoading: false,
    error: null as unknown,
  },
  save: { mutateAsync: vi.fn(), isPending: false },
  reset: { mutateAsync: vi.fn(), isPending: false },
  /** Records whether the read query was enabled, so the permission gate can be proved fail-closed. */
  enabled: vi.fn(),
}));

vi.mock('../../../api/hooks', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../api/hooks')>();
  return {
    ...actual,
    usePrivacyDpiaTemplate: (enabled: boolean) => {
      hooks.enabled(enabled);
      return hooks.template;
    },
    usePutPrivacyDpiaTemplate: () => hooks.save,
    useResetPrivacyDpiaTemplate: () => hooks.reset,
  };
});

const navigate = vi.hoisted(() => vi.fn());
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => navigate };
});

const NO_CLAIMS_FLAGS = [
  'authority_filing_completed',
  'authority_approval_obtained',
  'cnpd_filing_completed',
  'edpb_filing_completed',
  'cnpd_or_edpb_approval_obtained',
  'legal_review_accepted',
  'legal_validation_completed',
  'external_validation_completed',
  'external_legal_validation_completed',
  'external_delivery_completed',
  'dpia_completed',
  'dpia_completion_certified',
  'compliance_certification_completed',
  'transfer_approval_claimed',
  'transfer_execution_claimed',
  'authority_notification_claimed',
  'subject_notification_claimed',
  'automated_risk_scoring_performed',
  'risk_score_authority_claimed',
  'automated_legal_decision_made',
  'register_mutation_performed',
  'external_call_performed',
  'raw_register_contents_included',
  'processor_names_included',
  'data_subjects_included',
  'recipients_included',
  'personal_data_included',
  'secrets_included',
] as const;

const noClaims = Object.fromEntries(
  NO_CLAIMS_FLAGS.map((flag) => [flag, false]),
) as unknown as DpiaTemplateNoClaims;

/** The shipped body: real backend ids, English wire copy the catalog is expected to override. */
function shippedTemplate(): DpiaTemplateView {
  return {
    schema: 'chancela-privacy-dpia-template/v1',
    template_id: 'privacy-dpia-guidance/v1',
    title: 'Local DPIA guidance template',
    version: 1,
    language: 'en',
    scope: 'local_offline_guidance_only',
    local_offline_guidance_only: true,
    sections: [
      {
        id: 'risk_prompts',
        title: 'Risk prompts',
        description: 'Qualitative prompts only.',
        prompts: ['What rights-and-freedoms impacts should be reviewed?'],
        checklist: [
          {
            id: 'risk_review_note',
            label: 'Human risk review note',
            field_type: 'review_note',
            required: false,
          },
        ],
      },
    ],
    operator_actions: ['Fill placeholders locally.'],
    no_claims: noClaims,
    source: 'shipped',
  };
}

/**
 * An operator body that deliberately REUSES a shipped id (`risk_prompts`) with different words.
 * If the catalog were consulted, the shipped pt-PT string would win and the operator's own title
 * would never appear — which is the whole point of the assertion that uses this fixture.
 */
function operatorTemplate(): DpiaTemplateView {
  return {
    ...shippedTemplate(),
    title: 'Modelo interno',
    language: 'pt-PT',
    sections: [
      {
        id: 'risk_prompts',
        title: 'Riscos que a direção quer ver',
        description: 'Escrito internamente.',
        prompts: ['Que risco preocupa a direção?'],
        checklist: [
          {
            id: 'risk_review_note',
            label: 'Nota interna de risco',
            field_type: 'review_note',
            required: true,
          },
        ],
      },
    ],
    operator_actions: ['Rever antes de qualquer atualização.'],
    source: 'operator',
    updated_at: '2026-07-20T09:00:00Z',
    updated_by: 'amelia.marques',
  };
}

function renderPage(allowed = true) {
  const routes = (
    <Routes>
      <Route path="/settings/privacy/dpia-template/edit" element={<DpiaTemplatePage />} />
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
    ['/settings/privacy/dpia-template/edit'],
  );
}

function titleInput(): HTMLInputElement {
  return screen.getByLabelText(
    dpiaTemplateEditorPtPT['settings.privacy.dpiaTemplateEditor.field.title'],
  ) as HTMLInputElement;
}

function sectionTitleInput(): HTMLInputElement {
  return screen.getByLabelText(
    dpiaTemplateEditorPtPT['settings.privacy.dpiaTemplateEditor.field.sectionTitle'],
  ) as HTMLInputElement;
}

beforeEach(() => {
  hooks.template.data = shippedTemplate();
  hooks.template.isLoading = false;
  hooks.template.error = null;
  hooks.save.mutateAsync = vi.fn().mockResolvedValue(shippedTemplate());
  hooks.save.isPending = false;
  hooks.reset.mutateAsync = vi.fn().mockResolvedValue(shippedTemplate());
  hooks.reset.isPending = false;
  hooks.enabled.mockClear();
  navigate.mockClear();
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('the DPIA guidance model editor', () => {
  it('seeds the shipped body from the catalog, not from the English wire', () => {
    renderPage();

    // 🔴 The reader was looking at the pt-PT catalog string; the form must open on the same words.
    expect(sectionTitleInput().value).toBe(
      ptPT['settings.privacy.dpiaTemplate.section.risk_prompts.title'],
    );
    expect(sectionTitleInput().value).not.toBe('Risk prompts');

    const prompts = screen.getByLabelText(
      dpiaTemplateEditorPtPT['settings.privacy.dpiaTemplateEditor.field.prompts'],
    ) as HTMLTextAreaElement;
    expect(prompts.value).toBe(ptPT['settings.privacy.dpiaTemplate.section.risk_prompts.prompt.0']);

    // The id is a wire identifier and is seeded verbatim — it is not copy.
    expect(
      (
        screen.getByLabelText(
          dpiaTemplateEditorPtPT['settings.privacy.dpiaTemplateEditor.field.sectionId'],
        ) as HTMLInputElement
      ).value,
    ).toBe('risk_prompts');
  });

  it('renders an operator body verbatim and never through the catalog', () => {
    hooks.template.data = operatorTemplate();
    renderPage();

    // The id collides with a shipped one on purpose. The operator's words must win.
    expect(sectionTitleInput().value).toBe('Riscos que a direção quer ver');
    expect(sectionTitleInput().value).not.toBe(
      ptPT['settings.privacy.dpiaTemplate.section.risk_prompts.title'],
    );
    expect(titleInput().value).toBe('Modelo interno');
    expect(
      screen.getByText(dpiaTemplateEditorPtPT['settings.privacy.dpiaTemplateEditor.note.operator']),
    ).toBeTruthy();
  });

  it('saves an edited model through PUT, carrying no no_claims flag', async () => {
    renderPage();

    fireEvent.change(titleInput(), { target: { value: 'Modelo interno de AIPD' } });
    fireEvent.click(screen.getByRole('button', { name: ptPT['settings.privacy.action.save'] }));

    await waitFor(() => expect(hooks.save.mutateAsync).toHaveBeenCalledTimes(1));
    const body = hooks.save.mutateAsync.mock.calls[0][0] as PutDpiaTemplateBody;
    expect(body.title).toBe('Modelo interno de AIPD');
    expect(body.sections[0].id).toBe('risk_prompts');
    // Prompts are line-split, never comma-split: a prompt is a sentence and may contain commas.
    expect(body.sections[0].prompts).toEqual([
      ptPT['settings.privacy.dpiaTemplate.section.risk_prompts.prompt.0'],
    ]);

    // 🔒 Not one of the 28 flags may appear anywhere in what the client sends.
    const wire = JSON.stringify(body);
    for (const flag of NO_CLAIMS_FLAGS) {
      expect(wire.includes(flag), `${flag} must not be sent`).toBe(false);
    }
    expect(wire.includes('no_claims')).toBe(false);

    // A successful save returns to the privacy tab, with no unsaved-changes prompt.
    await waitFor(() => expect(navigate).toHaveBeenCalledWith('/settings/privacy'));
  });

  it('refuses to save a model with a blank or malformed section id', () => {
    renderPage();
    const sectionId = screen.getByLabelText(
      dpiaTemplateEditorPtPT['settings.privacy.dpiaTemplateEditor.field.sectionId'],
    );
    const save = screen.getByRole('button', { name: ptPT['settings.privacy.action.save'] });

    fireEvent.change(sectionId, { target: { value: '   ' } });
    expect((save as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(sectionId, { target: { value: 'risk/prompts' } });
    expect((save as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(sectionId, { target: { value: 'riscos_internos' } });
    expect((save as HTMLButtonElement).disabled).toBe(false);
  });

  it('offers reset only for an operator body, and only behind a confirmation', async () => {
    renderPage();
    const resetLabel = dpiaTemplateEditorPtPT['settings.privacy.dpiaTemplateEditor.action.reset'];
    // Nothing to discard: resetting the shipped model to itself is not an action.
    expect(screen.queryByRole('button', { name: resetLabel })).toBeNull();

    cleanup();
    hooks.template.data = operatorTemplate();
    renderPage();

    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    fireEvent.click(screen.getByRole('button', { name: resetLabel }));
    expect(confirm).toHaveBeenCalledWith(
      dpiaTemplateEditorPtPT['settings.privacy.dpiaTemplateEditor.reset.confirm'],
    );
    expect(hooks.reset.mutateAsync).not.toHaveBeenCalled();

    confirm.mockReturnValue(true);
    fireEvent.click(screen.getByRole('button', { name: resetLabel }));
    await waitFor(() => expect(hooks.reset.mutateAsync).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(navigate).toHaveBeenCalledWith('/settings/privacy'));
  });

  it('fails closed without privacy.manage: no read, no form', () => {
    renderPage(false);
    expect(hooks.enabled).toHaveBeenCalledWith(false);
    expect(
      screen.queryByLabelText(
        dpiaTemplateEditorPtPT['settings.privacy.dpiaTemplateEditor.field.title'],
      ),
    ).toBeNull();
  });
});
