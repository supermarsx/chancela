/**
 * The DPIA guidance model editor's SECTION and CHECKLIST surface, and the submit gate that guards
 * it.
 *
 * `DpiaTemplatePage.test.tsx` holds the four load-bearing rules (translated seeding, operator
 * verbatim, no `no_claims` on the wire, reset behind a confirmation). This file covers the
 * structure the operator builds and the refusals that stop a broken model from being saved at all:
 * duplicate ids inside one model, an unnamed section, a checklist item with no label. The server
 * enforces the same rules; a client that let the operator submit anyway would turn a typo into a
 * round trip that fails with no indication of which row was wrong.
 *
 * All assertions are on the PUT body and on catalog KEYS — never on a translated substring.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import type {
  DpiaTemplateNoClaims,
  DpiaTemplateView,
  PutDpiaTemplateBody,
} from '../../../api/types';
import { dpiaTemplateEditorPtPT as editor } from '../../../i18n/dpiaTemplateEditorFallback';
import { ptPT } from '../../../i18n/locales/pt-PT';
import { renderWithProviders } from '../../../test/utils';
import { DpiaTemplatePage } from './DpiaTemplatePage';

const hooks = vi.hoisted(() => ({
  template: { data: null as unknown, isLoading: false, error: null as unknown },
  save: { mutateAsync: vi.fn(), isPending: false },
  reset: { mutateAsync: vi.fn(), isPending: false },
}));

vi.mock('../../../api/hooks', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../api/hooks')>();
  return {
    ...actual,
    usePrivacyDpiaTemplate: () => hooks.template,
    usePutPrivacyDpiaTemplate: () => hooks.save,
    useResetPrivacyDpiaTemplate: () => hooks.reset,
  };
});

const navigate = vi.hoisted(() => vi.fn());
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => navigate };
});

/**
 * An operator-authored model, so nothing is resolved through the catalog and every value in the
 * form is the literal one this file put there.
 */
function operatorTemplate(): DpiaTemplateView {
  return {
    schema: 'chancela-privacy-dpia-template/v1',
    template_id: 'privacy-dpia-guidance/v1',
    title: 'Modelo interno',
    version: 2,
    language: 'pt-PT',
    scope: 'local_offline_guidance_only',
    local_offline_guidance_only: true,
    sections: [
      {
        id: 'riscos',
        title: 'Riscos',
        description: 'Escrito internamente.',
        prompts: ['Que risco preocupa a direção?'],
        checklist: [
          { id: 'nota_risco', label: 'Nota de risco', field_type: 'review_note', required: true },
        ],
      },
    ],
    operator_actions: ['Rever antes de qualquer atualização.'],
    no_claims: {} as unknown as DpiaTemplateNoClaims,
    source: 'operator',
    updated_at: '2026-07-20T09:00:00Z',
    updated_by: 'amelia.marques',
  };
}

function renderPage() {
  return renderWithProviders(
    <Routes>
      <Route path="/settings/privacy/dpia-template/edit" element={<DpiaTemplatePage />} />
    </Routes>,
    ['/settings/privacy/dpia-template/edit'],
  );
}

const label = (key: keyof typeof editor) => editor[key];

function saveButton(): HTMLButtonElement {
  return screen.getByRole('button', {
    name: ptPT['settings.privacy.action.save'],
  }) as HTMLButtonElement;
}

function byId(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`no #${id}`);
  return el;
}

function addSection() {
  fireEvent.click(
    screen.getByRole('button', {
      name: label('settings.privacy.dpiaTemplateEditor.action.addSection'),
    }),
  );
}

function submit() {
  fireEvent.click(saveButton());
}

/** The body the page would PUT, having submitted once. */
async function submittedBody(): Promise<PutDpiaTemplateBody> {
  submit();
  await waitFor(() => expect(hooks.save.mutateAsync).toHaveBeenCalledTimes(1));
  return hooks.save.mutateAsync.mock.calls[0][0] as PutDpiaTemplateBody;
}

beforeEach(() => {
  hooks.template.data = operatorTemplate();
  hooks.template.isLoading = false;
  hooks.template.error = null;
  hooks.save.mutateAsync = vi.fn().mockResolvedValue(operatorTemplate());
  hooks.save.isPending = false;
  hooks.reset.mutateAsync = vi.fn().mockResolvedValue(operatorTemplate());
  hooks.reset.isPending = false;
  navigate.mockClear();
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('DPIA model editor — sections', () => {
  it('adds a section and carries its whole content into the PUT body', async () => {
    renderPage();
    addSection();

    fireEvent.change(byId('dpia-template-section-1-id'), { target: { value: 'transferencias' } });
    fireEvent.change(byId('dpia-template-section-1-title'), {
      target: { value: 'Transferências' },
    });
    fireEvent.change(byId('dpia-template-section-1-description'), {
      target: { value: 'Notas locais.' },
    });
    // Prompts are LINE-split, never comma-split: a prompt is a sentence and may contain commas.
    fireEvent.change(byId('dpia-template-section-1-prompts'), {
      target: { value: 'Há transferências fora da UE, mesmo ocasionais?\nQuem as autoriza?' },
    });

    const body = await submittedBody();
    expect(body.sections).toHaveLength(2);
    expect(body.sections[1]).toEqual({
      id: 'transferencias',
      title: 'Transferências',
      description: 'Notas locais.',
      prompts: ['Há transferências fora da UE, mesmo ocasionais?', 'Quem as autoriza?'],
      checklist: [],
    });
  });

  it('removes the section the operator asked to remove, and only that one', async () => {
    renderPage();
    addSection();
    fireEvent.change(byId('dpia-template-section-1-id'), { target: { value: 'segunda' } });
    fireEvent.change(byId('dpia-template-section-1-title'), { target: { value: 'Segunda' } });

    const removes = screen.getAllByRole('button', {
      name: label('settings.privacy.dpiaTemplateEditor.action.removeSection'),
    });
    expect(removes).toHaveLength(2);
    fireEvent.click(removes[0]);

    const body = await submittedBody();
    expect(body.sections.map((section) => section.id)).toEqual(['segunda']);
  });

  it('keeps each section editing its own row after one is removed', () => {
    renderPage();
    addSection();
    fireEvent.change(byId('dpia-template-section-1-id'), { target: { value: 'segunda' } });
    fireEvent.change(byId('dpia-template-section-1-title'), { target: { value: 'Segunda' } });

    fireEvent.click(
      screen.getAllByRole('button', {
        name: label('settings.privacy.dpiaTemplateEditor.action.removeSection'),
      })[0],
    );

    // The surviving row shifted to index 0. Its ids move with it, so a subsequent edit still
    // reaches the section the operator is looking at rather than the deleted one's slot.
    expect((byId('dpia-template-section-0-id') as HTMLInputElement).value).toBe('segunda');
    expect(document.getElementById('dpia-template-section-1-id')).toBeNull();
  });

  it('says so when every section has been removed, instead of showing an empty form', () => {
    renderPage();
    fireEvent.click(
      screen.getByRole('button', {
        name: label('settings.privacy.dpiaTemplateEditor.action.removeSection'),
      }),
    );

    expect(
      screen.getByText(label('settings.privacy.dpiaTemplateEditor.section.empty')),
    ).toBeTruthy();
    // A model with no section is not a model: it cannot be saved.
    expect(saveButton().disabled).toBe(true);
  });

  it('carries an edited language and the operator actions', async () => {
    renderPage();
    fireEvent.change(byId('dpia-template-language'), { target: { value: 'pt-BR' } });
    fireEvent.change(byId('dpia-template-operator-actions'), {
      target: { value: 'Rever anualmente.\nArquivar a versão anterior.' },
    });

    const body = await submittedBody();
    expect(body.language).toBe('pt-BR');
    expect(body.operator_actions).toEqual(['Rever anualmente.', 'Arquivar a versão anterior.']);
  });
});

describe('DPIA model editor — checklist items', () => {
  it('adds an item and sends its identifier, label, field type and required flag', async () => {
    renderPage();
    fireEvent.click(
      screen.getByRole('button', {
        name: label('settings.privacy.dpiaTemplateEditor.action.addItem'),
      }),
    );

    fireEvent.change(byId('dpia-template-section-0-item-1-id'), {
      target: { value: 'medida_mitigacao' },
    });
    fireEvent.change(byId('dpia-template-section-0-item-1-label'), {
      target: { value: 'Medida de mitigação' },
    });
    // The option text IS the wire identifier — the six field types are deliberately untranslated.
    fireEvent.change(byId('dpia-template-section-0-item-1-type'), { target: { value: 'text' } });
    fireEvent.click(byId('dpia-template-section-0-item-1-required'));

    const body = await submittedBody();
    expect(body.sections[0].checklist[1]).toEqual({
      id: 'medida_mitigacao',
      label: 'Medida de mitigação',
      field_type: 'text',
      required: true,
    });
  });

  it('clears a required flag through the same checkbox', async () => {
    renderPage();
    fireEvent.click(byId('dpia-template-section-0-item-0-required'));

    const body = await submittedBody();
    expect(body.sections[0].checklist[0].required).toBe(false);
  });

  it('changes an item field type to another wire identifier', async () => {
    renderPage();
    fireEvent.change(byId('dpia-template-section-0-item-0-type'), {
      target: { value: 'evidence_reference' },
    });

    const body = await submittedBody();
    expect(body.sections[0].checklist[0].field_type).toBe('evidence_reference');
  });

  it('removes a checklist item without touching its section', async () => {
    renderPage();
    const section = byId('dpia-template-section-0-item-0-id').closest('.api-key-rate-grid');
    expect(section).toBeTruthy();
    fireEvent.click(
      within(section as HTMLElement).getByRole('button', { name: ptPT['common.remove'] }),
    );

    const body = await submittedBody();
    expect(body.sections[0].checklist).toEqual([]);
    expect(body.sections[0].id).toBe('riscos');
  });
});

describe('DPIA model editor — the submit gate', () => {
  it('refuses a model whose two sections share one identifier', () => {
    renderPage();
    addSection();
    fireEvent.change(byId('dpia-template-section-1-title'), { target: { value: 'Duplicada' } });

    fireEvent.change(byId('dpia-template-section-1-id'), { target: { value: 'riscos' } });
    expect(saveButton().disabled).toBe(true);

    fireEvent.change(byId('dpia-template-section-1-id'), { target: { value: 'riscos_2' } });
    expect(saveButton().disabled).toBe(false);
  });

  it('refuses a section with no title, and an item with no label', () => {
    renderPage();

    fireEvent.change(byId('dpia-template-section-0-title'), { target: { value: '  ' } });
    expect(saveButton().disabled).toBe(true);
    fireEvent.change(byId('dpia-template-section-0-title'), { target: { value: 'Riscos' } });
    expect(saveButton().disabled).toBe(false);

    fireEvent.change(byId('dpia-template-section-0-item-0-label'), { target: { value: ' ' } });
    expect(saveButton().disabled).toBe(true);
  });

  it('refuses two checklist items sharing an identifier inside one section', () => {
    renderPage();
    fireEvent.click(
      screen.getByRole('button', {
        name: label('settings.privacy.dpiaTemplateEditor.action.addItem'),
      }),
    );
    fireEvent.change(byId('dpia-template-section-0-item-1-label'), { target: { value: 'Outra' } });

    fireEvent.change(byId('dpia-template-section-0-item-1-id'), {
      target: { value: 'nota_risco' },
    });
    expect(saveButton().disabled).toBe(true);

    // The same id in a DIFFERENT section is fine: item ids are scoped to their section.
    fireEvent.change(byId('dpia-template-section-0-item-1-id'), { target: { value: 'nota_2' } });
    expect(saveButton().disabled).toBe(false);
  });

  it('refuses a malformed item identifier the server would reject', () => {
    renderPage();
    fireEvent.change(byId('dpia-template-section-0-item-0-id'), {
      target: { value: 'nota risco' },
    });
    expect(saveButton().disabled).toBe(true);
  });

  it('refuses a blank title or language for the model as a whole', () => {
    renderPage();

    fireEvent.change(byId('dpia-template-title'), { target: { value: '   ' } });
    expect(saveButton().disabled).toBe(true);
    fireEvent.change(byId('dpia-template-title'), { target: { value: 'Modelo interno' } });
    expect(saveButton().disabled).toBe(false);

    fireEvent.change(byId('dpia-template-language'), { target: { value: '' } });
    expect(saveButton().disabled).toBe(true);
  });

  it('surfaces a failed save as a toast and stays on the page', async () => {
    hooks.save.mutateAsync = vi.fn().mockRejectedValue(new Error('o servidor recusou'));
    renderPage();

    fireEvent.change(byId('dpia-template-title'), { target: { value: 'Modelo revisto' } });
    submit();

    expect(await screen.findByRole('alert')).toBeTruthy();
    // A failed PUT must not navigate away as though the model had been stored.
    expect(navigate).not.toHaveBeenCalled();
  });

  it('surfaces a failed reset instead of silently leaving the override in place', async () => {
    hooks.reset.mutateAsync = vi.fn().mockRejectedValue(new Error('o servidor recusou'));
    renderPage();
    vi.spyOn(window, 'confirm').mockReturnValue(true);

    fireEvent.click(
      screen.getByRole('button', {
        name: label('settings.privacy.dpiaTemplateEditor.action.reset'),
      }),
    );

    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(navigate).not.toHaveBeenCalled();
  });
});
