/**
 * The template import dialog (t43-e4): the two ways in (a file, or pasted JSON), the verify-then-
 * confirm gate, and — the point of this file — that each of the bundle envelope's new `422` codes
 * reaches the operator as an honest sentence rather than a raw status line. Reject, never transform:
 * a rejected bundle is refused with its reason and Confirm stays disarmed.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { TemplateImportDialog } from './TemplateImportDialog';
import { renderWithProviders } from '../../test/utils';
import type { TemplateSummary } from '../../api/types';

interface RecordedRequest {
  url: string;
  method: string;
  body?: BodyInit | null;
}

const USER_TEMPLATE: TemplateSummary = {
  id: 'user-encosto-ata/v1',
  family: 'CommercialCompany',
  stage: 'Ata',
  channels: ['Physical'],
  signature_policy: 'QualifiedPreferred',
  rule_pack_id: 'csc-art63/v2',
  law_references: [],
  locale: 'pt-PT',
  editable: true,
  source: 'user',
};

/** A `chancela.template-bundle` envelope as the exporter emits it — the shape import round-trips. */
const BUNDLE = JSON.stringify({
  format: 'chancela.template-bundle',
  format_version: 1,
  spec: {
    id: 'user-encosto-ata/v1',
    family: 'CommercialCompany',
    stage: 'Ata',
    channels: ['Physical'],
    signature_policy: 'QualifiedPreferred',
    rule_pack_id: 'csc-art63/v2',
    blocks: [{ kind: 'Paragraph', template: 'Ata de {{ entity.name }}.' }],
    locale: 'pt-PT',
  },
  body_markdown: '## Deliberações\n\nTexto inicial.',
});

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function jsonFile(content: string, name = 'modelo.json'): File {
  const file = new File([content], name, { type: 'application/json' });
  // jsdom's File does not implement async body readers; the dialog reads via `file.text()`.
  Object.defineProperty(file, 'text', { value: () => Promise.resolve(content) });
  return file;
}

/** A method-aware fetch that answers `/v1/templates/import` from `handle` and records every call. */
function importFetch(handle: (url: string, method: string) => Response | null) {
  const calls: RecordedRequest[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    calls.push({ url, method, body: init?.body });
    const custom = handle(url, method);
    if (custom) return Promise.resolve(custom);
    return Promise.reject(new Error(`no stub for ${method} ${url}`));
  }) as typeof fetch;
  return { fn, calls };
}

const importCalls = (calls: RecordedRequest[]) =>
  calls.filter((c) => c.method === 'POST' && c.url.includes('/v1/templates/import'));

function renderDialog(handle: (url: string, method: string) => Response | null) {
  const { fn, calls } = importFetch(handle);
  vi.stubGlobal('fetch', fn);
  renderWithProviders(<TemplateImportDialog onClose={() => {}} />, ['/templates']);
  const dialog = screen.getByRole('dialog', { name: 'Importar modelo' });
  return { dialog, calls };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('TemplateImportDialog — bundle rejection codes', () => {
  // Each of the five new envelope codes must arrive as its own sentence, never as a status line and
  // never silently dropped.
  it.each([
    [
      'unsupported_bundle_version',
      'A versão do pacote não é suportada por esta instalação. Exporte novamente a partir de uma versão compatível.',
    ],
    [
      'unsupported_bundle_format',
      'O ficheiro não é um pacote de modelo reconhecido. O campo «format» tem de ser «chancela.template-bundle».',
    ],
    ['body_too_large', 'O corpo do modelo (body_markdown) excede o limite permitido.'],
    [
      'invalid_seed',
      'O texto inicial do modelo é inválido: não pode estar vazio nem conter expressões de modelo (minijinja), e cada título tem de ter texto.',
    ],
  ])('surfaces %s honestly and keeps Confirm disarmed', async (code, message) => {
    const { dialog, calls } = renderDialog((url, method) =>
      url.includes('/v1/templates/import') && method === 'POST'
        ? jsonResponse({ ok: false, error: { code, message: 'raw server text' } })
        : null,
    );

    const fileInput = dialog.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.change(fileInput, { target: { files: [jsonFile('{"id":"user-x/v1"}')] } });

    expect(await within(dialog).findByText(message)).toBeTruthy();
    expect(
      (within(dialog).getByRole('button', { name: 'Confirmar importação' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    // The dry-run ran and persisted nothing.
    expect(importCalls(calls)).toHaveLength(1);
    expect(importCalls(calls)[0].url).toContain('dry_run=true');
  });

  it('rejects unsupported markdown in the body with its own reason', async () => {
    const { dialog } = renderDialog((url, method) =>
      url.includes('/v1/templates/import') && method === 'POST'
        ? jsonResponse({ ok: false, error: { code: 'unsupported_markdown', message: 'x' } })
        : null,
    );

    const fileInput = dialog.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.change(fileInput, { target: { files: [jsonFile(BUNDLE)] } });

    expect(await within(dialog).findByText(/subconjunto Markdown dos modelos/)).toBeTruthy();
  });
});

describe('TemplateImportDialog — paste flow', () => {
  it('preflights and commits pasted JSON byte-for-byte', async () => {
    const { dialog, calls } = renderDialog((url, method) =>
      url.includes('/v1/templates/import') && method === 'POST'
        ? url.includes('dry_run=true')
          ? jsonResponse({ ok: true })
          : jsonResponse(USER_TEMPLATE, 201)
        : null,
    );

    // Switch to the paste source; the file input yields to a textarea.
    fireEvent.click(within(dialog).getByRole('button', { name: 'Colar JSON' }));
    const textarea = within(dialog).getByLabelText('JSON do modelo') as HTMLTextAreaElement;
    fireEvent.change(textarea, { target: { value: BUNDLE } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Validar' }));

    // The valid verdict shows as both the InlineWarning title and its body — hence findAll.
    expect(
      await within(dialog).findAllByText('Ficheiro válido. Pode confirmar a importação.'),
    ).not.toHaveLength(0);
    expect(importCalls(calls)).toHaveLength(1);
    expect(importCalls(calls)[0].url).toContain('dry_run=true');
    // The preflight verified exactly the pasted bytes.
    expect(importCalls(calls)[0].body).toBe(BUNDLE);

    const confirm = within(dialog).getByRole('button', { name: 'Confirmar importação' });
    expect((confirm as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(confirm);

    await waitFor(() => expect(importCalls(calls)).toHaveLength(2));
    const commit = importCalls(calls)[1];
    expect(commit.url).not.toContain('dry_run');
    // Byte-for-byte: the commit must send exactly what was validated, or a re-exported bundle
    // would stop round-tripping and its digest would move.
    expect(commit.body).toBe(BUNDLE);
  });

  it('disarms Confirm when the operator switches source after a passing verdict', async () => {
    const { dialog, calls } = renderDialog((url, method) =>
      url.includes('/v1/templates/import') && method === 'POST' ? jsonResponse({ ok: true }) : null,
    );

    fireEvent.click(within(dialog).getByRole('button', { name: 'Colar JSON' }));
    fireEvent.change(within(dialog).getByLabelText('JSON do modelo'), {
      target: { value: BUNDLE },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Validar' }));

    const confirm = within(dialog).getByRole('button', {
      name: 'Confirmar importação',
    }) as HTMLButtonElement;
    await waitFor(() => expect(confirm.disabled).toBe(false));

    // Going back to the file source drops the stale verdict — Confirm cannot commit bytes the
    // operator is no longer looking at.
    fireEvent.click(within(dialog).getByRole('button', { name: 'Carregar ficheiro' }));
    expect(confirm.disabled).toBe(true);
    // Nothing was committed by the switch.
    expect(importCalls(calls).some((c) => !c.url.includes('dry_run'))).toBe(false);
  });
});
