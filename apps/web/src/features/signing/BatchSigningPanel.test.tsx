import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { BatchSigningPanel } from './BatchSigningPanel';
import { renderWithProviders, Wrapper } from '../../test/utils';
import { scopeBook } from '../session/permissions';
import type { ActView, CcBatchSignResponse } from '../../api/types';

const sealedAct: ActView = {
  id: 'act-1',
  book_id: 'book-1',
  title: 'Assembleia Geral Anual',
  channel: 'Physical',
  meeting_date: '2026-06-30',
  meeting_time: null,
  place: 'Lisboa',
  mesa: { presidente: 'Amélia Marques', secretarios: [] },
  agenda: [],
  attendance_reference: null,
  members_present: null,
  members_represented: null,
  referenced_documents: [],
  deliberations: '',
  deliberation_items: [],
  telematic_evidence: null,
  attachments: [],
  signatories: [],
  state: 'Sealed',
  ata_number: 1,
  payload_digest: null,
  seal_event_seq: null,
  seal_metadata: null,
  retifies: null,
};

function json(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }),
  );
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function renderPanel(act: ActView = sealedAct) {
  return renderWithProviders(
    <BatchSigningPanel currentAct={act} bookScope={scopeBook(act.book_id)} />,
  );
}

function addAct(actId: string) {
  fireEvent.change(screen.getByLabelText('ID do ato'), { target: { value: actId } });
  fireEvent.click(screen.getByRole('button', { name: 'Adicionar' }));
}

function successResponse(overrides: Partial<CcBatchSignResponse> = {}): CcBatchSignResponse {
  return {
    family: 'CartaoDeCidadao',
    auth_mode: 'single_auth',
    auth_events: 1,
    trusted_list_status: 'Granted',
    requested: 2,
    signed: 1,
    failed: 1,
    signer_capacity_evidence: {
      requested_provider_capacity: 'Presidente da Mesa',
      source: 'operator_request',
      verification_status: 'declared_only',
      verification_source: null,
      verified_at: null,
      authority_reference: null,
      status_scope: 'request_operator_evidence_only',
    },
    results: [
      {
        act_id: 'act-1',
        status: 'signed',
        document_id: 'source-doc-1',
        signed_pdf_digest:
          'a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00',
        signed_at: '2026-07-12T10:15:00Z',
        timestamp_token: true,
      },
      {
        act_id: 'act-2',
        status: 'error',
        error: 'cartão não detetado',
      },
    ],
    ...overrides,
  };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  window.localStorage.clear();
  window.sessionStorage.clear();
});

describe('BatchSigningPanel', () => {
  it('selects multiple document acts and keeps manual IDs unique', () => {
    renderPanel();

    expect(screen.getByText('1 selecionados de 200')).toBeTruthy();
    addAct('act-2');
    addAct('act-2');

    expect((screen.getByLabelText('Selecionar ato act-1') as HTMLInputElement).checked).toBe(
      true,
    );
    expect((screen.getByLabelText('Selecionar ato act-2') as HTMLInputElement).checked).toBe(
      true,
    );
    expect(screen.getAllByText('act-2').length).toBe(1);
    expect(screen.getByText('2 selecionados de 200')).toBeTruthy();

    fireEvent.click(screen.getByLabelText('Selecionar ato act-1'));
    expect(screen.getByText('1 selecionados de 200')).toBeTruthy();
    expect(
      (screen.getByRole('button', { name: 'Assinar lote com CC local' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
  });

  it('disables submit when fewer than two acts are selected', () => {
    renderPanel();

    expect(
      screen.getByText('Selecione pelo menos dois atos para usar assinatura em lote.'),
    ).toBeTruthy();
    expect(
      (screen.getByRole('button', { name: 'Assinar lote com CC local' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
  });

  it('submits the exact request shape and renders per-document success and error results', async () => {
    let requestBody: Record<string, unknown> | null = null;
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (url.endsWith('/v1/signature/cc/batch-sign')) {
        requestBody = JSON.parse(String(init?.body));
        return json(successResponse());
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderPanel();
    addAct('act-2');
    fireEvent.change(screen.getByLabelText('Qualidade/capacidade declarada'), {
      target: { value: ' Presidente da Mesa ' },
    });
    fireEvent.change(screen.getByLabelText('Ator'), { target: { value: ' operador-1 ' } });
    fireEvent.change(screen.getByLabelText('PIN de assinatura do Cartão de Cidadão (opcional)'), {
      target: { value: ' 1234 ' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Assinar lote com CC local' }));

    await waitFor(() =>
      expect(requestBody).toEqual({
        act_ids: ['act-1', 'act-2'],
        capacity: 'Presidente da Mesa',
        actor: 'operador-1',
        pin: '1234',
      }),
    );
    expect(screen.getByText('Autenticação única')).toBeTruthy();
    expect(screen.getByText('source-doc-1')).toBeTruthy();
    expect(
      screen.getByTitle('a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00'),
    ).toBeTruthy();
    expect(screen.getByText('cartão não detetado')).toBeTruthy();
    expect(screen.getByText(/Presidente da Mesa/)).toBeTruthy();
    expect(
      (
        screen.getByLabelText(
          'PIN de assinatura do Cartão de Cidadão (opcional)',
        ) as HTMLInputElement
      )
        .value,
    ).toBe('');
  });

  it('omits PIN when blank and labels per-document authentication only from the response', async () => {
    let requestBody: Record<string, unknown> | null = null;
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (url.endsWith('/v1/signature/cc/batch-sign')) {
        requestBody = JSON.parse(String(init?.body));
        return json(successResponse({ auth_mode: 'per_document_auth', auth_events: 2 }));
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderPanel();
    addAct('act-2');
    fireEvent.click(screen.getByRole('button', { name: 'Assinar lote com CC local' }));

    await waitFor(() =>
      expect(requestBody).toEqual({
        act_ids: ['act-1', 'act-2'],
      }),
    );
    expect(screen.getByText('Autenticação por documento')).toBeTruthy();
    expect(screen.queryByText('Autenticação única')).toBeNull();
  });

  it('clears the transient PIN on error and keeps the request body transient', async () => {
    const bodies: unknown[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (url.endsWith('/v1/signature/cc/batch-sign')) {
        bodies.push(JSON.parse(String(init?.body)));
        return json({ error: 'PIN rejeitado' }, 422);
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderPanel();
    addAct('act-2');
    fireEvent.change(screen.getByLabelText('PIN de assinatura do Cartão de Cidadão (opcional)'), {
      target: { value: '0000' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Assinar lote com CC local' }));

    expect((await screen.findAllByText('PIN rejeitado')).length).toBeGreaterThan(0);
    expect(
      (
        screen.getByLabelText(
          'PIN de assinatura do Cartão de Cidadão (opcional)',
        ) as HTMLInputElement
      )
        .value,
    ).toBe('');
    expect(bodies).toEqual([{ act_ids: ['act-1', 'act-2'], pin: '0000' }]);
  });

  it('resets transient batch state when the current act changes in a reused panel', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith('/v1/signature/cc/batch-sign')) {
        return json(successResponse());
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const nextAct: ActView = {
      ...sealedAct,
      id: 'act-next',
      title: 'Assembleia Extraordinária',
      ata_number: 2,
    };
    const { rerender } = renderPanel();
    addAct('manual-old');
    fireEvent.change(screen.getByLabelText('ID do ato'), { target: { value: 'manual-draft' } });
    fireEvent.change(screen.getByLabelText('Qualidade/capacidade declarada'), {
      target: { value: 'Presidente da Mesa' },
    });
    fireEvent.change(screen.getByLabelText('Ator'), { target: { value: 'operador-1' } });
    fireEvent.change(screen.getByLabelText('PIN de assinatura do Cartão de Cidadão (opcional)'), {
      target: { value: '1234' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Assinar lote com CC local' }));
    expect(await screen.findByText('Autenticação única')).toBeTruthy();

    rerender(
      <Wrapper>
        <BatchSigningPanel currentAct={nextAct} bookScope={scopeBook(nextAct.book_id)} />
      </Wrapper>,
    );

    expect(screen.queryByText('Autenticação única')).toBeNull();
    expect(screen.queryByText('source-doc-1')).toBeNull();
    expect(screen.queryByText('manual-old')).toBeNull();
    expect(screen.queryByText('act-1')).toBeNull();
    expect((screen.getByLabelText('Selecionar ato act-next') as HTMLInputElement).checked).toBe(
      true,
    );
    expect(screen.getByText('1 selecionados de 200')).toBeTruthy();
    expect((screen.getByLabelText('ID do ato') as HTMLInputElement).value).toBe('');
    expect(
      (screen.getByLabelText('Qualidade/capacidade declarada') as HTMLInputElement).value,
    ).toBe('');
    expect((screen.getByLabelText('Ator') as HTMLInputElement).value).toBe('');
    expect(
      (
        screen.getByLabelText(
          'PIN de assinatura do Cartão de Cidadão (opcional)',
        ) as HTMLInputElement
      )
        .value,
    ).toBe('');
    expect(
      (screen.getByRole('button', { name: 'Assinar lote com CC local' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
  });

  it('ignores stale batch completion after the current act changes', async () => {
    const pendingBatch = deferred<Response>();
    const requests: unknown[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (url.endsWith('/v1/signature/cc/batch-sign')) {
        requests.push(JSON.parse(String(init?.body)));
        return pendingBatch.promise;
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const nextAct: ActView = {
      ...sealedAct,
      id: 'act-next',
      title: 'Assembleia Extraordinária',
      ata_number: 2,
    };
    const { rerender } = renderPanel();
    addAct('act-2');
    fireEvent.change(screen.getByLabelText('Qualidade/capacidade declarada'), {
      target: { value: 'Presidente da Mesa' },
    });
    fireEvent.change(screen.getByLabelText('PIN de assinatura do Cartão de Cidadão (opcional)'), {
      target: { value: '1234' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Assinar lote com CC local' }));

    await waitFor(() =>
      expect(requests).toEqual([
        {
          act_ids: ['act-1', 'act-2'],
          capacity: 'Presidente da Mesa',
          pin: '1234',
        },
      ]),
    );

    rerender(
      <Wrapper>
        <BatchSigningPanel currentAct={nextAct} bookScope={scopeBook(nextAct.book_id)} />
      </Wrapper>,
    );
    expect((screen.getByLabelText('Selecionar ato act-next') as HTMLInputElement).checked).toBe(
      true,
    );

    pendingBatch.resolve(
      new Response(JSON.stringify(successResponse()), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    await pendingBatch.promise;
    await Promise.resolve();
    await Promise.resolve();

    await waitFor(() => {
      expect(screen.queryByText('Autenticação única')).toBeNull();
      expect(screen.queryByText('source-doc-1')).toBeNull();
      expect(screen.queryByText(/Presidente da Mesa/)).toBeNull();
      expect(screen.queryByText('cartão não detetado')).toBeNull();
      expect(screen.queryByText('Lote de assinatura CC concluído.')).toBeNull();
    });
    expect(screen.queryByText('act-1')).toBeNull();
    expect(screen.queryByText('act-2')).toBeNull();
    addAct('act-next-extra');
    expect(
      (screen.getByRole('button', { name: 'Assinar lote com CC local' }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
  });

  it('does not let stale settlement reset the current act batch mutation', async () => {
    const firstBatch = deferred<Response>();
    const secondBatch = deferred<Response>();
    const batches = [firstBatch, secondBatch];
    const requests: unknown[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (url.endsWith('/v1/signature/cc/batch-sign')) {
        const requestIndex = requests.length;
        requests.push(JSON.parse(String(init?.body)));
        return batches[requestIndex]?.promise ?? Promise.reject(new Error('unexpected request'));
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const nextAct: ActView = {
      ...sealedAct,
      id: 'act-next',
      title: 'Assembleia Extraordinária',
      ata_number: 2,
    };
    const { rerender } = renderPanel();
    addAct('act-2');
    fireEvent.change(screen.getByLabelText('PIN de assinatura do Cartão de Cidadão (opcional)'), {
      target: { value: '1111' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Assinar lote com CC local' }));

    await waitFor(() =>
      expect(requests).toEqual([{ act_ids: ['act-1', 'act-2'], pin: '1111' }]),
    );

    rerender(
      <Wrapper>
        <BatchSigningPanel currentAct={nextAct} bookScope={scopeBook(nextAct.book_id)} />
      </Wrapper>,
    );
    addAct('act-next-extra');
    fireEvent.change(screen.getByLabelText('PIN de assinatura do Cartão de Cidadão (opcional)'), {
      target: { value: '2222' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Assinar lote com CC local' }));

    await waitFor(() =>
      expect(requests).toEqual([
        { act_ids: ['act-1', 'act-2'], pin: '1111' },
        { act_ids: ['act-next', 'act-next-extra'], pin: '2222' },
      ]),
    );
    expect(
      (screen.getByRole('button', { name: 'A assinar lote…' }) as HTMLButtonElement).disabled,
    ).toBe(true);

    firstBatch.resolve(
      new Response(JSON.stringify(successResponse()), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    await firstBatch.promise;

    await waitFor(() => {
      expect(
        (screen.getByRole('button', { name: 'A assinar lote…' }) as HTMLButtonElement).disabled,
      ).toBe(true);
      expect(screen.queryByText('Autenticação única')).toBeNull();
      expect(screen.queryByText('source-doc-1')).toBeNull();
      expect(screen.queryByText('cartão não detetado')).toBeNull();
      expect(screen.queryByText('Lote de assinatura CC concluído.')).toBeNull();
    });
    expect(
      (
        screen.getByLabelText(
          'PIN de assinatura do Cartão de Cidadão (opcional)',
        ) as HTMLInputElement
      )
        .value,
    ).toBe('2222');

    secondBatch.resolve(
      new Response(
        JSON.stringify(
          successResponse({
            requested: 2,
            signed: 2,
            failed: 0,
            results: [
              {
                act_id: 'act-next',
                status: 'signed',
                document_id: 'source-doc-next',
                signed_pdf_digest:
                  '00112233445566778899aabbccddeeffa1b2c3d4e5f60718293a4b5c6d7e8f',
                signed_at: '2026-07-12T10:20:00Z',
                timestamp_token: true,
              },
            ],
          }),
        ),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    expect(await screen.findByText('source-doc-next')).toBeTruthy();
    expect(screen.getByText('Lote de assinatura CC concluído.')).toBeTruthy();
    expect(
      (
        screen.getByLabelText(
          'PIN de assinatura do Cartão de Cidadão (opcional)',
        ) as HTMLInputElement
      )
        .value,
    ).toBe('');
  });

  it('clears PIN on reset and unmount without writing storage', () => {
    const storageSet = vi.spyOn(Storage.prototype, 'setItem');
    const { unmount } = renderPanel();
    addAct('act-2');
    fireEvent.change(screen.getByLabelText('PIN de assinatura do Cartão de Cidadão (opcional)'), {
      target: { value: '7777' },
    });
    expect(
      (
        screen.getByLabelText(
          'PIN de assinatura do Cartão de Cidadão (opcional)',
        ) as HTMLInputElement
      )
        .value,
    ).toBe('7777');

    fireEvent.click(screen.getByRole('button', { name: 'Limpar lote' }));
    expect(
      (
        screen.getByLabelText(
          'PIN de assinatura do Cartão de Cidadão (opcional)',
        ) as HTMLInputElement
      )
        .value,
    ).toBe('');

    fireEvent.change(screen.getByLabelText('PIN de assinatura do Cartão de Cidadão (opcional)'), {
      target: { value: '8888' },
    });
    unmount();
    expect(storageSet).not.toHaveBeenCalled();
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);

    renderPanel();
    expect(
      (
        screen.getByLabelText(
          'PIN de assinatura do Cartão de Cidadão (opcional)',
        ) as HTMLInputElement
      )
        .value,
    ).toBe('');
  });
});
