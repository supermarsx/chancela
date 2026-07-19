/**
 * ScapAttributePicker tests (t67-e13). The load-bearing assertion is the honesty invariant: a
 * mock/declared SCAP attribute (the default `preprod` transport) is rendered as
 * «Declarado — não verificado pela SCAP» and NEVER as verified — both in the attribute list and in
 * the post-sign result, which keys its badge strictly off the response's `verification.verified` flag.
 * A second test proves the selection reaches the `/v1/scap/sign` body with the transient signer.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { ScapAttributePicker } from './ScapAttributePicker';
import { renderWithProviders } from '../../test/utils';
import { saveBlobAs, type SaveBlobResult } from '../../desktop/saveFile';
import type { ActView } from '../../api/types';

vi.mock('../../desktop/saveFile', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../desktop/saveFile')>();
  return { ...actual, saveBlobAs: vi.fn() };
});

const saveBlobAsMock = vi.mocked(saveBlobAs);

const sealedAct = { id: 'act-1', book_id: 'book-1' } as unknown as ActView;

function json(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }),
  );
}

const providersResponse = {
  report_kind: 'scap_attribute_providers',
  environment: 'preprod',
  transport: 'mock',
  providers: [
    { id: 'ordem-advogados', name: 'Ordem dos Advogados', attribute_names: ['Advogado'] },
  ],
};

const attributesResponse = {
  report_kind: 'scap_citizen_attributes',
  environment: 'preprod',
  transport: 'mock',
  citizen_id: '12345678',
  attributes: [
    {
      provider_id: 'ordem-advogados',
      provider_name: 'Ordem dos Advogados',
      name: 'Advogado',
      valid_from: null,
      valid_until: null,
      sub_attributes: [{ name: 'cedula', value: '12345P' }],
    },
  ],
};

// The mock/declared sign result: `verified` is false and the marker is the declared-only one. This is
// the ONLY shape the mock transport can ever return.
const declaredSignResponse = {
  report_kind: 'scap_professional_attribute_signature',
  environment: 'preprod',
  transport: 'mock',
  legal_notice: 'The professional capacity is a declared claim; it was not verified against SCAP.',
  verification: {
    verified: false,
    verification_status: 'declared_capacity_by_provider',
    status_scope: 'declared_capacity_evidence_only',
    attribute_name: 'Advogado',
    provider_id: 'ordem-advogados',
  },
  content_sha256: 'cd'.repeat(32),
  signature_base64: btoa('cades'),
  signature_sha256: 'ab'.repeat(32),
  signer_cert_subject: 'CN=Amélia Marques,O=Encosto Estratégico Lda',
  signer_cert_sha256: 'ef'.repeat(32),
};

function pkcs12File(bytes = 'pfx-bytes'): File {
  const file = new File([bytes], 'signer.pfx', { type: 'application/x-pkcs12' });
  Object.defineProperty(file, 'arrayBuffer', {
    value: () => Promise.resolve(new TextEncoder().encode(bytes).buffer),
  });
  return file;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  saveBlobAsMock.mockReset();
});

describe('ScapAttributePicker — honest declared-vs-verified labelling', () => {
  it('labels a mock/declared attribute as declared-not-verified and never as verified', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/v1/scap/providers')) return json(providersResponse);
      if (url.includes('/v1/scap/attributes')) return json(attributesResponse);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(
      <ScapAttributePicker
        act={sealedAct}
        loadContentBase64={() => Promise.resolve(btoa('%PDF'))}
      />,
    );

    fireEvent.change(screen.getByLabelText('Identificação do cidadão'), {
      target: { value: '12345678' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Procurar atributos' }));

    // The reported attribute appears, tagged as a DECLARED (unverified) capacity.
    expect(await screen.findByText('Advogado')).toBeTruthy();
    expect(screen.getByText('Declarado — não verificado pela SCAP')).toBeTruthy();
    // The mock transport can never yield a verified capacity — the verified label must be absent.
    expect(screen.queryByText('Verificado pela SCAP')).toBeNull();
  });

  it('reaches the /scap/sign body and renders the declared result (never verified)', async () => {
    let requestUrl: string | null = null;
    let requestBody: Record<string, unknown> | null = null;
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (url.includes('/v1/scap/providers')) return json(providersResponse);
      if (url.includes('/v1/scap/attributes')) return json(attributesResponse);
      if (url.includes('/v1/scap/sign')) {
        requestUrl = url;
        requestBody = JSON.parse(String(init?.body));
        return json(declaredSignResponse);
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(
      <ScapAttributePicker
        act={sealedAct}
        loadContentBase64={() => Promise.resolve(btoa('%PDF'))}
      />,
    );

    fireEvent.change(screen.getByLabelText('Identificação do cidadão'), {
      target: { value: '12345678' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Procurar atributos' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Selecionar' }));

    fireEvent.change(screen.getByLabelText('Ficheiro PKCS#12/PFX'), {
      target: { files: [pkcs12File()] },
    });
    fireEvent.change(screen.getByLabelText('Frase-passe'), { target: { value: 'pfx-passphrase' } });
    fireEvent.click(screen.getByRole('button', { name: 'Assinar com atributo' }));

    await waitFor(() =>
      expect(requestBody).toMatchObject({
        citizen_id: '12345678',
        provider_id: 'ordem-advogados',
        attribute_name: 'Advogado',
        environment: 'preprod',
        content_base64: btoa('%PDF'),
        signer: {
          kind: 'soft_pkcs12',
          pkcs12_base64: btoa('pfx-bytes'),
          passphrase: 'pfx-passphrase',
        },
      }),
    );
    expect(requestUrl).toContain('/v1/scap/sign');

    // The result is rendered honestly: declared, never verified.
    expect(
      (await screen.findAllByText('Assinatura com atributo profissional produzida')).length,
    ).toBeGreaterThan(0);
    expect(screen.getAllByText('Declarado — não verificado pela SCAP').length).toBeGreaterThan(0);
    expect(screen.queryByText('Verificado pela SCAP')).toBeNull();
    // The transient passphrase is dropped once consumed.
    expect((screen.getByLabelText('Frase-passe') as HTMLInputElement).value).toBe('');
  });
});

// --- s5-web-branches: lookup/sign/download error paths and honest fallbacks -------------------

/** Render the picker with a `loadContentBase64` that resolves to a stub PDF. */
function renderPicker(
  loadContentBase64: () => Promise<string> = () => Promise.resolve(btoa('%PDF')),
) {
  return renderWithProviders(
    <ScapAttributePicker act={sealedAct} loadContentBase64={loadContentBase64} />,
  );
}

function lookup(citizenId = '12345678') {
  fireEvent.change(screen.getByLabelText('Identificação do cidadão'), {
    target: { value: citizenId },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Procurar atributos' }));
}

async function selectAndSign() {
  fireEvent.click((await screen.findAllByRole('button', { name: 'Selecionar' }))[0]);
  fireEvent.change(screen.getByLabelText('Ficheiro PKCS#12/PFX'), {
    target: { files: [pkcs12File()] },
  });
  fireEvent.change(screen.getByLabelText('Frase-passe'), { target: { value: 'pfx-passphrase' } });
  fireEvent.click(screen.getByRole('button', { name: 'Assinar com atributo' }));
}

describe('ScapAttributePicker — lookup edge cases', () => {
  it('does not call SCAP for a blank or whitespace-only citizen reference', () => {
    const fetchSpy = vi.fn(() => Promise.reject(new Error('must not be called')));
    vi.stubGlobal('fetch', fetchSpy as unknown as typeof fetch);
    renderPicker();

    const lookupButton = screen.getByRole('button', {
      name: 'Procurar atributos',
    }) as HTMLButtonElement;
    expect(lookupButton.disabled).toBe(true);

    fireEvent.change(screen.getByLabelText('Identificação do cidadão'), {
      target: { value: '   ' },
    });
    expect(lookupButton.disabled).toBe(true);
    fireEvent.submit(lookupButton.closest('form') as HTMLFormElement);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('surfaces a failed attribute lookup instead of an empty list', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/v1/scap/providers')) return json(providersResponse);
      if (url.includes('/v1/scap/attributes')) return json({ error: 'SCAP indisponível' }, 502);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderPicker();
    lookup();

    expect((await screen.findAllByText('SCAP indisponível')).length).toBeGreaterThan(0);
    // A failed lookup must not be mistaken for "this citizen has no attributes".
    expect(
      screen.queryByText('A SCAP não reporta atributos profissionais para este cidadão.'),
    ).toBeNull();
    expect(screen.queryByText('Atributos reportados')).toBeNull();
  });

  it('reports an empty attribute list distinctly from a failure', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/v1/scap/providers')) return json({ ...providersResponse, providers: [] });
      if (url.includes('/v1/scap/attributes'))
        return json({ ...attributesResponse, attributes: [] });
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderPicker();
    lookup();

    expect(
      await screen.findByText('A SCAP não reporta atributos profissionais para este cidadão.'),
    ).toBeTruthy();
    expect(screen.queryByText('Atributos reportados')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Selecionar' })).toBeNull();
  });

  it('renders a validity window and omits the sub-attribute line when there is none', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      // No providers reported: the aggregate provider hint line must be omitted.
      if (url.includes('/v1/scap/providers')) return json({ ...providersResponse, providers: [] });
      if (url.includes('/v1/scap/attributes'))
        return json({
          ...attributesResponse,
          attributes: [
            {
              provider_id: 'ordem-advogados',
              provider_name: 'Ordem dos Advogados',
              name: 'Advogado',
              valid_from: '2024-01-01',
              valid_until: null,
              sub_attributes: [],
            },
          ],
        });
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderPicker();
    lookup();

    // An open-ended window renders the «sem termo» sentinel, never `null`.
    expect(await screen.findByText('Validade: 2024-01-01 – sem termo')).toBeTruthy();
    expect(screen.queryByText(/cedula/)).toBeNull();
    expect(screen.queryByText('Prestador: Ordem dos Advogados, Ordem dos Advogados')).toBeNull();
  });
});

describe('ScapAttributePicker — signing failures drop the secret', () => {
  it('replaces the signer form with the co-location notice on a 409 refusal', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/v1/scap/providers')) return json(providersResponse);
      if (url.includes('/v1/scap/attributes')) return json(attributesResponse);
      if (url.includes('/v1/scap/sign'))
        return json({ error: 'a API não está co-localizada com a chave privada' }, 409);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderPicker();
    lookup();
    await selectAndSign();

    expect(await screen.findByText('Disponível apenas na aplicação de secretária')).toBeTruthy();
    // The signer form is withdrawn — retrying in this browser cannot succeed.
    expect(screen.queryByLabelText('Frase-passe')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Assinar com atributo' })).toBeNull();
    expect(screen.queryByText('Assinatura com atributo profissional produzida')).toBeNull();
  });

  it('keeps the form retryable on a non-409 failure but clears the passphrase', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/v1/scap/providers')) return json(providersResponse);
      if (url.includes('/v1/scap/attributes')) return json(attributesResponse);
      if (url.includes('/v1/scap/sign')) return json({ error: 'frase-passe incorreta' }, 422);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderPicker();
    lookup();
    await selectAndSign();

    expect((await screen.findAllByText('frase-passe incorreta')).length).toBeGreaterThan(0);
    // Still a browser-usable form (this was not a co-location refusal)…
    expect(screen.getByLabelText('Frase-passe')).toBeTruthy();
    expect(screen.queryByText('Disponível apenas na aplicação de secretária')).toBeNull();
    // …but the transient signer material is gone, so submit is disabled again.
    expect((screen.getByLabelText('Frase-passe') as HTMLInputElement).value).toBe('');
    expect(
      (screen.getByRole('button', { name: 'Assinar com atributo' }) as HTMLButtonElement).disabled,
    ).toBe(true);
  });

  it('reports a failure to read the act content without sending the signer material', async () => {
    let signCalls = 0;
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/v1/scap/providers')) return json(providersResponse);
      if (url.includes('/v1/scap/attributes')) return json(attributesResponse);
      if (url.includes('/v1/scap/sign')) {
        signCalls += 1;
        return json(declaredSignResponse);
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderPicker(() => Promise.reject(new Error('PDF/A selado indisponível')));
    lookup();
    await selectAndSign();

    expect((await screen.findAllByText('PDF/A selado indisponível')).length).toBeGreaterThan(0);
    expect(signCalls).toBe(0);
    expect((screen.getByLabelText('Frase-passe') as HTMLInputElement).value).toBe('');
  });
});

describe('ScapAttributePicker — result rendering and download', () => {
  const verifiedSignResponse = {
    ...declaredSignResponse,
    verification: {
      ...declaredSignResponse.verification,
      verified: true,
      verification_status: 'verified_capacity',
    },
    signer_cert_subject: null,
  };

  function stubSign(response: unknown) {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/v1/scap/providers')) return json(providersResponse);
      if (url.includes('/v1/scap/attributes')) return json(attributesResponse);
      if (url.includes('/v1/scap/sign')) return json(response);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);
  }

  it('renders the verified badge only when the response says verified, and dashes an absent signer', async () => {
    stubSign(verifiedSignResponse);
    renderPicker();
    lookup();
    await selectAndSign();

    expect(await screen.findByText('Verificado pela SCAP')).toBeTruthy();
    expect(
      screen.getAllByText('Assinatura com atributo profissional produzida').length,
    ).toBeGreaterThan(0);
    // A response without a signer subject renders a dash, never `undefined`/`null`.
    expect(screen.getByText('—')).toBeTruthy();
    expect(screen.queryByText('null')).toBeNull();
  });

  it('saves the CAdES bytes it decoded from the response', async () => {
    stubSign(declaredSignResponse);
    saveBlobAsMock.mockResolvedValue({
      kind: 'desktop-save',
      path: 'C:/atos/assinatura-scap.p7s',
      filename: 'assinatura-scap.p7s',
      contentType: 'application/pkcs7-signature',
      bytes: 5,
    } satisfies SaveBlobResult);

    renderPicker();
    lookup();
    await selectAndSign();
    fireEvent.click(await screen.findByRole('button', { name: 'Descarregar assinatura CAdES' }));

    await waitFor(() => expect(saveBlobAsMock).toHaveBeenCalledTimes(1));
    const options = saveBlobAsMock.mock.calls[0][0];
    expect(options.filename).toBe('assinatura-scap.p7s');
    expect(options.contentType).toBe('application/pkcs7-signature');
    // The blob carries the DECODED signature bytes, not the base64 text.
    expect(await options.blob.text()).toBe('cades');
    expect(
      (await screen.findAllByText(/Ficheiro guardado: assinatura-scap\.p7s/)).length,
    ).toBeGreaterThan(0);
  });

  it('reports a cancelled save distinctly from a failed one', async () => {
    stubSign(declaredSignResponse);
    saveBlobAsMock.mockResolvedValue({
      kind: 'cancelled',
      filename: 'assinatura-scap.p7s',
      contentType: 'application/pkcs7-signature',
      bytes: 5,
    } satisfies SaveBlobResult);

    renderPicker();
    lookup();
    await selectAndSign();
    fireEvent.click(await screen.findByRole('button', { name: 'Descarregar assinatura CAdES' }));

    expect(
      (await screen.findAllByText(/Guardar cancelado: assinatura-scap\.p7s/)).length,
    ).toBeGreaterThan(0);
  });

  it('surfaces a save failure as an error', async () => {
    stubSign(declaredSignResponse);
    saveBlobAsMock.mockRejectedValue(new Error('disco cheio'));

    renderPicker();
    lookup();
    await selectAndSign();
    fireEvent.click(await screen.findByRole('button', { name: 'Descarregar assinatura CAdES' }));

    expect((await screen.findAllByText('disco cheio')).length).toBeGreaterThan(0);
    expect(screen.queryByText(/Ficheiro guardado/)).toBeNull();
  });

  it('drops a stale result when a different attribute is selected', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/v1/scap/providers')) return json(providersResponse);
      if (url.includes('/v1/scap/attributes'))
        return json({
          ...attributesResponse,
          attributes: [
            attributesResponse.attributes[0],
            {
              provider_id: 'ordem-medicos',
              provider_name: 'Ordem dos Médicos',
              name: 'Médico',
              valid_from: null,
              valid_until: null,
              sub_attributes: [],
            },
          ],
        });
      if (url.includes('/v1/scap/sign')) return json(declaredSignResponse);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderPicker();
    lookup();
    await selectAndSign();
    expect(
      await screen.findByRole('button', { name: 'Descarregar assinatura CAdES' }),
    ).toBeTruthy();

    // Picking another attribute invalidates the signature produced for the previous one.
    fireEvent.click(screen.getAllByRole('button', { name: 'Selecionar' })[0]);
    await waitFor(() =>
      expect(screen.queryByRole('button', { name: 'Descarregar assinatura CAdES' })).toBeNull(),
    );
  });
});
