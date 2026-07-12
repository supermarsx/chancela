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
import type { ActView } from '../../api/types';

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
