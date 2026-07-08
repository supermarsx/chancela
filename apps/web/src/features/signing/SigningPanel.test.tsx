/**
 * SigningPanel tests (t57-S4): the two-phase CMD signing journey (initiate → OTP → confirm) over a
 * mocked api, the signed-status display + signed-PDF download gating, an honest expired-session
 * (410) restart, and a clean wrong-OTP (422) retry. Secrets (PIN/OTP) stay in transient form state.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { SigningPanel } from './SigningPanel';
import { renderWithProviders } from '../../test/utils';
import type { ActView, SignatureStatusView } from '../../api/types';

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
  retifies: null,
};

const unsignedStatus: SignatureStatusView = {
  status: 'unsigned',
  finalization: 'finalizado',
  require_qualified_for_seal: false,
};

const signedStatus: SignatureStatusView = {
  status: 'signed',
  finalization: 'finalizado_qualificado',
  require_qualified_for_seal: false,
  signed: {
    family: 'ChaveMovelDigital',
    evidentiary_level: 'Qualified',
    trusted_list_status: 'Granted',
    signer_cert_subject: 'CN=Amélia Marques,O=Encosto Estratégico Lda',
    signing_time: '2026-07-06T10:00:00Z',
    signed_at: '2026-07-06T10:00:05Z',
    signed_pdf_digest: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
    timestamp_token: false,
    download: '/v1/acts/act-1/document/signed',
  },
};

function json(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }),
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('SigningPanel — gating', () => {
  it('renders nothing while the act is a draft (signing is post-seal)', () => {
    vi.stubGlobal('fetch', (() => Promise.reject(new Error('no fetch expected'))) as typeof fetch);
    const { container } = renderWithProviders(
      <SigningPanel act={{ ...sealedAct, state: 'Draft', ata_number: null }} />,
    );
    expect(container.querySelector('.panel')).toBeNull();
  });
});

describe('SigningPanel — two-phase flow', () => {
  it('walks initiate → OTP → confirm and toasts success', async () => {
    let signed = false;
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature') && method === 'GET') {
        return json(signed ? signedStatus : unsignedStatus);
      }
      if (url.includes('/signature/cmd/initiate')) {
        return json({
          session_id: 'sess-1',
          masked_phone: '+351 9••••678',
          status: 'otp_pending',
          expires_at: '2026-07-06T10:05:00Z',
          family: 'ChaveMovelDigital',
          evidentiary_level: 'Qualified',
        });
      }
      if (url.includes('/signature/cmd/confirm')) {
        signed = true;
        return json({
          document_id: 'doc-1',
          act_id: 'act-1',
          family: 'ChaveMovelDigital',
          evidentiary_level: 'Qualified',
          trusted_list_status: 'Granted',
          signed_at: '2026-07-06T10:00:05Z',
          signed_pdf_digest: signedStatus.signed!.signed_pdf_digest,
          timestamp_token: false,
          finalization: 'finalizado_qualificado',
        });
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} entityName="Encosto Estratégico Lda" />);

    // Unsigned → the entry action.
    const start = await screen.findByRole('button', { name: 'Assinar com Chave Móvel Digital' });
    fireEvent.click(start);

    // Phase 1: phone + PIN.
    const phone = (await screen.findByLabelText('Número de telemóvel')) as HTMLInputElement;
    const pin = screen.getByLabelText('PIN de assinatura da CMD') as HTMLInputElement;
    fireEvent.change(phone, { target: { value: '+351 912345678' } });
    fireEvent.change(pin, { target: { value: '1234' } });
    fireEvent.click(screen.getByRole('button', { name: 'Enviar código por SMS' }));

    // Phase 2: the OTP field appears (masked phone echoed), and the PIN field is gone.
    const otp = (await screen.findByLabelText('Código SMS (OTP)')) as HTMLInputElement;
    expect(screen.queryByLabelText('PIN de assinatura da CMD')).toBeNull();
    fireEvent.change(otp, { target: { value: '999888' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirmar assinatura' }));

    // Signed: the qualified-signature record + the signed-PDF download.
    expect(
      await screen.findByText('Ata assinada com assinatura eletrónica qualificada'),
    ).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Descarregar PDF assinado' })).toBeTruthy();
  });

  it('restarts cleanly on a 410 expired session and surfaces a wrong-OTP 422 inline', async () => {
    let expired = true;
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
      if (url.includes('/signature/cmd/initiate')) {
        return json({
          session_id: 'sess-1',
          masked_phone: '+351 9••••678',
          status: 'otp_pending',
          expires_at: '2026-07-06T10:05:00Z',
          family: 'ChaveMovelDigital',
          evidentiary_level: 'Qualified',
        });
      }
      if (url.includes('/signature/cmd/confirm')) {
        if (expired) {
          expired = false;
          return json({ error: 'a sessão de assinatura expirou; reinicie a assinatura' }, 410);
        }
        return json({ error: 'a Chave Móvel Digital recusou o pedido: OTP inválido' }, 422);
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} />);

    fireEvent.click(await screen.findByRole('button', { name: 'Assinar com Chave Móvel Digital' }));
    fireEvent.change(await screen.findByLabelText('Número de telemóvel'), {
      target: { value: '+351 912345678' },
    });
    fireEvent.change(screen.getByLabelText('PIN de assinatura da CMD'), {
      target: { value: '1234' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Enviar código por SMS' }));

    // Submit an OTP → 410 → the flow drops back to the credentials step (PIN field returns).
    fireEvent.change(await screen.findByLabelText('Código SMS (OTP)'), {
      target: { value: '111111' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirmar assinatura' }));
    await waitFor(() => expect(screen.getByLabelText('PIN de assinatura da CMD')).toBeTruthy());

    // Re-initiate, submit a wrong OTP → 422 surfaces inline without leaving the OTP step.
    fireEvent.change(screen.getByLabelText('Número de telemóvel'), {
      target: { value: '+351 912345678' },
    });
    fireEvent.change(screen.getByLabelText('PIN de assinatura da CMD'), {
      target: { value: '1234' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Enviar código por SMS' }));
    fireEvent.change(await screen.findByLabelText('Código SMS (OTP)'), {
      target: { value: '000000' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirmar assinatura' }));

    await waitFor(() => expect(screen.getByText(/OTP inválido/)).toBeTruthy());
    // Still on the OTP step (a rejected OTP is a retry, not a restart).
    expect(screen.getByRole('button', { name: 'Confirmar assinatura' })).toBeTruthy();
  });
});

describe('SigningPanel — signed status + download', () => {
  it('shows the qualified record and downloads the signed PDF only once signed', async () => {
    const pdf = new Blob(['%PDF-signed'], { type: 'application/pdf' });
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith('/signature')) return json(signedStatus);
      if (url.endsWith('/document/signed')) {
        return Promise.resolve(
          new Response(pdf, { status: 200, headers: { 'Content-Type': 'application/pdf' } }),
        );
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    // jsdom lacks URL.createObjectURL — stub it for the download trigger.
    const createUrl = vi.fn(() => 'blob:signed');
    const revokeUrl = vi.fn();
    vi.stubGlobal(
      'URL',
      Object.assign(URL, { createObjectURL: createUrl, revokeObjectURL: revokeUrl }),
    );

    renderWithProviders(<SigningPanel act={sealedAct} entityName="Encosto Estratégico Lda" />);

    expect(await screen.findByText('CN=Amélia Marques,O=Encosto Estratégico Lda')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Descarregar PDF assinado' }));
    await waitFor(() => expect(createUrl).toHaveBeenCalled());
  });
});
