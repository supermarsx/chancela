import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import {
  EXTERNAL_INVITE_SIGNED_PDF_RAW_MAX_BYTES,
  ExternalSignerInvitePage,
} from './ExternalSignerInvitePage';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('ExternalSignerInvitePage', () => {
  it('looks up a token, hides it from the page, and records acceptance', async () => {
    const envelope = {
      invite_id: 'invite-1',
      act: {
        id: 'act-1',
        title: 'Ata da AG anual',
        state: 'Sealed',
        meeting_date: '2026-03-30',
        ata_number: 1,
        entity_name: 'Encosto Estrategico, S.A.',
        book_kind: 'AssembleiaGeral',
      },
      document: {
        id: 'doc-1',
        template_id: 'csc-ata-ag/v1',
        profile: 'application/pdf; profile=PDF/A-2u',
        pdf_digest: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        artifact: {
          kind: 'working_copy_markdown',
          method: 'POST',
          path: '/v1/signature/external-invites/document/working-copy',
          content_type: 'text/markdown; charset=utf-8',
          filename: 'act-act-1-external-working-copy.md',
          notice: 'not canonical',
        },
      },
      recipient_name: 'Bruno Dias',
      provider_hint: 'manual-envelope',
      purpose: 'Assinar a ata como administrador externo',
      status: 'pending',
      workflow: 'tracking_only',
      created_at: '2026-07-06T10:00:00Z',
      expires_at: '2026-07-08T10:00:00Z',
      notice: 'tracking only',
    };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json(envelope))
      .mockResolvedValueOnce(
        json({
          ...envelope,
          status: 'accepted',
          responded_at: '2026-07-06T10:30:00Z',
        }),
      )
      .mockResolvedValueOnce(
        new Response('# EXTERNAL SIGNER WORKING COPY - NON-EVIDENTIARY', {
          headers: { 'Content-Type': 'text/markdown; charset=utf-8' },
        }),
      );
    vi.stubGlobal('fetch', fetchMock);

    renderWithProviders(<ExternalSignerInvitePage />, [
      '/assinatura-externa?token=cxi_secret_token_123',
    ]);

    expect(await screen.findByText('Convite externo')).toBeTruthy();
    expect(await screen.findByText('Ata da AG anual')).toBeTruthy();
    expect(screen.getByText('Encosto Estrategico, S.A.')).toBeTruthy();
    expect(screen.getByText('Acompanhamento apenas')).toBeTruthy();
    expect(screen.getByText('csc-ata-ag/v1')).toBeTruthy();
    expect(screen.getByText('Cópia não probatória')).toBeTruthy();
    expect(document.body.textContent).not.toContain('cxi_secret_token_123');
    expect(fetchMock.mock.calls[0][0]).toBe('/v1/signature/external-invites/lookup');
    expect(JSON.parse(fetchMock.mock.calls[0][1]?.body as string)).toEqual({
      token: 'cxi_secret_token_123',
    });

    fireEvent.click(screen.getByRole('button', { name: 'Aceitar acompanhamento' }));

    await waitFor(() => expect(screen.getByText('Aceite')).toBeTruthy());
    expect(fetchMock.mock.calls[1][0]).toBe('/v1/signature/external-invites/respond');
    expect(JSON.parse(fetchMock.mock.calls[1][1]?.body as string)).toEqual({
      token: 'cxi_secret_token_123',
      decision: 'accept',
    });
    expect(screen.getByText(/Este estado não é assinatura qualificada/)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Pré-visualizar cópia .md' }));

    await waitFor(() =>
      expect(screen.getByTestId('external-working-copy-preview').textContent).toContain(
        'EXTERNAL SIGNER WORKING COPY - NON-EVIDENTIARY',
      ),
    );
    expect(fetchMock.mock.calls[2][0]).toBe('/v1/signature/external-invites/document/working-copy');
    expect(JSON.parse(fetchMock.mock.calls[2][1]?.body as string)).toEqual({
      token: 'cxi_secret_token_123',
    });
    expect(document.body.textContent).not.toContain('cxi_secret_token_123');
  });

  it('uploads a linked signed PDF as technical evidence without leaking the token', async () => {
    const envelope = {
      invite_id: 'invite-1',
      act: {
        id: 'act-1',
        title: 'Ata com envelope',
        state: 'Sealed',
        meeting_date: '2026-03-30',
        ata_number: 1,
        entity_name: 'Encosto Estrategico, S.A.',
        book_kind: 'AssembleiaGeral',
      },
      recipient_name: 'Bruno Dias',
      purpose: 'Assinar a ata como administrador externo',
      status: 'pending',
      workflow: 'external_envelope',
      external_envelope: {
        id: 'env-1',
        slot_id: 'slot-1',
        order_policy: 'parallel',
        slot_status: 'initiated',
      },
      created_at: '2026-07-06T10:00:00Z',
      expires_at: '2026-07-08T10:00:00Z',
      notice: 'tracking only',
    };
    const signedDigest = 'f'.repeat(64);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json(envelope))
      .mockResolvedValueOnce(
        json({
          ...envelope,
          status: 'accepted',
          responded_at: '2026-07-06T10:30:00Z',
          external_envelope: {
            ...envelope.external_envelope,
            slot_status: 'signed',
          },
          signed_artifact: {
            family: 'ExternalSignerHandoff',
            evidentiary_level: 'ExternalSignedPdfTechnicalEvidence',
            signed_pdf_digest: signedDigest,
            timestamp_token: false,
            status_scope: 'technical_evidence_only',
            qualification_claimed: false,
            legal_status_claimed: false,
            notice: 'Technical evidence only; no provider, qualification, or legal claim.',
          },
        }),
      );
    vi.stubGlobal('fetch', fetchMock);

    renderWithProviders(<ExternalSignerInvitePage />, [
      '/assinatura-externa?token=cxi_secret_token_456',
    ]);

    expect(await screen.findByText('Carregamento de evidência técnica')).toBeTruthy();
    const signedPdf = new File(['%PDF-1.4\nsigned'], 'signed.pdf', {
      type: 'application/pdf',
    });
    const arrayBuffer = vi
      .fn()
      .mockResolvedValue(new TextEncoder().encode('%PDF-1.4\nsigned').buffer);
    Object.defineProperty(signedPdf, 'arrayBuffer', { value: arrayBuffer });
    fireEvent.change(screen.getByLabelText('PDF assinado'), {
      target: { files: [signedPdf] },
    });
    fireEvent.click(screen.getByLabelText(/Reconheço que este carregamento/));
    fireEvent.click(screen.getByRole('button', { name: 'Carregar PDF e aceitar' }));

    await waitFor(() => expect(screen.getByText('Artefacto técnico preservado')).toBeTruthy());
    expect(screen.getByText('Assinado')).toBeTruthy();
    expect(screen.getByTitle(signedDigest)).toBeTruthy();
    expect(screen.getByText('technical_evidence_only')).toBeTruthy();
    expect(JSON.parse(fetchMock.mock.calls[1][1]?.body as string)).toEqual({
      token: 'cxi_secret_token_456',
      decision: 'accept',
      signed_pdf_base64: 'JVBERi0xLjQKc2lnbmVk',
      filename: 'signed.pdf',
    });
    expect(arrayBuffer).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[1][0]).toBe('/v1/signature/external-invites/respond');
    expect(document.body.textContent).not.toContain('cxi_secret_token_456');
    expect(document.body.textContent).not.toMatch(/assinatura eletrónica qualificada/i);
    expect(document.body.textContent).not.toMatch(/validação de prestador concluída/i);
    expect(document.body.textContent).not.toMatch(/ata concluída/i);
  });

  it('shows the identity-required technical upload block reason', async () => {
    const envelope = {
      invite_id: 'invite-1',
      act: {
        id: 'act-1',
        title: 'Ata com identidade requerida',
        state: 'Sealed',
        entity_name: 'Encosto Estrategico, S.A.',
        book_kind: 'AssembleiaGeral',
      },
      recipient_name: 'Bruno Dias',
      purpose: 'Assinar a ata como administrador externo',
      status: 'pending',
      workflow: 'external_envelope',
      external_envelope: {
        id: 'env-1',
        slot_id: 'slot-1',
        order_policy: 'parallel',
        slot_status: 'initiated',
      },
      created_at: '2026-07-06T10:00:00Z',
      expires_at: '2026-07-08T10:00:00Z',
      notice: 'tracking only',
    };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json(envelope))
      .mockResolvedValueOnce(
        json({
          ...envelope,
          status: 'accepted',
          external_envelope: {
            ...envelope.external_envelope,
            slot_status: 'initiated',
            technical_upload_auto_sign: {
              status: 'blocked',
              reason: 'Technical slot update blocked because identity requirements are present.',
            },
          },
          signed_artifact: {
            family: 'ExternalSignerHandoff',
            evidentiary_level: 'ExternalSignedPdfTechnicalEvidence',
            signed_pdf_digest: 'a'.repeat(64),
            timestamp_token: false,
            status_scope: 'technical_evidence_only',
            qualification_claimed: false,
            legal_status_claimed: false,
            notice: 'Technical evidence only.',
          },
        }),
      );
    vi.stubGlobal('fetch', fetchMock);

    renderWithProviders(<ExternalSignerInvitePage />, [
      '/assinatura-externa?token=cxi_identity_token',
    ]);

    expect(await screen.findByText('Carregamento de evidência técnica')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('PDF assinado'), {
      target: {
        files: [new File(['%PDF-1.4\nidentity'], 'identity.pdf', { type: 'application/pdf' })],
      },
    });
    fireEvent.click(screen.getByLabelText(/Reconheço que este carregamento/));
    fireEvent.click(screen.getByRole('button', { name: 'Carregar PDF e aceitar' }));

    await waitFor(() =>
      expect(screen.getByText('Atualização técnica do slot bloqueada')).toBeTruthy(),
    );
    expect(screen.getByText(/identity requirements are present/)).toBeTruthy();
    expect(screen.getByText('Iniciado')).toBeTruthy();
    expect(document.body.textContent).not.toContain('cxi_identity_token');
  });

  it('rejects an oversized signed PDF before reading or submitting it', async () => {
    const envelope = {
      invite_id: 'invite-oversized',
      act: {
        id: 'act-1',
        title: 'Ata com envelope',
        state: 'Sealed',
        meeting_date: '2026-03-30',
        ata_number: 1,
        entity_name: 'Encosto Estrategico, S.A.',
        book_kind: 'AssembleiaGeral',
      },
      recipient_name: 'Bruno Dias',
      purpose: 'Assinar a ata como administrador externo',
      status: 'pending',
      workflow: 'external_envelope',
      external_envelope: {
        id: 'env-1',
        slot_id: 'slot-1',
        order_policy: 'parallel',
        slot_status: 'initiated',
      },
      created_at: '2026-07-06T10:00:00Z',
      expires_at: '2026-07-08T10:00:00Z',
      notice: 'tracking only',
    };
    const fetchMock = vi.fn().mockResolvedValueOnce(json(envelope));
    vi.stubGlobal('fetch', fetchMock);

    renderWithProviders(<ExternalSignerInvitePage />, [
      '/assinatura-externa?token=cxi_oversized_token',
    ]);

    expect(await screen.findByText('Carregamento de evidência técnica')).toBeTruthy();
    const signedPdf = new File(['%PDF-1.4\noversized'], 'oversized.pdf', {
      type: 'application/pdf',
    });
    const arrayBuffer = vi.fn().mockResolvedValue(new ArrayBuffer(0));
    Object.defineProperties(signedPdf, {
      arrayBuffer: { value: arrayBuffer },
      size: { value: EXTERNAL_INVITE_SIGNED_PDF_RAW_MAX_BYTES + 1 },
    });

    fireEvent.change(screen.getByLabelText('PDF assinado'), {
      target: { files: [signedPdf] },
    });
    fireEvent.click(screen.getByLabelText(/Reconheço que este carregamento/));
    fireEvent.click(screen.getByRole('button', { name: 'Carregar PDF e aceitar' }));

    expect(screen.getByText('O PDF assinado pode ter no máximo 16 MB.')).toBeTruthy();
    const submitButton = screen.getByRole<HTMLButtonElement>('button', {
      name: 'Carregar PDF e aceitar',
    });
    expect(submitButton.disabled).toBe(true);
    expect(arrayBuffer).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(document.body.textContent).not.toContain('cxi_oversized_token');
  });

  it('does not call the API when the link has no token', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    renderWithProviders(<ExternalSignerInvitePage />, ['/assinatura-externa']);

    expect(screen.getByText('Ligação sem token')).toBeTruthy();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
