import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import { ExternalSignerInvitePage } from './ExternalSignerInvitePage';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

afterEach(() => {
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

  it('does not call the API when the link has no token', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    renderWithProviders(<ExternalSignerInvitePage />, ['/assinatura-externa']);

    expect(screen.getByText('Ligação sem token')).toBeTruthy();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
