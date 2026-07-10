/**
 * SigningPanel tests (t57-S4): the two-phase CMD signing journey (initiate → OTP → confirm) over a
 * mocked api, the signed-status display + signed-PDF download gating, an honest expired-session
 * (410) restart, and a clean wrong-OTP (422) retry. Secrets (PIN/OTP) stay in transient form state.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { SigningPanel } from './SigningPanel';
import { renderWithProviders } from '../../test/utils';
import { StaticPermissionsProvider, permissionsValue } from '../session/permissions';
import { OFFICIAL_SIGNATURE_IMPORT_GUARDRAIL_IDS } from '../../api/types';
import type { ActView, SignatureEvidenceStatus, SignatureStatusView } from '../../api/types';

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

const unsignedStatus: SignatureStatusView = {
  status: 'unsigned',
  finalization: 'finalizado',
  require_qualified_for_seal: false,
  evidence: evidence('Unsigned', false, [
    'not_configured',
    'lt_not_implemented',
    'lta_not_implemented',
  ]),
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
  evidence: evidence('B-B', false, ['not_configured', 'lt_not_implemented', 'lta_not_implemented']),
};

function evidence(
  current_level: string,
  timestamp_evidence_present: boolean,
  long_term_status: SignatureEvidenceStatus['long_term_status'],
): SignatureEvidenceStatus {
  return {
    current_level,
    timestamp_evidence_present,
    dss_revocation_evidence_present: false,
    dss_revocation_evidence_status: 'unsupported',
    dss: {
      present: false,
      vri_count: 0,
      certificate_count: 0,
      ocsp_count: 0,
      crl_count: 0,
      certificate_sha256: [],
      ocsp_sha256: [],
      crl_sha256: [],
      revocation_evidence_present: false,
      inspection_status: 'not_applicable',
    },
    doc_timestamp: {
      present: false,
      count: 0,
      token_sha256: [],
      validations: [],
      all_imprints_valid: false,
      inspection_status: 'not_applicable',
    },
    local_b_lt_style_evidence_present: false,
    production_b_lt_status: 'not_claimed',
    live_revocation_fetching: false,
    legal_b_lt_claimed: false,
    legal_b_lta_claimed: false,
    renewal_policy: {
      status: 'not_configured',
      action: 'manual_review',
    },
    local_technical_renewal_plan: localTechnicalRenewalPlan(),
    multi_signature_local_renewal_plan: multiSignatureLocalRenewalPlan(),
    long_term_status,
    status_scope: 'technical_evidence_only',
  };
}

function localTechnicalRenewalPlan(
  overrides: Partial<SignatureEvidenceStatus['local_technical_renewal_plan']> = {},
): SignatureEvidenceStatus['local_technical_renewal_plan'] {
  return {
    status: 'unavailable',
    scope: 'signed_pdf',
    notice: 'Local embedded evidence planning only; not a B-LT/B-LTA or legal LTV claim.',
    signature_timestamp_present: false,
    dss_revocation_evidence_present: false,
    dss_validation_time_present: false,
    doc_timestamp_present: false,
    doc_timestamp_imprints_valid: false,
    missing_inputs: [],
    next_action: 'manual_review',
    has_local_evidence_gap: false,
    all_local_planning_inputs_present: false,
    production_long_term_profile_claimed: false,
    legal_ltv_claimed: false,
    ...overrides,
  };
}

function multiSignatureLocalRenewalPlan(
  overrides: Partial<SignatureEvidenceStatus['multi_signature_local_renewal_plan']> = {},
): SignatureEvidenceStatus['multi_signature_local_renewal_plan'] {
  return {
    status: 'not_applicable',
    scope: 'multi_signature_signed_pdf',
    notice: 'Local embedded evidence planning only; not a B-LT/B-LTA or legal LTV claim.',
    signature_count: 0,
    signatures: [],
    signatures_with_local_evidence_gaps: [],
    next_action: 'none',
    has_local_evidence_gap: false,
    all_local_planning_inputs_present: false,
    production_long_term_profile_claimed: false,
    legal_ltv_claimed: false,
    ...overrides,
  };
}

function json(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }),
  );
}

function emptyInviteList(url: string, method = 'GET'): Promise<Response> | null {
  if (url.includes('/signature/external-invites') && method === 'GET') return json([]);
  return null;
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
      return emptyInviteList(url, method) ?? Promise.reject(new Error(`no stub for ${url}`));
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
      return emptyInviteList(url, method) ?? Promise.reject(new Error(`no stub for ${url}`));
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
      return emptyInviteList(url) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    // jsdom lacks URL.createObjectURL — stub it for the browser-save fallback.
    const createUrl = vi.fn(() => 'blob:signed');
    const revokeUrl = vi.fn();
    vi.stubGlobal(
      'URL',
      Object.assign(URL, { createObjectURL: createUrl, revokeObjectURL: revokeUrl }),
    );
    const clickSpy = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);

    renderWithProviders(<SigningPanel act={sealedAct} entityName="Encosto Estratégico Lda" />);

    expect(await screen.findByText('CN=Amélia Marques,O=Encosto Estratégico Lda')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Descarregar PDF assinado' }));
    await waitFor(() => expect(createUrl).toHaveBeenCalled());
    expect(clickSpy).toHaveBeenCalled();
  });

  it('shows technical evidence status without implying B-LT/B-LTA support', async () => {
    const timestampedStatus: SignatureStatusView = {
      ...signedStatus,
      signed: { ...signedStatus.signed!, timestamp_token: true },
      evidence: evidence('B-T', true, ['timestamped', 'lt_not_implemented', 'lta_not_implemented']),
    };
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith('/signature')) return json(timestampedStatus);
      return emptyInviteList(url) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} />);

    expect(await screen.findByLabelText('Evidência técnica da assinatura')).toBeTruthy();
    expect(screen.getAllByText('PAdES B-T').length).toBeGreaterThan(0);
    expect(screen.getByText('Com selo temporal')).toBeTruthy();
    expect(screen.getByText(/B-LT não implementado/)).toBeTruthy();
    expect(screen.getByText(/B-LTA não implementado/)).toBeTruthy();
    expect(screen.getByText(/Não é uma decisão jurídica/)).toBeTruthy();
    expect(screen.getAllByRole('button', { name: 'Ajuda' }).length).toBeGreaterThan(0);
    expect(screen.queryByText('Lacunas locais')).toBeNull();
  });

  it('shows the available multi-signature local renewal plan as technical evidence only', async () => {
    const status: SignatureStatusView = {
      ...signedStatus,
      evidence: {
        ...evidence('B-LT-local', true, [
          'timestamped',
          'lt_local_technical_evidence_partial',
          'lt_production_not_claimed',
          'lta_not_implemented',
        ]),
        dss_revocation_evidence_present: true,
        dss_revocation_evidence_status: 'present_local_technical_only',
        local_b_lt_style_evidence_present: true,
        multi_signature_local_renewal_plan: multiSignatureLocalRenewalPlan({
          status: 'available',
          signature_count: 3,
          signatures_with_local_evidence_gaps: [0, 2],
          next_action: 'record_signature_dss_validation_time',
          has_local_evidence_gap: true,
          production_long_term_profile_claimed: false,
          legal_ltv_claimed: false,
        }),
      },
    };
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith('/signature')) return json(status);
      return emptyInviteList(url) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} />);

    expect(await screen.findByLabelText('Evidência técnica da assinatura')).toBeTruthy();
    expect(screen.getByText('Assinaturas')).toBeTruthy();
    expect(screen.getByText('Lacunas locais')).toBeTruthy();
    expect(screen.getByText('3')).toBeTruthy();
    expect(screen.getByText('2 (0, 2)')).toBeTruthy();
    expect(screen.getByText('registar tempo de validação DSS da assinatura')).toBeTruthy();
    expect(screen.getByText(/Plano de renovação local técnico apenas/)).toBeTruthy();
    expect(screen.getByText(/sem alegação de LTV legal/)).toBeTruthy();
    expect(screen.queryByText(/Atenção: a API devolveu/)).toBeNull();
  });
});

describe('SigningPanel — external signer invites', () => {
  it('lists invites, creates one with a one-time token, and revokes it', async () => {
    const createdInvite = {
      id: 'invite-1',
      act_id: 'act-1',
      recipient_name: 'Bruno Dias',
      recipient_email: 'bruno@example.test',
      provider_hint: 'manual-envelope',
      purpose: 'Assinar a ata como administrador externo',
      status: 'pending',
      workflow: 'tracking_only',
      token_hint: 'cxi_abcd...123456',
      created_at: '2026-07-06T10:00:00Z',
      created_by: 'amelia.marques',
      expires_at: '2026-07-08T10:00:00Z',
    };
    let invites: unknown[] = [];
    const bodies: unknown[] = [];

    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) return json([]);
      if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
      if (url.endsWith('/signature/external-invites') && method === 'GET') {
        return json(invites);
      }
      if (url.endsWith('/signature/external-invites') && method === 'POST') {
        bodies.push(JSON.parse(String(init?.body)));
        invites = [createdInvite];
        return json({ invite: createdInvite, token: 'cxi_fulltoken_1234567890' }, 201);
      }
      if (url.endsWith('/signature/external-invites/invite-1/revoke') && method === 'POST') {
        invites = [
          {
            ...createdInvite,
            status: 'revoked',
            revoked_at: '2026-07-06T10:10:00Z',
            revoked_by: 'amelia.marques',
          },
        ];
        return json(invites[0]);
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} />);

    expect(await screen.findByText('Convites de assinatura externa')).toBeTruthy();
    expect(await screen.findByText('Sem convites externos')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Criar convite' }));
    fireEvent.change(screen.getByLabelText('Nome do signatário'), {
      target: { value: 'Bruno Dias' },
    });
    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'bruno@example.test' },
    });
    fireEvent.change(screen.getByLabelText('Prestador ou referência'), {
      target: { value: 'manual-envelope' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Criar convite' }));

    expect(await screen.findByText('Token do convite emitido uma vez')).toBeTruthy();
    expect(screen.getByText('cxi_fulltoken_1234567890')).toBeTruthy();
    expect(screen.getByText(/assinatura-externa\?token=cxi_fulltoken_1234567890/)).toBeTruthy();
    expect(bodies[0]).toMatchObject({
      recipient_name: 'Bruno Dias',
      recipient_email: 'bruno@example.test',
      provider_hint: 'manual-envelope',
      purpose: 'Assinar a ata como signatário externo',
    });

    expect(await screen.findByText('Bruno Dias')).toBeTruthy();
    expect(screen.getByText('Acompanhamento apenas')).toBeTruthy();
    expect(screen.getByText('cxi_abcd...123456')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Revogar' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirmar revogação' }));

    await waitFor(() => expect(screen.getByText('Revogado')).toBeTruthy());
  });
});

// --- Cartão de Cidadão (CC) signing (t58) — synchronous, desktop-only -------------------

const ccSignedStatus: SignatureStatusView = {
  status: 'signed',
  finalization: 'finalizado_qualificado',
  require_qualified_for_seal: false,
  signed: {
    family: 'CartaoDeCidadao',
    evidentiary_level: 'Qualified',
    trusted_list_status: 'Granted',
    signer_cert_subject: 'CN=Amélia Marques,O=Encosto Estratégico Lda',
    signing_time: '2026-07-06T10:00:00Z',
    signed_at: '2026-07-06T10:00:05Z',
    signed_pdf_digest: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
    timestamp_token: false,
    download: '/v1/acts/act-1/document/signed',
  },
  evidence: evidence('B-B', false, ['not_configured', 'lt_not_implemented', 'lta_not_implemented']),
};

describe('SigningPanel — Cartão de Cidadão', () => {
  it('signs synchronously and flips to the signed CC record + download', async () => {
    let signed = false;
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.includes('/signature/cc/sign')) {
        signed = true;
        return json({
          document_id: 'doc-1',
          act_id: 'act-1',
          family: 'CartaoDeCidadao',
          evidentiary_level: 'Qualified',
          trusted_list_status: 'Granted',
          signed_at: '2026-07-06T10:00:05Z',
          signed_pdf_digest: ccSignedStatus.signed!.signed_pdf_digest,
          timestamp_token: false,
          finalization: 'finalizado_qualificado',
        });
      }
      if (url.endsWith('/signature') && method === 'GET') {
        return json(signed ? ccSignedStatus : unsignedStatus);
      }
      return emptyInviteList(url, method) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} entityName="Encosto Estratégico Lda" />);

    // Unsigned → the CC entry action → the honest prompt (no PIN field anywhere).
    fireEvent.click(await screen.findByRole('button', { name: 'Assinar com Cartão de Cidadão' }));
    const sign = await screen.findByRole('button', { name: 'Assinar com o cartão' });
    expect(screen.queryByLabelText('PIN de assinatura da CMD')).toBeNull();
    fireEvent.click(sign);

    // Signed: the CC-specific qualified label + the signed-PDF download.
    expect(
      await screen.findByText('Assinatura eletrónica qualificada (Cartão de Cidadão).'),
    ).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Descarregar PDF assinado' })).toBeTruthy();
  });

  it('renders an honest co-location note on a 409 (not co-located)', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.includes('/signature/cc/sign')) {
        return json(
          {
            error:
              'a assinatura com Cartão de Cidadão só está disponível na aplicação de secretária',
          },
          409,
        );
      }
      if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
      return emptyInviteList(url, method) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} />);

    fireEvent.click(await screen.findByRole('button', { name: 'Assinar com Cartão de Cidadão' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Assinar com o cartão' }));

    // 409 → honest co-location note; the CC entry affordance is dropped (not faked).
    expect(await screen.findByText('Disponível apenas na aplicação de secretária')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Assinar com Cartão de Cidadão' })).toBeNull();
  });

  it('surfaces a provider 422 honestly inline and stays on the CC step', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.includes('/signature/cc/sign')) {
        return json(
          {
            error:
              'não foi possível assinar com o Cartão de Cidadão (verifique o cartão, o leitor e o PIN): cartão não detetado',
          },
          422,
        );
      }
      if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
      return emptyInviteList(url, method) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} />);

    fireEvent.click(await screen.findByRole('button', { name: 'Assinar com Cartão de Cidadão' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Assinar com o cartão' }));

    // The honest server message renders inline; the flow stays on the CC step for a retry.
    expect(
      await screen.findByText(/não foi possível assinar com o Cartão de Cidadão/),
    ).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Assinar com o cartão' })).toBeTruthy();
  });

  it('gates the CC action with signing.perform (disable-with-explanation)', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith('/signature')) return json(unsignedStatus);
      return emptyInviteList(url) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    // A principal WITHOUT signing.perform: the CC action is present but inert (aria-disabled).
    renderWithProviders(
      <StaticPermissionsProvider value={permissionsValue((perm) => perm !== 'signing.perform')}>
        <SigningPanel act={sealedAct} />
      </StaticPermissionsProvider>,
    );

    const cc = await screen.findByRole('button', { name: 'Assinar com Cartão de Cidadão' });
    expect(cc.getAttribute('aria-disabled')).toBe('true');
    // Clicking the gated control does not advance to the CC prompt.
    fireEvent.click(cc);
    expect(screen.queryByRole('button', { name: 'Assinar com o cartão' })).toBeNull();
  });
});

// --- CSC QTSP providers (t59) — the provider picker + the generic two-phase flow --------

const cscSignedStatus: SignatureStatusView = {
  status: 'signed',
  finalization: 'finalizado_qualificado',
  require_qualified_for_seal: false,
  signed: {
    family: 'QualifiedCertificate',
    evidentiary_level: 'Qualified',
    trusted_list_status: 'Granted',
    signer_cert_subject: 'CN=Amélia Marques,O=Encosto Estratégico Lda',
    signing_time: '2026-07-06T10:00:00Z',
    signed_at: '2026-07-06T10:00:05Z',
    signed_pdf_digest: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
    timestamp_token: false,
    download: '/v1/acts/act-1/document/signed',
  },
  evidence: evidence('B-B', false, ['not_configured', 'lt_not_implemented', 'lta_not_implemented']),
};

const localPkcs12SignedStatus: SignatureStatusView = {
  status: 'signed',
  finalization: 'finalizado',
  require_qualified_for_seal: false,
  signed: {
    family: 'LocalPkcs12SoftwareCertificate',
    evidentiary_level: 'AdvancedLocalTechnicalEvidence',
    trusted_list_status: null,
    signer_cert_subject: 'CN=Amélia Marques,O=Encosto Estratégico Lda',
    signing_time: '2026-07-06T10:00:00Z',
    signed_at: '2026-07-06T10:00:05Z',
    signed_pdf_digest: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
    timestamp_token: false,
    download: '/v1/acts/act-1/document/signed',
  },
  evidence: evidence('B-B', false, ['not_configured', 'lt_not_implemented', 'lta_not_implemented']),
};

const officialHandoffSignedStatus: SignatureStatusView = {
  status: 'signed',
  finalization: 'finalizado',
  require_qualified_for_seal: false,
  signed: {
    family: 'AutenticacaoGovOfficialHandoff',
    evidentiary_level: 'ImportedOfficialHandoffTechnicalEvidence',
    trusted_list_status: null,
    signer_cert_subject: 'CN=Amélia Marques,O=Encosto Estratégico Lda',
    signing_time: '2026-07-06T10:00:00Z',
    signed_at: '2026-07-06T10:00:05Z',
    signed_pdf_digest: 'c1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
    timestamp_token: false,
    download: '/v1/acts/act-1/document/signed',
  },
  evidence: evidence('B-B', false, ['not_configured', 'lt_not_implemented', 'lta_not_implemented']),
};

/** A provider-list row builder (matches `SignatureProviderView`). */
function provider(id: string, label: string, family: string, configured: boolean) {
  return { id, family, label, evidentiary_level: 'Qualified', configured };
}

describe('SigningPanel — local PKCS#12 software certificate', () => {
  it('submits a transient PFX/passphrase request and refreshes to local technical evidence', async () => {
    let signed = false;
    let requestBody: Record<string, unknown> | null = null;
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) return json([]);
      if (url.includes('/signature/local/pkcs12/sign')) {
        requestBody = JSON.parse(String(init?.body));
        signed = true;
        return json({
          document_id: 'doc-1',
          act_id: 'act-1',
          family: 'LocalPkcs12SoftwareCertificate',
          evidentiary_level: 'AdvancedLocalTechnicalEvidence',
          trusted_list_status: null,
          signing_time: '2026-07-06T10:00:00Z',
          signed_at: '2026-07-06T10:00:05Z',
          signed_pdf_digest: localPkcs12SignedStatus.signed!.signed_pdf_digest,
          signer_cert_subject: 'CN=Amélia Marques,O=Encosto Estratégico Lda',
          signer_cert_sha256: 'b1'.repeat(32),
          certificate_chain_count: 1,
          timestamp_token: false,
          finalization: 'finalizado',
          qualification_claimed: false,
          legal_status_claimed: false,
          status_scope: 'local_technical_evidence_only',
          notice: 'technical evidence only',
        });
      }
      if (url.endsWith('/signature') && method === 'GET') {
        return json(signed ? localPkcs12SignedStatus : unsignedStatus);
      }
      return emptyInviteList(url, method) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} entityName="Encosto Estratégico Lda" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Assinar com PKCS#12 local' }));
    expect(await screen.findByText('Assinatura local com certificado de software')).toBeTruthy();
    expect(
      screen.getByText(/não é assinatura qualificada, CMD ou conclusão jurídica/),
    ).toBeTruthy();

    const file = new File(['pfx-bytes'], 'signer.pfx', { type: 'application/x-pkcs12' });
    Object.defineProperty(file, 'arrayBuffer', {
      value: () => Promise.resolve(new TextEncoder().encode('pfx-bytes').buffer),
    });
    fireEvent.change(screen.getByLabelText('Ficheiro PKCS#12/PFX'), {
      target: { files: [file] },
    });
    fireEvent.change(screen.getByLabelText('Palavra-passe do certificado'), {
      target: { value: 'pfx-passphrase' },
    });
    fireEvent.change(screen.getByLabelText('Nome amigável'), {
      target: { value: 'signing identity' },
    });
    fireEvent.change(screen.getByLabelText('Qualidade/capacidade'), {
      target: { value: 'Presidente da mesa' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Assinar localmente' }));

    await waitFor(() =>
      expect(requestBody).toMatchObject({
        pkcs12_base64: btoa('pfx-bytes'),
        passphrase: 'pfx-passphrase',
        friendly_name: 'signing identity',
        capacity: 'Presidente da mesa',
      }),
    );
    expect(await screen.findByText('Ata assinada com certificado de software local')).toBeTruthy();
    expect(
      screen.getByText(/evidência técnica avançada apenas; não é assinatura qualificada/),
    ).toBeTruthy();
    expect(screen.queryByLabelText('Palavra-passe do certificado')).toBeNull();
  });
});

describe('SigningPanel — official handoff import', () => {
  it('requires guardrail acknowledgement and submits the signed PDF with required ids', async () => {
    let signed = false;
    let requestBody: Record<string, unknown> | null = null;
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) return json([]);
      if (url.includes('/signature/official/import')) {
        requestBody = JSON.parse(String(init?.body));
        signed = true;
        return json({
          document_id: 'doc-1',
          act_id: 'act-1',
          family: 'AutenticacaoGovOfficialHandoff',
          evidentiary_level: 'ImportedOfficialHandoffTechnicalEvidence',
          trusted_list_status: null,
          legal_validation: {
            pades_valid: true,
            byte_range_covers_whole_file: true,
            sealed_pdf_prefix_match: true,
            trust_validation: 'not_performed',
            trust_validation_performed: false,
            qualified_status_claimed: false,
            legal_status_claimed: false,
          },
          signing_time: '2026-07-06T10:00:00Z',
          signed_at: '2026-07-06T10:00:05Z',
          signed_pdf_digest: officialHandoffSignedStatus.signed!.signed_pdf_digest,
          timestamp_token: false,
          finalization: 'finalizado',
          qualification_claimed: false,
          client_metadata_authoritative: false,
          guardrail_ids: OFFICIAL_SIGNATURE_IMPORT_GUARDRAIL_IDS,
          acknowledged_guardrail_ids: OFFICIAL_SIGNATURE_IMPORT_GUARDRAIL_IDS,
          acknowledgement_notice: 'technical evidence only',
        });
      }
      if (url.endsWith('/signature') && method === 'GET') {
        return json(signed ? officialHandoffSignedStatus : unsignedStatus);
      }
      return emptyInviteList(url, method) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} entityName="Encosto Estratégico Lda" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Importar PDF assinado' }));
    expect(await screen.findByText('Importar PDF assinado por handoff oficial')).toBeTruthy();
    expect(screen.getByText(/evidência técnica apenas/)).toBeTruthy();
    expect(screen.getByText(/não afirma validação na Lista de Confiança/)).toBeTruthy();
    expect(
      screen.queryByText(/validade legal|validade jurídica|legal-validity|legal validity/i),
    ).toBeNull();
    expect(screen.queryByLabelText('PIN de assinatura da CMD')).toBeNull();
    expect(screen.queryByLabelText('Código SMS (OTP)')).toBeNull();

    const submit = screen.getByRole('button', { name: 'Importar evidência técnica' });
    expect((submit as HTMLButtonElement).disabled).toBe(true);

    const file = new File(['%PDF-signed'], 'signed-by-official-app.pdf', {
      type: 'application/pdf',
    });
    Object.defineProperty(file, 'arrayBuffer', {
      value: () => Promise.resolve(new TextEncoder().encode('%PDF-signed').buffer),
    });
    fireEvent.change(screen.getByLabelText('PDF assinado'), {
      target: { files: [file] },
    });
    fireEvent.change(screen.getByLabelText('Prestador'), {
      target: { value: 'Autenticação.gov' },
    });
    fireEvent.change(screen.getByLabelText('Origem'), {
      target: { value: 'operator_selected_cc_or_cmd' },
    });
    expect((submit as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(submit);
    expect(requestBody).toBeNull();

    fireEvent.click(screen.getByLabelText(/reconheço estes limites/));
    expect((submit as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(submit);

    await waitFor(() =>
      expect(requestBody).toMatchObject({
        signed_pdf_base64: btoa('%PDF-signed'),
        provider: 'Autenticação.gov',
        source: 'operator_selected_cc_or_cmd',
        filename: 'signed-by-official-app.pdf',
        acknowledged_guardrail_ids: [...OFFICIAL_SIGNATURE_IMPORT_GUARDRAIL_IDS],
      }),
    );
    expect(requestBody).not.toHaveProperty('pin');
    expect(requestBody).not.toHaveProperty('otp');
    expect(requestBody).not.toHaveProperty('credential');
    expect(requestBody).not.toHaveProperty('passphrase');
    expect(
      await screen.findByText('Ata com PDF assinado importado da Autenticação.gov'),
    ).toBeTruthy();
  });
});

describe('SigningPanel — CSC QTSP providers', () => {
  it('lists a configured CSC QTSP and shows an unconfigured one disabled with an honest note', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith('/signature/providers')) {
        return json([
          provider('cmd', 'Chave Móvel Digital', 'ChaveMovelDigital', true),
          provider('multicert', 'Multicert', 'QualifiedCertificate', true),
          provider('digitalsign', 'DigitalSign', 'QualifiedCertificate', false),
        ]);
      }
      if (url.endsWith('/signature')) return json(unsignedStatus);
      return emptyInviteList(url) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} />);

    // CMD + CC are always offered; the configured QTSP is an enabled entry action.
    await screen.findByRole('button', { name: 'Assinar com Chave Móvel Digital' });
    expect(screen.getByText('Estado da assinatura')).toBeTruthy();
    expect(screen.getByText('Por assinar')).toBeTruthy();
    expect(
      screen.getByText(
        'Fluxo remoto em dois passos: PIN de assinatura e código SMS. Recomendado quando a CMD está ativa.',
      ),
    ).toBeTruthy();
    expect(screen.getByText(/O PIN nunca é pedido no browser/)).toBeTruthy();
    const mc = await screen.findByRole('button', { name: 'Assinar com Multicert' });
    expect(mc.getAttribute('aria-disabled')).not.toBe('true');
    expect(
      screen.getByText(
        'Prestador remoto qualificado. A app recolhe apenas a referência e encaminha a autorização para o prestador.',
      ),
    ).toBeTruthy();
    // The unconfigured QTSP is offered disabled with an honest «não configurado» note.
    const ds = screen.getByRole('button', { name: 'Assinar com DigitalSign' });
    expect((ds as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText('não configurado')).toBeTruthy();
  });

  it('keeps built-in modes usable when the remote provider list cannot be loaded', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith('/signature/providers')) {
        return json({ error: 'sem permissão para listar prestadores' }, 403);
      }
      if (url.endsWith('/signature')) return json(unsignedStatus);
      return emptyInviteList(url) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} />);

    expect(
      await screen.findByRole('button', { name: 'Assinar com Chave Móvel Digital' }),
    ).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Assinar com Cartão de Cidadão' })).toBeTruthy();
    expect(await screen.findByText('Prestadores remotos indisponíveis')).toBeTruthy();
    expect(
      screen.getByText(/Pode continuar com Chave Móvel Digital ou Cartão de Cidadão/),
    ).toBeTruthy();
  });

  it('signs via a CSC QTSP through the generic two-phase flow to a signed record', async () => {
    let signed = false;
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) {
        return json([provider('multicert', 'Multicert', 'QualifiedCertificate', true)]);
      }
      if (url.includes('/signature/remote/multicert/initiate')) {
        return json({
          session_id: 'sess-csc',
          provider_id: 'multicert',
          family: 'QualifiedCertificate',
          evidentiary_level: 'Qualified',
          status: 'activation_pending',
          activation_hint: 'confirme com o código de ativação enviado',
          expires_at: '2026-07-06T10:05:00Z',
        });
      }
      if (url.includes('/signature/remote/multicert/confirm')) {
        signed = true;
        return json({
          document_id: 'doc-1',
          act_id: 'act-1',
          provider_id: 'multicert',
          family: 'QualifiedCertificate',
          evidentiary_level: 'Qualified',
          trusted_list_status: 'Granted',
          signed_at: '2026-07-06T10:00:05Z',
          signed_pdf_digest: cscSignedStatus.signed!.signed_pdf_digest,
          timestamp_token: false,
          finalization: 'finalizado_qualificado',
        });
      }
      if (url.endsWith('/signature') && method === 'GET') {
        return json(signed ? cscSignedStatus : unsignedStatus);
      }
      return emptyInviteList(url, method) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} entityName="Encosto Estratégico Lda" />);

    // Choose the QTSP → phase 1 (user reference + credential; no CMD phone/PIN labels).
    fireEvent.click(await screen.findByRole('button', { name: 'Assinar com Multicert' }));
    const ref = (await screen.findByLabelText('Referência do utilizador')) as HTMLInputElement;
    const cred = screen.getByLabelText('Credencial de assinatura') as HTMLInputElement;
    expect(screen.queryByLabelText('PIN de assinatura da CMD')).toBeNull();
    fireEvent.change(ref, { target: { value: 'amelia.marques' } });
    fireEvent.change(cred, { target: { value: 'segredo' } });
    fireEvent.click(screen.getByRole('button', { name: 'Iniciar assinatura' }));

    // Phase 2: the activation code (the server's honest hint is echoed).
    const code = (await screen.findByLabelText('Código de autorização')) as HTMLInputElement;
    expect(screen.getByText('confirme com o código de ativação enviado')).toBeTruthy();
    fireEvent.change(code, { target: { value: '445566' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirmar assinatura' }));

    // Signed: the CSC-specific qualified label + the signed-PDF download.
    expect(
      await screen.findByText(
        'Assinatura eletrónica qualificada (certificado qualificado de prestador de confiança).',
      ),
    ).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Descarregar PDF assinado' })).toBeTruthy();
  });

  it('gates a CSC QTSP action with signing.perform (disable-with-explanation)', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith('/signature/providers')) {
        return json([provider('multicert', 'Multicert', 'QualifiedCertificate', true)]);
      }
      if (url.endsWith('/signature')) return json(unsignedStatus);
      return emptyInviteList(url) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(
      <StaticPermissionsProvider value={permissionsValue((perm) => perm !== 'signing.perform')}>
        <SigningPanel act={sealedAct} />
      </StaticPermissionsProvider>,
    );

    const mc = await screen.findByRole('button', { name: 'Assinar com Multicert' });
    expect(mc.getAttribute('aria-disabled')).toBe('true');
    fireEvent.click(mc);
    // The gated control does not advance to the CSC credentials step.
    expect(screen.queryByLabelText('Referência do utilizador')).toBeNull();
  });
});
