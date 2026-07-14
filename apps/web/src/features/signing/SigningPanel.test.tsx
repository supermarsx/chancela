/**
 * SigningPanel tests (t57-S4): the two-phase CMD signing journey (initiate → OTP → confirm) over a
 * mocked api, the signed-status display + signed-PDF download gating, an honest expired-session
 * (410) restart, and a clean wrong-OTP (422) retry. Secrets (PIN/OTP) stay in transient form state.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { SigningPanel } from './SigningPanel';
import { renderWithProviders } from '../../test/utils';
import { StaticPermissionsProvider, permissionsValue } from '../session/permissions';
import { OFFICIAL_SIGNATURE_IMPORT_GUARDRAIL_IDS } from '../../api/types';
import type {
  ActView,
  DocumentBundle,
  ExternalSigningEnvelopeView,
  SignatureEvidenceStatus,
  SignatureStatusView,
} from '../../api/types';

vi.mock('./seal-designer', async () => {
  const React = await import('react');
  return {
    SealDesigner: ({
      onApply,
    }: {
      onApply: (seal: {
        invisible: false;
        page: number;
        x: number;
        y: number;
        w: number;
        h: number;
        template: { kind: 'name_date'; name: string; date: string };
      }) => void;
    }) =>
      React.createElement(
        'button',
        {
          type: 'button',
          onClick: () =>
            onApply({
              invisible: false,
              page: 2,
              x: 10,
              y: 20,
              w: 120,
              h: 48,
              template: { kind: 'name_date', name: 'Amélia Marques', date: '2026-07-12' },
            }),
        },
        'Aplicar selo de teste',
      ),
  };
});

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

const canonicalPdfDigest = '0f'.repeat(32);

function signedAct(overrides: Partial<ActView> = {}): ActView {
  return {
    ...sealedAct,
    payload_digest: '11'.repeat(32),
    ...overrides,
  };
}

function documentBundle({
  fixity = {},
  signedDocument = {},
  document = {},
  validation = {},
}: {
  fixity?: Partial<DocumentBundle['validation_report']['fixity']>;
  signedDocument?: Partial<DocumentBundle['validation_report']['signed_document']>;
  document?: Partial<DocumentBundle['document']>;
  validation?: Partial<DocumentBundle['validation_report']>;
} = {}): DocumentBundle {
  const signedPdfDigest = signedStatus.signed!.signed_pdf_digest;
  const baseFixity: DocumentBundle['validation_report']['fixity'] = {
    canonical_pdf_sha256: canonicalPdfDigest,
    stored_pdf_digest: canonicalPdfDigest,
    canonical_pdf_digest_matches_metadata: true,
    attachment_count: 0,
    attachments_with_digest: 0,
    attachments_without_digest: 0,
    signed_pdf_sha256: signedPdfDigest,
    stored_signed_pdf_digest: signedPdfDigest,
    signed_pdf_digest_matches_metadata: true,
  };
  const baseSignedDocument: DocumentBundle['validation_report']['signed_document'] = {
    present: true,
    status: 'signed_pdf_metadata_present',
    document_id: 'doc-1',
    document_id_matches_canonical: true,
    byte_length: 1456,
    signed_pdf_digest: signedPdfDigest,
    signed_pdf_digest_matches_metadata: true,
    download: '/v1/acts/act-1/document/signed',
    signing_time: signedStatus.signed!.signing_time,
    signed_at: signedStatus.signed!.signed_at,
    stored_signature_family: signedStatus.signed!.family,
    stored_evidentiary_level: signedStatus.signed!.evidentiary_level,
    trusted_list_status: signedStatus.signed!.trusted_list_status,
    signer_cert_subject_present: true,
    timestamp_token_present: signedStatus.signed!.timestamp_token,
    structural_validation: null,
  };

  return {
    act_id: 'act-1',
    document: {
      id: 'doc-1',
      template_id: 'assoc-ata-ga',
      pdf_digest: canonicalPdfDigest,
      profile: 'pdfa-3',
      created_at: '2026-07-06T09:59:00Z',
      ...document,
    },
    pdf: {
      media_type: 'application/pdf',
      byte_length: 1234,
      download: '/v1/acts/act-1/document',
    },
    attachments_manifest: [],
    validation_report: {
      report_kind: 'document_bundle_validation',
      scope: 'generated_document_bundle',
      status: 'technical_consistent',
      legal_notice: 'Local document bundle metadata report only.',
      bundle_document_consistency: {
        route_act_id: 'act-1',
        stored_document_act_id: 'act-1',
        act_id_matches_document: true,
        document_id_present: true,
        template_id_present: true,
        created_at_present: true,
        profile_matches_expected: true,
        attachments_manifest_count: 0,
      },
      canonical_pdf: {
        present: true,
        media_type: 'application/pdf',
        byte_length: 1234,
        download: '/v1/acts/act-1/document',
        pdf_header_present: true,
        version: '1.7',
        eof_marker_present: true,
        startxref_present: true,
        pdfa_identification_markers_present: true,
      },
      fixity: { ...baseFixity, ...fixity },
      signed_document: { ...baseSignedDocument, ...signedDocument },
      non_certification: {
        legal_validity_claimed: false,
        pdfa_conformance_certified: false,
        pdfua_conformance_claimed: false,
        qualified_signature_claimed: false,
        dglab_certification_claimed: false,
        production_ltv_claimed: false,
        trust_provider_validation_performed: false,
      },
      findings: [],
      ...validation,
    },
  };
}

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
  if (url.endsWith('/document/bundle') && method === 'GET') return json(documentBundle());
  if (url.includes('/signature/external-invites') && method === 'GET') return json([]);
  if (url.includes('/external-signing/envelopes') && method === 'GET') return json([]);
  return null;
}

const envelopeNotice =
  'External signing envelope workflow only; no legal, qualified-signature, or certificate-level claim is made.';

function externalEnvelope(
  overrides: Partial<ExternalSigningEnvelopeView> = {},
): ExternalSigningEnvelopeView {
  return {
    id: 'env-1',
    act_id: 'act-1',
    order_policy: 'sequential',
    slots: [
      {
        id: 'slot-1',
        signer_label: 'Bruno Dias',
        contact_hint: 'bruno@example.test',
        identity_requirements: ['contact_control'],
        required: true,
        status: 'pending',
        evidence: [],
      },
      {
        id: 'slot-2',
        signer_label: 'Carla Sousa',
        required: true,
        status: 'initiated',
        evidence: [],
      },
    ],
    completed: false,
    completion: {
      completed: false,
      required_slot_count: 2,
      signed_required_slot_count: 0,
      blocking_required_slot_ids: ['slot-1', 'slot-2'],
    },
    notice: envelopeNotice,
    ...overrides,
  };
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
  it('restores an older CMD pending session without provider metadata through the dedicated confirm path', async () => {
    let signed = false;
    let cmdConfirmCalled = false;
    let remoteConfirmCalled = false;
    const pendingStatus: SignatureStatusView = {
      status: 'pending',
      finalization: 'finalizado',
      require_qualified_for_seal: false,
      pending: {
        session_id: 'sess-cmd',
        masked_phone: '+351 9••••678',
        expires_at: '2026-07-06T10:05:00Z',
      },
      evidence: evidence('Unsigned', false, [
        'not_configured',
        'lt_not_implemented',
        'lta_not_implemented',
      ]),
    };

    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) return json([]);
      if (url.endsWith('/signature') && method === 'GET') {
        return json(signed ? signedStatus : pendingStatus);
      }
      if (url.includes('/signature/remote/')) {
        remoteConfirmCalled = true;
        return json({ error: 'wrong endpoint' }, 500);
      }
      if (url.includes('/signature/cmd/confirm')) {
        cmdConfirmCalled = true;
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

    renderWithProviders(<SigningPanel act={sealedAct} />);

    fireEvent.change(await screen.findByLabelText('Código SMS (OTP)'), {
      target: { value: '999888' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirmar assinatura' }));

    await waitFor(() => expect(cmdConfirmCalled).toBe(true));
    expect(remoteConfirmCalled).toBe(false);
  });

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

  it('compares signed and bundle metadata when the local evidence matches', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith('/signature')) return json(signedStatus);
      return emptyInviteList(url) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={signedAct()} />);

    const panel = await screen.findByLabelText(
      'Comparação técnica local entre ato selado e PDF assinado',
    );
    expect(within(panel).getByText('Só metadados locais')).toBeTruthy();
    expect(within(panel).getByText('Sem reivindicação')).toBeTruthy();
    expect(within(panel).getByText('Digest do payload selado')).toBeTruthy();

    const signedDigestRow = within(panel).getAllByText('Digest do PDF assinado')[0].closest('div');
    expect(signedDigestRow).toBeTruthy();
    await waitFor(() =>
      expect(within(signedDigestRow as HTMLElement).getByText('Metadados coincidem')).toBeTruthy(),
    );

    const signedDocumentRow = within(panel).getByText('Documento assinado').closest('div');
    expect(signedDocumentRow).toBeTruthy();
    expect(within(signedDocumentRow as HTMLElement).getByText('Fornecido')).toBeTruthy();
    expect(panel.textContent).toContain('não lê PDF bruto');
    expect(panel.textContent).toContain('não recalcula digests');
  });

  it('surfaces signed metadata mismatches without turning them into validity claims', async () => {
    const mismatchedBundle = documentBundle({
      fixity: {
        signed_pdf_sha256: 'ff'.repeat(32),
        stored_signed_pdf_digest: 'ff'.repeat(32),
        signed_pdf_digest_matches_metadata: false,
      },
      signedDocument: {
        signed_pdf_digest: 'ff'.repeat(32),
        signed_pdf_digest_matches_metadata: false,
      },
    });
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith('/signature')) return json(signedStatus);
      if (url.endsWith('/document/bundle')) return json(mismatchedBundle);
      return emptyInviteList(url) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={signedAct()} />);

    const panel = await screen.findByLabelText(
      'Comparação técnica local entre ato selado e PDF assinado',
    );
    const signedDigestRow = within(panel).getAllByText('Digest do PDF assinado')[0].closest('div');
    expect(signedDigestRow).toBeTruthy();
    await waitFor(() =>
      expect(within(signedDigestRow as HTMLElement).getByText('Divergência')).toBeTruthy(),
    );
    expect(panel.textContent).toContain('não valida confiança');
    expect(panel.textContent).not.toContain('validade legal confirmada');
    expect(panel.textContent).not.toContain('validação externa concluída');
  });

  it('renders missing signed bundle metadata as unavailable instead of inferred', async () => {
    const missingSignedBundle = documentBundle({
      fixity: {
        signed_pdf_sha256: null,
        stored_signed_pdf_digest: null,
        signed_pdf_digest_matches_metadata: null,
      },
      signedDocument: {
        present: false,
        status: 'not_supplied',
        document_id: null,
        document_id_matches_canonical: null,
        byte_length: null,
        signed_pdf_digest: null,
        signed_pdf_digest_matches_metadata: null,
        download: null,
        signing_time: null,
        signed_at: null,
        stored_signature_family: null,
        stored_evidentiary_level: null,
        trusted_list_status: null,
        signer_cert_subject_present: null,
        timestamp_token_present: null,
      },
    });
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith('/signature')) return json(signedStatus);
      if (url.endsWith('/document/bundle')) return json(missingSignedBundle);
      return emptyInviteList(url) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={signedAct()} />);

    const panel = await screen.findByLabelText(
      'Comparação técnica local entre ato selado e PDF assinado',
    );
    const signedDocumentRow = within(panel).getByText('Documento assinado').closest('div');
    expect(signedDocumentRow).toBeTruthy();
    await waitFor(() =>
      expect(within(signedDocumentRow as HTMLElement).getByText('Não fornecido')).toBeTruthy(),
    );
    expect(
      Array.from(signedDocumentRow!.querySelectorAll('.signing-chip')).filter((chip) =>
        chip.textContent?.includes('não fornecido'),
      ),
    ).toHaveLength(2);

    const signedDigestRow = within(panel).getAllByText('Digest do PDF assinado')[0].closest('div');
    expect(signedDigestRow).toBeTruthy();
    await waitFor(() =>
      expect(within(signedDigestRow as HTMLElement).getByText('Não fornecido')).toBeTruthy(),
    );
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
      if (url.endsWith('/external-signing/envelopes') && method === 'GET') return json([]);
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
    expect(bodies[0]).not.toHaveProperty('external_envelope_id');
    expect(bodies[0]).not.toHaveProperty('external_slot_id');

    expect(await screen.findByText('Bruno Dias')).toBeTruthy();
    expect(screen.getByText('Acompanhamento apenas')).toBeTruthy();
    expect(screen.getByText('cxi_abcd...123456')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Revogar' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirmar revogação' }));

    await waitFor(() => expect(screen.getByText('Revogado')).toBeTruthy());
  });

  it('lists external-signing envelopes, slots, and the backend no-legal notice', async () => {
    const envelope = externalEnvelope();

    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) return json([]);
      if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
      if (url.endsWith('/external-signing/envelopes') && method === 'GET') {
        return json([envelope]);
      }
      if (url.endsWith('/signature/external-invites') && method === 'GET') return json([]);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} />);

    expect(await screen.findByText('Envelopes de assinatura externa')).toBeTruthy();
    expect(await screen.findByText(envelopeNotice)).toBeTruthy();
    expect(screen.getByText('Bruno Dias')).toBeTruthy();
    expect(screen.getByText('Carla Sousa')).toBeTruthy();
    expect(screen.getAllByText('Sequencial').length).toBeGreaterThan(0);
    expect(screen.getByText('Controlo do contacto')).toBeTruthy();
    expect(screen.getAllByText('Pendente').length).toBeGreaterThan(0);
    expect(screen.getByText('Iniciado')).toBeTruthy();
  });

  it('displays completed external-signing envelope progress from the backend summary', async () => {
    const envelope = externalEnvelope({
      slots: [
        {
          id: 'slot-1',
          signer_label: 'Bruno Dias',
          contact_hint: 'bruno@example.test',
          required: true,
          status: 'signed',
          evidence: [
            {
              label: 'Signed PDF SHA-256',
              reference: 'technical upload',
              digest: 'f'.repeat(64),
            },
            {
              label: 'Contact channel evidence',
              reference: 'operator-log:contact-control',
              identity_requirement: 'contact_control',
            },
          ],
        },
      ],
      completed: true,
      completion: {
        completed: true,
        required_slot_count: 1,
        signed_required_slot_count: 1,
        blocking_required_slot_ids: [],
      },
    });

    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) return json([]);
      if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
      if (url.endsWith('/external-signing/envelopes') && method === 'GET') {
        return json([envelope]);
      }
      if (url.endsWith('/signature/external-invites') && method === 'GET') return json([]);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} />);

    expect(await screen.findByText('1 de 1 assinados')).toBeTruthy();
    expect(screen.getByText('Concluído')).toBeTruthy();
    expect(screen.getByText('Nenhum')).toBeTruthy();
    expect(screen.getByText('Assinado')).toBeTruthy();
    expect(screen.getByText('Signed PDF SHA-256')).toBeTruthy();
    expect(screen.getByText('technical upload')).toBeTruthy();
    expect(screen.getByTitle('f'.repeat(64))).toBeTruthy();
    expect(screen.getByText('Contact channel evidence')).toBeTruthy();
    expect(screen.getByText('operator-log:contact-control')).toBeTruthy();
    expect(screen.getByText('Controlo do contacto')).toBeTruthy();
  });

  it('creates an external-signing envelope with order policy and signer slots', async () => {
    let envelopes: ExternalSigningEnvelopeView[] = [];
    const bodies: unknown[] = [];

    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) return json([]);
      if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
      if (url.endsWith('/signature/external-invites') && method === 'GET') return json([]);
      if (url.endsWith('/external-signing/envelopes') && method === 'GET') {
        return json(envelopes);
      }
      if (url.endsWith('/external-signing/envelopes') && method === 'POST') {
        bodies.push(JSON.parse(String(init?.body)));
        envelopes = [externalEnvelope({ slots: externalEnvelope().slots.slice(0, 1) })];
        return json(envelopes[0], 201);
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} />);

    fireEvent.click(await screen.findByRole('button', { name: 'Criar envelope' }));
    fireEvent.change(screen.getByLabelText('Política de ordem'), {
      target: { value: 'sequential' },
    });
    fireEvent.change(screen.getByLabelText('Signatário do slot 1'), {
      target: { value: 'Bruno Dias' },
    });
    fireEvent.change(screen.getByLabelText('Contacto ou referência'), {
      target: { value: 'bruno@example.test' },
    });
    fireEvent.change(screen.getByLabelText('Requisito de identidade'), {
      target: { value: 'contact_control' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Criar envelope' }));

    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({
      order_policy: 'sequential',
      slots: [
        {
          signer_label: 'Bruno Dias',
          contact_hint: 'bruno@example.test',
          identity_requirements: ['contact_control'],
          required: true,
        },
      ],
    });
  });

  it('submits identity-tagged slot evidence without completing the envelope', async () => {
    const bodies: unknown[] = [];
    const slot: ExternalSigningEnvelopeView['slots'][number] = {
      ...externalEnvelope().slots[0],
      identity_requirements: ['contact_control', 'provider_identity_assertion'],
      evidence: [],
    };
    let envelopes: ExternalSigningEnvelopeView[] = [
      externalEnvelope({
        order_policy: 'parallel',
        slots: [slot],
        completion: {
          completed: false,
          required_slot_count: 1,
          signed_required_slot_count: 0,
          blocking_required_slot_ids: ['slot-1'],
        },
      }),
    ];

    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) return json([]);
      if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
      if (url.endsWith('/external-signing/envelopes') && method === 'GET') {
        return json(envelopes);
      }
      if (url.endsWith('/external-signing/envelopes/env-1') && method === 'PATCH') {
        const body = JSON.parse(String(init?.body));
        bodies.push(body);
        const evidenceRows = body.slots[0].evidence;
        envelopes = [
          {
            ...envelopes[0],
            slots: [{ ...slot, status: 'signed', evidence: evidenceRows }],
            completion: {
              completed: false,
              required_slot_count: 1,
              signed_required_slot_count: 1,
              blocking_required_slot_ids: [],
            },
          },
        ];
        return json(envelopes[0]);
      }
      if (url.endsWith('/signature/external-invites') && method === 'GET') return json([]);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} />);

    fireEvent.click(await screen.findByRole('button', { name: 'Registar evidência' }));
    const submit = screen.getByRole('button', {
      name: 'Registar evidência e marcar slot assinado',
    }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);

    fireEvent.change(screen.getByLabelText('Referência da evidência'), {
      target: { value: 'operator-log:slot-1' },
    });
    fireEvent.change(screen.getByLabelText('Digest opcional'), {
      target: { value: 'b'.repeat(64) },
    });
    fireEvent.change(screen.getByLabelText('Referência para Controlo do contacto'), {
      target: { value: 'operator-log:contact-control' },
    });
    expect(submit.disabled).toBe(true);

    fireEvent.change(
      screen.getByLabelText('Referência para Declaração de identidade do prestador'),
      {
        target: { value: 'operator-log:provider-identity' },
      },
    );
    expect(submit.disabled).toBe(false);

    fireEvent.click(submit);

    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({
      slots: [
        {
          id: 'slot-1',
          status: 'signed',
          evidence: [
            {
              label: 'Evidência técnica do operador',
              reference: 'operator-log:slot-1',
              digest: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            },
            {
              label: 'Evidência técnica: Controlo do contacto',
              reference: 'operator-log:contact-control',
              identity_requirement: 'contact_control',
            },
            {
              label: 'Evidência técnica: Declaração de identidade do prestador',
              reference: 'operator-log:provider-identity',
              identity_requirement: 'provider_identity_assertion',
            },
          ],
        },
      ],
    });
    expect(bodies[0]).not.toHaveProperty('complete');
  });

  it('creates an invite linked to a selected envelope slot', async () => {
    const bodies: unknown[] = [];
    const envelope = externalEnvelope({
      order_policy: 'parallel',
      slots: [externalEnvelope().slots[0]],
      completion: {
        completed: false,
        required_slot_count: 1,
        signed_required_slot_count: 0,
        blocking_required_slot_ids: ['slot-1'],
      },
    });
    const createdInvite = {
      id: 'invite-1',
      act_id: 'act-1',
      recipient_name: 'Bruno Dias',
      recipient_email: 'bruno@example.test',
      purpose: 'Assinar a ata como signatário externo',
      status: 'pending',
      workflow: 'external_envelope',
      external_envelope: {
        id: 'env-1',
        slot_id: 'slot-1',
        order_policy: 'parallel',
        slot_status: 'initiated',
      },
      token_hint: 'cxi_abcd...123456',
      created_at: '2026-07-06T10:00:00Z',
      created_by: 'amelia.marques',
      expires_at: '2026-07-08T10:00:00Z',
    };

    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) return json([]);
      if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
      if (url.endsWith('/external-signing/envelopes') && method === 'GET') return json([envelope]);
      if (url.endsWith('/signature/external-invites') && method === 'GET') return json([]);
      if (url.endsWith('/signature/external-invites') && method === 'POST') {
        bodies.push(JSON.parse(String(init?.body)));
        return json({ invite: createdInvite, token: 'cxi_fulltoken_1234567890' }, 201);
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} />);

    fireEvent.click(await screen.findByRole('button', { name: 'Criar convite' }));
    fireEvent.change(screen.getByLabelText('Nome do signatário'), {
      target: { value: 'Bruno Dias' },
    });
    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'bruno@example.test' },
    });
    fireEvent.change(screen.getByLabelText('Slot do envelope'), {
      target: { value: 'env-1:slot-1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Criar convite' }));

    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toMatchObject({
      recipient_name: 'Bruno Dias',
      recipient_email: 'bruno@example.test',
      external_envelope_id: 'env-1',
      external_slot_id: 'slot-1',
    });
  });

  it('shows a safe sequential-order conflict without leaking token material', async () => {
    const bodies: unknown[] = [];
    const envelope = externalEnvelope({
      slots: [externalEnvelope().slots[0]],
      completion: {
        completed: false,
        required_slot_count: 1,
        signed_required_slot_count: 0,
        blocking_required_slot_ids: ['slot-1'],
      },
    });

    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) return json([]);
      if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
      if (url.endsWith('/external-signing/envelopes') && method === 'GET') return json([envelope]);
      if (url.endsWith('/signature/external-invites') && method === 'GET') return json([]);
      if (url.endsWith('/signature/external-invites') && method === 'POST') {
        bodies.push(JSON.parse(String(init?.body)));
        return json({ error: 'blocked for cxi_should_not_render' }, 409);
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} />);

    fireEvent.click(await screen.findByRole('button', { name: 'Criar convite' }));
    fireEvent.change(screen.getByLabelText('Nome do signatário'), {
      target: { value: 'Bruno Dias' },
    });
    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'bruno@example.test' },
    });
    fireEvent.change(screen.getByLabelText('Slot do envelope'), {
      target: { value: 'env-1:slot-1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Criar convite' }));

    expect(await screen.findByText('Slot ainda não disponível')).toBeTruthy();
    expect(screen.getAllByText(/slot obrigatório anterior em aberto/).length).toBeGreaterThan(0);
    expect(screen.queryByText(/cxi_should_not_render/)).toBeNull();
    expect(screen.queryByText(/Token do convite emitido uma vez/)).toBeNull();
    expect(bodies[0]).toMatchObject({
      external_envelope_id: 'env-1',
      external_slot_id: 'slot-1',
    });

    fireEvent.change(screen.getByLabelText('Slot do envelope'), {
      target: { value: '' },
    });

    await waitFor(() => expect(screen.queryByText('Slot ainda não disponível')).toBeNull());
    expect(screen.queryByText(/cxi_should_not_render/)).toBeNull();
    expect(screen.queryByText(/blocked for/)).toBeNull();
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
  it('submits an optional in-app PIN and flips to the signed CC record + download', async () => {
    let signed = false;
    let ccBody: unknown = null;
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.includes('/signature/cc/sign')) {
        ccBody = JSON.parse(String(init?.body));
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

    // Unsigned -> the CC entry action -> the honest prompt with a bounded optional PIN field.
    fireEvent.click(await screen.findByRole('button', { name: 'Assinar com Cartão de Cidadão' }));
    const sign = await screen.findByRole('button', { name: 'Assinar com o cartão' });
    fireEvent.change(screen.getByLabelText('PIN de assinatura do Cartão de Cidadão (opcional)'), {
      target: { value: ' 123456 ' },
    });
    fireEvent.click(sign);

    // Signed: the CC-specific qualified label + the signed-PDF download.
    expect(
      await screen.findByText('Assinatura eletrónica qualificada (Cartão de Cidadão).'),
    ).toBeTruthy();
    expect(ccBody).toEqual({ pin: '123456' });
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
    await waitFor(() =>
      expect(
        screen.getByLabelText('PIN de assinatura do Cartão de Cidadão (opcional)').closest('form')
          ?.textContent,
      ).toContain('não foi possível assinar com o Cartão de Cidadão'),
    );
    expect(screen.getByRole('button', { name: 'Assinar com o cartão' })).toBeTruthy();
  });

  it('keeps a structured CC PIN rejection visible after clearing mutation state', async () => {
    const bodies: unknown[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.includes('/signature/cc/sign')) {
        bodies.push(JSON.parse(String(init?.body)));
        return json(
          {
            error: 'PIN rejected',
            pin_status: 'wrong_pin',
            tries_left: 'final_try',
          },
          422,
        );
      }
      if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
      return emptyInviteList(url, method) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} />);

    fireEvent.click(await screen.findByRole('button', { name: 'Assinar com Cartão de Cidadão' }));
    fireEvent.change(
      await screen.findByLabelText('PIN de assinatura do Cartão de Cidadão (opcional)'),
      {
        target: { value: '0000' },
      },
    );
    fireEvent.click(screen.getByRole('button', { name: 'Assinar com o cartão' }));

    expect(await screen.findByText(/PIN de assinatura incorreto/)).toBeTruthy();
    expect(screen.getByText(/última tentativa/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Assinar com o cartão' })).toBeTruthy();
    expect(
      (
        screen.getByLabelText(
          'PIN de assinatura do Cartão de Cidadão (opcional)',
        ) as HTMLInputElement
      ).value,
    ).toBe('');
    expect(bodies).toEqual([{ pin: '0000' }]);
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

  it('threads an applied visible seal into the local PKCS#12 signing request', async () => {
    let requestBody: Record<string, unknown> | null = null;
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) return json([]);
      if (url.includes('/signature/local/pkcs12/sign')) {
        requestBody = JSON.parse(String(init?.body));
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
      if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
      return emptyInviteList(url, method) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} entityName="Encosto Estratégico Lda" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Posicionar selo visível' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Aplicar selo de teste' }));
    expect(await screen.findByText('Selo visível posicionado na página 3.')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Assinar com PKCS#12 local' }));
    const file = new File(['pfx-bytes'], 'signer.pfx', { type: 'application/x-pkcs12' });
    Object.defineProperty(file, 'arrayBuffer', {
      value: () => Promise.resolve(new TextEncoder().encode('pfx-bytes').buffer),
    });
    fireEvent.change(await screen.findByLabelText('Ficheiro PKCS#12/PFX'), {
      target: { files: [file] },
    });
    fireEvent.change(screen.getByLabelText('Palavra-passe do certificado'), {
      target: { value: 'pfx-passphrase' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Assinar localmente' }));

    await waitFor(() =>
      expect(requestBody).toMatchObject({
        pkcs12_base64: btoa('pfx-bytes'),
        passphrase: 'pfx-passphrase',
        seal: {
          invisible: false,
          page: 2,
          x: 10,
          y: 20,
          w: 120,
          h: 48,
          template: { kind: 'name_date', name: 'Amélia Marques', date: '2026-07-12' },
        },
      }),
    );
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

  it('restores a reloaded CSC pending session through the generic remote confirm path', async () => {
    let signed = false;
    let remoteConfirmCalled = false;
    let cmdConfirmCalled = false;
    const pendingStatus: SignatureStatusView = {
      status: 'pending',
      finalization: 'finalizado',
      require_qualified_for_seal: false,
      pending: {
        session_id: 'sess-csc',
        masked_phone: 'confirme com o código de ativação enviado',
        provider_id: 'multicert',
        family: 'QualifiedCertificate',
        activation_hint: 'confirme com o código de ativação enviado',
        expires_at: '2026-07-06T10:05:00Z',
      },
      evidence: evidence('Unsigned', false, [
        'not_configured',
        'lt_not_implemented',
        'lta_not_implemented',
      ]),
    };

    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) {
        return json([provider('multicert', 'Multicert', 'QualifiedCertificate', true)]);
      }
      if (url.includes('/signature/cmd/confirm')) {
        cmdConfirmCalled = true;
        return json({ error: 'wrong endpoint' }, 500);
      }
      if (url.includes('/signature/remote/multicert/confirm')) {
        remoteConfirmCalled = true;
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
        return json(signed ? cscSignedStatus : pendingStatus);
      }
      return emptyInviteList(url, method) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} />);

    fireEvent.change(await screen.findByLabelText('Código de autorização'), {
      target: { value: '445566' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirmar assinatura' }));

    await waitFor(() => expect(remoteConfirmCalled).toBe(true));
    expect(cmdConfirmCalled).toBe(false);
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

describe('SigningPanel — remote batch initiation', () => {
  function remoteBatchResponse(providerId: string, sessionId: string) {
    return {
      provider_id: providerId,
      family: 'QualifiedCertificate',
      evidentiary_level: 'Qualified',
      auth_mode: 'per_document_activation',
      requested: 2,
      pending: 2,
      failed: 0,
      initiate_events: 2,
      results: [
        {
          act_id: 'act-1',
          status: 'pending',
          session_id: sessionId,
          provider_id: providerId,
          family: 'QualifiedCertificate',
          pending_status: 'activation_pending',
          activation_hint: `ativação ${providerId}`,
          expires_at: '2026-07-14T10:05:00Z',
        },
        {
          act_id: 'act-2',
          status: 'pending',
          session_id: `${sessionId}-2`,
          provider_id: providerId,
          family: 'QualifiedCertificate',
          pending_status: 'activation_pending',
          activation_hint: `ativação ${providerId}`,
          expires_at: '2026-07-14T10:05:00Z',
        },
      ],
    };
  }

  it('submits per-document remote initiate payloads and renders redacted pending/error rows', async () => {
    let requestBody: Record<string, unknown> | null = null;
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) {
        return json([provider('multicert', 'Multicert', 'QualifiedCertificate', true)]);
      }
      if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
      if (url.endsWith('/v1/signature/remote/multicert/batch-initiate')) {
        requestBody = JSON.parse(String(init?.body));
        return json({
          provider_id: 'multicert',
          family: 'QualifiedCertificate',
          evidentiary_level: 'Qualified',
          auth_mode: 'per_document_activation',
          requested: 2,
          pending: 1,
          failed: 1,
          initiate_events: 1,
          results: [
            {
              act_id: 'act-1',
              status: 'pending',
              session_id: 'sess-remote-1',
              provider_id: 'multicert',
              family: 'QualifiedCertificate',
              pending_status: 'activation_pending',
              activation_hint: 'código enviado para a primeira ata',
              expires_at: '2026-07-14T10:05:00Z',
            },
            {
              act_id: 'act-2',
              status: 'error',
              error: 'ato já assinado',
            },
          ],
        });
      }
      return emptyInviteList(url, method) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} entityName="Encosto Estratégico Lda" />);

    const region = await screen.findByLabelText('Início remoto por documento');
    const batch = within(region);
    expect(batch.getByText('Uma ativação por documento')).toBeTruthy();

    fireEvent.change(batch.getByLabelText('ID do ato'), { target: { value: 'act-2' } });
    fireEvent.click(batch.getByRole('button', { name: 'Adicionar' }));
    fireEvent.change(batch.getByLabelText('Referência do utilizador para sessões remotas'), {
      target: { value: ' amelia.marques ' },
    });
    fireEvent.change(batch.getByLabelText('Credencial para sessões remotas'), {
      target: { value: 'transient-secret' },
    });
    fireEvent.change(batch.getByLabelText('Qualidade/capacidade declarada'), {
      target: { value: ' Presidente da Mesa ' },
    });
    fireEvent.change(batch.getByLabelText('Ator'), { target: { value: ' operator-1 ' } });
    fireEvent.click(batch.getByRole('button', { name: 'Iniciar sessões remotas' }));

    await waitFor(() =>
      expect(requestBody).toEqual({
        act_ids: ['act-1', 'act-2'],
        user_ref: 'amelia.marques',
        credential: 'transient-secret',
        capacity: 'Presidente da Mesa',
        actor: 'operator-1',
      }),
    );
    await waitFor(() =>
      expect(
        (batch.getByLabelText('Credencial para sessões remotas') as HTMLInputElement).value,
      ).toBe(''),
    );

    expect(batch.getAllByText('Ativação por documento').length).toBeGreaterThan(0);
    expect(batch.getByText('sess-remote-1')).toBeTruthy();
    expect(batch.getByText('multicert')).toBeTruthy();
    expect(batch.getByText('código enviado para a primeira ata')).toBeTruthy();
    expect(batch.getByText('ato já assinado')).toBeTruthy();
    expect(batch.getByText('Confirmar no fluxo normal deste ato.')).toBeTruthy();
    expect(
      batch.getByText('A resposta não mostra credenciais, códigos ou ativações.'),
    ).toBeTruthy();
    expect(region.textContent).not.toContain('transient-secret');
  });

  it('clears provider-bound credentials and stale remote batch results on provider switch', async () => {
    let multicertRequest: Record<string, unknown> | null = null;
    let digitalsignRequest: Record<string, unknown> | null = null;
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) {
        return json([
          provider('multicert', 'Multicert', 'QualifiedCertificate', true),
          provider('digitalsign', 'DigitalSign', 'QualifiedCertificate', true),
        ]);
      }
      if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
      if (url.endsWith('/v1/signature/remote/multicert/batch-initiate')) {
        multicertRequest = JSON.parse(String(init?.body));
        return json(remoteBatchResponse('multicert', 'sess-multicert'));
      }
      if (url.endsWith('/v1/signature/remote/digitalsign/batch-initiate')) {
        digitalsignRequest = JSON.parse(String(init?.body));
        return json(remoteBatchResponse('digitalsign', 'sess-digitalsign'));
      }
      return emptyInviteList(url, method) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} entityName="Encosto Estratégico Lda" />);

    const region = await screen.findByLabelText('Início remoto por documento');
    const batch = within(region);
    fireEvent.change(batch.getByLabelText('ID do ato'), { target: { value: 'act-2' } });
    fireEvent.click(batch.getByRole('button', { name: 'Adicionar' }));
    fireEvent.change(batch.getByLabelText('Referência do utilizador para sessões remotas'), {
      target: { value: 'amelia.marques' },
    });
    fireEvent.change(batch.getByLabelText('Credencial para sessões remotas'), {
      target: { value: 'first-secret' },
    });
    fireEvent.click(batch.getByRole('button', { name: 'Iniciar sessões remotas' }));

    await waitFor(() =>
      expect(multicertRequest).toMatchObject({
        act_ids: ['act-1', 'act-2'],
        user_ref: 'amelia.marques',
        credential: 'first-secret',
      }),
    );
    expect(await batch.findByText('sess-multicert')).toBeTruthy();

    fireEvent.change(batch.getByLabelText('Prestador remoto'), {
      target: { value: 'digitalsign' },
    });

    await waitFor(() => expect(batch.queryByText('sess-multicert')).toBeNull());
    expect(
      (batch.getByLabelText('Credencial para sessões remotas') as HTMLInputElement).value,
    ).toBe('');

    fireEvent.change(batch.getByLabelText('Prestador remoto'), {
      target: { value: 'multicert' },
    });
    fireEvent.change(batch.getByLabelText('Credencial para sessões remotas'), {
      target: { value: 'old-provider-secret' },
    });
    fireEvent.change(batch.getByLabelText('Prestador remoto'), {
      target: { value: 'digitalsign' },
    });
    expect(
      (batch.getByLabelText('Credencial para sessões remotas') as HTMLInputElement).value,
    ).toBe('');
    fireEvent.click(batch.getByRole('button', { name: 'Iniciar sessões remotas' }));

    await waitFor(() =>
      expect(digitalsignRequest).toEqual({
        act_ids: ['act-1', 'act-2'],
        user_ref: 'amelia.marques',
      }),
    );
    expect(JSON.stringify(digitalsignRequest)).not.toContain('old-provider-secret');
  });

  it('clears stale remote batch results when request fields or act selection change', async () => {
    let submitCount = 0;
    const requestBodies: Record<string, unknown>[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) {
        return json([provider('multicert', 'Multicert', 'QualifiedCertificate', true)]);
      }
      if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
      if (url.endsWith('/v1/signature/remote/multicert/batch-initiate')) {
        submitCount += 1;
        requestBodies.push(JSON.parse(String(init?.body)));
        return json(remoteBatchResponse('multicert', `sess-request-${submitCount}`));
      }
      return emptyInviteList(url, method) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} entityName="Encosto Estratégico Lda" />);

    const region = await screen.findByLabelText('Início remoto por documento');
    const batch = within(region);
    fireEvent.change(batch.getByLabelText('ID do ato'), { target: { value: 'act-2' } });
    fireEvent.click(batch.getByRole('button', { name: 'Adicionar' }));
    fireEvent.change(batch.getByLabelText('Referência do utilizador para sessões remotas'), {
      target: { value: 'amelia.marques' },
    });
    fireEvent.click(batch.getByRole('button', { name: 'Iniciar sessões remotas' }));

    expect(await batch.findByText('sess-request-1')).toBeTruthy();
    fireEvent.change(batch.getByLabelText('Referência do utilizador para sessões remotas'), {
      target: { value: 'bruno.dias' },
    });
    await waitFor(() => expect(batch.queryByText('sess-request-1')).toBeNull());

    fireEvent.click(batch.getByRole('button', { name: 'Iniciar sessões remotas' }));
    expect(await batch.findByText('sess-request-2')).toBeTruthy();
    fireEvent.click(batch.getByLabelText('Selecionar ato act-2'));
    await waitFor(() => expect(batch.queryByText('sess-request-2')).toBeNull());

    fireEvent.click(batch.getByLabelText('Selecionar ato act-2'));
    fireEvent.click(batch.getByRole('button', { name: 'Iniciar sessões remotas' }));
    expect(await batch.findByText('sess-request-3')).toBeTruthy();
    fireEvent.click(batch.getByRole('button', { name: 'Remover ato' }));
    await waitFor(() => expect(batch.queryByText('sess-request-3')).toBeNull());

    expect(requestBodies).toHaveLength(3);
    expect(requestBodies[1]).toMatchObject({ user_ref: 'bruno.dias' });
  });
});

// A binary document response for the local XAdES/ASiC tools' `loadContentBase64` (the act's PDF/A).
function pdf(bytes: string, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(new TextEncoder().encode(bytes), {
      status,
      headers: { 'Content-Type': 'application/pdf' },
    }),
  );
}

function pkcs12File(bytes = 'pfx-bytes'): File {
  const file = new File([bytes], 'signer.pfx', { type: 'application/x-pkcs12' });
  Object.defineProperty(file, 'arrayBuffer', {
    value: () => Promise.resolve(new TextEncoder().encode(bytes).buffer),
  });
  return file;
}

describe('SigningPanel — signing-format selector (t67-e13)', () => {
  it('routes an XAdES format/level/packaging choice to the xades/sign endpoint body', async () => {
    let requestUrl: string | null = null;
    let requestBody: Record<string, unknown> | null = null;
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) return json([]);
      if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
      if (url.endsWith('/v1/acts/act-1/document') && method === 'GET') return pdf('%PDF-1.7');
      if (url.includes('/v1/signature/xades/sign')) {
        requestUrl = url;
        requestBody = JSON.parse(String(init?.body));
        return json({
          report_kind: 'xades_signature',
          scope: 'local_technical_xades_evidence',
          legal_notice: 'Local technical XAdES signature production only.',
          xades_base64: btoa('<xml/>'),
          xades_sha256: 'ab'.repeat(32),
          level: 'XAdES-T',
          packaging: 'enveloping',
          content_sha256: 'cd'.repeat(32),
          signer_cert_subject: 'CN=Amélia Marques,O=Encosto Estratégico Lda',
          signer_cert_sha256: 'ef'.repeat(32),
          signature_algorithm: 'rsa-sha256',
        });
      }
      return emptyInviteList(url, method) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} entityName="Encosto Estratégico Lda" />);

    // Switch the format to XAdES; the local XAdES tool replaces the PAdES provider picker.
    fireEvent.change(await screen.findByLabelText('Formato de assinatura'), {
      target: { value: 'xades' },
    });
    expect(await screen.findByText('Assinatura XAdES local')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Assinar com Chave Móvel Digital' })).toBeNull();

    // A level + packaging choice must reach the request body.
    fireEvent.change(screen.getByLabelText('Empacotamento'), { target: { value: 'enveloping' } });
    fireEvent.change(screen.getByLabelText('Nível'), { target: { value: 'T' } });
    fireEvent.change(screen.getByLabelText('Ficheiro PKCS#12/PFX'), {
      target: { files: [pkcs12File()] },
    });
    fireEvent.change(screen.getByLabelText('Frase-passe'), { target: { value: 'pfx-passphrase' } });
    fireEvent.click(screen.getByRole('button', { name: 'Produzir XAdES' }));

    await waitFor(() =>
      expect(requestBody).toMatchObject({
        content_name: 'ata.pdf',
        packaging: 'enveloping',
        level: 'T',
        content_base64: btoa('%PDF-1.7'),
        signer: {
          kind: 'soft_pkcs12',
          pkcs12_base64: btoa('pfx-bytes'),
          passphrase: 'pfx-passphrase',
        },
      }),
    );
    expect(requestUrl).toContain('/v1/signature/xades/sign');
    // The result heading (and the success toast) both surface the produced-XAdES title.
    expect((await screen.findAllByText('XAdES produzido')).length).toBeGreaterThan(0);
    // The transient passphrase is dropped once consumed.
    expect((screen.getByLabelText('Frase-passe') as HTMLInputElement).value).toBe('');
  });

  it('routes an ASiC-E container/level/role/archive choice to the asic/sign endpoint body', async () => {
    let requestUrl: string | null = null;
    let requestBody: Record<string, unknown> | null = null;
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) return json([]);
      if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
      if (url.endsWith('/v1/acts/act-1/document') && method === 'GET') return pdf('%PDF-1.7');
      if (url.includes('/v1/signature/asic/sign')) {
        requestUrl = url;
        requestBody = JSON.parse(String(init?.body));
        return json({
          report_kind: 'asic_signature',
          scope: 'local_technical_asic_evidence',
          legal_notice: 'Local technical ASiC container production only.',
          asic_base64: btoa('PK'),
          asic_sha256: 'ab'.repeat(32),
          container: 'ASiC-E',
          xades_level: 'XAdES-T',
          payload_count: 1,
          cades_signature_count: 1,
          xades_signature_count: 0,
          archive_timestamp: true,
        });
      }
      return emptyInviteList(url, method) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} entityName="Encosto Estratégico Lda" />);

    fireEvent.change(await screen.findByLabelText('Formato de assinatura'), {
      target: { value: 'asic' },
    });
    expect(await screen.findByText('Contentor ASiC local')).toBeTruthy();

    // Choose ASiC-E → the role selector + archive-timestamp checkbox appear.
    fireEvent.change(screen.getByLabelText('Tipo de contentor'), {
      target: { value: 'asic_e_multi' },
    });
    fireEvent.change(screen.getByLabelText('Nível XAdES'), { target: { value: 'T' } });
    fireEvent.change(await screen.findByLabelText('Tipo de assinatura'), {
      target: { value: 'cades' },
    });
    fireEvent.click(screen.getByLabelText('Manifesto de arquivo com carimbo temporal'));
    fireEvent.change(screen.getByLabelText('Ficheiro PKCS#12/PFX'), {
      target: { files: [pkcs12File()] },
    });
    fireEvent.change(screen.getByLabelText('Frase-passe'), { target: { value: 'pfx-passphrase' } });
    fireEvent.click(screen.getByRole('button', { name: 'Produzir ASiC' }));

    await waitFor(() =>
      expect(requestBody).toMatchObject({
        container: 'asic_e_multi',
        xades_level: 'T',
        archive_timestamp: true,
        payloads: [
          { name: 'ata.pdf', content_base64: btoa('%PDF-1.7'), mime_type: 'application/pdf' },
        ],
        signers: [
          { role: 'cades', pkcs12_base64: btoa('pfx-bytes'), passphrase: 'pfx-passphrase' },
        ],
      }),
    );
    expect(requestUrl).toContain('/v1/signature/asic/sign');
    expect((await screen.findAllByText('Contentor ASiC produzido')).length).toBeGreaterThan(0);
  });

  it('surfaces the honest co-location note when the local XAdES tool 409s off-host', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/signature/providers')) return json([]);
      if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
      if (url.endsWith('/v1/acts/act-1/document') && method === 'GET') return pdf('%PDF-1.7');
      if (url.includes('/v1/signature/xades/sign')) {
        return json({ error: 'requires the desktop app' }, 409);
      }
      return emptyInviteList(url, method) ?? Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={sealedAct} />);
    fireEvent.change(await screen.findByLabelText('Formato de assinatura'), {
      target: { value: 'xades' },
    });
    fireEvent.change(await screen.findByLabelText('Ficheiro PKCS#12/PFX'), {
      target: { files: [pkcs12File()] },
    });
    fireEvent.change(screen.getByLabelText('Frase-passe'), { target: { value: 'pfx-passphrase' } });
    fireEvent.click(screen.getByRole('button', { name: 'Produzir XAdES' }));

    expect(await screen.findByText('Disponível apenas na aplicação de secretária')).toBeTruthy();
    // The submit action is withdrawn once the co-location note is shown.
    expect(screen.queryByRole('button', { name: 'Produzir XAdES' })).toBeNull();
  });
});
