import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../api/client';
import { OFFICIAL_SIGNATURE_IMPORT_GUARDRAIL_IDS } from '../../api/types';
import type {
  ExternalSignerIdentityRequirement,
  ExternalSigningEnvelopeSlotView,
  ExternalSigningEnvelopeView,
  PendingSignatureInfo,
  SignatureEvidenceStatus,
  SignatureProviderView,
} from '../../api/types';
import type { TFunction } from '../../i18n';
import {
  base64ToBytes,
  buildSlotEvidenceRows,
  bytesToBase64,
  comparisonStatus,
  dateTimeInputToIso,
  defaultInviteExpiryInput,
  dssEvidenceLabel,
  evidenceLevelLabel,
  evidenceLevelTone,
  evidenceTimestampLabel,
  evidenceTimestampTone,
  externalInviteLink,
  fileToBase64,
  hasMetadata,
  identityRequirementLabel,
  inviteSlotOptions,
  isCcPinRejection,
  longTermEvidenceLabel,
  officialImportGuardrailLabel,
  orderPolicyLabel,
  providerAuthorizationLabel,
  providerEnvironmentLabel,
  providerFromPending,
  renewalPlanActionLabel,
  sameMetadata,
  signingDownloadSlug,
  slotCanRecordTechnicalEvidence,
  slotIdentityRequirements,
  slotStatusLabel,
  technicalComparisonFamilyLabel,
  toLocalDateTimeInput,
  trustedListLabel,
  trustedListTone,
  workflowLabel,
} from './SigningPanel';

const t = ((key: string) => key) as TFunction;

/** A minimal envelope slot; every field the helpers under test read is overridable. */
function slot(
  overrides: Partial<ExternalSigningEnvelopeSlotView> = {},
): ExternalSigningEnvelopeSlotView {
  return {
    id: 'slot-1',
    signer_label: 'Amélia Marques',
    required: true,
    status: 'pending',
    evidence: [],
    ...overrides,
  };
}

function signatureEvidence(
  overrides: Partial<SignatureEvidenceStatus> = {},
): SignatureEvidenceStatus {
  return {
    current_level: 'B-B',
    timestamp_evidence_present: false,
    dss_revocation_evidence_present: false,
    dss_revocation_evidence_status: 'unsupported',
    ...overrides,
  } as SignatureEvidenceStatus;
}

afterEach(() => vi.useRealTimers());

describe('SigningPanel presentation and conversion logic', () => {
  it('normalizes safe download slugs including accents, punctuation, and empty input', () => {
    expect(signingDownloadSlug('  Encôsto Estratégico, Lda.  ')).toBe('encosto-estrategico-lda');
    expect(signingDownloadSlug('***')).toBe('documento');
  });

  it('labels and tones every evidence level without claiming unknown levels', () => {
    expect(
      ['Unsigned', 'B-B', 'B-T', 'B-LT-local', 'B-LTA-local', 'future'].map((level) =>
        evidenceLevelLabel(level, t),
      ),
    ).toEqual([
      'signing.evidence.level.unsigned',
      'PAdES B-B',
      'PAdES B-T',
      'PAdES B-LT local',
      'PAdES B-LTA local',
      'future',
    ]);
    expect(['B-LT-local', 'B-LTA-local', 'B-T', 'B-B', 'Unsigned'].map(evidenceLevelTone)).toEqual([
      'ok',
      'ok',
      'ok',
      'accent',
      'neutral',
    ]);
  });

  it('maps every long-term and renewal status and preserves future server values', () => {
    const longTerm = [
      'timestamped',
      'not_configured',
      'lt_local_technical_evidence',
      'lt_local_technical_evidence_partial',
      'lta_local_technical_evidence',
      'lta_local_technical_evidence_partial',
      'lt_not_implemented',
      'lta_not_implemented',
    ];
    for (const status of longTerm) expect(longTermEvidenceLabel(status, t)).toMatch(/^signing\./);
    expect(longTermEvidenceLabel('future_status', t)).toBe('future_status');

    const renewal = [
      'none',
      'manual_review',
      'add_signature_timestamp',
      'embed_dss_revocation_evidence',
      'record_dss_validation_time',
      'add_document_timestamp',
      'record_signature_dss_validation_time',
    ];
    for (const action of renewal) expect(renewalPlanActionLabel(action, t)).toMatch(/^signing\./);
    expect(renewalPlanActionLabel('future_action', t)).toBe('future_action');
  });

  it('renders DSS, timestamp, and trusted-list evidence conservatively', () => {
    expect(dssEvidenceLabel(signatureEvidence({ dss_revocation_evidence_present: true }), t)).toBe(
      'signing.evidence.dss.present',
    );
    expect(
      dssEvidenceLabel(signatureEvidence({ dss_revocation_evidence_status: 'unsupported' }), t),
    ).toBe('signing.evidence.dss.unsupported');
    expect(
      dssEvidenceLabel(signatureEvidence({ dss_revocation_evidence_status: 'not_present' }), t),
    ).toBe('signing.evidence.dss.notPresent');
    expect(
      dssEvidenceLabel(signatureEvidence({ dss_revocation_evidence_status: 'future' }), t),
    ).toBe('future');

    expect(evidenceTimestampLabel(signatureEvidence({ timestamp_evidence_present: true }), t)).toBe(
      'signing.evidence.timestamp.present',
    );
    expect(evidenceTimestampLabel(signatureEvidence(), t)).toBe(
      'signing.evidence.timestamp.absent',
    );
    expect(evidenceTimestampTone(signatureEvidence({ timestamp_evidence_present: true }))).toBe(
      'ok',
    );
    expect(evidenceTimestampTone(signatureEvidence())).toBe('neutral');

    expect(
      ['Granted', 'Withdrawn', 'Unknown', 'Future'].map((status) => trustedListLabel(status, t)),
    ).toEqual([
      'signing.trustedList.granted',
      'signing.trustedList.withdrawn',
      'signing.trustedList.unknown',
      'Future',
    ]);
    expect(trustedListTone('Granted')).toBe('ok');
    expect(trustedListTone('Withdrawn')).toBe('warn');
  });

  it('recognizes only structured Cartão de Cidadão PIN rejections', () => {
    expect(isCcPinRejection(new ApiError(422, { error: 'wrong', pin_status: 'wrong_pin' }))).toBe(
      true,
    );
    expect(isCcPinRejection(new ApiError(422, { error: 'blocked', pin_status: 'blocked' }))).toBe(
      true,
    );
    expect(isCcPinRejection(new ApiError(422, { error: 'other', pin_status: 'future' }))).toBe(
      false,
    );
    expect(isCcPinRejection(new ApiError(409, { error: 'wrong', pin_status: 'wrong_pin' }))).toBe(
      false,
    );
    expect(isCcPinRejection(new Error('wrong'))).toBe(false);
  });

  it('labels every official-import guardrail and leaves additive values visible', () => {
    for (const guardrail of OFFICIAL_SIGNATURE_IMPORT_GUARDRAIL_IDS) {
      expect(officialImportGuardrailLabel(guardrail, t)).toMatch(
        /^signing\.official\.guardrails\./,
      );
    }
    expect(officialImportGuardrailLabel('future_guardrail' as never, t)).toBe('future_guardrail');
  });

  it('converts dates, external links, and binary payloads without data loss', async () => {
    const date = new Date('2026-07-16T12:34:00Z');
    const localInput = toLocalDateTimeInput(date);
    expect(dateTimeInputToIso(localInput)).toBe(date.toISOString());

    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-07-16T12:00:00Z'));
    expect(dateTimeInputToIso(defaultInviteExpiryInput())).toBe('2026-07-18T12:00:00.000Z');
    expect(externalInviteLink('token with/slash')).toContain(
      '/assinatura-externa?token=token%20with%2Fslash',
    );

    const bytes = new Uint8Array([0, 1, 127, 128, 255]);
    const encoded = bytesToBase64(bytes);
    expect([...base64ToBytes(encoded)]).toEqual([...bytes]);
    const file = {
      arrayBuffer: () => Promise.resolve(bytes.buffer.slice(0)),
    } as unknown as File;
    await expect(fileToBase64(file)).resolves.toBe(encoded);
  });
});

// --- s5-web-branches: pending-session, metadata-comparison and envelope label logic ----------

describe('SigningPanel pending-session adoption', () => {
  const cscProvider = {
    id: 'multicert',
    family: 'QualifiedCertificate',
    label: 'Multicert',
    evidentiary_level: 'qualified',
    configured: true,
  } as SignatureProviderView;

  it('treats a pending session with no provider, or the CMD provider, as CMD', () => {
    expect(providerFromPending({ session_id: 's1' } as PendingSignatureInfo, [])).toEqual({
      id: 'cmd',
      kind: 'cmd',
      label: 'CMD',
    });
    expect(
      providerFromPending({ session_id: 's1', provider_id: 'cmd' } as PendingSignatureInfo, [
        cscProvider,
      ]),
    ).toEqual({ id: 'cmd', kind: 'cmd', label: 'CMD' });
  });

  it('resolves a CSC provider label from the list, falling back to its raw id', () => {
    expect(
      providerFromPending({ session_id: 's1', provider_id: 'multicert' } as PendingSignatureInfo, [
        cscProvider,
      ]),
    ).toEqual({ id: 'multicert', kind: 'csc', label: 'Multicert' });

    // A session for a provider the picker no longer lists still resolves — with the id as label,
    // so a reload mid-flow can never render an empty provider name.
    expect(
      providerFromPending(
        { session_id: 's1', provider_id: 'retired-qtsp' } as PendingSignatureInfo,
        [cscProvider],
      ),
    ).toEqual({ id: 'retired-qtsp', kind: 'csc', label: 'retired-qtsp' });
  });
});

describe('SigningPanel metadata comparison', () => {
  it('treats blank, null and undefined metadata as absent', () => {
    expect(hasMetadata('CN=Amélia Marques')).toBe(true);
    expect(hasMetadata('   ')).toBe(false);
    expect(hasMetadata('')).toBe(false);
    expect(hasMetadata(null)).toBe(false);
    expect(hasMetadata(undefined)).toBe(false);
  });

  it('compares metadata case-insensitively and only when both sides are present', () => {
    expect(sameMetadata(' CN=Amélia Marques ', 'cn=amélia marques')).toBe(true);
    expect(sameMetadata('CN=Amélia Marques', 'CN=Outro')).toBe(false);
    // An absent side is never a match — not even against another absent side.
    expect(sameMetadata(null, 'CN=Amélia Marques')).toBe(false);
    expect(sameMetadata('CN=Amélia Marques', '  ')).toBe(false);
    expect(sameMetadata(null, undefined)).toBe(false);
  });

  it('tones every comparison outcome, defaulting an unknown kind to a warning', () => {
    expect(
      (['match', 'present', 'partial', 'mismatch', 'notClaimed', 'loading', 'unavailable'] as const)
        .map((kind) => comparisonStatus(kind, t))
        .map((status) => status.tone),
    ).toEqual(['accent', 'neutral', 'warn', 'error', 'neutral', 'neutral', 'warn']);
    expect(comparisonStatus('match', t).label).toBe('signing.technicalComparison.status.match');
    // An unrecognised kind must fail conservatively rather than claim a match.
    const unknown = comparisonStatus('future_kind' as never, t);
    expect(unknown.tone).toBe('warn');
    expect(unknown.label).toBe('signing.technicalComparison.status.unavailable');
  });

  it('names the official handoff family specially and passes unknown families through', () => {
    expect(technicalComparisonFamilyLabel('AutenticacaoGovOfficialHandoff', t)).toBe(
      'signing.official.family',
    );
    expect(technicalComparisonFamilyLabel('future_family', t)).toBe('future_family');
  });
});

describe('SigningPanel provider manifest labels', () => {
  it('labels every environment and falls back to unknown', () => {
    expect(
      ['preprod', 'prod', 'sandbox', 'something-else', null, undefined].map((environment) =>
        providerEnvironmentLabel(environment, t),
      ),
    ).toEqual([
      'signing.provider.manifest.environment.preprod',
      'signing.provider.manifest.environment.prod',
      'signing.provider.manifest.environment.sandbox',
      'signing.provider.manifest.environment.unknown',
      'signing.provider.manifest.environment.unknown',
      'signing.provider.manifest.environment.unknown',
    ]);
  });

  it('labels every authorization mode and falls back to unknown', () => {
    expect(
      ['pin_otp', 'service', 'user', 'something-else', null, undefined].map((mode) =>
        providerAuthorizationLabel(mode, t),
      ),
    ).toEqual([
      'signing.provider.manifest.authorization.pinOtp',
      'signing.provider.manifest.authorization.service',
      'signing.provider.manifest.authorization.user',
      'signing.provider.manifest.authorization.unknown',
      'signing.provider.manifest.authorization.unknown',
      'signing.provider.manifest.authorization.unknown',
    ]);
  });
});

describe('SigningPanel external envelope labels', () => {
  it('labels known workflows and leaves an unknown one visible verbatim', () => {
    expect(workflowLabel('tracking_only', t)).toBe('signing.invites.workflow.trackingOnly');
    expect(workflowLabel('external_envelope', t)).toBe('signing.invites.workflow.externalEnvelope');
    expect(workflowLabel('future_workflow', t)).toBe('future_workflow');
  });

  it('labels both order policies', () => {
    expect(orderPolicyLabel('sequential', t)).toBe('signing.envelopes.order.sequential');
    expect(orderPolicyLabel('parallel', t)).toBe('signing.envelopes.order.parallel');
  });

  it('labels every identity requirement', () => {
    expect(
      (
        [
          'contact_control',
          'provider_identity_assertion',
          'government_id_check',
          'representative_capacity',
        ] as ExternalSignerIdentityRequirement[]
      ).map((requirement) => identityRequirementLabel(requirement, t)),
    ).toEqual([
      'signing.envelopes.identity.contactControl',
      'signing.envelopes.identity.providerIdentity',
      'signing.envelopes.identity.governmentId',
      'signing.envelopes.identity.representativeCapacity',
    ]);
  });

  it('labels every slot status', () => {
    expect(
      (['pending', 'initiated', 'signed', 'declined', 'revoked', 'expired'] as const).map(
        (status) => slotStatusLabel(status, t),
      ),
    ).toEqual([
      'signing.envelopes.slot.status.pending',
      'signing.envelopes.slot.status.initiated',
      'signing.envelopes.slot.status.signed',
      'signing.envelopes.slot.status.declined',
      'signing.envelopes.slot.status.revoked',
      'signing.envelopes.slot.status.expired',
    ]);
  });

  it('joins a slot’s identity requirements and reports none explicitly', () => {
    expect(
      slotIdentityRequirements(
        slot({ identity_requirements: ['contact_control', 'government_id_check'] }),
        t,
      ),
    ).toBe('signing.envelopes.identity.contactControl, signing.envelopes.identity.governmentId');
    expect(slotIdentityRequirements(slot({ identity_requirements: [] }), t)).toBe(
      'signing.envelopes.identity.none',
    );
    // An older server may omit the field entirely.
    expect(slotIdentityRequirements(slot({ identity_requirements: undefined }), t)).toBe(
      'signing.envelopes.identity.none',
    );
  });

  it('allows technical evidence only for a slot still awaiting its signer', () => {
    expect(
      (['pending', 'initiated'] as const).map((status) =>
        slotCanRecordTechnicalEvidence(slot({ status })),
      ),
    ).toEqual([true, true]);
    expect(
      (['signed', 'declined', 'revoked', 'expired'] as const).map((status) =>
        slotCanRecordTechnicalEvidence(slot({ status })),
      ),
    ).toEqual([false, false, false, false]);
  });
});

describe('SigningPanel evidence row construction', () => {
  const form = {
    label: '  Recibo de entrega  ',
    reference: '  REF-1  ',
    digest: '   ',
    identityReferences: { contact_control: '  contacto-1  ' },
  };

  it('trims the operator row and omits a blank digest entirely', () => {
    const rows = buildSlotEvidenceRows(slot({ identity_requirements: [] }), form, t);
    expect(rows).toEqual([{ label: 'Recibo de entrega', reference: 'REF-1' }]);
    // A whitespace-only digest must not be sent as an empty string.
    expect('digest' in rows[0]).toBe(false);
  });

  it('keeps a real digest and appends one row per identity requirement', () => {
    const rows = buildSlotEvidenceRows(
      slot({ identity_requirements: ['contact_control', 'government_id_check'] }),
      { ...form, digest: '  ab12  ' },
      t,
    );

    expect(rows[0]).toEqual({
      label: 'Recibo de entrega',
      reference: 'REF-1',
      digest: 'ab12',
    });
    expect(rows).toHaveLength(3);
    expect(rows[1]).toEqual({
      label: 'signing.envelopes.evidence.identityLabel',
      reference: 'contacto-1',
      identity_requirement: 'contact_control',
    });
    // A requirement with no reference typed yet still produces a row, with an empty reference.
    expect(rows[2]).toEqual({
      label: 'signing.envelopes.evidence.identityLabel',
      reference: '',
      identity_requirement: 'government_id_check',
    });
  });
});

describe('SigningPanel invite slot options', () => {
  it('offers only pending slots, keyed by envelope and slot', () => {
    const envelopes = [
      {
        id: 'env-1',
        order_policy: 'sequential',
        slots: [
          slot({ id: 'slot-1', signer_label: 'Amélia Marques', status: 'pending' }),
          slot({ id: 'slot-2', signer_label: 'Já assinou', status: 'signed' }),
        ],
      },
      {
        id: 'env-2',
        order_policy: 'parallel',
        slots: [slot({ id: 'slot-3', signer_label: 'Outro', status: 'pending' })],
      },
    ] as unknown as ExternalSigningEnvelopeView[];

    const options = inviteSlotOptions(envelopes, t);

    expect(options.map((option) => option.value)).toEqual(['env-1:slot-1', 'env-2:slot-3']);
    expect(options.map((option) => option.slotId)).toEqual(['slot-1', 'slot-3']);
    expect(options.map((option) => option.envelopeId)).toEqual(['env-1', 'env-2']);
    expect(options.every((option) => option.status === 'pending')).toBe(true);
  });

  it('returns nothing when no slot is still pending', () => {
    const envelopes = [
      {
        id: 'env-1',
        order_policy: 'parallel',
        slots: [
          slot({ id: 'slot-1', status: 'signed' }),
          slot({ id: 'slot-2', status: 'revoked' }),
        ],
      },
    ] as unknown as ExternalSigningEnvelopeView[];

    expect(inviteSlotOptions(envelopes, t)).toEqual([]);
    expect(inviteSlotOptions([], t)).toEqual([]);
  });
});
