import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../api/client';
import { OFFICIAL_SIGNATURE_IMPORT_GUARDRAIL_IDS } from '../../api/types';
import type { SignatureEvidenceStatus } from '../../api/types';
import type { TFunction } from '../../i18n';
import {
  base64ToBytes,
  bytesToBase64,
  dateTimeInputToIso,
  defaultInviteExpiryInput,
  dssEvidenceLabel,
  evidenceLevelLabel,
  evidenceLevelTone,
  evidenceTimestampLabel,
  evidenceTimestampTone,
  externalInviteLink,
  fileToBase64,
  isCcPinRejection,
  longTermEvidenceLabel,
  officialImportGuardrailLabel,
  renewalPlanActionLabel,
  signingDownloadSlug,
  toLocalDateTimeInput,
  trustedListLabel,
  trustedListTone,
} from './SigningPanel';

const t = ((key: string) => key) as TFunction;

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
