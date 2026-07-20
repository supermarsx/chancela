import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, api } from '../../api/client';
import { clearSessionToken, setSessionToken } from '../../api/session';
import type {
  GeneratedDocumentDispatchEvidenceStatus,
  GeneratedDocumentView,
  ImportedDocumentView,
} from '../../api/types';
import type { TFunction } from '../../i18n';
import {
  buildImportedDocumentReviewOptions,
  canonicalConversionPreflightSourceLabel,
  canonicalConversionPreflightStatusLabel,
  dispatchChannelLabel,
  documentArrayBufferToBase64,
  documentDownloadSlug,
  documentMetadataText,
  documentYesNo,
  formatDocumentBytes,
  generatedDispatchStatusLabel,
  generatedDispatchStatusTone,
  generatedDocumentDownloadName,
  importedAcknowledgedReviewGuardrails,
  importedCanonicalRecordStatusLabel,
  importedDisplayName,
  importedDocumentHasReviewReceipt,
  importedDownloadName,
  importedGuardrailChecklist,
  importedGuardrailLabel,
  importedRequiredReviewGuardrails,
  importedReviewStatusLabel,
  importedReviewStatusTone,
  importedSignedArtifactStatusLabel,
  isNoDocumentTemplate,
  lifecycleStageLabel,
  listImportedDocumentsForAct,
  localDateTimeInputValue,
  localDateTimeToRfc3339,
  mergeImportedDocument,
  readDocumentFileAsBase64,
  reviewPatchStatusFromDocument,
  shouldShowCanonicalConversionPreflight,
  trimDocumentTextOrNull,
  uniqueImportedGuardrails,
  validateImportedDocument,
} from './ActDocumentPanel';

const t = ((key: string) => key) as TFunction;

function imported(overrides: Partial<ImportedDocumentView> = {}): ImportedDocumentView {
  return {
    id: 'IMP1',
    filename: null,
    review_guardrail_checklist: [],
    acknowledged_guardrail_ids: [],
    ...overrides,
  } as ImportedDocumentView;
}

afterEach(() => {
  clearSessionToken();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('ActDocumentPanel pure document/evidence logic', () => {
  it('classifies no-template errors and creates safe filenames', () => {
    expect(isNoDocumentTemplate(new ApiError(404, { error: 'missing' }))).toBe(true);
    expect(isNoDocumentTemplate(new ApiError(422, { error: 'unsupported' }))).toBe(true);
    expect(isNoDocumentTemplate(new ApiError(500, { error: 'boom' }))).toBe(false);
    expect(isNoDocumentTemplate(new Error('boom'))).toBe(false);
    expect(documentDownloadSlug('Órgão / Ata #1')).toBe('orgao-ata-1');
    expect(documentDownloadSlug('***')).toBe('documento');
    expect(importedDisplayName(imported({ filename: '  source.doc  ' }), t)).toBe('source.doc');
    expect(importedDisplayName(imported(), t)).toBe('documents.import.unnamed');
    expect(importedDownloadName(imported({ id: 'ID / 1' }))).toBe('documento-importado-id-1.bin');
    expect(
      generatedDocumentDownloadName({
        id: 'DOC / 1',
        template_id: 'Ata Geral',
      } as GeneratedDocumentView),
    ).toBe('generated-ata-geral-doc-1.pdf');
  });

  it('loads imported documents with the documented 404 fallback only', async () => {
    vi.spyOn(api, 'listImportedDocuments').mockResolvedValueOnce([imported()]);
    await expect(listImportedDocumentsForAct('A1')).resolves.toHaveLength(1);
    vi.mocked(api.listImportedDocuments).mockRejectedValueOnce(
      new ApiError(404, { error: 'none' }),
    );
    await expect(listImportedDocumentsForAct('A1')).resolves.toEqual([]);
    vi.mocked(api.listImportedDocuments).mockRejectedValueOnce(
      new ApiError(503, { error: 'down' }),
    );
    await expect(listImportedDocumentsForAct('A1')).rejects.toMatchObject({ status: 503 });
  });

  it('validates imports with JSON/session headers and clears stale sessions', async () => {
    setSessionToken('session-token');
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ verdict: 'accepted' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);
    await expect(validateImportedDocument({} as never)).resolves.toEqual({ verdict: 'accepted' });
    expect(fetchMock.mock.calls[0][1].headers['X-Chancela-Session']).toBe('session-token');

    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'expired' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    await expect(validateImportedDocument({} as never)).rejects.toMatchObject({ status: 401 });
  });

  it('base64-encodes files through both arrayBuffer and FileReader paths', async () => {
    const bytes = new Uint8Array([0, 1, 127, 255]);
    expect(documentArrayBufferToBase64(bytes.buffer)).toBe('AAF//w==');
    vi.stubGlobal('FileReader', undefined);
    await expect(
      readDocumentFileAsBase64(
        { arrayBuffer: () => Promise.resolve(bytes.buffer) } as unknown as File,
        t,
      ),
    ).resolves.toBe('AAF//w==');

    class Reader {
      result: string | ArrayBuffer | null = 'data:application/octet-stream;base64,QUJD';
      error: DOMException | null = null;
      onload: null | (() => void) = null;
      onerror: null | (() => void) = null;
      readAsDataURL() {
        this.onload?.();
      }
    }
    vi.stubGlobal('FileReader', Reader);
    await expect(readDocumentFileAsBase64({} as File, t)).resolves.toBe('QUJD');

    class InvalidReader extends Reader {
      override result: string | ArrayBuffer | null = new ArrayBuffer(0);
    }
    vi.stubGlobal('FileReader', InvalidReader);
    await expect(readDocumentFileAsBase64({} as File, t)).rejects.toThrow(
      'documents.import.readError.imported',
    );

    class ErrorReader extends Reader {
      override readAsDataURL() {
        this.onerror?.();
      }
    }
    vi.stubGlobal('FileReader', ErrorReader);
    await expect(readDocumentFileAsBase64({} as File, t)).rejects.toThrow(
      'documents.import.readError.file',
    );
  });

  it('formats metadata, sizes, dates, booleans, and review selector options', () => {
    expect(documentMetadataText('  value ')).toBe('value');
    expect(documentMetadataText(' ')).toBeNull();
    expect(documentMetadataText(5)).toBeNull();
    expect(formatDocumentBytes(Number.NaN, t)).toBe('documents.import.sizeUnknown');
    expect(formatDocumentBytes(-1, t)).toBe('documents.import.sizeUnknown');
    expect(formatDocumentBytes(512, t)).toBe('512 bytes');
    expect(formatDocumentBytes(1536, t)).toBe('1.5 KB');
    expect(formatDocumentBytes(10 * 1024, t)).toBe('10 KB');
    expect(formatDocumentBytes(2 * 1024 ** 4, t)).toBe('2 TB');
    expect(localDateTimeInputValue(new Date(2026, 6, 16, 9, 5))).toBe('2026-07-16T09:05');
    expect(localDateTimeToRfc3339('invalid')).toBe('invalid');
    expect(localDateTimeToRfc3339('2026-07-16T09:05')).toMatch(/^2026-07-16T/);
    expect(trimDocumentTextOrNull(' value ')).toBe('value');
    expect(trimDocumentTextOrNull(' ')).toBeNull();
    expect(documentYesNo(true, t)).toBe('common.yes');
    expect(documentYesNo(false, t)).toBe('common.no');
    expect(buildImportedDocumentReviewOptions(t).map((option) => option.value)).toEqual([
      'reviewed_non_canonical_original_only',
      'rejected_non_canonical_evidence',
    ]);
    expect(lifecycleStageLabel('Ata', t)).toBe('enum.lifecycleStage.Ata');
  });

  it('labels generated dispatch status/channel without inventing future semantics', () => {
    const status = (value: string) =>
      ({ status: value }) as GeneratedDocumentDispatchEvidenceStatus;
    expect(
      ['required_pending', 'operator_evidence_partial', 'operator_evidence_covered', 'none'].map(
        (value) => generatedDispatchStatusLabel(status(value), t),
      ),
    ).toEqual([
      'documents.generated.status.requiredPending',
      'documents.generated.status.partial',
      'documents.generated.status.covered',
      'documents.generated.status.notRequired',
    ]);
    expect(
      ['required_pending', 'operator_evidence_partial', 'operator_evidence_covered', 'none'].map(
        (value) => generatedDispatchStatusTone(status(value)),
      ),
    ).toEqual(['warn', 'warn', 'ok', 'neutral']);
    expect(dispatchChannelLabel(null, t)).toBe('documents.generated.evidence.notIndicated');
    for (const channel of [
      'RegisteredLetter',
      'RegisteredLetterAR',
      'Email',
      'HandDelivery',
      'Publication',
      'Portal',
    ]) {
      expect(dispatchChannelLabel(channel, t)).toMatch(/^enum\.dispatchChannel\./);
    }
    expect(dispatchChannelLabel('future', t)).toBe('future');
  });

  it('maps imported-review statuses, guardrails, receipts, and cache merges', () => {
    const statuses = [
      'operator_review_required',
      'ocr_review_required',
      'canonical_conversion_review_required',
      'reviewed_non_canonical_original_only',
      'rejected_non_canonical_evidence',
      'future',
      null,
    ];
    expect(statuses.map((status) => importedReviewStatusTone(status))).toEqual([
      'warn',
      'warn',
      'warn',
      'ok',
      'error',
      'neutral',
      'neutral',
    ]);
    for (const status of statuses) expect(importedReviewStatusLabel(status, t)).toBeTruthy();
    expect(importedCanonicalRecordStatusLabel('not_canonical_record', t)).toContain('canonical');
    expect(importedCanonicalRecordStatusLabel(null, t)).toBeNull();
    expect(importedCanonicalRecordStatusLabel('future', t)).toBe('future');
    expect(importedSignedArtifactStatusLabel('not_signed_artifact', t)).toContain('signed');
    expect(importedSignedArtifactStatusLabel(null, t)).toBeNull();
    expect(importedGuardrailChecklist('not-array')).toEqual([]);
    expect(importedGuardrailChecklist([' one ', '', null])).toEqual(['one']);
    expect(uniqueImportedGuardrails(['one', 'one', 'two'])).toEqual(['one', 'two']);

    const explicit = imported({
      review_guardrail_checklist: ['canonical_pdfa_record_is_not_replaced'],
    });
    expect(importedRequiredReviewGuardrails(explicit)).toEqual([
      'canonical_pdfa_record_is_not_replaced',
    ]);
    expect(
      importedRequiredReviewGuardrails(
        imported({ preservation_policy: { review_guardrail_checklist: ['policy'] } as never }),
      ),
    ).toEqual(['policy']);
    expect(importedRequiredReviewGuardrails(imported())).toHaveLength(4);
    for (const guardrail of importedRequiredReviewGuardrails(imported())) {
      expect(importedGuardrailLabel(guardrail, t)).toMatch(/^documents\.import\.guardrails\./);
    }
    expect(importedGuardrailLabel('future', t)).toBe(
      'documents.import.guardrails.checklist.unknown',
    );
    expect(
      importedAcknowledgedReviewGuardrails(
        imported({ acknowledged_guardrail_ids: ['one', 'one'] as never }),
      ),
    ).toEqual(['one']);
    expect(importedDocumentHasReviewReceipt(imported())).toBe(false);
    expect(
      importedDocumentHasReviewReceipt(
        imported({ operator_review_status: 'reviewed_non_canonical_original_only' }),
      ),
    ).toBe(true);
    expect(importedDocumentHasReviewReceipt(imported({ operator_reviewed_by: 'operator' }))).toBe(
      true,
    );
    expect(reviewPatchStatusFromDocument('rejected_non_canonical_evidence')).toBe(
      'rejected_non_canonical_evidence',
    );
    expect(reviewPatchStatusFromDocument(undefined)).toBe('reviewed_non_canonical_original_only');
    expect(
      mergeImportedDocument(
        [imported({ id: 'OLD' }), imported()],
        imported({ id: 'IMP1', filename: 'new' }),
      ),
    ).toHaveLength(2);
  });

  it('shows canonical-conversion preflight only for legacy/blocked evidence', () => {
    const preflight = (source_format: unknown, status: unknown) =>
      ({ source_format, status }) as never;
    expect(shouldShowCanonicalConversionPreflight(undefined)).toBe(false);
    expect(
      shouldShowCanonicalConversionPreflight(preflight('legacy_word_doc', 'not_attempted')),
    ).toBe(true);
    expect(shouldShowCanonicalConversionPreflight(preflight('ole_compound_file', 'x'))).toBe(true);
    expect(shouldShowCanonicalConversionPreflight(preflight('pdf', 'blocked'))).toBe(true);
    expect(shouldShowCanonicalConversionPreflight(preflight('pdf', 'ok'))).toBe(false);
    expect(
      ['blocked', 'not_attempted', null, 'future'].map((value) =>
        canonicalConversionPreflightStatusLabel(value, t),
      ),
    ).toHaveLength(4);
    expect(
      ['legacy_word_doc', 'ole_compound_file', 'not_legacy_doc_or_ole', null, 'future'].map(
        (value) => canonicalConversionPreflightSourceLabel(value, t),
      ),
    ).toHaveLength(5);
  });
});
