import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, renderHook } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { api } from './client';
import {
  keys,
  useAdvanceAct,
  useArchiveAct,
  useControlPlatformService,
  useCreateExternalSigningEnvelope,
  useCreatePaperBookOcrConversionDossier,
  useDeleteRole,
  useDeleteSession,
  useExportTemplate,
  useImportTemplate,
  usePatchPrivacyBreachPlaybook,
  usePatchPrivacyTransferControl,
  usePatchRole,
  useRecordGeneratedDocumentDispatchEvidence,
  useRemoveAttestationKey,
  useRemoveUserSecret,
  useRevokeDelegation,
  useStartOverInstance,
  useUnassignRole,
  useUpdatePaperBookImportOcrStatus,
  useUpdateTemplate,
} from './hooks';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function harness() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
  return { qc, wrapper };
}

async function mutate(result: { current: { mutateAsync: unknown } }, value?: unknown) {
  await act(async () => {
    await (result.current.mutateAsync as (input: unknown) => Promise<unknown>)(value);
  });
}

describe('API hooks execute mutations and maintain authoritative caches', () => {
  it('runs the remaining mutation wrappers and their invalidation paths', async () => {
    const { wrapper } = harness();
    vi.spyOn(api, 'updateTemplate').mockResolvedValue({} as never);
    vi.spyOn(api, 'exportTemplate').mockResolvedValue({} as never);
    vi.spyOn(api, 'importTemplate').mockResolvedValue({} as never);
    vi.spyOn(api, 'advanceAct').mockResolvedValue({ book_id: 'B1' } as never);
    vi.spyOn(api, 'archiveAct').mockResolvedValue({ book_id: 'B1' } as never);
    vi.spyOn(api, 'removeUserSecret').mockResolvedValue({} as never);
    vi.spyOn(api, 'removeAttestationKey').mockResolvedValue({} as never);
    vi.spyOn(api, 'deleteSession').mockResolvedValue(undefined);
    vi.spyOn(api, 'patchRole').mockResolvedValue({} as never);
    vi.spyOn(api, 'deleteRole').mockResolvedValue(undefined);
    vi.spyOn(api, 'unassignRole').mockResolvedValue([]);
    vi.spyOn(api, 'revokeDelegation').mockResolvedValue(undefined);
    vi.spyOn(api, 'patchBreachPlaybook').mockResolvedValue({ id: 'BR1' } as never);
    vi.spyOn(api, 'patchTransferControl').mockResolvedValue({ id: 'TR1' } as never);

    await mutate(renderHook(() => useUpdateTemplate(), { wrapper }).result, {
      id: 'tpl',
      rawJson: '{}',
    });
    await mutate(renderHook(() => useExportTemplate(), { wrapper }).result, 'tpl');
    const importHook = renderHook(() => useImportTemplate(), { wrapper });
    await mutate(importHook.result, { rawJson: '{}', dryRun: true });
    await mutate(importHook.result, { rawJson: '{}', dryRun: false });
    await mutate(renderHook(() => useAdvanceAct('A1'), { wrapper }).result, 'Sealed');
    await mutate(renderHook(() => useArchiveAct('A1'), { wrapper }).result);
    await mutate(renderHook(() => useRemoveUserSecret('U1'), { wrapper }).result, {});
    await mutate(renderHook(() => useRemoveAttestationKey('U1'), { wrapper }).result, {});
    await mutate(renderHook(() => useDeleteSession(), { wrapper }).result);
    await mutate(renderHook(() => usePatchRole('R1'), { wrapper }).result, {});
    await mutate(renderHook(() => useDeleteRole(), { wrapper }).result, 'R1');
    await mutate(renderHook(() => useUnassignRole('U1'), { wrapper }).result, {});
    await mutate(renderHook(() => useRevokeDelegation(), { wrapper }).result, 'D1');
    await mutate(renderHook(() => usePatchPrivacyBreachPlaybook(), { wrapper }).result, {
      id: 'BR1',
      body: {},
    });
    await mutate(renderHook(() => usePatchPrivacyTransferControl(), { wrapper }).result, {
      id: 'TR1',
      body: {},
    });

    expect(api.updateTemplate).toHaveBeenCalledWith('tpl', '{}');
    expect(api.importTemplate).toHaveBeenCalledTimes(2);
    expect(api.archiveAct).toHaveBeenCalledWith('A1');
    expect(api.deleteSession).toHaveBeenCalledTimes(1);
  });

  it('updates OCR/dossier/envelope/dispatch caches without duplicating records', async () => {
    const { qc, wrapper } = harness();
    const ocrStatus = { import_id: 'I1', ocr_status: 'completed' };
    vi.spyOn(api, 'updatePaperBookImportOcrStatus').mockResolvedValue(ocrStatus as never);
    qc.setQueryData(keys.paperBookImports('BOOK'), [
      { import_id: 'I1', ocr_status: 'queued' },
      { import_id: 'I2', ocr_status: 'queued' },
    ]);
    await mutate(renderHook(() => useUpdatePaperBookImportOcrStatus('BOOK'), { wrapper }).result, {
      id: 'I1',
      status: 'completed',
    });
    expect(
      (qc.getQueryData<Array<{ import_id: string; ocr_status: string }>>(
        keys.paperBookImports('BOOK'),
      ) ?? [])[0]?.ocr_status,
    ).toBe('completed');

    const dossier = { dossier_id: 'DOS1', import_id: 'I1', draft_id: 'DR1' };
    vi.spyOn(api, 'createPaperBookOcrConversionDossier').mockResolvedValue(dossier as never);
    const dossierHook = renderHook(() => useCreatePaperBookOcrConversionDossier(), { wrapper });
    await mutate(dossierHook.result, { importId: 'I1', draftId: 'DR1' });
    qc.setQueryData(keys.paperBookOcrConversionDossiers('I1'), [
      { ...dossier, status: 'old' },
      { dossier_id: 'DOS2', import_id: 'I1', draft_id: 'DR2' },
    ]);
    await mutate(dossierHook.result, { importId: 'I1', draftId: 'DR1' });
    expect(
      qc.getQueryData<Array<{ dossier_id: string }>>(keys.paperBookOcrConversionDossiers('I1')),
    ).toHaveLength(2);

    const envelope = { id: 'ENV1' };
    vi.spyOn(api, 'createExternalSigningEnvelope').mockResolvedValue(envelope as never);
    const envelopeHook = renderHook(() => useCreateExternalSigningEnvelope('A1'), { wrapper });
    await mutate(envelopeHook.result, {});
    qc.setQueryData(keys.externalSigningEnvelopes('A1'), [
      { id: 'ENV1', status: 'old' },
      { id: 'ENV2' },
    ]);
    await mutate(envelopeHook.result, {});
    expect(
      qc.getQueryData<Array<{ id: string }>>(keys.externalSigningEnvelopes('A1')),
    ).toHaveLength(2);

    const response = {
      dispatch_evidence_status: 'recorded',
      evidence: {
        idempotency_key: 'KEY1',
        act_id: 'A1',
        document_id: 'DOC1',
      },
    };
    vi.spyOn(api, 'recordGeneratedDocumentDispatchEvidence').mockResolvedValue(response as never);
    const dispatchHook = renderHook(() => useRecordGeneratedDocumentDispatchEvidence(), {
      wrapper,
    });
    await mutate(dispatchHook.result, { documentId: 'DOC1', body: {} });
    qc.setQueryData(keys.generatedDocumentDispatchEvidence('DOC1'), { evidence: [] });
    await mutate(dispatchHook.result, { documentId: 'DOC1', body: {} });
    await mutate(dispatchHook.result, { documentId: 'DOC1', body: {} });
    expect(
      qc.getQueryData<{ evidence: unknown[] }>(keys.generatedDocumentDispatchEvidence('DOC1'))
        ?.evidence,
    ).toHaveLength(1);
  });

  it('patches platform-service cache safely and executes recovery invalidation', async () => {
    const { qc, wrapper } = harness();
    const response = { service: { id: 'api', status: 'running' } };
    vi.spyOn(api, 'controlPlatformService').mockResolvedValue(response as never);
    const control = renderHook(() => useControlPlatformService(), { wrapper });

    await mutate(control.result, { id: 'api', action: 'start' });
    qc.setQueryData(keys.platformServices, { services: [null, { id: 'api' }] });
    await mutate(control.result, { id: 'api', action: 'start' });
    expect(
      qc.getQueryData<{ services: Array<{ status?: string } | null> }>(keys.platformServices)
        ?.services[1]?.status,
    ).toBe('running');

    vi.spyOn(api, 'startOverInstance').mockResolvedValue({} as never);
    await mutate(renderHook(() => useStartOverInstance(), { wrapper }).result, {});
    expect(api.startOverInstance).toHaveBeenCalledTimes(1);
    expect(keys.ledger({ q: 'audit' })).toEqual(['ledger', { q: 'audit' }]);
  });
});
