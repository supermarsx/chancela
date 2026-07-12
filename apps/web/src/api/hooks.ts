/**
 * TanStack Query hooks over the typed `api` client (plan t5 §2).
 *
 * Query keys are structured so mutations can invalidate precisely: creating an
 * entity refetches the entity list; opening/closing a book refetches the book, its
 * entity's book list and the dashboard; every act mutation refetches that act, its
 * compliance and the dashboard; sealing additionally refetches the ledger. The
 * compliance-gated seal (§2.5) therefore keeps the CompliancePanel and dashboard
 * counts live without manual wiring.
 */
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';
import type {
  CaeRevision,
  CloseBookBody,
  CloseRetentionExecutionReviewBody,
  BreachPlaybookView,
  CreateBreachPlaybookBody,
  CreateDsrRequestBody,
  CreateDpiaRecordBody,
  CreateEntityBody,
  CreateProcessorRecordBody,
  CreateRetentionPolicyBody,
  CreateUserBody,
  DraftActBody,
  EntityFamily,
  LifecycleStage,
  CmdInitiateBody,
  CmdConfirmBody,
  CcSignBody,
  CcBatchSignBody,
  LocalPkcs12SignBody,
  OfficialSignatureImportBody,
  XadesSignBody,
  AsicSignBody,
  ScapProvidersBody,
  ScapAttributesBody,
  ScapSignBody,
  RemoteInitiateBody,
  RemoteConfirmBody,
  CompleteFollowUpBody,
  CreateFollowUpBody,
  CreateExternalSignerInviteBody,
  ExternalSignerInviteView,
  CreateExternalSigningEnvelopeBody,
  ExternalSigningEnvelopeView,
  UpdateExternalSigningEnvelopeBody,
  ExternalValidatorReportUploadRequest,
  FollowUpView,
  GeneratedDocumentDispatchEvidenceRequest,
  GeneratedDocumentDispatchEvidenceRecord,
  ImportedDocumentReviewBody,
  ImportedDocumentView,
  ImportFromRegistryBody,
  LawEntryView,
  LawCitationRequest,
  LedgerArchiveDocumentParams,
  LedgerQueryParams,
  OpenBookBody,
  PaperBookImportValidateBody,
  PaperBookImportPreserveBody,
  PaperBookImportView,
  PaperBookOcrConversionDossierView,
  PaperBookOcrDraftCanonicalDraftResponse,
  PaperBookOcrDraftCreateBody,
  PaperBookOcrDraftReviewBody,
  PaperBookOcrDraftView,
  PaperBookOcrRunView,
  PaperBookOcrStatus,
  PdfSignatureValidationBody,
  PlatformControllableServiceId,
  PlatformLogsQueryParams,
  PlatformServiceAction,
  RegistryAutoUpdateAttemptBody,
  RegistryImportBody,
  SealActBody,
  Settings,
  SetSecretBody,
  RemoveSecretBody,
  AttestationKeyBody,
  IssueRecoveryBody,
  UpdateActBody,
  UpdateEntityBody,
  UpdateUserBody,
  VerifyAiHumanReviewBody,
  ActState,
  DataCleanupBody,
  DataKeyRotationExecuteBody,
  DataKeyRotationPreflightBody,
  BackupRecoveryDrillBody,
  ReanchorBody,
  RestoreBody,
  RestorePreflightBody,
  CollisionPolicy,
  StartOverBookBody,
  ResetDataBody,
  StartOverInstanceBody,
  CreateRoleBody,
  DpiaRecordView,
  PatchRoleBody,
  PatchFollowUpBody,
  PatchBreachPlaybookBody,
  PatchDpiaRecordBody,
  PatchProcessorRecordBody,
  PatchRetentionPolicyBody,
  ProcessorRecordView,
  RetentionDryRunBody,
  RetentionExecutionRecord,
  RetentionExecutionStatus,
  RetentionPolicyView,
  TransferControlView,
  CreateTransferControlBody,
  PatchTransferControlBody,
  RoleAssignmentInput,
  GrantDelegationBody,
  CreateApiKeyBody,
  DsrRequestView,
  SetBookLegalHoldBody,
  TslCatalogSearchParams,
  TslRefreshRequest,
  TsaCatalogSearchParams,
} from './types';
import { api, type ActDocumentWorkingCopyFormat } from './client';
import { clearSessionToken, onSessionCleared, setSessionToken } from './session';

export const keys = {
  entities: ['entities'] as const,
  entity: (id: string) => ['entities', id] as const,
  entityChronology: (id: string) => ['entities', id, 'chronology'] as const,
  entityRegistry: (id: string) => ['entities', id, 'registry'] as const,
  registryAutoUpdatePlan: ['registry', 'auto-update', 'due-plan'] as const,
  books: (entityId?: string) => ['books', { entityId: entityId ?? null }] as const,
  book: (id: string) => ['books', id] as const,
  bookLegalHold: (id: string) => ['books', id, 'legal-hold'] as const,
  bookActs: (id: string) => ['books', id, 'acts'] as const,
  paperBookImports: (bookRef?: string) =>
    ['books', 'paper-imports', { bookRef: bookRef ?? null }] as const,
  paperBookOcrDrafts: (importId: string) =>
    ['books', 'paper-imports', importId, 'ocr-drafts'] as const,
  paperBookOcrConversionDossiers: (importId: string) =>
    ['books', 'paper-imports', importId, 'conversion-dossiers'] as const,
  act: (id: string) => ['acts', id] as const,
  compliance: (id: string) => ['acts', id, 'compliance'] as const,
  actFollowUps: (id: string) => ['acts', id, 'follow-ups'] as const,
  actDocumentPreview: (id: string) => ['acts', id, 'document', 'preview'] as const,
  actDocumentBundle: (id: string) => ['acts', id, 'document', 'bundle'] as const,
  generatedDocuments: (actId: string) => ['acts', actId, 'documents', 'generated'] as const,
  generatedDocumentDispatchEvidence: (documentId: string) =>
    ['documents', 'generated', documentId, 'dispatch-evidence'] as const,
  importedDocuments: (actId?: string) =>
    ['documents', 'imported', { actId: actId ?? null }] as const,
  importedDocument: (id: string) => ['documents', 'imported', id] as const,
  actSignature: (id: string) => ['acts', id, 'signature'] as const,
  externalSigningEnvelopes: (id: string) => ['acts', id, 'external-signing', 'envelopes'] as const,
  externalSignerInvites: (id: string) => ['acts', id, 'signature', 'external-invites'] as const,
  signatureProviders: ['signature', 'providers'] as const,
  templates: (family?: EntityFamily, stage?: LifecycleStage) =>
    ['templates', { family: family ?? null, stage: stage ?? null }] as const,
  ledger: (params: LedgerQueryParams) => ['ledger', params] as const,
  ledgerPage: (params: LedgerQueryParams) => ['ledger', 'page', params] as const,
  ledgerVerify: ['ledger', 'verify'] as const,
  ledgerIntegrity: ['ledger', 'integrity'] as const,
  ledgerRestorePreflight: ['ledger', 'restore', 'preflight'] as const,
  backupRecoveryDrills: ['backup', 'recovery-drills'] as const,
  dataStatus: ['data', 'status'] as const,
  dataBackup: ['data', 'backup'] as const,
  dataKeyRotationPreflight: ['data', 'key-rotation', 'preflight'] as const,
  dataKeyRotationExecution: ['data', 'key-rotation', 'execution'] as const,
  dashboard: ['dashboard'] as const,
  settings: ['settings'] as const,
  platformServices: ['platform', 'services'] as const,
  platformLogs: (params: PlatformLogsQueryParams = {}) =>
    [
      'platform',
      'logs',
      {
        service_id: params.service_id ?? null,
        level: params.level ?? null,
        tail: params.tail ?? null,
      },
    ] as const,
  health: ['health'] as const,
  caeCatalog: ['cae', 'catalog'] as const,
  caeSearch: (search: string, revision?: CaeRevision) =>
    ['cae', 'search', search, revision] as const,
  caeEntry: (code: string, revision?: CaeRevision) => ['cae', 'entry', code, revision] as const,
  caeChildren: (code: string, revision: CaeRevision) =>
    ['cae', 'children', code, revision] as const,
  trustStatus: ['trust', 'status'] as const,
  trustCatalog: ['trust', 'catalog'] as const,
  trustSearch: (params: TslCatalogSearchParams) => ['trust', 'search', params] as const,
  trustProvider: (id: string) => ['trust', 'provider', id] as const,
  trustService: (id: string) => ['trust', 'service', id] as const,
  tsaCatalog: ['trust', 'tsa'] as const,
  tsaSearch: (params: TsaCatalogSearchParams) => ['trust', 'tsa', 'search', params] as const,
  pdfSignatureValidation: ['signature', 'pdf', 'validate'] as const,
  externalValidatorReports: ['external-validator-reports'] as const,
  lawManifest: ['law', 'manifest'] as const,
  lawCorpus: ['law', 'corpus'] as const,
  lawDiploma: (diploma: string) => ['law', 'corpus', diploma] as const,
  lawSearch: (q: string) => ['law', 'corpus', 'search', q] as const,
  users: ['users'] as const,
  user: (id: string) => ['users', id] as const,
  userDsrRequests: (id: string) => ['users', id, 'dsr-requests'] as const,
  session: ['session'] as const,
  passwordPolicy: ['session', 'password-policy'] as const,
  sessionPermissions: ['session', 'permissions'] as const,
  roster: ['session', 'roster'] as const,
  roles: ['roles'] as const,
  permissionCatalog: ['permissions'] as const,
  delegations: ['delegations'] as const,
  apiKeys: ['api-keys'] as const,
  privacyProcessors: ['privacy', 'processors'] as const,
  privacyDpias: ['privacy', 'dpias'] as const,
  privacyBreachPlaybooks: ['privacy', 'breach-playbooks'] as const,
  privacyTransferControls: ['privacy', 'transfer-controls'] as const,
  privacyRetentionPolicies: ['privacy', 'retention-policies'] as const,
  privacyRetentionDueCandidates: ['privacy', 'retention-due-candidates'] as const,
  privacyRetentionExecutions: (status: RetentionExecutionStatus | 'all' = 'all') =>
    ['privacy', 'retention-executions', status] as const,
};

// --- Entities -------------------------------------------------------------------

export function useEntities() {
  return useQuery({ queryKey: keys.entities, queryFn: () => api.listEntities() });
}

export function useEntity(id: string) {
  return useQuery({ queryKey: keys.entity(id), queryFn: () => api.getEntity(id), enabled: !!id });
}

export function useEntityChronology(id: string) {
  return useQuery({
    queryKey: keys.entityChronology(id),
    queryFn: () => api.getEntityChronology(id),
    enabled: !!id,
    retry: false,
  });
}

export function useCreateEntity() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateEntityBody) => api.createEntity(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.entities });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

/**
 * Set/clear an entity's statute overlay (`PATCH /v1/entities/{id}`, ENT-03/t31). On
 * success the entity refetches (so the profile/statute panels reflect the change) and
 * the ledger refetches (the PATCH appends an `entity.statute_updated` event).
 */
export function useUpdateEntity(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: UpdateEntityBody) => api.updateEntity(id, body),
    onSuccess: (entity) => {
      qc.setQueryData(keys.entity(id), entity);
      void qc.invalidateQueries({ queryKey: keys.entity(id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

// --- Registry — certidão permanente (plan t11) ----------------------------------

/**
 * The stored registry extract for an entity (`GET /v1/entities/{id}/registry`). The
 * server returns `404` until something has been imported; we treat that as "no
 * extract" (the panel shows an empty state) rather than an error, and never retry it.
 * The response carries only the MASKED access code — the full código de acesso is
 * never cached here.
 */
export function useEntityRegistry(id: string) {
  return useQuery({
    queryKey: keys.entityRegistry(id),
    queryFn: () => api.getEntityRegistry(id),
    enabled: !!id,
    retry: false,
  });
}

/**
 * Create a new entity from a certidão (`POST /v1/entities/import-from-registry`). The
 * `code` lives only in the mutation variables for the duration of the request; on
 * success the entity list + dashboard refetch and the caller navigates to the new
 * entity.
 */
export function useImportFromRegistry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ImportFromRegistryBody) => api.importFromRegistry(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.entities });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

/**
 * Enrich an existing entity from a certidão (`POST /v1/entities/{id}/registry/import`).
 * Refetches the entity, its stored extract and the ledger (an import appends a
 * `registry.imported` event). The `code` is only ever a transient mutation variable.
 */
export function useImportEntityRegistry(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RegistryImportBody) => api.importEntityRegistry(id, body),
    onSuccess: (report) => {
      qc.setQueryData(keys.entity(id), report.entity);
      qc.setQueryData(keys.entityRegistry(id), report.extract);
      void qc.invalidateQueries({ queryKey: keys.entity(id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

/**
 * Backend-owned dry-run plan for registry auto-update work (`GET /v1/registry/lookup`).
 * It is status only: the frontend never performs a registry lookup here and never supplies
 * result data.
 */
export function useRegistryAutoUpdateDuePlan() {
  return useQuery({
    queryKey: keys.registryAutoUpdatePlan,
    queryFn: () => api.getRegistryAutoUpdateDuePlan(),
    staleTime: 30_000,
    retry: false,
  });
}

/**
 * Request one metadata-only registry auto-update attempt for an entity. The body carries only
 * worker control fields (`force`, `dry_run`, `reason`); no raw HTML or parsed extract is accepted
 * by the backend. Refetch the dry-run plan and ledger after a recorded attempt.
 */
export function useRequestRegistryAutoUpdate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body = {} }: { id: string; body?: RegistryAutoUpdateAttemptBody }) =>
      api.requestRegistryAutoUpdate(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.registryAutoUpdatePlan });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

// --- Books ----------------------------------------------------------------------

export function useBooks(entityId?: string) {
  return useQuery({ queryKey: keys.books(entityId), queryFn: () => api.listBooks(entityId) });
}

export function useBook(id: string) {
  return useQuery({ queryKey: keys.book(id), queryFn: () => api.getBook(id), enabled: !!id });
}

export function useBookActs(id: string) {
  return useQuery({
    queryKey: keys.bookActs(id),
    queryFn: () => api.listBookActs(id),
    enabled: !!id,
  });
}

export function useBookLegalHold(id: string) {
  return useQuery({
    queryKey: keys.bookLegalHold(id),
    queryFn: () => api.getBookLegalHold(id),
    enabled: !!id,
    retry: false,
  });
}

export function useOpenBook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: OpenBookBody) => api.openBook(body),
    onSuccess: (book) => {
      void qc.invalidateQueries({ queryKey: ['books'] });
      void qc.invalidateQueries({ queryKey: keys.entity(book.entity_id) });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

export function useCloseBook(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CloseBookBody) => api.closeBook(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['books'] });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

export function useSetBookLegalHold(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: SetBookLegalHoldBody) => api.setBookLegalHold(id, body),
    onSuccess: (hold) => {
      qc.setQueryData(keys.bookLegalHold(id), hold);
      void qc.invalidateQueries({ queryKey: keys.bookLegalHold(id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function useClearBookLegalHold(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.clearBookLegalHold(id),
    onSuccess: (hold) => {
      qc.setQueryData(
        keys.bookLegalHold(id),
        hold ?? { legal_hold: false, reason: null, actor: null, set_at: null },
      );
      void qc.invalidateQueries({ queryKey: keys.bookLegalHold(id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/**
 * Download a book's Chancela internal preservation package
 * (`GET /v1/books/{id}/archive/package`, application/zip). This is a read-only package export,
 * distinct from the retained self-verifying book bundle (`POST /export`) used by recovery flows.
 */
export function useDownloadBookArchivePackage(id: string) {
  return useMutation({ mutationFn: () => api.fetchBookArchivePackage(id) });
}

/**
 * Download the metadata-only local DGLAB interchange manifest scaffold as JSON.
 * Read-only: this GET must not create archive/package bytes or mutate ledger state.
 */
export function useDownloadBookLocalDglabInterchangeManifest(id: string) {
  return useMutation({ mutationFn: () => api.getBookLocalDglabInterchangeManifest(id) });
}

export function usePaperBookImports(bookRef?: string) {
  return useQuery({
    queryKey: keys.paperBookImports(bookRef),
    queryFn: () => api.listPaperBookImports({ book_ref: bookRef }),
    enabled: bookRef !== '',
    retry: false,
  });
}

export function useValidatePaperBookImport() {
  return useMutation({
    mutationFn: (body: PaperBookImportValidateBody) => api.validatePaperBookImport(body),
  });
}

export function usePreservePaperBookImport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: PaperBookImportPreserveBody) => api.preservePaperBookImport(body),
    onSuccess: (report) => {
      void qc.invalidateQueries({
        queryKey: keys.paperBookImports(report.identity.book_ref),
      });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

function replacePaperBookImportOcrStatus(
  rows: PaperBookImportView[] | undefined,
  importId: string,
  ocrStatus: PaperBookOcrStatus,
  patch: Partial<Pick<PaperBookImportView, 'ocr_status_notice' | 'ocr_text_stored'>> = {},
): PaperBookImportView[] | undefined {
  return rows?.map((row) =>
    row.import_id === importId ? { ...row, ...patch, ocr_status: ocrStatus } : row,
  );
}

export function useEnqueuePaperBookImportOcr(bookRef?: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.enqueuePaperBookImportOcr(id),
    onSuccess: (status) => {
      qc.setQueryData<PaperBookImportView[]>(keys.paperBookImports(bookRef), (rows) =>
        replacePaperBookImportOcrStatus(rows, status.import_id, status.ocr_status),
      );
      void qc.invalidateQueries({ queryKey: keys.paperBookImports(bookRef) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function useUpdatePaperBookImportOcrStatus(bookRef?: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: PaperBookOcrStatus }) =>
      api.updatePaperBookImportOcrStatus(id, { status }),
    onSuccess: (status) => {
      qc.setQueryData<PaperBookImportView[]>(keys.paperBookImports(bookRef), (rows) =>
        replacePaperBookImportOcrStatus(rows, status.import_id, status.ocr_status),
      );
      void qc.invalidateQueries({ queryKey: keys.paperBookImports(bookRef) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function useRunPaperBookImportOcr(bookRef?: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.runPaperBookImportOcr(id),
    onSuccess: (result: PaperBookOcrRunView) => {
      qc.setQueryData<PaperBookImportView[]>(keys.paperBookImports(bookRef), (rows) =>
        replacePaperBookImportOcrStatus(rows, result.import_id, result.ocr_status, {
          ocr_status_notice: result.status_notice,
        }),
      );
      const draft = result.draft;
      if (draft) {
        qc.setQueryData<PaperBookOcrDraftView[]>(
          keys.paperBookOcrDrafts(result.import_id),
          (rows) => upsertPaperBookOcrDraft(rows, draft),
        );
      }
      void qc.invalidateQueries({ queryKey: ['books', 'paper-imports'] });
      void qc.invalidateQueries({ queryKey: keys.paperBookOcrDrafts(result.import_id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function usePaperBookOcrDrafts(importId: string) {
  return useQuery({
    queryKey: keys.paperBookOcrDrafts(importId),
    queryFn: () => api.listPaperBookImportOcrDrafts(importId),
    enabled: !!importId,
    retry: false,
  });
}

function upsertPaperBookOcrDraft(
  rows: PaperBookOcrDraftView[] | undefined,
  draft: PaperBookOcrDraftView,
): PaperBookOcrDraftView[] {
  const current = rows ?? [];
  return current.some((row) => row.draft_id === draft.draft_id)
    ? current.map((row) => (row.draft_id === draft.draft_id ? draft : row))
    : [draft, ...current];
}

export function useCreatePaperBookOcrDraft() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ importId, body }: { importId: string; body: PaperBookOcrDraftCreateBody }) =>
      api.createPaperBookImportOcrDraft(importId, body),
    onSuccess: (draft) => {
      qc.setQueryData<PaperBookOcrDraftView[]>(keys.paperBookOcrDrafts(draft.import_id), (rows) =>
        upsertPaperBookOcrDraft(rows, draft),
      );
      void qc.invalidateQueries({ queryKey: keys.paperBookOcrDrafts(draft.import_id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function useReviewPaperBookOcrDraft() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      importId,
      draftId,
      body,
    }: {
      importId: string;
      draftId: string;
      body: PaperBookOcrDraftReviewBody;
    }) => api.reviewPaperBookImportOcrDraft(importId, draftId, body),
    onSuccess: (draft) => {
      qc.setQueryData<PaperBookOcrDraftView[]>(keys.paperBookOcrDrafts(draft.import_id), (rows) =>
        upsertPaperBookOcrDraft(rows, draft),
      );
      void qc.invalidateQueries({ queryKey: keys.paperBookOcrDrafts(draft.import_id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function useCreatePaperBookOcrDraftActDraft(bookId?: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ importId, draftId }: { importId: string; draftId: string }) =>
      api.createPaperBookOcrDraftActDraft(importId, draftId),
    onSuccess: (result: PaperBookOcrDraftCanonicalDraftResponse) => {
      qc.setQueryData(keys.act(result.act.id), result.act);
      void qc.invalidateQueries({ queryKey: keys.bookActs(bookId ?? result.act.book_id) });
      void qc.invalidateQueries({ queryKey: keys.act(result.act.id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function usePaperBookOcrConversionDossiers(importId: string) {
  return useQuery({
    queryKey: keys.paperBookOcrConversionDossiers(importId),
    queryFn: () => api.listPaperBookOcrConversionDossiers(importId),
    enabled: !!importId,
    retry: false,
  });
}

function upsertPaperBookOcrConversionDossier(
  rows: PaperBookOcrConversionDossierView[] | undefined,
  dossier: PaperBookOcrConversionDossierView,
): PaperBookOcrConversionDossierView[] {
  const current = rows ?? [];
  const isSameDossier = (row: PaperBookOcrConversionDossierView) =>
    row.dossier_id === dossier.dossier_id ||
    (row.import_id === dossier.import_id && row.draft_id === dossier.draft_id);
  return current.some(isSameDossier)
    ? current.map((row) => (isSameDossier(row) ? dossier : row))
    : [dossier, ...current];
}

export function useCreatePaperBookOcrConversionDossier() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ importId, draftId }: { importId: string; draftId: string }) =>
      api.createPaperBookOcrConversionDossier(importId, draftId),
    onSuccess: (dossier) => {
      qc.setQueryData<PaperBookOcrConversionDossierView[]>(
        keys.paperBookOcrConversionDossiers(dossier.import_id),
        (rows) => upsertPaperBookOcrConversionDossier(rows, dossier),
      );
      void qc.invalidateQueries({
        queryKey: keys.paperBookOcrConversionDossiers(dossier.import_id),
      });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function useDownloadPaperBookImport() {
  return useMutation({ mutationFn: (id: string) => api.fetchPaperBookImportBytes(id) });
}

export function useValidatePdfSignature() {
  return useMutation({
    mutationKey: keys.pdfSignatureValidation,
    mutationFn: (body: PdfSignatureValidationBody) => api.validatePdfSignature(body),
  });
}

export function useExternalValidatorReports() {
  return useQuery({
    queryKey: keys.externalValidatorReports,
    queryFn: () => api.listExternalValidatorReports(),
    retry: false,
  });
}

export function useUploadExternalValidatorReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ExternalValidatorReportUploadRequest) =>
      api.uploadExternalValidatorReport(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.externalValidatorReports });
    },
  });
}

// --- Acts -----------------------------------------------------------------------

export function useAct(id: string) {
  return useQuery({ queryKey: keys.act(id), queryFn: () => api.getAct(id), enabled: !!id });
}

export function useCompliance(id: string) {
  return useQuery({
    queryKey: keys.compliance(id),
    queryFn: () => api.getCompliance(id),
    enabled: !!id,
  });
}

export function useDraftAct() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: DraftActBody) => api.draftAct(body),
    onSuccess: (act) => {
      void qc.invalidateQueries({ queryKey: keys.bookActs(act.book_id) });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

export function useUpdateAct(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: UpdateActBody) => api.updateAct(id, body),
    onSuccess: (act) => {
      qc.setQueryData(keys.act(id), act);
      void qc.invalidateQueries({ queryKey: keys.compliance(id) });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

export function useAdvanceAct(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (to: ActState) => api.advanceAct(id, { to }),
    onSuccess: (act) => {
      qc.setQueryData(keys.act(id), act);
      void qc.invalidateQueries({ queryKey: keys.compliance(id) });
      void qc.invalidateQueries({ queryKey: keys.bookActs(act.book_id) });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

export function useVerifyActHumanReview(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: VerifyAiHumanReviewBody) => api.verifyActHumanReview(id, body),
    onSuccess: (act) => {
      qc.setQueryData(keys.act(id), act);
      void qc.invalidateQueries({ queryKey: keys.compliance(id) });
      void qc.invalidateQueries({ queryKey: keys.bookActs(act.book_id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

export function useSealAct(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: SealActBody) => api.sealAct(id, body),
    onSuccess: (result) => {
      qc.setQueryData(keys.act(id), result.act);
      void qc.invalidateQueries({ queryKey: keys.compliance(id) });
      void qc.invalidateQueries({ queryKey: keys.bookActs(result.act.book_id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

export function useActFollowUps(id: string) {
  return useQuery({
    queryKey: keys.actFollowUps(id),
    queryFn: () => api.listActFollowUps(id),
    enabled: !!id,
  });
}

function replaceFollowUp(rows: FollowUpView[] | undefined, row: FollowUpView): FollowUpView[] {
  const current = rows ?? [];
  return current.some((item) => item.id === row.id)
    ? current.map((item) => (item.id === row.id ? row : item))
    : [row, ...current];
}

export function useCreateActFollowUp(actId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateFollowUpBody) => api.createActFollowUp(actId, body),
    onSuccess: (row) => {
      qc.setQueryData<FollowUpView[]>(keys.actFollowUps(actId), (rows) =>
        replaceFollowUp(rows, row),
      );
      void qc.invalidateQueries({ queryKey: keys.actFollowUps(actId) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function usePatchFollowUp(actId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: PatchFollowUpBody }) =>
      api.patchFollowUp(id, body),
    onSuccess: (row) => {
      qc.setQueryData<FollowUpView[]>(keys.actFollowUps(actId), (rows) =>
        replaceFollowUp(rows, row),
      );
      void qc.invalidateQueries({ queryKey: keys.actFollowUps(actId) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function useCompleteFollowUp(actId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body = {} }: { id: string; body?: CompleteFollowUpBody }) =>
      api.completeFollowUp(id, body),
    onSuccess: (row) => {
      qc.setQueryData<FollowUpView[]>(keys.actFollowUps(actId), (rows) =>
        replaceFollowUp(rows, row),
      );
      void qc.invalidateQueries({ queryKey: keys.actFollowUps(actId) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/**
 * The live document preview for an act (`GET /v1/acts/{id}/document/preview`, t48). Renders
 * the CURRENT record — works pre-seal for a draft preview and post-seal alike. Lazily
 * enabled (the caller flips `enabled` when the user asks to preview) so the render only
 * runs on demand. A `422`/`404` is the "family has no template" signal, surfaced to the
 * caller as an honest empty state rather than retried — so `retry: false`.
 */
export function useActDocumentPreview(id: string, enabled: boolean) {
  return useQuery({
    queryKey: keys.actDocumentPreview(id),
    queryFn: () => api.getActDocumentPreview(id),
    enabled: enabled && !!id,
    retry: false,
  });
}

/**
 * The DOC-03 bundle for a sealed act (`GET /v1/acts/{id}/document/bundle`, t48). 404 until
 * sealed — and 404 for a sealed act whose family has no template (the documented no-document
 * fallback), which the caller renders honestly. Enabled only once sealed; never retried so
 * the 404 resolves immediately to the empty state.
 */
export function useActDocumentBundle(id: string, enabled: boolean) {
  return useQuery({
    queryKey: keys.actDocumentBundle(id),
    queryFn: () => api.getActDocumentBundle(id),
    enabled: enabled && !!id,
    retry: false,
  });
}

export function useGeneratedDocuments(actId: string, enabled = true) {
  return useQuery({
    queryKey: keys.generatedDocuments(actId),
    queryFn: () => api.listGeneratedDocuments(actId),
    enabled: enabled && !!actId,
    retry: false,
  });
}

export function useGeneratedDocumentDispatchEvidence(documentId: string | null | undefined) {
  return useQuery({
    queryKey: keys.generatedDocumentDispatchEvidence(documentId ?? ''),
    queryFn: () => api.getGeneratedDocumentDispatchEvidence(documentId ?? ''),
    enabled: !!documentId,
    retry: false,
  });
}

export function useRecordGeneratedDocumentDispatchEvidence() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      documentId,
      body,
    }: {
      documentId: string;
      body: GeneratedDocumentDispatchEvidenceRequest;
    }) => api.recordGeneratedDocumentDispatchEvidence(documentId, body),
    onSuccess: (response) => {
      const { act_id: actId, document_id: documentId } = response.evidence;
      qc.setQueryData(keys.generatedDocumentDispatchEvidence(documentId), (current: unknown) => {
        if (!current || typeof current !== 'object') return current;
        const existing = current as {
          evidence?: GeneratedDocumentDispatchEvidenceRecord[];
        };
        const rows = existing.evidence ?? [];
        const alreadyPresent = rows.some(
          (row) => row.idempotency_key === response.evidence.idempotency_key,
        );
        return {
          ...existing,
          dispatch_evidence_status: response.dispatch_evidence_status,
          evidence: alreadyPresent ? rows : [...rows, response.evidence],
        };
      });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
      void qc.invalidateQueries({ queryKey: keys.generatedDocuments(actId) });
      void qc.invalidateQueries({ queryKey: keys.generatedDocumentDispatchEvidence(documentId) });
      void qc.invalidateQueries({ queryKey: keys.importedDocuments(actId) });
      void qc.invalidateQueries({ queryKey: keys.actDocumentBundle(actId) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

function replaceImportedDocument(
  rows: ImportedDocumentView[] | undefined,
  document: ImportedDocumentView,
): ImportedDocumentView[] {
  const current = rows ?? [];
  return current.some((item) => item.id === document.id)
    ? current.map((item) => (item.id === document.id ? document : item))
    : [document, ...current];
}

/**
 * Metadata-only operator review for imported, non-canonical document evidence. The server
 * permits only conservative terminal states and records the actor/timestamp; no OCR, conversion,
 * canonical replacement, or legal acceptance is performed by this PATCH.
 */
export function useReviewImportedDocument(actId?: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: ImportedDocumentReviewBody }) =>
      api.reviewImportedDocument(id, body),
    onSuccess: (document) => {
      const listActId = document.act_id ?? actId;
      qc.setQueryData(keys.importedDocument(document.id), document);
      qc.setQueryData<ImportedDocumentView[]>(keys.importedDocuments(listActId), (rows) =>
        replaceImportedDocument(rows, document),
      );
      void qc.invalidateQueries({ queryKey: keys.importedDocument(document.id) });
      void qc.invalidateQueries({ queryKey: keys.importedDocuments(listActId) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/**
 * The template catalog for a family × stage (`GET /v1/templates`, t48). Informational for
 * v1 (the seal auto-picks) — the picker just surfaces which model applies. Kept fresh for
 * a minute; the catalog is embedded, static data.
 */
export function useTemplates(family?: EntityFamily, stage?: LifecycleStage) {
  return useQuery({
    queryKey: keys.templates(family, stage),
    queryFn: () => api.listTemplates({ family, stage }),
    staleTime: 60_000,
  });
}

/**
 * Download a sealed act's PDF/A (`GET /v1/acts/{id}/document`, t48). A mutation so the
 * button gets `isPending` + the toast idiom for free; the caller triggers the browser
 * download from the returned `Blob` with an honest filename. Only offered post-seal (the
 * endpoint 404s until then).
 */
export function useDownloadActDocument(id: string) {
  return useMutation({ mutationFn: () => api.fetchActDocumentPdf(id) });
}

/**
 * Download a sealed act's working copy (`GET /v1/acts/{id}/document/working-copy`).
 * Markdown is the default format; TXT, HTML, RTF, and ODT are explicit variants. These exports
 * are non-evidentiary, so callers keep them visually separate from the official PDF/A.
 */
export function useDownloadActDocumentWorkingCopy(
  id: string,
  format: ActDocumentWorkingCopyFormat = 'markdown',
) {
  return useMutation({ mutationFn: () => api.fetchActDocumentWorkingCopy(id, format) });
}

/**
 * Download a sealed act's DOCX office working copy (`GET /v1/acts/{id}/document/office`).
 * Non-evidentiary and read-only; the preserved PDF/A or signed PDF remains canonical.
 */
export function useDownloadActDocumentOffice(id: string) {
  return useMutation({ mutationFn: () => api.fetchActDocumentOffice(id) });
}

// --- Qualified CMD signing (§ t57) ----------------------------------------------

/**
 * The act's signature status (`GET /v1/acts/{id}/signature`, t57). Drives the signing
 * panel: unsigned / pending (aguarda-OTP) / signed. Enabled only once sealed (the endpoint
 * is meaningful post-seal); never retried so a transient state resolves immediately.
 */
export function useActSignature(id: string, enabled: boolean) {
  return useQuery({
    queryKey: keys.actSignature(id),
    queryFn: () => api.getActSignature(id),
    enabled: enabled && !!id,
    retry: false,
  });
}

/**
 * Phase 1 of CMD signing (`POST /v1/acts/{id}/signature/cmd/initiate`, t57): phone + PIN →
 * the server dispatches the SMS OTP and returns a `session_id`. The PIN lives only in the
 * mutation variables for the duration of this request — never cached or persisted here.
 */
export function useCmdInitiateSignature(id: string) {
  return useMutation({ mutationFn: (body: CmdInitiateBody) => api.cmdInitiateSignature(id, body) });
}

/**
 * Phase 2 of CMD signing (`POST /v1/acts/{id}/signature/cmd/confirm`, t57): session_id + OTP
 * → the signed PDF. The OTP is a transient mutation variable. On success the signature status,
 * the act and the dashboard refetch (the confirm appends a `document.signed` ledger event).
 */
export function useCmdConfirmSignature(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CmdConfirmBody) => api.cmdConfirmSignature(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.actSignature(id) });
      void qc.invalidateQueries({ queryKey: keys.act(id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

/**
 * Qualified Cartão de Cidadão signing (`POST /v1/acts/{id}/signature/cc/sign`, t58) — a
 * SYNCHRONOUS, desktop-only single call. The optional in-app PIN is a transient mutation
 * variable; when it is absent, protected authentication happens at the reader / Autenticação.gov
 * prompt. The call BLOCKS while the card signs, so the caller shows a brief "a assinar…" busy
 * state. On success the signature status, the act, the ledger and the dashboard refetch (the sign
 * appends a `document.signed` event). A 409 means the API is not co-located with a reader
 * (browser/remote); a 422 is an honest provider error (no card / wrong PIN / not activated / no
 * reader) — both surfaced by the caller, never persisted.
 */
export function useCcSignSignature(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CcSignBody = {}) => api.ccSignSignature(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.actSignature(id) });
      void qc.invalidateQueries({ queryKey: keys.act(id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

/**
 * In-app Cartão de Cidadão **batch** signing (`POST /v1/signature/cc/batch-sign`, t67). Signs a set
 * of sealed acts under one signer authentication where the card allows it. The optional PIN is a
 * transient mutation variable only — the caller clears it and calls `reset()` after each submit so
 * it never lingers in the retained mutation state. A batch may touch acts across many books, so the
 * broad signing/ledger/dashboard surfaces are invalidated on success (each affected act refetches).
 */
export function useCcBatchSign() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CcBatchSignBody) => api.signCcBatch(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['acts'] });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

/**
 * Advanced local PKCS#12/PFX software-certificate signing. The encrypted PFX and passphrase are
 * transient mutation variables only; on success the same signed-document surfaces refetch as the
 * other signing flows. The server labels the result local technical evidence, not qualified/CMD.
 */
export function useLocalPkcs12SignSignature(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: LocalPkcs12SignBody) => api.localPkcs12SignSignature(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.actSignature(id) });
      void qc.invalidateQueries({ queryKey: keys.act(id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

/**
 * Official Autenticação.gov/provider handoff import. The upload is already signed outside
 * Chancela, and the server stores technical evidence only after all guardrails are acknowledged.
 */
export function useImportOfficialSignature(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: OfficialSignatureImportBody) => api.importOfficialSignature(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.actSignature(id) });
      void qc.invalidateQueries({ queryKey: keys.act(id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

// --- Local technical XAdES / ASiC / SCAP signing tools (§ t67-e13) ----------------
//
// These local tools return a document (or a CAdES signature) without changing act state, so — unlike
// the act-signing lanes — they invalidate NO query cache. The transient PKCS#12 material rides only
// in the mutation variables; each caller clears it and calls `reset()` after every submit so it never
// lingers in the retained mutation state.

/** Local XAdES production (`POST /v1/signature/xades/sign`). Co-location-gated; returns the XML. */
export function useXadesSign() {
  return useMutation({ mutationFn: (body: XadesSignBody) => api.signXades(body) });
}

/** Local ASiC production (`POST /v1/signature/asic/sign`). Co-location-gated; returns the container. */
export function useAsicSign() {
  return useMutation({ mutationFn: (body: AsicSignBody) => api.signAsic(body) });
}

/** SCAP attribute-provider list (`POST /v1/scap/providers`). */
export function useScapProviders() {
  return useMutation({ mutationFn: (body: ScapProvidersBody = {}) => api.scapProviders(body) });
}

/** SCAP citizen professional-attribute fetch (`POST /v1/scap/attributes`). */
export function useScapAttributes() {
  return useMutation({ mutationFn: (body: ScapAttributesBody) => api.scapAttributes(body) });
}

/**
 * SCAP attribute-qualified signing (`POST /v1/scap/sign`). The response's `verification.verified` is
 * the single source of truth for the declared-vs-verified label; the mock transport can never set it.
 */
export function useScapSign() {
  return useMutation({ mutationFn: (body: ScapSignBody) => api.scapSign(body) });
}

// --- Generic remote qualified signing (§ t59) — the provider picker + CSC QTSPs ---

/**
 * The signing-provider picker list (`GET /v1/signature/providers`, t59): Chave Móvel Digital
 * plus every configured CSC QTSP, each with a non-secret `configured` flag. Enabled only once
 * sealed and never retried; the endpoint is gated `signing.perform` server-side, so a principal
 * without signing authority (or an older server) simply gets no list — the panel then falls
 * back to the always-available CMD + CC flows rather than surfacing an error.
 */
export function useSignatureProviders(enabled: boolean) {
  return useQuery({
    queryKey: keys.signatureProviders,
    queryFn: () => api.listSignatureProviders(),
    enabled,
    retry: false,
    staleTime: 60_000,
  });
}

/**
 * Phase 1 of the generic remote flow (`POST .../signature/remote/{provider}/initiate`, t59):
 * `user_ref` + `credential` → the provider dispatches an activation and returns a `session_id`.
 * The credential lives only in the mutation variables for this request — never cached or
 * persisted. Used for CSC QTSPs (CMD keeps its dedicated `/signature/cmd/*` path).
 */
export function useRemoteInitiateSignature(id: string) {
  return useMutation({
    mutationFn: ({ provider, body }: { provider: string; body: RemoteInitiateBody }) =>
      api.remoteInitiateSignature(id, provider, body),
  });
}

/**
 * Phase 2 of the generic remote flow (`POST .../signature/remote/{provider}/confirm`, t59):
 * session_id + activation → the signed PDF. The activation is a transient mutation variable. On
 * success the signature status, the act, the ledger and the dashboard refetch (the confirm
 * appends a `document.signed` event).
 */
export function useRemoteConfirmSignature(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ provider, body }: { provider: string; body: RemoteConfirmBody }) =>
      api.remoteConfirmSignature(id, provider, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.actSignature(id) });
      void qc.invalidateQueries({ queryKey: keys.act(id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

/**
 * Sealed-act external signer invitation metadata. The endpoint is gated by
 * `signing.perform`; callers should enable it only when the current principal has that grant.
 * The list is redacted by contract: no plaintext token or token hash is ever cached here.
 */
export function useExternalSignerInvites(id: string, enabled: boolean) {
  return useQuery({
    queryKey: keys.externalSignerInvites(id),
    queryFn: () => api.listExternalSignerInvites(id),
    enabled: enabled && !!id,
    retry: false,
  });
}

/**
 * Workflow-only external signing envelopes for one sealed act. The server response is redacted to
 * ordered slot/status metadata and an explicit no-legal/no-qualified notice.
 */
export function useExternalSigningEnvelopes(id: string, enabled: boolean) {
  return useQuery({
    queryKey: keys.externalSigningEnvelopes(id),
    queryFn: () => api.listExternalSigningEnvelopes(id),
    enabled: enabled && !!id,
    retry: false,
  });
}

/** Create one workflow-only external-signing envelope for a sealed act. */
export function useCreateExternalSigningEnvelope(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateExternalSigningEnvelopeBody) =>
      api.createExternalSigningEnvelope(id, body),
    onSuccess: (envelope) => {
      qc.setQueryData<ExternalSigningEnvelopeView[]>(
        keys.externalSigningEnvelopes(id),
        (current) => {
          const rows = current ?? [];
          return rows.some((row) => row.id === envelope.id)
            ? rows.map((row) => (row.id === envelope.id ? envelope : row))
            : [envelope, ...rows];
        },
      );
      void qc.invalidateQueries({ queryKey: keys.externalSigningEnvelopes(id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/** Update slot status/evidence for an external-signing envelope. */
export function useUpdateExternalSigningEnvelope(actId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      envelopeId,
      body,
    }: {
      envelopeId: string;
      body: UpdateExternalSigningEnvelopeBody;
    }) => api.updateExternalSigningEnvelope(envelopeId, body),
    onSuccess: (envelope) => {
      qc.setQueryData<ExternalSigningEnvelopeView[]>(
        keys.externalSigningEnvelopes(actId),
        (current) => current?.map((row) => (row.id === envelope.id ? envelope : row)) ?? [envelope],
      );
      void qc.invalidateQueries({ queryKey: keys.externalSigningEnvelopes(actId) });
      void qc.invalidateQueries({ queryKey: keys.externalSignerInvites(actId) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/**
 * Create an external signer invitation. The returned plaintext token is emitted exactly once by
 * the server; this mutation invalidates the redacted list rather than writing the token to it.
 */
export function useCreateExternalSignerInvite(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateExternalSignerInviteBody) => api.createExternalSignerInvite(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.externalSignerInvites(id) });
      void qc.invalidateQueries({ queryKey: keys.externalSigningEnvelopes(id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/** Revoke a tracked external signer invite; the retained row refetches as `revoked`. */
export function useRevokeExternalSignerInvite(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (inviteId: string) => api.revokeExternalSignerInvite(id, inviteId),
    onSuccess: (revoked) => {
      qc.setQueryData<ExternalSignerInviteView[]>(keys.externalSignerInvites(id), (current) =>
        current?.map((invite) => (invite.id === revoked.id ? revoked : invite)),
      );
      void qc.invalidateQueries({ queryKey: keys.externalSignerInvites(id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/**
 * Download an act's SIGNED PDF (`GET /v1/acts/{id}/document/signed`, t57). A mutation so the
 * button gets `isPending` + the toast idiom for free; only offered once the act is signed (the
 * endpoint 404s until then).
 */
export function useDownloadSignedDocument(id: string) {
  return useMutation({ mutationFn: () => api.fetchSignedActDocumentPdf(id) });
}

export function useArchiveAct(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.archiveAct(id),
    onSuccess: (act) => {
      qc.setQueryData(keys.act(id), act);
      void qc.invalidateQueries({ queryKey: keys.bookActs(act.book_id) });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

// --- Ledger / Dashboard ---------------------------------------------------------

export function useLedger(params: LedgerQueryParams = {}) {
  return useQuery({ queryKey: keys.ledger(params), queryFn: () => api.listLedger(params) });
}

export function useLedgerPages(params: LedgerQueryParams = {}) {
  return useInfiniteQuery({
    queryKey: keys.ledgerPage(params),
    queryFn: ({ pageParam }) =>
      api.listLedgerPage({ ...params, before_seq: pageParam ?? params.before_seq }),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (lastPage) =>
      lastPage.has_more && lastPage.next_cursor ? lastPage.next_cursor : undefined,
  });
}

export function useLedgerVerify() {
  return useQuery({ queryKey: keys.ledgerVerify, queryFn: () => api.verifyLedger() });
}

/**
 * Download the filtered ledger archive (`GET /v1/ledger/archive/document`, t67).
 * A mutation so the Arquivo action can expose pending state and toast errors like the
 * other document downloads.
 */
export function useDownloadLedgerArchiveDocument() {
  return useMutation({
    mutationFn: (params: LedgerArchiveDocumentParams) => api.fetchLedgerArchiveDocument(params),
  });
}

// --- Chain integrity + recovery + data management (t54) --------------------------

/**
 * The multi-chain integrity report (`GET /v1/ledger/integrity`, t54). Read-only and
 * always available (even while the instance is degraded). Backs the "Livros &
 * Integridade" sub-tab's per-chain status, exact break location and re-anchor disclosure.
 */
export function useLedgerIntegrity() {
  return useQuery({ queryKey: keys.ledgerIntegrity, queryFn: () => api.ledgerIntegrity() });
}

/** Read-only data-directory and storage telemetry for the Data Management tab. */
export function useDataStatus() {
  return useQuery({
    queryKey: keys.dataStatus,
    queryFn: () => api.dataStatus(),
    staleTime: 15_000,
    retry: false,
  });
}

/** Hot whole-store backup (`POST /v1/backup`). Returns only the server manifest. */
export function useCreateBackup() {
  const qc = useQueryClient();
  return useMutation({
    mutationKey: keys.dataBackup,
    mutationFn: () => api.backup(),
    onSuccess: () => {
      invalidateAfterRecovery(qc);
    },
  });
}

/** Bounded storage cleanup for maintenance-only concerns such as crash reports and exports. */
export function useCleanDataStorage() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: DataCleanupBody) => api.cleanDataStorage(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.dataStatus });
    },
  });
}

/** Read-only SQLCipher key-rotation preflight; does not execute the rotation. */
export function useDataKeyRotationPreflight() {
  return useMutation({
    mutationKey: keys.dataKeyRotationPreflight,
    mutationFn: (body: DataKeyRotationPreflightBody) => api.preflightDataKeyRotation(body),
  });
}

/** Guarded SQLCipher rekey execution for an already-open keyed durable store. */
export function useDataKeyRotationExecution() {
  const qc = useQueryClient();
  return useMutation({
    mutationKey: keys.dataKeyRotationExecution,
    mutationFn: (body: DataKeyRotationExecuteBody) => api.executeDataKeyRotation(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.dataStatus });
    },
  });
}

/** Invalidate every read that a recovery / data-management op can change (integrity,
 *  verify, ledger feed, dashboard, books, entities, health). */
function invalidateAfterRecovery(qc: ReturnType<typeof useQueryClient>) {
  void qc.invalidateQueries({ queryKey: keys.ledgerIntegrity });
  void qc.invalidateQueries({ queryKey: keys.ledgerVerify });
  void qc.invalidateQueries({ queryKey: keys.dataStatus });
  void qc.invalidateQueries({ queryKey: ['ledger'] });
  void qc.invalidateQueries({ queryKey: keys.dashboard });
  void qc.invalidateQueries({ queryKey: ['books'] });
  void qc.invalidateQueries({ queryKey: keys.entities });
  void qc.invalidateQueries({ queryKey: keys.health });
}

/**
 * Last-resort chain re-anchor (`POST /v1/ledger/recovery/reanchor`, t54). Rebuilds the
 * chain hashes from the break forward — permanently disclosed. Requires a non-empty reason
 * and step-up re-auth (403 without, t54-R1); 409 when the chain already verifies.
 */
export function useReanchorLedger() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ReanchorBody) => api.reanchorLedger(body),
    onSuccess: () => invalidateAfterRecovery(qc),
  });
}

/**
 * Whole-store restore from a verified backup (`POST /v1/ledger/recovery/restore`, t54).
 * Never rewrites history; a backup that does not verify is refused (422) with the live
 * store untouched.
 */
export function useRestoreLedger() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RestoreBody) => api.restoreLedger(body),
    onSuccess: () => invalidateAfterRecovery(qc),
  });
}

/**
 * Read-only whole-store restore preflight. It verifies a selected archive and optional
 * transient passphrase without executing restore or invalidating live recovery state.
 */
export function useRestoreLedgerPreflight() {
  return useMutation({
    mutationKey: keys.ledgerRestorePreflight,
    mutationFn: (body: RestorePreflightBody) => api.restoreLedgerPreflight(body),
  });
}

/**
 * Non-destructive backup recovery drill receipt. The server runs restore preflight only and stores
 * a bounded custody receipt; no live restore endpoint is called by this mutation.
 */
export function useCreateBackupRecoveryDrill() {
  const qc = useQueryClient();
  return useMutation({
    mutationKey: keys.backupRecoveryDrills,
    mutationFn: (body: BackupRecoveryDrillBody) => api.createBackupRecoveryDrill(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.backupRecoveryDrills });
    },
  });
}

/**
 * Export one book as a self-verifying bundle (`POST /v1/books/{id}/export`, t54). Returns
 * the `.zip` blob + response headers (the retained export path / bundle digest); the caller
 * triggers the browser download. A mutation so the button gets `isPending` + toast for free.
 */
export function useExportBook() {
  return useMutation({ mutationFn: (bookId: string) => api.exportBook(bookId) });
}

/**
 * Read-only preflight for a book bundle import (`POST /v1/books/import/preflight`, t54).
 * It uses the same raw `.zip` bytes and collision policy but does not create an import id,
 * append `ledger.imported`, or invalidate live data.
 */
export function usePreflightImportBook() {
  return useMutation({
    mutationFn: ({ bytes, policy }: { bytes: ArrayBuffer; policy: CollisionPolicy }) =>
      api.preflightImportBook(bytes, policy),
  });
}

/**
 * Import a book bundle (`POST /v1/books/import`, t54). Verify-before-trust →
 * `Verified` (into the live instance) | `Quarantined` (isolated, read-only). Refetches
 * books + ledger on success (a Quarantined verdict is still a 200 success).
 */
export function useImportBook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ bytes, policy }: { bytes: ArrayBuffer; policy: CollisionPolicy }) =>
      api.importBook(bytes, policy),
    onSuccess: () => invalidateAfterRecovery(qc),
  });
}

/**
 * Per-book start-over (`POST /v1/books/{id}/start-over`, t54). Archives the old book +
 * chain, records `ledger.reinitialized`, and opens a fresh successor. Non-destructive
 * (the old events stay append-only); blocked with 503 while degraded.
 */
export function useStartOverBook(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: StartOverBookBody) => api.startOverBook(id, body),
    onSuccess: () => invalidateAfterRecovery(qc),
  });
}

/**
 * Destructive data-management wipe (`POST /v1/data/reset`, t54). `backend_domain`
 * preserves the ledger (chained `data.wiped`); `backend_factory` blanks everything.
 * Requires the exact confirm phrase + step-up re-auth + (mandatory) export-first.
 */
export function useResetData() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ResetDataBody) => api.resetData(body),
    onSuccess: () => invalidateAfterRecovery(qc),
  });
}

/**
 * Whole-instance start-over (`POST /v1/data/start-over`, t54). Archives the whole store
 * then re-seeds empty domain data (users/settings preserved). Confirm phrase `RECOMEÇAR`
 * + step-up re-auth.
 */
export function useStartOverInstance() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: StartOverInstanceBody) => api.startOverInstance(body),
    onSuccess: () => invalidateAfterRecovery(qc),
  });
}

export function useDashboard() {
  return useQuery({ queryKey: keys.dashboard, queryFn: () => api.dashboard() });
}

// --- CAE catalog + lookup (plan t14) --------------------------------------------

/**
 * The active CAE catalog metadata (`GET /v1/cae` without `search`): origin
 * (Embedded/Cache), generation stamp and per-revision node counts. Kept fresh for a
 * minute; a successful refresh invalidates it.
 */
export function useCaeCatalog() {
  return useQuery({
    queryKey: keys.caeCatalog,
    queryFn: () => api.getCaeCatalog(),
    staleTime: 60_000,
  });
}

/**
 * Search-as-you-type over the CAE catalog (`GET /v1/cae?search=`). Disabled for a
 * blank term (the server treats blank as "no search" and would return metadata, not an
 * array), and the previous results are kept visible while the next term loads.
 */
export function useCaeSearch(search: string, revision?: CaeRevision) {
  const term = search.trim();
  return useQuery({
    queryKey: keys.caeSearch(term, revision),
    queryFn: () => api.searchCae(term, { revision }),
    enabled: term.length > 0,
    placeholderData: (prev) => prev,
  });
}

/**
 * Resolve a single código (`GET /v1/cae/{code}?revision=`) to its designation, level,
 * revision and ancestor `hierarchy` (secção → … → self). Disabled for a blank code; a
 * `404` (unknown code) surfaces as an error the caller renders as "not found". Kept
 * fresh for a minute — a code's meaning only changes on a catalog refresh.
 */
export function useCae(code: string, revision?: CaeRevision) {
  const trimmed = code.trim();
  return useQuery({
    queryKey: keys.caeEntry(trimmed, revision),
    queryFn: () => api.getCae(trimmed, revision),
    enabled: trimmed.length > 0,
    staleTime: 60_000,
    retry: false,
  });
}

/** The largest child-search page the tree drill-down requests (the server caps at 500). */
export const CAE_CHILD_SEARCH_LIMIT = 500;

/**
 * Fetch the candidate pool for a node's direct children by searching its código
 * (`GET /v1/cae?search=<code>&revision=`), which the caller filters down to the exact
 * one-level-deeper prefix children. This backs the tree's downward drill for the
 * numeric levels (divisão→grupo→classe→subclasse), where children share the parent's
 * code prefix. Enumerating a secção's divisões (whose parent is a letter, not a code
 * prefix) is NOT prefix-derivable and needs a backend children endpoint — see the
 * explorer note; this hook is only enabled for the numeric levels.
 */
export function useCaeChildren(code: string, revision: CaeRevision, enabled: boolean) {
  const trimmed = code.trim();
  return useQuery({
    queryKey: keys.caeChildren(trimmed, revision),
    queryFn: () => api.searchCae(trimmed, { revision, limit: CAE_CHILD_SEARCH_LIMIT }),
    enabled: enabled && trimmed.length > 0,
    staleTime: 60_000,
    placeholderData: (prev) => prev,
  });
}

/**
 * Force a catalog refresh (`POST /v1/cae/refresh`). On a real update the catalog
 * metadata is invalidated so the counts/origin refresh; a same/older dataset is a
 * no-op (`updated:false`) and the page surfaces that distinctly.
 */
export function useRefreshCae() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.refreshCae(),
    onSuccess: (result) => {
      if (result.updated) {
        qc.setQueryData(keys.caeCatalog, result.metadata);
        void qc.invalidateQueries({ queryKey: ['cae'] });
        void qc.invalidateQueries({ queryKey: ['ledger'] });
      }
    },
  });
}

// --- TSL trust catalog ----------------------------------------------------------

export function useTrustStatus() {
  return useQuery({
    queryKey: keys.trustStatus,
    queryFn: () => api.getTrustStatus(),
    staleTime: 60_000,
  });
}

export function useTrustCatalog() {
  return useQuery({
    queryKey: keys.trustCatalog,
    queryFn: () => api.getTrustCatalog(),
    staleTime: 60_000,
  });
}

export function useRefreshTrustTsl() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: TslRefreshRequest = {}) => api.refreshTrustTsl(body),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: keys.trustStatus });
      void qc.invalidateQueries({ queryKey: keys.trustCatalog });
      void qc.invalidateQueries({ queryKey: keys.tsaCatalog });
      void qc.invalidateQueries({ queryKey: ['trust'] });
    },
  });
}

function normalizeTrustSearchParams(params: TslCatalogSearchParams): TslCatalogSearchParams {
  return {
    ...params,
    search: params.search?.trim() || undefined,
    identifier: params.identifier?.trim() || undefined,
  };
}

function hasTrustSearchParams(params: TslCatalogSearchParams): boolean {
  return (
    !!params.search ||
    !!params.identifier ||
    !!params.service_type ||
    !!params.status ||
    !!params.history ||
    !!params.supply_point
  );
}

export function useTrustCatalogSearch(params: TslCatalogSearchParams, enabled = true) {
  const normalized = normalizeTrustSearchParams(params);
  return useQuery({
    queryKey: keys.trustSearch(normalized),
    queryFn: () => api.searchTrustCatalog(normalized),
    enabled: enabled && hasTrustSearchParams(normalized),
    staleTime: 60_000,
  });
}

export function useTrustProvider(id: string) {
  const trimmed = id.trim();
  return useQuery({
    queryKey: keys.trustProvider(trimmed),
    queryFn: () => api.getTrustProvider(trimmed),
    enabled: trimmed.length > 0,
    staleTime: 60_000,
    retry: false,
  });
}

export function useTrustService(id: string) {
  const trimmed = id.trim();
  return useQuery({
    queryKey: keys.trustService(trimmed),
    queryFn: () => api.getTrustService(trimmed),
    enabled: trimmed.length > 0,
    staleTime: 60_000,
    retry: false,
  });
}

export function useTsaCatalog() {
  return useQuery({
    queryKey: keys.tsaCatalog,
    queryFn: () => api.getTsaCatalog(),
    staleTime: 60_000,
  });
}

export function useTsaCatalogSearch(params: TsaCatalogSearchParams, enabled = true) {
  const normalized = normalizeTrustSearchParams(params);
  return useQuery({
    queryKey: keys.tsaSearch(normalized),
    queryFn: () => api.searchTsaCatalog(normalized),
    enabled: enabled && hasTrustSearchParams(normalized),
    staleTime: 60_000,
  });
}

// --- Law archive (t27) — the local "mini law archive" ---------------------------

/**
 * The resolved state of the local law archive: either the feature is unavailable (the
 * running server predates t27) or it is available with a per-diploma-id lookup of the
 * manifest entries.
 */
export type LawArchiveState =
  { available: false } | { available: true; entries: Map<string, LawEntryView> };

/**
 * Load + normalize the `/v1/law` manifest into a {@link LawArchiveState}. A 404, a
 * non-JSON reply (an old server SPA-falls-back unknown routes to `index.html`), or any
 * transport error is swallowed to `{ available: false }` so the Legislação shelf degrades
 * gracefully to links-only rather than surfacing an error for an optional feature.
 */
async function loadLawArchive(): Promise<LawArchiveState> {
  try {
    const raw = await api.getLawManifest();
    const list = Array.isArray(raw) ? raw : (raw?.entries ?? []);
    return { available: true, entries: new Map(list.map((e) => [e.id, e])) };
  } catch {
    return { available: false };
  }
}

/** Feature-detected law-archive manifest; never errors (absent → `{ available:false }`). */
export function useLawArchive() {
  return useQuery({ queryKey: keys.lawManifest, queryFn: loadLawArchive, staleTime: 60_000 });
}

/**
 * Download + store a diploma's official PDF (`POST /v1/law/{id}/fetch`). On success the
 * manifest is invalidated so the card flips to its "stored" state (badge + local "Abrir
 * PDF").
 */
export function useFetchLawPdf() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.fetchLawPdf(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.lawManifest });
    },
  });
}

// --- Law corpus reader (t55-E2) — full-text statute reader ----------------------

/**
 * The embedded law corpus (`GET /v1/law/corpus`, t55): provenance/integrity metadata plus a
 * per-diploma summary (article/verified/pending counts). Read-only reference — the corpus is
 * immutable and compiled in, so it is kept fresh for a minute. Backs the reader's diploma
 * browser and the "origem/autenticidade" caveat.
 */
export function useLawCorpus() {
  return useQuery({
    queryKey: keys.lawCorpus,
    queryFn: () => api.getLawCorpus(),
    staleTime: 60_000,
  });
}

/**
 * One diploma with its full article set (`GET /v1/law/corpus/{diploma}`, t55). Enabled only
 * when a diploma is selected; a `404` (unknown diploma) surfaces as an error the caller renders
 * as "not found". Static reference data, kept fresh for a minute.
 */
export function useLawDiploma(diploma: string, enabled = true) {
  const id = diploma.trim();
  return useQuery({
    queryKey: keys.lawDiploma(id),
    queryFn: () => api.getLawDiploma(id),
    enabled: enabled && id.length > 0,
    staleTime: 60_000,
    retry: false,
  });
}

/**
 * Full-text corpus search (`GET /v1/law/corpus/search?q=`, t55). Disabled for a blank term (the
 * server returns an empty set for blank `q`, but there is no point round-tripping it), keeping
 * the previous results visible while the next term loads — the search-as-you-type idiom the CAE
 * explorer uses.
 */
export function useLawCorpusSearch(q: string, limit?: number) {
  const term = q.trim();
  return useQuery({
    queryKey: keys.lawSearch(term),
    queryFn: () => api.searchLawCorpus(term, limit),
    enabled: term.length > 0,
    placeholderData: (prev) => prev,
  });
}

/**
 * Normalize selected corpus article refs into draft/compliance citation metadata. This is a
 * read-only mutation because the request body carries an explicit bounded list of refs.
 */
export function useResolveLawCitations() {
  return useMutation({
    mutationFn: (body: LawCitationRequest) => api.resolveLawCitations(body),
  });
}

// --- Users + session (plan t14) -------------------------------------------------

export function useUsers() {
  return useQuery({ queryKey: keys.users, queryFn: () => api.listUsers() });
}

/**
 * A single user by id (`GET /v1/users/{id}`, t50 W2) — the edit screen's cold-deep-link
 * fallback: when a `/utilizadores/:id` URL is opened directly the list cache may be empty,
 * so the autonomous edit page resolves the user through this read. Sharing the `['users',
 * id]` key means a mutation that invalidates `keys.users` (create/toggle/secret/key) also
 * refetches an open detail view.
 */
export function useUser(id: string) {
  return useQuery({ queryKey: keys.user(id), queryFn: () => api.getUser(id), enabled: !!id });
}

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateUserBody) => api.createUser(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.users });
      // The unauth roster gates onboarding-vs-sign-in; creating a user (the first-run
      // bootstrap especially) flips `onboarding_required`, so the guard must refetch it.
      void qc.invalidateQueries({ queryKey: keys.roster });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/**
 * Set / change a user's sign-in secret (`POST /v1/users/{id}/secret`, t29). Changing an
 * existing secret requires `current_password` (verified server-side; 401 on mismatch)
 * and re-wraps any attestation key under the new secret. The updated `UserView`
 * (`has_secret:true`) primes the caches the sign-in roster and management panel read.
 */
export function useSetUserSecret(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: SetSecretBody) => api.setUserSecret(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.users });
      void qc.invalidateQueries({ queryKey: keys.roster });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/**
 * Remove a user's sign-in secret (`DELETE /v1/users/{id}/secret`, t29). Cascades: the
 * attestation key is destroyed with the secret (its KEK is gone). Requires the current
 * password when one is set (401 on mismatch).
 */
export function useRemoveUserSecret(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RemoveSecretBody) => api.removeUserSecret(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.users });
      void qc.invalidateQueries({ queryKey: keys.roster });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/**
 * Generate / rotate a user's PKI audit-attestation key (`POST /v1/users/{id}/attestation-key`,
 * t29). Requires a sign-in secret first (409 if none) and the current password (401 on
 * mismatch). Rotating replaces the key; prior attestations still verify (each carries its
 * own fingerprint).
 */
export function useCreateAttestationKey(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AttestationKeyBody) => api.createAttestationKey(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.users });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/** Remove a user's attestation key (`DELETE /v1/users/{id}/attestation-key`, t29). */
export function useRemoveAttestationKey(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AttestationKeyBody) => api.removeAttestationKey(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.users });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/**
 * Issue / rotate a user's one-time recovery phrase (`POST /v1/users/{id}/recovery`, t51).
 * Subject to the same cross-user proof rules as the secret ops (the target's current
 * password OR an existing recovery phrase; 403 on absent/wrong proof). The returned phrase
 * is shown ONCE by the caller and never persisted — this hook only invalidates the caches
 * so `has_recovery_phrase` flips to `true` (invalidating `keys.users` also refetches the
 * open `['users', id]` detail view). The plaintext phrase never enters any cache.
 */
export function useIssueRecovery(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: IssueRecoveryBody) => api.issueRecovery(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.users });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function useExportUserDsr(id: string) {
  return useMutation({ mutationFn: () => api.exportUserDsr(id) });
}

export function useUserDsrRequests(id: string) {
  return useQuery({
    queryKey: keys.userDsrRequests(id),
    queryFn: () => api.listUserDsrRequests(id),
    enabled: !!id,
    retry: false,
  });
}

export function useCreateUserDsrRequest(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateDsrRequestBody) => api.createUserDsrRequest(id, body),
    onSuccess: (created) => {
      qc.setQueryData<DsrRequestView[]>(keys.userDsrRequests(id), (current = []) => [
        ...current,
        created,
      ]);
      void qc.invalidateQueries({ queryKey: keys.userDsrRequests(id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function useCompleteUserDsrRequest(userId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (requestId: string) => api.completeUserDsrRequest(userId, requestId),
    onSuccess: (completed) => {
      qc.setQueryData<DsrRequestView[]>(keys.userDsrRequests(userId), (current = []) =>
        current.map((request) => (request.id === completed.id ? completed : request)),
      );
      void qc.invalidateQueries({ queryKey: keys.userDsrRequests(userId) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function useUpdateUser(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: UpdateUserBody) => api.updateUser(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.users });
      void qc.invalidateQueries({ queryKey: keys.session });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/**
 * The current session (`GET /v1/session`), read from the in-memory token. On a fresh
 * page load the token is gone (it is never persisted — see `./session`), so this
 * resolves to `{ user: null, permissions: [] }` until a user is picked; that is the
 * intended v1 behaviour. The picker keys its display off this query.
 *
 * This hook is always mounted at the app shell (via `CurrentUserPicker` in `layout`),
 * so it is the natural place to register the 401-clear listener: when the API client
 * drops a stale token on a 401, the session query is invalidated and refetches with
 * no token → `{ user: null }`, so the UI reflects the signed-out state immediately
 * instead of showing a stale signed-in user.
 */
export function useSession() {
  const qc = useQueryClient();
  useEffect(() => {
    return onSessionCleared(() => {
      qc.setQueryData(keys.session, { user: null, permissions: [] });
      void qc.invalidateQueries({ queryKey: keys.session });
    });
  }, [qc]);
  return useQuery({ queryKey: keys.session, queryFn: () => api.getSession() });
}

/**
 * The UNAUTHENTICATED sign-in roster (`GET /v1/session/roster`, t45-e1). Readable while
 * signed out (no session header, never 401s), so the auth guard and the sign-in surface
 * use it — NOT the auth-gated `GET /v1/users`, which 401s signed-out (the chicken-and-egg
 * lockout the t43 audit flagged). Kept fresh briefly; `useCreateUser`/`useSetUserSecret`
 * invalidate it when the roster changes.
 */
export function useSessionRoster() {
  return useQuery({
    queryKey: keys.roster,
    queryFn: () => api.getSessionRoster(),
    staleTime: 15_000,
    retry: false,
  });
}

/**
 * The unauthenticated password policy (`GET /v1/session/password-policy`, t68). Static for
 * a running server, cached long enough to keep the onboarding/users checklist stable.
 */
export function usePasswordPolicy() {
  return useQuery({
    queryKey: keys.passwordPolicy,
    queryFn: () => api.getPasswordPolicy(),
    staleTime: 5 * 60_000,
    retry: false,
  });
}

/** Arguments for {@link useCreateSession}: the user to sign in as and their password. */
export interface SignInArgs {
  userId: string;
  password: string;
}

/**
 * Sign in as a user (`POST /v1/session`, t29). The issued token is stored in memory so
 * every subsequent request carries it; the session query is primed with a full session
 * read so RBAC-gated UI has the effective permission grants immediately. A password is
 * always sent; a wrong/missing password is a **401**, a legacy account with no password
 * verifier is a **409**, and too many attempts a **429** (backoff) — the caller surfaces
 * those distinctly.
 */
export function useCreateSession() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ userId, password }: SignInArgs) =>
      api.createSession({ user_id: userId, password }),
    onSuccess: async (result) => {
      setSessionToken(result.token);
      qc.setQueryData(keys.session, await api.getSession());
      // Now signed in, the auth-gated user list becomes readable — refetch it so the
      // management page / picker have the full UserView set.
      void qc.invalidateQueries({ queryKey: keys.users });
    },
  });
}

/** Sign out (`DELETE /v1/session`); drops the token and clears the session query. */
export function useDeleteSession() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.deleteSession(),
    onSuccess: () => {
      clearSessionToken();
      qc.setQueryData(keys.session, { user: null, permissions: [] });
      void qc.invalidateQueries({ queryKey: keys.session });
    },
  });
}

// --- RBAC management (t64-E6) — roles, scoped assignment, scoped delegation -------

/**
 * The role catalog (`GET /v1/roles`, t64-E4). Any valid session may read it — it backs the
 * Funções list and the assign/delegation role pickers. Also drives the client-side subset
 * reflection (the server re-enforces regardless).
 */
export function useRoles() {
  return useQuery({ queryKey: keys.roles, queryFn: () => api.listRoles() });
}

/**
 * The frozen permission verb catalog (`GET /v1/permissions`, t64-E4) — the 37-verb set with
 * a `meta` flag per verb. Backs the permission-matrix editor. Static data, kept fresh long.
 */
export function usePermissionCatalog() {
  return useQuery({
    queryKey: keys.permissionCatalog,
    queryFn: () => api.listPermissions(),
    staleTime: 5 * 60_000,
  });
}

/**
 * The signed-in principal's fuller permission view (`GET /v1/session/permissions`, t64-E3):
 * identity + role assignments (with scopes) + effective grants. Used to seed the assignment
 * manager with the CURRENT user's own assignments (no read endpoint exists for another
 * user's assignments — the assign/unassign responses are authoritative there).
 */
export function useSessionPermissions() {
  return useQuery({
    queryKey: keys.sessionPermissions,
    queryFn: () => api.getSessionPermissions(),
  });
}

/** Create a custom role (`POST /v1/roles`, t64-E4). The server rejects a permission the actor
 *  lacks (subset invariant, 403). Refetches the role list + ledger on success. */
export function useCreateRole() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateRoleBody) => api.createRole(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.roles });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/** Rename / re-set a custom role's permissions (`PATCH /v1/roles/{id}`, t64-E4). A protected
 *  role refuses any edit (403); a resulting set outside the actor's own perms is refused
 *  (subset, 403). Refetches roles, the session embed (own grants may change) + ledger. */
export function usePatchRole(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: PatchRoleBody) => api.patchRole(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.roles });
      void qc.invalidateQueries({ queryKey: keys.session });
      void qc.invalidateQueries({ queryKey: keys.sessionPermissions });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/** Delete a non-protected custom role (`DELETE /v1/roles/{id}`, t64-E4). The protected Owner
 *  role is undeletable (403). Refetches the role list + ledger. */
export function useDeleteRole() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.deleteRole(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.roles });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/**
 * Assign a `(role, scope)` to a user (`POST /v1/users/{id}/roles`, t64-E4). Gated
 * `role.assign` at the scope + the subset invariant at that scope (server-enforced, 403). The
 * response is the user's UPDATED assignment list. Refetches the session embed (if assigning
 * to self, own grants change) + ledger.
 */
export function useAssignRole(userId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RoleAssignmentInput) => api.assignRole(userId, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.session });
      void qc.invalidateQueries({ queryKey: keys.sessionPermissions });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/**
 * Remove a `(role, scope)` assignment from a user (`DELETE /v1/users/{id}/roles`, t64-E4).
 * The last-Owner guard refuses removing the final Owner\@Global assignment (409 — surfaced as
 * an honest message). The response is the user's updated assignment list.
 */
export function useUnassignRole(userId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RoleAssignmentInput) => api.unassignRole(userId, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.session });
      void qc.invalidateQueries({ queryKey: keys.sessionPermissions });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/**
 * The delegations touching the caller (`GET /v1/delegations`, t64-E4): those they granted or
 * received (own), or all when they hold `delegation.revoke`. Backs the delegation panel's
 * active/expired/revoked view.
 */
export function useDelegations() {
  return useQuery({ queryKey: keys.delegations, queryFn: () => api.listDelegations() });
}

/**
 * Grant a scoped delegation (`POST /v1/delegations`, t64-E4). Only a permission the grantor
 * holds VIA A ROLE at the scope is delegable (meta verbs are non-delegable); the server 403s
 * otherwise. Refetches the delegation list + ledger.
 */
export function useGrantDelegation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: GrantDelegationBody) => api.grantDelegation(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.delegations });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/** Revoke a delegation (`DELETE /v1/delegations/{id}`, t64-E4). Allowed to the grantor or a
 *  `delegation.revoke` holder; revocation is immediate. Refetches the list + ledger. */
export function useRevokeDelegation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.revokeDelegation(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.delegations });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

// --- API-key management ---------------------------------------------------------

/** List non-secret API-key metadata. The one-time plaintext secret is never part of this query. */
export function useApiKeys() {
  return useQuery({ queryKey: keys.apiKeys, queryFn: () => api.listApiKeys() });
}

/**
 * Mint a new API key. The response contains the plaintext secret exactly once; this mutation
 * deliberately invalidates the metadata list rather than seeding it with the create payload.
 */
export function useCreateApiKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateApiKeyBody) => api.createApiKey(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.apiKeys });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/**
 * Rotate an API key's credential material. The plaintext replacement is returned once; keep it in
 * mutation-local UI state only, and refetch metadata instead of writing the secret-bearing result.
 */
export function useRotateApiKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.rotateApiKey(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.apiKeys });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/** Revoke an API key by id. The server returns updated metadata; refetch the list for ordering. */
export function useRevokeApiKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.revokeApiKey(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.apiKeys });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

// --- Privacy/compliance registers ----------------------------------------------

export function usePrivacyProcessors(enabled = true) {
  return useQuery({
    queryKey: keys.privacyProcessors,
    queryFn: () => api.listProcessorRecords(),
    enabled,
  });
}

export function useCreatePrivacyProcessor() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateProcessorRecordBody) => api.createProcessorRecord(body),
    onSuccess: (created) => {
      qc.setQueryData<ProcessorRecordView[]>(keys.privacyProcessors, (current = []) => [
        ...current,
        created,
      ]);
      void qc.invalidateQueries({ queryKey: keys.privacyProcessors });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function usePatchPrivacyProcessor() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: PatchProcessorRecordBody }) =>
      api.patchProcessorRecord(id, body),
    onSuccess: (updated) => {
      qc.setQueryData<ProcessorRecordView[]>(keys.privacyProcessors, (current = []) =>
        current.map((record) => (record.id === updated.id ? updated : record)),
      );
      void qc.invalidateQueries({ queryKey: keys.privacyProcessors });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function usePrivacyDpias(enabled = true) {
  return useQuery({
    queryKey: keys.privacyDpias,
    queryFn: () => api.listDpiaRecords(),
    enabled,
  });
}

export function useCreatePrivacyDpia() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateDpiaRecordBody) => api.createDpiaRecord(body),
    onSuccess: (created) => {
      qc.setQueryData<DpiaRecordView[]>(keys.privacyDpias, (current = []) => [...current, created]);
      void qc.invalidateQueries({ queryKey: keys.privacyDpias });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function usePatchPrivacyDpia() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: PatchDpiaRecordBody }) =>
      api.patchDpiaRecord(id, body),
    onSuccess: (updated) => {
      qc.setQueryData<DpiaRecordView[]>(keys.privacyDpias, (current = []) =>
        current.map((record) => (record.id === updated.id ? updated : record)),
      );
      void qc.invalidateQueries({ queryKey: keys.privacyDpias });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function usePrivacyBreachPlaybooks(enabled = true) {
  return useQuery({
    queryKey: keys.privacyBreachPlaybooks,
    queryFn: () => api.listBreachPlaybooks(),
    enabled,
  });
}

export function useCreatePrivacyBreachPlaybook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateBreachPlaybookBody) => api.createBreachPlaybook(body),
    onSuccess: (created) => {
      qc.setQueryData<BreachPlaybookView[]>(keys.privacyBreachPlaybooks, (current = []) => [
        ...current,
        created,
      ]);
      void qc.invalidateQueries({ queryKey: keys.privacyBreachPlaybooks });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function usePatchPrivacyBreachPlaybook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: PatchBreachPlaybookBody }) =>
      api.patchBreachPlaybook(id, body),
    onSuccess: (updated) => {
      qc.setQueryData<BreachPlaybookView[]>(keys.privacyBreachPlaybooks, (current = []) =>
        current.map((record) => (record.id === updated.id ? updated : record)),
      );
      void qc.invalidateQueries({ queryKey: keys.privacyBreachPlaybooks });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function usePrivacyTransferControls(enabled = true) {
  return useQuery({
    queryKey: keys.privacyTransferControls,
    queryFn: () => api.listTransferControls(),
    enabled,
  });
}

export function useCreatePrivacyTransferControl() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateTransferControlBody) => api.createTransferControl(body),
    onSuccess: (created) => {
      qc.setQueryData<TransferControlView[]>(keys.privacyTransferControls, (current = []) => [
        ...current,
        created,
      ]);
      void qc.invalidateQueries({ queryKey: keys.privacyTransferControls });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function usePatchPrivacyTransferControl() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: PatchTransferControlBody }) =>
      api.patchTransferControl(id, body),
    onSuccess: (updated) => {
      qc.setQueryData<TransferControlView[]>(keys.privacyTransferControls, (current = []) =>
        current.map((record) => (record.id === updated.id ? updated : record)),
      );
      void qc.invalidateQueries({ queryKey: keys.privacyTransferControls });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function usePrivacyRetentionPolicies(enabled = true) {
  return useQuery({
    queryKey: keys.privacyRetentionPolicies,
    queryFn: () => api.listRetentionPolicies(),
    enabled,
  });
}

export function usePrivacyRetentionExecutions(
  status: RetentionExecutionStatus | 'all' = 'all',
  enabled = true,
) {
  return useQuery({
    queryKey: keys.privacyRetentionExecutions(status),
    queryFn: () => api.listRetentionExecutions(status === 'all' ? undefined : status),
    enabled,
  });
}

export function usePrivacyRetentionDueCandidates(enabled = true) {
  return useQuery({
    queryKey: keys.privacyRetentionDueCandidates,
    queryFn: () => api.listRetentionDueCandidates(),
    enabled,
  });
}

export function useClosePrivacyRetentionExecutionReview() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: CloseRetentionExecutionReviewBody }) =>
      api.closeRetentionExecutionReview(id, body),
    onSuccess: (updated) => {
      qc.setQueriesData<RetentionExecutionRecord[]>(
        { queryKey: ['privacy', 'retention-executions'] },
        (current) => current?.map((record) => (record.id === updated.id ? updated : record)),
      );
      void qc.invalidateQueries({ queryKey: ['privacy', 'retention-executions'] });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function useCreatePrivacyRetentionPolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateRetentionPolicyBody) => api.createRetentionPolicy(body),
    onSuccess: (created) => {
      qc.setQueryData<RetentionPolicyView[]>(keys.privacyRetentionPolicies, (current = []) => [
        ...current,
        created,
      ]);
      void qc.invalidateQueries({ queryKey: keys.privacyRetentionPolicies });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function usePatchPrivacyRetentionPolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: PatchRetentionPolicyBody }) =>
      api.patchRetentionPolicy(id, body),
    onSuccess: (updated) => {
      qc.setQueryData<RetentionPolicyView[]>(keys.privacyRetentionPolicies, (current = []) =>
        current.map((record) => (record.id === updated.id ? updated : record)),
      );
      void qc.invalidateQueries({ queryKey: keys.privacyRetentionPolicies });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function useDryRunPrivacyRetentionPolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RetentionDryRunBody) => api.dryRunRetentionPolicy(body),
    onSuccess: (report) => {
      if (!report.execution_record) return;
      void qc.invalidateQueries({ queryKey: keys.privacyRetentionDueCandidates });
      void qc.invalidateQueries({ queryKey: ['privacy', 'retention-executions'] });
    },
  });
}

// --- Settings / Health ----------------------------------------------------------

/**
 * The application settings document (§2.8), loaded once at app start and shared by
 * every consumer (the appearance layer, the Configurações page, the actor/numbering
 * pre-fills). Settings rarely change, so the cache is kept fresh for a minute.
 */
export function useSettings() {
  return useQuery({
    queryKey: keys.settings,
    queryFn: () => api.getSettings(),
    staleTime: 60_000,
  });
}

/**
 * Persist the whole settings document. Optimistic: the cache is updated with the
 * outgoing document immediately (so the live appearance layer reacts without waiting
 * for the round-trip), rolled back on error, and reconciled with the server's echoed
 * document (which stamps `schema_version`) on settle.
 */
export function useUpdateSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Settings) => api.putSettings(body),
    onMutate: async (next) => {
      await qc.cancelQueries({ queryKey: keys.settings });
      const previous = qc.getQueryData<Settings>(keys.settings);
      qc.setQueryData(keys.settings, next);
      return { previous };
    },
    onError: (_err, _next, context) => {
      if (context?.previous) qc.setQueryData(keys.settings, context.previous);
    },
    onSuccess: (stored) => {
      qc.setQueryData(keys.settings, stored);
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: keys.settings });
    },
  });
}

/** Platform services status (`GET /v1/platform/services`): desired state, observed runtime,
 * logging level and the backend's honest control limitations for API + MCP stdio. */
export function usePlatformServices() {
  return useQuery({
    queryKey: keys.platformServices,
    queryFn: () => api.listPlatformServices(),
    staleTime: 15_000,
    retry: false,
  });
}

/** Platform log tail (`GET /v1/platform/logs`): API-owned structured entries
 * returned from the bounded tail after optional service/level filters. */
export function usePlatformLogs(params: PlatformLogsQueryParams) {
  return useQuery({
    queryKey: keys.platformLogs(params),
    queryFn: () => api.listPlatformLogs(params),
    staleTime: 5_000,
    retry: false,
  });
}

/** Record a desired lifecycle action for a platform service. The API deliberately does not
 * spawn/kill processes; a successful response means settings/audit were updated. */
export function useControlPlatformService() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      action,
    }: {
      id: PlatformControllableServiceId;
      action: PlatformServiceAction;
    }) => api.controlPlatformService(id, action),
    onSuccess: (response) => {
      qc.setQueryData(keys.platformServices, (current: unknown) => {
        if (
          !current ||
          typeof current !== 'object' ||
          !Array.isArray((current as { services?: unknown }).services)
        ) {
          return current;
        }
        return {
          ...(current as object),
          services: (current as { services: unknown[] }).services.map((service) =>
            service &&
            typeof service === 'object' &&
            (service as { id?: unknown }).id === response.service.id
              ? response.service
              : service,
          ),
        };
      });
      void qc.invalidateQueries({ queryKey: keys.platformServices });
      void qc.invalidateQueries({ queryKey: ['platform', 'logs'] });
      void qc.invalidateQueries({ queryKey: keys.settings });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/** Liveness + running server version, for the Configurações “Sobre” section. */
export function useHealth() {
  return useQuery({ queryKey: keys.health, queryFn: () => api.health(), staleTime: 60_000 });
}

/**
 * Poll `/health` for the server-driven degraded signal (t54). Shares the `keys.health`
 * cache with {@link useHealth} but re-fetches on an interval so the read-only degraded
 * banner appears/clears without a manual reload. Deliberately never retries into a spin
 * and stays quiet on transport failure (an unreachable server is not a degraded chain).
 */
export function useDegradedHealth() {
  return useQuery({
    queryKey: keys.health,
    queryFn: () => api.health(),
    refetchInterval: 20_000,
    refetchOnWindowFocus: true,
    retry: false,
  });
}
