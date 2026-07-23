/**
 * Typed `fetch` wrappers for the Chancela API (plan t5 §2).
 *
 * By default, every path stays relative (`/v1/...`, `/health`) so the same client
 * works in the Vite dev proxy, the same-origin production server, and the Tauri
 * desktop WebView. Mobile shells or deployments can opt into an absolute API base
 * URL through the central resolver. Errors are surfaced as `ApiError`, which carries the
 * HTTP status plus the optional `issues`/`warnings` arrays some endpoints add to the
 * base `{ "error": "..." }` body (compliance/seal per §2.5).
 */
import type {
  ActView,
  ActBodyPreviewResponse,
  PreviewActBody,
  AdvanceActBody,
  RevertActBody,
  ReopenActBody,
  ReopenActResponse,
  CaeCatalogView,
  CaeEntryView,
  CaeNode,
  CaeRefreshResult,
  CaeRevision,
  CaeUpdates,
  TslCatalogView,
  TslCatalogSearchParams,
  TslProviderDetailView,
  TslRefreshRequest,
  TslRefreshStatusView,
  TslServiceDetailView,
  TslServiceSummaryView,
  TslSummaryView,
  TsaCatalogView,
  TsaCatalogSearchParams,
  TsaRecordView,
  CloseBookBody,
  CloseRetentionExecutionReviewBody,
  ComplianceIssue,
  ComplianceReport,
  CompleteFollowUpBody,
  BreachPlaybookView,
  CreateBreachPlaybookBody,
  CreateDsrRequestBody,
  CreateDpiaRecordBody,
  CreateEntityBody,
  CreateFollowUpBody,
  CreateProcessorRecordBody,
  CreateRetentionPolicyBody,
  CreateSessionBody,
  CreateUserBody,
  Dashboard,
  DataCleanupBody,
  DataCleanupResult,
  DataKeyRotationExecuteBody,
  DataKeyRotationExecution,
  DataKeyRotationPreflight,
  DataKeyRotationPreflightBody,
  DataStatusResponse,
  NotificationTriageResponse,
  NotificationTriageUpdateBody,
  NotificationTriageUpdateResponse,
  DocumentBundle,
  DispatchActConveningBody,
  GeneratedDocumentDispatchEvidenceList,
  GeneratedDocumentDispatchEvidenceRequest,
  GeneratedDocumentDispatchEvidenceResponse,
  GeneratedDocumentView,
  ImportedDocumentView,
  ImportedDocumentReviewBody,
  ImportDocumentBody,
  DocumentModel,
  DraftActBody,
  DpiaRecordView,
  DpiaTemplateView,
  DsrRequestView,
  Entity,
  EntityChronologyView,
  EntityFamily,
  LifecycleStage,
  TemplateImportVerdict,
  TemplateSummary,
  ImportFromRegistryBody,
  LawEntryView,
  LawCorpusView,
  LawDiplomaDetailView,
  LawArticleView,
  LawCitationRequest,
  LawCitationReport,
  LawSearchView,
  FollowUpView,
  BookImportPreflightView,
  LedgerArchiveDocumentParams,
  LedgerEventsPage,
  LedgerEventView,
  LedgerQueryParams,
  LedgerVerify,
  LocalDglabInterchangeManifest,
  OpenBookBody,
  TermoInstrumentView,
  PatchTermoAberturaBody,
  SignTermoSlotBody,
  SignTermoSlotPkcs12Body,
  OpenBookFromTermoBody,
  PatchTermoEncerramentoBody,
  CloseBookFromTermoBody,
  PaperBookImportReport,
  PaperBookImportPreservationReport,
  PaperBookImportPreserveBody,
  PaperBookImportView,
  PaperBookImportValidateBody,
  PaperBookOcrCanonicalRehearsalReport,
  PaperBookOcrConversionDossierView,
  PaperBookOcrDraftCanonicalDraftResponse,
  PaperBookOcrDraftCreateBody,
  PaperBookOcrDraftReviewBody,
  PaperBookOcrDraftView,
  PaperBookOcrRunView,
  PaperBookOcrStatusUpdateBody,
  PaperBookOcrStatusView,
  PdfSignatureValidationBody,
  PdfSignatureValidationResponse,
  AsicSignatureInspectionBody,
  AsicSignatureInspectionResponse,
  PlatformControllableServiceId,
  PlatformControlResponse,
  PlatformLogsQueryParams,
  PlatformLogsResponse,
  PlatformServiceAction,
  PlatformServicesResponse,
  ServerEnvResponse,
  ServerEnvUpdateRequest,
  RegistryExtractView,
  RegistryAutoUpdateAttemptBody,
  RegistryAutoUpdateAttemptView,
  RegistryAutoUpdateDuePlan,
  RegistryImportBody,
  RegistryImportReport,
  RegistryLookupBody,
  SealActBody,
  SealResult,
  PatchBreachPlaybookBody,
  PatchFollowUpBody,
  PatchDpiaRecordBody,
  PatchProcessorRecordBody,
  PatchRetentionPolicyBody,
  RetentionCandidateResolutionBody,
  RetentionCandidateResolutionRecord,
  RetentionDryRunBody,
  RetentionDueCandidatesReport,
  RetentionDryRunReport,
  RetentionExecutionRecord,
  RetentionExecutionStatus,
  RetentionPolicyView,
  SignatureStatusView,
  CmdInitiateBody,
  CmdInitiateResult,
  CmdConfirmBody,
  CmdConfirmResult,
  CcSignBody,
  CcSignResult,
  CcBatchSignBody,
  CcBatchSignResponse,
  LocalPkcs12SignBody,
  LocalPkcs12SignResult,
  OfficialSignatureImportBody,
  OfficialSignatureImportResult,
  XadesSignBody,
  XadesSignResponse,
  AsicSignBody,
  AsicSignResponse,
  ScapProvidersBody,
  ScapProvidersResponse,
  ScapAttributesBody,
  ScapAttributesResponse,
  ScapSignBody,
  ScapSignResponse,
  CreateExternalSignerInviteBody,
  CreateExternalSignerInviteResult,
  CreateExternalSigningEnvelopeBody,
  ExternalSignerInviteDecision,
  ExternalSignerInvitePublicView,
  ExternalSignerInviteRespondOptions,
  ExternalSignerInviteView,
  ExternalSigningEnvelopeView,
  UpdateExternalSigningEnvelopeBody,
  ExternalValidatorReportUploadRequest,
  ExternalValidatorReportsResponse,
  ExternalValidatorReportUploadResponse,
  SignatureProviderView,
  RemoteBatchInitiateBody,
  RemoteBatchInitiateResponse,
  RemoteInitiateBody,
  RemoteInitiateResult,
  RemoteConfirmBody,
  RemoteConfirmResult,
  UpdateEntityBody,
  SessionResult,
  CreateSessionOutcome,
  CompleteChallengeBody,
  SessionRoster,
  SessionView,
  PasswordPolicyView,
  ProcessorRecordView,
  CreateTransferControlBody,
  PatchTransferControlBody,
  TransferControlView,
  SetSecretBody,
  RemoveSecretBody,
  AttestationKeyBody,
  IssueRecoveryBody,
  RecoveryIssued,
  TwoFactorStatus,
  TotpEnrolment,
  TotpConfirmBody,
  BackupCodes,
  SessionListResponse,
  RevokedResponse,
  Settings,
  UserPreferences,
  EmailStatusView,
  EmailTestResult,
  UpdateActBody,
  UpdateUserBody,
  UserView,
  VerifyAiHumanReviewBody,
  RoleView,
  SeededRoleReconciliationView,
  PermissionCatalogView,
  CreateRoleBody,
  PatchRoleBody,
  RoleAssignmentInput,
  RoleAssignmentView,
  ApiKeyCreated,
  ApiKeyRotated,
  ApiKeyView,
  CreateApiKeyBody,
  MintPairingCodeBody,
  PairingCodeMinted,
  PairingDevices,
  CredentialMode,
  ProviderCredentialsListView,
  ProviderCredentialEntryMutationResponse,
  ProviderCredentialEntryListResponse,
  CreateProviderCredentialEntryBody,
  UpdateProviderCredentialEntryBody,
  ReorderProviderCredentialEntriesBody,
  SignStoredPkcs12Body,
  SessionPermissions,
  DelegationView,
  GrantDelegationBody,
  BookView,
  BookArchivePackageParams,
  BookLegalHoldView,
  ClearBookLegalHoldBody,
  HealthResponse,
  IntegrityReportView,
  ReanchorBody,
  ReanchorResult,
  RestoreBody,
  RestoreOutcomeView,
  RestorePreflightBody,
  RestorePreflightView,
  BackupRecoveryDrillBody,
  BackupRecoveryDrillList,
  BackupRecoveryDrillReceipt,
  BackupManifest,
  SyncHandoffPreflightReport,
  ImportOutcomeView,
  CollisionPolicy,
  StartOverBookBody,
  StartOverBookResult,
  ResetDataBody,
  ResetOutcomeView,
  StartOverInstanceBody,
  StartOverInstanceView,
  SetBookLegalHoldBody,
  UserDsrExport,
  AppendGroupTemplateLibraryRevisionBody,
  CompanyGroupView,
  ConnectorJobListView,
  ConnectorJobView,
  ConnectorProbeView,
  ConnectorTargetView,
  CreateCompanyGroupBody,
  CreateConnectorTargetBody,
  CreateGroupTemplateLibraryBody,
  CreateRepositoryBody,
  GroupDashboardView,
  GroupTemplateLibraryRevision,
  GroupTemplateLibraryView,
  ListConnectorJobsParams,
  OpaqueBlobManifest,
  PatchCompanyGroupBody,
  PatchConnectorTargetBody,
  PatchGroupTemplateLibraryBody,
  PatchRepositoryBody,
  PendingZkUploadView,
  PutTenantRepositoryPolicyBody,
  ReadabilityPackageBody,
  RunConnectorTargetBody,
  StoredRepositoryPolicy,
  TenantRepositoryPolicy,
  TenantRepositoryPolicyView,
  ZkObjectVersionView,
  ZkStorageStatus,
} from './types';
import { clearSessionToken, getSessionToken } from './session';
import { resolveApiUrl } from './baseUrl';
import { t } from '../i18n';

/** The header that carries the current-user session token (plan t14 §2.8). */
export const SESSION_HEADER = 'X-Chancela-Session';

/** Shape of an error response body; `issues`/`warnings`/`pin_status` are endpoint-specific. */
interface ApiErrorBody {
  error?: string;
  code?: string;
  field?: string;
  message?: string;
  issues?: ComplianceIssue[];
  warnings?: ComplianceIssue[];
  /** In-app CC PIN rejection (t67): `"wrong_pin"`/`"blocked"`. Never carries the PIN. */
  pin_status?: string;
  /** Coarse remaining-attempt hint (`"low"`/`"final_try"`/`"locked"`/`"unknown"`). */
  tries_left?: string;
  /**
   * Byte offset into an ata body source of the construct a `422 InvalidActBody` rejected (t74).
   * A **byte** offset (UTF-8), not a character index — the body editor converts it before
   * underlining. Absent unless the error is a rejected markdown body.
   */
  offset?: number;
}

/**
 * Endpoints whose 401 means "the credential proof you supplied is wrong or missing", NOT
 * "your session is dead": the secret, attestation-key and recovery-phrase endpoints all
 * verify the target's CURRENT password (`verify_current`) and answer a bad proof with
 * `401 palavra-passe atual incorreta`. Signing the operator out on those would mean a typo
 * in the current-password field ejects them from the whole app.
 *
 * The TOTP **confirm** endpoint (t103/t107) belongs here for the same reason: it answers a wrong
 * six-digit activation code with `401`, and a mistyped code during enrolment must not eject the
 * operator from the app. Only `confirm` verifies a code — enrol/disable/backup-codes do not —
 * so the pattern names it specifically rather than matching the whole `two-factor` subtree.
 *
 * `POST /v1/session/challenge` (t95 P2, two-step sign-in) belongs here too: a wrong TOTP/backup code
 * is a rejected credential proof, not a dead session. It matters most for the in-session account
 * switcher, where a token already exists — a mistyped challenge code must reject inline, never sign
 * the operator out of their current session. From the signed-out sign-in path the token store is
 * empty and clearing would be a harmless no-op; tagging it keeps both paths on the inline-reject rule.
 */
const CREDENTIAL_PROOF_PATH =
  /\/v1\/(users\/[^/]+\/(secret|attestation-key|recovery|two-factor\/totp\/confirm)|session\/challenge)(\?|$)/;

/** Whether a 401 on `path` is a rejected credential proof rather than an expired session. */
export function isCredentialProofPath(path: string | undefined): boolean {
  return path !== undefined && CREDENTIAL_PROOF_PATH.test(path);
}

/**
 * The shared 401 rule for every helper below: clear the stale token for an ordinary 401, but
 * leave the session alone when the 401 came from a credential-proof path. Returns whether this
 * was such a refusal so the caller can tag the `ApiError` for inline, field-level handling.
 */
function handleUnauthorized(res: Response, path: string): boolean {
  if (res.status !== 401) return false;
  if (isCredentialProofPath(path)) return true;
  clearSessionToken();
  return false;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly field?: string;
  readonly issues?: ComplianceIssue[];
  readonly warnings?: ComplianceIssue[];
  /**
   * A 401 that rejected a supplied credential proof (wrong/missing current password or recovery
   * phrase) rather than an expired session. The session token is deliberately NOT cleared for
   * these, and callers render them as a field-level refusal next to the proof input.
   */
  readonly credentialProof: boolean;
  /**
   * Structured in-app Cartão de Cidadão PIN-rejection fields (t67-e8's `422 PinRejected`). Both are
   * PIN-free: `pinStatus` is `"wrong_pin"`/`"blocked"`, `triesLeft` a coarse hint. Absent on every
   * non-PIN error, so callers must feature-detect before rendering PIN-specific copy.
   */
  readonly pinStatus?: string;
  readonly triesLeft?: string;
  /**
   * Byte offset of the construct a rejected ata body (`422 InvalidActBody`, t74) refused, when the
   * error carries one. Paired with `code` (`unsupported_markdown`/`invalid_placeholder`/…) so the
   * body editor can underline the offending byte in place. Absent on every non-body error.
   */
  readonly offset?: number;

  constructor(status: number, body: ApiErrorBody, credentialProof = false) {
    super(body.error || body.message || t('error.requestFailed', { status }));
    this.name = 'ApiError';
    this.status = status;
    this.credentialProof = credentialProof;
    this.code = body.code;
    this.field = body.field;
    this.issues = body.issues;
    this.warnings = body.warnings;
    this.pinStatus = body.pin_status;
    this.triesLeft = body.tries_left;
    this.offset = body.offset;
  }
}

/** A non-JSON text export plus the original download metadata. */
export interface TextDownload {
  text: string;
  blob: Blob;
  contentType: string;
  headers: Headers;
}

export type ActDocumentWorkingCopyFormat = 'markdown' | 'txt' | 'html' | 'rtf' | 'odt';

/** The path a response came back on, for diagnostics; empty when the URL is unavailable. */
function responsePath(res: Response, path?: string): string {
  if (path) return path;
  try {
    return new URL(res.url).pathname;
  } catch {
    return res.url || '';
  }
}

/**
 * Parse a `Response` into JSON, throwing `ApiError` on non-2xx. Exposed for unit
 * testing the parse/error path against a mocked `fetch`. `204 No Content` and empty
 * bodies resolve to `undefined`. `path` (when known) is woven into diagnostics.
 *
 * Guards the `Content-Type` before parsing: a non-JSON body (typically the SPA's
 * `index.html`, served when a route the running server does not know falls through to the
 * app shell) becomes a clear typed error instead of an opaque `JSON.parse` "Unexpected
 * token '<'". That condition almost always means the server binary is older than this UI.
 */
export async function parseResponse<T>(res: Response, path?: string): Promise<T> {
  // Tag a rejected credential proof so callers can show it inline instead of treating it as
  // a dead session (the token is left intact for these — see `handleUnauthorized`).
  const proof = res.status === 401 && isCredentialProofPath(path);
  const text = await res.text();
  if (!text) {
    // Empty body (e.g. 204): nothing to parse. A non-2xx empty body still errors.
    if (!res.ok) {
      throw new ApiError(
        res.status,
        { error: t('error.requestFailed', { status: res.status }) },
        proof,
      );
    }
    return undefined as T;
  }

  const contentType = res.headers.get('content-type') ?? '';
  if (!contentType.includes('application/json')) {
    const looksHtml = contentType.includes('text/html') || text.trimStart().startsWith('<');
    const where = responsePath(res, path);
    const suffix = where ? t('error.pathSuffix', { path: where }) : '';
    const detail = looksHtml
      ? t('error.detail.html')
      : t('error.detail.type', { contentType: contentType || t('error.detail.unknownType') });
    throw new ApiError(
      res.status,
      { error: t('error.unexpectedResponse', { detail, suffix, status: res.status }) },
      proof,
    );
  }

  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    const where = responsePath(res, path);
    const suffix = where ? t('error.pathSuffix', { path: where }) : '';
    throw new ApiError(
      res.status,
      { error: t('error.invalidJson', { suffix, status: res.status }) },
      proof,
    );
  }

  if (!res.ok) {
    const body: ApiErrorBody =
      data && typeof data === 'object' && 'error' in data
        ? (data as ApiErrorBody)
        : { error: t('error.requestFailed', { status: res.status }) };
    throw new ApiError(res.status, body, proof);
  }
  return data as T;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  // Attach the current-user session token (when signed in) so the server attributes
  // the ledger actor. Absent when signed out → the system ("api") actor, unchanged.
  const token = getSessionToken();
  // Caller headers FIRST, then the security-critical ones LAST, so a caller cannot
  // overwrite the session token or content-type (L-4: header spread order).
  const headers: Record<string, string> = {
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (token) headers[SESSION_HEADER] = token;
  if (init?.body) headers['Content-Type'] = 'application/json';
  const res = await fetch(resolveApiUrl(path), { ...init, headers });
  // A 401 usually means the server no longer recognises the token (revoked, idle-expired, or past
  // its absolute lifetime cap): clear the stale token and notify listeners so the session
  // query refetches and the UI reflects the signed-out state (L-1). A credential-proof path
  // is the exception — there the 401 is about the submitted proof, not the session.
  handleUnauthorized(res, path);
  return parseResponse<T>(res, path);
}

const get = <T>(path: string) => request<T>(path);
const post = <T>(path: string, body?: unknown) =>
  request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) });
const postRawJsonText = <T>(path: string, rawJson: string) =>
  request<T>(path, {
    method: 'POST',
    body: rawJson,
    headers: { 'Content-Type': 'application/json' },
  });
const putRawJsonText = <T>(path: string, rawJson: string) =>
  request<T>(path, {
    method: 'PUT',
    body: rawJson,
    headers: { 'Content-Type': 'application/json' },
  });
const patch = <T>(path: string, body: unknown) =>
  request<T>(path, { method: 'PATCH', body: JSON.stringify(body) });
const put = <T>(path: string, body: unknown) =>
  request<T>(path, { method: 'PUT', body: JSON.stringify(body) });
const del = <T>(path: string, body?: unknown) =>
  request<T>(path, {
    method: 'DELETE',
    body: body === undefined ? undefined : JSON.stringify(body),
  });

/**
 * Fetch a binary body (e.g. a generated PDF) as a `Blob`, attaching the session token
 * exactly like {@link request} and clearing a stale token on 401. A non-2xx status is
 * surfaced as an `ApiError` (its friendly `{error}` body parsed when the server sent
 * JSON — e.g. the 404-until-sealed case), so callers get the same error idiom as the
 * JSON path. Used for the document download, which must not go through JSON parsing.
 */
export async function fetchBlob(path: string): Promise<Blob> {
  const token = getSessionToken();
  const headers: Record<string, string> = {};
  if (token) headers[SESSION_HEADER] = token;
  const res = await fetch(resolveApiUrl(path), { headers });
  const credentialProof = handleUnauthorized(res, path);
  if (!res.ok) {
    let message = t('error.requestFailed', { status: res.status });
    try {
      const body = (await res.json()) as { error?: string };
      if (body?.error) message = body.error;
    } catch {
      // Non-JSON error body — keep the generic status message.
    }
    throw new ApiError(res.status, { error: message }, credentialProof);
  }
  return res.blob();
}

/**
 * Fetch a binary body as an `ArrayBuffer`, attaching the session token exactly like
 * {@link fetchBlob}. Reads the bytes straight off the `Response` (not via `Blob.arrayBuffer`, which
 * jsdom does not implement) so callers that need the raw bytes — e.g. base64-encoding the act's
 * PDF/A for the local XAdES/ASiC/SCAP tools — work in both the browser and tests.
 */
export async function fetchArrayBuffer(path: string): Promise<ArrayBuffer> {
  const token = getSessionToken();
  const headers: Record<string, string> = {};
  if (token) headers[SESSION_HEADER] = token;
  const res = await fetch(resolveApiUrl(path), { headers });
  const credentialProof = handleUnauthorized(res, path);
  if (!res.ok) {
    let message = t('error.requestFailed', { status: res.status });
    try {
      const body = (await res.json()) as { error?: string };
      if (body?.error) message = body.error;
    } catch {
      // Non-JSON error body — keep the generic status message.
    }
    throw new ApiError(res.status, { error: message }, credentialProof);
  }
  return res.arrayBuffer();
}

/**
 * Fetch a textual download without routing it through JSON parsing or PDF-specific
 * helpers. Returns both text and Blob forms, preserving
 * the response content type/header metadata for callers that save the file.
 */
export async function fetchTextDownload(path: string): Promise<TextDownload> {
  const token = getSessionToken();
  const headers: Record<string, string> = {};
  if (token) headers[SESSION_HEADER] = token;
  const res = await fetch(resolveApiUrl(path), { headers });
  const credentialProof = handleUnauthorized(res, path);
  if (!res.ok) {
    let message = t('error.requestFailed', { status: res.status });
    try {
      const body = (await res.json()) as { error?: string };
      if (body?.error) message = body.error;
    } catch {
      // Non-JSON error body — keep the generic status message.
    }
    throw new ApiError(res.status, { error: message }, credentialProof);
  }
  const contentType = res.headers.get('Content-Type') ?? '';
  const text = await res.clone().text();
  const blob = await res.blob();
  return { text, blob, contentType, headers: res.headers };
}

/**
 * Fetch a textual download via POST with a JSON body. Used by public token-gated downloads whose
 * token must stay in the request body rather than a path or query string.
 */
export async function postTextDownload(path: string, body: unknown): Promise<TextDownload> {
  const token = getSessionToken();
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) headers[SESSION_HEADER] = token;
  const res = await fetch(resolveApiUrl(path), {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  const credentialProof = handleUnauthorized(res, path);
  if (!res.ok) {
    let message = t('error.requestFailed', { status: res.status });
    try {
      const parsed = (await res.json()) as { error?: string };
      if (parsed?.error) message = parsed.error;
    } catch {
      // Non-JSON error body — keep the generic status message.
    }
    throw new ApiError(res.status, { error: message }, credentialProof);
  }
  const contentType = res.headers.get('Content-Type') ?? '';
  const text = await res.clone().text();
  const blob = await res.blob();
  return { text, blob, contentType, headers: res.headers };
}

/**
 * Fetch a binary body via a non-GET method (e.g. the book-export `.zip`, produced by a
 * `POST`). Mirrors {@link fetchBlob}: attaches the session token, clears a stale token on
 * 401, and surfaces a non-2xx as an `ApiError` (parsing the friendly `{error}` body when
 * the server sent JSON). Returns the `Blob` plus the response headers so a caller can read
 * the retained export path / bundle digest the server rides in `X-Chancela-*` headers.
 */
export async function fetchBlobVia(
  path: string,
  method: string,
): Promise<{ blob: Blob; headers: Headers }> {
  const token = getSessionToken();
  const headers: Record<string, string> = {};
  if (token) headers[SESSION_HEADER] = token;
  const res = await fetch(resolveApiUrl(path), { method, headers });
  const credentialProof = handleUnauthorized(res, path);
  if (!res.ok) {
    let message = t('error.requestFailed', { status: res.status });
    try {
      const body = (await res.json()) as { error?: string };
      if (body?.error) message = body.error;
    } catch {
      // Non-JSON error body — keep the generic status message.
    }
    throw new ApiError(res.status, { error: message }, credentialProof);
  }
  return { blob: await res.blob(), headers: res.headers };
}

/**
 * POST raw (non-JSON) bytes and parse a JSON response. The book-import endpoint takes the
 * bundle `.zip` bytes directly as the request body — NOT `application/json` — so it needs
 * its own path that does not stamp the JSON content-type `request` sets on a body.
 */
export async function postBytes<T>(path: string, bytes: ArrayBuffer | Blob): Promise<T> {
  const token = getSessionToken();
  const headers: Record<string, string> = { 'Content-Type': 'application/zip' };
  if (token) headers[SESSION_HEADER] = token;
  const res = await fetch(resolveApiUrl(path), { method: 'POST', headers, body: bytes });
  handleUnauthorized(res, path);
  return parseResponse<T>(res, path);
}

/** PUT opaque bytes and parse the endpoint's JSON response without ever JSON-encoding the bytes. */
export async function putOpaqueBytes<T>(path: string, bytes: ArrayBuffer | Blob): Promise<T> {
  const token = getSessionToken();
  const headers: Record<string, string> = { 'Content-Type': 'application/octet-stream' };
  if (token) headers[SESSION_HEADER] = token;
  const res = await fetch(resolveApiUrl(path), { method: 'PUT', headers, body: bytes });
  handleUnauthorized(res, path);
  return parseResponse<T>(res, path);
}

/** POST JSON and return an attachment body plus response headers. */
export async function postJsonBlob(
  path: string,
  body: unknown,
): Promise<{ blob: Blob; headers: Headers }> {
  const token = getSessionToken();
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) headers[SESSION_HEADER] = token;
  const res = await fetch(resolveApiUrl(path), {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  const credentialProof = handleUnauthorized(res, path);
  if (!res.ok) {
    let message = t('error.requestFailed', { status: res.status });
    try {
      const parsed = (await res.json()) as { error?: string };
      if (parsed.error) message = parsed.error;
    } catch {
      // Preserve the bounded status-only message for non-JSON error bodies.
    }
    throw new ApiError(res.status, { error: message }, credentialProof);
  }
  return { blob: await res.blob(), headers: res.headers };
}

/**
 * The provider path segment for a credential record. Single-instance providers (CMD/SCAP)
 * are keyed by the empty provider id and use the literal `_` sentinel; CSC/PKCS#12 carry a
 * real, URL-encoded provider id.
 */
function providerSegment(providerId: string): string {
  return providerId === '' ? '_' : encodeURIComponent(providerId);
}

/** Build a query string from defined params only (skips `undefined`). */
function query(params: Record<string, string | number | undefined>): string {
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined) usp.set(k, String(v));
  }
  const s = usp.toString();
  return s ? `?${s}` : '';
}

function trustSearchQuery(
  params: TslCatalogSearchParams | string,
  limit?: number,
): Record<string, string | number | undefined> {
  if (typeof params === 'string') return { search: params, limit };
  return {
    search: params.search,
    identifier: params.identifier,
    service_type: params.service_type,
    status: params.status,
    history: params.history,
    supply_point: params.supply_point,
    limit: params.limit ?? limit,
  };
}

function importTemplate(rawJson: string, options: { dryRun: true }): Promise<TemplateImportVerdict>;
function importTemplate(rawJson: string, options?: { dryRun?: false }): Promise<TemplateSummary>;
function importTemplate(
  rawJson: string,
  options: { dryRun?: boolean } = {},
): Promise<TemplateSummary | TemplateImportVerdict> {
  return postRawJsonText<TemplateSummary | TemplateImportVerdict>(
    `/v1/templates/import${query({ dry_run: options.dryRun ? 'true' : undefined })}`,
    rawJson,
  );
}

export const api = {
  health: () => get<HealthResponse>('/health'),

  // Settings (§2.8) — whole-document GET/PUT.
  getSettings: () => get<Settings>('/v1/settings'),
  putSettings: (body: Settings) => put<Settings>('/v1/settings', body),

  // Per-user table-column preferences (t37) — self-scoped, whole-document GET/PUT. PUT replaces
  // the caller's entire `table_columns`; a table omitted from the body clears its override.
  getMePreferences: () => get<UserPreferences>('/v1/me/preferences'),
  putMePreferences: (body: UserPreferences) => put<UserPreferences>('/v1/me/preferences', body),

  // Outbound email (t23). The non-secret configuration rides `putSettings` with the rest of the
  // document; these three cover what cannot — the write-only relay password, the status that
  // reports it without revealing it, and the test send.
  getEmailStatus: () => get<EmailStatusView>('/v1/settings/email/status'),
  putEmailPassword: (password: string) =>
    put<EmailStatusView>('/v1/settings/email/password', { password }),
  deleteEmailPassword: () => del<EmailStatusView>('/v1/settings/email/password'),
  /** Resolves with `ok: false` and a structured `failure` when the RELAY rejects; it rejects with
   *  an `ApiError` only when the request itself was bad (no permission, mail not configured). */
  testEmail: (to: string) => post<EmailTestResult>('/v1/settings/email/test', { to }),

  /** The live zero-knowledge object-root interlock. Read-only: the value that governs it is
   *  written through the settings document, not here. */
  getZkStorageStatus: () => get<ZkStorageStatus>('/v1/zk-repositories/storage-status'),

  /** Declare (or, with `null`, clear) the shared-mounted ZK object root. The server validates the
   *  path before storing it and returns the LIVE interlock — which this write does not open, since
   *  the root is resolved at process start. */
  putZkSharedObjectRoot: (sharedObjectRoot: string | null) =>
    put<ZkStorageStatus>('/v1/zk-repositories/shared-object-root', {
      shared_object_root: sharedObjectRoot,
    }),

  // Platform operations — desired-state controls plus honest runtime limitations.
  listPlatformServices: () => get<PlatformServicesResponse>('/v1/platform/services'),
  controlPlatformService: (id: PlatformControllableServiceId, action: PlatformServiceAction) =>
    post<PlatformControlResponse>(
      `/v1/platform/services/${encodeURIComponent(id)}/actions/${encodeURIComponent(action)}`,
    ),
  listPlatformLogs: (params: PlatformLogsQueryParams = {}) =>
    get<PlatformLogsResponse>(
      `/v1/platform/logs${query({
        service_id: params.service_id,
        level: params.level,
        tail: params.tail,
      })}`,
    ),

  /** The server-declared env-override registry joined with live state (`GET /v1/platform/env`):
   *  every overridable var with its tier, source, effective value (masked for secrets) and
   *  `restart_pending`. Read-only view; the panel writes with {@link updateServerEnv}. */
  getServerEnv: () => get<ServerEnvResponse>('/v1/platform/env'),

  /** Replace the non-secret override map (`PUT /v1/platform/env`). `overrides` is the COMPLETE desired
   *  set — a key absent from it is cleared — and `acknowledge` must name every security-boundary var
   *  being changed, or the server answers `422` (surfaced as an `ApiError`, `status: 422`, whose
   *  `issues`/`warnings` the panel renders inline). Returns a fresh `ServerEnvResponse`, so the caller
   *  sees the new `source`/`restart_pending` without a refetch. */
  updateServerEnv: (body: ServerEnvUpdateRequest) =>
    put<ServerEnvResponse>('/v1/platform/env', body),

  // Entities (§2.3)
  listEntities: () => get<Entity[]>('/v1/entities'),
  getEntity: (id: string) => get<Entity>(`/v1/entities/${id}`),
  getEntityChronology: (id: string) => get<EntityChronologyView>(`/v1/entities/${id}/chronology`),
  createEntity: (body: CreateEntityBody) => post<Entity>('/v1/entities', body),
  // Statute overlay (ENT-03, t31). Omit `statute` to leave it untouched, `null` to
  // clear it, or an object to set it; appends an `entity.statute_updated` ledger event.
  updateEntity: (id: string, body: UpdateEntityBody) => patch<Entity>(`/v1/entities/${id}`, body),

  // Tenant-local company groups and immutable shared-template-library revisions.
  listCompanyGroups: (tenantId: string) =>
    get<CompanyGroupView[]>(`/v1/tenants/${encodeURIComponent(tenantId)}/groups`),
  createCompanyGroup: (tenantId: string, body: CreateCompanyGroupBody) =>
    post<CompanyGroupView>(`/v1/tenants/${encodeURIComponent(tenantId)}/groups`, body),
  getCompanyGroup: (tenantId: string, groupId: string) =>
    get<CompanyGroupView>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/groups/${encodeURIComponent(groupId)}`,
    ),
  patchCompanyGroup: (tenantId: string, groupId: string, body: PatchCompanyGroupBody) =>
    patch<CompanyGroupView>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/groups/${encodeURIComponent(groupId)}`,
      body,
    ),
  archiveCompanyGroup: (tenantId: string, groupId: string) =>
    del<void>(`/v1/tenants/${encodeURIComponent(tenantId)}/groups/${encodeURIComponent(groupId)}`),
  assignEntityToGroup: (tenantId: string, groupId: string, entityId: string) =>
    put<Entity>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/groups/${encodeURIComponent(groupId)}/entities/${encodeURIComponent(entityId)}`,
      undefined,
    ),
  removeEntityFromGroup: (tenantId: string, groupId: string, entityId: string) =>
    del<Entity>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/groups/${encodeURIComponent(groupId)}/entities/${encodeURIComponent(entityId)}`,
    ),
  getGroupDashboard: (tenantId: string, groupId: string) =>
    get<GroupDashboardView>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/groups/${encodeURIComponent(groupId)}/dashboard`,
    ),
  listGroupTemplateLibraries: (tenantId: string, groupId: string) =>
    get<GroupTemplateLibraryView[]>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/groups/${encodeURIComponent(groupId)}/template-libraries`,
    ),
  createGroupTemplateLibrary: (
    tenantId: string,
    groupId: string,
    body: CreateGroupTemplateLibraryBody,
  ) =>
    post<GroupTemplateLibraryView>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/groups/${encodeURIComponent(groupId)}/template-libraries`,
      body,
    ),
  patchGroupTemplateLibrary: (
    tenantId: string,
    groupId: string,
    libraryId: string,
    body: PatchGroupTemplateLibraryBody,
  ) =>
    patch<GroupTemplateLibraryView>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/groups/${encodeURIComponent(groupId)}/template-libraries/${encodeURIComponent(libraryId)}`,
      body,
    ),
  archiveGroupTemplateLibrary: (tenantId: string, groupId: string, libraryId: string) =>
    del<void>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/groups/${encodeURIComponent(groupId)}/template-libraries/${encodeURIComponent(libraryId)}`,
    ),
  appendGroupTemplateLibraryRevision: (
    tenantId: string,
    groupId: string,
    libraryId: string,
    body: AppendGroupTemplateLibraryRevisionBody,
  ) =>
    post<GroupTemplateLibraryRevision>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/groups/${encodeURIComponent(groupId)}/template-libraries/${encodeURIComponent(libraryId)}/revisions`,
      body,
    ),
  listGroupTemplateLibraryHistory: (tenantId: string, groupId: string, libraryId: string) =>
    get<GroupTemplateLibraryRevision[]>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/groups/${encodeURIComponent(groupId)}/template-libraries/${encodeURIComponent(libraryId)}/history`,
    ),

  // Tenant-scoped connector targets and durable operator jobs. Configuration contains
  // credential references only; actual secret material is never accepted by this client.
  listConnectorTargets: (tenantId: string) =>
    get<ConnectorTargetView[]>(`/v1/tenants/${encodeURIComponent(tenantId)}/connector-targets`),
  createConnectorTarget: (tenantId: string, body: CreateConnectorTargetBody) =>
    post<ConnectorTargetView>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/connector-targets`,
      body,
    ),
  patchConnectorTarget: (tenantId: string, targetId: string, body: PatchConnectorTargetBody) =>
    patch<ConnectorTargetView>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/connector-targets/${encodeURIComponent(targetId)}`,
      body,
    ),
  archiveConnectorTarget: (tenantId: string, targetId: string) =>
    del<void>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/connector-targets/${encodeURIComponent(targetId)}`,
    ),
  probeConnectorTarget: (tenantId: string, targetId: string) =>
    post<ConnectorProbeView>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/connector-targets/${encodeURIComponent(targetId)}/probe`,
    ),
  runConnectorTarget: (tenantId: string, targetId: string, body: RunConnectorTargetBody) =>
    post<ConnectorJobView>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/connector-targets/${encodeURIComponent(targetId)}/run`,
      body,
    ),
  listConnectorJobs: (tenantId: string, params: ListConnectorJobsParams = {}) =>
    get<ConnectorJobListView>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/connector-jobs${query({
        limit: params.limit,
        before_created_unix_millis: params.before_created_unix_millis,
      })}`,
    ),
  getConnectorJob: (tenantId: string, jobId: string) =>
    get<ConnectorJobView>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/connector-jobs/${encodeURIComponent(jobId)}`,
    ),
  cancelConnectorJob: (tenantId: string, jobId: string) =>
    post<ConnectorJobView>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/connector-jobs/${encodeURIComponent(jobId)}/cancel`,
    ),
  retryConnectorJob: (tenantId: string, jobId: string) =>
    post<ConnectorJobView>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/connector-jobs/${encodeURIComponent(jobId)}/retry`,
    ),

  // Opt-in zero-knowledge repository policy, opaque ciphertext, and readability handoff.
  getTenantRepositoryPolicy: (tenantId: string) =>
    get<TenantRepositoryPolicyView>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/repository-policy`,
    ),
  putTenantRepositoryPolicy: (tenantId: string, body: PutTenantRepositoryPolicyBody) =>
    put<TenantRepositoryPolicy>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/repository-policy`,
      body,
    ),
  deleteTenantRepositoryPolicy: (tenantId: string) =>
    del<void>(`/v1/tenants/${encodeURIComponent(tenantId)}/repository-policy`),
  listRepositories: (tenantId: string) =>
    get<StoredRepositoryPolicy[]>(`/v1/tenants/${encodeURIComponent(tenantId)}/repositories`),
  createRepository: (tenantId: string, body: CreateRepositoryBody) =>
    post<StoredRepositoryPolicy>(`/v1/tenants/${encodeURIComponent(tenantId)}/repositories`, body),
  patchRepository: (tenantId: string, repositoryId: string, body: PatchRepositoryBody) =>
    patch<StoredRepositoryPolicy>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/repositories/${encodeURIComponent(repositoryId)}`,
      body,
    ),
  deleteRepository: (tenantId: string, repositoryId: string) =>
    del<void>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/repositories/${encodeURIComponent(repositoryId)}`,
    ),
  listZkObjectVersions: (tenantId: string, repositoryId: string) =>
    get<ZkObjectVersionView[]>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/repositories/${encodeURIComponent(repositoryId)}/objects`,
    ),
  createZkObjectUpload: (tenantId: string, repositoryId: string, manifest: OpaqueBlobManifest) =>
    post<PendingZkUploadView>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/repositories/${encodeURIComponent(repositoryId)}/uploads`,
      { manifest },
    ),
  commitZkObjectCiphertext: (uploadUrl: string, ciphertext: ArrayBuffer | Blob) =>
    putOpaqueBytes<ZkObjectVersionView>(uploadUrl, ciphertext),
  fetchZkObjectCiphertext: (
    tenantId: string,
    repositoryId: string,
    objectId: string,
    version: number,
  ) =>
    fetchArrayBuffer(
      `/v1/tenants/${encodeURIComponent(tenantId)}/repositories/${encodeURIComponent(repositoryId)}/objects/${encodeURIComponent(objectId)}/versions/${version}/ciphertext`,
    ),
  createZkReadabilityPackage: (
    tenantId: string,
    repositoryId: string,
    objectId: string,
    version: number,
    body: ReadabilityPackageBody,
  ) =>
    postJsonBlob(
      `/v1/tenants/${encodeURIComponent(tenantId)}/repositories/${encodeURIComponent(repositoryId)}/objects/${encodeURIComponent(objectId)}/versions/${version}/readability-package`,
      body,
    ),

  // Books (§2.4)
  listBooks: (entityId?: string) => get<BookView[]>(`/v1/books${query({ entity_id: entityId })}`),
  getBook: (id: string) => get<BookView>(`/v1/books/${id}`),
  openBook: (body: OpenBookBody) => post<BookView>('/v1/books', body),
  closeBook: (id: string, body: CloseBookBody) => post<BookView>(`/v1/books/${id}/close`, body),
  listBookActs: (id: string) => get<ActView[]>(`/v1/books/${id}/acts`),
  getBookLegalHold: (id: string) => get<BookLegalHoldView>(`/v1/books/${id}/legal-hold`),
  setBookLegalHold: (id: string, body: SetBookLegalHoldBody) =>
    put<BookLegalHoldView>(`/v1/books/${id}/legal-hold`, body),
  clearBookLegalHold: (id: string, body?: ClearBookLegalHoldBody) =>
    del<BookLegalHoldView | void>(`/v1/books/${id}/legal-hold`, body),
  // Internal Chancela preservation package (`GET .../archive/package`, application/zip).
  // Read-only and not a DGLAB-specific export; offered as a direct browser download.
  fetchBookArchivePackage: (id: string, params: BookArchivePackageParams = {}) =>
    fetchBlob(
      `/v1/books/${id}/archive/package${query({
        // Only sent when asked for: the server defaults `legal_hold` to false, and it rejects
        // `legal_hold=true` without a non-blank reason, so the reason rides along or neither does.
        legal_hold: params.legal_hold ? 'true' : undefined,
        legal_hold_reason: params.legal_hold ? params.legal_hold_reason : undefined,
      })}`,
    ),
  // Metadata-only local DGLAB interchange scaffold (`GET .../local-dglab-interchange-manifest`).
  // Read-only JSON derived from the internal package manifest; not an official DGLAB export.
  getBookLocalDglabInterchangeManifest: (id: string) =>
    get<LocalDglabInterchangeManifest>(`/v1/books/${id}/archive/local-dglab-interchange-manifest`),

  // Termo de abertura as its own signable ata (two-phase book opening, t23). A book minted with
  // `one_shot: false` (see `openBook`) carries a `Draft` termo reachable here; the operator fills it
  // (`patchBookTermoAbertura`), freezes it (`advanceBookTermoAbertura`), collects signatures
  // (`signBookTermoAbertura`), then seals it to open the book (`openBookFromTermo`). GET is
  // `book.read`; every mutation is `book.open`. A one-shot book has no draft termo → the GET 404s.
  getBookTermoAbertura: (bookId: string) =>
    get<TermoInstrumentView>(`/v1/books/${bookId}/termo/abertura`),
  patchBookTermoAbertura: (bookId: string, body: PatchTermoAberturaBody) =>
    patch<TermoInstrumentView>(`/v1/books/${bookId}/termo/abertura`, body),
  advanceBookTermoAbertura: (bookId: string) =>
    post<TermoInstrumentView>(`/v1/books/${bookId}/termo/abertura/advance`),
  signBookTermoAbertura: (bookId: string, body: SignTermoSlotBody) =>
    post<TermoInstrumentView>(`/v1/books/${bookId}/termo/abertura/sign`, body),
  // Real per-slot PAdES signature with a locally supplied PKCS#12/PFX (desk-app only; a remote server
  // refuses with 409). The signed set is what the fail-closed `open` gate requires.
  signBookTermoAberturaPkcs12: (bookId: string, body: SignTermoSlotPkcs12Body) =>
    post<TermoInstrumentView>(`/v1/books/${bookId}/termo/abertura/sign/pkcs12`, body),
  // Seal the signed termo and open the book. Currently FAILS CLOSED with 409 ("not cryptographically
  // signed") until real per-slot PAdES signing lands (t41) — surfaced to the caller, never hidden.
  openBookFromTermo: (bookId: string, body: OpenBookFromTermoBody = {}) =>
    post<BookView>(`/v1/books/${bookId}/termo/abertura/open`, body),

  // Termo de encerramento as its own signable ata (two-phase book CLOSE, t44 — the mirror of the
  // abertura above). `closeBook(id, { one_shot: false })` mints a `Draft` encerramento for an OPEN
  // book (which stays Open); the operator fills it (`patchBookTermoEncerramento`), freezes it
  // (`advanceBookTermoEncerramento`), collects signatures (`signBookTermoEncerramento` reference /
  // `signBookTermoEncerramentoPkcs12` real PAdES), then seals it to close the book
  // (`closeBookFromTermo`). GET is `book.read`; every mutation is `book.close`. A one-shot/legacy
  // book has no draft termo → the GET 404s.
  getBookTermoEncerramento: (bookId: string) =>
    get<TermoInstrumentView>(`/v1/books/${bookId}/termo/encerramento`),
  patchBookTermoEncerramento: (bookId: string, body: PatchTermoEncerramentoBody) =>
    patch<TermoInstrumentView>(`/v1/books/${bookId}/termo/encerramento`, body),
  advanceBookTermoEncerramento: (bookId: string) =>
    post<TermoInstrumentView>(`/v1/books/${bookId}/termo/encerramento/advance`),
  signBookTermoEncerramento: (bookId: string, body: SignTermoSlotBody) =>
    post<TermoInstrumentView>(`/v1/books/${bookId}/termo/encerramento/sign`, body),
  // Real per-slot PAdES signature with a locally supplied PKCS#12/PFX (desk-app only; a remote server
  // refuses with 409). The signed set is what the fail-closed `close` gate requires.
  signBookTermoEncerramentoPkcs12: (bookId: string, body: SignTermoSlotPkcs12Body) =>
    post<TermoInstrumentView>(`/v1/books/${bookId}/termo/encerramento/sign/pkcs12`, body),
  // Seal the signed termo and close the book. FAILS CLOSED with 409 unless every required slot has a
  // real PAdES signature; also 409 if the material ata count moved mid-signing (stale-fact guard).
  closeBookFromTermo: (bookId: string, body: CloseBookFromTermoBody = {}) =>
    post<BookView>(`/v1/books/${bookId}/termo/encerramento/close`, body),

  // Acts (§2.5)
  getAct: (id: string) => get<ActView>(`/v1/acts/${id}`),
  draftAct: (body: DraftActBody) => post<ActView>('/v1/acts', body),
  updateAct: (id: string, body: UpdateActBody) => patch<ActView>(`/v1/acts/${id}`, body),
  // Compile a markdown body source into `Block[]` server-side (t74 §6) — the SAME compiler the seal
  // runs, so a clean preview is exactly what will be sealed. Read-only (`act.read`), usable in any
  // state. A rejected source is a `422` carrying `{ code, offset }` on the `ApiError`, never a
  // silently-dropped construct.
  previewActBody: (id: string, body: PreviewActBody) =>
    post<ActBodyPreviewResponse>(`/v1/acts/${id}/body/preview`, body),
  dispatchActConvening: (id: string, body: DispatchActConveningBody) =>
    post<ActView>(`/v1/acts/${id}/convening/dispatch`, body),
  advanceAct: (id: string, body: AdvanceActBody) => post<ActView>(`/v1/acts/${id}/advance`, body),
  // Move an act backward among the pre-signature drafting states (D1 = jump to any earlier one).
  // Appends a distinct `act.reverted` event; 422 on empty reason / invalid target, 409 from Signing
  // (points at reopen) or legal hold, 403 without `act.revert`.
  revertAct: (id: string, body: RevertActBody) => post<ActView>(`/v1/acts/${id}/revert`, body),
  // The one guarded reverse edge: pull a `Signing` act back to `TextApproved` for correction. 409
  // once a signature has been collected, under legal hold, or when the book is not open.
  reopenAct: (id: string, body: ReopenActBody) =>
    post<ReopenActResponse>(`/v1/acts/${id}/reopen`, body),
  verifyActHumanReview: (id: string, body: VerifyAiHumanReviewBody) =>
    post<ActView>(`/v1/acts/${id}/human-verification`, body),
  getCompliance: (id: string) => get<ComplianceReport>(`/v1/acts/${id}/compliance`),
  sealAct: (id: string, body: SealActBody) => post<SealResult>(`/v1/acts/${id}/seal`, body),
  archiveAct: (id: string) => post<ActView>(`/v1/acts/${id}/archive`),
  listActFollowUps: (id: string) => get<FollowUpView[]>(`/v1/acts/${id}/follow-ups`),
  createActFollowUp: (id: string, body: CreateFollowUpBody) =>
    post<FollowUpView>(`/v1/acts/${id}/follow-ups`, body),
  patchFollowUp: (id: string, body: PatchFollowUpBody) =>
    patch<FollowUpView>(`/v1/follow-ups/${encodeURIComponent(id)}`, body),
  completeFollowUp: (id: string, body: CompleteFollowUpBody = {}) =>
    post<FollowUpView>(`/v1/follow-ups/${encodeURIComponent(id)}/complete`, body),

  // Generated documents (§3.3, plan t48). The preview renders the CURRENT record live
  // (works pre-seal); a `422`/`404` means the family has no template for the stage — the
  // caller renders that as an honest "sem modelo disponível" state, not an error. The
  // bundle is `404` until sealed (and for a sealed act whose family has no template).
  getActDocumentPreview: (id: string) => get<DocumentModel>(`/v1/acts/${id}/document/preview`),
  getActDocumentBundle: (id: string) => get<DocumentBundle>(`/v1/acts/${id}/document/bundle`),
  listGeneratedDocuments: (actId: string) =>
    get<GeneratedDocumentView[]>(`/v1/acts/${encodeURIComponent(actId)}/documents/generated`),
  generateActDocument: (actId: string, templateId: string) =>
    post<GeneratedDocumentView>(
      `/v1/acts/${encodeURIComponent(actId)}/document/generate${query({
        template_id: templateId,
      })}`,
    ),
  listTemplates: (params: { family?: EntityFamily; stage?: LifecycleStage } = {}) =>
    get<TemplateSummary[]>(`/v1/templates${query(params)}`),
  createTemplate: (rawJson: string) => postRawJsonText<TemplateSummary>('/v1/templates', rawJson),
  updateTemplate: (id: string, rawJson: string) =>
    putRawJsonText<TemplateSummary>(`/v1/templates/${encodeURIComponent(id)}`, rawJson),
  deleteTemplate: (id: string) => del<void>(`/v1/templates/${encodeURIComponent(id)}`),
  exportTemplate: (id: string) =>
    fetchTextDownload(`/v1/templates/${encodeURIComponent(id)}/export`),
  importTemplate,
  // The persisted PDF/A bytes (`GET /v1/acts/{id}/document`, `application/pdf`). Fetched
  // as a Blob (not JSON) so it can be triggered as a download with an honest filename;
  // carries the session token like every other request. 404 until sealed.
  fetchActDocumentPdf: (id: string) => fetchBlob(`/v1/acts/${id}/document`),
  // The persisted PDF/A bytes as a raw ArrayBuffer (for base64-encoding into the local
  // XAdES/ASiC/SCAP tools). Same auth/404 semantics as `fetchActDocumentPdf`.
  fetchActDocumentBytes: (id: string) => fetchArrayBuffer(`/v1/acts/${id}/document`),
  fetchGeneratedDocumentPdf: (documentId: string) =>
    fetchBlob(`/v1/documents/generated/${encodeURIComponent(documentId)}`),
  getGeneratedDocumentDispatchEvidence: (documentId: string) =>
    get<GeneratedDocumentDispatchEvidenceList>(
      `/v1/documents/generated/${encodeURIComponent(documentId)}/dispatch-evidence`,
    ),
  recordGeneratedDocumentDispatchEvidence: (
    documentId: string,
    body: GeneratedDocumentDispatchEvidenceRequest,
  ) =>
    post<GeneratedDocumentDispatchEvidenceResponse>(
      `/v1/documents/generated/${encodeURIComponent(documentId)}/dispatch-evidence`,
      body,
    ),
  // Working-copy export (`GET .../document/working-copy`, text/markdown by default;
  // `?format=txt|html|rtf|odt` for other review formats). Non-evidentiary and intentionally
  // separate from the persisted/signed PDF downloads.
  fetchActDocumentWorkingCopy: (id: string, format: ActDocumentWorkingCopyFormat = 'markdown') =>
    fetchTextDownload(
      `/v1/acts/${id}/document/working-copy${format === 'markdown' ? '' : query({ format })}`,
    ),
  // Office-editable DOCX working-copy export (`GET .../document/office`). Read-only and
  // non-evidentiary; the persisted PDF/A or signed PDF remains the canonical record.
  fetchActDocumentOffice: (id: string) => fetchBlob(`/v1/acts/${id}/document/office`),
  // Non-canonical imported document evidence. Import re-runs server validation before
  // persistence; metadata JSON never carries raw bytes.
  importDocument: (body: ImportDocumentBody) =>
    post<ImportedDocumentView>('/v1/documents/import', body),
  listImportedDocuments: (params: { act_id?: string } = {}) =>
    get<ImportedDocumentView[]>(`/v1/documents/imported${query(params)}`),
  getImportedDocument: (id: string) =>
    get<ImportedDocumentView>(`/v1/documents/imported/${encodeURIComponent(id)}`),
  reviewImportedDocument: (id: string, body: ImportedDocumentReviewBody) =>
    patch<ImportedDocumentView>(`/v1/documents/imported/${encodeURIComponent(id)}/review`, body),
  fetchImportedDocumentBytes: (id: string) =>
    fetchBlob(`/v1/documents/imported/${encodeURIComponent(id)}/bytes`),

  // Qualified Chave Móvel Digital signing (§ t57). The two-phase flow: `initiate` (phone +
  // PIN → dispatches the SMS OTP) then `confirm` (session_id + OTP → the signed PDF). PIN/OTP
  // ride only in the request body and are never persisted client-side. The signature status
  // is `null`-free (unsigned/pending/signed); the signed PDF 404s until the act is signed.
  getActSignature: (id: string) => get<SignatureStatusView>(`/v1/acts/${id}/signature`),
  cmdInitiateSignature: (id: string, body: CmdInitiateBody) =>
    post<CmdInitiateResult>(`/v1/acts/${id}/signature/cmd/initiate`, body),
  cmdConfirmSignature: (id: string, body: CmdConfirmBody) =>
    post<CmdConfirmResult>(`/v1/acts/${id}/signature/cmd/confirm`, body),
  // Qualified Cartão de Cidadão signing (§ t58) — SYNCHRONOUS and desktop-only. A single
  // call signs the sealed PDF at the co-located card reader. The optional PIN is transient
  // request input only; callers must not persist it and the API does not take custody of it.
  // Refused with 409 when the API is not co-located with a reader (browser/remote server); a
  // provider failure (no card / wrong PIN / not activated / no reader) is an honest 422 whose
  // PT message is surfaced verbatim.
  ccSignSignature: (id: string, body: CcSignBody = {}) =>
    post<CcSignResult>(`/v1/acts/${id}/signature/cc/sign`, body),
  // In-app Cartão de Cidadão BATCH signing (§ t67) — signs many sealed acts under one signer
  // authentication where the card allows it. The optional PIN rides only in this request body; the
  // response and every per-document result are PIN-free. Not act-scoped (the batch spans acts).
  signCcBatch: (body: CcBatchSignBody) =>
    post<CcBatchSignResponse>('/v1/signature/cc/batch-sign', body),
  // Advanced local PKCS#12/PFX software-certificate signing. The PFX bytes and passphrase
  // ride only in this request body; the response is local technical evidence, not qualified/CMD.
  localPkcs12SignSignature: (id: string, body: LocalPkcs12SignBody) =>
    post<LocalPkcs12SignResult>(`/v1/acts/${id}/signature/local/pkcs12/sign`, body),
  // Official Autenticação.gov/provider handoff import. The uploaded signed PDF is stored as
  // technical evidence only; provider/source/filename are non-authoritative trace metadata.
  importOfficialSignature: (id: string, body: OfficialSignatureImportBody) =>
    post<OfficialSignatureImportResult>(`/v1/acts/${id}/signature/official/import`, body),
  fetchSignedActDocumentPdf: (id: string) => fetchBlob(`/v1/acts/${id}/document/signed`),

  // Local technical XAdES / ASiC signing tools (§ t67-e10/e13) — distinct from the act-signing
  // lanes above: each takes a transient co-located PKCS#12 signer + content and RETURNS a document
  // (never persisted, never changing act state). Co-location-gated (409 off-host). The PKCS#12 bytes
  // + passphrase ride only in the request body and must never be persisted client-side.
  signXades: (body: XadesSignBody) => post<XadesSignResponse>('/v1/signature/xades/sign', body),
  signAsic: (body: AsicSignBody) => post<AsicSignResponse>('/v1/signature/asic/sign', body),
  // SCAP professional-attribute surface (§ t67-e10/e13). `scapProviders`/`scapAttributes` are POSTs
  // (they carry the environment + citizen selectors). `scapSign` attaches a reported attribute and
  // returns a CAdES signature whose honesty status is decided by the transport — the mock/declared
  // path can never report a verified capacity. The PKCS#12 material rides only in the sign body.
  scapProviders: (body: ScapProvidersBody = {}) =>
    post<ScapProvidersResponse>('/v1/scap/providers', body),
  scapAttributes: (body: ScapAttributesBody) =>
    post<ScapAttributesResponse>('/v1/scap/attributes', body),
  scapSign: (body: ScapSignBody) => post<ScapSignResponse>('/v1/scap/sign', body),

  // Generic remote qualified signing (§ t59) — the provider picker + the provider-agnostic
  // two-phase flow. `listSignatureProviders` enumerates CMD + every configured CSC QTSP (gated
  // `signing.perform`; a role without it → 403); the `remote/{provider}/initiate|confirm` pair
  // drives a CSC QTSP through the SAME two-phase activation as CMD. The credential/activation
  // ride only in the request body and are never persisted client-side.
  listSignatureProviders: () => get<SignatureProviderView[]>('/v1/signature/providers'),
  remoteInitiateSignature: (id: string, provider: string, body: RemoteInitiateBody) =>
    post<RemoteInitiateResult>(
      `/v1/acts/${id}/signature/remote/${encodeURIComponent(provider)}/initiate`,
      body,
    ),
  remoteConfirmSignature: (id: string, provider: string, body: RemoteConfirmBody) =>
    post<RemoteConfirmResult>(
      `/v1/acts/${id}/signature/remote/${encodeURIComponent(provider)}/confirm`,
      body,
    ),
  remoteBatchInitiateSignature: (provider: string, body: RemoteBatchInitiateBody) =>
    post<RemoteBatchInitiateResponse>(
      `/v1/signature/remote/${encodeURIComponent(provider)}/batch-initiate`,
      body,
    ),
  listExternalSigningEnvelopes: (id: string) =>
    get<ExternalSigningEnvelopeView[]>(`/v1/acts/${id}/external-signing/envelopes`),
  createExternalSigningEnvelope: (id: string, body: CreateExternalSigningEnvelopeBody) =>
    post<ExternalSigningEnvelopeView>(`/v1/acts/${id}/external-signing/envelopes`, body),
  updateExternalSigningEnvelope: (id: string, body: UpdateExternalSigningEnvelopeBody) =>
    patch<ExternalSigningEnvelopeView>(
      `/v1/external-signing/envelopes/${encodeURIComponent(id)}`,
      body,
    ),
  listExternalSignerInvites: (id: string) =>
    get<ExternalSignerInviteView[]>(`/v1/acts/${id}/signature/external-invites`),
  createExternalSignerInvite: (id: string, body: CreateExternalSignerInviteBody) =>
    post<CreateExternalSignerInviteResult>(`/v1/acts/${id}/signature/external-invites`, body),
  revokeExternalSignerInvite: (id: string, inviteId: string) =>
    post<ExternalSignerInviteView>(
      `/v1/acts/${id}/signature/external-invites/${encodeURIComponent(inviteId)}/revoke`,
    ),
  lookupExternalSignerInvite: (token: string) =>
    post<ExternalSignerInvitePublicView>('/v1/signature/external-invites/lookup', { token }),
  respondExternalSignerInvite: (
    token: string,
    decision: ExternalSignerInviteDecision,
    options: ExternalSignerInviteRespondOptions = {},
  ) =>
    post<ExternalSignerInvitePublicView>('/v1/signature/external-invites/respond', {
      token,
      decision,
      ...options,
    }),
  fetchExternalSignerInviteWorkingCopy: (token: string) =>
    postTextDownload('/v1/signature/external-invites/document/working-copy', { token }),
  validatePdfSignature: (body: PdfSignatureValidationBody) =>
    post<PdfSignatureValidationResponse>('/v1/signature/pdf/validate', body),
  inspectAsicSignature: (body: AsicSignatureInspectionBody) =>
    post<AsicSignatureInspectionResponse>('/v1/signature/asic/inspect', body),
  listExternalValidatorReports: () =>
    get<ExternalValidatorReportsResponse>('/v1/external-validator-reports'),
  uploadExternalValidatorReport: (body: ExternalValidatorReportUploadRequest) =>
    typeof body === 'string'
      ? postRawJsonText<ExternalValidatorReportUploadResponse>(
          '/v1/external-validator-reports',
          body,
        )
      : post<ExternalValidatorReportUploadResponse>('/v1/external-validator-reports', body),

  // Registry — certidão permanente (§2.7). The `code` in each body is a secret; it is
  // sent transiently in the request and never returned (provenance is masked).
  registryLookup: (body: RegistryLookupBody) =>
    post<RegistryExtractView>('/v1/registry/lookup', body),
  getRegistryAutoUpdateDuePlan: () => get<RegistryAutoUpdateDuePlan>('/v1/registry/lookup'),
  getEntityRegistry: (id: string) => get<RegistryExtractView>(`/v1/entities/${id}/registry`),
  requestRegistryAutoUpdate: (id: string, body: RegistryAutoUpdateAttemptBody = {}) =>
    post<RegistryAutoUpdateAttemptView>(`/v1/entities/${id}/registry`, body),
  importEntityRegistry: (id: string, body: RegistryImportBody) =>
    post<RegistryImportReport>(`/v1/entities/${id}/registry/import`, body),
  importFromRegistry: (body: ImportFromRegistryBody) =>
    post<RegistryImportReport>('/v1/entities/import-from-registry', body),

  // CAE — Classificação das Atividades Económicas (§2.7, plan t14).
  getCae: (code: string, revision?: CaeRevision) =>
    get<CaeEntryView>(`/v1/cae/${encodeURIComponent(code)}${query({ revision })}`),
  searchCae: (search: string, params: { revision?: CaeRevision; limit?: number } = {}) =>
    get<CaeNode[]>(`/v1/cae${query({ search, ...params })}`),
  getCaeCatalog: () => get<CaeCatalogView>('/v1/cae'),
  refreshCae: () => post<CaeRefreshResult>('/v1/cae/refresh'),
  // The INE SMI update-availability signal (t33-e2). Read-only; 502 when SMI is
  // unreachable. The "Verificar novas revisões" UI that consumes it is t23-e3's.
  getCaeUpdates: () => get<CaeUpdates>('/v1/cae/updates'),

  // TSL trust catalog — read-only parsed Trusted List status/search/detail. No live fetch is
  // triggered by these endpoints; the server parses cached XML or its bundled fixture.
  getTrustStatus: () => get<TslSummaryView>('/v1/trust/status'),
  refreshTrustTsl: (body: TslRefreshRequest = {}) =>
    post<TslRefreshStatusView>('/v1/trust/refresh', body),
  getTrustCatalog: () => get<TslCatalogView>('/v1/trust/catalog'),
  searchTrustCatalog: (params: TslCatalogSearchParams | string, limit?: number) =>
    get<TslServiceSummaryView[]>(`/v1/trust/catalog${query(trustSearchQuery(params, limit))}`),
  getTrustProvider: (id: string) =>
    get<TslProviderDetailView>(`/v1/trust/providers/${encodeURIComponent(id)}`),
  getTrustService: (id: string) =>
    get<TslServiceDetailView>(`/v1/trust/services/${encodeURIComponent(id)}`),
  // TSA diagnostics/catalog — read-only configured RFC 3161 status plus offline fixture probe and
  // TSL timestamp-authority records. No live timestamp request is triggered.
  getTsaCatalog: () => get<TsaCatalogView>('/v1/trust/tsa'),
  searchTsaCatalog: (params: TsaCatalogSearchParams | string, limit?: number) =>
    get<TsaRecordView[]>(`/v1/trust/tsa${query(trustSearchQuery(params, limit))}`),

  // Law archive (t27, FROZEN §law-v1) — the local "mini law archive". `GET /v1/law` is a
  // bare `[LawEntryView]`; the tolerant `{ entries }` alternative is kept only so the hook's
  // normalizer is robust. A 404 / non-JSON reply means the running server predates the
  // feature, which `useLawArchive` catches to fall back to links-only. `fetchLawPdf` may
  // fail with 404 / 409 (pdf_url null) / 422 (no data dir) / 502 — the friendly `{error}`
  // body is surfaced to the user via `ApiError.message`.
  getLawManifest: () => get<LawEntryView[] | { entries: LawEntryView[] }>('/v1/law'),
  fetchLawPdf: (id: string) => post<LawEntryView>(`/v1/law/${encodeURIComponent(id)}/fetch`),

  // Law corpus reader (t55-E2, FROZEN corpus-v1) — read-only, full-text access to the embedded
  // statute corpus, gated `law.read@Global`. Distinct from the PDF archive above: this surfaces
  // the article-by-article verbatim text (or the loud unverified marker for a `Pending` article)
  // plus a per-article authenticity status, and an accent/case-insensitive full-text search.
  // `getLawDiploma`/`getLawArticle` 404 on an unknown diploma/article; a blank search `q` → an
  // empty result set (`limit` default 50, max 500 server-side).
  getLawCorpus: () => get<LawCorpusView>('/v1/law/corpus'),
  getLawDiploma: (diploma: string) =>
    get<LawDiplomaDetailView>(`/v1/law/corpus/${encodeURIComponent(diploma)}`),
  getLawArticle: (diploma: string, article: string) =>
    get<LawArticleView>(
      `/v1/law/corpus/${encodeURIComponent(diploma)}/${encodeURIComponent(article)}`,
    ),
  searchLawCorpus: (q: string, limit?: number) =>
    get<LawSearchView>(`/v1/law/corpus/search${query({ q, limit })}`),
  resolveLawCitations: (body: LawCitationRequest) =>
    post<LawCitationReport>('/v1/law/citations/resolve', body),

  // Users + session (§2.8, plan t14). The session token is stored in memory (see
  // `./session`) and sent as `X-Chancela-Session` on every request by `request`.
  listUsers: () => get<UserView[]>('/v1/users'),
  getUser: (id: string) => get<UserView>(`/v1/users/${id}`),
  createUser: (body: CreateUserBody) => post<UserView>('/v1/users', body),
  updateUser: (id: string, body: UpdateUserBody) => patch<UserView>(`/v1/users/${id}`, body),
  exportUserDsr: (id: string) => get<UserDsrExport>(`/v1/privacy/users/${id}/export`),
  listUserDsrRequests: (id: string) =>
    get<DsrRequestView[]>(`/v1/privacy/users/${id}/dsr-requests`),
  createUserDsrRequest: (id: string, body: CreateDsrRequestBody) =>
    post<DsrRequestView>(`/v1/privacy/users/${id}/dsr-requests`, body),
  completeUserDsrRequest: (userId: string, requestId: string) =>
    post<DsrRequestView>(`/v1/privacy/users/${userId}/dsr-requests/${requestId}/complete`),
  listProcessorRecords: () => get<ProcessorRecordView[]>('/v1/privacy/processors'),
  createProcessorRecord: (body: CreateProcessorRecordBody) =>
    post<ProcessorRecordView>('/v1/privacy/processors', body),
  patchProcessorRecord: (id: string, body: PatchProcessorRecordBody) =>
    patch<ProcessorRecordView>(`/v1/privacy/processors/${id}`, body),
  listDpiaRecords: () => get<DpiaRecordView[]>('/v1/privacy/dpias'),
  getDpiaTemplate: () => get<DpiaTemplateView>('/v1/privacy/dpia-template'),
  createDpiaRecord: (body: CreateDpiaRecordBody) => post<DpiaRecordView>('/v1/privacy/dpias', body),
  patchDpiaRecord: (id: string, body: PatchDpiaRecordBody) =>
    patch<DpiaRecordView>(`/v1/privacy/dpias/${id}`, body),
  listBreachPlaybooks: () => get<BreachPlaybookView[]>('/v1/privacy/breach-playbooks'),
  createBreachPlaybook: (body: CreateBreachPlaybookBody) =>
    post<BreachPlaybookView>('/v1/privacy/breach-playbooks', body),
  patchBreachPlaybook: (id: string, body: PatchBreachPlaybookBody) =>
    patch<BreachPlaybookView>(`/v1/privacy/breach-playbooks/${id}`, body),
  listTransferControls: () => get<TransferControlView[]>('/v1/privacy/transfer-controls'),
  createTransferControl: (body: CreateTransferControlBody) =>
    post<TransferControlView>('/v1/privacy/transfer-controls', body),
  patchTransferControl: (id: string, body: PatchTransferControlBody) =>
    patch<TransferControlView>(`/v1/privacy/transfer-controls/${id}`, body),
  listRetentionPolicies: () => get<RetentionPolicyView[]>('/v1/privacy/retention-policies'),
  createRetentionPolicy: (body: CreateRetentionPolicyBody) =>
    post<RetentionPolicyView>('/v1/privacy/retention-policies', body),
  patchRetentionPolicy: (id: string, body: PatchRetentionPolicyBody) =>
    patch<RetentionPolicyView>(`/v1/privacy/retention-policies/${id}`, body),
  dryRunRetentionPolicy: (body: RetentionDryRunBody) =>
    post<RetentionDryRunReport>('/v1/privacy/retention-policies/dry-run', body),
  listRetentionDueCandidates: () =>
    get<RetentionDueCandidatesReport>('/v1/privacy/retention-due-candidates'),
  listRetentionCandidateResolutions: () =>
    get<RetentionCandidateResolutionRecord[]>('/v1/privacy/retention-candidate-resolutions'),
  recordRetentionCandidateResolution: (
    candidateId: string,
    body: RetentionCandidateResolutionBody,
  ) =>
    post<RetentionCandidateResolutionRecord>(
      `/v1/privacy/retention-due-candidates/${encodeURIComponent(candidateId)}/resolution`,
      body,
    ),
  listRetentionExecutions: (status?: RetentionExecutionStatus) =>
    get<RetentionExecutionRecord[]>(`/v1/privacy/retention-executions${query({ status })}`),
  closeRetentionExecutionReview: (id: string, body: CloseRetentionExecutionReviewBody) =>
    post<RetentionExecutionRecord>(`/v1/privacy/retention-executions/${id}/review-closure`, body),
  // Sign-in secret + attestation-key management (t29 §4). All echo the updated UserView.
  // The `current_password` (when a secret already exists) rides in the body; a DELETE
  // carries it too (the `del` helper JSON-encodes an optional body).
  setUserSecret: (id: string, body: SetSecretBody) =>
    post<UserView>(`/v1/users/${id}/secret`, body),
  removeUserSecret: (id: string, body: RemoveSecretBody = {}) =>
    del<UserView>(`/v1/users/${id}/secret`, body),
  createAttestationKey: (id: string, body: AttestationKeyBody = {}) =>
    post<UserView>(`/v1/users/${id}/attestation-key`, body),
  removeAttestationKey: (id: string, body: AttestationKeyBody = {}) =>
    del<UserView>(`/v1/users/${id}/attestation-key`, body),
  // Issue/rotate a one-time recovery phrase (t51). The returned phrase is shown ONCE and
  // never crosses the wire again (stored only as a verifier) — callers must not persist it.
  issueRecovery: (id: string, body: IssueRecoveryBody = {}) =>
    post<RecoveryIssued>(`/v1/users/${id}/recovery`, body),
  // Two-factor (TOTP) — frozen contract from t107 (t95 §2.3). The status read is visible to the
  // holder and to an admin (`user.manage`) for another account; enrol/confirm/disable/backup are
  // self-only (`require_self`). The `secret`, `provisioning_uri` and backup codes are each shown
  // ONCE by the caller and never persisted — these methods return them, they do not cache them.
  getTwoFactor: (id: string) => get<TwoFactorStatus>(`/v1/users/${id}/two-factor`),
  enrolTotp: (id: string) => post<TotpEnrolment>(`/v1/users/${id}/two-factor/totp/enrol`, {}),
  confirmTotp: (id: string, body: TotpConfirmBody) =>
    post<BackupCodes>(`/v1/users/${id}/two-factor/totp/confirm`, body),
  disableTotp: (id: string) => del<UserView>(`/v1/users/${id}/two-factor/totp`),
  regenerateBackupCodes: (id: string) =>
    post<BackupCodes>(`/v1/users/${id}/two-factor/backup-codes`, {}),
  // Active sessions — frozen contract from t107 (t95, funded). SELF-SCOPED: all three act on the
  // caller's OWN sessions regardless of any path parameter, so the UI only surfaces them on one's
  // own account. Only `session_id` (an opaque handle) crosses the wire, never the token/digest.
  listSessions: () => get<SessionListResponse>('/v1/sessions'),
  revokeSession: (sessionId: string) =>
    del<RevokedResponse>(`/v1/sessions/${encodeURIComponent(sessionId)}`),
  revokeOtherSessions: () => post<RevokedResponse>('/v1/sessions/revoke-others', {}),
  getSession: () => get<SessionView>('/v1/session'),
  // Active password-strength ruleset (t68). Exempt so onboarding can render the checklist
  // before a user/session exists; the server remains authoritative on submit.
  getPasswordPolicy: () => get<PasswordPolicyView>('/v1/session/password-policy'),
  // The fuller permission view (identity + role assignments + effective grants) for the
  // signed-in principal (`GET /v1/session/permissions`, t64-E3). Used to seed the
  // role-assignment manager with the current user's OWN assignments (there is no read
  // endpoint for another user's assignments — the assign/unassign responses are the source
  // of truth for those).
  getSessionPermissions: () => get<SessionPermissions>('/v1/session/permissions'),

  // RBAC management (§ t64-E4, FROZEN DTOs). The server re-enforces the subset invariant,
  // protected-Owner, last-Owner and delegation hold-via-role rules on every write regardless
  // of what the UI offers — a rejected escalation comes back as an honest 403/409.
  listRoles: () => get<RoleView[]>('/v1/roles'),
  listPermissions: () => get<PermissionCatalogView>('/v1/permissions'),
  createRole: (body: CreateRoleBody) => post<RoleView>('/v1/roles', body),
  patchRole: (id: string, body: PatchRoleBody) => patch<RoleView>(`/v1/roles/${id}`, body),
  deleteRole: (id: string) => del<void>(`/v1/roles/${id}`),
  getSeededRoleReconciliation: (id: string) =>
    get<SeededRoleReconciliationView>(`/v1/roles/${id}/seeded-drift-reconciliation`),
  applySeededRoleReconciliation: (id: string) =>
    post<SeededRoleReconciliationView>(`/v1/roles/${id}/seeded-drift-reconciliation`, {}),
  // Assign/unassign a `(role, scope)` to a user. Both echo the user's UPDATED assignment
  // list, so the caller keeps the shown assignments authoritative without a separate read.
  assignRole: (userId: string, body: RoleAssignmentInput) =>
    post<RoleAssignmentView[]>(`/v1/users/${userId}/roles`, body),
  unassignRole: (userId: string, body: RoleAssignmentInput) =>
    del<RoleAssignmentView[]>(`/v1/users/${userId}/roles`, body),
  // Scoped delegations. `GET` returns the delegations touching the caller (own) or all (for a
  // `delegation.revoke` holder); grant/revoke/suspend/resume are gated + invariant-enforced
  // server-side. A grant hands over one or more FUNÇÕES sharing one scope, lifetime and legal
  // basis; revoke withdraws all of them at once (the delegation, not the função, is the unit of
  // revocation). Suspend/resume is the reversible pause — same authority as revoke.
  listDelegations: () => get<DelegationView[]>('/v1/delegations'),
  grantDelegation: (body: GrantDelegationBody) => post<DelegationView>('/v1/delegations', body),
  revokeDelegation: (id: string) => del<void>(`/v1/delegations/${id}`),
  suspendDelegation: (id: string) => post<DelegationView>(`/v1/delegations/${id}/suspend`, {}),
  resumeDelegation: (id: string) => post<DelegationView>(`/v1/delegations/${id}/resume`, {}),

  // API keys — interactive-session-only management. Create/rotate return the plaintext secret once;
  // list/revoke return metadata only.
  listApiKeys: () => get<ApiKeyView[]>('/v1/api-keys'),
  createApiKey: (body: CreateApiKeyBody) => post<ApiKeyCreated>('/v1/api-keys', body),
  rotateApiKey: (id: string) => post<ApiKeyRotated>(`/v1/api-keys/${id}/rotate`),
  revokeApiKey: (id: string) => del<ApiKeyView>(`/v1/api-keys/${id}`),

  // Provider-credential entries (wp13) — multi-key/priority/failover management over the
  // encrypted store. Single-instance providers (CMD/SCAP) use the `_` path segment; CSC and
  // PKCS#12 carry a real provider id. Secrets are write-only: no response echoes a secret.
  listProviderCredentials: () =>
    get<ProviderCredentialsListView>('/v1/signature/provider-credentials'),
  createProviderCredentialEntry: (
    mode: CredentialMode,
    providerId: string,
    body: CreateProviderCredentialEntryBody,
  ) =>
    post<ProviderCredentialEntryMutationResponse>(
      `/v1/signature/provider-credentials/${mode}/${providerSegment(providerId)}/entries`,
      body,
    ),
  updateProviderCredentialEntry: (
    mode: CredentialMode,
    providerId: string,
    entryId: string,
    body: UpdateProviderCredentialEntryBody,
  ) =>
    patch<ProviderCredentialEntryMutationResponse>(
      `/v1/signature/provider-credentials/${mode}/${providerSegment(providerId)}/entries/${encodeURIComponent(entryId)}`,
      body,
    ),
  deleteProviderCredentialEntry: (mode: CredentialMode, providerId: string, entryId: string) =>
    del<ProviderCredentialEntryMutationResponse>(
      `/v1/signature/provider-credentials/${mode}/${providerSegment(providerId)}/entries/${encodeURIComponent(entryId)}`,
    ),
  reorderProviderCredentialEntries: (
    mode: CredentialMode,
    providerId: string,
    body: ReorderProviderCredentialEntriesBody,
  ) =>
    post<ProviderCredentialEntryListResponse>(
      `/v1/signature/provider-credentials/${mode}/${providerSegment(providerId)}/entries/reorder`,
      body,
    ),
  // Sign a sealed act with a STORED PKCS#12 identity (no secret in the request body).
  signStoredPkcs12: (actId: string, body: SignStoredPkcs12Body) =>
    post<LocalPkcs12SignResult>(
      `/v1/acts/${encodeURIComponent(actId)}/signature/local/pkcs12/sign-stored`,
      body,
    ),

  // The UNAUTHENTICATED sign-in roster (t45-e1): decides onboarding-vs-sign-in and lists
  // the signable users while signed out, without the auth-gated `GET /v1/users`.
  getSessionRoster: () => get<SessionRoster>('/v1/session/roster'),
  // `POST /v1/session` is an untagged union: an authenticated `SessionResult` (carries `token`) or a
  // pending `{ two_factor_challenge }` when the account has a confirmed second factor. The caller
  // discriminates by which key is present (see `CreateSessionOutcome`); only the token arm is a
  // completed sign-in.
  createSession: (body: CreateSessionBody) => post<CreateSessionOutcome>('/v1/session', body),
  // `POST /v1/session/challenge` completes a two-step sign-in. The route is Exempt (the
  // `challenge_id` is the credential); a wrong/spent/expired code is a uniform opaque 401 that
  // `CREDENTIAL_PROOF_PATH` marks so it rejects inline rather than clearing the session.
  completeChallenge: (body: CompleteChallengeBody) =>
    post<SessionResult>('/v1/session/challenge', body),
  deleteSession: () => del<void>('/v1/session'),

  // Ledger (§2.6)
  listLedger: (params: LedgerQueryParams = {}) =>
    get<LedgerEventView[]>(
      `/v1/ledger/events${query({
        q: params.q,
        chain: params.chain,
        scope: params.scope,
        kind: params.kind,
        actor: params.actor,
        from: params.from,
        to: params.to,
        limit: params.limit,
        order: params.order,
      })}`,
    ),
  listLedgerPage: (params: LedgerQueryParams = {}) =>
    get<LedgerEventsPage>(
      `/v1/ledger/events/page${query({
        q: params.q,
        chain: params.chain,
        scope: params.scope,
        kind: params.kind,
        actor: params.actor,
        from: params.from,
        to: params.to,
        before_seq: params.before_seq,
        limit: params.limit,
        order: params.order,
      })}`,
    ),
  fetchLedgerArchiveDocument: (params: LedgerArchiveDocumentParams = {}) =>
    fetchBlob(
      `/v1/ledger/archive/document${query({
        format: params.format,
        export_scope: params.export_scope,
        q: params.q,
        chain: params.chain,
        scope: params.scope,
        kind: params.kind,
        actor: params.actor,
        from: params.from,
        to: params.to,
        limit: params.limit,
        order: params.order,
      })}`,
    ),
  verifyLedger: () => get<LedgerVerify>('/v1/ledger/verify'),

  // Chain integrity + recovery + per-book export/import/start-over + data management
  // (t54, frozen E3 DTOs). Every destructive op carries a step-up `reauth` proof.
  ledgerIntegrity: () => get<IntegrityReportView>('/v1/ledger/integrity'),
  reanchorLedger: (body: ReanchorBody) =>
    post<ReanchorResult>('/v1/ledger/recovery/reanchor', body),
  restoreLedgerPreflight: (body: RestorePreflightBody) =>
    post<RestorePreflightView>('/v1/ledger/recovery/restore/preflight', body),
  restoreLedger: (body: RestoreBody) =>
    post<RestoreOutcomeView>('/v1/ledger/recovery/restore', body),
  createBackupRecoveryDrill: (body: BackupRecoveryDrillBody) =>
    post<BackupRecoveryDrillReceipt>('/v1/backup/recovery-drills', body),
  listBackupRecoveryDrills: () => get<BackupRecoveryDrillList>('/v1/backup/recovery-drills'),
  syncHandoffPreflight: () => get<SyncHandoffPreflightReport>('/v1/sync/handoff-preflight'),
  // Take a hot backup and return its manifest (`POST /v1/backup`, contract §3.2, t30). No
  // body; gated by `data.backup`@Global. 422 when the instance has no on-disk persistence
  // (in-memory mode). Server-response-modelled — no backup UI drives this yet.
  backup: () => post<BackupManifest>('/v1/backup'),
  // Book bundle export: a `POST` that streams `application/zip`; the retained path +
  // digest ride in `X-Chancela-Export-Path` / `X-Chancela-Bundle-Digest` headers.
  exportBook: (id: string) => fetchBlobVia(`/v1/books/${id}/export`, 'POST'),
  // Book import preflight: raw `.zip` bytes, no mutation and no import id in the response.
  preflightImportBook: (bytes: ArrayBuffer | Blob, policy: CollisionPolicy = 'refuse') =>
    postBytes<BookImportPreflightView>(`/v1/books/import/preflight${query({ policy })}`, bytes),
  // Book import: raw `.zip` bytes in the body; verify-before-trust → Verified|Quarantined.
  importBook: (bytes: ArrayBuffer | Blob, policy: CollisionPolicy = 'refuse') =>
    postBytes<ImportOutcomeView>(`/v1/books/import${query({ policy })}`, bytes),
  validatePaperBookImport: (body: PaperBookImportValidateBody) =>
    post<PaperBookImportReport>('/v1/books/paper-import/validate', body),
  preservePaperBookImport: (body: PaperBookImportPreserveBody) =>
    post<PaperBookImportPreservationReport>('/v1/books/paper-import', body),
  listPaperBookImports: (params: { book_ref?: string } = {}) =>
    get<PaperBookImportView[]>(`/v1/books/paper-import${query(params)}`),
  getPaperBookImport: (id: string) =>
    get<PaperBookImportView>(`/v1/books/paper-import/${encodeURIComponent(id)}`),
  enqueuePaperBookImportOcr: (id: string) =>
    post<PaperBookOcrStatusView>(`/v1/books/paper-import/${encodeURIComponent(id)}/ocr/enqueue`),
  runPaperBookImportOcr: (id: string) =>
    post<PaperBookOcrRunView>(`/v1/books/paper-import/${encodeURIComponent(id)}/ocr/run`),
  updatePaperBookImportOcrStatus: (id: string, body: PaperBookOcrStatusUpdateBody) =>
    patch<PaperBookOcrStatusView>(
      `/v1/books/paper-import/${encodeURIComponent(id)}/ocr-status`,
      body,
    ),
  listPaperBookImportOcrDrafts: (id: string) =>
    get<PaperBookOcrDraftView[]>(`/v1/books/paper-import/${encodeURIComponent(id)}/ocr-drafts`),
  createPaperBookImportOcrDraft: (id: string, body: PaperBookOcrDraftCreateBody) =>
    post<PaperBookOcrDraftView>(
      `/v1/books/paper-import/${encodeURIComponent(id)}/ocr-drafts`,
      body,
    ),
  reviewPaperBookImportOcrDraft: (
    importId: string,
    draftId: string,
    body: PaperBookOcrDraftReviewBody,
  ) =>
    patch<PaperBookOcrDraftView>(
      `/v1/books/paper-import/${encodeURIComponent(importId)}/ocr-drafts/${encodeURIComponent(
        draftId,
      )}/review`,
      body,
    ),
  createPaperBookOcrDraftActDraft: (importId: string, draftId: string) =>
    post<PaperBookOcrDraftCanonicalDraftResponse>(
      `/v1/books/paper-import/${encodeURIComponent(importId)}/ocr-drafts/${encodeURIComponent(
        draftId,
      )}/canonical-draft`,
    ),
  listPaperBookOcrConversionDossiers: (id: string) =>
    get<PaperBookOcrConversionDossierView[]>(
      `/v1/books/paper-import/${encodeURIComponent(id)}/conversion-dossiers`,
    ),
  getPaperBookOcrCanonicalRehearsal: (id: string) =>
    get<PaperBookOcrCanonicalRehearsalReport>(
      `/v1/books/paper-import/${encodeURIComponent(id)}/ocr-canonical-rehearsal`,
    ),
  createPaperBookOcrConversionDossier: (importId: string, draftId: string) =>
    post<PaperBookOcrConversionDossierView>(
      `/v1/books/paper-import/${encodeURIComponent(importId)}/ocr-drafts/${encodeURIComponent(
        draftId,
      )}/conversion-dossier`,
    ),
  fetchPaperBookImportBytes: (id: string) =>
    fetchBlob(`/v1/books/paper-import/${encodeURIComponent(id)}/bytes`),
  startOverBook: (id: string, body: StartOverBookBody) =>
    post<StartOverBookResult>(`/v1/books/${id}/start-over`, body),
  dataStatus: () => get<DataStatusResponse>('/v1/data/status'),
  cleanDataStorage: (body: DataCleanupBody) => post<DataCleanupResult>('/v1/data/cleanup', body),
  preflightDataKeyRotation: (body: DataKeyRotationPreflightBody) =>
    post<DataKeyRotationPreflight>('/v1/data/key-rotation/preflight', body),
  executeDataKeyRotation: (body: DataKeyRotationExecuteBody) =>
    post<DataKeyRotationExecution>('/v1/data/key-rotation', body),
  // Data management (§2.11). Frontend-reset is client-only — it has NO endpoint here.
  resetData: (body: ResetDataBody) => post<ResetOutcomeView>('/v1/data/reset', body),
  startOverInstance: (body: StartOverInstanceBody) =>
    post<StartOverInstanceView>('/v1/data/start-over', body),

  // Companion pairing / device enrollment (wp27). The desktop mints a single-use code
  // (shown as a QR / deep-link), polls the device list until the phone exchanges it, and
  // can revoke an enrolled device. The phone-side `exchange` is unauthenticated and not
  // driven from this client.
  createPairingCode: (body: MintPairingCodeBody = {}) =>
    post<PairingCodeMinted>('/v1/pairing/codes', body),
  listPairingDevices: () => get<PairingDevices>('/v1/pairing/devices'),
  revokePairingDevice: (deviceId: string) =>
    del<void>(`/v1/pairing/devices/${encodeURIComponent(deviceId)}`),

  // Dashboard (§2.7)
  dashboard: () => get<Dashboard>('/v1/dashboard'),
  getNotificationTriage: () => get<NotificationTriageResponse>('/v1/notifications/triage'),
  patchNotificationTriage: (id: string, body: NotificationTriageUpdateBody) =>
    patch<NotificationTriageUpdateResponse>(
      `/v1/notifications/triage/${encodeURIComponent(id)}`,
      body,
    ),
};

/**
 * The same-origin path that serves a stored law PDF (`GET /v1/law/{id}/pdf`). Used as a
 * plain link target (not routed through `openExternal`) since it is an app-origin URL the
 * embedded server serves — in the browser it opens in a new tab, in the desktop WebView it
 * resolves against the in-process server.
 */
export function lawPdfPath(id: string): string {
  return resolveApiUrl(`/v1/law/${encodeURIComponent(id)}/pdf`);
}
