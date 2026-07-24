/**
 * SigningPanel — signing and signed-PDF evidence over the frozen `Signing` snapshot.
 *
 * Entering `Signing` freezes the canonical PDF/A. That snapshot can then be signed through a
 * chosen method; sealing happens only afterward. The panel presents a provider picker and routes
 * each choice to the right flow:
 *
 *   • **Chave Móvel Digital (CMD)** — an honest two-phase flow (t57), remote-capable:
 *       1. «Assinar com Chave Móvel Digital» → collect the mobile number + signature PIN →
 *          `cmd/initiate` (the server dispatches an SMS OTP);
 *       2. collect the OTP received by SMS → `cmd/confirm` → the act is signed.
 *
 *   • **Cartão de Cidadão (CC)** — a SYNCHRONOUS single call (t58), desktop-only. «Assinar com
 *     Cartão de Cidadão» → an honest prompt (insert the card; optionally enter the transient PIN
 *     in the desktop app, or leave it blank for protected authentication at the reader) → `cc/sign`
 *     blocks while the card signs → the act is signed. CC only works when the API is co-located
 *     with the reader (the desktop app); a remote/browser server refuses with **409**, which we
 *     surface as an honest note.
 *
 *   • **A configured CSC QTSP** (Multicert / DigitalSign / … by label, t59) — the SAME two-phase
 *     activation flow as CMD, driven through the GENERIC endpoints
 *     `remote/{provider}/initiate|confirm` (provider = the chosen id): collect the user reference
 *     + credential → `initiate` (the QTSP dispatches an OTP/SAD) → enter the activation code →
 *     `confirm` → the act is signed. Only **configured** QTSPs are offered; an unconfigured one is
 *     shown disabled with an honest «não configurado» note.
 *
 *   • **Official Autenticação.gov/provider handoff import** — the operator uploads a PDF already
 *     signed outside Chancela. This stores technical signed-PDF evidence only after explicit
 *     guardrail acknowledgement; it does not collect secrets or claim trust-list validation,
 *     qualified status, or legal completion.
 *
 * The picker is fed by `GET /v1/signature/providers`; CMD and CC are always offered (each has a
 * dedicated flow that does not depend on the list), and every configured CSC QTSP is appended. The
 * settings `preferred_family` marks the recommended method. When the list is unavailable (an older
 * server, or a principal without `signing.perform`) the panel simply offers CMD + CC.
 *
 * States are honest end-to-end (unsigned → pending/aguarda-OTP → signed): a 410 expired session
 * restarts cleanly, a rejected OTP surfaces a clear retry. The two-phase credential/OTP (CMD) and
 * user-reference/credential/activation (CSC) are TRANSIENT — held only in this component's form
 * state for the duration of the request that consumes them, cleared the instant they are sent, and
 * never stored client-side. The optional CC PIN follows the same rule and is omitted when the
 * signer uses the reader / Autenticação.gov prompt instead. The qualified-signing methods label
 * their qualified status accurately, while imported and local technical evidence are kept visibly
 * separate.
 *
 * Read errors render inline; the mutations follow the toast idiom (success + error) per
 * CONVENTIONS §2/§3. The sign actions are gated with `useCan('signing.perform', <act's book
 * scope>)` (disable-with-explanation); the server re-enforces the permission regardless.
 */
import { useCallback, useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type {
  ActView,
  AsicContainer,
  AsicSignerRole,
  AsicSignResponse,
  CreateExternalSignerInviteBody,
  DocumentBundle,
  ExternalSignerIdentityRequirement,
  ExternalSignerInviteView,
  ExternalSignerSlotStatus,
  ExternalSigningEnvelopeSlotView,
  ExternalSigningEnvelopeView,
  ExternalSigningOrderPolicy,
  LocalSignatureLevel,
  OfficialSignatureImportGuardrail,
  PendingSignatureInfo,
  SealAppearanceBody,
  Settings,
  SignatureEvidenceStatus,
  SignatureFamily,
  SignatureProviderView,
  SignedSignatureInfo,
  UpdateExternalSigningEnvelopeEvidenceBody,
  XadesPackaging,
  XadesSignResponse,
} from '../../api/types';
import { OFFICIAL_SIGNATURE_IMPORT_GUARDRAIL_IDS } from '../../api/types';
import { ApiError, api } from '../../api/client';
import { BatchSigningPanel } from './BatchSigningPanel';
import { RemoteBatchSigningPanel } from './RemoteBatchSigningPanel';
import {
  Pkcs12SignerFields,
  base64ToBytes,
  bytesToBase64,
  emptyPkcs12Signer,
  fileToBase64,
  type Pkcs12SignerState,
} from './Pkcs12SignerFields';
// Re-exported so existing consumers (and SigningPanel.logic.test) keep importing these from here.
export { base64ToBytes, bytesToBase64, fileToBase64 } from './Pkcs12SignerFields';
import { ScapAttributePicker } from './ScapAttributePicker';
import { SealDesigner } from './seal-designer';
import { actStateLabels, signatureFamilyLabels } from '../../api/labels';
import {
  keys,
  useActDocumentBundle,
  useActSignature,
  useAsicSign,
  useCcSignSignature,
  useCmdConfirmSignature,
  useCmdInitiateSignature,
  useCreateExternalSignerInvite,
  useCreateExternalSigningEnvelope,
  useDownloadSignedDocument,
  useExternalSignerInvites,
  useExternalSigningEnvelopes,
  useImportOfficialSignature,
  useLocalPkcs12SignSignature,
  useRemoteConfirmSignature,
  useRemoteInitiateSignature,
  useRevokeExternalSignerInvite,
  useSignatureProviders,
  useUpdateExternalSigningEnvelope,
  useXadesSign,
} from '../../api/hooks';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import { GateButton, scopeBook, useCan, type CanScope } from '../session/permissions';
import { useT, type TFunction } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  DateTime,
  Digest,
  EmptyState,
  ErrorNote,
  Field,
  FieldHelp,
  Icon,
  InlineWarning,
  Input,
  Select,
  Skeleton,
  Table,
  TextArea,
  useToast,
} from '../../ui';

/** The serialized signing family a Cartão de Cidadão signature reports (t58-e2). */
const FAMILY_CC = 'CartaoDeCidadao';
/** The serialized signing family a CSC QTSP signature reports (t59-S3). */
const FAMILY_CSC = 'QualifiedCertificate';
/** The serialized signing family for local PKCS#12/PFX software-certificate signatures. */
const FAMILY_LOCAL_PKCS12 = 'LocalPkcs12SoftwareCertificate';
/** The serialized family for official Autenticação.gov/provider handoff imports. */
const FAMILY_OFFICIAL_HANDOFF = 'AutenticacaoGovOfficialHandoff';
/** The built-in Chave Móvel Digital provider id (its `{provider}` path segment). */
const CMD_PROVIDER_ID = 'cmd';

/** Slugify an entity/title fragment for a filesystem-friendly download name. */
export function signingDownloadSlug(value: string): string {
  return (
    value
      .normalize('NFD')
      .replace(/[̀-ͯ]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'documento'
  );
}

export function evidenceLevelLabel(level: string, t: TFunction): string {
  if (level === 'Unsigned') return t('signing.evidence.level.unsigned');
  if (level === 'B-B') return 'PAdES B-B';
  if (level === 'B-T') return 'PAdES B-T';
  if (level === 'B-LT-local') return 'PAdES B-LT local';
  if (level === 'B-LTA-local') return 'PAdES B-LTA local';
  return level;
}

export function longTermEvidenceLabel(status: string, t: TFunction): string {
  if (status === 'timestamped') return t('signing.evidence.longTerm.timestamped');
  if (status === 'not_configured') return t('signing.evidence.longTerm.notConfigured');
  if (status === 'lt_local_technical_evidence')
    return t('signing.evidence.longTerm.ltLocalTechnical');
  if (status === 'lt_local_technical_evidence_partial')
    return t('signing.evidence.longTerm.ltLocalTechnicalPartial');
  if (status === 'lta_local_technical_evidence')
    return t('signing.evidence.longTerm.ltaLocalTechnical');
  if (status === 'lta_local_technical_evidence_partial')
    return t('signing.evidence.longTerm.ltaLocalTechnicalPartial');
  if (status === 'lt_not_implemented') return t('signing.evidence.longTerm.ltNotImplemented');
  if (status === 'lta_not_implemented') return t('signing.evidence.longTerm.ltaNotImplemented');
  return status;
}

export function renewalPlanActionLabel(action: string, t: TFunction): string {
  if (action === 'none') return t('signing.evidence.renewal.action.none');
  if (action === 'manual_review') return t('signing.evidence.renewal.action.manualReview');
  if (action === 'add_signature_timestamp')
    return t('signing.evidence.renewal.action.addSignatureTimestamp');
  if (action === 'embed_dss_revocation_evidence')
    return t('signing.evidence.renewal.action.embedDssRevocationEvidence');
  if (action === 'record_dss_validation_time')
    return t('signing.evidence.renewal.action.recordDssValidationTime');
  if (action === 'add_document_timestamp')
    return t('signing.evidence.renewal.action.addDocumentTimestamp');
  if (action === 'record_signature_dss_validation_time')
    return t('signing.evidence.renewal.action.recordSignatureDssValidationTime');
  return action;
}

export function dssEvidenceLabel(evidence: SignatureEvidenceStatus, t: TFunction): string {
  if (evidence.dss_revocation_evidence_present) return t('signing.evidence.dss.present');
  if (evidence.dss_revocation_evidence_status === 'unsupported')
    return t('signing.evidence.dss.unsupported');
  if (evidence.dss_revocation_evidence_status === 'not_present')
    return t('signing.evidence.dss.notPresent');
  return evidence.dss_revocation_evidence_status;
}

export function trustedListLabel(status: string, t: TFunction): string {
  if (status === 'Granted') return t('signing.trustedList.granted');
  if (status === 'Withdrawn') return t('signing.trustedList.withdrawn');
  if (status === 'Unknown') return t('signing.trustedList.unknown');
  return status;
}

export function trustedListTone(status: string): 'ok' | 'warn' {
  return status === 'Granted' ? 'ok' : 'warn';
}

export function isCcPinRejection(error: unknown): error is ApiError {
  return (
    error instanceof ApiError &&
    error.status === 422 &&
    (error.pinStatus === 'wrong_pin' || error.pinStatus === 'blocked')
  );
}

export function officialImportGuardrailLabel(
  guardrail: OfficialSignatureImportGuardrail,
  t: TFunction,
): string {
  switch (guardrail) {
    case 'official_import_preserves_uploaded_signed_pdf_as_technical_evidence':
      return t('signing.official.guardrails.preserve');
    case 'official_import_trust_validation_not_performed':
      return t('signing.official.guardrails.trust');
    case 'official_import_qualified_status_not_claimed':
      return t('signing.official.guardrails.qualified');
    case 'official_import_legal_status_not_claimed':
      return t('signing.official.guardrails.legal');
    case 'official_import_no_secret_factor_collected':
      return t('signing.official.guardrails.noSecret');
    default:
      return guardrail;
  }
}

export function evidenceLevelTone(level: string): 'neutral' | 'accent' | 'ok' {
  if (level === 'B-LT-local' || level === 'B-LTA-local') return 'ok';
  if (level === 'B-T') return 'ok';
  if (level === 'B-B') return 'accent';
  return 'neutral';
}

export function evidenceTimestampLabel(evidence: SignatureEvidenceStatus, t: TFunction): string {
  return evidence.timestamp_evidence_present
    ? t('signing.evidence.timestamp.present')
    : t('signing.evidence.timestamp.absent');
}

export function evidenceTimestampTone(evidence: SignatureEvidenceStatus): 'ok' | 'neutral' {
  return evidence.timestamp_evidence_present ? 'ok' : 'neutral';
}

export function toLocalDateTimeInput(date: Date): string {
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

export function defaultInviteExpiryInput(): string {
  return toLocalDateTimeInput(new Date(Date.now() + 2 * 24 * 60 * 60 * 1000));
}

export function dateTimeInputToIso(value: string): string {
  return new Date(value).toISOString();
}

export function externalInviteLink(token: string): string {
  const path = `/external-signature?token=${encodeURIComponent(token)}`;
  if (typeof window === 'undefined') return path;
  return new URL(path, window.location.origin).toString();
}

/**
 * The signing format the user selects. `pades` is the qualified act-signing lane (the existing
 * provider picker, which signs the act's sealed PDF in place). `xades`/`asic`/`scap` are local
 * technical tools that produce a downloadable document over the act's PDF/A without changing act
 * state; each is co-location-gated server-side.
 */
type SigningFormat = 'pades' | 'xades' | 'asic' | 'scap';

/** Trigger a browser download of local-tool output bytes with an honest filename. */
function downloadToolBytes(
  base64: string,
  filename: string,
  contentType: string,
  toast: ReturnType<typeof useToast>,
) {
  saveBlobAs({
    blob: new Blob([base64ToBytes(base64) as BlobPart], { type: contentType }),
    filename,
    contentType,
    preferBrowserSavePicker: true,
  })
    .then((result) => {
      if (result.kind === 'cancelled') toast.info(saveBlobResultMessage(result));
      else toast.success(saveBlobResultMessage(result));
    })
    .catch((err) => toast.error(err));
}

/**
 * Local XAdES production tool. Signs the act's sealed PDF/A with a co-located PKCS#12 and returns a
 * XAdES-B/T document. Co-location-gated (409 off-host → honest note). Only B/T are offered — LT/LTA
 * are rejected by the backend, stated honestly rather than shown as a false capability.
 */
function XadesToolForm({ loadContentBase64 }: { loadContentBase64: () => Promise<string> }) {
  const t = useT();
  const toast = useToast();
  const xadesSign = useXadesSign();
  const [packaging, setPackaging] = useState<XadesPackaging>('detached');
  const [level, setLevel] = useState<LocalSignatureLevel>('B');
  const [signer, setSigner] = useState<Pkcs12SignerState>(emptyPkcs12Signer);
  const [error, setError] = useState<unknown>(null);
  const [coLocationBlocked, setCoLocationBlocked] = useState(false);
  const [result, setResult] = useState<XadesSignResponse | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!signer.file || signer.passphrase.length === 0 || xadesSign.isPending) return;
    setError(null);
    try {
      const [contentBase64, pkcs12Base64] = await Promise.all([
        loadContentBase64(),
        fileToBase64(signer.file),
      ]);
      const response = await xadesSign.mutateAsync({
        content_base64: contentBase64,
        content_name: 'ata.pdf',
        packaging,
        level,
        signer: {
          kind: 'soft_pkcs12',
          pkcs12_base64: pkcs12Base64,
          passphrase: signer.passphrase,
          friendly_name: signer.friendlyName.trim() || undefined,
        },
      });
      setSigner(emptyPkcs12Signer());
      setResult(response);
      toast.success(t('signing.xades.result.title'));
    } catch (err) {
      setSigner(emptyPkcs12Signer());
      setError(err);
      if (err instanceof ApiError && err.status === 409) setCoLocationBlocked(true);
      toast.error(err);
    } finally {
      xadesSign.reset();
    }
  }

  return (
    <form className="form" onSubmit={onSubmit}>
      <InlineWarning tone="info" title={t('signing.xades.title')}>
        {t('signing.xades.intro')}
      </InlineWarning>
      <p className="field__hint">{t('signing.tool.content.note')}</p>
      <div className="form__grid">
        <Field label={t('signing.xades.packaging.label')} htmlFor="xades-packaging">
          <Select
            id="xades-packaging"
            value={packaging}
            onChange={(event) => setPackaging(event.target.value as XadesPackaging)}
            options={[
              { value: 'detached', label: t('signing.xades.packaging.detached') },
              { value: 'enveloping', label: t('signing.xades.packaging.enveloping') },
            ]}
          />
        </Field>
        <Field
          label={t('signing.xades.level.label')}
          htmlFor="xades-level"
          hint={t('signing.xades.level.note')}
        >
          <Select
            id="xades-level"
            value={level}
            onChange={(event) => setLevel(event.target.value as LocalSignatureLevel)}
            options={[
              { value: 'B', label: t('signing.xades.level.b') },
              { value: 'T', label: t('signing.xades.level.t') },
            ]}
          />
        </Field>
      </div>
      {coLocationBlocked ? (
        <InlineWarning tone="info" title={t('signing.tool.coLocation.title')}>
          {t('signing.tool.coLocation.body')}
        </InlineWarning>
      ) : (
        <Pkcs12SignerFields
          idPrefix="xades"
          signer={signer}
          disabled={xadesSign.isPending}
          onChange={(patch) => setSigner((current) => ({ ...current, ...patch }))}
        />
      )}
      {error ? <ErrorNote error={error} /> : null}
      {!coLocationBlocked ? (
        <div className="rowline">
          <Button
            type="submit"
            variant="primary"
            icon={<Icon.PenNib />}
            disabled={!signer.file || signer.passphrase.length === 0 || xadesSign.isPending}
          >
            {xadesSign.isPending ? t('signing.xades.submitting') : t('signing.xades.submit')}
          </Button>
        </div>
      ) : null}
      {result ? (
        <section className="signing-status signing-status--ok">
          <div className="signing-status__icon" aria-hidden="true">
            <Icon.Check />
          </div>
          <div className="signing-status__body">
            <p className="signing-status__title">{t('signing.xades.result.title')}</p>
            <dl className="deflist signing-deflist signing-deflist--compact">
              <div>
                <dt>{t('signing.xades.result.level')}</dt>
                <dd>{result.level}</dd>
              </div>
              <div>
                <dt>{t('signing.xades.result.packaging')}</dt>
                <dd>{result.packaging}</dd>
              </div>
              <div>
                <dt>{t('signing.xades.result.algorithm')}</dt>
                <dd>{result.signature_algorithm}</dd>
              </div>
              <div>
                <dt>{t('signing.tool.result.signer')}</dt>
                <dd className="mono">{result.signer_cert_subject ?? '—'}</dd>
              </div>
              <div>
                <dt>{t('signing.tool.result.contentDigest')}</dt>
                <dd>
                  <Digest value={result.content_sha256} />
                </dd>
              </div>
              <div className="signing-deflist__wide">
                <dt>{t('signing.tool.legalNotice.title')}</dt>
                <dd>{result.legal_notice}</dd>
              </div>
            </dl>
            <Button
              type="button"
              variant="secondary"
              icon={<Icon.FileText />}
              onClick={() =>
                downloadToolBytes(result.xades_base64, 'ata-xades.xml', 'application/xml', toast)
              }
            >
              {t('signing.tool.download')}
            </Button>
          </div>
        </section>
      ) : null}
    </form>
  );
}

/**
 * Local ASiC container tool. Signs the act's sealed PDF/A payload with a co-located PKCS#12 and
 * returns an ASiC-S (single XAdES) or ASiC-E (single CAdES/XAdES signer here) container.
 * Co-location-gated. Only XAdES levels B/T are offered; the archive timestamp applies to ASiC-E only.
 */
function AsicToolForm({ loadContentBase64 }: { loadContentBase64: () => Promise<string> }) {
  const t = useT();
  const toast = useToast();
  const asicSign = useAsicSign();
  const [container, setContainer] = useState<AsicContainer>('asic_s_xades');
  const [level, setLevel] = useState<LocalSignatureLevel>('B');
  const [role, setRole] = useState<AsicSignerRole>('xades');
  const [archiveTimestamp, setArchiveTimestamp] = useState(false);
  const [signer, setSigner] = useState<Pkcs12SignerState>(emptyPkcs12Signer);
  const [error, setError] = useState<unknown>(null);
  const [coLocationBlocked, setCoLocationBlocked] = useState(false);
  const [result, setResult] = useState<AsicSignResponse | null>(null);

  const isAsicE = container === 'asic_e_multi';

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!signer.file || signer.passphrase.length === 0 || asicSign.isPending) return;
    setError(null);
    try {
      const [contentBase64, pkcs12Base64] = await Promise.all([
        loadContentBase64(),
        fileToBase64(signer.file),
      ]);
      const response = await asicSign.mutateAsync({
        container,
        xades_level: level,
        archive_timestamp: isAsicE ? archiveTimestamp : false,
        payloads: [
          { name: 'ata.pdf', content_base64: contentBase64, mime_type: 'application/pdf' },
        ],
        signers: [
          {
            // ASiC-S is always XAdES; the role only matters for ASiC-E.
            role: isAsicE ? role : 'xades',
            pkcs12_base64: pkcs12Base64,
            passphrase: signer.passphrase,
            friendly_name: signer.friendlyName.trim() || undefined,
          },
        ],
      });
      setSigner(emptyPkcs12Signer());
      setResult(response);
      toast.success(t('signing.asic.result.title'));
    } catch (err) {
      setSigner(emptyPkcs12Signer());
      setError(err);
      if (err instanceof ApiError && err.status === 409) setCoLocationBlocked(true);
      toast.error(err);
    } finally {
      asicSign.reset();
    }
  }

  return (
    <form className="form" onSubmit={onSubmit}>
      <InlineWarning tone="info" title={t('signing.asic.title')}>
        {t('signing.asic.intro')}
      </InlineWarning>
      <p className="field__hint">{t('signing.tool.content.note')}</p>
      <div className="form__grid">
        <Field label={t('signing.asic.container.label')} htmlFor="asic-container">
          <Select
            id="asic-container"
            value={container}
            onChange={(event) => setContainer(event.target.value as AsicContainer)}
            options={[
              { value: 'asic_s_xades', label: t('signing.asic.container.asicS') },
              { value: 'asic_e_multi', label: t('signing.asic.container.asicE') },
            ]}
          />
        </Field>
        <Field
          label={t('signing.asic.level.label')}
          htmlFor="asic-level"
          hint={t('signing.xades.level.note')}
        >
          <Select
            id="asic-level"
            value={level}
            onChange={(event) => setLevel(event.target.value as LocalSignatureLevel)}
            options={[
              { value: 'B', label: t('signing.xades.level.b') },
              { value: 'T', label: t('signing.xades.level.t') },
            ]}
          />
        </Field>
        {isAsicE ? (
          <Field
            label={t('signing.asic.role.label')}
            htmlFor="asic-role"
            hint={t('signing.asic.role.hint')}
          >
            <Select
              id="asic-role"
              value={role}
              onChange={(event) => setRole(event.target.value as AsicSignerRole)}
              options={[
                { value: 'xades', label: t('signing.asic.role.xades') },
                { value: 'cades', label: t('signing.asic.role.cades') },
              ]}
            />
          </Field>
        ) : null}
      </div>
      {isAsicE ? (
        <label className="checkline" htmlFor="asic-archive-timestamp">
          <input
            id="asic-archive-timestamp"
            type="checkbox"
            checked={archiveTimestamp}
            disabled={asicSign.isPending}
            onChange={(event) => setArchiveTimestamp(event.target.checked)}
          />
          {t('signing.asic.archiveTimestamp.label')}
        </label>
      ) : null}
      {isAsicE ? <p className="field__hint">{t('signing.asic.archiveTimestamp.hint')}</p> : null}
      {coLocationBlocked ? (
        <InlineWarning tone="info" title={t('signing.tool.coLocation.title')}>
          {t('signing.tool.coLocation.body')}
        </InlineWarning>
      ) : (
        <Pkcs12SignerFields
          idPrefix="asic"
          signer={signer}
          disabled={asicSign.isPending}
          onChange={(patch) => setSigner((current) => ({ ...current, ...patch }))}
        />
      )}
      {error ? <ErrorNote error={error} /> : null}
      {!coLocationBlocked ? (
        <div className="rowline">
          <Button
            type="submit"
            variant="primary"
            icon={<Icon.PenNib />}
            disabled={!signer.file || signer.passphrase.length === 0 || asicSign.isPending}
          >
            {asicSign.isPending ? t('signing.asic.submitting') : t('signing.asic.submit')}
          </Button>
        </div>
      ) : null}
      {result ? (
        <section className="signing-status signing-status--ok">
          <div className="signing-status__icon" aria-hidden="true">
            <Icon.Check />
          </div>
          <div className="signing-status__body">
            <p className="signing-status__title">{t('signing.asic.result.title')}</p>
            <dl className="deflist signing-deflist signing-deflist--compact">
              <div>
                <dt>{t('signing.asic.result.container')}</dt>
                <dd>{result.container}</dd>
              </div>
              <div>
                <dt>{t('signing.asic.result.level')}</dt>
                <dd>{result.xades_level}</dd>
              </div>
              <div>
                <dt>{t('signing.asic.result.signatures')}</dt>
                <dd>
                  {t('signing.asic.result.signatures', {
                    cades: result.cades_signature_count,
                    xades: result.xades_signature_count,
                  })}
                </dd>
              </div>
              <div>
                <dt>{t('signing.asic.result.archiveTimestamp')}</dt>
                <dd>{result.archive_timestamp ? t('common.yes') : t('common.no')}</dd>
              </div>
              <div className="signing-deflist__wide">
                <dt>{t('signing.tool.legalNotice.title')}</dt>
                <dd>{result.legal_notice}</dd>
              </div>
            </dl>
            <Button
              type="button"
              variant="secondary"
              icon={<Icon.FileText />}
              onClick={() =>
                downloadToolBytes(
                  result.asic_base64,
                  container === 'asic_s_xades' ? 'ata.asics' : 'ata.asice',
                  'application/vnd.etsi.asic-e+zip',
                  toast,
                )
              }
            >
              {t('signing.tool.download')}
            </Button>
          </div>
        </section>
      ) : null}
    </form>
  );
}

/**
 * The chosen two-phase provider: `cmd` drives the dedicated `/signature/cmd/*` path; `csc`
 * drives the generic `/signature/remote/{id}/*` path. `label` names it in the prompts.
 */
type SigningProvider = { id: string; kind: 'cmd' | 'csc'; label: string };

/** The built-in CMD provider descriptor (its labels are fixed; `label` is unused for CMD). */
const CMD_PROVIDER: SigningProvider = { id: CMD_PROVIDER_ID, kind: 'cmd', label: 'CMD' };

export function providerFromPending(
  pending: PendingSignatureInfo,
  availableProviders: SignatureProviderView[],
): SigningProvider {
  if (!pending.provider_id || pending.provider_id === CMD_PROVIDER_ID) return CMD_PROVIDER;
  const provider = availableProviders.find((p) => p.id === pending.provider_id);
  return {
    id: pending.provider_id,
    kind: 'csc',
    label: provider?.label ?? pending.provider_id,
  };
}

/**
 * The active step of the local flow (server-authoritative status backs the rest). CMD and CSC
 * are two-phase (`credentials` → `otp`); CC is a single synchronous prompt (`cc`).
 */
type Step =
  | { kind: 'view' }
  | { kind: 'credentials'; provider: SigningProvider }
  | { kind: 'otp'; provider: SigningProvider; sessionId: string; hint: string }
  | { kind: 'cc' }
  | { kind: 'pkcs12' }
  | { kind: 'officialImport' };

type EnvelopeSlotFormRow = {
  id: string;
  signerLabel: string;
  contactHint: string;
  identityRequirement: '' | ExternalSignerIdentityRequirement;
  required: boolean;
};

type InviteSlotOption = {
  value: string;
  envelopeId: string;
  slotId: string;
  label: string;
  status: ExternalSignerSlotStatus;
};

type SlotEvidenceFormState = {
  label: string;
  reference: string;
  digest: string;
  identityReferences: Partial<Record<ExternalSignerIdentityRequirement, string>>;
};

type RecordingSlot = {
  envelopeId: string;
  slotId: string;
};

function newEnvelopeSlotFormRow(): EnvelopeSlotFormRow {
  return {
    id: globalThis.crypto?.randomUUID?.() ?? String(Date.now() + Math.random()),
    signerLabel: '',
    contactHint: '',
    identityRequirement: '',
    required: true,
  };
}

function SignatureEvidenceSummary({ evidence }: { evidence: SignatureEvidenceStatus }) {
  const t = useT();
  const longTerm = evidence.long_term_status.map((status) => longTermEvidenceLabel(status, t));
  const multiRenewalPlan = evidence.multi_signature_local_renewal_plan;
  const showMultiRenewalPlan = multiRenewalPlan?.status === 'available';
  const gapIndexes = multiRenewalPlan?.signatures_with_local_evidence_gaps ?? [];
  return (
    <section className="signing-evidence" aria-label={t('signing.evidence.aria')}>
      <div className="signing-evidence__head">
        <div>
          <p className="signing-kicker">{t('signing.evidence.kicker')}</p>
          <p className="signing-evidence__title">{t('signing.evidence.title')}</p>
        </div>
        <div className="signing-evidence__badges" aria-label={t('signing.evidence.summary.aria')}>
          <Badge tone={evidenceLevelTone(evidence.current_level)}>
            {evidenceLevelLabel(evidence.current_level, t)}
          </Badge>
          <Badge tone={evidenceTimestampTone(evidence)}>
            {evidenceTimestampLabel(evidence, t)}
          </Badge>
        </div>
      </div>
      <dl className="deflist signing-deflist signing-deflist--compact">
        <div>
          <dt>
            {t('signing.evidence.observedLevel')}
            <FieldHelp text={t('signing.evidence.observedLevel.help')} placement="bottom" />
          </dt>
          <dd>{evidenceLevelLabel(evidence.current_level, t)}</dd>
        </div>
        <div>
          <dt>
            {t('signing.evidence.dss.label')}
            <FieldHelp text={t('signing.evidence.dss.help')} placement="bottom" />
          </dt>
          <dd>{dssEvidenceLabel(evidence, t)}</dd>
        </div>
        <div className="signing-deflist__wide">
          <dt>
            {t('signing.evidence.longTerm.label')}
            <FieldHelp text={t('signing.evidence.longTerm.help')} placement="bottom" />
          </dt>
          <dd>
            {longTerm.length ? (
              <span className="signing-chipline">
                {longTerm.map((item) => (
                  <span className="signing-chip" key={item}>
                    {item}
                  </span>
                ))}
              </span>
            ) : (
              t('signing.evidence.noDetails')
            )}
          </dd>
        </div>
        {showMultiRenewalPlan ? (
          <>
            <div>
              <dt>{t('signing.evidence.renewal.signatures')}</dt>
              <dd>{multiRenewalPlan.signature_count}</dd>
            </div>
            <div>
              <dt>{t('signing.evidence.renewal.gaps')}</dt>
              <dd>
                {t('signing.evidence.renewal.gapSummary', {
                  count: gapIndexes.length,
                  indexes: gapIndexes.length
                    ? gapIndexes.join(', ')
                    : t('signing.evidence.renewal.noGapIndexes'),
                })}
              </dd>
            </div>
            <div>
              <dt>{t('signing.evidence.renewal.nextAction')}</dt>
              <dd>{renewalPlanActionLabel(multiRenewalPlan.next_action, t)}</dd>
            </div>
            <div className="signing-deflist__wide">
              <dt>{t('signing.evidence.renewal.scope')}</dt>
              <dd>
                {multiRenewalPlan.legal_ltv_claimed ||
                multiRenewalPlan.production_long_term_profile_claimed
                  ? t('signing.evidence.renewal.guardrailUnexpected')
                  : t('signing.evidence.renewal.guardrail')}
              </dd>
            </div>
          </>
        ) : null}
      </dl>
      <p className="field__hint">{t('signing.evidence.disclaimer')}</p>
    </section>
  );
}

type TechnicalComparisonKind =
  'match' | 'present' | 'partial' | 'unavailable' | 'mismatch' | 'notClaimed' | 'loading';

type TechnicalComparisonTone = 'neutral' | 'accent' | 'warn' | 'error' | 'ok';

export function hasMetadata(value: string | null | undefined): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

export function sameMetadata(
  left: string | null | undefined,
  right: string | null | undefined,
): boolean {
  return (
    hasMetadata(left) &&
    hasMetadata(right) &&
    left.trim().toLowerCase() === right.trim().toLowerCase()
  );
}

export function comparisonStatus(
  kind: TechnicalComparisonKind,
  t: TFunction,
): { tone: TechnicalComparisonTone; label: string } {
  switch (kind) {
    case 'match':
      return { tone: 'accent', label: t('signing.technicalComparison.status.match') };
    case 'present':
      return { tone: 'neutral', label: t('signing.technicalComparison.status.present') };
    case 'partial':
      return { tone: 'warn', label: t('signing.technicalComparison.status.partial') };
    case 'mismatch':
      return { tone: 'error', label: t('signing.technicalComparison.status.mismatch') };
    case 'notClaimed':
      return { tone: 'neutral', label: t('signing.technicalComparison.status.notClaimed') };
    case 'loading':
      return { tone: 'neutral', label: t('signing.technicalComparison.status.loading') };
    case 'unavailable':
    default:
      return { tone: 'warn', label: t('signing.technicalComparison.status.unavailable') };
  }
}

export function technicalComparisonFamilyLabel(family: string, t: TFunction): string {
  if (family === FAMILY_OFFICIAL_HANDOFF) return t('signing.official.family');
  return signatureFamilyLabels[family as SignatureFamily] ?? family;
}

function TechnicalComparisonPanel({
  act,
  signed,
  bundle,
  bundleLoading,
  bundleError,
}: {
  act: ActView;
  signed: SignedSignatureInfo;
  bundle?: DocumentBundle;
  bundleLoading: boolean;
  bundleError: unknown;
}) {
  const t = useT();
  const bundleReady = !!bundle && !bundleError;
  const bundleMissingKind: TechnicalComparisonKind =
    bundleLoading && !bundle ? 'loading' : 'unavailable';
  const report = bundle?.validation_report;
  const consistency = report?.bundle_document_consistency;
  const fixity = report?.fixity;
  const signedDocument = report?.signed_document;
  const signingSnapshotDigest = act.seal_metadata?.signing_snapshot_digest ?? act.payload_digest;

  function textValue(value: string | number | null | undefined): React.ReactNode {
    if (typeof value === 'number') return value;
    return hasMetadata(value) ? value : t('signing.technicalComparison.detail.notSupplied');
  }

  function digestValue(value: string | null | undefined): React.ReactNode {
    return hasMetadata(value) ? (
      <Digest value={value} copyable={false} />
    ) : (
      t('signing.technicalComparison.detail.notSupplied')
    );
  }

  function boolValue(value: boolean | null | undefined): string {
    if (value == null) return t('signing.technicalComparison.detail.notSupplied');
    return value ? t('common.yes') : t('common.no');
  }

  function Detail({
    label,
    children,
  }: {
    label: string;
    children: React.ReactNode;
  }): React.ReactElement {
    return (
      <span className="signing-chip">
        {label}: {children}
      </span>
    );
  }

  const actIdCandidates = [
    bundle?.act_id,
    consistency?.route_act_id,
    consistency?.stored_document_act_id,
  ].filter(hasMetadata);
  const actIdKind: TechnicalComparisonKind = !bundleReady
    ? bundleMissingKind
    : actIdCandidates.length > 0 && actIdCandidates.every((id) => id === act.id)
      ? 'match'
      : 'mismatch';

  const canonicalDigestCandidates = [
    bundle?.document.pdf_digest,
    fixity?.canonical_pdf_sha256,
    fixity?.stored_pdf_digest,
  ].filter(hasMetadata);
  const canonicalDigestKind: TechnicalComparisonKind = !bundleReady
    ? bundleMissingKind
    : fixity?.canonical_pdf_digest_matches_metadata === false ||
        (canonicalDigestCandidates.length > 1 &&
          !canonicalDigestCandidates.every((value) =>
            sameMetadata(value, canonicalDigestCandidates[0]),
          ))
      ? 'mismatch'
      : canonicalDigestCandidates.length === 0
        ? 'unavailable'
        : fixity?.canonical_pdf_digest_matches_metadata === true ||
            canonicalDigestCandidates.length > 1
          ? 'match'
          : 'partial';

  const bundleSignedDigestCandidates = [
    signedDocument?.signed_pdf_digest,
    fixity?.signed_pdf_sha256,
    fixity?.stored_signed_pdf_digest,
  ].filter(hasMetadata);
  const signedDigestMismatched =
    signedDocument?.signed_pdf_digest_matches_metadata === false ||
    fixity?.signed_pdf_digest_matches_metadata === false ||
    bundleSignedDigestCandidates.some((value) => !sameMetadata(signed.signed_pdf_digest, value));
  const signedDigestKind: TechnicalComparisonKind = !bundleReady
    ? bundleMissingKind
    : signedDocument?.present === false
      ? 'unavailable'
      : signedDigestMismatched
        ? 'mismatch'
        : bundleSignedDigestCandidates.length > 0
          ? 'match'
          : 'unavailable';

  const signedDocumentHasId = hasMetadata(signedDocument?.document_id);
  const signedDocumentHasDownload = hasMetadata(signedDocument?.download);
  const signedDocumentKind: TechnicalComparisonKind = !bundleReady
    ? bundleMissingKind
    : signedDocument?.present === false || !signedDocument
      ? 'unavailable'
      : signedDocumentHasId && signedDocumentHasDownload
        ? 'present'
        : 'partial';

  const signingTimeKind: TechnicalComparisonKind = !bundleReady
    ? bundleMissingKind
    : !hasMetadata(signedDocument?.signing_time)
      ? 'unavailable'
      : sameMetadata(signed.signing_time, signedDocument.signing_time)
        ? 'match'
        : 'mismatch';

  const familyMatches = hasMetadata(signedDocument?.stored_signature_family)
    ? sameMetadata(signed.family, signedDocument.stored_signature_family)
    : null;
  const levelMatches = hasMetadata(signedDocument?.stored_evidentiary_level)
    ? sameMetadata(signed.evidentiary_level, signedDocument.stored_evidentiary_level)
    : null;
  const trustListCompared =
    hasMetadata(signed.trusted_list_status) || hasMetadata(signedDocument?.trusted_list_status);
  const trustListMatches = trustListCompared
    ? sameMetadata(signed.trusted_list_status, signedDocument?.trusted_list_status)
    : null;
  const signatureMetadataChecks = [familyMatches, levelMatches, trustListMatches].filter(
    (value): value is boolean => value != null,
  );
  const signatureMetadataKind: TechnicalComparisonKind = !bundleReady
    ? bundleMissingKind
    : signatureMetadataChecks.some((value) => !value)
      ? 'mismatch'
      : signatureMetadataChecks.length === 0 && !hasMetadata(signedDocument?.status)
        ? 'unavailable'
        : signatureMetadataChecks.length < (trustListCompared ? 3 : 2)
          ? 'partial'
          : 'match';

  const attachmentsWithoutDigest = fixity?.attachments_without_digest ?? null;
  const fixityFlags = [
    fixity?.canonical_pdf_digest_matches_metadata,
    fixity?.signed_pdf_digest_matches_metadata,
    signedDocument?.document_id_matches_canonical,
  ];
  const bundleFixityKind: TechnicalComparisonKind = !bundleReady
    ? bundleMissingKind
    : fixityFlags.some((value) => value === false) ||
        (attachmentsWithoutDigest != null && attachmentsWithoutDigest > 0)
      ? 'mismatch'
      : fixityFlags.some((value) => value == null)
        ? 'partial'
        : 'match';

  const rows: {
    key: string;
    label: string;
    kind: TechnicalComparisonKind;
    wide?: boolean;
    details: React.ReactNode[];
  }[] = [
    {
      key: 'act-id',
      label: t('signing.technicalComparison.row.actId'),
      kind: actIdKind,
      details: [
        <Detail key="act" label={t('signing.technicalComparison.detail.act')}>
          {act.id}
        </Detail>,
        <Detail key="bundle" label={t('signing.technicalComparison.detail.bundle')}>
          {textValue(bundle?.act_id)}
        </Detail>,
        <Detail key="document" label={t('signing.technicalComparison.detail.document')}>
          {textValue(consistency?.stored_document_act_id)}
        </Detail>,
      ],
    },
    {
      key: 'signing-snapshot-digest',
      label: t('signing.technicalComparison.row.signingSnapshotDigest'),
      kind: hasMetadata(signingSnapshotDigest) ? 'present' : 'unavailable',
      details: [
        <Detail key="act" label={t('signing.technicalComparison.detail.act')}>
          {digestValue(signingSnapshotDigest)}
        </Detail>,
      ],
    },
    {
      key: 'canonical-digest',
      label: t('signing.technicalComparison.row.canonicalPdfDigest'),
      kind: canonicalDigestKind,
      wide: true,
      details: [
        <Detail key="document" label={t('signing.technicalComparison.detail.document')}>
          {digestValue(bundle?.document.pdf_digest)}
        </Detail>,
        <Detail key="report" label={t('signing.technicalComparison.detail.report')}>
          {digestValue(fixity?.canonical_pdf_sha256)}
        </Detail>,
        <Detail key="flag" label={t('signing.technicalComparison.detail.metadataFlag')}>
          {boolValue(fixity?.canonical_pdf_digest_matches_metadata)}
        </Detail>,
      ],
    },
    {
      key: 'signed-digest',
      label: t('signing.technicalComparison.row.signedPdfDigest'),
      kind: signedDigestKind,
      wide: true,
      details: [
        <Detail key="signature" label={t('signing.technicalComparison.detail.signature')}>
          {digestValue(signed.signed_pdf_digest)}
        </Detail>,
        <Detail key="report" label={t('signing.technicalComparison.detail.report')}>
          {digestValue(signedDocument?.signed_pdf_digest)}
        </Detail>,
        <Detail key="fixity" label={t('signing.technicalComparison.detail.fixity')}>
          {digestValue(fixity?.signed_pdf_sha256)}
        </Detail>,
      ],
    },
    {
      key: 'signed-document',
      label: t('signing.technicalComparison.row.signedDocument'),
      kind: signedDocumentKind,
      details: [
        <Detail key="document" label={t('signing.technicalComparison.detail.document')}>
          {textValue(signedDocument?.document_id)}
        </Detail>,
        <Detail key="download" label={t('signing.technicalComparison.detail.download')}>
          {signedDocumentHasDownload
            ? t('signing.technicalComparison.detail.present')
            : t('signing.technicalComparison.detail.notSupplied')}
        </Detail>,
      ],
    },
    {
      key: 'signing-time',
      label: t('signing.signed.signingTime'),
      kind: signingTimeKind,
      details: [
        // Signing times are the evidence being compared here, so they carry seconds and zone.
        <Detail key="signature" label={t('signing.technicalComparison.detail.signature')}>
          <DateTime value={signed.signing_time} evidentiary />
        </Detail>,
        <Detail key="report" label={t('signing.technicalComparison.detail.report')}>
          {hasMetadata(signedDocument?.signing_time) ? (
            <DateTime value={signedDocument.signing_time} evidentiary />
          ) : (
            t('signing.technicalComparison.detail.notSupplied')
          )}
        </Detail>,
        <Detail key="signed-at" label={t('signing.technicalComparison.detail.signedAt')}>
          {hasMetadata(signedDocument?.signed_at) ? (
            <DateTime value={signedDocument.signed_at} evidentiary />
          ) : (
            t('signing.technicalComparison.detail.notSupplied')
          )}
        </Detail>,
      ],
    },
    {
      key: 'signature-metadata',
      label: t('signing.technicalComparison.row.signatureMetadata'),
      kind: signatureMetadataKind,
      wide: true,
      details: [
        <Detail key="family" label={t('signing.signed.family')}>
          {technicalComparisonFamilyLabel(signed.family, t)}
        </Detail>,
        <Detail key="report-family" label={t('signing.technicalComparison.detail.report')}>
          {hasMetadata(signedDocument?.stored_signature_family)
            ? technicalComparisonFamilyLabel(signedDocument.stored_signature_family, t)
            : t('signing.technicalComparison.detail.notSupplied')}
        </Detail>,
        <Detail key="level" label={t('signing.xades.level.label')}>
          {textValue(signedDocument?.stored_evidentiary_level ?? signed.evidentiary_level)}
        </Detail>,
        <Detail key="status" label={t('signing.technicalComparison.detail.status')}>
          {textValue(signedDocument?.status)}
        </Detail>,
        <Detail key="trust" label={t('signing.signed.trustedList')}>
          {hasMetadata(signed.trusted_list_status)
            ? trustedListLabel(signed.trusted_list_status, t)
            : t('signing.technicalComparison.detail.notSupplied')}
        </Detail>,
      ],
    },
    {
      key: 'bundle-fixity',
      label: t('signing.technicalComparison.row.bundleFixity'),
      kind: bundleFixityKind,
      wide: true,
      details: [
        <Detail key="canonical" label={t('signing.technicalComparison.row.canonicalPdfDigest')}>
          {boolValue(fixity?.canonical_pdf_digest_matches_metadata)}
        </Detail>,
        <Detail key="signed" label={t('signing.technicalComparison.row.signedPdfDigest')}>
          {boolValue(fixity?.signed_pdf_digest_matches_metadata)}
        </Detail>,
        <Detail key="document-id" label={t('signing.technicalComparison.detail.documentId')}>
          {boolValue(signedDocument?.document_id_matches_canonical)}
        </Detail>,
        <Detail key="attachments" label={t('signing.technicalComparison.detail.attachments')}>
          {fixity
            ? `${fixity.attachments_with_digest}/${fixity.attachment_count} · ${fixity.attachments_without_digest} ${t(
                'signing.technicalComparison.detail.withoutDigest',
              )}`
            : t('signing.technicalComparison.detail.notSupplied')}
        </Detail>,
      ],
    },
  ];

  return (
    <section className="signing-evidence" aria-label={t('signing.technicalComparison.aria')}>
      <div className="signing-evidence__head">
        <div>
          <p className="signing-kicker">{t('signing.technicalComparison.kicker')}</p>
          <p className="signing-evidence__title">{t('signing.technicalComparison.title')}</p>
        </div>
        <div
          className="signing-evidence__badges"
          aria-label={t('signing.technicalComparison.summary.aria')}
        >
          <Badge tone="neutral">{t('signing.technicalComparison.badge.local')}</Badge>
          <Badge tone="neutral">{t('signing.technicalComparison.badge.noClaim')}</Badge>
        </div>
      </div>
      {!bundleReady && !bundleLoading ? (
        <p className="field__hint">{t('signing.technicalComparison.bundleUnavailable')}</p>
      ) : null}
      <dl className="deflist signing-deflist signing-deflist--compact">
        {rows.map((row) => {
          const status = comparisonStatus(row.kind, t);
          return (
            <div key={row.key} className={row.wide ? 'signing-deflist__wide' : undefined}>
              <dt>{row.label}</dt>
              <dd>
                <span className="signing-chipline">
                  <Badge tone={status.tone}>{status.label}</Badge>
                  {row.details}
                </span>
              </dd>
            </div>
          );
        })}
      </dl>
      <p className="field__hint">{t('signing.technicalComparison.noClaim')}</p>
    </section>
  );
}

function StatusSummary({
  tone,
  badge,
  title,
  children,
}: {
  tone: 'ok' | 'warn' | 'info';
  badge: string;
  title: string;
  children: React.ReactNode;
}) {
  const t = useT();
  return (
    <section className={`signing-status signing-status--${tone}`}>
      <div className="signing-status__icon" aria-hidden="true">
        {tone === 'ok' ? <Icon.Check /> : tone === 'warn' ? <Icon.Info /> : <Icon.PenNib />}
      </div>
      <div className="signing-status__body">
        <div className="signing-status__topline">
          <p className="signing-kicker">{t('signing.status.kicker')}</p>
          <Badge tone={tone === 'ok' ? 'ok' : tone === 'warn' ? 'warn' : 'accent'}>{badge}</Badge>
        </div>
        <p className="signing-status__title">{title}</p>
        <div className="signing-status__copy">{children}</div>
      </div>
    </section>
  );
}

function ProviderChoice({
  title,
  description,
  badges,
  details,
  disabledNote,
  children,
}: {
  title: string;
  description: string;
  badges?: React.ReactNode;
  details?: React.ReactNode;
  disabledNote?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={`signing-provider${disabledNote ? ' signing-provider--disabled' : ''}`}>
      <div className="signing-provider__copy">
        <div className="signing-provider__titleline">
          <strong>{title}</strong>
          {badges}
        </div>
        <p>{description}</p>
        {details}
        {disabledNote ? <p className="field__hint">{disabledNote}</p> : null}
      </div>
      <div className="signing-provider__action">{children}</div>
    </div>
  );
}

export function providerEnvironmentLabel(
  environment: string | null | undefined,
  t: TFunction,
): string {
  if (environment === 'preprod') return t('signing.provider.manifest.environment.preprod');
  if (environment === 'prod') return t('signing.provider.manifest.environment.prod');
  if (environment === 'sandbox') return t('signing.provider.manifest.environment.sandbox');
  return t('signing.provider.manifest.environment.unknown');
}

export function providerAuthorizationLabel(mode: string | null | undefined, t: TFunction): string {
  if (mode === 'pin_otp') return t('signing.provider.manifest.authorization.pinOtp');
  if (mode === 'service') return t('signing.provider.manifest.authorization.service');
  if (mode === 'user') return t('signing.provider.manifest.authorization.user');
  return t('signing.provider.manifest.authorization.unknown');
}

function ProviderManifestSummary({ provider }: { provider?: SignatureProviderView }) {
  const t = useT();
  const manifest = provider?.manifest;
  if (!manifest) return null;
  return (
    <div className="field__hint stack--tight">
      <p>
        <strong>{t('signing.provider.manifest.title')}</strong>{' '}
        {manifest.readiness.configured
          ? t('signing.provider.manifest.configured')
          : t('signing.provider.manifest.unconfigured')}
        {' · '}
        {providerEnvironmentLabel(manifest.readiness.environment, t)}
        {' · '}
        {manifest.readiness.production_blocked
          ? t('signing.provider.manifest.productionBlocked')
          : t('signing.provider.manifest.productionNotBlocked')}
        {' · '}
        {providerAuthorizationLabel(manifest.readiness.authorization_mode, t)}
      </p>
      <p>
        {t('signing.provider.manifest.batchSemantics', {
          repeated: manifest.capabilities.remote_batch_repeated_per_document_initiate
            ? t('common.yes')
            : t('common.no'),
          native: manifest.capabilities.provider_native_batch_claimed
            ? t('common.yes')
            : t('common.no'),
          single: manifest.capabilities.single_otp_pin_sad_batch_claimed
            ? t('common.yes')
            : t('common.no'),
        })}
      </p>
      <p>{t('signing.provider.manifest.boundary')}</p>
    </div>
  );
}

function inviteStatusBadge(invite: ExternalSignerInviteView, t: TFunction) {
  if (invite.status === 'pending')
    return <Badge tone="accent">{t('signing.invites.status.pending')}</Badge>;
  if (invite.status === 'accepted')
    return <Badge tone="ok">{t('signing.invites.status.accepted')}</Badge>;
  if (invite.status === 'declined')
    return <Badge tone="warn">{t('signing.invites.status.declined')}</Badge>;
  if (invite.status === 'expired')
    return <Badge tone="warn">{t('signing.invites.status.expired')}</Badge>;
  return <Badge tone="neutral">{t('signing.invites.status.revoked')}</Badge>;
}

export function workflowLabel(workflow: string, t: TFunction): string {
  if (workflow === 'tracking_only') return t('signing.invites.workflow.trackingOnly');
  if (workflow === 'external_envelope') return t('signing.invites.workflow.externalEnvelope');
  return workflow;
}

export function orderPolicyLabel(policy: ExternalSigningOrderPolicy, t: TFunction): string {
  if (policy === 'sequential') return t('signing.envelopes.order.sequential');
  return t('signing.envelopes.order.parallel');
}

export function identityRequirementLabel(
  requirement: ExternalSignerIdentityRequirement,
  t: TFunction,
): string {
  if (requirement === 'contact_control') return t('signing.envelopes.identity.contactControl');
  if (requirement === 'provider_identity_assertion')
    return t('signing.envelopes.identity.providerIdentity');
  if (requirement === 'government_id_check') return t('signing.envelopes.identity.governmentId');
  return t('signing.envelopes.identity.representativeCapacity');
}

export function slotStatusLabel(status: ExternalSignerSlotStatus, t: TFunction): string {
  if (status === 'pending') return t('signing.envelopes.slot.status.pending');
  if (status === 'initiated') return t('signing.envelopes.slot.status.initiated');
  if (status === 'signed') return t('signing.envelopes.slot.status.signed');
  if (status === 'declined') return t('signing.envelopes.slot.status.declined');
  if (status === 'revoked') return t('signing.envelopes.slot.status.revoked');
  return t('signing.envelopes.slot.status.expired');
}

function slotStatusBadge(status: ExternalSignerSlotStatus, t: TFunction) {
  if (status === 'signed') return <Badge tone="ok">{slotStatusLabel(status, t)}</Badge>;
  if (status === 'pending' || status === 'initiated')
    return <Badge tone="accent">{slotStatusLabel(status, t)}</Badge>;
  return <Badge tone="warn">{slotStatusLabel(status, t)}</Badge>;
}

export function slotIdentityRequirements(
  slot: ExternalSigningEnvelopeSlotView,
  t: TFunction,
): string {
  const requirements = slot.identity_requirements ?? [];
  return requirements.length
    ? requirements.map((requirement) => identityRequirementLabel(requirement, t)).join(', ')
    : t('signing.envelopes.identity.none');
}

function SlotEvidenceMetadata({ slot }: { slot: ExternalSigningEnvelopeSlotView }) {
  const t = useT();
  if (slot.evidence.length === 0) {
    return <span className="muted">{t('signing.envelopes.evidence.none')}</span>;
  }
  return (
    <ul className="plain-list">
      {slot.evidence.map((evidence, index) => (
        <li key={`${evidence.label}-${evidence.reference}-${index}`}>
          <strong>{evidence.label}</strong>
          <br />
          <span className="mono">{evidence.reference}</span>
          {evidence.digest ? (
            <>
              <br />
              <Digest value={evidence.digest} copyable={false} />
            </>
          ) : null}
          {evidence.identity_requirement ? (
            <>
              <br />
              <Badge tone="neutral">
                {identityRequirementLabel(evidence.identity_requirement, t)}
              </Badge>
            </>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

export function slotCanRecordTechnicalEvidence(slot: ExternalSigningEnvelopeSlotView): boolean {
  return slot.status === 'pending' || slot.status === 'initiated';
}

export function buildSlotEvidenceRows(
  slot: ExternalSigningEnvelopeSlotView,
  form: SlotEvidenceFormState,
  t: TFunction,
): UpdateExternalSigningEnvelopeEvidenceBody[] {
  const digest = form.digest.trim();
  const rows: UpdateExternalSigningEnvelopeEvidenceBody[] = [
    {
      label: form.label.trim(),
      reference: form.reference.trim(),
      ...(digest ? { digest } : {}),
    },
  ];
  for (const requirement of slot.identity_requirements ?? []) {
    rows.push({
      label: t('signing.envelopes.evidence.identityLabel', {
        requirement: identityRequirementLabel(requirement, t),
      }),
      reference: form.identityReferences[requirement]?.trim() ?? '',
      identity_requirement: requirement,
    });
  }
  return rows;
}

export function inviteSlotOptions(envelopes: ExternalSigningEnvelopeView[], t: TFunction) {
  return envelopes.flatMap((envelope) =>
    envelope.slots
      .filter((slot) => slot.status === 'pending')
      .map<InviteSlotOption>((slot) => ({
        value: `${envelope.id}:${slot.id}`,
        envelopeId: envelope.id,
        slotId: slot.id,
        status: slot.status,
        label: t('signing.invites.slot.option', {
          signer: slot.signer_label,
          order: orderPolicyLabel(envelope.order_policy, t),
          status: slotStatusLabel(slot.status, t),
        }),
      })),
  );
}

function ExternalSigningEnvelopesSection({ act }: { act: ActView }) {
  const t = useT();
  const toast = useToast();
  const can = useCan();
  const bookScope = scopeBook(act.book_id);
  const canManage = can('signing.perform', bookScope);
  const envelopes = useExternalSigningEnvelopes(act.id, canManage);
  const create = useCreateExternalSigningEnvelope(act.id);
  const updateEnvelope = useUpdateExternalSigningEnvelope(act.id);
  const [creating, setCreating] = useState(false);
  const [orderPolicy, setOrderPolicy] = useState<ExternalSigningOrderPolicy>('parallel');
  const [slots, setSlots] = useState<EnvelopeSlotFormRow[]>(() => [newEnvelopeSlotFormRow()]);
  const [recordingSlot, setRecordingSlot] = useState<RecordingSlot | null>(null);
  const [evidenceForm, setEvidenceForm] = useState<SlotEvidenceFormState>({
    label: '',
    reference: '',
    digest: '',
    identityReferences: {},
  });

  if (!canManage) return null;

  const slotPayload = slots
    .map((slot) => ({
      signer_label: slot.signerLabel.trim(),
      contact_hint: slot.contactHint.trim() || undefined,
      identity_requirements: slot.identityRequirement ? [slot.identityRequirement] : undefined,
      required: slot.required,
    }))
    .filter((slot) => slot.signer_label.length > 0);
  const canSubmit = slotPayload.length > 0 && !create.isPending;
  const list = envelopes.data ?? [];
  const selectedEnvelope = recordingSlot
    ? list.find((envelope) => envelope.id === recordingSlot.envelopeId)
    : undefined;
  const selectedSlot = selectedEnvelope?.slots.find((slot) => slot.id === recordingSlot?.slotId);
  const selectedIdentityRequirements = selectedSlot?.identity_requirements ?? [];
  const selectedIdentityRequirementsComplete = selectedIdentityRequirements.every((requirement) =>
    evidenceForm.identityReferences[requirement]?.trim(),
  );
  const selectedEvidenceRows = selectedSlot
    ? buildSlotEvidenceRows(selectedSlot, evidenceForm, t)
    : [];
  const canSubmitEvidence =
    Boolean(selectedSlot) &&
    Boolean(selectedSlot && slotCanRecordTechnicalEvidence(selectedSlot)) &&
    evidenceForm.label.trim().length > 0 &&
    evidenceForm.reference.trim().length > 0 &&
    selectedIdentityRequirementsComplete &&
    !updateEnvelope.isPending;

  function resetForm() {
    setOrderPolicy('parallel');
    setSlots([newEnvelopeSlotFormRow()]);
  }

  function resetEvidenceForm() {
    setRecordingSlot(null);
    setEvidenceForm({ label: '', reference: '', digest: '', identityReferences: {} });
    updateEnvelope.reset();
  }

  function updateSlot(id: string, patch: Partial<EnvelopeSlotFormRow>) {
    setSlots((current) => current.map((slot) => (slot.id === id ? { ...slot, ...patch } : slot)));
  }

  function openEvidenceForm(
    envelope: ExternalSigningEnvelopeView,
    slot: ExternalSigningEnvelopeSlotView,
  ) {
    setRecordingSlot({ envelopeId: envelope.id, slotId: slot.id });
    setEvidenceForm({
      label: t('signing.envelopes.evidence.defaultLabel'),
      reference: '',
      digest: '',
      identityReferences: Object.fromEntries(
        (slot.identity_requirements ?? []).map((requirement) => [requirement, '']),
      ) as Partial<Record<ExternalSignerIdentityRequirement, string>>,
    });
    updateEnvelope.reset();
  }

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    create.mutate(
      { order_policy: orderPolicy, slots: slotPayload },
      {
        onSuccess: () => {
          resetForm();
          setCreating(false);
          create.reset();
          toast.success(t('signing.envelopes.createdToast'));
        },
        onError: (err) => toast.error(err),
      },
    );
  }

  function onSubmitEvidence(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedEnvelope || !selectedSlot || !canSubmitEvidence) return;
    updateEnvelope.mutate(
      {
        envelopeId: selectedEnvelope.id,
        body: {
          slots: [
            {
              id: selectedSlot.id,
              status: 'signed',
              evidence: selectedEvidenceRows,
            },
          ],
        },
      },
      {
        onSuccess: () => {
          toast.success(t('signing.envelopes.evidence.recordedToast'));
          resetEvidenceForm();
        },
        onError: (err) => toast.error(err),
      },
    );
  }

  return (
    <section className="stack--tight">
      <div className="rowline">
        <strong>{t('signing.envelopes.title')}</strong>
        {!creating ? (
          <GateButton
            perm="signing.perform"
            scope={bookScope}
            type="button"
            variant="secondary"
            icon={<Icon.Plus />}
            onClick={() => setCreating(true)}
          >
            {t('signing.envelopes.create')}
          </GateButton>
        ) : null}
      </div>
      <InlineWarning tone="info" title={t('signing.envelopes.guardrail.title')}>
        {t('signing.envelopes.guardrail.body')}
      </InlineWarning>

      {creating ? (
        <form className="form" onSubmit={onSubmit}>
          <Field label={t('signing.envelopes.order.label')} htmlFor="external-envelope-order">
            <Select
              id="external-envelope-order"
              value={orderPolicy}
              onChange={(event) => setOrderPolicy(event.target.value as ExternalSigningOrderPolicy)}
              options={[
                { value: 'parallel', label: t('signing.envelopes.order.parallel') },
                { value: 'sequential', label: t('signing.envelopes.order.sequential') },
              ]}
            />
          </Field>
          <div className="stack--tight">
            <p className="card__label">{t('signing.envelopes.slots.label')}</p>
            {slots.map((slot, index) => (
              <div className="stack--tight" key={slot.id}>
                <div className="form__grid">
                  <Field
                    label={t('signing.envelopes.slot.signerLabel', { index: index + 1 })}
                    htmlFor={`external-envelope-slot-${slot.id}-label`}
                  >
                    <Input
                      id={`external-envelope-slot-${slot.id}-label`}
                      value={slot.signerLabel}
                      onChange={(event) => updateSlot(slot.id, { signerLabel: event.target.value })}
                    />
                  </Field>
                  <Field
                    label={t('signing.envelopes.slot.contactHint')}
                    htmlFor={`external-envelope-slot-${slot.id}-contact`}
                  >
                    <Input
                      id={`external-envelope-slot-${slot.id}-contact`}
                      value={slot.contactHint}
                      placeholder={t('signing.envelopes.slot.contactHint.placeholder')}
                      onChange={(event) => updateSlot(slot.id, { contactHint: event.target.value })}
                    />
                  </Field>
                  <Field
                    label={t('signing.envelopes.slot.identityRequirement')}
                    htmlFor={`external-envelope-slot-${slot.id}-identity`}
                  >
                    <Select
                      id={`external-envelope-slot-${slot.id}-identity`}
                      value={slot.identityRequirement}
                      onChange={(event) =>
                        updateSlot(slot.id, {
                          identityRequirement: event.target
                            .value as EnvelopeSlotFormRow['identityRequirement'],
                        })
                      }
                      options={[
                        { value: '', label: t('signing.envelopes.identity.none') },
                        {
                          value: 'contact_control',
                          label: t('signing.envelopes.identity.contactControl'),
                        },
                        {
                          value: 'provider_identity_assertion',
                          label: t('signing.envelopes.identity.providerIdentity'),
                        },
                        {
                          value: 'government_id_check',
                          label: t('signing.envelopes.identity.governmentId'),
                        },
                        {
                          value: 'representative_capacity',
                          label: t('signing.envelopes.identity.representativeCapacity'),
                        },
                      ]}
                    />
                  </Field>
                </div>
                <div className="rowline">
                  <label
                    className="checkline"
                    htmlFor={`external-envelope-slot-${slot.id}-required`}
                  >
                    <input
                      id={`external-envelope-slot-${slot.id}-required`}
                      type="checkbox"
                      checked={slot.required}
                      onChange={(event) => updateSlot(slot.id, { required: event.target.checked })}
                    />
                    {t('signing.envelopes.slot.required')}
                  </label>
                  <Button
                    type="button"
                    variant="ghost"
                    icon={<Icon.Trash />}
                    disabled={slots.length === 1}
                    onClick={() =>
                      setSlots((current) => current.filter((row) => row.id !== slot.id))
                    }
                  >
                    {t('common.remove')}
                  </Button>
                </div>
              </div>
            ))}
            <Button
              type="button"
              variant="secondary"
              icon={<Icon.Plus />}
              onClick={() => setSlots((current) => [...current, newEnvelopeSlotFormRow()])}
            >
              {t('signing.envelopes.slot.add')}
            </Button>
          </div>
          {create.error ? <ErrorNote error={create.error} /> : null}
          <div className="form__actions">
            <Button
              type="button"
              variant="ghost"
              disabled={create.isPending}
              onClick={() => {
                setCreating(false);
                resetForm();
                create.reset();
              }}
            >
              {t('common.cancel')}
            </Button>
            <GateButton
              perm="signing.perform"
              scope={bookScope}
              type="submit"
              variant="primary"
              icon={<Icon.Plus />}
              disabled={!canSubmit}
            >
              {create.isPending ? t('signing.envelopes.creating') : t('signing.envelopes.create')}
            </GateButton>
          </div>
        </form>
      ) : null}

      {envelopes.isLoading ? (
        <Skeleton height="4rem" />
      ) : envelopes.error ? (
        <ErrorNote error={envelopes.error} />
      ) : list.length === 0 ? (
        <EmptyState title={t('signing.envelopes.empty.title')}>
          <p>{t('signing.envelopes.empty.body')}</p>
        </EmptyState>
      ) : (
        <div className="stack--tight">
          {list.map((envelope, index) => (
            <div className="external-signing-envelope stack--tight" key={envelope.id}>
              <div className="section-head">
                <div>
                  <p className="card__label">
                    {t('signing.envelopes.envelopeTitle', { index: index + 1 })}
                  </p>
                  <p className="chainrow__meta">{orderPolicyLabel(envelope.order_policy, t)}</p>
                </div>
                <Badge tone={envelope.completed ? 'ok' : 'accent'}>
                  {envelope.completed
                    ? t('signing.envelopes.completed')
                    : t('signing.envelopes.open')}
                </Badge>
              </div>
              {envelope.notice ? (
                <InlineWarning tone="info" title={t('signing.envelopes.notice.title')}>
                  {envelope.notice}
                </InlineWarning>
              ) : null}
              <dl className="deflist deflist--tight">
                <div>
                  <dt>{t('signing.envelopes.order.label')}</dt>
                  <dd>{orderPolicyLabel(envelope.order_policy, t)}</dd>
                </div>
                <div>
                  <dt>{t('signing.envelopes.completion')}</dt>
                  <dd>
                    {t('signing.envelopes.completion.summary', {
                      signed: envelope.completion.signed_required_slot_count,
                      required: envelope.completion.required_slot_count,
                    })}
                  </dd>
                </div>
                <div className="deflist__wide">
                  <dt>{t('signing.envelopes.blockingSlots')}</dt>
                  <dd>
                    {envelope.completion.blocking_required_slot_ids.length
                      ? envelope.completion.blocking_required_slot_ids.join(', ')
                      : t('signing.envelopes.blockingSlots.none')}
                  </dd>
                </div>
              </dl>
              <Table
                head={
                  <tr>
                    <th>{t('signing.envelopes.table.signer')}</th>
                    <th>{t('signing.envelopes.table.status')}</th>
                    <th>{t('signing.envelopes.table.identity')}</th>
                    <th>{t('signing.envelopes.table.evidence')}</th>
                    <th>{t('signing.envelopes.table.required')}</th>
                    <th>{t('signing.envelopes.table.actions')}</th>
                  </tr>
                }
              >
                {envelope.slots.map((slot) => (
                  <tr key={slot.id}>
                    <td>
                      <strong>{slot.signer_label}</strong>
                      {slot.contact_hint ? (
                        <>
                          <br />
                          <span className="muted">{slot.contact_hint}</span>
                        </>
                      ) : null}
                    </td>
                    <td>{slotStatusBadge(slot.status, t)}</td>
                    <td>{slotIdentityRequirements(slot, t)}</td>
                    <td>
                      <SlotEvidenceMetadata slot={slot} />
                    </td>
                    <td>{slot.required ? t('common.yes') : t('common.no')}</td>
                    <td>
                      {slotCanRecordTechnicalEvidence(slot) ? (
                        <GateButton
                          perm="signing.perform"
                          scope={bookScope}
                          type="button"
                          variant="secondary"
                          icon={<Icon.FileText />}
                          onClick={() => openEvidenceForm(envelope, slot)}
                        >
                          {t('signing.envelopes.evidence.record')}
                        </GateButton>
                      ) : (
                        <span className="muted">{t('signing.envelopes.evidence.noAction')}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </Table>
              {selectedEnvelope?.id === envelope.id && selectedSlot ? (
                <form className="form" onSubmit={onSubmitEvidence}>
                  <InlineWarning tone="info" title={t('signing.envelopes.evidence.formTitle')}>
                    {t('signing.envelopes.evidence.formNotice')}
                  </InlineWarning>
                  <div className="form__grid">
                    <Field
                      label={t('signing.envelopes.evidence.label')}
                      htmlFor={`external-slot-${selectedSlot.id}-evidence-label`}
                    >
                      <Input
                        id={`external-slot-${selectedSlot.id}-evidence-label`}
                        value={evidenceForm.label}
                        onChange={(event) =>
                          setEvidenceForm((current) => ({
                            ...current,
                            label: event.target.value,
                          }))
                        }
                      />
                    </Field>
                    <Field
                      label={t('signing.envelopes.evidence.reference')}
                      htmlFor={`external-slot-${selectedSlot.id}-evidence-reference`}
                    >
                      <Input
                        id={`external-slot-${selectedSlot.id}-evidence-reference`}
                        value={evidenceForm.reference}
                        onChange={(event) =>
                          setEvidenceForm((current) => ({
                            ...current,
                            reference: event.target.value,
                          }))
                        }
                      />
                    </Field>
                    <Field
                      label={t('signing.envelopes.evidence.digest')}
                      htmlFor={`external-slot-${selectedSlot.id}-evidence-digest`}
                    >
                      <Input
                        id={`external-slot-${selectedSlot.id}-evidence-digest`}
                        value={evidenceForm.digest}
                        onChange={(event) =>
                          setEvidenceForm((current) => ({
                            ...current,
                            digest: event.target.value,
                          }))
                        }
                      />
                    </Field>
                  </div>
                  {selectedIdentityRequirements.length ? (
                    <div className="stack--tight">
                      <p className="card__label">{t('signing.envelopes.evidence.identityTitle')}</p>
                      {selectedIdentityRequirements.map((requirement) => (
                        <Field
                          key={requirement}
                          label={t('signing.envelopes.evidence.identityReference', {
                            requirement: identityRequirementLabel(requirement, t),
                          })}
                          htmlFor={`external-slot-${selectedSlot.id}-identity-${requirement}`}
                          hint={t('signing.envelopes.evidence.identityHint')}
                        >
                          <Input
                            id={`external-slot-${selectedSlot.id}-identity-${requirement}`}
                            value={evidenceForm.identityReferences[requirement] ?? ''}
                            onChange={(event) =>
                              setEvidenceForm((current) => ({
                                ...current,
                                identityReferences: {
                                  ...current.identityReferences,
                                  [requirement]: event.target.value,
                                },
                              }))
                            }
                          />
                        </Field>
                      ))}
                      {!selectedIdentityRequirementsComplete ? (
                        <InlineWarning
                          tone="warn"
                          title={t('signing.envelopes.evidence.identityMissingTitle')}
                        >
                          {t('signing.envelopes.evidence.identityMissingBody')}
                        </InlineWarning>
                      ) : null}
                    </div>
                  ) : null}
                  {updateEnvelope.error ? <ErrorNote error={updateEnvelope.error} /> : null}
                  <div className="form__actions">
                    <Button
                      type="button"
                      variant="ghost"
                      disabled={updateEnvelope.isPending}
                      onClick={resetEvidenceForm}
                    >
                      {t('common.cancel')}
                    </Button>
                    <GateButton
                      perm="signing.perform"
                      scope={bookScope}
                      type="submit"
                      variant="primary"
                      icon={<Icon.Check />}
                      disabled={!canSubmitEvidence}
                    >
                      {updateEnvelope.isPending
                        ? t('signing.envelopes.evidence.recording')
                        : t('signing.envelopes.evidence.submit')}
                    </GateButton>
                  </div>
                </form>
              ) : null}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function ExternalInviteSecretPanel({ token, onDone }: { token: string; onDone: () => void }) {
  const t = useT();
  const toast = useToast();
  const link = externalInviteLink(token);

  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      toast.success(t('common.copied'));
    } catch (err) {
      toast.error(err);
    }
  }

  return (
    <InlineWarning tone="warn" title={t('signing.invites.secret.title')}>
      <div className="stack--tight">
        <p>{t('signing.invites.secret.body')}</p>
        <div className="api-key-secret__value">
          <code className="mono">{token}</code>
          <Button
            type="button"
            variant="secondary"
            icon={<Icon.Copy />}
            onClick={() => copy(token)}
          >
            {t('signing.invites.secret.copyToken')}
          </Button>
        </div>
        <div className="api-key-secret__value">
          <code className="mono">{link}</code>
          <Button type="button" variant="secondary" icon={<Icon.Copy />} onClick={() => copy(link)}>
            {t('signing.invites.secret.copyLink')}
          </Button>
        </div>
        <div className="form__actions">
          <Button type="button" variant="primary" icon={<Icon.Check />} onClick={onDone}>
            {t('signing.invites.secret.close')}
          </Button>
        </div>
      </div>
    </InlineWarning>
  );
}

function ExternalInviteRow({
  actId,
  invite,
  bookScope,
}: {
  actId: string;
  invite: ExternalSignerInviteView;
  bookScope: CanScope;
}) {
  const t = useT();
  const toast = useToast();
  const revoke = useRevokeExternalSignerInvite(actId);
  const [confirming, setConfirming] = useState(false);

  function doRevoke() {
    revoke.mutate(invite.id, {
      onSuccess: () => {
        toast.success(t('signing.invites.revokedToast'));
        setConfirming(false);
      },
      onError: (err) => {
        toast.error(err);
        setConfirming(false);
      },
    });
  }

  return (
    <tr>
      <td>
        <strong>{invite.recipient_name}</strong>
        <br />
        <span className="muted">{invite.recipient_email}</span>
      </td>
      <td>{inviteStatusBadge(invite, t)}</td>
      <td>
        <span>{workflowLabel(invite.workflow, t)}</span>
        {invite.external_envelope ? (
          <>
            <br />
            <span className="muted">
              {t('signing.invites.workflow.slotStatus', {
                status: invite.external_envelope.slot_status
                  ? slotStatusLabel(invite.external_envelope.slot_status, t)
                  : t('signing.envelopes.slot.status.pending'),
              })}
            </span>
          </>
        ) : null}
      </td>
      <td>
        <code className="mono">{invite.token_hint}</code>
      </td>
      {/* An expiry is scheduling metadata, not a record of an event: to the minute. */}
      <td>
        <DateTime value={invite.expires_at} />
      </td>
      <td className="users-actions">
        {invite.status !== 'pending' ? (
          <span className="muted">—</span>
        ) : confirming ? (
          <span className="row-wrap">
            <Button
              type="button"
              variant="ghost"
              disabled={revoke.isPending}
              onClick={() => setConfirming(false)}
            >
              {t('common.cancel')}
            </Button>
            <GateButton
              perm="signing.perform"
              scope={bookScope}
              type="button"
              variant="primary"
              icon={<Icon.Trash />}
              disabled={revoke.isPending}
              onClick={doRevoke}
            >
              {revoke.isPending
                ? t('signing.invites.revoking')
                : t('signing.invites.revokeConfirm')}
            </GateButton>
          </span>
        ) : (
          <GateButton
            perm="signing.perform"
            scope={bookScope}
            type="button"
            variant="ghost"
            icon={<Icon.Trash />}
            disabled={revoke.isPending}
            onClick={() => setConfirming(true)}
          >
            {t('signing.invites.revoke')}
          </GateButton>
        )}
      </td>
    </tr>
  );
}

function ExternalSignerInvitesSection({ act }: { act: ActView }) {
  const t = useT();
  const toast = useToast();
  const can = useCan();
  const bookScope = scopeBook(act.book_id);
  const canManageInvites = can('signing.perform', bookScope);
  const invites = useExternalSignerInvites(act.id, canManageInvites);
  const envelopes = useExternalSigningEnvelopes(act.id, canManageInvites);
  const create = useCreateExternalSignerInvite(act.id);
  const [creating, setCreating] = useState(false);
  const [issuedToken, setIssuedToken] = useState<string | null>(null);
  const [recipientName, setRecipientName] = useState('');
  const [recipientEmail, setRecipientEmail] = useState('');
  const [providerHint, setProviderHint] = useState('');
  const [purpose, setPurpose] = useState(() => t('signing.invites.defaultPurpose'));
  const [expiresAt, setExpiresAt] = useState(() => defaultInviteExpiryInput());
  const [selectedSlot, setSelectedSlot] = useState('');
  const [linkedInviteError, setLinkedInviteError] = useState<string | null>(null);
  const [suppressLinkedInviteMutationError, setSuppressLinkedInviteMutationError] = useState(false);

  if (!canManageInvites) {
    return (
      <InlineWarning tone="info" title={t('signing.invites.title')}>
        {t('signing.invites.permissionNote')}
      </InlineWarning>
    );
  }

  const canSubmit =
    recipientName.trim().length > 0 &&
    recipientEmail.trim().length > 0 &&
    purpose.trim().length > 0 &&
    expiresAt.length > 0 &&
    !create.isPending;

  function resetForm() {
    setRecipientName('');
    setRecipientEmail('');
    setProviderHint('');
    setPurpose(t('signing.invites.defaultPurpose'));
    setExpiresAt(defaultInviteExpiryInput());
    setSelectedSlot('');
    setLinkedInviteError(null);
    setSuppressLinkedInviteMutationError(false);
  }

  const slotOptions = inviteSlotOptions(envelopes.data ?? [], t);

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setLinkedInviteError(null);
    setSuppressLinkedInviteMutationError(false);
    create.reset();
    const linkedSlot = slotOptions.find((option) => option.value === selectedSlot);
    const body: CreateExternalSignerInviteBody = {
      recipient_name: recipientName.trim(),
      recipient_email: recipientEmail.trim(),
      provider_hint: providerHint.trim() || undefined,
      expires_at: dateTimeInputToIso(expiresAt),
      purpose: purpose.trim(),
    };
    if (linkedSlot) {
      body.external_envelope_id = linkedSlot.envelopeId;
      body.external_slot_id = linkedSlot.slotId;
    }
    create.mutate(body, {
      onSuccess: (result) => {
        setIssuedToken(result.token);
        setCreating(false);
        resetForm();
        create.reset();
        toast.success(t('signing.invites.createdToast'));
      },
      onError: (err) => {
        if (linkedSlot && err instanceof ApiError && err.status === 409) {
          const message = t('signing.invites.slot.sequentialConflict');
          setLinkedInviteError(message);
          setSuppressLinkedInviteMutationError(true);
          create.reset();
          toast.error(message);
          return;
        }
        setSuppressLinkedInviteMutationError(false);
        toast.error(err);
      },
    });
  }

  const list = invites.data ?? [];

  return (
    <div className="stack--tight">
      <div className="rowline">
        <strong>{t('signing.invites.title')}</strong>
        {!creating ? (
          <GateButton
            perm="signing.perform"
            scope={bookScope}
            type="button"
            variant="secondary"
            icon={<Icon.Plus />}
            onClick={() => setCreating(true)}
          >
            {t('signing.invites.create')}
          </GateButton>
        ) : null}
      </div>
      <p className="field__hint">{t('signing.invites.hint')}</p>

      {issuedToken ? (
        <ExternalInviteSecretPanel token={issuedToken} onDone={() => setIssuedToken(null)} />
      ) : null}

      {creating ? (
        <form className="form" onSubmit={onSubmit}>
          <div className="form__grid">
            <Field label={t('signing.invites.recipientName')} htmlFor="external-invite-name">
              <Input
                id="external-invite-name"
                value={recipientName}
                autoComplete="name"
                onChange={(e) => setRecipientName(e.target.value)}
              />
            </Field>
            <Field label={t('signing.invites.email')} htmlFor="external-invite-email">
              <Input
                id="external-invite-email"
                type="email"
                value={recipientEmail}
                autoComplete="email"
                onChange={(e) => setRecipientEmail(e.target.value)}
              />
            </Field>
            <Field label={t('signing.invites.providerHint')} htmlFor="external-invite-provider">
              <Input
                id="external-invite-provider"
                value={providerHint}
                placeholder={t('signing.invites.providerHint.placeholder')}
                onChange={(e) => setProviderHint(e.target.value)}
              />
            </Field>
            <Field label={t('signing.invites.expiresAt')} htmlFor="external-invite-expires">
              <Input
                id="external-invite-expires"
                type="datetime-local"
                value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)}
              />
            </Field>
            <Field
              label={t('signing.invites.slot.label')}
              htmlFor="external-invite-slot"
              hint={
                slotOptions.length
                  ? t('signing.invites.slot.hint')
                  : t('signing.invites.slot.emptyHint')
              }
            >
              <Select
                id="external-invite-slot"
                value={selectedSlot}
                disabled={envelopes.isLoading || slotOptions.length === 0}
                onChange={(event) => {
                  setSelectedSlot(event.target.value);
                  setLinkedInviteError(null);
                }}
                options={[
                  { value: '', label: t('signing.invites.slot.trackingOnly') },
                  ...slotOptions.map((option) => ({ value: option.value, label: option.label })),
                ]}
              />
            </Field>
          </div>
          <Field label={t('signing.invites.purpose')} htmlFor="external-invite-purpose">
            <TextArea
              id="external-invite-purpose"
              rows={3}
              value={purpose}
              onChange={(e) => setPurpose(e.target.value)}
            />
          </Field>
          {linkedInviteError ? (
            <InlineWarning tone="warn" title={t('signing.invites.slot.conflictTitle')}>
              {linkedInviteError}
            </InlineWarning>
          ) : create.error && !suppressLinkedInviteMutationError ? (
            <ErrorNote error={create.error} />
          ) : null}
          <div className="form__actions">
            <Button
              type="button"
              variant="ghost"
              disabled={create.isPending}
              onClick={() => {
                setCreating(false);
                setLinkedInviteError(null);
                setSuppressLinkedInviteMutationError(false);
                create.reset();
              }}
            >
              {t('common.cancel')}
            </Button>
            <GateButton
              perm="signing.perform"
              scope={bookScope}
              type="submit"
              variant="primary"
              icon={<Icon.Plus />}
              disabled={!canSubmit}
            >
              {create.isPending ? t('signing.invites.creating') : t('signing.invites.create')}
            </GateButton>
          </div>
        </form>
      ) : null}

      {invites.isLoading ? (
        <Skeleton height="4rem" />
      ) : invites.error ? (
        <ErrorNote error={invites.error} />
      ) : list.length === 0 ? (
        <EmptyState title={t('signing.invites.empty.title')}>
          <p>{t('signing.invites.empty.body')}</p>
        </EmptyState>
      ) : (
        <Table
          head={
            <tr>
              <th>{t('signing.invites.table.signer')}</th>
              <th>{t('signing.invites.table.status')}</th>
              <th>{t('signing.invites.table.workflow')}</th>
              <th>{t('uiLiteral.signingPanel.token')}</th>
              <th>{t('signing.invites.table.expiry')}</th>
              <th>{t('signing.invites.table.actions')}</th>
            </tr>
          }
        >
          {list.map((invite) => (
            <ExternalInviteRow
              key={invite.id}
              actId={act.id}
              invite={invite}
              bookScope={bookScope}
            />
          ))}
        </Table>
      )}
    </div>
  );
}

export function SigningPanel({ act, entityName }: { act: ActView; entityName?: string }) {
  const t = useT();
  const toast = useToast();

  const signingOpen = act.state === 'Signing';
  const signatureAvailable = signingOpen || act.state === 'Sealed' || act.state === 'Archived';
  const status = useActSignature(act.id, signatureAvailable);
  const providers = useSignatureProviders(signingOpen);
  // The preferred signing family (for the «Recomendada» hint) is read from the already-loaded
  // settings cache — never a fresh fetch here, so a pre-Signing act triggers no request at all.
  const qc = useQueryClient();
  const initiate = useCmdInitiateSignature(act.id);
  const confirm = useCmdConfirmSignature(act.id);
  const remoteInitiate = useRemoteInitiateSignature(act.id);
  const remoteConfirm = useRemoteConfirmSignature(act.id);
  const ccSign = useCcSignSignature(act.id);
  const localPkcs12Sign = useLocalPkcs12SignSignature(act.id);
  const importOfficialSignature = useImportOfficialSignature(act.id);
  const download = useDownloadSignedDocument(act.id);
  // The sign actions are gated at the act's book scope (disable-with-explanation, t64-E5).
  const bookScope = scopeBook(act.book_id);

  const [step, setStep] = useState<Step>({ kind: 'view' });
  // The two-phase secrets are transient: they live here only while the form is filled and are
  // cleared the instant they are sent. `identifier` is the CMD phone / CSC user_ref; `secret` the
  // CMD PIN / CSC credential; `activation` the CMD OTP / CSC OTP-SAD. Nothing persists them (no
  // localStorage, no query cache, no logging).
  const [identifier, setIdentifier] = useState('');
  const [secret, setSecret] = useState('');
  const [activation, setActivation] = useState('');
  const [pkcs12File, setPkcs12File] = useState<File | null>(null);
  const [pkcs12Passphrase, setPkcs12Passphrase] = useState('');
  const [pkcs12FriendlyName, setPkcs12FriendlyName] = useState('');
  const [pkcs12Capacity, setPkcs12Capacity] = useState('');
  const [pkcs12Error, setPkcs12Error] = useState<unknown>(null);
  const [officialImportFile, setOfficialImportFile] = useState<File | null>(null);
  const [officialImportProvider, setOfficialImportProvider] = useState('');
  const [officialImportSource, setOfficialImportSource] = useState('');
  const [officialImportFilename, setOfficialImportFilename] = useState('');
  const [officialImportAcknowledged, setOfficialImportAcknowledged] = useState(false);
  const [officialImportError, setOfficialImportError] = useState<unknown>(null);
  const [expired, setExpired] = useState(false);
  // Set once a CC sign attempt 409s: the API is not co-located with a card reader (browser /
  // remote server). We then swap the CC affordance for an honest note rather than fake it.
  const [ccBlocked, setCcBlocked] = useState(false);
  // The optional in-app CC PIN (co-location-gated). A transient secret: it lives here only while the
  // CC step is open, is dropped the instant the request is sent (success OR error), and never
  // reaches localStorage/sessionStorage/URL/query-cache. `ccSignError` mirrors the last CC failure
  // locally so the inline message survives the `ccSign.reset()` we call to purge the PIN from the
  // retained mutation variables (t68-r7: React Query keeps `mutation.variables` until reset).
  const [ccPin, setCcPin] = useState('');
  const [ccSignError, setCcSignError] = useState<unknown>(null);
  // The optional visible-seal appearance (t67-e12). Set by the visual seal designer and threaded
  // into whichever signing lane the user then picks (CMD / CC / CSC / local PKCS#12). Absent ⇒ the
  // signature stays the backward-compatible invisible widget.
  const [seal, setSeal] = useState<SealAppearanceBody | null>(null);
  const [showSealDesigner, setShowSealDesigner] = useState(false);
  // The chosen signing format (t67-e13). `pades` is the qualified act-signing lane (the provider
  // picker below); `xades`/`asic`/`scap` are the local technical tools over the act's PDF/A.
  const [format, setFormat] = useState<SigningFormat>('pades');
  // Loads the frozen canonical PDF/A bytes the designer renders. Memoized on the act so the
  // designer's render effect does not re-fetch on every parent re-render.
  const loadSealPdf = useCallback(
    () => api.fetchActDocumentPdf(act.id).then((blob) => blob.arrayBuffer()),
    [act.id],
  );
  // Loads the frozen PDF/A as base64 — the content local XAdES/ASiC/SCAP tools bind over.
  const loadContentBase64 = useCallback(
    () => api.fetchActDocumentBytes(act.id).then((buffer) => bytesToBase64(new Uint8Array(buffer))),
    [act.id],
  );

  const data = status.data;
  const documentBundle = useActDocumentBundle(
    act.id,
    signatureAvailable && data?.status === 'signed',
  );
  // Only CSC QTSPs come from the picker list — CMD + CC always have their own always-available
  // entry actions and do not depend on the list resolving (older server / no `signing.perform`).
  const cmdProviderView = (providers.data ?? []).find((p) => p.id === CMD_PROVIDER_ID);
  const cscProviders = (providers.data ?? []).filter((p) => p.id !== CMD_PROVIDER_ID);
  const preferred = qc.getQueryData<Settings>(keys.settings)?.signing.preferred_family;

  /** Whether the settings `preferred_family` recommends a given entry method. */
  function isRecommended(target: 'cmd' | 'cc' | 'csc'): boolean {
    if (preferred === 'ChaveMovelDigital') return target === 'cmd';
    if (preferred === 'CartaoCidadao') return target === 'cc';
    if (preferred === 'OtherQualified') return target === 'csc';
    return false;
  }

  // Adopt a server-known pending session (e.g. after a reload mid-flow) into the OTP step, but
  // only from the neutral «view» step so a deliberate restart is never snapped back. Older status
  // responses lack provider metadata and therefore keep the legacy CMD restore path.
  useEffect(() => {
    if (signingOpen && step.kind === 'view' && data?.status === 'pending' && data.pending) {
      const provider = providerFromPending(data.pending, providers.data ?? []);
      setStep({
        kind: 'otp',
        provider,
        sessionId: data.pending.session_id,
        hint: data.pending.activation_hint ?? data.pending.masked_phone,
      });
    }
  }, [data, providers.data, signingOpen, step.kind]);

  if (!signatureAvailable) return null;

  /** Enter phase 1 for a chosen provider. */
  function onPick(provider: SigningProvider) {
    setExpired(false);
    setIdentifier('');
    setSecret('');
    setActivation('');
    setStep({ kind: 'credentials', provider });
  }

  function onInitiate(e: React.FormEvent, provider: SigningProvider) {
    e.preventDefault();
    setExpired(false);
    const onSuccess = (sessionId: string, hint: string) => {
      setSecret(''); // credential consumed — drop it immediately
      setActivation('');
      setStep({ kind: 'otp', provider, sessionId, hint });
      toast.success(t('toast.signing.otpSent'));
    };
    if (provider.kind === 'cmd') {
      initiate.mutate(
        { phone: identifier.trim(), pin: secret, seal: seal ?? undefined },
        {
          onSuccess: (res) => onSuccess(res.session_id, res.masked_phone),
          onError: (err) => toast.error(err),
        },
      );
    } else {
      remoteInitiate.mutate(
        {
          provider: provider.id,
          body: { user_ref: identifier.trim(), credential: secret, seal: seal ?? undefined },
        },
        {
          onSuccess: (res) => onSuccess(res.session_id, res.activation_hint),
          onError: (err) => toast.error(err),
        },
      );
    }
  }

  function onConfirm(e: React.FormEvent, sessionId: string, provider: SigningProvider) {
    e.preventDefault();
    const onSuccess = () => {
      setActivation('');
      setIdentifier('');
      setSecret('');
      setStep({ kind: 'view' });
      toast.success(t('toast.signing.signed'));
    };
    const onError = (err: unknown) => {
      toast.error(err);
      // A 410 is an expired single-use session — restart cleanly at the credentials step.
      if (err instanceof ApiError && err.status === 410) {
        setActivation('');
        setExpired(true);
        setStep({ kind: 'credentials', provider });
      }
    };
    if (provider.kind === 'cmd') {
      confirm.mutate({ session_id: sessionId, otp: activation }, { onSuccess, onError });
    } else {
      remoteConfirm.mutate(
        { provider: provider.id, body: { session_id: sessionId, activation } },
        { onSuccess, onError },
      );
    }
  }

  /** Enter the CC step, clearing any stale transient PIN / error from a previous attempt. */
  function onPickCc() {
    setCcPin('');
    setCcSignError(null);
    ccSign.reset();
    setStep({ kind: 'cc' });
  }

  /** Leave the CC step back to the picker, dropping the transient PIN and error. */
  function onCancelCc() {
    setCcPin('');
    setCcSignError(null);
    ccSign.reset();
    setStep({ kind: 'view' });
  }

  function onCcSign(e: React.FormEvent) {
    e.preventDefault();
    if (ccSign.isPending) return;
    // The call BLOCKS while the card signs; the button shows «A assinar…». The optional in-app PIN
    // (co-location-gated) rides only in this request body — absent ⇒ the reader owns the PIN
    // (protected authentication). On BOTH success and error we clear the PIN and call `ccSign.reset()`
    // to purge the retained mutation variables, so the secret never lingers in client state. The
    // failure is mirrored into local `ccSignError` first so the inline message survives that reset.
    setCcSignError(null);
    const trimmedPin = ccPin.trim();
    const pin = trimmedPin.length > 0 ? trimmedPin : undefined;
    ccSign.mutate(
      { pin, seal: seal ?? undefined },
      {
        onSuccess: () => {
          setCcPin('');
          ccSign.reset();
          setStep({ kind: 'view' });
          toast.success(t('toast.signing.signed'));
        },
        onError: (err) => {
          setCcPin(''); // consumed — drop it immediately, even on failure
          setCcSignError(err); // keep the message locally; `reset()` clears `ccSign.error` next
          ccSign.reset();
          toast.error(err);
          // 409 = the API is not co-located with a reader (browser / remote server). Surface the
          // honest co-location note and drop the CC affordance rather than retry blindly.
          if (err instanceof ApiError && err.status === 409) {
            setCcBlocked(true);
            setCcSignError(null);
            setStep({ kind: 'view' });
          }
          // A 422 (wrong/blocked PIN, no card, not activated, no reader) STAYS on the CC step so the
          // honest message renders inline for a retry.
        },
      },
    );
  }

  /** The localized, PIN-free message for a structured CC PIN rejection (422 `pin_status`). */
  function ccPinRejectionMessage(err: ApiError): string {
    if (err.pinStatus === 'blocked') return t('signing.cc.pin.blocked');
    const hint =
      err.triesLeft === 'final_try'
        ? t('signing.cc.pin.triesFinal')
        : err.triesLeft === 'locked'
          ? t('signing.cc.pin.triesLocked')
          : err.triesLeft === 'low'
            ? t('signing.cc.pin.triesLow')
            : '';
    const base = t('signing.cc.pin.wrong');
    return hint ? `${base} ${hint}` : base;
  }

  function resetPkcs12Form() {
    setPkcs12File(null);
    setPkcs12Passphrase('');
    setPkcs12FriendlyName('');
    setPkcs12Capacity('');
    setPkcs12Error(null);
  }

  function resetOfficialImportForm() {
    setOfficialImportFile(null);
    setOfficialImportProvider('');
    setOfficialImportSource('');
    setOfficialImportFilename('');
    setOfficialImportAcknowledged(false);
    setOfficialImportError(null);
  }

  async function onLocalPkcs12Sign(e: React.FormEvent) {
    e.preventDefault();
    if (!pkcs12File || pkcs12Passphrase.length === 0 || localPkcs12Sign.isPending) return;
    setPkcs12Error(null);
    try {
      const pkcs12Base64 = await fileToBase64(pkcs12File);
      await localPkcs12Sign.mutateAsync({
        pkcs12_base64: pkcs12Base64,
        passphrase: pkcs12Passphrase,
        friendly_name: pkcs12FriendlyName.trim() || undefined,
        capacity: pkcs12Capacity.trim() || undefined,
        seal: seal ?? undefined,
      });
      resetPkcs12Form();
      setStep({ kind: 'view' });
      toast.success(t('toast.signing.signed'));
    } catch (err) {
      setPkcs12Error(err);
      toast.error(err);
    } finally {
      localPkcs12Sign.reset();
    }
  }

  async function onImportOfficialSignature(e: React.FormEvent) {
    e.preventDefault();
    if (!officialImportFile || !officialImportAcknowledged || importOfficialSignature.isPending) {
      return;
    }
    setOfficialImportError(null);
    try {
      const signedPdfBase64 = await fileToBase64(officialImportFile);
      await importOfficialSignature.mutateAsync({
        signed_pdf_base64: signedPdfBase64,
        provider: officialImportProvider.trim() || undefined,
        source: officialImportSource.trim() || undefined,
        filename: officialImportFilename.trim() || undefined,
        acknowledged_guardrail_ids: [...OFFICIAL_SIGNATURE_IMPORT_GUARDRAIL_IDS],
      });
      resetOfficialImportForm();
      setStep({ kind: 'view' });
      toast.success(t('toast.signing.officialImported'));
    } catch (err) {
      setOfficialImportError(err);
      toast.error(err);
    } finally {
      importOfficialSignature.reset();
    }
  }

  function showSaveResult(result: SaveBlobResult) {
    if (result.kind === 'cancelled') {
      toast.info(saveBlobResultMessage(result));
      return;
    }
    toast.success(saveBlobResultMessage(result));
  }

  function onDownloadSigned() {
    const base = entityName ? `${signingDownloadSlug(entityName)}-` : '';
    const n = act.ata_number != null ? String(act.ata_number) : act.id;
    download.mutate(undefined, {
      onSuccess: async (blob) => {
        try {
          showSaveResult(
            await saveBlobAs({
              blob,
              filename: `${base}ata-${n}-assinada.pdf`,
              contentType: 'application/pdf',
              preferBrowserSavePicker: true,
            }),
          );
        } catch (e) {
          toast.error(e);
        }
      },
      onError: (e) => toast.error(e),
    });
  }

  function familyLabel(family: string): string {
    if (family === FAMILY_OFFICIAL_HANDOFF) return t('signing.official.family');
    return signatureFamilyLabels[family as SignatureFamily] ?? family;
  }

  /** The honest, method-accurate qualified-signature label for a signed record. */
  function qualifiedLabel(family: string): string {
    if (family === FAMILY_LOCAL_PKCS12) return t('signing.signed.localPkcs12Label');
    if (family === FAMILY_OFFICIAL_HANDOFF) return t('signing.signed.officialLabel');
    if (family === FAMILY_CC) return t('signing.signed.qualifiedLabelCc');
    if (family === FAMILY_CSC) return t('signing.signed.qualifiedLabelCsc');
    return t('signing.signed.qualifiedLabel');
  }

  function signedBoundaryNote(family: string): string {
    if (family === FAMILY_OFFICIAL_HANDOFF) return t('signing.signed.officialNote');
    return t('signing.signed.validityNote');
  }

  function signedTitle(family: string): string {
    if (family === FAMILY_LOCAL_PKCS12) return t('signing.signed.localPkcs12Title');
    if (family === FAMILY_OFFICIAL_HANDOFF) return t('signing.signed.officialTitle');
    return t('signing.signed.title');
  }

  return (
    <Card title={t('signing.title')}>
      <div className="stack--tight">
        {status.isLoading ? (
          <Skeleton height="6rem" />
        ) : status.error ? (
          <ErrorNote error={status.error} />
        ) : data?.status === 'signed' && data.signed ? (
          // --- SIGNED: the qualified-signature record + the signed-PDF download ----------------
          <div className="stack--tight">
            <StatusSummary
              tone="ok"
              badge={t('signing.status.signed')}
              title={signedTitle(data.signed.family)}
            >
              <p>{qualifiedLabel(data.signed.family)}</p>
              <p>{signedBoundaryNote(data.signed.family)}</p>
            </StatusSummary>
            <dl className="deflist signing-deflist">
              <div>
                <dt>
                  {t('signing.signed.signer')}
                  <FieldHelp text={t('signing.signed.signer.help')} placement="bottom" />
                </dt>
                <dd className="mono">{data.signed.signer_cert_subject ?? '—'}</dd>
              </div>
              <div>
                <dt>{t('signing.signed.family')}</dt>
                <dd>{familyLabel(data.signed.family)}</dd>
              </div>
              <div>
                <dt>{t('signing.signed.signingTime')}</dt>
                {/* The signature time is the evidentiary fact of this panel. */}
                <dd>
                  <DateTime value={data.signed.signing_time} evidentiary />
                </dd>
              </div>
              {data.signed.trusted_list_status ? (
                <div>
                  <dt>
                    {t('signing.signed.trustedList')}
                    <FieldHelp text={t('signing.signed.trustedList.help')} placement="bottom" />
                  </dt>
                  <dd>
                    <Badge tone={trustedListTone(data.signed.trusted_list_status)}>
                      {trustedListLabel(data.signed.trusted_list_status, t)}
                    </Badge>
                  </dd>
                </div>
              ) : null}
              <div>
                <dt>{t('signing.signed.timestamp')}</dt>
                <dd>
                  {data.signed.timestamp_token
                    ? t('signing.signed.timestampPresent')
                    : t('signing.signed.timestampAbsent')}
                </dd>
              </div>
              <div>
                <dt>
                  {t('signing.signed.digest')}
                  <FieldHelp text={t('signing.signed.digest.help')} placement="bottom" />
                </dt>
                <dd>
                  <Digest value={data.signed.signed_pdf_digest} />
                </dd>
              </div>
            </dl>
            <Button
              type="button"
              variant="primary"
              icon={<Icon.FileText />}
              disabled={download.isPending}
              onClick={onDownloadSigned}
            >
              {download.isPending ? t('documents.download.pending') : t('signing.download')}
            </Button>
            <TechnicalComparisonPanel
              act={act}
              signed={data.signed}
              bundle={documentBundle.data}
              bundleLoading={documentBundle.isLoading}
              bundleError={documentBundle.error}
            />
          </div>
        ) : !signingOpen ? (
          <StatusSummary
            tone="info"
            badge={actStateLabels[act.state]}
            title={t('signing.closed.title')}
          >
            <p>{t('signing.closed.body')}</p>
          </StatusSummary>
        ) : step.kind === 'officialImport' ? (
          // --- Official app/provider handoff: upload an already-signed PDF as evidence only.
          <form className="form" onSubmit={onImportOfficialSignature}>
            <StatusSummary
              tone="warn"
              badge={t('signing.status.officialHandoff')}
              title={t('signing.official.title')}
            >
              <p>{t('signing.official.notice')}</p>
            </StatusSummary>
            <div className="form__grid">
              <Field
                label={t('signing.official.file.label')}
                htmlFor="sign-official-file"
                hint={t('signing.official.file.hint')}
              >
                <Input
                  id="sign-official-file"
                  type="file"
                  accept=".pdf,application/pdf"
                  autoComplete="off"
                  onChange={(event) => {
                    const file = event.target.files?.[0] ?? null;
                    setOfficialImportFile(file);
                    setOfficialImportFilename(file?.name ?? '');
                  }}
                />
              </Field>
              <Field
                label={t('signing.official.provider.label')}
                htmlFor="sign-official-provider"
                hint={t('signing.official.provider.hint')}
              >
                <Input
                  id="sign-official-provider"
                  type="text"
                  autoComplete="off"
                  value={officialImportProvider}
                  placeholder={t('signing.official.provider.placeholder')}
                  onChange={(event) => setOfficialImportProvider(event.target.value)}
                />
              </Field>
              <Field
                label={t('signing.official.source.label')}
                htmlFor="sign-official-source"
                hint={t('signing.official.source.hint')}
              >
                <Input
                  id="sign-official-source"
                  type="text"
                  autoComplete="off"
                  value={officialImportSource}
                  placeholder={t('signing.official.source.placeholder')}
                  onChange={(event) => setOfficialImportSource(event.target.value)}
                />
              </Field>
              <Field
                label={t('signing.official.filename.label')}
                htmlFor="sign-official-filename"
                hint={t('signing.official.filename.hint')}
              >
                <Input
                  id="sign-official-filename"
                  type="text"
                  autoComplete="off"
                  value={officialImportFilename}
                  onChange={(event) => setOfficialImportFilename(event.target.value)}
                />
              </Field>
            </div>
            <div className="stack--tight">
              <p className="card__label">{t('signing.official.guardrails.title')}</p>
              <ul className="plain-list">
                {OFFICIAL_SIGNATURE_IMPORT_GUARDRAIL_IDS.map((guardrail) => (
                  <li key={guardrail}>{officialImportGuardrailLabel(guardrail, t)}</li>
                ))}
              </ul>
              <label className="checkline" htmlFor="sign-official-guardrails">
                <input
                  id="sign-official-guardrails"
                  type="checkbox"
                  checked={officialImportAcknowledged}
                  disabled={importOfficialSignature.isPending}
                  onChange={(event) => setOfficialImportAcknowledged(event.target.checked)}
                />
                {t('signing.official.ack.label')}
              </label>
            </div>
            {officialImportError ? <ErrorNote error={officialImportError} /> : null}
            <div className="rowline">
              <Button
                type="submit"
                variant="primary"
                icon={<Icon.FileText />}
                disabled={
                  !officialImportFile ||
                  !officialImportAcknowledged ||
                  importOfficialSignature.isPending
                }
              >
                {importOfficialSignature.isPending
                  ? t('signing.official.importing')
                  : t('signing.official.import')}
              </Button>
              <Button
                type="button"
                variant="ghost"
                icon={<Icon.Refresh />}
                disabled={importOfficialSignature.isPending}
                onClick={() => {
                  resetOfficialImportForm();
                  setStep({ kind: 'view' });
                }}
              >
                {t('signing.cc.cancel')}
              </Button>
            </div>
          </form>
        ) : step.kind === 'pkcs12' ? (
          // --- Local PKCS#12/PFX: advanced software-certificate signing, technical evidence only.
          <form className="form" onSubmit={onLocalPkcs12Sign}>
            <StatusSummary
              tone="warn"
              badge={t('signing.status.localPkcs12')}
              title={t('signing.pkcs12.title')}
            >
              <p>{t('signing.pkcs12.notice')}</p>
            </StatusSummary>
            <div className="form__grid">
              <Field
                label={t('signing.pkcs12.file.label')}
                htmlFor="sign-pkcs12-file"
                hint={t('signing.pkcs12.file.hint')}
              >
                <Input
                  id="sign-pkcs12-file"
                  type="file"
                  accept=".p12,.pfx,application/x-pkcs12"
                  autoComplete="off"
                  onChange={(event) => setPkcs12File(event.target.files?.[0] ?? null)}
                />
              </Field>
              <Field
                label={t('signing.pkcs12.passphrase.label')}
                htmlFor="sign-pkcs12-passphrase"
                hint={t('signing.pkcs12.passphrase.hint')}
              >
                <Input
                  id="sign-pkcs12-passphrase"
                  type="password"
                  autoComplete="off"
                  value={pkcs12Passphrase}
                  onChange={(event) => setPkcs12Passphrase(event.target.value)}
                />
              </Field>
              <Field
                label={t('signing.pkcs12.friendlyName.label')}
                htmlFor="sign-pkcs12-friendly-name"
                hint={t('signing.pkcs12.friendlyName.hint')}
              >
                <Input
                  id="sign-pkcs12-friendly-name"
                  type="text"
                  autoComplete="off"
                  value={pkcs12FriendlyName}
                  onChange={(event) => setPkcs12FriendlyName(event.target.value)}
                />
              </Field>
              <Field
                label={t('signing.pkcs12.capacity.label')}
                htmlFor="sign-pkcs12-capacity"
                hint={t('signing.pkcs12.capacity.hint')}
              >
                <Input
                  id="sign-pkcs12-capacity"
                  type="text"
                  autoComplete="off"
                  value={pkcs12Capacity}
                  onChange={(event) => setPkcs12Capacity(event.target.value)}
                />
              </Field>
            </div>
            {pkcs12Error ? <ErrorNote error={pkcs12Error} /> : null}
            <div className="rowline">
              <Button
                type="submit"
                variant="primary"
                icon={<Icon.PenNib />}
                disabled={!pkcs12File || pkcs12Passphrase.length === 0 || localPkcs12Sign.isPending}
              >
                {localPkcs12Sign.isPending ? t('signing.pkcs12.signing') : t('signing.pkcs12.sign')}
              </Button>
              <Button
                type="button"
                variant="ghost"
                icon={<Icon.Refresh />}
                disabled={localPkcs12Sign.isPending}
                onClick={() => {
                  resetPkcs12Form();
                  setStep({ kind: 'view' });
                }}
              >
                {t('signing.cc.cancel')}
              </Button>
            </div>
          </form>
        ) : step.kind === 'credentials' ? (
          // --- PHASE 1: collect the identifier + credential (CMD phone/PIN; CSC user_ref/credential)
          (() => {
            const p = step.provider;
            const isCmd = p.kind === 'cmd';
            const initiating = isCmd ? initiate.isPending : remoteInitiate.isPending;
            const initiateError = isCmd ? initiate.error : remoteInitiate.error;
            return (
              <form className="form" onSubmit={(e) => onInitiate(e, p)}>
                {expired ? (
                  <InlineWarning tone="warn" title={t('signing.expired')}>
                    {isCmd ? t('signing.credentials.intro') : t('signing.csc.credentials.intro')}
                  </InlineWarning>
                ) : (
                  <p className="field__hint">
                    {isCmd ? t('signing.credentials.intro') : t('signing.csc.credentials.intro')}
                  </p>
                )}
                <Field
                  label={isCmd ? t('signing.phone.label') : t('signing.csc.userRef.label')}
                  htmlFor="sign-identifier"
                  hint={isCmd ? undefined : t('signing.csc.userRef.hint')}
                >
                  <Input
                    id="sign-identifier"
                    type={isCmd ? 'tel' : 'text'}
                    autoComplete="off"
                    value={identifier}
                    placeholder={isCmd ? t('signing.phone.placeholder') : undefined}
                    onChange={(e) => setIdentifier(e.target.value)}
                  />
                </Field>
                <Field
                  label={isCmd ? t('signing.pin.label') : t('signing.csc.credential.label')}
                  htmlFor="sign-secret"
                  hint={isCmd ? t('signing.pin.hint') : t('signing.csc.credential.hint')}
                >
                  <Input
                    id="sign-secret"
                    type="password"
                    inputMode={isCmd ? 'numeric' : 'text'}
                    autoComplete="off"
                    value={secret}
                    onChange={(e) => setSecret(e.target.value)}
                  />
                </Field>
                {initiateError ? <ErrorNote error={initiateError} /> : null}
                <div className="rowline">
                  <Button
                    type="submit"
                    variant="primary"
                    icon={<Icon.PenNib />}
                    disabled={initiating || !identifier.trim() || (isCmd && secret.length === 0)}
                  >
                    {isCmd
                      ? initiating
                        ? t('signing.initiate.pending')
                        : t('signing.initiate')
                      : initiating
                        ? t('signing.csc.initiate.pending')
                        : t('signing.csc.initiate')}
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    icon={<Icon.Refresh />}
                    disabled={initiating}
                    onClick={() => setStep({ kind: 'view' })}
                  >
                    {t('signing.cc.cancel')}
                  </Button>
                </div>
              </form>
            );
          })()
        ) : step.kind === 'otp' ? (
          // --- PHASE 2: collect the activation code (SMS OTP for CMD; OTP/SAD for CSC) and confirm
          (() => {
            const p = step.provider;
            const isCmd = p.kind === 'cmd';
            const confirming = isCmd ? confirm.isPending : remoteConfirm.isPending;
            const confirmError = isCmd ? confirm.error : remoteConfirm.error;
            return (
              <form className="form" onSubmit={(e) => onConfirm(e, step.sessionId, p)}>
                {isCmd ? (
                  <p className="field__hint">{t('signing.otp.sent', { phone: step.hint })}</p>
                ) : (
                  <>
                    <p className="field__hint">{t('signing.csc.otp.sent')}</p>
                    {step.hint ? <p className="field__hint">{step.hint}</p> : null}
                  </>
                )}
                <Field
                  label={isCmd ? t('signing.otp.label') : t('signing.csc.otp.label')}
                  htmlFor="sign-activation"
                  hint={isCmd ? t('signing.otp.hint') : t('signing.csc.otp.hint')}
                >
                  <Input
                    id="sign-activation"
                    inputMode={isCmd ? 'numeric' : 'text'}
                    autoComplete="one-time-code"
                    value={activation}
                    placeholder={isCmd ? t('signing.otp.placeholder') : undefined}
                    onChange={(e) => setActivation(e.target.value)}
                  />
                </Field>
                {confirmError ? <ErrorNote error={confirmError} /> : null}
                <div className="rowline">
                  <Button
                    type="submit"
                    variant="primary"
                    icon={<Icon.Check />}
                    disabled={confirming || activation.trim().length === 0}
                  >
                    {confirming ? t('signing.confirm.pending') : t('signing.confirm')}
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    icon={<Icon.Refresh />}
                    disabled={confirming}
                    onClick={() => {
                      setActivation('');
                      setSecret('');
                      setStep({ kind: 'credentials', provider: p });
                    }}
                  >
                    {t('signing.restart')}
                  </Button>
                </div>
              </form>
            );
          })()
        ) : step.kind === 'cc' ? (
          // --- CC: the honest synchronous prompt with an optional transient in-app PIN ----------
          <form className="form" onSubmit={onCcSign}>
            <StatusSummary
              tone="info"
              badge={t('signing.status.localCard')}
              title={t('signing.cc.prompt.title')}
            >
              <p>{t('signing.cc.prompt.body')}</p>
            </StatusSummary>
            <Field
              label={t('signing.cc.pin.label')}
              htmlFor="sign-cc-pin"
              hint={t('signing.cc.pin.hint')}
            >
              <Input
                id="sign-cc-pin"
                type="password"
                inputMode="numeric"
                autoComplete="off"
                value={ccPin}
                maxLength={12}
                placeholder={t('signing.cc.pin.placeholder')}
                disabled={ccSign.isPending}
                onChange={(event) => setCcPin(event.target.value.slice(0, 12))}
              />
            </Field>
            {ccSignError ? (
              <div role="alert" aria-live="assertive">
                {isCcPinRejection(ccSignError) ? (
                  <InlineWarning tone="error" title={t('common.error')}>
                    {ccPinRejectionMessage(ccSignError)}
                  </InlineWarning>
                ) : (
                  <ErrorNote error={ccSignError} />
                )}
              </div>
            ) : null}
            <div className="rowline">
              <Button
                type="submit"
                variant="primary"
                icon={<Icon.IdCard />}
                disabled={ccSign.isPending}
              >
                {ccSign.isPending ? t('signing.cc.signing') : t('signing.cc.sign')}
              </Button>
              <Button
                type="button"
                variant="ghost"
                icon={<Icon.Refresh />}
                disabled={ccSign.isPending}
                onClick={onCancelCc}
              >
                {t('signing.cc.cancel')}
              </Button>
            </div>
          </form>
        ) : (
          // --- UNSIGNED: the honest state + the provider picker (CMD + CC + configured CSC QTSPs) -
          <div className="stack--tight">
            <StatusSummary
              tone={data?.require_qualified_for_seal ? 'warn' : 'info'}
              badge={
                data?.require_qualified_for_seal
                  ? t('signing.status.required')
                  : t('signing.status.unsigned')
              }
              title={t('signing.unsigned.title')}
            >
              <p>
                {data?.require_qualified_for_seal
                  ? t('signing.required.body')
                  : t('signing.unsigned.body')}
              </p>
            </StatusSummary>
            {/* Signing-format selector (t67-e13). PAdES is the qualified act-signing lane below;
                XAdES / ASiC / SCAP are local technical tools over the act's PDF/A. */}
            <Field
              label={t('signing.format.label')}
              htmlFor="signing-format"
              hint={t('signing.format.hint')}
            >
              <Select
                id="signing-format"
                value={format}
                onChange={(event) => setFormat(event.target.value as SigningFormat)}
                options={[
                  { value: 'pades', label: t('signing.format.pades') },
                  { value: 'xades', label: t('signing.format.xades') },
                  { value: 'asic', label: t('signing.format.asic') },
                  { value: 'scap', label: t('signing.format.scap') },
                ]}
              />
            </Field>
            {format === 'xades' ? (
              <XadesToolForm loadContentBase64={loadContentBase64} />
            ) : format === 'asic' ? (
              <AsicToolForm loadContentBase64={loadContentBase64} />
            ) : format === 'scap' ? (
              <ScapAttributePicker act={act} loadContentBase64={loadContentBase64} />
            ) : (
              <>
                {/* Optional visible-seal placement (t67-e12). The applied seal rides into whichever
                    signing lane the user then picks. */}
                <div className="signing-seal-affordance stack--tight">
                  {seal ? (
                    <div className="rowline">
                      <p className="field__hint">
                        {t('signing.seal.applied.summary', {
                          page: String((seal.page ?? 0) + 1),
                        })}
                      </p>
                      <Button
                        type="button"
                        variant="ghost"
                        onClick={() => setShowSealDesigner(true)}
                      >
                        {t('signing.seal.applied.edit')}
                      </Button>
                      <Button type="button" variant="ghost" onClick={() => setSeal(null)}>
                        {t('signing.seal.applied.remove')}
                      </Button>
                    </div>
                  ) : showSealDesigner ? null : (
                    <div className="stack--tight">
                      <Button
                        type="button"
                        variant="ghost"
                        icon={<Icon.PenNib />}
                        onClick={() => setShowSealDesigner(true)}
                      >
                        {t('signing.seal.affordance.open')}
                      </Button>
                      <p className="field__hint">{t('signing.seal.affordance.hint')}</p>
                    </div>
                  )}
                  {showSealDesigner ? (
                    <SealDesigner
                      loadPdf={loadSealPdf}
                      initialSeal={seal}
                      onApply={(applied) => {
                        setSeal(applied);
                        setShowSealDesigner(false);
                      }}
                      onCancel={() => setShowSealDesigner(false)}
                    />
                  ) : null}
                </div>
                <div className="signing-provider-list">
                  {/* Chave Móvel Digital — always offered (its dedicated two-phase path). */}
                  <ProviderChoice
                    title={t('signing.provider.cmd.title')}
                    description={t('signing.provider.cmd.description')}
                    details={<ProviderManifestSummary provider={cmdProviderView} />}
                    badges={
                      isRecommended('cmd') ? (
                        <Badge tone="accent">{t('signing.recommended')}</Badge>
                      ) : null
                    }
                  >
                    <GateButton
                      perm="signing.perform"
                      scope={bookScope}
                      type="button"
                      variant="primary"
                      icon={<Icon.PenNib />}
                      onClick={() => onPick(CMD_PROVIDER)}
                    >
                      {t('signing.start')}
                    </GateButton>
                  </ProviderChoice>
                  {/* Cartão de Cidadão — always offered unless a 409 proved this server is not co-located. */}
                  {ccBlocked ? null : (
                    <ProviderChoice
                      title={t('signing.provider.cc.title')}
                      description={t('signing.provider.cc.description')}
                      badges={
                        isRecommended('cc') ? (
                          <Badge tone="accent">{t('signing.recommended')}</Badge>
                        ) : null
                      }
                    >
                      <GateButton
                        perm="signing.perform"
                        scope={bookScope}
                        type="button"
                        variant="secondary"
                        icon={<Icon.IdCard />}
                        onClick={onPickCc}
                      >
                        {t('signing.cc.start')}
                      </GateButton>
                    </ProviderChoice>
                  )}
                  {ccBlocked ? null : <BatchSigningPanel currentAct={act} bookScope={bookScope} />}
                  <ProviderChoice
                    title={t('signing.provider.pkcs12.title')}
                    description={t('signing.provider.pkcs12.description')}
                    badges={<Badge tone="warn">{t('signing.provider.pkcs12.badge')}</Badge>}
                  >
                    <GateButton
                      perm="signing.perform"
                      scope={bookScope}
                      type="button"
                      variant="secondary"
                      icon={<Icon.FileText />}
                      onClick={() => {
                        resetPkcs12Form();
                        setStep({ kind: 'pkcs12' });
                      }}
                    >
                      {t('signing.pkcs12.start')}
                    </GateButton>
                  </ProviderChoice>
                  <ProviderChoice
                    title={t('signing.provider.official.title')}
                    description={t('signing.provider.official.description')}
                    badges={<Badge tone="warn">{t('signing.provider.official.badge')}</Badge>}
                  >
                    <GateButton
                      perm="signing.perform"
                      scope={bookScope}
                      type="button"
                      variant="secondary"
                      icon={<Icon.FileText />}
                      onClick={() => {
                        resetOfficialImportForm();
                        setStep({ kind: 'officialImport' });
                      }}
                    >
                      {t('signing.official.start')}
                    </GateButton>
                  </ProviderChoice>
                  {providers.isLoading ? (
                    <p className="field__hint signing-provider-list__note">
                      {t('signing.provider.loading')}
                    </p>
                  ) : providers.error ? (
                    <InlineWarning tone="info" title={t('signing.provider.unavailable.title')}>
                      {t('signing.provider.unavailable.body')}
                    </InlineWarning>
                  ) : null}
                  {/* Every configured CSC QTSP (Multicert / DigitalSign / …) — the generic two-phase path.
                An unconfigured provider is shown disabled with an honest «não configurado» note. */}
                  {cscProviders.map((provider) =>
                    provider.configured ? (
                      <ProviderChoice
                        key={provider.id}
                        title={provider.label}
                        description={t('signing.provider.csc.description')}
                        details={<ProviderManifestSummary provider={provider} />}
                        badges={
                          isRecommended('csc') ? (
                            <Badge tone="accent">{t('signing.recommended')}</Badge>
                          ) : null
                        }
                      >
                        <GateButton
                          perm="signing.perform"
                          scope={bookScope}
                          type="button"
                          variant="secondary"
                          icon={<Icon.PenNib />}
                          onClick={() =>
                            onPick({ id: provider.id, kind: 'csc', label: provider.label })
                          }
                        >
                          {t('signing.csc.start', { provider: provider.label })}
                        </GateButton>
                      </ProviderChoice>
                    ) : (
                      <ProviderChoice
                        key={provider.id}
                        title={provider.label}
                        description={t('signing.provider.csc.unconfigured')}
                        details={<ProviderManifestSummary provider={provider} />}
                        disabledNote={t('signing.csc.notConfigured')}
                      >
                        <Button
                          type="button"
                          variant="secondary"
                          icon={<Icon.PenNib />}
                          aria-disabled="true"
                          disabled
                        >
                          {t('signing.csc.start', { provider: provider.label })}
                        </Button>
                      </ProviderChoice>
                    ),
                  )}
                  {!providers.isLoading && !providers.error ? (
                    <RemoteBatchSigningPanel
                      currentAct={act}
                      bookScope={bookScope}
                      providers={providers.data ?? []}
                      seal={seal}
                    />
                  ) : null}
                </div>
                {ccBlocked ? (
                  <InlineWarning tone="info" title={t('signing.cc.coLocation.title')}>
                    {t('signing.cc.coLocation.body')}
                  </InlineWarning>
                ) : null}
              </>
            )}
          </div>
        )}
        {data?.evidence ? <SignatureEvidenceSummary evidence={data.evidence} /> : null}
        {signingOpen ? <ExternalSigningEnvelopesSection act={act} /> : null}
        {signingOpen ? <ExternalSignerInvitesSection act={act} /> : null}
      </div>
    </Card>
  );
}
