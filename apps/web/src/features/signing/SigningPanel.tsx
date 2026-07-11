/**
 * SigningPanel — signing and signed-PDF evidence on a sealed act (plans t57 + t58 + t59).
 *
 * A sealed act's unsigned PDF/A can be turned into a **qualified** signed PDF through a chosen
 * signing method. The panel presents a provider picker and routes each choice to the right flow:
 *
 *   • **Chave Móvel Digital (CMD)** — an honest two-phase flow (t57), remote-capable:
 *       1. «Assinar com Chave Móvel Digital» → collect the mobile number + signature PIN →
 *          `cmd/initiate` (the server dispatches an SMS OTP);
 *       2. collect the OTP received by SMS → `cmd/confirm` → the act is signed.
 *
 *   • **Cartão de Cidadão (CC)** — a SYNCHRONOUS single call (t58), desktop-only. «Assinar com
 *     Cartão de Cidadão» → an honest prompt (insert the card; the PIN is entered AT THE READER
 *     via the Autenticação.gov middleware, never here) → `cc/sign` blocks while the card signs →
 *     the act is signed. CC only works when the API is co-located with the reader (the desktop
 *     app); a remote/browser server refuses with **409**, which we surface as an honest note.
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
 * never stored client-side. The CC PIN never enters the web app at all (it is entered at the
 * reader). The qualified-signing methods label their qualified status accurately, while imported
 * and local technical evidence are kept visibly separate.
 *
 * Read errors render inline; the mutations follow the toast idiom (success + error) per
 * CONVENTIONS §2/§3. The sign actions are gated with `useCan('signing.perform', <act's book
 * scope>)` (disable-with-explanation); the server re-enforces the permission regardless.
 */
import { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type {
  ActView,
  CreateExternalSignerInviteBody,
  ExternalSignerIdentityRequirement,
  ExternalSignerInviteView,
  ExternalSignerSlotStatus,
  ExternalSigningEnvelopeSlotView,
  ExternalSigningEnvelopeView,
  ExternalSigningOrderPolicy,
  OfficialSignatureImportGuardrail,
  Settings,
  SignatureEvidenceStatus,
  SignatureFamily,
  UpdateExternalSigningEnvelopeEvidenceBody,
} from '../../api/types';
import { OFFICIAL_SIGNATURE_IMPORT_GUARDRAIL_IDS } from '../../api/types';
import { ApiError } from '../../api/client';
import { signatureFamilyLabels } from '../../api/labels';
import {
  keys,
  useActSignature,
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
} from '../../api/hooks';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import { GateButton, scopeBook, useCan, type CanScope } from '../session/permissions';
import { useLocale, useT, type TFunction } from '../../i18n';
import {
  Badge,
  Button,
  Card,
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
function slug(value: string): string {
  return (
    value
      .normalize('NFD')
      .replace(/[̀-ͯ]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'documento'
  );
}

/** Localised date+time for the signing timestamps (falls back to the raw ISO on a parse miss). */
function useDateTime(): (iso: string) => string {
  const locale = useLocale();
  return (iso: string) => {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(d);
  };
}

function evidenceLevelLabel(level: string, t: TFunction): string {
  if (level === 'Unsigned') return t('signing.evidence.level.unsigned');
  if (level === 'B-B') return 'PAdES B-B';
  if (level === 'B-T') return 'PAdES B-T';
  if (level === 'B-LT-local') return 'PAdES B-LT local';
  if (level === 'B-LTA-local') return 'PAdES B-LTA local';
  return level;
}

function longTermEvidenceLabel(status: string, t: TFunction): string {
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

function renewalPlanActionLabel(action: string, t: TFunction): string {
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

function dssEvidenceLabel(evidence: SignatureEvidenceStatus, t: TFunction): string {
  if (evidence.dss_revocation_evidence_present) return t('signing.evidence.dss.present');
  if (evidence.dss_revocation_evidence_status === 'unsupported')
    return t('signing.evidence.dss.unsupported');
  if (evidence.dss_revocation_evidence_status === 'not_present')
    return t('signing.evidence.dss.notPresent');
  return evidence.dss_revocation_evidence_status;
}

function trustedListLabel(status: string, t: TFunction): string {
  if (status === 'Granted') return t('signing.trustedList.granted');
  if (status === 'Withdrawn') return t('signing.trustedList.withdrawn');
  if (status === 'Unknown') return t('signing.trustedList.unknown');
  return status;
}

function trustedListTone(status: string): 'ok' | 'warn' {
  return status === 'Granted' ? 'ok' : 'warn';
}

function officialImportGuardrailLabel(
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

function evidenceLevelTone(level: string): 'neutral' | 'accent' | 'ok' {
  if (level === 'B-LT-local' || level === 'B-LTA-local') return 'ok';
  if (level === 'B-T') return 'ok';
  if (level === 'B-B') return 'accent';
  return 'neutral';
}

function evidenceTimestampLabel(evidence: SignatureEvidenceStatus, t: TFunction): string {
  return evidence.timestamp_evidence_present
    ? t('signing.evidence.timestamp.present')
    : t('signing.evidence.timestamp.absent');
}

function evidenceTimestampTone(evidence: SignatureEvidenceStatus): 'ok' | 'neutral' {
  return evidence.timestamp_evidence_present ? 'ok' : 'neutral';
}

function toLocalDateTimeInput(date: Date): string {
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

function defaultInviteExpiryInput(): string {
  return toLocalDateTimeInput(new Date(Date.now() + 2 * 24 * 60 * 60 * 1000));
}

function dateTimeInputToIso(value: string): string {
  return new Date(value).toISOString();
}

function externalInviteLink(token: string): string {
  const path = `/assinatura-externa?token=${encodeURIComponent(token)}`;
  if (typeof window === 'undefined') return path;
  return new URL(path, window.location.origin).toString();
}

async function fileToBase64(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

/**
 * The chosen two-phase provider: `cmd` drives the dedicated `/signature/cmd/*` path; `csc`
 * drives the generic `/signature/remote/{id}/*` path. `label` names it in the prompts.
 */
type SigningProvider = { id: string; kind: 'cmd' | 'csc'; label: string };

/** The built-in CMD provider descriptor (its labels are fixed; `label` is unused for CMD). */
const CMD_PROVIDER: SigningProvider = { id: CMD_PROVIDER_ID, kind: 'cmd', label: 'CMD' };

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
  disabledNote,
  children,
}: {
  title: string;
  description: string;
  badges?: React.ReactNode;
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
        {disabledNote ? <p className="field__hint">{disabledNote}</p> : null}
      </div>
      <div className="signing-provider__action">{children}</div>
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

function workflowLabel(workflow: string, t: TFunction): string {
  if (workflow === 'tracking_only') return t('signing.invites.workflow.trackingOnly');
  if (workflow === 'external_envelope') return t('signing.invites.workflow.externalEnvelope');
  return workflow;
}

function orderPolicyLabel(policy: ExternalSigningOrderPolicy, t: TFunction): string {
  if (policy === 'sequential') return t('signing.envelopes.order.sequential');
  return t('signing.envelopes.order.parallel');
}

function identityRequirementLabel(
  requirement: ExternalSignerIdentityRequirement,
  t: TFunction,
): string {
  if (requirement === 'contact_control') return t('signing.envelopes.identity.contactControl');
  if (requirement === 'provider_identity_assertion')
    return t('signing.envelopes.identity.providerIdentity');
  if (requirement === 'government_id_check') return t('signing.envelopes.identity.governmentId');
  return t('signing.envelopes.identity.representativeCapacity');
}

function slotStatusLabel(status: ExternalSignerSlotStatus, t: TFunction): string {
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

function slotIdentityRequirements(slot: ExternalSigningEnvelopeSlotView, t: TFunction): string {
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

function slotCanRecordTechnicalEvidence(slot: ExternalSigningEnvelopeSlotView): boolean {
  return slot.status === 'pending' || slot.status === 'initiated';
}

function buildSlotEvidenceRows(
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

function inviteSlotOptions(envelopes: ExternalSigningEnvelopeView[], t: TFunction) {
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
  formatDateTime,
}: {
  actId: string;
  invite: ExternalSignerInviteView;
  bookScope: CanScope;
  formatDateTime: (iso: string) => string;
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
      <td>{formatDateTime(invite.expires_at)}</td>
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

function ExternalSignerInvitesSection({
  act,
  formatDateTime,
}: {
  act: ActView;
  formatDateTime: (iso: string) => string;
}) {
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
              <th>Token</th>
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
              formatDateTime={formatDateTime}
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
  const formatDateTime = useDateTime();

  const sealed = act.state === 'Sealed' || act.state === 'Archived';
  const status = useActSignature(act.id, sealed);
  const providers = useSignatureProviders(sealed);
  // The preferred signing family (for the «Recomendada» hint) is read from the already-loaded
  // settings cache — never a fresh fetch here, so a non-sealed act triggers no request at all.
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

  const data = status.data;
  // Only CSC QTSPs come from the picker list — CMD + CC always have their own always-available
  // entry actions and do not depend on the list resolving (older server / no `signing.perform`).
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
  // only from the neutral «view» step so a deliberate restart is never snapped back. The status
  // view does not carry the provider, so an adopted session is driven as CMD (its dedicated path).
  useEffect(() => {
    if (step.kind === 'view' && data?.status === 'pending' && data.pending) {
      setStep({
        kind: 'otp',
        provider: CMD_PROVIDER,
        sessionId: data.pending.session_id,
        hint: data.pending.masked_phone,
      });
    }
  }, [data, step.kind]);

  if (!sealed) return null;

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
        { phone: identifier.trim(), pin: secret },
        {
          onSuccess: (res) => onSuccess(res.session_id, res.masked_phone),
          onError: (err) => toast.error(err),
        },
      );
    } else {
      remoteInitiate.mutate(
        { provider: provider.id, body: { user_ref: identifier.trim(), credential: secret } },
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

  function onCcSign() {
    // No secret in the body — the PIN is entered at the reader by the Autenticação.gov
    // middleware. The call BLOCKS while the card signs; the button shows «A assinar…».
    ccSign.mutate(
      {},
      {
        onSuccess: () => {
          setStep({ kind: 'view' });
          toast.success(t('toast.signing.signed'));
        },
        onError: (err) => {
          toast.error(err);
          // 409 = the API is not co-located with a reader (browser / remote server). Surface
          // the honest co-location note and drop the CC affordance rather than retry blindly.
          if (err instanceof ApiError && err.status === 409) {
            setCcBlocked(true);
            setStep({ kind: 'view' });
          }
          // A 422 provider error (no card / wrong PIN / not activated / no reader) STAYS on the
          // CC step so the honest server message renders inline for a retry.
        },
      },
    );
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
    const base = entityName ? `${slug(entityName)}-` : '';
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
                <dd>{formatDateTime(data.signed.signing_time)}</dd>
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
          </div>
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
          // --- CC: the honest synchronous prompt (PIN is entered at the reader) -----------------
          <div className="stack--tight">
            <StatusSummary
              tone="info"
              badge={t('signing.status.localCard')}
              title={t('signing.cc.prompt.title')}
            >
              <p>{t('signing.cc.prompt.body')}</p>
            </StatusSummary>
            {ccSign.error ? <ErrorNote error={ccSign.error} /> : null}
            <div className="rowline">
              <Button
                type="button"
                variant="primary"
                icon={<Icon.IdCard />}
                disabled={ccSign.isPending}
                onClick={onCcSign}
              >
                {ccSign.isPending ? t('signing.cc.signing') : t('signing.cc.sign')}
              </Button>
              <Button
                type="button"
                variant="ghost"
                icon={<Icon.Refresh />}
                disabled={ccSign.isPending}
                onClick={() => setStep({ kind: 'view' })}
              >
                {t('signing.cc.cancel')}
              </Button>
            </div>
          </div>
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
            <div className="signing-provider-list">
              {/* Chave Móvel Digital — always offered (its dedicated two-phase path). */}
              <ProviderChoice
                title={t('signing.provider.cmd.title')}
                description={t('signing.provider.cmd.description')}
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
                    onClick={() => setStep({ kind: 'cc' })}
                  >
                    {t('signing.cc.start')}
                  </GateButton>
                </ProviderChoice>
              )}
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
            </div>
            {ccBlocked ? (
              <InlineWarning tone="info" title={t('signing.cc.coLocation.title')}>
                {t('signing.cc.coLocation.body')}
              </InlineWarning>
            ) : null}
          </div>
        )}
        {data?.evidence ? <SignatureEvidenceSummary evidence={data.evidence} /> : null}
        <ExternalSigningEnvelopesSection act={act} />
        <ExternalSignerInvitesSection act={act} formatDateTime={formatDateTime} />
      </div>
    </Card>
  );
}
