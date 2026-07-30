import { useState, type ReactNode } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useProbeProviderCredentialEntry, useProviderCredentials } from '../../api/hooks';
import type { CredentialMode } from '../../api/types';
import { useT } from '../../i18n';
import { useProviderCredentialsT } from '../../i18n/providerCredentialsFallback';
import {
  Button,
  Card,
  ErrorNote,
  InlineWarning,
  PageHeader,
  SkeletonRegion,
  SkeletonTable,
} from '../../ui';
import { PermissionDeniedNote, useCan } from '../session/permissions';
import {
  ProtectionBanner,
  Pkcs12ProbeConfirmModal,
  ProviderCredentialEntryForm,
  ProviderCredentialProbeModal,
  canStoreSecrets,
} from './ProviderCredentialsSection';
import { CmdTestSignatureAction } from './CmdTestSignatureAction';
import { decodeProviderSegment, isCredentialMode } from './providerCredentialRoutes';

const LIST_PATH = '/admin/signing/providers';

export function ProviderCredentialPage() {
  const t = useT();
  const pt = useProviderCredentialsT();
  const navigate = useNavigate();
  const can = useCan();
  const [searchParams] = useSearchParams();
  const {
    mode: modeParam,
    providerId: providerParam,
    entryId,
  } = useParams<{
    mode?: string;
    providerId?: string;
    entryId?: string;
  }>();
  const isEdit = entryId !== undefined;
  const allowed = can('signing.configure');
  const canPerform = can('signing.perform');
  const credentials = useProviderCredentials(allowed);
  const probe = useProbeProviderCredentialEntry();
  const [confirmingProbe, setConfirmingProbe] = useState(false);
  // Progress and the per-check log live in the dialog (t112), not inline under the form.
  const [probeOpen, setProbeOpen] = useState(false);

  const queryMode = searchParams.get('mode');
  const mode: CredentialMode | null = isEdit
    ? isCredentialMode(modeParam)
      ? modeParam
      : null
    : isCredentialMode(queryMode)
      ? queryMode
      : 'csc';
  const providerId = isEdit
    ? providerParam === undefined
      ? null
      : decodeProviderSegment(providerParam)
    : searchParams.has('provider')
      ? (searchParams.get('provider') ?? '')
      : undefined;
  const title = isEdit
    ? pt('providerCredentials.page.editTitle')
    : pt('providerCredentials.page.createTitle');

  const shell = (body: ReactNode, actions?: ReactNode) => (
    <div className="stack form-page">
      <PageHeader
        crumbs={
          <>
            <Link to={LIST_PATH}>{pt('providerCredentials.page.back')}</Link> · {title}
          </>
        }
        title={title}
        actions={actions}
      />
      {body}
    </div>
  );

  if (!allowed) {
    return shell(
      <>
        <PermissionDeniedNote />
        <p>
          <Link to={LIST_PATH}>{pt('providerCredentials.page.back')}</Link>
        </p>
      </>,
    );
  }
  if (mode === null || providerId === null || (isEdit && !entryId)) {
    return shell(
      <InlineWarning tone="error" title={pt('providerCredentials.error.invalidRoute')}>
        <Link to={LIST_PATH}>{pt('providerCredentials.page.back')}</Link>
      </InlineWarning>,
    );
  }
  if (credentials.isLoading) {
    return shell(
      <Card title={title}>
        <SkeletonRegion>
          <SkeletonTable cols={2} rows={5} />
        </SkeletonRegion>
      </Card>,
    );
  }
  if (credentials.error) return shell(<ErrorNote error={credentials.error} />);
  const data = credentials.data;
  if (!data) return shell(<ErrorNote error={new Error(t('common.error'))} />);
  const storable = canStoreSecrets(data);
  const group =
    providerId === undefined
      ? undefined
      : data.providers.find(
          (candidate) => candidate.mode === mode && candidate.provider_id === providerId,
        );
  const existing = isEdit
    ? group?.entries.find((candidate) => candidate.entry_id === entryId)
    : undefined;
  if (isEdit && !existing) {
    return shell(
      <InlineWarning tone="error" title={pt('providerCredentials.error.notFound')}>
        <Link to={LIST_PATH}>{pt('providerCredentials.page.back')}</Link>
      </InlineWarning>,
    );
  }

  const testAction =
    isEdit && existing && providerId !== undefined ? (
      <Button
        type="button"
        variant="secondary"
        disabled={probe.isPending || (mode === 'pkcs12' && !canPerform)}
        title={
          mode === 'pkcs12' && !canPerform
            ? pt('providerCredentials.probe.pkcs12.permission')
            : undefined
        }
        onClick={() => {
          if (mode === 'pkcs12') {
            setConfirmingProbe(true);
            return;
          }
          setProbeOpen(true);
          probe.mutate({ mode, providerId, entryId: existing.entry_id });
        }}
      >
        {probe.isPending
          ? pt('providerCredentials.action.testing')
          : pt('providerCredentials.action.test')}
      </Button>
    ) : undefined;

  return shell(
    <>
      <ProtectionBanner
        strict={data.strict}
        level={data.protection_level}
        storable={storable}
        failure={data.storage_failure}
      />
      {testAction ? (
        <p className="field__hint">{pt('providerCredentials.page.savedConfiguration')}</p>
      ) : null}
      <ProviderCredentialEntryForm
        key={`${mode}:${providerId ?? 'choose'}:${entryId ?? 'new'}`}
        mode={mode}
        providerId={providerId}
        existing={existing}
        disabled={!isEdit && !storable}
        onDone={() => navigate(LIST_PATH)}
        onCancel={() => navigate(LIST_PATH)}
      />
      <Pkcs12ProbeConfirmModal
        open={mode === 'pkcs12' && confirmingProbe}
        pending={probe.isPending}
        onClose={() => setConfirmingProbe(false)}
        onConfirm={async () => {
          if (!isEdit || !existing || providerId === undefined) return;
          setConfirmingProbe(false);
          setProbeOpen(true);
          probe.mutate({ mode, providerId, entryId: existing.entry_id });
        }}
      />
      <ProviderCredentialProbeModal
        open={probeOpen}
        onClose={() => setProbeOpen(false)}
        pending={probe.isPending}
        result={probe.data}
        error={probe.error}
        // No re-run for PKCS#12: repeating it is a real private-key operation, and it must go back
        // through the confirmation gate rather than a button inside the result dialog.
        onRerun={
          mode !== 'pkcs12' && isEdit && existing && providerId !== undefined
            ? () => probe.mutate({ mode, providerId, entryId: existing.entry_id })
            : undefined
        }
      />
      {/*
        The route from the safe probe to the real thing (t82). An operator who runs the probe on
        this page reads `live_provider_operation — Not run` and, until now, had nowhere to go from
        there: the end-to-end control existed only in the credential list's table row. That refusal
        is correct — CMD has no non-signing health operation — but leaving it as the last word made
        the product look like it could not test CMD at all. So the real test lives immediately
        under the panel that explains why the probe stopped, and its intro names that connection.
      */}
      {mode === 'cmd' && isEdit && existing ? (
        <Card title={pt('providerCredentials.cmdTest.sectionTitle')}>
          <div className="stack stack--tight">
            <p className="field__hint">{pt('providerCredentials.cmdTest.sectionIntro')}</p>
            <p className="field__hint">{pt('providerCredentials.cmdTest.sectionWhatItDoes')}</p>
            {/* Labelled, not icon-only: this control is alone under its heading, and a completed
                run costs a real qualified signature. See CmdTestSignatureAction for the full
                reasoning — it is the deliberate exception to the icon-only row treatment. */}
            <CmdTestSignatureAction
              entry={existing}
              canPerform={canPerform}
              presentation="labelled"
            />
          </div>
        </Card>
      ) : null}
    </>,
    testAction,
  );
}
