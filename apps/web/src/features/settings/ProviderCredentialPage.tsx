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
  useToast,
} from '../../ui';
import { PermissionDeniedNote, useCan } from '../session/permissions';
import {
  ProtectionBanner,
  Pkcs12ProbeConfirmModal,
  ProviderCredentialEntryForm,
  ProviderCredentialProbeResult,
  canStoreSecrets,
} from './ProviderCredentialsSection';
import { decodeProviderSegment, isCredentialMode } from './providerCredentialRoutes';

const LIST_PATH = '/admin/signing/providers';

export function ProviderCredentialPage() {
  const t = useT();
  const pt = useProviderCredentialsT();
  const toast = useToast();
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
          probe.mutate(
            { mode, providerId, entryId: existing.entry_id },
            { onError: (error) => toast.error(error) },
          );
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
          await probe.mutateAsync({ mode, providerId, entryId: existing.entry_id });
          setConfirmingProbe(false);
        }}
      />
      {probe.data ? <ProviderCredentialProbeResult result={probe.data} /> : null}
      {probe.error ? <ErrorNote error={probe.error} /> : null}
    </>,
    testAction,
  );
}
