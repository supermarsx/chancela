/**
 * User-facing host for the desktop-local Cartão de Cidadão bridge.
 *
 * The route deliberately has no credential, PIN, reader, certificate, or document inputs. Status
 * is a sanitized read model; the only mutation accepts no variables and exercises the local private
 * key over a fresh in-memory challenge after an explicit user confirmation.
 */
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useCitizenCardBridgeStatus, useTestCitizenCardBridge } from '../../api/hooks';
import { ConfirmActionModal } from '../../ui/ConfirmActionModal';
import { PageHeader } from '../../ui';
import { PermissionDeniedNote, useCan } from '../session/permissions';
import { CitizenCardBridgeDiagnostics } from './CitizenCardBridgeDiagnostics';
import { useCitizenCardBridgePageT } from './CitizenCardBridgePageFallback';

const SIGNING_PROVIDERS_PATH = '/admin/signing/trust-services';

/**
 * Replaces transport/provider errors with fixed feature copy before they reach ErrorNote or the
 * confirmation modal's toast. The API DTO carries only reviewed diagnostics, but thrown client
 * errors can contain URLs or host details and therefore never render verbatim on this surface.
 */
function sanitizedError(error: unknown, message: string): Error | undefined {
  return error ? new Error(message) : undefined;
}

export function CitizenCardBridgePage() {
  const t = useCitizenCardBridgePageT();
  const can = useCan();
  const canConfigure = can('signing.configure');
  const canPerform = can('signing.perform');
  const status = useCitizenCardBridgeStatus(canConfigure);
  const probe = useTestCitizenCardBridge();
  const [confirmingProbe, setConfirmingProbe] = useState(false);

  return (
    <div className="stack form-page">
      <PageHeader
        crumbs={<Link to={SIGNING_PROVIDERS_PATH}>{t('ccBridge.page.back')}</Link>}
        title={t('ccBridge.page.title')}
      />

      {!canConfigure ? (
        <PermissionDeniedNote />
      ) : (
        <CitizenCardBridgeDiagnostics
          status={status.data ?? null}
          statusError={sanitizedError(status.error, t('ccBridge.page.statusError'))}
          isRefreshing={status.isLoading || status.isFetching}
          onRefresh={() => {
            void status.refetch();
          }}
          probe={probe.data ?? null}
          probeError={sanitizedError(probe.error, t('ccBridge.page.probeError'))}
          isTesting={probe.isPending}
          canTest={canConfigure && canPerform}
          onTest={() => setConfirmingProbe(true)}
        />
      )}

      <ConfirmActionModal
        open={canConfigure && canPerform && confirmingProbe}
        onClose={() => setConfirmingProbe(false)}
        title={t('ccBridge.page.confirm.title')}
        intro={<p>{t('ccBridge.page.confirm.intro')}</p>}
        confirmLabel={t('ccBridge.page.confirm.action')}
        pendingLabel={t('ccBridge.page.confirm.pending')}
        pending={probe.isPending}
        onConfirm={async () => {
          try {
            await probe.mutateAsync();
          } catch {
            throw new Error(t('ccBridge.page.probeError'));
          }
        }}
      />
    </div>
  );
}
