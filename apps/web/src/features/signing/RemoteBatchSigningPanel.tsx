import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
} from 'react';
import type {
  ActView,
  RemoteBatchInitiateResponse,
  RemoteBatchInitiateResult,
  SealAppearanceBody,
  SignatureProviderView,
} from '../../api/types';
import { MAX_REMOTE_BATCH_ACTS } from '../../api/types';
import { useRemoteBatchInitiateSignature } from '../../api/hooks';
import { useT, type TFunction } from '../../i18n';
import {
  Badge,
  Button,
  ErrorNote,
  Field,
  Icon,
  IconButton,
  InlineWarning,
  Input,
  Select,
  Table,
  useToast,
} from '../../ui';
import { GateButton, type CanScope } from '../session/permissions';

type RemoteBatchItem = {
  actId: string;
  label: string;
  source: 'current' | 'manual';
};

function authModeLabel(authMode: RemoteBatchInitiateResponse['auth_mode'], t: TFunction) {
  if (authMode === 'per_document_activation')
    return t('signing.remoteBatch.authMode.perDocumentActivation');
  return authMode;
}

function resultStatusBadge(result: RemoteBatchInitiateResult, t: TFunction) {
  if (result.status === 'pending') {
    return <Badge tone="ok">{t('signing.remoteBatch.result.pending')}</Badge>;
  }
  return <Badge tone="error">{t('signing.remoteBatch.result.error')}</Badge>;
}

function RemoteBatchProviderManifest({ provider }: { provider?: SignatureProviderView }) {
  const t = useT();
  const manifest = provider?.manifest;
  if (!manifest) return null;
  return (
    <InlineWarning tone="info" title={t('signing.remoteBatch.manifest.title')}>
      {t('signing.remoteBatch.manifest.body', {
        provider: provider.label,
        repeated: manifest.capabilities.remote_batch_repeated_per_document_initiate
          ? t('common.yes')
          : t('common.no'),
        native: manifest.capabilities.provider_native_batch_claimed ? t('common.yes') : t('common.no'),
        single: manifest.capabilities.single_otp_pin_sad_batch_claimed
          ? t('common.yes')
          : t('common.no'),
      })}
    </InlineWarning>
  );
}

export function RemoteBatchSigningPanel({
  currentAct,
  bookScope,
  providers,
  seal,
}: {
  currentAct: ActView;
  bookScope: CanScope;
  providers: SignatureProviderView[];
  seal?: SealAppearanceBody | null;
}) {
  const t = useT();
  const toast = useToast();
  const remoteBatch = useRemoteBatchInitiateSignature();
  const resetRemoteBatch = remoteBatch.reset;
  const currentItem = useMemo<RemoteBatchItem>(
    () => ({
      actId: currentAct.id,
      label: currentAct.title || currentAct.id,
      source: 'current',
    }),
    [currentAct.id, currentAct.title],
  );
  const providerOptions = useMemo(
    () =>
      providers
        .filter((provider) => provider.configured)
        .map((provider) => ({ value: provider.id, label: provider.label })),
    [providers],
  );
  const sealSignature = useMemo(() => JSON.stringify(seal ?? null), [seal]);
  const previousActIdRef = useRef(currentAct.id);
  const [items, setItems] = useState<RemoteBatchItem[]>(() => [currentItem]);
  const [selectedActIds, setSelectedActIds] = useState<Set<string>>(() => new Set([currentAct.id]));
  const [manualActId, setManualActId] = useState('');
  const [providerId, setProviderId] = useState(() => providerOptions[0]?.value ?? '');
  const [userRef, setUserRef] = useState('');
  const [credential, setCredential] = useState('');
  const [capacity, setCapacity] = useState('');
  const [actor, setActor] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [response, setResponse] = useState<RemoteBatchInitiateResponse | null>(null);
  const requestGenerationRef = useRef(0);
  const credentialProviderRef = useRef<string | null>(providerId);
  const previousSealSignatureRef = useRef(sealSignature);
  const mountedRef = useRef(true);
  const selectedProvider = useMemo(
    () => providers.find((provider) => provider.id === providerId),
    [providerId, providers],
  );

  const clearRequestArtifacts = useCallback(() => {
    requestGenerationRef.current += 1;
    setError(null);
    setResponse(null);
    resetRemoteBatch();
  }, [resetRemoteBatch]);

  const changeProvider = useCallback(
    (nextProviderId: string) => {
      if (nextProviderId === providerId) return;
      credentialProviderRef.current = null;
      setProviderId(nextProviderId);
      setCredential('');
      clearRequestArtifacts();
    },
    [clearRequestArtifacts, providerId],
  );

  useLayoutEffect(() => {
    if (previousActIdRef.current !== currentAct.id) {
      requestGenerationRef.current += 1;
      previousActIdRef.current = currentAct.id;
      setItems([currentItem]);
      setSelectedActIds(new Set([currentAct.id]));
      setManualActId('');
      setUserRef('');
      setCredential('');
      credentialProviderRef.current = null;
      setCapacity('');
      setActor('');
      setError(null);
      setResponse(null);
      resetRemoteBatch();
      return;
    }

    setItems((existing) => {
      const withoutOldCurrent = existing.filter((item) => item.source !== 'current');
      const hasCurrent = withoutOldCurrent.some((item) => item.actId === currentItem.actId);
      return hasCurrent ? withoutOldCurrent : [currentItem, ...withoutOldCurrent];
    });
  }, [currentAct.id, currentItem, resetRemoteBatch]);

  useEffect(() => {
    const nextProviderId =
      providerOptions.length === 0
        ? ''
        : providerOptions.some((provider) => provider.value === providerId)
          ? providerId
          : providerOptions[0].value;
    changeProvider(nextProviderId);
  }, [changeProvider, providerId, providerOptions]);

  useEffect(() => {
    if (previousSealSignatureRef.current === sealSignature) return;
    previousSealSignatureRef.current = sealSignature;
    clearRequestArtifacts();
  }, [clearRequestArtifacts, sealSignature]);

  useEffect(() => {
    return () => {
      mountedRef.current = false;
      requestGenerationRef.current += 1;
      resetRemoteBatch();
    };
  }, [resetRemoteBatch]);

  const selectedIds = useMemo(
    () => items.map((item) => item.actId).filter((actId) => selectedActIds.has(actId)),
    [items, selectedActIds],
  );
  const canSubmit =
    providerId.length > 0 &&
    userRef.trim().length > 0 &&
    selectedIds.length >= 2 &&
    selectedIds.length <= MAX_REMOTE_BATCH_ACTS;
  const maxReached = items.length >= MAX_REMOTE_BATCH_ACTS;

  function toggleAct(actId: string, checked: boolean) {
    clearRequestArtifacts();
    setSelectedActIds((current) => {
      const next = new Set(current);
      if (checked) next.add(actId);
      else next.delete(actId);
      return next;
    });
  }

  function addManualActId() {
    const actId = manualActId.trim();
    if (!actId || maxReached || items.some((item) => item.actId === actId)) {
      setManualActId('');
      return;
    }
    clearRequestArtifacts();
    setItems((current) => [
      ...current,
      { actId, label: t('signing.ccBatch.manual.label', { id: actId }), source: 'manual' },
    ]);
    setSelectedActIds((current) => new Set([...current, actId]));
    setManualActId('');
  }

  function removeManualActId(actId: string) {
    clearRequestArtifacts();
    setItems((current) => current.filter((item) => item.actId !== actId));
    setSelectedActIds((current) => {
      const next = new Set(current);
      next.delete(actId);
      return next;
    });
  }

  function changeUserRef(value: string) {
    setUserRef(value);
    clearRequestArtifacts();
  }

  function changeCredential(value: string) {
    credentialProviderRef.current = providerId;
    setCredential(value);
    clearRequestArtifacts();
  }

  function changeCapacity(value: string) {
    setCapacity(value);
    clearRequestArtifacts();
  }

  function changeActor(value: string) {
    setActor(value);
    clearRequestArtifacts();
  }

  function resetPanel() {
    requestGenerationRef.current += 1;
    setItems([currentItem]);
    setSelectedActIds(new Set([currentAct.id]));
    setManualActId('');
    setUserRef('');
    setCredential('');
    credentialProviderRef.current = null;
    setCapacity('');
    setActor('');
    setError(null);
    setResponse(null);
    remoteBatch.reset();
  }

  async function submitBatch(e: FormEvent) {
    e.preventDefault();
    if (!canSubmit || remoteBatch.isPending) return;
    const requestGeneration = (requestGenerationRef.current += 1);
    setError(null);
    setResponse(null);
    const trimmedUserRef = userRef.trim();
    const trimmedCapacity = capacity.trim();
    const trimmedActor = actor.trim();
    const requestCredential = credentialProviderRef.current === providerId ? credential : '';
    try {
      const result = await remoteBatch.mutateAsync({
        provider: providerId,
        body: {
          act_ids: selectedIds,
          user_ref: trimmedUserRef,
          credential: requestCredential.length > 0 ? requestCredential : undefined,
          capacity: trimmedCapacity || undefined,
          actor: trimmedActor || undefined,
          seal: seal ?? undefined,
        },
      });
      if (!mountedRef.current || requestGenerationRef.current !== requestGeneration) return;
      setResponse(result);
      toast.success(t('toast.signing.remoteBatchInitiated'));
    } catch (err) {
      if (!mountedRef.current || requestGenerationRef.current !== requestGeneration) return;
      setError(err);
      toast.error(err);
    } finally {
      if (mountedRef.current && requestGenerationRef.current === requestGeneration) {
        credentialProviderRef.current = null;
        setCredential('');
        remoteBatch.reset();
      }
    }
  }

  return (
    <section
      className="signing-provider signing-provider--batch stack--tight"
      aria-label={t('signing.remoteBatch.aria')}
    >
      <div className="signing-provider__copy stack--tight">
        <div className="signing-provider__titleline">
          <strong>{t('signing.remoteBatch.title')}</strong>
          <Badge tone="accent">{t('signing.remoteBatch.badge')}</Badge>
        </div>
        <p>{t('signing.remoteBatch.description')}</p>
      </div>

      <form className="form stack--tight" onSubmit={submitBatch}>
        <InlineWarning tone="info" title={t('signing.remoteBatch.boundary.title')}>
          {t('signing.remoteBatch.boundary.body')}
        </InlineWarning>

        <div className="stack--tight">
          <p className="card__label">{t('signing.ccBatch.selection.title')}</p>
          <Table
            head={
              <tr>
                <th>{t('signing.ccBatch.table.select')}</th>
                <th>{t('signing.ccBatch.table.act')}</th>
                <th>{t('signing.ccBatch.table.source')}</th>
                <th>{t('signing.ccBatch.table.actions')}</th>
              </tr>
            }
          >
            {items.map((item) => (
              <tr key={item.actId}>
                <td>
                  <input
                    type="checkbox"
                    aria-label={t('signing.ccBatch.selectAct', { id: item.actId })}
                    checked={selectedActIds.has(item.actId)}
                    disabled={remoteBatch.isPending}
                    onChange={(event) => toggleAct(item.actId, event.target.checked)}
                  />
                </td>
                <td>
                  <span className="mono">{item.actId}</span>
                  {item.label !== item.actId ? <p className="field__hint">{item.label}</p> : null}
                </td>
                <td>
                  {item.source === 'current'
                    ? t('signing.ccBatch.source.current')
                    : t('signing.ccBatch.source.manual')}
                </td>
                <td>
                  {item.source === 'manual' ? (
                    <IconButton
                      icon={<Icon.Trash />}
                      label={t('signing.ccBatch.removeAct')}
                      placement="left"
                      disabled={remoteBatch.isPending}
                      onClick={() => removeManualActId(item.actId)}
                    />
                  ) : (
                    '—'
                  )}
                </td>
              </tr>
            ))}
          </Table>
          <p className="field__hint">
            {t('signing.ccBatch.selection.count', {
              count: String(selectedIds.length),
              max: String(MAX_REMOTE_BATCH_ACTS),
            })}
          </p>
        </div>

        <div className="rowline">
          <Field
            label={t('signing.ccBatch.add.label')}
            htmlFor="remote-batch-act-id"
            hint={t('signing.ccBatch.add.hint')}
          >
            <Input
              id="remote-batch-act-id"
              type="text"
              autoComplete="off"
              value={manualActId}
              disabled={remoteBatch.isPending || maxReached}
              onChange={(event) => setManualActId(event.target.value)}
            />
          </Field>
          <Button
            type="button"
            variant="secondary"
            icon={<Icon.Plus />}
            disabled={!manualActId.trim() || maxReached || remoteBatch.isPending}
            onClick={addManualActId}
          >
            {t('signing.ccBatch.add.action')}
          </Button>
        </div>
        {maxReached ? (
          <p className="field__hint">
            {t('signing.ccBatch.maxReached', { max: String(MAX_REMOTE_BATCH_ACTS) })}
          </p>
        ) : null}

        <div className="form__grid">
          <Field
            label={t('signing.remoteBatch.provider.label')}
            htmlFor="remote-batch-provider"
            hint={t('signing.remoteBatch.provider.hint')}
          >
            <Select
              id="remote-batch-provider"
              value={providerId}
              disabled={remoteBatch.isPending || providerOptions.length === 0}
              onChange={(event) => changeProvider(event.target.value)}
              options={
                providerOptions.length > 0
                  ? providerOptions
                  : [{ value: '', label: t('signing.remoteBatch.provider.none') }]
              }
            />
          </Field>
          <Field
            label={t('signing.remoteBatch.userRef.label')}
            htmlFor="remote-batch-user-ref"
            hint={t('signing.remoteBatch.userRef.hint')}
          >
            <Input
              id="remote-batch-user-ref"
              type="text"
              autoComplete="off"
              value={userRef}
              disabled={remoteBatch.isPending}
              onChange={(event) => changeUserRef(event.target.value)}
            />
          </Field>
          <Field
            label={t('signing.remoteBatch.credential.label')}
            htmlFor="remote-batch-credential"
            hint={t('signing.remoteBatch.credential.hint')}
          >
            <Input
              id="remote-batch-credential"
              type="password"
              autoComplete="off"
              value={credential}
              disabled={remoteBatch.isPending}
              onChange={(event) => changeCredential(event.target.value)}
            />
          </Field>
          <Field
            label={t('signing.ccBatch.capacity.label')}
            htmlFor="remote-batch-capacity"
            hint={t('signing.ccBatch.capacity.hint')}
          >
            <Input
              id="remote-batch-capacity"
              type="text"
              autoComplete="off"
              value={capacity}
              disabled={remoteBatch.isPending}
              onChange={(event) => changeCapacity(event.target.value)}
            />
          </Field>
          <Field
            label={t('signing.ccBatch.actor.label')}
            htmlFor="remote-batch-actor"
            hint={t('signing.ccBatch.actor.hint')}
          >
            <Input
              id="remote-batch-actor"
              type="text"
              autoComplete="off"
              value={actor}
              disabled={remoteBatch.isPending}
              onChange={(event) => changeActor(event.target.value)}
            />
          </Field>
        </div>
        <RemoteBatchProviderManifest provider={selectedProvider} />

        {!canSubmit ? (
          <p className="field__hint">{t('signing.remoteBatch.selection.needMore')}</p>
        ) : null}
        {error ? <ErrorNote error={error} /> : null}

        <div className="rowline">
          <GateButton
            perm="signing.perform"
            scope={bookScope}
            type="submit"
            variant="primary"
            icon={<Icon.PenNib />}
            disabled={!canSubmit || remoteBatch.isPending}
          >
            {remoteBatch.isPending
              ? t('signing.remoteBatch.submit.pending')
              : t('signing.remoteBatch.submit')}
          </GateButton>
          <Button
            type="button"
            variant="ghost"
            icon={<Icon.Refresh />}
            disabled={remoteBatch.isPending}
            onClick={resetPanel}
          >
            {t('signing.remoteBatch.reset')}
          </Button>
        </div>
      </form>

      {response ? <RemoteBatchInitiateResultView response={response} /> : null}
    </section>
  );
}

function RemoteBatchInitiateResultView({ response }: { response: RemoteBatchInitiateResponse }) {
  const t = useT();
  return (
    <section className="stack--tight" aria-live="polite">
      <dl className="deflist signing-deflist signing-deflist--compact">
        <div>
          <dt>{t('signing.remoteBatch.result.authMode')}</dt>
          <dd>{authModeLabel(response.auth_mode, t)}</dd>
        </div>
        <div>
          <dt>{t('signing.ccBatch.result.requested')}</dt>
          <dd>{response.requested}</dd>
        </div>
        <div>
          <dt>{t('signing.remoteBatch.result.pendingCount')}</dt>
          <dd>{response.pending}</dd>
        </div>
        <div>
          <dt>{t('signing.ccBatch.result.failedCount')}</dt>
          <dd>{response.failed}</dd>
        </div>
        <div>
          <dt>{t('signing.remoteBatch.result.initiateEvents')}</dt>
          <dd>{response.initiate_events}</dd>
        </div>
      </dl>
      <p className="field__hint">{t('signing.remoteBatch.result.boundary')}</p>
      <Table
        head={
          <tr>
            <th>{t('signing.ccBatch.result.table.act')}</th>
            <th>{t('signing.ccBatch.result.table.status')}</th>
            <th>{t('signing.remoteBatch.result.table.session')}</th>
            <th>{t('signing.remoteBatch.result.table.provider')}</th>
            <th>{t('signing.remoteBatch.result.table.activation')}</th>
            <th>{t('signing.remoteBatch.result.table.expires')}</th>
          </tr>
        }
      >
        {response.results.map((result) => (
          <tr key={result.act_id}>
            <td className="mono">{result.act_id}</td>
            <td>{resultStatusBadge(result, t)}</td>
            <td>{result.session_id ? <span className="mono">{result.session_id}</span> : '—'}</td>
            <td>
              {result.provider_id ? (
                <>
                  <span className="mono">{result.provider_id}</span>
                  {result.family ? <p className="field__hint">{result.family}</p> : null}
                </>
              ) : (
                '—'
              )}
            </td>
            <td>
              {result.status === 'error' ? (
                result.error ?? t('common.error')
              ) : (
                <>
                  {result.activation_hint ?? '—'}
                  <p className="field__hint">{t('signing.remoteBatch.result.confirmNormally')}</p>
                </>
              )}
            </td>
            <td>{result.expires_at ?? '—'}</td>
          </tr>
        ))}
      </Table>
      <p className="field__hint">{t('signing.remoteBatch.result.noSecret')}</p>
    </section>
  );
}
