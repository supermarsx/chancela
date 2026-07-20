import { useEffect, useLayoutEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import type { ActView, CcBatchDocResult, CcBatchSignResponse } from '../../api/types';
import { MAX_CC_BATCH_ACTS } from '../../api/types';
import { useCcBatchSign } from '../../api/hooks';
import { useT, type TFunction } from '../../i18n';
import {
  Badge,
  Button,
  Digest,
  ErrorNote,
  Field,
  Icon,
  IconButton,
  InlineWarning,
  Input,
  Table,
  useToast,
} from '../../ui';
import { GateButton, type CanScope } from '../session/permissions';

type BatchSigningItem = {
  actId: string;
  label: string;
  source: 'current' | 'manual';
};

function authModeLabel(authMode: CcBatchSignResponse['auth_mode'], t: TFunction) {
  if (authMode === 'single_auth') return t('signing.ccBatch.authMode.single');
  return t('signing.ccBatch.authMode.perDocument');
}

function resultStatusBadge(result: CcBatchDocResult, t: TFunction) {
  if (result.status === 'signed') {
    return <Badge tone="ok">{t('signing.ccBatch.result.signed')}</Badge>;
  }
  return <Badge tone="error">{t('signing.ccBatch.result.error')}</Badge>;
}

export function BatchSigningPanel({
  currentAct,
  bookScope,
}: {
  currentAct: ActView;
  bookScope: CanScope;
}) {
  const t = useT();
  const toast = useToast();
  const ccBatchSign = useCcBatchSign();
  const resetCcBatchSign = ccBatchSign.reset;
  const currentItem = useMemo<BatchSigningItem>(
    () => ({
      actId: currentAct.id,
      label: currentAct.title || currentAct.id,
      source: 'current',
    }),
    [currentAct.id, currentAct.title],
  );
  const previousActIdRef = useRef(currentAct.id);
  const [items, setItems] = useState<BatchSigningItem[]>(() => [currentItem]);
  const [selectedActIds, setSelectedActIds] = useState<Set<string>>(() => new Set([currentAct.id]));
  const [manualActId, setManualActId] = useState('');
  const [capacity, setCapacity] = useState('');
  const [actor, setActor] = useState('');
  const [pin, setPin] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [response, setResponse] = useState<CcBatchSignResponse | null>(null);
  const requestGenerationRef = useRef(0);
  const mountedRef = useRef(true);

  useLayoutEffect(() => {
    if (previousActIdRef.current !== currentAct.id) {
      requestGenerationRef.current += 1;
      previousActIdRef.current = currentAct.id;
      setItems([currentItem]);
      setSelectedActIds(new Set([currentAct.id]));
      setManualActId('');
      setCapacity('');
      setActor('');
      setPin('');
      setError(null);
      setResponse(null);
      resetCcBatchSign();
      return;
    }

    setItems((existing) => {
      const withoutOldCurrent = existing.filter((item) => item.source !== 'current');
      const hasCurrent = withoutOldCurrent.some((item) => item.actId === currentItem.actId);
      return hasCurrent ? withoutOldCurrent : [currentItem, ...withoutOldCurrent];
    });
  }, [currentAct.id, currentItem, resetCcBatchSign]);

  useEffect(() => {
    return () => {
      mountedRef.current = false;
      requestGenerationRef.current += 1;
      resetCcBatchSign();
    };
  }, [resetCcBatchSign]);

  const selectedIds = useMemo(
    () => items.map((item) => item.actId).filter((actId) => selectedActIds.has(actId)),
    [items, selectedActIds],
  );
  const canSubmit = selectedIds.length >= 2 && selectedIds.length <= MAX_CC_BATCH_ACTS;
  const maxReached = items.length >= MAX_CC_BATCH_ACTS;

  function toggleAct(actId: string, checked: boolean) {
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
    setItems((current) => [
      ...current,
      { actId, label: t('signing.ccBatch.manual.label', { id: actId }), source: 'manual' },
    ]);
    setSelectedActIds((current) => new Set([...current, actId]));
    setManualActId('');
    setError(null);
    setResponse(null);
  }

  function removeManualActId(actId: string) {
    setItems((current) => current.filter((item) => item.actId !== actId));
    setSelectedActIds((current) => {
      const next = new Set(current);
      next.delete(actId);
      return next;
    });
  }

  function resetPanel() {
    requestGenerationRef.current += 1;
    setItems([currentItem]);
    setSelectedActIds(new Set([currentAct.id]));
    setManualActId('');
    setCapacity('');
    setActor('');
    setPin('');
    setError(null);
    setResponse(null);
    ccBatchSign.reset();
  }

  async function submitBatch(e: FormEvent) {
    e.preventDefault();
    if (!canSubmit || ccBatchSign.isPending) return;
    const requestGeneration = (requestGenerationRef.current += 1);
    setError(null);
    setResponse(null);
    const trimmedCapacity = capacity.trim();
    const trimmedActor = actor.trim();
    const trimmedPin = pin.trim();
    try {
      const result = await ccBatchSign.mutateAsync({
        act_ids: selectedIds,
        capacity: trimmedCapacity || undefined,
        actor: trimmedActor || undefined,
        pin: trimmedPin || undefined,
      });
      if (!mountedRef.current || requestGenerationRef.current !== requestGeneration) return;
      setResponse(result);
      toast.success(t('toast.signing.ccBatchSigned'));
    } catch (err) {
      if (!mountedRef.current || requestGenerationRef.current !== requestGeneration) return;
      setError(err);
      toast.error(err);
    } finally {
      if (mountedRef.current && requestGenerationRef.current === requestGeneration) {
        setPin('');
        ccBatchSign.reset();
      }
    }
  }

  return (
    <section
      className="signing-provider signing-provider--batch stack--tight"
      aria-label={t('signing.ccBatch.aria')}
    >
      <div className="signing-provider__copy stack--tight">
        <div className="signing-provider__titleline">
          <strong>{t('signing.ccBatch.title')}</strong>
          <Badge tone="accent">{t('signing.ccBatch.badge')}</Badge>
        </div>
        <p>{t('signing.ccBatch.description')}</p>
      </div>

      <form className="form stack--tight" onSubmit={submitBatch}>
        <InlineWarning tone="info" title={t('signing.ccBatch.boundary.title')}>
          {t('signing.ccBatch.boundary.body')}
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
                    disabled={ccBatchSign.isPending}
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
                      disabled={ccBatchSign.isPending}
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
              max: String(MAX_CC_BATCH_ACTS),
            })}
          </p>
        </div>

        <div className="rowline">
          <Field
            label={t('signing.ccBatch.add.label')}
            htmlFor="cc-batch-act-id"
            hint={t('signing.ccBatch.add.hint')}
          >
            <Input
              id="cc-batch-act-id"
              type="text"
              autoComplete="off"
              value={manualActId}
              disabled={ccBatchSign.isPending || maxReached}
              onChange={(event) => setManualActId(event.target.value)}
            />
          </Field>
          <Button
            type="button"
            variant="secondary"
            icon={<Icon.Plus />}
            disabled={!manualActId.trim() || maxReached || ccBatchSign.isPending}
            onClick={addManualActId}
          >
            {t('signing.ccBatch.add.action')}
          </Button>
        </div>
        {maxReached ? (
          <p className="field__hint">
            {t('signing.ccBatch.maxReached', { max: String(MAX_CC_BATCH_ACTS) })}
          </p>
        ) : null}

        <div className="form__grid">
          <Field
            label={t('signing.ccBatch.capacity.label')}
            htmlFor="cc-batch-capacity"
            hint={t('signing.ccBatch.capacity.hint')}
          >
            <Input
              id="cc-batch-capacity"
              type="text"
              autoComplete="off"
              value={capacity}
              disabled={ccBatchSign.isPending}
              onChange={(event) => setCapacity(event.target.value)}
            />
          </Field>
          <Field
            label={t('signing.ccBatch.actor.label')}
            htmlFor="cc-batch-actor"
            hint={t('signing.ccBatch.actor.hint')}
          >
            <Input
              id="cc-batch-actor"
              type="text"
              autoComplete="off"
              value={actor}
              disabled={ccBatchSign.isPending}
              onChange={(event) => setActor(event.target.value)}
            />
          </Field>
          <Field
            label={t('signing.cc.pin.label')}
            htmlFor="cc-batch-pin"
            hint={t('signing.ccBatch.pin.hint')}
          >
            <Input
              id="cc-batch-pin"
              type="password"
              inputMode="numeric"
              autoComplete="off"
              value={pin}
              maxLength={12}
              placeholder={t('signing.cc.pin.placeholder')}
              disabled={ccBatchSign.isPending}
              onChange={(event) => setPin(event.target.value.slice(0, 12))}
            />
          </Field>
        </div>

        {!canSubmit ? (
          <p className="field__hint">{t('signing.ccBatch.selection.needMore')}</p>
        ) : null}
        {error ? <ErrorNote error={error} /> : null}

        <div className="rowline">
          <GateButton
            perm="signing.perform"
            scope={bookScope}
            type="submit"
            variant="primary"
            icon={<Icon.IdCard />}
            disabled={!canSubmit || ccBatchSign.isPending}
          >
            {ccBatchSign.isPending
              ? t('signing.ccBatch.submit.pending')
              : t('signing.ccBatch.submit')}
          </GateButton>
          <Button
            type="button"
            variant="ghost"
            icon={<Icon.Refresh />}
            disabled={ccBatchSign.isPending}
            onClick={resetPanel}
          >
            {t('signing.ccBatch.reset')}
          </Button>
        </div>
      </form>

      {response ? <BatchSigningResult response={response} /> : null}
    </section>
  );
}

function BatchSigningResult({ response }: { response: CcBatchSignResponse }) {
  const t = useT();
  return (
    <section className="stack--tight" aria-live="polite">
      <dl className="deflist signing-deflist signing-deflist--compact">
        <div>
          <dt>{t('signing.ccBatch.result.authMode')}</dt>
          <dd>{authModeLabel(response.auth_mode, t)}</dd>
        </div>
        <div>
          <dt>{t('signing.ccBatch.result.authEvents')}</dt>
          <dd>{response.auth_events}</dd>
        </div>
        <div>
          <dt>{t('signing.ccBatch.result.requested')}</dt>
          <dd>{response.requested}</dd>
        </div>
        <div>
          <dt>{t('signing.ccBatch.result.signedCount')}</dt>
          <dd>{response.signed}</dd>
        </div>
        <div>
          <dt>{t('signing.ccBatch.result.failedCount')}</dt>
          <dd>{response.failed}</dd>
        </div>
        {response.trusted_list_status ? (
          <div>
            <dt>{t('signing.ccBatch.result.trustedList')}</dt>
            <dd>{response.trusted_list_status}</dd>
          </div>
        ) : null}
        {response.signer_capacity_evidence ? (
          <div className="signing-deflist__wide">
            <dt>{t('signing.ccBatch.result.capacityEvidence')}</dt>
            <dd>
              {t('signing.ccBatch.result.capacityEvidenceText', {
                capacity: response.signer_capacity_evidence.requested_provider_capacity,
                status: response.signer_capacity_evidence.verification_status,
                scope: response.signer_capacity_evidence.status_scope,
              })}
            </dd>
          </div>
        ) : null}
      </dl>
      <p className="field__hint">{t('signing.ccBatch.result.boundary')}</p>
      <Table
        head={
          <tr>
            <th>{t('signing.ccBatch.result.table.act')}</th>
            <th>{t('signing.ccBatch.result.table.status')}</th>
            <th>{t('signing.ccBatch.result.table.document')}</th>
            <th>{t('signing.ccBatch.result.table.signedAt')}</th>
            <th>{t('signing.ccBatch.result.table.digest')}</th>
            <th>{t('signing.ccBatch.result.table.evidence')}</th>
          </tr>
        }
      >
        {response.results.map((result) => (
          <tr key={result.act_id}>
            <td className="mono">{result.act_id}</td>
            <td>{resultStatusBadge(result, t)}</td>
            <td>{result.document_id ? <span className="mono">{result.document_id}</span> : '—'}</td>
            <td>{result.signed_at ?? '—'}</td>
            <td>{result.signed_pdf_digest ? <Digest value={result.signed_pdf_digest} /> : '—'}</td>
            <td>
              {result.status === 'error'
                ? (result.error ?? t('common.error'))
                : result.timestamp_token == null
                  ? '—'
                  : result.timestamp_token
                    ? t('signing.signed.timestampPresent')
                    : t('signing.signed.timestampAbsent')}
            </td>
          </tr>
        ))}
      </Table>
    </section>
  );
}
