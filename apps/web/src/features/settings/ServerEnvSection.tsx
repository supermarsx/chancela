/**
 * "Ambiente do servidor" (t14) — the Operações pane that renders the server-declared env-override
 * registry (`GET /v1/platform/env`) and writes non-secret overrides back (`PUT /v1/platform/env`).
 *
 * This is the editable superset of the read-only environment panes already under Operações
 * (Servidor/API, Base de dados, Redis): those transcribe a curated handful of launch-time vars as
 * facts, while this pane lists everything the server *declares* and lets an operator override the
 * ones that are safe to. The server owns the classification; the pane renders whatever tier each
 * var carries and never invents an affordance the registry did not grant.
 *
 * **The four tiers, exactly as the registry declares them.**
 * - **Tier A** (`editable`, non-secret, non-boundary): a plain editor. Empty clears the override.
 * - **Tier C** (`editable`, `boundary`): the same editor, but a change is inert until its
 *   acknowledgement toggle is checked — the `email.allow_insecure` mould. The server enforces a
 *   `422` if an unacknowledged boundary change reaches it; this toggle is the discovery mechanism,
 *   the `422` the backstop.
 * - **Tier B** (`secret`): display-only. A `configured`/masked state, NEVER an input — the value is
 *   never echoed by the server and is never solicited here.
 * - **Tier D** and typed-slice-excluded vars (`editable: false`, non-secret): a read-only fact with
 *   the reason it cannot be edited here (derived from the process, or governed by a dedicated
 *   setting with its own precedence). Narrow-only ceilings carry the "can only narrow" note.
 *
 * **Restart-to-apply is the whole model.** Every value is resolved once at process start, so an
 * override is stored but does not take effect until the next restart. The response's
 * `restart_pending` raises a banner; a row whose stored override differs from the running value
 * carries its own badge. Nothing here ever implies a live change.
 *
 * **Copy lives in the shared catalogs** under `settings.serverEnv.*`, translated in all fourteen
 * locales. (It briefly lived in a two-locale `serverEnvFallback` module while the catalogs were
 * under a write lock; that module is gone and the pane reads `t(...)` like everything else.) RBAC
 * mirrors the rest of Settings: the editors are gated on `settings.manage`; a reader without it sees
 * the same facts, read-only.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { useServerEnv, useUpdateServerEnv } from '../../api/hooks';
import { SERVER_ENV_GROUPS, type ServerEnvVarGroup, type ServerEnvVarView } from '../../api/types';
import { useT, type MessageKey } from '../../i18n';
import { useCan } from '../session/permissions';
import {
  Badge,
  Button,
  Card,
  ErrorNote,
  InlineWarning,
  Input,
  Select,
  Toggle,
  useToast,
} from '../../ui';

/** The override map keyed by var name. An absent key (or an empty string) means "no override". */
type OverrideDraft = Record<string, string>;

/** The saved overrides the response declares, as the pane's editing baseline: a var carries an entry
 *  only when it currently has an override. Tier A/C editable vars only — nothing else is writable. */
function baselineOverrides(vars: readonly ServerEnvVarView[]): OverrideDraft {
  const draft: OverrideDraft = {};
  for (const v of vars) {
    if (v.editable && v.override_value !== null) draft[v.name] = v.override_value;
  }
  return draft;
}

/** A var's value in the working draft, normalised so "" and "absent" compare equal. */
function draftValue(draft: OverrideDraft, name: string): string {
  return draft[name] ?? '';
}

/** The group label key — the registry's group ids are exactly the catalog's `group.*` key suffixes,
 *  so a group the server adds without a matching catalog key is a compile-time miss, not a blank. */
function groupKey(group: ServerEnvVarGroup): MessageKey {
  return `settings.serverEnv.group.${group}` as MessageKey;
}

export function ServerEnvSection() {
  const t = useT();
  const toast = useToast();
  const can = useCan();
  const canManage = can('settings.manage');

  const query = useServerEnv();
  const update = useUpdateServerEnv();
  const data = query.data;

  const baseline = useMemo(() => baselineOverrides(data?.vars ?? []), [data?.vars]);

  // The editing draft is reseeded from the baseline whenever a fresh generation of the view arrives
  // — the first load, and each successful PUT (the mutation seeds the query cache from its response).
  // Keying on `generated_at` keeps local edits stable between renders but discards them once the
  // server's own view moves on, so a saved override never lingers as a phantom "unsaved change".
  const [draft, setDraft] = useState<OverrideDraft>({});
  const [acks, setAcks] = useState<Record<string, boolean>>({});
  const lastGeneration = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (data && data.generated_at !== lastGeneration.current) {
      lastGeneration.current = data.generated_at;
      setDraft(baseline);
      setAcks({});
    }
  }, [data, baseline]);

  const setOverride = (name: string, value: string) =>
    setDraft((prev) => ({ ...prev, [name]: value }));

  const editableVars = useMemo(() => (data?.vars ?? []).filter((v) => v.editable), [data?.vars]);

  const isDirty = (v: ServerEnvVarView): boolean =>
    draftValue(draft, v.name) !== draftValue(baseline, v.name);

  const dirtyBoundary = editableVars.filter((v) => v.boundary && isDirty(v));
  const anyDirty = editableVars.some(isDirty);
  const unacknowledged = dirtyBoundary.filter((v) => !acks[v.name]);

  const discard = () => {
    setDraft(baseline);
    setAcks({});
  };

  const save = () => {
    if (!canManage || unacknowledged.length > 0) return;
    const overrides: Record<string, string> = {};
    for (const v of editableVars) {
      const value = draftValue(draft, v.name);
      if (value !== '') overrides[v.name] = value;
    }
    update.mutate(
      { overrides, acknowledge: dirtyBoundary.map((v) => v.name) },
      { onSuccess: () => toast.success(t('settings.serverEnv.saved')) },
    );
  };

  if (query.isLoading) {
    return (
      <Card title={t('settings.serverEnv.title')}>
        <p className="muted">{t('settings.serverEnv.loading')}</p>
      </Card>
    );
  }
  if (query.error) {
    return (
      <Card title={t('settings.serverEnv.title')}>
        <ErrorNote error={query.error} />
      </Card>
    );
  }
  if (!data) return null;

  const groups = SERVER_ENV_GROUPS.filter((g) => data.vars.some((v) => v.group === g));

  return (
    <div className="stack">
      <Card title={t('settings.serverEnv.title')}>
        <div className="form settings-rows">
          <p className="field__hint">{t('settings.serverEnv.intro')}</p>
          <p className="field__hint">
            {t('settings.serverEnv.overridesPath', { path: data.overrides_path })}
          </p>
          {data.restart_pending ? (
            <InlineWarning tone="info" title={t('settings.serverEnv.restart.title')}>
              {t('settings.serverEnv.restart.body')}
            </InlineWarning>
          ) : null}
          {data.vars.length === 0 ? <p className="muted">{t('settings.serverEnv.empty')}</p> : null}
        </div>
      </Card>

      {groups.map((group) => (
        <Card key={group} title={t(groupKey(group))}>
          <div className="form settings-rows">
            {data.vars
              .filter((v) => v.group === group)
              .map((v) => (
                <EnvRow
                  key={v.name}
                  v={v}
                  value={draftValue(draft, v.name)}
                  dirty={isDirty(v)}
                  acknowledged={acks[v.name] ?? false}
                  canManage={canManage}
                  t={t}
                  onChange={(value) => setOverride(v.name, value)}
                  onAck={(checked) => setAcks((prev) => ({ ...prev, [v.name]: checked }))}
                />
              ))}
          </div>
        </Card>
      ))}

      {canManage ? (
        <Card title={t('settings.serverEnv.save')}>
          <div className="form settings-rows">
            {update.error ? <ErrorNote error={update.error} /> : null}
            {unacknowledged.length > 0 ? (
              <InlineWarning tone="warn" title={t('settings.serverEnv.boundary.warningTitle')}>
                {t('settings.serverEnv.ackRequiredError')}
              </InlineWarning>
            ) : null}
            <div className="row-wrap">
              <Button
                variant="primary"
                onClick={save}
                disabled={!anyDirty || unacknowledged.length > 0 || update.isPending}
              >
                {update.isPending ? t('settings.serverEnv.saving') : t('settings.serverEnv.save')}
              </Button>
              <Button
                variant="secondary"
                onClick={discard}
                disabled={!anyDirty || update.isPending}
              >
                {t('settings.serverEnv.discard')}
              </Button>
            </div>
          </div>
        </Card>
      ) : null}
    </div>
  );
}

/** One variable row: an editor for Tier A/C, a masked state for Tier B, a read-only fact for Tier D
 *  and typed-slice-excluded vars. The row owns its own labelling and describedby wiring. */
function EnvRow({
  v,
  value,
  dirty,
  acknowledged,
  canManage,
  t,
  onChange,
  onAck,
}: {
  v: ServerEnvVarView;
  value: string;
  dirty: boolean;
  acknowledged: boolean;
  canManage: boolean;
  t: ReturnType<typeof useT>;
  onChange: (value: string) => void;
  onAck: (checked: boolean) => void;
}) {
  const inputId = `env-${v.name}`;
  const hintId = `env-hint-${v.name}`;
  const ackId = `env-ack-${v.name}`;

  const badges = (
    <span className="row-wrap">
      {v.boundary ? <Badge tone="warn">{t('settings.serverEnv.boundary.badge')}</Badge> : null}
      {v.narrow_only ? <Badge tone="warn">{t('settings.serverEnv.narrowOnly.badge')}</Badge> : null}
      {v.external_reader !== null ? (
        <Badge tone="neutral">{t('settings.serverEnv.externalReader.badge')}</Badge>
      ) : !v.editable && !v.secret ? (
        <Badge tone="neutral">{t('settings.serverEnv.readOnly.badge')}</Badge>
      ) : null}
      {v.restart_pending ? (
        <Badge tone="info">{t('settings.serverEnv.restart.badge')}</Badge>
      ) : null}
    </span>
  );

  return (
    <div className="field">
      <span className="field__labelrow">
        <label className="field__label mono" htmlFor={v.editable ? inputId : undefined}>
          {v.name}
        </label>
        {badges}
      </span>

      {v.secret ? (
        <SecretState v={v} t={t} />
      ) : v.editable ? (
        <EnvEditor
          v={v}
          value={value}
          inputId={inputId}
          hintId={hintId}
          disabled={!canManage}
          onChange={onChange}
          t={t}
        />
      ) : null}

      {/* Value context: what the live process resolved, from where, and the code default. For an
          editable row it is the input's description (the effective value it will replace); for a
          read-only row it is the value itself. */}
      {!v.secret ? (
        <p className="field__hint" id={hintId}>
          {t('settings.serverEnv.col.value')}:{' '}
          <span className="mono">{v.effective_value ?? t('settings.serverEnv.value.unset')}</span>
          {' · '}
          {t('settings.serverEnv.col.source')}: <SourceBadge v={v} t={t} />
          {v.default_value !== null ? (
            <>
              {' · '}
              {t('settings.serverEnv.col.default')}: <span className="mono">{v.default_value}</span>
            </>
          ) : null}
        </p>
      ) : null}

      {v.editable ? <p className="field__hint">{t('settings.serverEnv.field.hint')}</p> : null}

      {/* Tier C: the acknowledgement gate + the boundary warning, shown once the row is changed. */}
      {v.editable && v.boundary && dirty ? (
        <>
          <InlineWarning tone="warn" title={t('settings.serverEnv.boundary.warningTitle')}>
            {t('settings.serverEnv.boundary.warningBody')}
          </InlineWarning>
          <Toggle
            id={ackId}
            checked={acknowledged}
            disabled={!canManage}
            onChange={onAck}
            label={t('settings.serverEnv.boundary.ackLabel')}
          />
        </>
      ) : null}

      {/* Why a read-only var cannot be edited here: a different process reads it (and never sees
          this override file), a dedicated typed setting owns it, or it is a derived fact. The
          external-reader note also applies to secrets, whose `configured` flag describes THIS
          process — so without it a masked "not configured" would read as a claim about the reader. */}
      {v.external_reader !== null ? (
        <p className="field__hint">
          {`${t('settings.serverEnv.externalReader.note')} ${v.external_reader}`}
        </p>
      ) : !v.editable && !v.secret ? (
        <p className="field__hint">
          {v.excluded_typed_slice !== null
            ? `${t('settings.serverEnv.typedSlice.note')} ${v.excluded_typed_slice}`
            : t('settings.serverEnv.readOnly.note')}
          {v.narrow_only ? ` ${t('settings.serverEnv.narrowOnly.note')}` : ''}
        </p>
      ) : null}
    </div>
  );
}

/** The Tier A/C editor: a Select for bool/enum (so "no override" is an explicit choice), a numeric
 *  Input for unsigned, a text Input otherwise. Empty clears the override. */
function EnvEditor({
  v,
  value,
  inputId,
  hintId,
  disabled,
  onChange,
  t,
}: {
  v: ServerEnvVarView;
  value: string;
  inputId: string;
  hintId: string;
  disabled: boolean;
  onChange: (value: string) => void;
  t: ReturnType<typeof useT>;
}) {
  const kind = v.validator.kind;
  const unset = t('settings.serverEnv.value.unset');

  if (kind === 'bool') {
    return (
      <Select
        id={inputId}
        aria-describedby={hintId}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
        options={[
          { value: '', label: unset },
          { value: 'true', label: t('settings.serverEnv.field.boolTrue') },
          { value: 'false', label: t('settings.serverEnv.field.boolFalse') },
        ]}
      />
    );
  }

  if (kind === 'enum') {
    return (
      <Select
        id={inputId}
        aria-describedby={hintId}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
        options={[
          { value: '', label: unset },
          ...(v.validator.allowed ?? []).map((a) => ({ value: a, label: a })),
        ]}
      />
    );
  }

  return (
    <Input
      id={inputId}
      aria-describedby={hintId}
      type={kind === 'unsigned' ? 'number' : 'text'}
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}

/** Tier B: never a value, only whether the secret is configured. */
function SecretState({ v, t }: { v: ServerEnvVarView; t: ReturnType<typeof useT> }) {
  return (
    <div className="stack--tight">
      <span className="row-wrap">
        <Badge tone={v.configured ? 'ok' : 'neutral'}>
          {v.configured
            ? t('settings.serverEnv.secret.configured')
            : t('settings.serverEnv.secret.notConfigured')}
        </Badge>
        <span className="field__hint">{t('settings.serverEnv.secret.note')}</span>
      </span>
      <p className="field__hint">{t('settings.serverEnv.secret.body')}</p>
    </div>
  );
}

/** The source of the value the live process resolved. */
function SourceBadge({ v, t }: { v: ServerEnvVarView; t: ReturnType<typeof useT> }) {
  const tone = v.source === 'override' ? 'accent' : 'neutral';
  const key = `settings.serverEnv.source.${v.source}` as MessageKey;
  return <Badge tone={tone}>{t(key)}</Badge>;
}
