/**
 * Operações › Gestão de dados — the zero-knowledge shared object root (t105).
 *
 * ## What this setting actually is
 *
 * It is **not** a path chooser. On PostgreSQL/HA the server demands that the declared value resolve
 * to exactly `<CHANCELA_DATA_DIR>/zk-repositories`; any other path fails closed. So the only thing
 * an operator supplies here is an **explicit declaration that that one directory is a shared
 * mount** — a fail-closed safety interlock, not a convenience toggle. Until it is declared, the
 * zero-knowledge repository routes refuse to serve, and that refusal is the correct behaviour: a
 * node-local root on a cluster would give each node its own private object storage, silently, with
 * no error anywhere and no way to notice until a restore came up short.
 *
 * ## The one thing this UI must not imply
 *
 * The server validates everything a **single node** can check — absolute, exactly the expected
 * root, exists, writable. It cannot check the thing that actually matters, which is whether the
 * path is a genuinely *shared* mount rather than node-local storage: nothing visible from one node
 * distinguishes them, and every node in a misconfigured cluster would pass the check against its
 * own private directory. The copy therefore says so in as many words instead of letting a green
 * "válido" badge imply an assurance that was never made. Overstating this would be worse than
 * showing nothing, because it is exactly the check an operator would otherwise go and do by hand.
 *
 * ## Why the pane reports a restart
 *
 * The root is resolved once, at process start. Saving here writes the declaration; it does not open
 * the interlock. So the pane always shows two things side by side — what is saved, and what the
 * running process is actually using — and says plainly when they differ. An editor that appeared to
 * take effect immediately would be the exact dishonesty this surface exists to avoid.
 *
 * Input is a form on `.settings-rows`; the live interlock beside it is a readout, so it is a table.
 * (t69's line, and the one t104 held across the rest of this section.)
 */
import { useEffect, useState } from 'react';

import { useSettings, useZkStorageStatus, usePutZkSharedObjectRoot } from '../../api/hooks';
import { useT } from '../../i18n';
import { useCan } from '../session/permissions';
import {
  Badge,
  Button,
  Card,
  ErrorNote,
  Field,
  Input,
  InlineWarning,
  Skeleton,
  SkeletonRegion,
  Table,
  useToast,
} from '../../ui';

export function ZkObjectRootSection() {
  const t = useT();
  const toast = useToast();
  const can = useCan();
  const canManage = can('settings.manage');

  const settings = useSettings();
  const status = useZkStorageStatus();
  const save = usePutZkSharedObjectRoot();

  const saved = settings.data?.data_management?.zk_shared_object_root ?? '';
  const [draft, setDraft] = useState(saved);
  // Re-seed the field when the persisted value arrives or changes underneath, but never while the
  // operator is mid-save — clobbering what they typed with a stale read is its own small betrayal.
  useEffect(() => {
    if (!save.isPending) setDraft(saved);
  }, [saved, save.isPending]);

  const live = status.data;
  // The declaration is pinned by the environment: the field is not the writer, and saying so is
  // more useful than letting someone type into a box whose value will be ignored at startup.
  const pinnedByEnvironment = live?.source === 'environment';
  const dirty = draft.trim() !== (saved ?? '').trim();
  // Saved, but the running process has not picked it up. This is the normal state immediately
  // after a successful save, and it must be stated rather than left to be discovered.
  const restartOutstanding =
    !dirty &&
    !!live &&
    (saved ?? '') !== '' &&
    !live.ready &&
    live.requires_shared_root &&
    live.source !== 'environment';

  const submit = () => {
    const next = draft.trim();
    save.mutate(next === '' ? null : next, {
      onSuccess: () => toast.success(t('settings.zkRoot.saved')),
      onError: (error) => toast.error(error),
    });
  };

  return (
    <div className="stack">
      <Card title={t('settings.zkRoot.cardTitle')}>
        <div className="form settings-rows">
          <p className="field__hint">{t('settings.zkRoot.intro')}</p>

          {/* Stated before the field, not after it: an operator needs to know what this declaration
              does and does not assert BEFORE they type a path into it. */}
          <InlineWarning tone="warn" title={t('settings.zkRoot.cannotVerify.title')}>
            {t('settings.zkRoot.cannotVerify.body')}
          </InlineWarning>

          {pinnedByEnvironment ? (
            <InlineWarning tone="info" title={t('settings.zkRoot.fromEnv.title')}>
              {t('settings.zkRoot.fromEnv.body')}
            </InlineWarning>
          ) : null}

          <Field
            label={t('settings.zkRoot.field.label')}
            htmlFor="zk-shared-object-root"
            hint={t('settings.zkRoot.field.hint')}
            help={t('settings.zkRoot.field.help')}
          >
            <Input
              id="zk-shared-object-root"
              className="mono"
              value={draft}
              spellCheck={false}
              autoComplete="off"
              disabled={!canManage || pinnedByEnvironment || save.isPending}
              onChange={(e) => setDraft(e.target.value)}
            />
          </Field>

          {save.error ? <ErrorNote error={save.error} /> : null}

          <div className="row-wrap">
            <Button
              onClick={submit}
              disabled={!canManage || pinnedByEnvironment || save.isPending || !dirty}
            >
              {t('settings.zkRoot.save')}
            </Button>
          </div>

          {/* Never presented as "applied". Saving stores a declaration; the interlock is resolved
              at process start and the readout below is the authority on what is actually live. */}
          {restartOutstanding ? (
            <InlineWarning tone="warn" title={t('settings.zkRoot.restart.title')}>
              {t('settings.zkRoot.restart.body')}
            </InlineWarning>
          ) : null}
        </div>
      </Card>

      <Card title={t('settings.zkRoot.live.title')}>
        <p className="muted">{t('settings.zkRoot.live.hint')}</p>
        {status.isLoading ? (
          <SkeletonRegion label={t('settings.zkRoot.live.title')}>
            <Skeleton height="3.2rem" />
          </SkeletonRegion>
        ) : null}
        {status.error ? <ErrorNote error={status.error} /> : null}
        {live ? (
          <>
            <Table
              caption={t('settings.zkRoot.live.title')}
              head={
                <tr>
                  <th scope="col">{t('settings.zkRoot.live.col.fact')}</th>
                  <th scope="col">{t('settings.zkRoot.live.col.value')}</th>
                </tr>
              }
            >
              <tr>
                <th scope="row">{t('settings.zkRoot.live.state')}</th>
                <td>
                  <Badge tone={live.ready ? 'ok' : 'warn'}>
                    {live.ready
                      ? t('settings.zkRoot.live.state.open')
                      : t('settings.zkRoot.live.state.closed')}
                  </Badge>
                </td>
              </tr>
              <tr>
                <th scope="row">{t('settings.zkRoot.live.required')}</th>
                <td>
                  {live.requires_shared_root
                    ? t('settings.zkRoot.live.required.yes')
                    : t('settings.zkRoot.live.required.no')}
                </td>
              </tr>
              <tr>
                <th scope="row">{t('settings.zkRoot.live.root')}</th>
                <td className="mono">{live.declared_root ?? '—'}</td>
              </tr>
              <tr>
                <th scope="row">{t('settings.zkRoot.live.source')}</th>
                <td>{t(`settings.zkRoot.live.source.${live.source}` as const)}</td>
              </tr>
            </Table>
            {/* The reason the interlock is closed, verbatim from the server. Misconfiguration is
                never silent: if it is closed, this says why. */}
            {live.reason ? (
              <InlineWarning tone="warn" title={t('settings.zkRoot.live.reason.title')}>
                <span className="mono">{live.reason}</span>
              </InlineWarning>
            ) : null}
          </>
        ) : null}
      </Card>
    </div>
  );
}
