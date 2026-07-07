/**
 * Enrich an existing entity from its certidão permanente (plan t11 §2.7,
 * `POST /v1/entities/{id}/registry/import`). The import cross-checks the certidão
 * against the stored entity:
 *
 *  - blank entity fields (name/seat) are filled silently and listed as `applied`;
 *  - a value that DIVERGES from a non-blank field is reported as a conflict and the
 *    current value is KEPT — unless the operator explicitly confirms an overwrite,
 *    which re-submits the same code with `overwrite: true`.
 *
 * Secrecy: the código de acesso is held only transiently. It is captured into a ref at
 * submit (so an overwrite confirmation can re-send it without re-prompting), cleared
 * from the visible input immediately, and wiped once resolved or on unmount — it is
 * never persisted, cached, or rendered back.
 */
import { useEffect, useRef, useState } from 'react';
import { useImportEntityRegistry } from '../../api/hooks';
import { registryFieldLabel } from '../../api/labels';
import { useT } from '../../i18n';
import { Badge, Button, Card, Field, Icon, Input, InlineWarning, Table } from '../../ui';
import { CaeRefList } from '../cae/CaeRefList';
import { AccessCodeField } from './AccessCodeField';
import { RegistryErrorNote } from './RegistryErrorNote';

export function RegistryImportPanel({ entityId }: { entityId: string }) {
  const t = useT();
  const importEntity = useImportEntityRegistry(entityId);
  const [code, setCode] = useState('');
  const [email, setEmail] = useState('');
  // The secret code, kept only to allow an overwrite re-submit within this session.
  const pendingCode = useRef('');

  useEffect(() => {
    // Wipe the transient secret when the panel unmounts.
    return () => {
      pendingCode.current = '';
    };
  }, []);

  function runImport(overwrite: boolean, theCode: string) {
    importEntity.mutate(
      { code: theCode, email: email.trim() || undefined, overwrite },
      {
        onSuccess: (report) => {
          setCode('');
          // Nothing left to overwrite once there are no conflicts.
          if (report.conflicts.length === 0) pendingCode.current = '';
        },
      },
    );
  }

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    pendingCode.current = code;
    runImport(false, code);
  }

  const report = importEntity.data;
  const conflicts = report?.conflicts ?? [];
  const applied = report?.applied ?? [];
  const cae = report?.extract.cae ?? [];
  const warnings = report?.warnings ?? [];

  return (
    <Card title={t('registry.importCard')}>
      <form className="form" onSubmit={onSubmit}>
        <p className="muted">{t('registry.enrich.intro')}</p>
        <AccessCodeField id="entity-import-code" value={code} onChange={setCode} />
        <Field label={t('registry.email.label')} htmlFor="entity-import-email">
          <Input
            id="entity-import-email"
            type="email"
            value={email}
            autoComplete="off"
            onChange={(e) => setEmail(e.target.value)}
            placeholder={t('registry.email.placeholder')}
          />
        </Field>
        {importEntity.error ? <RegistryErrorNote error={importEntity.error} /> : null}
        <div className="form__actions">
          <Button
            type="submit"
            variant="primary"
            icon={<Icon.Tray />}
            disabled={importEntity.isPending || code.trim() === ''}
          >
            {importEntity.isPending ? t('registry.enrich.consulting') : t('registry.enrich.submit')}
          </Button>
        </div>
      </form>

      {report ? (
        <div className="stack--tight registry-report">
          {warnings.length > 0 ? (
            <InlineWarning tone="warn" title={t('registry.warnings.title')}>
              <ul className="registry-warnings">
                {warnings.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            </InlineWarning>
          ) : null}

          {applied.length > 0 ? (
            <div className="registry-applied">
              <p className="field__label">{t('registry.appliedFields')}</p>
              <div className="row-wrap">
                {applied.map((field) => (
                  <Badge key={field} tone="ok">
                    {registryFieldLabel(field)}
                  </Badge>
                ))}
              </div>
            </div>
          ) : null}

          {cae.length > 0 ? (
            <div className="registry-applied">
              <p className="field__label">{t('registry.caeSection')}</p>
              <CaeRefList refs={cae} />
            </div>
          ) : null}

          {conflicts.length > 0 ? (
            <InlineWarning tone="warn" title={t('registry.conflicts.title')}>
              <p>{t('registry.conflicts.body')}</p>
              <Table
                head={
                  <tr>
                    <th>{t('registry.conflicts.th.field')}</th>
                    <th>{t('registry.conflicts.th.current')}</th>
                    <th>{t('registry.conflicts.th.incoming')}</th>
                  </tr>
                }
              >
                {conflicts.map((c) => (
                  <tr key={c.field}>
                    <td>{registryFieldLabel(c.field)}</td>
                    <td>{c.current ?? <span className="muted">—</span>}</td>
                    <td>{c.incoming ?? <span className="muted">—</span>}</td>
                  </tr>
                ))}
              </Table>
              <div className="form__actions">
                <Button
                  type="button"
                  variant="primary"
                  icon={<Icon.Check />}
                  disabled={importEntity.isPending || pendingCode.current === ''}
                  onClick={() => runImport(true, pendingCode.current)}
                >
                  {importEntity.isPending
                    ? t('registry.conflicts.replacing')
                    : t('registry.conflicts.confirmReplace')}
                </Button>
              </div>
            </InlineWarning>
          ) : applied.length === 0 ? (
            <p className="muted" role="status">
              {t('registry.import.alreadyConform')}
            </p>
          ) : null}
        </div>
      ) : null}
    </Card>
  );
}
