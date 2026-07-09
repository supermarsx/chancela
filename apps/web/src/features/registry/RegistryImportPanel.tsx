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
import type { RegistryExtractView, RegistryImportReport } from '../../api/types';
import { useT } from '../../i18n';
import {
  Badge,
  Button,
  ButtonLink,
  Card,
  Field,
  Icon,
  Input,
  InlineWarning,
  Table,
  FieldHelp,
  useToast,
} from '../../ui';
import { CaeRefList } from '../cae/CaeRefList';
import { AccessCodeField } from './AccessCodeField';
import { RegistryErrorNote } from './RegistryErrorNote';
import { registryFieldHelp } from './fieldHelp';

function ValueCell({ value }: { value: string | null }) {
  return value === null ? (
    <span className="muted">—</span>
  ) : (
    <span className="registry-breakable">{value}</span>
  );
}

function HelpTerm({ label, help }: { label: string; help?: string }) {
  return help ? (
    <span className="field__labelrow">
      <span>{label}</span>
      <FieldHelp text={help} />
    </span>
  ) : (
    <>{label}</>
  );
}

function SummaryRow({
  term,
  value,
  mono,
  wide,
  help,
}: {
  term: string;
  value: string | null;
  mono?: boolean;
  wide?: boolean;
  help?: string;
}) {
  return (
    <div className={wide ? 'deflist__wide' : undefined}>
      <dt>
        <HelpTerm label={term} help={help} />
      </dt>
      <dd className={mono ? 'mono registry-breakable' : 'registry-breakable'}>
        {value ?? <span className="muted">—</span>}
      </dd>
    </div>
  );
}

function RegistryExtractSummary({ extract }: { extract: RegistryExtractView }) {
  const t = useT();
  const formaJuridica = extract.forma_juridica ?? extract.legal_form;
  return (
    <div className="registry-result-box">
      <p className="field__label">Resumo</p>
      <dl className="deflist deflist--pairs registry-result-summary">
        <SummaryRow
          term={t('registry.field.firma')}
          value={extract.firma}
          help={registryFieldHelp.firma}
          wide
        />
        <SummaryRow
          term={t('registry.field.nipc')}
          value={extract.nipc}
          help={registryFieldHelp.nipc}
          mono
        />
        <SummaryRow
          term={t('registry.field.legalForm')}
          value={formaJuridica}
          help={registryFieldHelp.legalForm}
        />
        <SummaryRow
          term={t('registry.field.matricula')}
          value={extract.matricula}
          help={registryFieldHelp.matricula}
        />
        <SummaryRow
          term={t('registry.field.sede')}
          value={extract.sede}
          help={registryFieldHelp.sede}
          wide
        />
      </dl>
    </div>
  );
}

function RegistryReportProvenance({ extract }: { extract: RegistryExtractView }) {
  const t = useT();
  const p = extract.provenance;
  return (
    <div className="registry-result-box registry-result-box--provenance">
      <p className="field__label">{t('registry.provenance.title')}</p>
      <dl className="deflist registry-provenance-mini">
        <SummaryRow
          term={t('registry.provenance.accessCode')}
          value={p.access_code_masked}
          help={registryFieldHelp.accessCodeMasked}
          mono
        />
        <SummaryRow
          term={t('registry.provenance.retrievedAt')}
          value={p.retrieved_at}
          help={registryFieldHelp.retrievedAt}
          mono
        />
        <SummaryRow
          term={t('registry.provenance.source')}
          value={p.source_url}
          help={registryFieldHelp.source}
          mono
          wide
        />
        <SummaryRow
          term={t('registry.provenance.digest')}
          value={p.raw_digest}
          help={registryFieldHelp.digest}
          mono
          wide
        />
      </dl>
    </div>
  );
}

function ImportStatus({
  pending,
  hasError,
  report,
  hasCode,
}: {
  pending: boolean;
  hasError: boolean;
  report?: RegistryImportReport;
  hasCode: boolean;
}) {
  if (pending) {
    return (
      <aside className="registry-import-state registry-import-state--active" role="status">
        <p className="field__label">Estado</p>
        <Badge tone="accent">A consultar</Badge>
        <p>
          A certidão está a ser consultada. Os valores atuais só mudam quando o resultado chegar.
        </p>
      </aside>
    );
  }

  if (hasError) {
    return (
      <aside className="registry-import-state registry-import-state--error">
        <p className="field__label">Estado</p>
        <Badge tone="error">Ação necessária</Badge>
        <p>Corrija o código ou e-mail e tente novamente.</p>
      </aside>
    );
  }

  if (report) {
    const hasConflicts = report.conflicts.length > 0;
    const changed = report.applied.length > 0;
    return (
      <aside className="registry-import-state">
        <p className="field__label">Estado</p>
        <Badge tone={hasConflicts ? 'warn' : changed ? 'ok' : 'neutral'}>
          {hasConflicts ? 'Rever divergências' : changed ? 'Atualizada' : 'Sem alterações'}
        </Badge>
        <p>
          {hasConflicts
            ? 'Os valores atuais foram mantidos até confirmar a substituição.'
            : 'Reveja a proveniência e volte à entidade quando terminar.'}
        </p>
      </aside>
    );
  }

  return (
    <aside className="registry-import-state">
      <p className="field__label">Estado</p>
      <Badge tone={hasCode ? 'ok' : 'neutral'}>{hasCode ? 'Pronto' : 'Aguardando código'}</Badge>
      <p>
        {hasCode
          ? 'Pronto para consultar a certidão e comparar com a entidade.'
          : 'Introduza o código da certidão permanente. Divergências serão apresentadas antes de substituir valores.'}
      </p>
    </aside>
  );
}

function ImportReport({
  report,
  pending,
  canOverwrite,
  onOverwrite,
}: {
  report: RegistryImportReport;
  pending: boolean;
  canOverwrite: boolean;
  onOverwrite: () => void;
}) {
  const t = useT();
  const conflicts = report.conflicts;
  const applied = report.applied;
  const cae = report.extract.cae;
  const warnings = report.warnings;
  const hasConflicts = conflicts.length > 0;
  const hasChanges = applied.length > 0;
  const outcomeTone = hasConflicts
    ? 'warn'
    : warnings.length > 0
      ? 'warn'
      : hasChanges
        ? 'ok'
        : 'neutral';

  return (
    <section className="stack--tight registry-report" aria-live="polite">
      <div className="registry-report__head">
        <div>
          <p className="registry-import-copy__eyebrow">Resultado</p>
          <h4>Resumo da importação</h4>
        </div>
        <Badge tone={outcomeTone}>
          {hasConflicts ? 'Requer confirmação' : hasChanges ? 'Importada' : 'Sem alterações'}
        </Badge>
      </div>

      {warnings.length > 0 ? (
        <InlineWarning tone="warn" title={t('registry.warnings.title')}>
          <ul className="registry-warnings">
            {warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </InlineWarning>
      ) : null}

      {hasConflicts ? (
        <InlineWarning tone="warn" title={t('registry.conflicts.title')}>
          <p>{t('registry.conflicts.body')}</p>
          <div className="registry-conflict-table">
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
                  <td>
                    <ValueCell value={c.current} />
                  </td>
                  <td>
                    <ValueCell value={c.incoming} />
                  </td>
                </tr>
              ))}
            </Table>
          </div>
          <div className="form__actions registry-next-actions">
            <Button
              type="button"
              variant="primary"
              icon={<Icon.Check />}
              disabled={pending || !canOverwrite}
              onClick={onOverwrite}
            >
              {pending ? t('registry.conflicts.replacing') : t('registry.conflicts.confirmReplace')}
            </Button>
          </div>
        </InlineWarning>
      ) : null}

      <div className="registry-result-grid">
        <RegistryExtractSummary extract={report.extract} />
        <RegistryReportProvenance extract={report.extract} />
      </div>

      {applied.length > 0 ? (
        <div className="registry-applied registry-result-box">
          <p className="field__label">{t('registry.appliedFields')}</p>
          <div className="row-wrap">
            {applied.map((field) => (
              <Badge key={field} tone="ok">
                {registryFieldLabel(field)}
              </Badge>
            ))}
          </div>
        </div>
      ) : !hasConflicts ? (
        <InlineWarning tone="info" title="Sem alterações">
          {t('registry.import.alreadyConform')}
        </InlineWarning>
      ) : null}

      {cae.length > 0 ? (
        <div className="registry-applied registry-result-box">
          <p className="field__label">{t('registry.caeSection')}</p>
          <CaeRefList refs={cae} />
        </div>
      ) : null}

      {!hasConflicts ? (
        <div className="registry-next-actions">
          <p className="field__label">Próximo passo</p>
          <ButtonLink
            to={`/entidades/${report.entity.id}`}
            variant="primary"
            icon={<Icon.ArrowRight />}
          >
            {t('entities.backToEntity')}
          </ButtonLink>
        </div>
      ) : null}
    </section>
  );
}

export function RegistryImportPanel({ entityId }: { entityId: string }) {
  const t = useT();
  const toast = useToast();
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
          // Toast only when a field actually changed — a report that is all conflicts (or
          // already conform) leaves the entity untouched, so the inline table/notice below
          // carries that outcome instead (R7).
          if (report.applied.length > 0) toast.success(t('toast.registry.enriched'));
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (code.trim() === '' || importEntity.isPending) return;
    pendingCode.current = code;
    runImport(false, code);
  }

  const report = importEntity.data;
  const hasCode = code.trim() !== '';

  return (
    <Card title={t('registry.importCard')}>
      <div className="registry-import-flow">
        <div className="registry-import-flow__main">
          <div className="registry-import-copy">
            <p className="registry-import-copy__eyebrow">Consulta</p>
            <p className="muted">{t('registry.enrich.intro')}</p>
          </div>
          <form className="form registry-import-form" onSubmit={onSubmit}>
            <AccessCodeField id="entity-import-code" value={code} onChange={setCode} />
            <Field
              label={t('registry.email.label')}
              htmlFor="entity-import-email"
              help={registryFieldHelp.email}
            >
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
                disabled={importEntity.isPending || !hasCode}
              >
                {importEntity.isPending
                  ? t('registry.enrich.consulting')
                  : t('registry.enrich.submit')}
              </Button>
            </div>
          </form>
        </div>
        <ImportStatus
          pending={importEntity.isPending}
          hasError={Boolean(importEntity.error)}
          report={report}
          hasCode={hasCode}
        />
      </div>

      {report ? (
        <ImportReport
          report={report}
          pending={importEntity.isPending}
          canOverwrite={pendingCode.current !== ''}
          onOverwrite={() => runImport(true, pendingCode.current)}
        />
      ) : !importEntity.error ? (
        <div className="registry-report registry-report--empty" aria-live="polite">
          <p className="field__label">Resultado</p>
          <p className="muted">A consulta ainda não foi executada.</p>
        </div>
      ) : null}
    </Card>
  );
}
