/**
 * A single entity, full width. Its "Registo comercial" provenance now spans the whole
 * column (t13 item 3), with the certidão import moved behind a neat button that opens
 * `/entidades/:id/importar`. Opening a book against this entity is likewise a neat
 * button that carries the entity through to the open-book page.
 */
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useBooks, useEntity, useUpdateEntity } from '../../api/hooks';
import { entityFamilyLabels, entityKindLabels } from '../../api/labels';
import type { Entity } from '../../api/types';
import { useT } from '../../i18n';
import {
  Card,
  ErrorNote,
  Field,
  Icon,
  Input,
  PageHeader,
  Skeleton,
  SkeletonDeflist,
  SkeletonTable,
  useToast,
} from '../../ui';
import { GateButton, GateButtonLink, scopeEntity } from '../session/permissions';
import { BooksTable } from '../books/BooksTable';
import { RegistryProvenance } from '../registry/RegistryProvenance';
import { EntityStatuteEditor } from './EntityStatuteEditor';
import { NipcBadge } from './NipcBadge';
import { PrintButton } from './PrintButton';
import { EntityPrintDocument } from './EntityPrintDocument';

const FISCAL_YEAR_END_FIELD_LABEL = 'Fecho do exercício';
const FISCAL_YEAR_END_INPUT_LABEL = 'Fecho do exercício (MM-DD)';
const FISCAL_YEAR_END_HINT = 'Opcional. Vazio mantém o fecho por omissão em 12-31.';
const FISCAL_YEAR_END_ERROR = 'Use uma data válida no formato MM-DD.';

function displayFiscalYearEnd(value: string | null | undefined) {
  return value ? value : '12-31 (por omissão)';
}

function normalizeFiscalYearEndInput(input: string): string | null {
  const value = input.trim();
  if (value === '') return null;
  const match = /^(\d{2})-(\d{2})$/.exec(value);
  if (!match) throw new Error(FISCAL_YEAR_END_ERROR);
  const month = Number(match[1]);
  const day = Number(match[2]);
  const daysInMonth = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth[month - 1]) {
    throw new Error(FISCAL_YEAR_END_ERROR);
  }
  return `${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
}

function FiscalYearEndEditor({ entity }: { entity: Entity }) {
  const toast = useToast();
  const update = useUpdateEntity(entity.id);
  const [draft, setDraft] = useState(entity.fiscal_year_end ?? '');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setDraft(entity.fiscal_year_end ?? '');
    setError(null);
  }, [entity.id, entity.fiscal_year_end]);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    let fiscalYearEnd: string | null;
    try {
      fiscalYearEnd = normalizeFiscalYearEndInput(draft);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : FISCAL_YEAR_END_ERROR);
      return;
    }
    update.mutate(
      { fiscal_year_end: fiscalYearEnd },
      {
        onSuccess: (saved) => {
          setDraft(saved.fiscal_year_end ?? '');
          toast.success('Exercício fiscal atualizado.');
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  return (
    <Card title="Exercício fiscal">
      {update.error ? <ErrorNote error={update.error} /> : null}
      <dl className="deflist">
        <div>
          <dt>{FISCAL_YEAR_END_FIELD_LABEL}</dt>
          <dd>
            <code className="mono">{displayFiscalYearEnd(entity.fiscal_year_end)}</code>
          </dd>
        </div>
      </dl>
      <form className="form" onSubmit={submit}>
        <Field
          label={FISCAL_YEAR_END_INPUT_LABEL}
          htmlFor="entity-fiscal-year-end"
          hint={FISCAL_YEAR_END_HINT}
          error={error}
        >
          <Input
            id="entity-fiscal-year-end"
            value={draft}
            onChange={(e) => {
              setDraft(e.target.value);
              if (error) setError(null);
            }}
            placeholder="12-31"
            maxLength={5}
          />
        </Field>
        <div className="form__actions">
          <GateButton
            perm="entity.update"
            scope={scopeEntity(entity.id)}
            type="submit"
            variant="primary"
            icon={<Icon.Save />}
            disabled={update.isPending}
          >
            {update.isPending ? 'A guardar' : 'Guardar fecho'}
          </GateButton>
        </div>
      </form>
    </Card>
  );
}

export function EntityDetailPage() {
  const t = useT();
  const { id = '' } = useParams();
  const entity = useEntity(id);
  const books = useBooks(id);

  if (entity.isLoading) {
    return (
      <div className="stack">
        <PageHeader
          crumbs={<Link to="/entidades">{t('entities.crumb')}</Link>}
          title={<Skeleton width="16rem" height="1.6rem" />}
        />
        <Card title={t('entities.identificationCard')}>
          <SkeletonDeflist />
        </Card>
      </div>
    );
  }
  if (entity.error) return <ErrorNote error={entity.error} />;
  if (!entity.data) return null;

  const ent = entity.data;

  return (
    <div className="stack">
      <PageHeader
        crumbs={
          <>
            <Link to="/entidades">{t('entities.crumb')}</Link> · {ent.name}
          </>
        }
        title={ent.name}
        actions={<PrintButton />}
      />

      <Card title={t('entities.identificationCard')}>
        <dl className="deflist">
          <div>
            <dt>{t('entities.field.nipc')}</dt>
            <dd>
              <span className="nipc-cell">
                <code className="mono">{ent.nipc}</code>
                {!ent.nipc_validated ? <NipcBadge /> : null}
              </span>
            </dd>
          </div>
          <div>
            <dt>{t('entities.field.seat')}</dt>
            <dd>{ent.seat}</dd>
          </div>
          <div>
            <dt>{t('entities.field.legalForm')}</dt>
            <dd>{entityKindLabels[ent.kind]}</dd>
          </div>
          <div>
            <dt>{t('entities.field.family')}</dt>
            <dd>{entityFamilyLabels[ent.family]}</dd>
          </div>
          <div>
            <dt>{FISCAL_YEAR_END_FIELD_LABEL}</dt>
            <dd>
              <code className="mono">{displayFiscalYearEnd(ent.fiscal_year_end)}</code>
            </dd>
          </div>
        </dl>
      </Card>

      <FiscalYearEndEditor entity={ent} />
      <EntityStatuteEditor entity={ent} />

      <section className="stack">
        <div className="section-head">
          <h3 className="section-subtitle">{t('entities.registrySection')}</h3>
          <GateButtonLink
            perm="entity.registry.import"
            scope={scopeEntity(ent.id)}
            to={`/entidades/${ent.id}/importar`}
            icon={<Icon.Tray />}
          >
            {t('entities.importButton')}
          </GateButtonLink>
        </div>
        <RegistryProvenance entityId={ent.id} />
      </section>

      <Card
        title={t('entities.booksCard')}
        actions={
          <GateButtonLink
            perm="book.open"
            scope={scopeEntity(ent.id)}
            to={`/livros/novo?entidade=${ent.id}`}
            variant="primary"
            icon={<Icon.BookPlus />}
          >
            {t('entities.openBookButton')}
          </GateButtonLink>
        }
      >
        {books.isLoading ? (
          <SkeletonTable cols={5} />
        ) : books.error ? (
          <ErrorNote error={books.error} />
        ) : (
          <BooksTable books={books.data ?? []} />
        )}
      </Card>

      {/* Print-only filing abstract (portaled to <body>, hidden on screen). */}
      <EntityPrintDocument entityId={ent.id} />
    </div>
  );
}
