/**
 * A single entity, full width, split into sub-tabs: Livros · Identificação ·
 * Exercício fiscal · Registo comercial · Inscrições e averbamentos · Cronologia e grafo.
 *
 * Seventh surface on the shared `<SubNav>` (`apps/web/src/ui/SubNav.tsx`) + the `?sec=`
 * deep-link convention established by Configurações and reused by Ferramentas, Privacidade,
 * o livro (t25), o arquivo (t32) and o validador PDF (t35). Same `route-transition` fade
 * keyed on the active id, same "the default section carries no `sec` param" rule
 * (`/entidades/:id` still lands on Livros), same deliberate `role="group"` + `aria-pressed`
 * semantics rather than an ARIA tablist — that divergence belongs in `SubNav` for all seven
 * surfaces at once, not here.
 *
 * Unlike the book sub-nav, selecting a tab **pushes** a history entry: browser Back returns
 * to the previous tab instead of leaving the entity, which is the trap t34 had to undo in
 * the legislação reader.
 *
 * The certidão import stays a neat button on the Registo comercial tab (`/entidades/:id/importar`);
 * opening a book is likewise a button on Livros that carries the entity through.
 */
import { useEffect, useState, type ReactNode } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { useBooks, useEntity, useUpdateEntity } from '../../api/hooks';
import { entityFamilyLabels, entityKindLabels } from '../../api/labels';
import type { Entity } from '../../api/types';
import { useT, type MessageKey, type TFunction } from '../../i18n';
import {
  Card,
  ErrorNote,
  Field,
  FieldHelp,
  Icon,
  Input,
  PageHeader,
  Skeleton,
  SkeletonDeflist,
  SkeletonTable,
  SubNav,
  useToast,
} from '../../ui';
import {
  GateButton,
  GateButtonLink,
  PermissionDeniedNote,
  scopeEntity,
  useCan,
} from '../session/permissions';
import { BooksTable } from '../books/BooksTable';
import { RegistryProvenance } from '../registry/RegistryProvenance';
import { EntityChronologyPanel } from './EntityChronologyPanel';
import { EntityStatuteEditor } from './EntityStatuteEditor';
import { NipcBadge } from './NipcBadge';
import { PrintButton } from './PrintButton';
import { EntityPrintDocument } from './EntityPrintDocument';
import { entityFieldHelp } from './fieldHelp';

/**
 * The entity sub-tabs, in the order the operator asked for. Labels reuse the section titles
 * they head, exactly as the Configurações and Livros sub-navs do; only "Inscrições e
 * averbamentos" gets a shorter label than its card, whose title is the full
 * "Inscrições, averbamentos e anotações".
 */
type EntitySection =
  | 'livros'
  | 'identificacao'
  | 'fiscal'
  | 'registo'
  | 'inscricoes'
  | 'cronologia';

const ENTITY_SECTIONS: { id: EntitySection; label: MessageKey; icon: ReactNode }[] = [
  { id: 'livros', label: 'entities.booksCard', icon: <Icon.BookClosed /> },
  { id: 'identificacao', label: 'entities.identificationCard', icon: <Icon.IdCard /> },
  { id: 'fiscal', label: 'entities.fiscalYearEnd.cardTitle', icon: <Icon.Calendar /> },
  { id: 'registo', label: 'entities.registrySection', icon: <Icon.Seal /> },
  { id: 'inscricoes', label: 'entities.subnav.inscricoes', icon: <Icon.Layers /> },
  { id: 'cronologia', label: 'entities.chronology.title', icon: <Icon.Shuffle /> },
];

const isEntitySection = (value: string | null): value is EntitySection =>
  ENTITY_SECTIONS.some((section) => section.id === value);

function displayFiscalYearEnd(value: string | null | undefined, t: TFunction) {
  return value ? value : t('entities.fiscalYearEnd.default');
}

function HelpTerm({ label, help }: { label: string; help: string }) {
  return (
    <span className="field__labelrow">
      <span>{label}</span>
      <FieldHelp text={help} />
    </span>
  );
}

function normalizeFiscalYearEndInput(input: string): string | null {
  const value = input.trim();
  if (value === '') return null;
  const match = /^(\d{2})-(\d{2})$/.exec(value);
  if (!match) throw new Error('invalid fiscal-year end');
  const month = Number(match[1]);
  const day = Number(match[2]);
  const daysInMonth = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth[month - 1]) {
    throw new Error('invalid fiscal-year end');
  }
  return `${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
}

function FiscalYearEndEditor({ entity }: { entity: Entity }) {
  const t = useT();
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
    } catch {
      setError(t('entities.fiscalYearEnd.invalid'));
      return;
    }
    update.mutate(
      { fiscal_year_end: fiscalYearEnd },
      {
        onSuccess: (saved) => {
          setDraft(saved.fiscal_year_end ?? '');
          toast.success(t('entities.fiscalYearEnd.updated'));
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  return (
    <Card title={t('entities.fiscalYearEnd.cardTitle')}>
      {update.error ? <ErrorNote error={update.error} /> : null}
      <dl className="deflist">
        <div>
          <dt>
            <HelpTerm
              label={t('entities.fiscalYearEnd.fieldLabel')}
              help={entityFieldHelp.fiscalYearEnd}
            />
          </dt>
          <dd>
            <code className="mono">{displayFiscalYearEnd(entity.fiscal_year_end, t)}</code>
          </dd>
        </div>
      </dl>
      <form className="form" onSubmit={submit}>
        <Field
          label={t('entities.fiscalYearEnd.inputLabel')}
          htmlFor="entity-fiscal-year-end"
          hint={t('entities.fiscalYearEnd.hint')}
          help={entityFieldHelp.fiscalYearEnd}
          error={error}
        >
          <Input
            id="entity-fiscal-year-end"
            value={draft}
            onChange={(e) => {
              setDraft(e.target.value);
              if (error) setError(null);
            }}
            placeholder={t('entities.fiscalYearEnd.placeholder')}
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
            {update.isPending
              ? t('entities.fiscalYearEnd.saving')
              : t('entities.fiscalYearEnd.save')}
          </GateButton>
        </div>
      </form>
    </Card>
  );
}

export function EntityDetailPage() {
  const t = useT();
  const can = useCan();
  const { id = '' } = useParams();
  const [params, setParams] = useSearchParams();
  // Livros is the default and carries no `sec` param, so `/entidades/:id` still lands on it.
  const secParam = params.get('sec');
  const section: EntitySection = isEntitySection(secParam) ? secParam : 'livros';
  // A PUSH, not a replace: the tab is a place the operator navigated to, so browser Back
  // must return to the previous tab rather than leaving the entity altogether (t34).
  const selectSection = (next: EntitySection) =>
    setParams((prev) => {
      const p = new URLSearchParams(prev);
      if (next === 'livros') p.delete('sec');
      else p.set('sec', next);
      return p;
    });

  // `GET /v1/books` is gated `book.read@Global`, which a principal holding only
  // `entity.read` on this entity may not have. Don't fire a request we know would 403 —
  // the Livros tab renders a permission note instead (the book-detail retention pattern).
  const canReadBooks = can('book.read');
  const entity = useEntity(id);
  const books = useBooks(id, canReadBooks);

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
      >
        <SubNav
          items={ENTITY_SECTIONS.map((s) => ({ id: s.id, label: t(s.label), icon: s.icon }))}
          active={section}
          onSelect={selectSection}
          ariaLabel={t('entities.subnav.aria')}
        />
      </PageHeader>

      {/* One section at a time; the panel replays the route-enter fade on each switch. */}
      <div className="route-transition stack" key={section}>
        {section === 'livros' ? (
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
            {!canReadBooks ? (
              <PermissionDeniedNote />
            ) : books.isLoading ? (
              <SkeletonTable cols={5} />
            ) : books.error ? (
              <ErrorNote error={books.error} />
            ) : (
              <BooksTable books={books.data ?? []} />
            )}
          </Card>
        ) : null}

        {section === 'identificacao' ? (
          <>
            <Card title={t('entities.identificationCard')}>
              <dl className="deflist">
                <div>
                  <dt>
                    <HelpTerm label={t('entities.field.nipc')} help={entityFieldHelp.nipc} />
                  </dt>
                  <dd>
                    <span className="nipc-cell">
                      <code className="mono">{ent.nipc}</code>
                      {!ent.nipc_validated ? <NipcBadge /> : null}
                    </span>
                  </dd>
                </div>
                <div>
                  <dt>
                    <HelpTerm label={t('entities.field.seat')} help={entityFieldHelp.seat} />
                  </dt>
                  <dd>{ent.seat}</dd>
                </div>
                <div>
                  <dt>
                    <HelpTerm
                      label={t('entities.field.legalForm')}
                      help={entityFieldHelp.legalForm}
                    />
                  </dt>
                  <dd>{entityKindLabels[ent.kind]}</dd>
                </div>
                <div>
                  <dt>{t('entities.field.family')}</dt>
                  <dd>{entityFamilyLabels[ent.family]}</dd>
                </div>
                <div>
                  <dt>
                    <HelpTerm
                      label={t('entities.fiscalYearEnd.fieldLabel')}
                      help={entityFieldHelp.fiscalYearEnd}
                    />
                  </dt>
                  <dd>
                    <code className="mono">{displayFiscalYearEnd(ent.fiscal_year_end, t)}</code>
                  </dd>
                </div>
              </dl>
            </Card>
            {/* Estatutos has no tab of its own in the requested set. It lives here because it
                is the rest of "what this entity is": the derived compliance profile (rule pack,
                family, allowed channels, signature policy) plus the statute overlay that
                tightens the legal minimums. */}
            <EntityStatuteEditor entity={ent} />
          </>
        ) : null}

        {section === 'fiscal' ? <FiscalYearEndEditor entity={ent} /> : null}

        {section === 'registo' ? (
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
            <RegistryProvenance entityId={ent.id} part="commercial" />
          </section>
        ) : null}

        {section === 'inscricoes' ? (
          <RegistryProvenance entityId={ent.id} part="inscriptions" />
        ) : null}

        {section === 'cronologia' ? <EntityChronologyPanel entityId={ent.id} /> : null}
      </div>

      {/* Print-only filing abstract (portaled to <body>, hidden on screen). Kept outside the
          tab panel so "Imprimir" yields the whole filing abstract from any tab. */}
      <EntityPrintDocument entityId={ent.id} />
    </div>
  );
}
