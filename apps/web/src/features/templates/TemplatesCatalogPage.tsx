import { useMemo, useState } from 'react';
import { useTemplates } from '../../api/hooks';
import { entityFamilyLabels, lifecycleStageLabels } from '../../api/labels';
import {
  LIFECYCLE_STAGES,
  type EntityFamily,
  type LifecycleStage,
  type TemplateSummary,
} from '../../api/types';
import { useT } from '../../i18n';
import {
  Badge,
  Button,
  ButtonLink,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  PageHeader,
  Select,
  SkeletonCards,
} from '../../ui';

const ENTITY_FAMILIES: readonly EntityFamily[] = [
  'CommercialCompany',
  'Condominium',
  'Association',
  'Foundation',
  'Cooperative',
];

function searchText(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase();
}

function templateMatches(template: TemplateSummary, query: string): boolean {
  if (!query) return true;
  return [
    template.id,
    template.locale,
    template.family,
    template.stage,
    entityFamilyLabels[template.family],
    lifecycleStageLabels[template.stage],
  ].some((part) => searchText(part).includes(query));
}

function sortTemplates(a: TemplateSummary, b: TemplateSummary): number {
  return (
    a.family.localeCompare(b.family) ||
    a.stage.localeCompare(b.stage) ||
    a.locale.localeCompare(b.locale) ||
    a.id.localeCompare(b.id)
  );
}

export function TemplatesCatalogPage() {
  const t = useT();
  const templates = useTemplates();
  const [query, setQuery] = useState('');
  const [family, setFamily] = useState<EntityFamily | ''>('');
  const [stage, setStage] = useState<LifecycleStage | ''>('');
  const [locale, setLocale] = useState('');

  const allTemplates = useMemo(
    () => [...(templates.data ?? [])].sort(sortTemplates),
    [templates.data],
  );
  const locales = useMemo(
    () => Array.from(new Set(allTemplates.map((template) => template.locale))).sort(),
    [allTemplates],
  );
  const normalizedQuery = searchText(query.trim());
  const filtered = allTemplates.filter(
    (template) =>
      (!family || template.family === family) &&
      (!stage || template.stage === stage) &&
      (!locale || template.locale === locale) &&
      templateMatches(template, normalizedQuery),
  );
  const hasFilters = query.trim() !== '' || family !== '' || stage !== '' || locale !== '';

  function clearFilters() {
    setQuery('');
    setFamily('');
    setStage('');
    setLocale('');
  }

  return (
    <div className="stack">
      <PageHeader
        title={t('templates.title')}
        lede={t('templates.lede')}
        actions={
          <ButtonLink to="/livros" variant="primary" icon={<Icon.ArrowRight />}>
            {t('templates.openAct')}
          </ButtonLink>
        }
      />

      <InlineWarning tone="info" title={t('templates.noteTitle')}>
        {t('templates.noteBody')}
      </InlineWarning>

      <Card title={t('templates.filters.title')}>
        <fieldset className="templates-controls">
          <legend className="sr-only">{t('templates.filters.title')}</legend>
          <div className="templates-controls__search">
            <Field label={t('templates.search.label')} htmlFor="templates-search">
              <div className="templates-search-control">
                <span className="templates-search-control__icon" aria-hidden="true">
                  <Icon.Search />
                </span>
                <Input
                  id="templates-search"
                  value={query}
                  type="search"
                  placeholder={t('templates.search.placeholder')}
                  onChange={(event) => setQuery(event.target.value)}
                />
              </div>
            </Field>
          </div>
          <div className="templates-controls__filters">
            <Field label={t('templates.family.label')} htmlFor="templates-family">
              <Select
                id="templates-family"
                value={family}
                options={[
                  { value: '', label: t('templates.family.all') },
                  ...ENTITY_FAMILIES.map((value) => ({
                    value,
                    label: entityFamilyLabels[value],
                  })),
                ]}
                onChange={(event) => setFamily(event.target.value as EntityFamily | '')}
              />
            </Field>
            <Field label={t('templates.stage.label')} htmlFor="templates-stage">
              <Select
                id="templates-stage"
                value={stage}
                options={[
                  { value: '', label: t('templates.stage.all') },
                  ...LIFECYCLE_STAGES.map((value) => ({
                    value,
                    label: lifecycleStageLabels[value],
                  })),
                ]}
                onChange={(event) => setStage(event.target.value as LifecycleStage | '')}
              />
            </Field>
            <Field label={t('templates.locale.label')} htmlFor="templates-locale">
              <Select
                id="templates-locale"
                value={locale}
                options={[
                  { value: '', label: t('templates.locale.all') },
                  ...locales.map((value) => ({ value, label: value })),
                ]}
                onChange={(event) => setLocale(event.target.value)}
              />
            </Field>
          </div>
          <div className="templates-controls__actions">
            <Button
              type="button"
              variant="ghost"
              icon={<Icon.Close />}
              disabled={!hasFilters}
              onClick={clearFilters}
            >
              {t('templates.clearFilters')}
            </Button>
          </div>
        </fieldset>
      </Card>

      <section className="stack--tight" aria-labelledby="templates-catalog-title">
        <div className="templates-results-head">
          <h3 id="templates-catalog-title" className="panel__title">
            {t('templates.catalog.title')}
          </h3>
          <span className="muted">
            {t('templates.count', {
              shown: filtered.length,
              total: allTemplates.length,
            })}
          </span>
        </div>

        {templates.isLoading ? (
          <SkeletonCards count={4} />
        ) : templates.error ? (
          <ErrorNote error={templates.error} />
        ) : filtered.length === 0 ? (
          <EmptyState title={t('templates.empty.title')}>
            <p>{t('templates.empty.body')}</p>
          </EmptyState>
        ) : (
          <div className="templates-grid">
            {filtered.map((template) => (
              <article className="template-card" key={template.id}>
                <div className="template-card__head">
                  <p className="card__label">{t('templates.card.id')}</p>
                  <Badge tone="accent">{template.locale}</Badge>
                </div>
                <code className="template-card__id">{template.id}</code>
                <dl className="template-card__meta">
                  <div>
                    <dt>{t('templates.card.family')}</dt>
                    <dd>{entityFamilyLabels[template.family]}</dd>
                  </div>
                  <div>
                    <dt>{t('templates.card.stage')}</dt>
                    <dd>{lifecycleStageLabels[template.stage]}</dd>
                  </div>
                </dl>
                <div className="template-card__actions">
                  <ButtonLink to="/livros" icon={<Icon.ArrowRight />}>
                    {t('templates.openAct')}
                  </ButtonLink>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
