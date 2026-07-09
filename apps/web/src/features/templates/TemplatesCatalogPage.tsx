import { useMemo, useState } from 'react';
import { useTemplates } from '../../api/hooks';
import {
  entityFamilyLabels,
  lifecycleStageLabels,
  meetingChannelLabels,
  signaturePolicyLabels,
} from '../../api/labels';
import {
  LIFECYCLE_STAGES,
  MEETING_CHANNELS,
  type EntityFamily,
  type LifecycleStage,
  type MeetingChannel,
  type SignaturePolicyHint,
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
  const channelParts = template.channels.flatMap((channel) => [
    channel,
    meetingChannelLabels[channel],
  ]);
  return [
    template.id,
    template.locale,
    template.family,
    template.stage,
    template.rule_pack_id,
    template.signature_policy,
    entityFamilyLabels[template.family],
    lifecycleStageLabels[template.stage],
    signaturePolicyLabels[template.signature_policy],
    ...channelParts,
  ].some((part) => searchText(part).includes(query));
}

function sortTemplates(a: TemplateSummary, b: TemplateSummary): number {
  return (
    a.family.localeCompare(b.family) ||
    a.stage.localeCompare(b.stage) ||
    a.rule_pack_id.localeCompare(b.rule_pack_id) ||
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
  const [channel, setChannel] = useState<MeetingChannel | ''>('');
  const [signaturePolicy, setSignaturePolicy] = useState<SignaturePolicyHint | ''>('');
  const [rulePack, setRulePack] = useState('');

  const allTemplates = useMemo(
    () => [...(templates.data ?? [])].sort(sortTemplates),
    [templates.data],
  );
  const locales = useMemo(
    () => Array.from(new Set(allTemplates.map((template) => template.locale))).sort(),
    [allTemplates],
  );
  const channels = useMemo(
    () =>
      MEETING_CHANNELS.filter((value) =>
        allTemplates.some((template) => template.channels.includes(value)),
      ),
    [allTemplates],
  );
  const signaturePolicies = useMemo(
    () => Array.from(new Set(allTemplates.map((template) => template.signature_policy))).sort(),
    [allTemplates],
  );
  const rulePacks = useMemo(
    () => Array.from(new Set(allTemplates.map((template) => template.rule_pack_id))).sort(),
    [allTemplates],
  );
  const normalizedQuery = searchText(query.trim());
  const filtered = allTemplates.filter(
    (template) =>
      (!family || template.family === family) &&
      (!stage || template.stage === stage) &&
      (!locale || template.locale === locale) &&
      (!channel || template.channels.includes(channel)) &&
      (!signaturePolicy || template.signature_policy === signaturePolicy) &&
      (!rulePack || template.rule_pack_id === rulePack) &&
      templateMatches(template, normalizedQuery),
  );
  const hasFilters =
    query.trim() !== '' ||
    family !== '' ||
    stage !== '' ||
    locale !== '' ||
    channel !== '' ||
    signaturePolicy !== '' ||
    rulePack !== '';

  function clearFilters() {
    setQuery('');
    setFamily('');
    setStage('');
    setLocale('');
    setChannel('');
    setSignaturePolicy('');
    setRulePack('');
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
            <Field label={t('templates.channel.label')} htmlFor="templates-channel">
              <Select
                id="templates-channel"
                value={channel}
                options={[
                  { value: '', label: t('templates.channel.all') },
                  ...channels.map((value) => ({
                    value,
                    label: meetingChannelLabels[value],
                  })),
                ]}
                onChange={(event) => setChannel(event.target.value as MeetingChannel | '')}
              />
            </Field>
            <Field label={t('templates.signature.label')} htmlFor="templates-signature">
              <Select
                id="templates-signature"
                value={signaturePolicy}
                options={[
                  { value: '', label: t('templates.signature.all') },
                  ...signaturePolicies.map((value) => ({
                    value,
                    label: signaturePolicyLabels[value],
                  })),
                ]}
                onChange={(event) =>
                  setSignaturePolicy(event.target.value as SignaturePolicyHint | '')
                }
              />
            </Field>
            <Field label={t('templates.rulePack.label')} htmlFor="templates-rule-pack">
              <Select
                id="templates-rule-pack"
                value={rulePack}
                options={[
                  { value: '', label: t('templates.rulePack.all') },
                  ...rulePacks.map((value) => ({ value, label: value })),
                ]}
                onChange={(event) => setRulePack(event.target.value)}
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
                  <div>
                    <dt>{t('templates.card.signature')}</dt>
                    <dd>{signaturePolicyLabels[template.signature_policy]}</dd>
                  </div>
                  <div>
                    <dt>{t('templates.card.rulePack')}</dt>
                    <dd>
                      <code className="template-card__code">{template.rule_pack_id}</code>
                    </dd>
                  </div>
                  <div>
                    <dt>{t('templates.card.channels')}</dt>
                    <dd>
                      {template.channels.length > 0 ? (
                        <span className="template-card__channels">
                          {template.channels.map((value) => (
                            <Badge key={value}>{meetingChannelLabels[value]}</Badge>
                          ))}
                        </span>
                      ) : (
                        <span className="muted">{t('templates.channels.none')}</span>
                      )}
                    </dd>
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
