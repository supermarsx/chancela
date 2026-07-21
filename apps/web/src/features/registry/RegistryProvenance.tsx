/**
 * Read-only rendering of an entity's imported certidão permanente (plan t11 §2.7,
 * `GET /v1/entities/{id}/registry`). Three parts:
 *
 *  1. Provenance (LEG-22): the MASKED access code, retrieval timestamp, source URL and
 *     the raw-HTML digest — the audit trail for where the data came from.
 *  2. The imported identification (firma, NIPC, forma jurídica, sede, CAE, capital,
 *     objeto, data de constituição) and the órgãos sociais with appointment/cessation.
 *  3. The ordered `inscrições` list, numbered as printed — the raw event feed that
 *     seeds the future chronology view (DOC-30).
 *
 * The provenance only ever carries the masked code; the full código de acesso is never
 * present in this response and so never reaches the DOM.
 *
 * `part` selects which of those groups to render (see {@link RegistryPart}); it defaults to
 * the whole document, so call-sites that want one column are unchanged.
 */
import { useParams } from 'react-router-dom';
import { useEntityRegistry } from '../../api/hooks';
import { legalFormLabel } from '../../api/labels';
import { ApiError } from '../../api/client';
import { formatDate } from '../../format';
import { useT } from '../../i18n';
import {
  Badge,
  Card,
  DateOnly,
  DateTime,
  Digest,
  EmptyState,
  ErrorNote,
  FieldHelp,
  SkeletonDeflist,
  SkeletonRegion,
  Truncate,
} from '../../ui';
import { CaeRefList } from '../cae/CaeRefList';
import { AnotacoesList, InscriptionDetailBody } from './InscriptionDetail';
import { registryFieldHelp } from './fieldHelp';
import type {
  RegistryEventView,
  RegistryExtractView,
  RegistryOfficerView,
  RegistryProvenanceView,
} from '../../api/types';

/**
 * A `<dl>` row, omitted entirely when the value is absent. In a two-column grid
 * (`deflist--pairs`) a `wide` row spans both columns — used for long free-text
 * fields (objeto, sede) that would otherwise wrap awkwardly in a half-width cell.
 */
function Row({
  term,
  wide,
  help,
  children,
}: {
  term: string;
  wide?: boolean;
  help?: string;
  children: React.ReactNode;
}) {
  if (children === null || children === undefined || children === '') return null;
  return (
    <div className={wide ? 'deflist__wide' : undefined}>
      <dt>
        {help ? (
          <span className="field__labelrow">
            <span>{term}</span>
            <FieldHelp text={help} />
          </span>
        ) : (
          term
        )}
      </dt>
      <dd>{children}</dd>
    </div>
  );
}

function Officer({ officer }: { officer: RegistryOfficerView }) {
  const t = useT();
  const ceased = officer.cessation_date !== null;
  return (
    <li className="registry-officer">
      <div className="registry-officer__head">
        <span className="registry-officer__name">{officer.name}</span>
        {officer.role ? <span className="registry-officer__role">{officer.role}</span> : null}
        {ceased ? (
          <Badge tone="neutral">{t('registry.officer.ceased')}</Badge>
        ) : (
          <Badge tone="ok">{t('registry.officer.active')}</Badge>
        )}
      </div>
      <p className="registry-officer__dates muted">
        {/* Appointment/cessation are calendar days the server already normalized to ISO; they go
            through the shared formatter as the `date` interpolation rather than raw. */}
        {officer.appointment_date
          ? t('registry.officer.appointment', { date: formatDate(officer.appointment_date) })
          : t('registry.officer.appointmentNone')}
        {officer.cessation_date
          ? ` · ${t('registry.officer.cessation', { date: formatDate(officer.cessation_date) })}`
          : null}
        {officer.source_event
          ? ` · ${t('registry.officer.inscricao', { event: officer.source_event })}`
          : null}
      </p>
    </li>
  );
}

/**
 * A single inscrição / averbamento / anotação. The número (mono marker), kind hint
 * (accent badge) and date (aligned to the end of the header) always head the entry; the
 * body is either the structured `detail` (apresentação, a per-kind payload card, and the
 * raw text one "texto integral" toggle away — see {@link InscriptionDetailBody}) or, when
 * the parser produced no structure, the raw apresentação line + text as before (t13). The
 * printed certidão order is preserved either way.
 */
function Inscricao({ event, index }: { event: RegistryEventView; index: number }) {
  const t = useT();
  return (
    <li className="registry-inscricao">
      <div className="registry-inscricao__head">
        <span className="registry-inscricao__num">{event.number ?? `#${index + 1}`}</span>
        {event.kind_hint ? <Badge tone="accent">{event.kind_hint}</Badge> : null}
        {event.date ? (
          <DateOnly value={event.date} className="registry-inscricao__date mono" />
        ) : null}
      </div>
      {event.detail ? (
        <InscriptionDetailBody detail={event.detail} rawText={event.text} />
      ) : (
        <>
          {event.apresentacao ? (
            <p className="registry-inscricao__meta">
              <span className="registry-inscricao__meta-label">
                {t('registry.inscricao.apresentacao')}
              </span>
              <span className="mono">{event.apresentacao}</span>
            </p>
          ) : null}
          <p className="registry-inscricao__text">{event.text}</p>
        </>
      )}
    </li>
  );
}

/**
 * The certidão's validity, driven by the server-computed `expired` flag: a prominent
 * danger badge past `valid_until`, an "em vigor" badge while it holds, and nothing when
 * the certidão carried no validity window. Shown in the Proveniência card header.
 */
function ValidityBadge({ provenance }: { provenance: RegistryProvenanceView }) {
  const t = useT();
  if (provenance.expired === true) {
    return (
      <span className="registry-validity registry-validity--expired">
        <Badge tone="error">{t('registry.provenance.expired')}</Badge>
      </span>
    );
  }
  if (provenance.valid_until) {
    return (
      <span className="registry-validity">
        <Badge tone="ok">{t('registry.provenance.valid')}</Badge>
      </span>
    );
  }
  return null;
}

/**
 * Which slice of the extract to render. The entity detail page splits the certidão across
 * two sub-tabs — `commercial` (where the data came from and what it said) and
 * `inscriptions` (the event feed) — while every other call-site keeps the whole document
 * in one column with `all`.
 */
export type RegistryPart = 'all' | 'commercial' | 'inscriptions';

/**
 * Proveniência · Dados do registo · Órgãos sociais — where the certidão came from and the
 * identification it carried. One coherent group: the "Dados do registo" card is the payload
 * the provenance above it vouches for.
 */
function CommercialCards({ extract }: { extract: RegistryExtractView }) {
  const t = useT();
  const p = extract.provenance;
  const formaJuridica =
    extract.forma_juridica ?? (extract.legal_form ? legalFormLabel(extract.legal_form) : null);

  return (
    <>
      <Card title={t('registry.provenance.title')} actions={<ValidityBadge provenance={p} />}>
        <dl className="deflist">
          <Row term={t('registry.provenance.accessCode')} help={registryFieldHelp.accessCodeMasked}>
            <code className="mono">{p.access_code_masked}</code>
          </Row>
          <Row term={t('registry.provenance.retrievedAt')} help={registryFieldHelp.retrievedAt}>
            {/* The retrieval instant is the audit trail for this import — evidentiary, so it
                carries seconds and the zone, with the exact stamp in the `datetime` attribute. */}
            <DateTime value={p.retrieved_at} evidentiary className="mono" />
          </Row>
          <Row term={t('registry.provenance.conservatoria')} help={registryFieldHelp.conservatoria}>
            {p.conservatoria}
          </Row>
          <Row term={t('registry.provenance.oficial')} help={registryFieldHelp.oficial}>
            {p.oficial}
          </Row>
          <Row term={t('registry.provenance.subscribedOn')} help={registryFieldHelp.subscribedOn}>
            {p.subscribed_on ? <DateOnly value={p.subscribed_on} className="mono" /> : null}
          </Row>
          <Row term={t('registry.provenance.validUntil')} help={registryFieldHelp.validUntil}>
            {p.valid_until ? <DateOnly value={p.valid_until} className="mono" /> : null}
          </Row>
          <Row term={t('registry.provenance.source')} help={registryFieldHelp.source}>
            <Truncate text={p.source_url} href={p.source_url} mono />
          </Row>
          <Row term={t('registry.provenance.digest')} help={registryFieldHelp.digest}>
            <Digest value={p.raw_digest} />
          </Row>
        </dl>
      </Card>

      <Card title={t('registry.registryData')}>
        <dl className="deflist deflist--pairs">
          <Row term={t('registry.field.firma')} help={registryFieldHelp.firma} wide>
            {extract.firma}
          </Row>
          <Row term={t('registry.field.nipc')} help={registryFieldHelp.nipc}>
            {extract.nipc ? <code className="mono">{extract.nipc}</code> : null}
          </Row>
          <Row term={t('registry.field.matricula')} help={registryFieldHelp.matricula}>
            {extract.matricula}
          </Row>
          <Row term={t('registry.field.legalForm')} help={registryFieldHelp.legalForm}>
            {formaJuridica}
          </Row>
          <Row
            term={t('registry.field.dataConstituicao')}
            help={registryFieldHelp.dataConstituicao}
          >
            {extract.data_constituicao ? <DateOnly value={extract.data_constituicao} /> : null}
          </Row>
          <Row term={t('registry.field.capital')} help={registryFieldHelp.capital}>
            {extract.capital}
          </Row>
          <Row term={t('registry.field.sede')} help={registryFieldHelp.sede} wide>
            {extract.sede}
          </Row>
          <Row term={t('registry.field.objeto')} help={registryFieldHelp.objeto} wide>
            {extract.objeto}
          </Row>
          <Row term={t('registry.field.cae')} help={registryFieldHelp.cae} wide>
            {extract.cae.length > 0 ? <CaeRefList refs={extract.cae} /> : null}
          </Row>
        </dl>
      </Card>

      {extract.orgaos.length > 0 ? (
        <Card title={t('registry.orgaosSociais')}>
          <ul className="registry-officers">
            {extract.orgaos.map((o, i) => (
              <Officer key={`${o.name}-${o.source_event ?? i}`} officer={o} />
            ))}
          </ul>
        </Card>
      ) : null}
    </>
  );
}

/**
 * The event feed: the numbered inscrições/averbamentos in printed order, followed by the
 * anotações. Anotações stay beside them rather than in a tab of their own — they are marginal
 * notes on the same certidão (the list card is already titled "Inscrições, averbamentos e
 * anotações") and reading one without the other loses the cross-reference.
 *
 * When `standalone`, the anotações card always renders — with an honest empty line when the
 * certidão carried none — because it heads a named section the operator navigated to.
 */
function InscriptionCards({
  extract,
  standalone,
}: {
  extract: RegistryExtractView;
  standalone: boolean;
}) {
  const t = useT();
  return (
    <>
      <Card title={t('registry.inscricoes.title')}>
        {extract.inscricoes.length === 0 ? (
          <p className="muted">{t('registry.inscricoes.emptyLegible')}</p>
        ) : (
          <ol className="registry-inscricoes">
            {extract.inscricoes.map((ev, i) => (
              <Inscricao key={`${ev.number ?? i}`} event={ev} index={i} />
            ))}
          </ol>
        )}
      </Card>

      {extract.anotacoes.length > 0 ? (
        <Card title={t('registry.anotacoes.title')}>
          <AnotacoesList anotacoes={extract.anotacoes} />
        </Card>
      ) : standalone ? (
        <Card title={t('registry.anotacoes.title')}>
          <p className="muted">{t('registry.anotacoes.empty')}</p>
        </Card>
      ) : null}
    </>
  );
}

function ExtractBody({ extract, part }: { extract: RegistryExtractView; part: RegistryPart }) {
  return (
    <div className="stack">
      {part !== 'inscriptions' ? <CommercialCards extract={extract} /> : null}
      {part !== 'commercial' ? (
        <InscriptionCards extract={extract} standalone={part === 'inscriptions'} />
      ) : null}
    </div>
  );
}

export function RegistryProvenance({
  entityId,
  part = 'all',
}: {
  entityId: string;
  part?: RegistryPart;
}) {
  const t = useT();
  const { id: routeId = '' } = useParams();
  const id = entityId || routeId;
  const registry = useEntityRegistry(id);

  // What arrives is a stack of cards of label/value pairs (the commercial extract, then
  // the inscriptions), so the placeholder is that: two deflist-shaped cards.
  if (registry.isLoading)
    return (
      <SkeletonRegion className="stack" label={t('registry.loading')}>
        <Card>
          <SkeletonDeflist rows={6} />
        </Card>
        <Card>
          <SkeletonDeflist rows={4} />
        </Card>
      </SkeletonRegion>
    );

  // A 404 means "nothing imported yet" — an empty state, not an error.
  if (registry.error) {
    if (registry.error instanceof ApiError && registry.error.status === 404) {
      return (
        <Card title={t('registry.emptyCard.title')}>
          <EmptyState title={t('registry.empty.title')}>
            <p>
              {t('registry.emptyBody.before')}
              <strong>{t('registry.importFromRegistry')}</strong>
              {t('registry.emptyBody.after')}
            </p>
          </EmptyState>
        </Card>
      );
    }
    return <ErrorNote error={registry.error} />;
  }

  if (!registry.data) return null;
  return <ExtractBody extract={registry.data} part={part} />;
}
