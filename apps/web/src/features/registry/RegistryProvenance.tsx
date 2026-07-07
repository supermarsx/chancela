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
 */
import { useParams } from 'react-router-dom';
import { useEntityRegistry } from '../../api/hooks';
import { legalFormLabel } from '../../api/labels';
import { ApiError } from '../../api/client';
import { useT } from '../../i18n';
import { Badge, Card, Digest, EmptyState, ErrorNote, Loading, Truncate } from '../../ui';
import { CaeRefList } from '../cae/CaeRefList';
import type { RegistryEventView, RegistryExtractView, RegistryOfficerView } from '../../api/types';

/**
 * A `<dl>` row, omitted entirely when the value is absent. In a two-column grid
 * (`deflist--pairs`) a `wide` row spans both columns — used for long free-text
 * fields (objeto, sede) that would otherwise wrap awkwardly in a half-width cell.
 */
function Row({
  term,
  wide,
  children,
}: {
  term: string;
  wide?: boolean;
  children: React.ReactNode;
}) {
  if (children === null || children === undefined || children === '') return null;
  return (
    <div className={wide ? 'deflist__wide' : undefined}>
      <dt>{term}</dt>
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
        {officer.appointment_date
          ? t('registry.officer.appointment', { date: officer.appointment_date })
          : t('registry.officer.appointmentNone')}
        {officer.cessation_date
          ? ` · ${t('registry.officer.cessation', { date: officer.cessation_date })}`
          : null}
        {officer.source_event
          ? ` · ${t('registry.officer.inscricao', { event: officer.source_event })}`
          : null}
      </p>
    </li>
  );
}

/**
 * A single inscrição / averbamento / anotação, rendered as distinct, labelled parts
 * (t13 item 6): the número as a mono marker, the kind hint as an accent badge, the date
 * aligned to the end of the header, the apresentação on its own labelled meta line, and
 * the text body cleanly set below — while preserving the printed certidão order.
 */
function Inscricao({ event, index }: { event: RegistryEventView; index: number }) {
  const t = useT();
  return (
    <li className="registry-inscricao">
      <div className="registry-inscricao__head">
        <span className="registry-inscricao__num">{event.number ?? `#${index + 1}`}</span>
        {event.kind_hint ? <Badge tone="accent">{event.kind_hint}</Badge> : null}
        {event.date ? (
          <time className="registry-inscricao__date mono" dateTime={event.date}>
            {event.date}
          </time>
        ) : null}
      </div>
      {event.apresentacao ? (
        <p className="registry-inscricao__meta">
          <span className="registry-inscricao__meta-label">
            {t('registry.inscricao.apresentacao')}
          </span>
          <span className="mono">{event.apresentacao}</span>
        </p>
      ) : null}
      <p className="registry-inscricao__text">{event.text}</p>
    </li>
  );
}

function ExtractBody({ extract }: { extract: RegistryExtractView }) {
  const t = useT();
  const p = extract.provenance;
  const formaJuridica =
    extract.forma_juridica ?? (extract.legal_form ? legalFormLabel(extract.legal_form) : null);

  return (
    <div className="stack">
      <Card title={t('registry.provenance.title')}>
        <dl className="deflist">
          <Row term={t('registry.provenance.accessCode')}>
            <code className="mono">{p.access_code_masked}</code>
          </Row>
          <Row term={t('registry.provenance.retrievedAt')}>
            <span className="mono">{p.retrieved_at}</span>
          </Row>
          <Row term={t('registry.provenance.source')}>
            <Truncate text={p.source_url} href={p.source_url} mono />
          </Row>
          <Row term={t('registry.provenance.digest')}>
            <Digest value={p.raw_digest} />
          </Row>
        </dl>
      </Card>

      <Card title={t('registry.registryData')}>
        <dl className="deflist deflist--pairs">
          <Row term={t('registry.field.firma')} wide>
            {extract.firma}
          </Row>
          <Row term={t('registry.field.nipc')}>
            {extract.nipc ? <code className="mono">{extract.nipc}</code> : null}
          </Row>
          <Row term={t('registry.field.matricula')}>{extract.matricula}</Row>
          <Row term={t('registry.field.legalForm')}>{formaJuridica}</Row>
          <Row term={t('registry.field.dataConstituicao')}>{extract.data_constituicao}</Row>
          <Row term={t('registry.field.capital')}>{extract.capital}</Row>
          <Row term={t('registry.field.sede')} wide>
            {extract.sede}
          </Row>
          <Row term={t('registry.field.objeto')} wide>
            {extract.objeto}
          </Row>
          <Row term={t('registry.field.cae')} wide>
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
    </div>
  );
}

export function RegistryProvenance({ entityId }: { entityId: string }) {
  const t = useT();
  const { id: routeId = '' } = useParams();
  const id = entityId || routeId;
  const registry = useEntityRegistry(id);

  if (registry.isLoading) return <Loading label={t('registry.loading')} />;

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
  return <ExtractBody extract={registry.data} />;
}
