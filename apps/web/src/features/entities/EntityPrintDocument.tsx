/**
 * The print-only registry abstract for an entity (t20). It is rendered into a portal
 * at the end of `<body>` and kept `display:none` on screen; the `@media print`
 * stylesheet (theme.css) hides the whole app shell and reveals only this document, so
 * printing the entity page yields a clean, filing-quality certidão abstract rather than
 * a screenshot of the UI.
 *
 * Composition (top to bottom):
 *   - a letterhead: the Chancela seal, the firma, and an identification line
 *     (NIPC · forma jurídica · sede), closed by a hairline rule;
 *   - "Dados do registo" in the same two-column arrangement as the screen card;
 *   - "Órgãos sociais" with appointment / cessation;
 *   - the numbered "Inscrições" list with dates;
 *   - a provenance footer (masked access code, retrieved-at, document digest);
 *   - the printed-on date.
 *
 * When no certidão has been imported yet the body degrades to the entity's own
 * identification so the sheet is still a coherent document.
 *
 * It reads the same React Query caches the visible page already populated
 * (`useEntity` / `useEntityRegistry`), so it adds no network cost.
 */
import { createPortal } from 'react-dom';
import { ApiError } from '../../api/client';
import { useEntity, useEntityRegistry } from '../../api/hooks';
import {
  caeLevelLabels,
  caeRevisionLabels,
  caeRoleLabels,
  entityFamilyLabels,
  entityKindLabels,
  legalFormLabel,
} from '../../api/labels';
import { useT, useLocale } from '../../i18n';
import type {
  Entity,
  RegistryEventView,
  RegistryExtractView,
  RegistryOfficerView,
} from '../../api/types';

/** "7 de julho de 2026" — the day the abstract is printed, in the active locale. */
function printedOn(locale: string): string {
  return new Intl.DateTimeFormat(locale, {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  }).format(new Date());
}

/** A print `<dl>` pair, skipped when empty. `wide` spans both columns. */
function PrintRow({ term, wide, value }: { term: string; wide?: boolean; value: React.ReactNode }) {
  if (value === null || value === undefined || value === '') return null;
  return (
    <div className={wide ? 'print-pair print-pair--wide' : 'print-pair'}>
      <dt>{term}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function PrintOfficer({ officer }: { officer: RegistryOfficerView }) {
  const t = useT();
  const dates = [
    officer.appointment_date
      ? t('entities.print.officer.appointment', { date: officer.appointment_date })
      : null,
    officer.cessation_date
      ? t('entities.print.officer.cessation', { date: officer.cessation_date })
      : null,
    officer.source_event
      ? t('entities.print.officer.inscricao', { event: officer.source_event })
      : null,
  ].filter(Boolean);
  return (
    <li className="print-officer">
      <span className="print-officer__name">{officer.name}</span>
      {officer.role ? <span className="print-officer__role"> — {officer.role}</span> : null}
      {dates.length > 0 ? <div className="print-officer__dates">{dates.join(' · ')}</div> : null}
    </li>
  );
}

function PrintInscricao({ event, index }: { event: RegistryEventView; index: number }) {
  const t = useT();
  return (
    <li className="print-inscricao">
      <div className="print-inscricao__head">
        <span className="print-inscricao__num">{event.number ?? `#${index + 1}`}</span>
        {event.kind_hint ? <span className="print-inscricao__kind">{event.kind_hint}</span> : null}
        {event.date ? <span className="print-inscricao__date">{event.date}</span> : null}
      </div>
      {event.apresentacao ? (
        <div className="print-inscricao__meta">
          {t('entities.print.inscricao.apresentacao', { num: event.apresentacao })}
        </div>
      ) : null}
      <p className="print-inscricao__text">{event.text}</p>
    </li>
  );
}

function ExtractDocument({ extract }: { extract: RegistryExtractView }) {
  const t = useT();
  const p = extract.provenance;
  const formaJuridica =
    extract.forma_juridica ?? (extract.legal_form ? legalFormLabel(extract.legal_form) : null);

  return (
    <>
      <section className="print-section">
        <h2 className="print-h2">{t('entities.print.registryData')}</h2>
        <dl className="print-deflist">
          <PrintRow term={t('registry.field.firma')} wide value={extract.firma} />
          <PrintRow
            term={t('registry.field.nipc')}
            value={extract.nipc ? <span className="print-mono">{extract.nipc}</span> : null}
          />
          <PrintRow term={t('registry.field.matricula')} value={extract.matricula} />
          <PrintRow term={t('registry.field.legalForm')} value={formaJuridica} />
          <PrintRow term={t('registry.field.dataConstituicao')} value={extract.data_constituicao} />
          <PrintRow term={t('registry.field.capital')} value={extract.capital} />
          <PrintRow term={t('registry.field.sede')} wide value={extract.sede} />
          <PrintRow term={t('registry.field.objeto')} wide value={extract.objeto} />
          <PrintRow
            term={t('registry.field.cae')}
            wide
            value={
              extract.cae.length > 0 ? (
                <ul className="print-cae">
                  {extract.cae.map((c) => {
                    const meta =
                      c.level && c.revision
                        ? ` (${caeLevelLabels[c.level]} · ${caeRevisionLabels[c.revision]})`
                        : '';
                    return (
                      <li key={`${c.code}-${c.role}`}>
                        <span className="print-mono">{c.code}</span> · {caeRoleLabels[c.role]}
                        {c.designation
                          ? ` — ${c.designation}`
                          : ` — ${t('registry.cae.uncatalogued')}`}
                        {meta}
                      </li>
                    );
                  })}
                </ul>
              ) : null
            }
          />
        </dl>
      </section>

      {extract.orgaos.length > 0 ? (
        <section className="print-section">
          <h2 className="print-h2">{t('registry.orgaosSociais')}</h2>
          <ul className="print-officers">
            {extract.orgaos.map((o, i) => (
              <PrintOfficer key={`${o.name}-${o.source_event ?? i}`} officer={o} />
            ))}
          </ul>
        </section>
      ) : null}

      <section className="print-section">
        <h2 className="print-h2">{t('registry.inscricoes.title')}</h2>
        {extract.inscricoes.length === 0 ? (
          <p className="print-muted">{t('registry.inscricoes.emptyLegible')}</p>
        ) : (
          <ol className="print-inscricoes">
            {extract.inscricoes.map((ev, i) => (
              <PrintInscricao key={`${ev.number ?? i}`} event={ev} index={i} />
            ))}
          </ol>
        )}
      </section>

      <footer className="print-provenance">
        <h2 className="print-h2">{t('registry.provenance.title')}</h2>
        <dl className="print-deflist">
          <PrintRow
            term={t('registry.provenance.accessCode')}
            value={<span className="print-mono">{p.access_code_masked}</span>}
          />
          <PrintRow
            term={t('registry.provenance.retrievedAt')}
            value={<span className="print-mono">{p.retrieved_at}</span>}
          />
          <PrintRow
            term={t('registry.provenance.source')}
            wide
            value={<span className="print-mono print-break">{p.source_url}</span>}
          />
          <PrintRow
            term={t('registry.provenance.digest')}
            wide
            value={<span className="print-mono print-break">{p.raw_digest}</span>}
          />
        </dl>
      </footer>
    </>
  );
}

/** Fallback body when no certidão has been imported: the entity's own identification. */
function IdentificationDocument({ entity }: { entity: Entity }) {
  const t = useT();
  return (
    <section className="print-section">
      <h2 className="print-h2">{t('entities.print.identification')}</h2>
      <dl className="print-deflist">
        <PrintRow
          term={t('entities.field.nipc')}
          value={<span className="print-mono">{entity.nipc}</span>}
        />
        <PrintRow term={t('entities.field.legalForm')} value={entityKindLabels[entity.kind]} />
        <PrintRow term={t('entities.field.family')} value={entityFamilyLabels[entity.family]} />
        <PrintRow term={t('entities.field.seat')} wide value={entity.seat} />
      </dl>
      <p className="print-muted">{t('entities.print.noCertidao')}</p>
    </section>
  );
}

export function EntityPrintDocument({ entityId }: { entityId: string }) {
  const t = useT();
  const locale = useLocale();
  const entity = useEntity(entityId);
  const registry = useEntityRegistry(entityId);

  const ent = entity.data;
  if (!ent) return null;

  // A 404 registry means "nothing imported yet" — print identification only. Any other
  // registry error simply omits the registry body; the letterhead still prints.
  const hasExtract =
    registry.data !== undefined && registry.data !== null && !(registry.error instanceof ApiError);

  const formaJuridica = registry.data
    ? (registry.data.forma_juridica ??
      (registry.data.legal_form ? legalFormLabel(registry.data.legal_form) : null))
    : entityKindLabels[ent.kind];

  const subtitle = [
    ent.nipc ? t('entities.print.subtitleNipc', { nipc: ent.nipc }) : null,
    formaJuridica,
    ent.seat,
  ]
    .filter(Boolean)
    .join(' · ');

  const doc = (
    <article className="print-doc" role="document" aria-hidden="true">
      <header className="print-letterhead">
        <svg className="print-seal" viewBox="0 0 24 24" aria-hidden="true">
          <circle cx="12" cy="12" r="9.25" />
          <circle cx="12" cy="12" r="6.5" />
          <text x="12" y="15.5" textAnchor="middle">
            C
          </text>
        </svg>
        <div className="print-letterhead__body">
          <h1 className="print-title">{ent.name}</h1>
          <p className="print-subtitle">{subtitle}</p>
        </div>
        <p className="print-mark">{t('entities.print.mark')}</p>
      </header>
      <hr className="print-rule" />

      {hasExtract && registry.data ? (
        <ExtractDocument extract={registry.data} />
      ) : (
        <IdentificationDocument entity={ent} />
      )}

      <p className="print-printed-on">
        {t('entities.print.printedOn', { date: printedOn(locale) })}
      </p>
    </article>
  );

  return createPortal(doc, document.body);
}
