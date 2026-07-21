/**
 * Structured rendering of a certidão inscrição's parsed `detail` (plan t21 §4). The
 * server parses each inscrição body into a typed `InscriptionDetailView` — an
 * apresentação header (número + date + multi-act kinds) and, when the act is one of the
 * v1-structured kinds, a discriminated `payload`:
 *
 *  - `Constitution` — the richest: identificação, sede (address), objecto, capital (+
 *    realization note), sócios/quotas table, órgãos designados, forma de obrigar,
 *    deliberation date;
 *  - `Designation` / `Cessation` / `ContractAmendment` — compact structured cards reusing
 *    the shared address / organ / member sub-renderers.
 *
 * Whatever the parser understood, the raw `text` is NEVER hidden: a structured entry
 * keeps its full body one collapsible "texto integral" toggle away; an unstructured
 * entry (`payload === null`, e.g. a transmissão de quotas deferred in v1) falls straight
 * back to the raw text. Every value is best-effort — an absent field is simply omitted.
 */
import type { ReactNode } from 'react';
import { formatDate } from '../../format';
import { useT } from '../../i18n';
import { Badge, DateOnly, FieldHelp, Table, Truncate } from '../../ui';
import { registryFieldHelp } from './fieldHelp';
import type {
  AddressView,
  ApresentacaoView,
  InscriptionDetailView,
  InscriptionPayloadView,
  MoneyView,
  OrganMemberView,
  OrganView,
  QuotaView,
  RegistryAnnotationView,
  RegistryOfficialSignatureView,
} from '../../api/types';

/** "100,00 Euros" — amount and currency joined, currency omitted when absent. */
function moneyText(money: MoneyView): string {
  return money.currency ? `${money.amount_text} ${money.currency}` : money.amount_text;
}

/** A `<dl>` row, omitted when empty. `wide` spans both columns of a pair grid. */
function DefRow({
  term,
  wide,
  help,
  children,
}: {
  term: string;
  wide?: boolean;
  help?: string;
  children: ReactNode;
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

/** A section with a small uppercase heading, omitted by the caller when its body is empty. */
function DetailBlock({
  title,
  help,
  children,
}: {
  title: string;
  help?: string;
  children: ReactNode;
}) {
  return (
    <section className="registry-detail__block">
      <h5 className="registry-detail__h">
        {help ? (
          <span className="field__labelrow">
            <span>{title}</span>
            <FieldHelp text={help} />
          </span>
        ) : (
          title
        )}
      </h5>
      {children}
    </section>
  );
}

/**
 * A postal address exactly as printed: the free lines, then the `postal_code locality`
 * line, then the Distrito / Concelho / Freguesia administrative breakdown when present.
 */
function AddressBlock({ address }: { address: AddressView }) {
  const t = useT();
  const postal = [address.postal_code, address.locality].filter(Boolean).join(' ');
  const admin = [
    address.distrito ? `${t('registry.address.distrito')}: ${address.distrito}` : null,
    address.concelho ? `${t('registry.address.concelho')}: ${address.concelho}` : null,
    address.freguesia ? `${t('registry.address.freguesia')}: ${address.freguesia}` : null,
  ]
    .filter(Boolean)
    .join(' · ');
  return (
    <div className="registry-address">
      {address.lines.map((line, i) => (
        <span key={`${line}-${i}`} className="registry-address__line">
          {line}
        </span>
      ))}
      {postal ? <span className="registry-address__postal">{postal}</span> : null}
      {admin ? <span className="registry-address__admin muted">{admin}</span> : null}
    </div>
  );
}

/** The SÓCIOS E QUOTAS table: quota amount + the titular's identity and residência. */
function QuotaTable({ socios }: { socios: QuotaView[] }) {
  const t = useT();
  const dash = <span className="muted">—</span>;
  return (
    <Table
      head={
        <tr>
          <th>{t('registry.quota.amount')}</th>
          <th>{t('registry.quota.titular')}</th>
          <th>{t('registry.party.nif')}</th>
          <th>{t('registry.party.estadoCivil')}</th>
          <th>{t('registry.party.nacionalidade')}</th>
          <th>{t('registry.party.residencia')}</th>
        </tr>
      }
    >
      {socios.map((q, i) => (
        <tr key={`${q.titular.name}-${i}`}>
          <td className="mono">{moneyText(q.amount)}</td>
          <td>{q.titular.name}</td>
          <td className="mono">{q.titular.nif ?? dash}</td>
          <td>{q.titular.estado_civil ?? dash}</td>
          <td>{q.titular.nacionalidade ?? dash}</td>
          <td>{q.titular.residencia ? <AddressBlock address={q.titular.residencia} /> : dash}</td>
        </tr>
      ))}
    </Table>
  );
}

/** One organ member: name + cargo badge, then the remaining identity in a pair grid. */
function MemberItem({ member }: { member: OrganMemberView }) {
  const t = useT();
  return (
    <li className="registry-member">
      <div className="registry-member__head">
        <span className="registry-member__name">{member.name}</span>
        {member.cargo ? <Badge tone="accent">{member.cargo}</Badge> : null}
      </div>
      <dl className="deflist deflist--pairs registry-member__meta">
        <DefRow term={t('registry.party.nif')}>
          {member.nif ? <code className="mono">{member.nif}</code> : null}
        </DefRow>
        <DefRow term={t('registry.party.nacionalidade')}>{member.nacionalidade}</DefRow>
        <DefRow term={t('registry.party.residencia')} wide>
          {member.residencia ? <AddressBlock address={member.residencia} /> : null}
        </DefRow>
      </dl>
    </li>
  );
}

function MemberList({ members }: { members: OrganMemberView[] }) {
  return (
    <ul className="registry-members">
      {members.map((m, i) => (
        <MemberItem key={`${m.name}-${i}`} member={m} />
      ))}
    </ul>
  );
}

/** A designated organ (GERÊNCIA, CONSELHO DE ADMINISTRAÇÃO, …) and its members. */
function OrganList({ orgaos }: { orgaos: OrganView[] }) {
  return (
    <ul className="registry-organs">
      {orgaos.map((organ, i) => (
        <li key={`${organ.name}-${i}`} className="registry-organ">
          <p className="registry-organ__name">{organ.name}</p>
          <MemberList members={organ.members} />
        </li>
      ))}
    </ul>
  );
}

function ConstitutionCard({
  payload,
}: {
  payload: Extract<InscriptionPayloadView, { type: 'Constitution' }>;
}) {
  const t = useT();
  return (
    <div className="registry-detail">
      <dl className="deflist deflist--pairs">
        <DefRow term={t('registry.field.firma')} help={registryFieldHelp.firma} wide>
          {payload.firma}
        </DefRow>
        <DefRow term={t('registry.field.nipc')} help={registryFieldHelp.nipc}>
          {payload.nipc ? <code className="mono">{payload.nipc}</code> : null}
        </DefRow>
        <DefRow
          term={t('registry.detail.naturezaJuridica')}
          help={registryFieldHelp.naturezaJuridica}
        >
          {payload.natureza_juridica}
        </DefRow>
        <DefRow term={t('registry.field.capital')} help={registryFieldHelp.capital}>
          {payload.capital ? moneyText(payload.capital) : null}
        </DefRow>
        <DefRow term={t('registry.detail.fiscalYearEnd')} help={registryFieldHelp.fiscalYearEnd}>
          {payload.fiscal_year_end}
        </DefRow>
        <DefRow
          term={t('registry.detail.capitalRealization')}
          help={registryFieldHelp.capitalRealization}
          wide
        >
          {payload.capital_realization_note}
        </DefRow>
        <DefRow
          term={t('registry.detail.deliberationDate')}
          help={registryFieldHelp.deliberationDate}
        >
          {/* The server normalizes every parsed certidão date to ISO; it is a calendar day, so
              it renders date-only rather than as a raw `2026-05-11`. */}
          {payload.deliberation_date ? <DateOnly value={payload.deliberation_date} /> : null}
        </DefRow>
      </dl>

      {payload.sede ? (
        <DetailBlock title={t('registry.field.sede')} help={registryFieldHelp.sede}>
          <AddressBlock address={payload.sede} />
        </DetailBlock>
      ) : null}
      {payload.objecto ? (
        <DetailBlock title={t('registry.field.objeto')} help={registryFieldHelp.objeto}>
          <p className="registry-detail__prose">{payload.objecto}</p>
        </DetailBlock>
      ) : null}
      {payload.forma_de_obrigar ? (
        <DetailBlock
          title={t('registry.detail.formaObrigar')}
          help={registryFieldHelp.formaObrigar}
        >
          <p className="registry-detail__prose">{payload.forma_de_obrigar}</p>
        </DetailBlock>
      ) : null}
      {payload.socios.length > 0 ? (
        <DetailBlock title={t('registry.detail.socios')}>
          <QuotaTable socios={payload.socios} />
        </DetailBlock>
      ) : null}
      {payload.orgaos.length > 0 ? (
        <DetailBlock title={t('registry.detail.orgaos')}>
          <OrganList orgaos={payload.orgaos} />
        </DetailBlock>
      ) : null}
    </div>
  );
}

function DesignationCard({
  payload,
}: {
  payload: Extract<InscriptionPayloadView, { type: 'Designation' }>;
}) {
  const t = useT();
  return (
    <div className="registry-detail">
      {payload.orgaos.length > 0 ? <OrganList orgaos={payload.orgaos} /> : null}
      {payload.deliberation_date ? (
        <dl className="deflist deflist--pairs">
          <DefRow
            term={t('registry.detail.deliberationDate')}
            help={registryFieldHelp.deliberationDate}
          >
            <DateOnly value={payload.deliberation_date} />
          </DefRow>
        </dl>
      ) : null}
    </div>
  );
}

function CessationCard({
  payload,
}: {
  payload: Extract<InscriptionPayloadView, { type: 'Cessation' }>;
}) {
  const t = useT();
  return (
    <div className="registry-detail">
      {payload.members.length > 0 ? <MemberList members={payload.members} /> : null}
      <dl className="deflist deflist--pairs">
        <DefRow term={t('registry.detail.cessationCause')}>{payload.cause}</DefRow>
        <DefRow term={t('registry.detail.cessationDate')}>
          {payload.date ? <DateOnly value={payload.date} /> : null}
        </DefRow>
      </dl>
    </div>
  );
}

function AmendmentCard({
  payload,
}: {
  payload: Extract<InscriptionPayloadView, { type: 'ContractAmendment' }>;
}) {
  const t = useT();
  return (
    <div className="registry-detail">
      <dl className="deflist deflist--pairs">
        <DefRow term={t('registry.detail.newFirma')} wide>
          {payload.new_firma}
        </DefRow>
        <DefRow term={t('registry.detail.newCapital')}>
          {payload.new_capital ? moneyText(payload.new_capital) : null}
        </DefRow>
        <DefRow
          term={t('registry.detail.deliberationDate')}
          help={registryFieldHelp.deliberationDate}
        >
          {payload.deliberation_date ? <DateOnly value={payload.deliberation_date} /> : null}
        </DefRow>
        <DefRow term={t('registry.detail.newObjecto')} help={registryFieldHelp.objeto} wide>
          {payload.new_objecto}
        </DefRow>
      </dl>
      {payload.new_sede ? (
        <DetailBlock title={t('registry.detail.newSede')} help={registryFieldHelp.sede}>
          <AddressBlock address={payload.new_sede} />
        </DetailBlock>
      ) : null}
    </div>
  );
}

/** Dispatch on the payload discriminant; an unknown future kind renders nothing (raw
 * text still carries it — never lossy). */
function PayloadCard({ payload }: { payload: InscriptionPayloadView }) {
  switch (payload.type) {
    case 'Constitution':
      return <ConstitutionCard payload={payload} />;
    case 'Designation':
      return <DesignationCard payload={payload} />;
    case 'Cessation':
      return <CessationCard payload={payload} />;
    case 'ContractAmendment':
      return <AmendmentCard payload={payload} />;
    default:
      return null;
  }
}

/** The apresentação header: `AP. N`, date, optional time, and one accent badge per act kind. */
function ApresentacaoLine({ apresentacao }: { apresentacao: ApresentacaoView }) {
  const t = useT();
  const stub = [
    apresentacao.number ? `AP. ${apresentacao.number}` : null,
    // The parsed apresentação day (ISO from the server) and its clock time are separate fields;
    // only the day goes through the shared date formatter, the time is printed as recorded.
    apresentacao.date ? formatDate(apresentacao.date) : null,
    apresentacao.time,
  ]
    .filter(Boolean)
    .join(' · ');
  return (
    <p className="registry-inscricao__meta">
      <span className="registry-inscricao__meta-label">{t('registry.inscricao.apresentacao')}</span>
      {stub ? <span className="mono">{stub}</span> : null}
      {apresentacao.act_kinds.map((kind, i) => (
        <Badge key={`${kind}-${i}`} tone="accent">
          {kind}
        </Badge>
      ))}
    </p>
  );
}

/** The conservatória / oficial signature pair(s) sitting inside an entry body. */
function SignatureBlock({ signatures }: { signatures: RegistryOfficialSignatureView[] }) {
  const t = useT();
  return (
    <ul className="registry-signatures">
      {signatures.map((sig, i) => (
        <li key={i} className="registry-signature muted">
          {[
            sig.conservatoria
              ? `${t('registry.provenance.conservatoria')}: ${sig.conservatoria}`
              : null,
            sig.oficial ? `${t('registry.provenance.oficial')}: ${sig.oficial}` : null,
          ]
            .filter(Boolean)
            .join(' · ')}
        </li>
      ))}
    </ul>
  );
}

/**
 * The full structured body of one inscrição. Renders the apresentação, the payload card
 * (when a v1-structured kind), and any in-body signatures; the raw `text` is always
 * reachable — collapsed under a "texto integral" toggle when structured, shown plainly
 * otherwise.
 */
export function InscriptionDetailBody({
  detail,
  rawText,
}: {
  detail: InscriptionDetailView;
  rawText: string;
}) {
  const t = useT();
  const hasPayload = detail.payload !== null;
  return (
    <div className="registry-detail-wrap">
      {detail.apresentacao ? <ApresentacaoLine apresentacao={detail.apresentacao} /> : null}
      {detail.payload ? <PayloadCard payload={detail.payload} /> : null}
      {detail.signatures.length > 0 ? <SignatureBlock signatures={detail.signatures} /> : null}
      {hasPayload ? (
        <details className="registry-detail__raw">
          <summary>{t('registry.inscricao.textoIntegral')}</summary>
          <p className="registry-inscricao__text">{rawText}</p>
        </details>
      ) : (
        <p className="registry-inscricao__text">{rawText}</p>
      )}
    </div>
  );
}

/** The `An. N` publication annotations on the matrícula, each with its publication link. */
export function AnotacoesList({ anotacoes }: { anotacoes: RegistryAnnotationView[] }) {
  const t = useT();
  return (
    <ul className="registry-anotacoes">
      {anotacoes.map((a, i) => (
        <li key={`${a.number ?? i}`} className="registry-anotacao">
          <div className="registry-anotacao__head">
            <span className="registry-anotacao__num mono">
              {a.number ? t('registry.anotacoes.item', { number: a.number }) : `#${i + 1}`}
            </span>
            {a.date ? <DateOnly value={a.date} className="registry-anotacao__date mono" /> : null}
          </div>
          <p className="registry-anotacao__text">{a.text}</p>
          {a.publication_url ? (
            <p className="registry-anotacao__pub">
              <span className="registry-inscricao__meta-label">
                {t('registry.anotacoes.publication')}
              </span>
              <Truncate text={a.publication_url} href={a.publication_url} mono />
            </p>
          ) : null}
        </li>
      ))}
    </ul>
  );
}
