/**
 * DocumentPreview — a faithful, print-friendly render of a server `DocumentModel`
 * (plan t48-e6, deliverable 1).
 *
 * The server is the single source of truth: this component renders ONLY the block tree
 * the `GET /v1/acts/{id}/document/preview` endpoint returns — it never fabricates or
 * infers document content client-side. It supersedes the ad-hoc deliberations print
 * approach: screen and PDF/A now share one model, and this same DOM is what
 * `window.print()` emits (see `documents.css` `@media print`).
 *
 * Every block variant of `chancela-core::Block` is handled: Heading (by level),
 * Paragraph (bold/italic runs), KeyValue (2-col), VoteTable (favor/against/abstain),
 * SignatureBlock (ruled signature lines), Rule, and PageBreak (a page division).
 * Document content is verbatim server text (UX-21) — only the structural labels the
 * table headers need are localized.
 */
import type { Block, DocumentModel, Run } from '../../api/types';
import { useT } from '../../i18n';
import './documents.css';

/** Render one styled text run. bold → <strong>, italic → <em>, both nest. */
function RunView({ run }: { run: Run }) {
  let node = <>{run.text}</>;
  if (run.italic) node = <em>{node}</em>;
  if (run.bold) node = <strong>{node}</strong>;
  return node;
}

/** Clamp a server-supplied heading level into the 1–6 range for the tag + class. */
function headingLevel(level: number): 1 | 2 | 3 | 4 | 5 | 6 {
  if (!Number.isFinite(level)) return 2;
  return Math.min(6, Math.max(1, Math.round(level))) as 1 | 2 | 3 | 4 | 5 | 6;
}

function BlockView({ block }: { block: Block }) {
  const t = useT();
  switch (block.type) {
    case 'Heading': {
      const level = headingLevel(block.level);
      const Tag = `h${level}` as const;
      return <Tag className={`doc-block doc-heading doc-heading--${level}`}>{block.text}</Tag>;
    }
    case 'Paragraph':
      return (
        <p className="doc-block doc-paragraph">
          {block.runs.map((run, i) => (
            <RunView key={i} run={run} />
          ))}
        </p>
      );
    case 'KeyValue':
      return (
        <dl className="doc-block doc-kv">
          {block.rows.map((row, i) => (
            <div key={i} className="doc-kv__row" style={{ display: 'contents' }}>
              <dt className="doc-kv__key">{row.key}</dt>
              <dd className="doc-kv__value">{row.value}</dd>
            </div>
          ))}
        </dl>
      );
    case 'VoteTable':
      return (
        <table className="doc-block doc-votetable">
          <thead>
            <tr>
              <th scope="col">{t('documents.vote.label')}</th>
              <th scope="col" className="doc-votetable__num">
                {t('documents.vote.favor')}
              </th>
              <th scope="col" className="doc-votetable__num">
                {t('documents.vote.against')}
              </th>
              <th scope="col" className="doc-votetable__num">
                {t('documents.vote.abstain')}
              </th>
            </tr>
          </thead>
          <tbody>
            {block.rows.map((row, i) => (
              <tr key={i}>
                <td>{row.label}</td>
                <td className="doc-votetable__num">{row.favor}</td>
                <td className="doc-votetable__num">{row.against}</td>
                <td className="doc-votetable__num">{row.abstain}</td>
              </tr>
            ))}
          </tbody>
        </table>
      );
    case 'SignatureBlock':
      return (
        <div className="doc-block doc-signatures">
          {block.slots.map((slot, i) => (
            <div key={i} className="doc-signature">
              <p className="doc-signature__role">{slot.role}</p>
              <div className="doc-signature__line">
                <span className="doc-signature__name">{slot.name}</span>
              </div>
            </div>
          ))}
        </div>
      );
    case 'Rule':
      return <hr className="doc-block doc-rule" />;
    case 'PageBreak':
      return (
        <div className="doc-block doc-pagebreak" aria-hidden="true">
          {t('documents.pageBreak')}
        </div>
      );
    default:
      // Exhaustiveness guard: a future Block variant renders nothing rather than crashing.
      return null;
  }
}

export function DocumentPreview({ doc }: { doc: DocumentModel }) {
  const t = useT();
  return (
    <article className="doc-preview" lang={doc.language || undefined}>
      <header className="doc-preview__head">
        <h1 className="doc-preview__title">{doc.title}</h1>
        <p className="doc-preview__entity">{doc.entity_name}</p>
        {doc.entity_nipc ? (
          <p className="doc-preview__nipc">
            {t('documents.preview.nipc', { nipc: doc.entity_nipc })}
          </p>
        ) : null}
        {doc.subject ? <p className="doc-preview__subject">{doc.subject}</p> : null}
      </header>
      <div className="doc-preview__body">
        {doc.blocks.length === 0 ? (
          <p className="muted">{t('documents.preview.empty')}</p>
        ) : (
          doc.blocks.map((block, i) => <BlockView key={i} block={block} />)
        )}
      </div>
    </article>
  );
}
