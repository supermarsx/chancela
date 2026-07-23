/**
 * TemplateBodyPreview — a read-only render of the SERVER-compiled narrative body (t56).
 *
 * The server is the single source of truth: this renders ONLY the `Block[]` that
 * `POST /v1/templates/body/preview` returns from the same `compile_markdown` the seal path runs, so
 * the author sees exactly the structure the document would carry. The client never compiles or
 * fabricates content itself.
 *
 * Merge tags render in their LITERAL token form (e.g. a heading reading `Ata n.º {{ ata_number }}`):
 * the preview is stateless — there is no act context to resolve them against — so it is honest about
 * being unresolved rather than inventing values. Compiling a template body through `md-block/v1`
 * yields headings, paragraphs (with bold/italic runs) and rules; the remaining `Block` variants
 * cannot arise from markdown but are handled for completeness so a future compiler change never
 * crashes the pane. It borrows the shared `.doc-*` block styles so screen and PDF/A read alike.
 *
 * Authored heading levels are nested under the preview's labelled level-2 boundary. They therefore
 * render as paragraphs carrying the matching `.doc-heading--N` class plus an explicit ARIA heading
 * level offset by two. A template containing `# ...` remains navigable as a level-3 heading without
 * injecting a second native `<h1>` into the application page.
 */
import type { Block, Run } from '../../api/types';
import '../documents/documents.css';

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

/** Place a document heading beneath the application page and its level-2 preview label. */
export function previewHeadingAriaLevel(level: number): 3 | 4 | 5 | 6 {
  return Math.min(6, headingLevel(level) + 2) as 3 | 4 | 5 | 6;
}

function BlockView({ block }: { block: Block }) {
  switch (block.type) {
    case 'Heading': {
      const level = headingLevel(block.level);
      return (
        <p
          className={`doc-block doc-heading doc-heading--${level}`}
          data-heading-level={level}
          role="heading"
          aria-level={previewHeadingAriaLevel(level)}
        >
          {block.text}
        </p>
      );
    }
    case 'Paragraph':
      return (
        <p className="doc-block doc-paragraph">
          {block.runs.map((run, i) => (
            <RunView key={i} run={run} />
          ))}
        </p>
      );
    case 'Rule':
      return <hr className="doc-block doc-rule" />;
    default:
      // KeyValue / VoteTable / SignatureBlock / PageBreak cannot arise from a compiled markdown
      // body; a future variant renders nothing rather than crashing.
      return null;
  }
}

export function TemplateBodyPreview({
  blocks,
  emptyLabel,
}: {
  blocks: Block[];
  emptyLabel: string;
}) {
  if (blocks.length === 0) {
    return <p className="muted">{emptyLabel}</p>;
  }
  return (
    <div className="doc-preview__body">
      {blocks.map((block, i) => (
        <BlockView key={i} block={block} />
      ))}
    </div>
  );
}
