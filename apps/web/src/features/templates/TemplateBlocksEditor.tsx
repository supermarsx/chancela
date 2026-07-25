/**
 * Friendly, lossless editing for the authored `TemplateBlockSpec[]`.
 *
 * The block schema is a discriminated union, so each kind gets the controls that belong to it
 * instead of asking an operator to hand-author JSON. Blocks stay in document order and can be
 * added, removed or reordered. Key/value blocks expose their nested rows as another compact,
 * editable collection.
 *
 * The canonical JSON remains available behind an explicitly advanced disclosure. It is the source
 * of truth passed to the create/edit pages so half-typed JSON is never discarded; the structured
 * controls are suspended and explain the validation error until that JSON is valid again.
 */
import { useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import type { TemplateBlockSpec, TemplateKvRowSpec } from '../../api/types';
import {
  useTemplatesEditorT,
  type TemplatesEditorCopyKey,
} from '../../i18n/templatesEditorFallback';
import {
  Button,
  ConfirmActionModal,
  Field,
  Icon,
  InlineWarning,
  Input,
  Select,
  TextArea,
} from '../../ui';
import './templateEditor.css';

const BLOCK_KINDS = [
  'Heading',
  'Paragraph',
  'KeyValue',
  'VoteTable',
  'SignatureBlock',
  'PageBreak',
  'Rule',
  'NarrativeBody',
] as const satisfies readonly TemplateBlockSpec['kind'][];

type BlockKind = (typeof BLOCK_KINDS)[number];

export interface NarrativeBodyPlacement {
  index: number;
  occurrence: number;
  primary: boolean;
}

interface PendingKindChange {
  index: number;
  fromKind: BlockKind;
  toKind: BlockKind;
}

type BlockFocusTarget = 'up' | 'down' | 'insert' | 'duplicate' | 'kind';

interface PendingBlockFocus {
  index: number;
  preferredAction: BlockFocusTarget;
  expectedValue: string;
}

type BlocksParseError = 'invalidJson' | 'notArray' | 'empty' | 'unknownKind' | 'invalidShape';

type BlocksParseResult =
  { blocks: TemplateBlockSpec[]; error: null } | { blocks: null; error: BlocksParseError };

const kindCopyKey: Record<BlockKind, TemplatesEditorCopyKey> = {
  Heading: 'templates.editor.blocks.kind.heading',
  Paragraph: 'templates.editor.blocks.kind.paragraph',
  KeyValue: 'templates.editor.blocks.kind.keyValue',
  VoteTable: 'templates.editor.blocks.kind.voteTable',
  SignatureBlock: 'templates.editor.blocks.kind.signatureBlock',
  PageBreak: 'templates.editor.blocks.kind.pageBreak',
  Rule: 'templates.editor.blocks.kind.rule',
  NarrativeBody: 'templates.editor.blocks.kind.narrativeBody',
};

const parseErrorCopyKey: Record<BlocksParseError, TemplatesEditorCopyKey> = {
  invalidJson: 'templates.editor.blocks.raw.invalidJson',
  notArray: 'templates.editor.blocks.raw.notArray',
  empty: 'templates.editor.blocks.raw.empty',
  unknownKind: 'templates.editor.blocks.raw.unknownKind',
  invalidShape: 'templates.editor.blocks.raw.invalidShape',
};

function isOptionalString(value: unknown): value is string | null | undefined {
  return value === undefined || value === null || typeof value === 'string';
}

function hasOnlyKnownKind(value: unknown): value is { kind: BlockKind } {
  if (!value || typeof value !== 'object') return false;
  const kind = (value as { kind?: unknown }).kind;
  return typeof kind === 'string' && (BLOCK_KINDS as readonly string[]).includes(kind);
}

function isKvRow(value: unknown): value is TemplateKvRowSpec {
  if (!value || typeof value !== 'object') return false;
  const row = value as Partial<TemplateKvRowSpec>;
  return typeof row.key === 'string' && typeof row.value === 'string';
}

function isTemplateBlock(value: unknown): value is TemplateBlockSpec {
  if (!hasOnlyKnownKind(value)) return false;
  const block = value as Record<string, unknown> & { kind: BlockKind };
  switch (block.kind) {
    case 'Heading':
      return typeof block.level === 'number' && typeof block.template === 'string';
    case 'Paragraph':
      return typeof block.template === 'string' && isOptionalString(block.items);
    case 'KeyValue':
      return (
        Array.isArray(block.rows) && block.rows.every(isKvRow) && isOptionalString(block.items)
      );
    case 'VoteTable':
      return (
        typeof block.items === 'string' &&
        typeof block.label === 'string' &&
        isOptionalString(block.vote_field) &&
        isOptionalString(block.unanimous_total)
      );
    case 'SignatureBlock':
      return (
        typeof block.source === 'string' &&
        typeof block.role === 'string' &&
        typeof block.name === 'string'
      );
    case 'PageBreak':
    case 'Rule':
    case 'NarrativeBody':
      return true;
  }
}

/**
 * Parse the canonical JSON without normalising it. Exported for the regression tests that pin the
 * advanced escape hatch and the complete discriminated union.
 */
export function parseTemplateBlocksText(value: string): BlocksParseResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return { blocks: null, error: 'invalidJson' };
  }
  if (!Array.isArray(parsed)) return { blocks: null, error: 'notArray' };
  if (parsed.length === 0) return { blocks: null, error: 'empty' };
  if (parsed.some((block) => !hasOnlyKnownKind(block))) {
    return { blocks: null, error: 'unknownKind' };
  }
  if (!parsed.every(isTemplateBlock)) return { blocks: null, error: 'invalidShape' };
  return { blocks: parsed, error: null };
}

/**
 * Add the narrative-body placement marker without disturbing any existing structured block.
 * Invalid Advanced JSON returns `null` so the recovery button never overwrites half-typed source.
 */
export function withNarrativeBodyPlacement(value: string): string | null {
  const parsed = parseTemplateBlocksText(value);
  if (!parsed.blocks) return null;
  if (parsed.blocks.some((block) => block.kind === 'NarrativeBody')) return value;
  return JSON.stringify([...parsed.blocks, { kind: 'NarrativeBody' }], null, 2);
}

/** A valid seed for each block kind. The server applies its normal default for omitted fields. */
export function newTemplateBlock(kind: BlockKind): TemplateBlockSpec {
  switch (kind) {
    case 'Heading':
      return { kind, level: 2, template: '' };
    case 'Paragraph':
      return { kind, template: '' };
    case 'KeyValue':
      return { kind, rows: [{ key: '', value: '' }] };
    case 'VoteTable':
      return { kind, items: 'deliberation_items', label: '{{ text }}', vote_field: 'vote' };
    case 'SignatureBlock':
      return { kind, source: 'signatories', role: '{{ capacity }}', name: '{{ name }}' };
    case 'PageBreak':
    case 'Rule':
    case 'NarrativeBody':
      return { kind };
  }
}

/**
 * A kind change replaces the whole discriminated-union member. Require an explicit confirmation
 * whenever that replacement would discard anything beyond the discriminator itself. Looking at
 * the runtime keys also protects fields authored through the Advanced JSON escape hatch.
 */
function hasDiscardableFields(block: TemplateBlockSpec): boolean {
  return Object.keys(block).some((key) => key !== 'kind');
}

function blockSummary(block: TemplateBlockSpec): string {
  switch (block.kind) {
    case 'Heading':
    case 'Paragraph':
      return block.template;
    case 'KeyValue':
      return block.rows
        .map((row) => row.key)
        .filter(Boolean)
        .join(' · ');
    case 'VoteTable':
      return block.label;
    case 'SignatureBlock':
      return block.source;
    case 'PageBreak':
    case 'Rule':
    case 'NarrativeBody':
      return '';
  }
}

interface DocumentPageBlock {
  block: TemplateBlockSpec;
  index: number;
}

/**
 * Explicit page-break blocks are the only honest pagination boundary available before rendering.
 * Grouping around those markers gives the author a paper flow without pretending browser height
 * is the PDF renderer's final pagination.
 */
function paginateDocumentBlocks(blocks: TemplateBlockSpec[]): DocumentPageBlock[][] {
  const pages: DocumentPageBlock[][] = [[]];
  blocks.forEach((block, index) => {
    pages[pages.length - 1].push({ block, index });
    if (block.kind === 'PageBreak' && index < blocks.length - 1) pages.push([]);
  });
  return pages;
}

function withoutBlankOptional<T extends TemplateBlockSpec, K extends keyof T>(
  block: T,
  key: K,
  value: string,
): T {
  const next = { ...block } as T & Record<K, unknown>;
  if (value.trim() === '') delete next[key];
  else next[key] = value as T[K];
  return next;
}

function MarkerExplanation({ kind }: { kind: 'PageBreak' | 'Rule' | 'NarrativeBody' }) {
  const bt = useTemplatesEditorT();
  const key: Record<typeof kind, TemplatesEditorCopyKey> = {
    PageBreak: 'templates.editor.blocks.marker.pageBreak',
    Rule: 'templates.editor.blocks.marker.rule',
    NarrativeBody: 'templates.editor.blocks.marker.narrativeBody',
  };
  return <p className="field__hint">{bt(key[kind])}</p>;
}

function BlockFields({
  block,
  index,
  onChange,
}: {
  block: TemplateBlockSpec;
  index: number;
  onChange: (next: TemplateBlockSpec) => void;
}) {
  const bt = useTemplatesEditorT();
  const prefix = `template-block-${index}`;

  switch (block.kind) {
    case 'Heading':
      return (
        <>
          <Field label={bt('templates.editor.blocks.field.level')} htmlFor={`${prefix}-level`}>
            <Select
              id={`${prefix}-level`}
              value={String(block.level)}
              options={[1, 2, 3, 4, 5, 6].map((level) => ({
                value: String(level),
                label: String(level),
              }))}
              onChange={(event) => onChange({ ...block, level: Number(event.target.value) })}
            />
          </Field>
          <Field
            label={bt('templates.editor.blocks.field.template')}
            htmlFor={`${prefix}-template`}
          >
            <TextArea
              id={`${prefix}-template`}
              rows={3}
              value={block.template}
              onChange={(event) => onChange({ ...block, template: event.target.value })}
            />
          </Field>
        </>
      );

    case 'Paragraph':
      return (
        <>
          <Field
            label={bt('templates.editor.blocks.field.template')}
            htmlFor={`${prefix}-template`}
          >
            <TextArea
              id={`${prefix}-template`}
              rows={3}
              value={block.template}
              onChange={(event) => onChange({ ...block, template: event.target.value })}
            />
          </Field>
          <Field label={bt('templates.editor.blocks.field.items')} htmlFor={`${prefix}-items`}>
            <Input
              id={`${prefix}-items`}
              className="control mono"
              value={block.items ?? ''}
              onChange={(event) =>
                onChange(withoutBlankOptional(block, 'items', event.target.value))
              }
            />
          </Field>
        </>
      );

    case 'KeyValue':
      return (
        <>
          <Field label={bt('templates.editor.blocks.field.items')} htmlFor={`${prefix}-items`}>
            <Input
              id={`${prefix}-items`}
              className="control mono"
              value={block.items ?? ''}
              onChange={(event) =>
                onChange(withoutBlankOptional(block, 'items', event.target.value))
              }
            />
          </Field>
          <Field label={bt('templates.editor.blocks.field.rows')}>
            <div className="stack--tight">
              {block.rows.map((row, rowIndex) => (
                <div
                  key={rowIndex}
                  className="template-block-editor__kv-row"
                  role="group"
                  aria-label={`${bt('templates.editor.blocks.field.rows')} ${rowIndex + 1}`}
                >
                  <Input
                    aria-label={`${bt('templates.editor.blocks.field.key')} ${rowIndex + 1}`}
                    placeholder={bt('templates.editor.blocks.field.key')}
                    value={row.key}
                    onChange={(event) =>
                      onChange({
                        ...block,
                        rows: block.rows.map((current, currentIndex) =>
                          currentIndex === rowIndex
                            ? { ...current, key: event.target.value }
                            : current,
                        ),
                      })
                    }
                  />
                  <Input
                    aria-label={`${bt('templates.editor.blocks.field.value')} ${rowIndex + 1}`}
                    placeholder={bt('templates.editor.blocks.field.value')}
                    value={row.value}
                    onChange={(event) =>
                      onChange({
                        ...block,
                        rows: block.rows.map((current, currentIndex) =>
                          currentIndex === rowIndex
                            ? { ...current, value: event.target.value }
                            : current,
                        ),
                      })
                    }
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    icon={<Icon.Trash />}
                    aria-label={`${bt('templates.editor.blocks.removeRow')} ${rowIndex + 1}`}
                    onClick={() =>
                      onChange({
                        ...block,
                        rows: block.rows.filter((_, currentIndex) => currentIndex !== rowIndex),
                      })
                    }
                  />
                </div>
              ))}
              <Button
                type="button"
                variant="secondary"
                icon={<Icon.Plus />}
                onClick={() =>
                  onChange({ ...block, rows: [...block.rows, { key: '', value: '' }] })
                }
              >
                {bt('templates.editor.blocks.addRow')}
              </Button>
            </div>
          </Field>
        </>
      );

    case 'VoteTable':
      return (
        <>
          <Field label={bt('templates.editor.blocks.field.items')} htmlFor={`${prefix}-items`}>
            <Input
              id={`${prefix}-items`}
              className="control mono"
              value={block.items}
              onChange={(event) => onChange({ ...block, items: event.target.value })}
            />
          </Field>
          <Field label={bt('templates.editor.blocks.field.label')} htmlFor={`${prefix}-label`}>
            <Input
              id={`${prefix}-label`}
              value={block.label}
              onChange={(event) => onChange({ ...block, label: event.target.value })}
            />
          </Field>
          <Field
            label={bt('templates.editor.blocks.field.voteField')}
            htmlFor={`${prefix}-vote-field`}
          >
            <Input
              id={`${prefix}-vote-field`}
              className="control mono"
              value={block.vote_field ?? ''}
              onChange={(event) =>
                onChange(withoutBlankOptional(block, 'vote_field', event.target.value))
              }
            />
          </Field>
          <Field
            label={bt('templates.editor.blocks.field.unanimousTotal')}
            htmlFor={`${prefix}-unanimous-total`}
          >
            <Input
              id={`${prefix}-unanimous-total`}
              value={block.unanimous_total ?? ''}
              onChange={(event) =>
                onChange(withoutBlankOptional(block, 'unanimous_total', event.target.value))
              }
            />
          </Field>
        </>
      );

    case 'SignatureBlock':
      return (
        <>
          <Field label={bt('templates.editor.blocks.field.source')} htmlFor={`${prefix}-source`}>
            <Input
              id={`${prefix}-source`}
              className="control mono"
              value={block.source}
              onChange={(event) => onChange({ ...block, source: event.target.value })}
            />
          </Field>
          <Field label={bt('templates.editor.blocks.field.role')} htmlFor={`${prefix}-role`}>
            <Input
              id={`${prefix}-role`}
              value={block.role}
              onChange={(event) => onChange({ ...block, role: event.target.value })}
            />
          </Field>
          <Field label={bt('templates.editor.blocks.field.name')} htmlFor={`${prefix}-name`}>
            <Input
              id={`${prefix}-name`}
              value={block.name}
              onChange={(event) => onChange({ ...block, name: event.target.value })}
            />
          </Field>
        </>
      );

    case 'PageBreak':
    case 'Rule':
    case 'NarrativeBody':
      return <MarkerExplanation kind={block.kind} />;
  }
}

function DocumentBlockInspector({
  block,
  index,
  idPrefix,
  kindOptions,
  onKindChange,
  children,
}: {
  block: TemplateBlockSpec;
  index: number;
  idPrefix: string;
  kindOptions: readonly { value: string; label: string }[];
  onKindChange: (kind: BlockKind) => void;
  children?: ReactNode;
}) {
  const bt = useTemplatesEditorT();
  return (
    <details className="template-document-block__inspector">
      <summary>{bt('templates.editor.blocks.inspector')}</summary>
      <div className="form template-document-block__inspector-fields">
        <Field label={bt('templates.editor.blocks.kind')} htmlFor={`${idPrefix}-${index}-kind`}>
          <Select
            id={`${idPrefix}-${index}-kind`}
            value={block.kind}
            options={kindOptions}
            data-template-block-action="kind"
            onChange={(event) => onKindChange(event.target.value as BlockKind)}
          />
        </Field>
        {children}
      </div>
    </details>
  );
}

/**
 * Document mode keeps prose-like values on the paper and moves implementation details into one
 * compact disclosure. This is still the exact BlockSpec — no preview-only shadow model exists.
 */
function DocumentBlockFields({
  block,
  index,
  idPrefix,
  kindOptions,
  onChange,
  onKindChange,
}: {
  block: TemplateBlockSpec;
  index: number;
  idPrefix: string;
  kindOptions: readonly { value: string; label: string }[];
  onChange: (next: TemplateBlockSpec) => void;
  onKindChange: (kind: BlockKind) => void;
}) {
  const bt = useTemplatesEditorT();
  const prefix = `template-document-block-${index}`;
  const inspector = (children?: ReactNode) => (
    <DocumentBlockInspector
      block={block}
      index={index}
      idPrefix={idPrefix}
      kindOptions={kindOptions}
      onKindChange={onKindChange}
    >
      {children}
    </DocumentBlockInspector>
  );

  switch (block.kind) {
    case 'Heading':
      return (
        <>
          <TextArea
            id={`${prefix}-template`}
            className="template-document-block__direct-text template-document-block__direct-text--heading"
            aria-label={bt('templates.editor.blocks.field.template')}
            rows={2}
            value={block.template}
            onChange={(event) => onChange({ ...block, template: event.target.value })}
          />
          {inspector(
            <Field label={bt('templates.editor.blocks.field.level')} htmlFor={`${prefix}-level`}>
              <Select
                id={`${prefix}-level`}
                value={String(block.level)}
                options={[1, 2, 3, 4, 5, 6].map((level) => ({
                  value: String(level),
                  label: String(level),
                }))}
                onChange={(event) => onChange({ ...block, level: Number(event.target.value) })}
              />
            </Field>,
          )}
        </>
      );

    case 'Paragraph':
      return (
        <>
          <TextArea
            id={`${prefix}-template`}
            className="template-document-block__direct-text"
            aria-label={bt('templates.editor.blocks.field.template')}
            rows={3}
            value={block.template}
            onChange={(event) => onChange({ ...block, template: event.target.value })}
          />
          {inspector(
            <Field label={bt('templates.editor.blocks.field.items')} htmlFor={`${prefix}-items`}>
              <Input
                id={`${prefix}-items`}
                className="control mono"
                value={block.items ?? ''}
                onChange={(event) =>
                  onChange(withoutBlankOptional(block, 'items', event.target.value))
                }
              />
            </Field>,
          )}
        </>
      );

    case 'KeyValue':
      return (
        <>
          <div className="template-document-block__kv-table">
            {block.rows.map((row, rowIndex) => (
              <div
                key={rowIndex}
                className="template-block-editor__kv-row"
                role="group"
                aria-label={`${bt('templates.editor.blocks.field.rows')} ${rowIndex + 1}`}
              >
                <Input
                  aria-label={`${bt('templates.editor.blocks.field.key')} ${rowIndex + 1}`}
                  placeholder={bt('templates.editor.blocks.field.key')}
                  value={row.key}
                  onChange={(event) =>
                    onChange({
                      ...block,
                      rows: block.rows.map((current, currentIndex) =>
                        currentIndex === rowIndex
                          ? { ...current, key: event.target.value }
                          : current,
                      ),
                    })
                  }
                />
                <Input
                  aria-label={`${bt('templates.editor.blocks.field.value')} ${rowIndex + 1}`}
                  placeholder={bt('templates.editor.blocks.field.value')}
                  value={row.value}
                  onChange={(event) =>
                    onChange({
                      ...block,
                      rows: block.rows.map((current, currentIndex) =>
                        currentIndex === rowIndex
                          ? { ...current, value: event.target.value }
                          : current,
                      ),
                    })
                  }
                />
                <Button
                  type="button"
                  variant="ghost"
                  icon={<Icon.Trash />}
                  aria-label={`${bt('templates.editor.blocks.removeRow')} ${rowIndex + 1}`}
                  onClick={() =>
                    onChange({
                      ...block,
                      rows: block.rows.filter((_, currentIndex) => currentIndex !== rowIndex),
                    })
                  }
                />
              </div>
            ))}
            <Button
              type="button"
              variant="ghost"
              icon={<Icon.Plus />}
              onClick={() => onChange({ ...block, rows: [...block.rows, { key: '', value: '' }] })}
            >
              {bt('templates.editor.blocks.addRow')}
            </Button>
          </div>
          {inspector(
            <Field label={bt('templates.editor.blocks.field.items')} htmlFor={`${prefix}-items`}>
              <Input
                id={`${prefix}-items`}
                className="control mono"
                value={block.items ?? ''}
                onChange={(event) =>
                  onChange(withoutBlankOptional(block, 'items', event.target.value))
                }
              />
            </Field>,
          )}
        </>
      );

    case 'VoteTable':
      return (
        <>
          <Field label={bt('templates.editor.blocks.field.label')} htmlFor={`${prefix}-label`}>
            <Input
              id={`${prefix}-label`}
              className="template-document-block__direct-input"
              value={block.label}
              onChange={(event) => onChange({ ...block, label: event.target.value })}
            />
          </Field>
          {inspector(
            <>
              <Field label={bt('templates.editor.blocks.field.items')} htmlFor={`${prefix}-items`}>
                <Input
                  id={`${prefix}-items`}
                  className="control mono"
                  value={block.items}
                  onChange={(event) => onChange({ ...block, items: event.target.value })}
                />
              </Field>
              <Field
                label={bt('templates.editor.blocks.field.voteField')}
                htmlFor={`${prefix}-vote-field`}
              >
                <Input
                  id={`${prefix}-vote-field`}
                  className="control mono"
                  value={block.vote_field ?? ''}
                  onChange={(event) =>
                    onChange(withoutBlankOptional(block, 'vote_field', event.target.value))
                  }
                />
              </Field>
              <Field
                label={bt('templates.editor.blocks.field.unanimousTotal')}
                htmlFor={`${prefix}-unanimous-total`}
              >
                <Input
                  id={`${prefix}-unanimous-total`}
                  value={block.unanimous_total ?? ''}
                  onChange={(event) =>
                    onChange(withoutBlankOptional(block, 'unanimous_total', event.target.value))
                  }
                />
              </Field>
            </>,
          )}
        </>
      );

    case 'SignatureBlock':
      return (
        <>
          <div className="template-document-block__signature-lines">
            <Field label={bt('templates.editor.blocks.field.role')} htmlFor={`${prefix}-role`}>
              <Input
                id={`${prefix}-role`}
                value={block.role}
                onChange={(event) => onChange({ ...block, role: event.target.value })}
              />
            </Field>
            <Field label={bt('templates.editor.blocks.field.name')} htmlFor={`${prefix}-name`}>
              <Input
                id={`${prefix}-name`}
                value={block.name}
                onChange={(event) => onChange({ ...block, name: event.target.value })}
              />
            </Field>
          </div>
          {inspector(
            <Field label={bt('templates.editor.blocks.field.source')} htmlFor={`${prefix}-source`}>
              <Input
                id={`${prefix}-source`}
                className="control mono"
                value={block.source}
                onChange={(event) => onChange({ ...block, source: event.target.value })}
              />
            </Field>,
          )}
        </>
      );

    case 'PageBreak':
    case 'Rule':
    case 'NarrativeBody':
      return (
        <>
          <MarkerExplanation kind={block.kind} />
          {inspector()}
        </>
      );
  }
}

export function TemplateBlocksEditor({
  value,
  onChange,
  idPrefix = 'template-blocks',
  presentation = 'cards',
  renderNarrativeBody,
  disabled = false,
}: {
  value: string;
  onChange: (next: string) => void;
  idPrefix?: string;
  /**
   * `document` keeps every block open in authored order. The legacy `cards` presentation remains
   * useful for focused component tests and any compact embedding outside the full-page editor.
   */
  presentation?: 'cards' | 'document';
  /** Mount the editor once and honest read-only mirrors at later NarrativeBody placements. */
  renderNarrativeBody?: (placement: NarrativeBodyPlacement) => ReactNode;
  /** Lock every mutation while the owning form is saving. */
  disabled?: boolean;
}) {
  const bt = useTemplatesEditorT();
  const [addKind, setAddKind] = useState<BlockKind>('Paragraph');
  const [openBlocks, setOpenBlocks] = useState<Record<number, boolean>>({ 0: true });
  const [pendingKindChange, setPendingKindChange] = useState<PendingKindChange | null>(null);
  const [pendingRemove, setPendingRemove] = useState<number | null>(null);
  const [pendingBlockFocus, setPendingBlockFocus] = useState<PendingBlockFocus | null>(null);
  const editorRef = useRef<HTMLElement>(null);
  const parsed = useMemo(() => parseTemplateBlocksText(value), [value]);
  const blocks = parsed.blocks;
  const blockCount = blocks?.length ?? 0;
  const narrativeBodyIndex = blocks?.findIndex((block) => block.kind === 'NarrativeBody') ?? -1;
  const narrativeBodyIndexes =
    blocks?.flatMap((block, index) => (block.kind === 'NarrativeBody' ? [index] : [])) ?? [];
  const kindOptions = BLOCK_KINDS.map((kind) => ({ value: kind, label: bt(kindCopyKey[kind]) }));

  const write = (next: TemplateBlockSpec[]) => onChange(JSON.stringify(next, null, 2));
  const update = (index: number, block: TemplateBlockSpec) => {
    if (!blocks) return;
    write(blocks.map((current, currentIndex) => (currentIndex === index ? block : current)));
  };
  useLayoutEffect(() => {
    if (!pendingBlockFocus) return;
    if (disabled) {
      setPendingBlockFocus(null);
      return;
    }
    if (value !== pendingBlockFocus.expectedValue) return;

    const movedBlock = editorRef.current?.querySelector<HTMLElement>(
      `[data-template-block-index="${pendingBlockFocus.index}"]`,
    );
    const preferred = movedBlock?.querySelector<HTMLButtonElement>(
      `[data-template-block-action="${pendingBlockFocus.preferredAction}"]:not(:disabled)`,
    );
    const oppositeAction =
      pendingBlockFocus.preferredAction === 'up'
        ? 'down'
        : pendingBlockFocus.preferredAction === 'down'
          ? 'up'
          : null;
    const fallback = oppositeAction
      ? movedBlock?.querySelector<HTMLButtonElement>(
          `[data-template-block-action="${oppositeAction}"]:not(:disabled)`,
        )
      : null;
    const kindSelect = movedBlock?.querySelector<HTMLSelectElement>('select:not(:disabled)');
    (preferred ?? fallback ?? kindSelect)?.focus();
    setPendingBlockFocus(null);
  }, [disabled, pendingBlockFocus, value]);

  const writeWithFocus = (
    next: TemplateBlockSpec[],
    index: number,
    preferredAction: BlockFocusTarget,
  ) => {
    const expectedValue = JSON.stringify(next, null, 2);
    setPendingBlockFocus({ index, preferredAction, expectedValue });
    onChange(expectedValue);
  };
  const swap = (index: number, target: number, preferredAction: BlockFocusTarget) => {
    if (!blocks || target < 0 || target >= blocks.length) return;
    const next = blocks.slice();
    [next[index], next[target]] = [next[target], next[index]];
    if (presentation === 'cards') {
      setOpenBlocks((current) => ({
        ...current,
        [index]: current[target] ?? false,
        [target]: current[index] ?? false,
      }));
    }
    writeWithFocus(next, target, preferredAction);
  };
  const insertAfter = (index: number) => {
    if (!blocks) return;
    const next = blocks.slice();
    // Inline insertion is intentionally predictable: prose is the common connective tissue in a
    // document. The append control below remains the place to choose any specialised block kind.
    next.splice(index + 1, 0, newTemplateBlock('Paragraph'));
    writeWithFocus(next, index + 1, 'insert');
  };
  const duplicate = (index: number) => {
    if (!blocks) return;
    const duplicateBlock = JSON.parse(JSON.stringify(blocks[index])) as TemplateBlockSpec;
    const next = blocks.slice();
    next.splice(index + 1, 0, duplicateBlock);
    writeWithFocus(next, index + 1, 'duplicate');
  };
  const changeKind = (index: number, block: TemplateBlockSpec, toKind: BlockKind) => {
    if (block.kind === toKind) return;
    if (hasDiscardableFields(block)) {
      setPendingKindChange({ index, fromKind: block.kind, toKind });
      return;
    }
    update(index, newTemplateBlock(toKind));
  };

  const renderDocumentBlock = (block: TemplateBlockSpec, index: number) => (
    <div
      key={`${block.kind}:${index}`}
      className={`template-document-block template-document-block--${block.kind.toLowerCase()}`}
      data-template-block-kind={block.kind}
      data-template-block-index={index}
      role="group"
      aria-label={`${bt('templates.editor.blocks.item', { number: index + 1 })}: ${bt(
        kindCopyKey[block.kind],
      )}`}
    >
      <div className="template-document-block__gutter">
        <span className="template-document-block__number" aria-hidden="true">
          {String(index + 1).padStart(2, '0')}
        </span>
        <span className="sr-only">{bt('templates.editor.blocks.item', { number: index + 1 })}</span>
        <strong className="template-document-block__kind">{bt(kindCopyKey[block.kind])}</strong>
        <div className="template-block-editor__actions">
          <Button
            type="button"
            variant="ghost"
            icon={<Icon.Plus />}
            data-template-block-action="insert"
            aria-label={`${bt('templates.editor.blocks.insertAfter')} ${index + 1}`}
            onClick={() => insertAfter(index)}
          />
          <Button
            type="button"
            variant="ghost"
            icon={<Icon.ArrowUp />}
            disabled={index === 0}
            data-template-block-action="up"
            aria-label={`${bt('templates.editor.blocks.moveUp')} ${index + 1}`}
            onClick={() => swap(index, index - 1, 'up')}
          />
          <Button
            type="button"
            variant="ghost"
            icon={<Icon.ArrowDown />}
            disabled={index === blockCount - 1}
            data-template-block-action="down"
            aria-label={`${bt('templates.editor.blocks.moveDown')} ${index + 1}`}
            onClick={() => swap(index, index + 1, 'down')}
          />
          <Button
            type="button"
            variant="ghost"
            icon={<Icon.Copy />}
            data-template-block-action="duplicate"
            aria-label={`${bt('templates.editor.blocks.duplicate')} ${index + 1}`}
            onClick={() => duplicate(index)}
          />
          <Button
            type="button"
            variant="ghost"
            icon={<Icon.Trash />}
            disabled={blockCount === 1}
            aria-label={`${bt('templates.editor.blocks.remove')} ${index + 1}`}
            onClick={() => setPendingRemove(index)}
          />
        </div>
      </div>
      <div className="template-document-block__content">
        {block.kind === 'NarrativeBody' && renderNarrativeBody ? (
          <>
            <DocumentBlockInspector
              block={block}
              index={index}
              idPrefix={idPrefix}
              kindOptions={kindOptions}
              onKindChange={(kind) => changeKind(index, block, kind)}
            />
            {renderNarrativeBody({
              index,
              occurrence: narrativeBodyIndexes.indexOf(index) + 1,
              primary: index === narrativeBodyIndex,
            })}
          </>
        ) : (
          <DocumentBlockFields
            block={block}
            index={index}
            idPrefix={idPrefix}
            kindOptions={kindOptions}
            onChange={(next) => update(index, next)}
            onKindChange={(kind) => changeKind(index, block, kind)}
          />
        )}
      </div>
    </div>
  );

  return (
    <section
      className={`stack--tight template-block-editor ${
        presentation === 'document' ? 'template-block-editor--document' : ''
      }`}
      ref={editorRef}
    >
      <fieldset
        className="template-block-editor__fieldset"
        aria-label={bt('templates.editor.document.controls')}
        disabled={disabled}
      >
        <p className="field__hint">{bt('templates.editor.blocks.intro')}</p>

        {parsed.error ? (
          <InlineWarning tone="error" title={bt('templates.editor.blocks.raw.invalidJson')}>
            <p>{bt(parseErrorCopyKey[parsed.error])}</p>
          </InlineWarning>
        ) : null}

        {blocks ? (
          presentation === 'document' ? (
            <div className="template-document-page-flow" data-template-document-flow>
              {paginateDocumentBlocks(blocks).map((page, pageIndex) => (
                <div
                  key={pageIndex}
                  className="template-document-page"
                  data-template-document-page={pageIndex + 1}
                >
                  {page.map(({ block, index }) => renderDocumentBlock(block, index))}
                  <span className="template-document-page__folio" aria-hidden="true">
                    {pageIndex + 1}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="template-block-editor__list">
              {blocks.map((block, index) => {
                const summary = blockSummary(block);
                return (
                  <details
                    key={`${block.kind}:${index}`}
                    className="template-block-editor__item"
                    data-template-block-index={index}
                    open={openBlocks[index] ?? false}
                    onToggle={(event) => {
                      const open = event.currentTarget.open;
                      setOpenBlocks((current) =>
                        current[index] === open ? current : { ...current, [index]: open },
                      );
                    }}
                  >
                    <summary>
                      <strong>{bt('templates.editor.blocks.item', { number: index + 1 })}</strong>
                      <span>{bt(kindCopyKey[block.kind])}</span>
                      {summary ? <code className="mono">{summary}</code> : null}
                    </summary>
                    <div className="template-block-editor__body">
                      <div className="form field-table">
                        <Field
                          label={bt('templates.editor.blocks.kind')}
                          htmlFor={`${idPrefix}-${index}-kind`}
                        >
                          <Select
                            id={`${idPrefix}-${index}-kind`}
                            value={block.kind}
                            options={kindOptions}
                            onChange={(event) =>
                              changeKind(index, block, event.target.value as BlockKind)
                            }
                          />
                        </Field>
                        <BlockFields
                          block={block}
                          index={index}
                          onChange={(next) => update(index, next)}
                        />
                      </div>
                      <div className="row-wrap template-block-editor__actions">
                        <Button
                          type="button"
                          variant="ghost"
                          icon={<Icon.Plus />}
                          data-template-block-action="insert"
                          aria-label={`${bt('templates.editor.blocks.insertAfter')} ${index + 1}`}
                          onClick={() => insertAfter(index)}
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          icon={<Icon.ArrowUp />}
                          disabled={index === 0}
                          data-template-block-action="up"
                          aria-label={`${bt('templates.editor.blocks.moveUp')} ${index + 1}`}
                          onClick={() => swap(index, index - 1, 'up')}
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          icon={<Icon.ArrowDown />}
                          disabled={index === blocks.length - 1}
                          data-template-block-action="down"
                          aria-label={`${bt('templates.editor.blocks.moveDown')} ${index + 1}`}
                          onClick={() => swap(index, index + 1, 'down')}
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          icon={<Icon.Copy />}
                          data-template-block-action="duplicate"
                          aria-label={`${bt('templates.editor.blocks.duplicate')} ${index + 1}`}
                          onClick={() => duplicate(index)}
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          icon={<Icon.Trash />}
                          disabled={blocks.length === 1}
                          aria-label={`${bt('templates.editor.blocks.remove')} ${index + 1}`}
                          onClick={() => setPendingRemove(index)}
                        />
                      </div>
                    </div>
                  </details>
                );
              })}
            </div>
          )
        ) : null}

        {blocks ? (
          <div className="row-wrap template-block-editor__add">
            <Field label={bt('templates.editor.blocks.addKind')} htmlFor={`${idPrefix}-new-kind`}>
              <Select
                id={`${idPrefix}-new-kind`}
                value={addKind}
                options={kindOptions}
                onChange={(event) => setAddKind(event.target.value as BlockKind)}
              />
            </Field>
            <Button
              type="button"
              variant="secondary"
              icon={<Icon.Plus />}
              onClick={() => write([...blocks, newTemplateBlock(addKind)])}
            >
              {bt('templates.editor.blocks.add')}
            </Button>
          </div>
        ) : null}

        <details className="template-block-editor__raw">
          <summary>{bt('templates.editor.blocks.raw.summary')}</summary>
          <div className="stack--tight">
            <p className="field__hint">{bt('templates.editor.blocks.raw.hint')}</p>
            <TextArea
              id={`${idPrefix}-raw`}
              aria-label={bt('templates.editor.blocks.raw.summary')}
              className="control control--textarea mono"
              rows={16}
              spellCheck={false}
              value={value}
              onChange={(event) => onChange(event.target.value)}
            />
            {parsed.error ? (
              <p className="field__error" role="alert">
                {bt(parseErrorCopyKey[parsed.error])}
              </p>
            ) : null}
          </div>
        </details>
      </fieldset>

      <ConfirmActionModal
        open={!disabled && pendingKindChange !== null}
        onClose={() => setPendingKindChange(null)}
        title={bt('templates.editor.blocks.changeKind.title')}
        intro={
          <p>
            {bt('templates.editor.blocks.changeKind.intro', {
              from: pendingKindChange ? bt(kindCopyKey[pendingKindChange.fromKind]) : '',
              to: pendingKindChange ? bt(kindCopyKey[pendingKindChange.toKind]) : '',
            })}
          </p>
        }
        confirmLabel={bt('templates.editor.blocks.changeKind.confirm')}
        pendingLabel={bt('templates.editor.blocks.changeKind.pending')}
        danger
        onConfirm={async () => {
          if (disabled || !pendingKindChange || !blocks) return;
          const current = blocks[pendingKindChange.index];
          if (!current || current.kind !== pendingKindChange.fromKind) return;
          update(pendingKindChange.index, newTemplateBlock(pendingKindChange.toKind));
        }}
      />
      <ConfirmActionModal
        open={!disabled && pendingRemove !== null}
        onClose={() => setPendingRemove(null)}
        title={bt('templates.editor.blocks.removeConfirm.title')}
        intro={<p>{bt('templates.editor.blocks.removeConfirm.intro')}</p>}
        confirmLabel={bt('templates.editor.blocks.removeConfirm.confirm')}
        pendingLabel={bt('templates.editor.blocks.removeConfirm.pending')}
        danger
        onConfirm={async () => {
          if (disabled || pendingRemove === null || !blocks || blocks.length === 1) return;
          write(blocks.filter((_, currentIndex) => currentIndex !== pendingRemove));
        }}
      />
    </section>
  );
}
