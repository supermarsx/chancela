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
import {
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
  type TextareaHTMLAttributes,
} from 'react';
import { createPortal } from 'react-dom';
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
  IconButton,
  InlineWarning,
  Input,
  Select,
  TextArea,
} from '../../ui';
import { useFocusTrap } from '../../ui/useFocusTrap';
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

function AutoGrowDocumentTextArea({
  className,
  onInput,
  ...props
}: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const ref = useRef<HTMLTextAreaElement>(null);
  const resize = () => {
    const element = ref.current;
    if (!element) return;
    element.style.height = 'auto';
    if (element.scrollHeight > 0) element.style.height = `${element.scrollHeight}px`;
  };

  useLayoutEffect(() => {
    const element = ref.current;
    if (!element) return;
    element.style.height = 'auto';
    if (element.scrollHeight > 0) element.style.height = `${element.scrollHeight}px`;
  }, [props.value]);

  return (
    <textarea
      {...props}
      ref={ref}
      className={`control control--textarea ${className ?? ''}`.trim()}
      onInput={(event) => {
        resize();
        onInput?.(event);
      }}
    />
  );
}

/**
 * Document mode keeps only document-like values on the full-width writing surface. Implementation
 * details and the complete friendly field set live in the explicit right-side inspector below.
 * This is still the exact BlockSpec — no preview-only shadow model exists.
 */
function DocumentBlockFields({
  block,
  index,
  onChange,
}: {
  block: TemplateBlockSpec;
  index: number;
  onChange: (next: TemplateBlockSpec) => void;
}) {
  const bt = useTemplatesEditorT();
  const prefix = `template-document-block-${index}`;

  switch (block.kind) {
    case 'Heading':
      return (
        <AutoGrowDocumentTextArea
          id={`${prefix}-template`}
          className="template-document-block__direct-text template-document-block__direct-text--heading"
          aria-label={bt('templates.editor.blocks.field.template')}
          rows={2}
          value={block.template}
          onChange={(event) => onChange({ ...block, template: event.target.value })}
        />
      );

    case 'Paragraph':
      return (
        <AutoGrowDocumentTextArea
          id={`${prefix}-template`}
          className="template-document-block__direct-text"
          aria-label={bt('templates.editor.blocks.field.template')}
          rows={3}
          value={block.template}
          onChange={(event) => onChange({ ...block, template: event.target.value })}
        />
      );

    case 'KeyValue':
      return (
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
                      currentIndex === rowIndex ? { ...current, key: event.target.value } : current,
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
              <IconButton
                icon={<Icon.Trash />}
                label={`${bt('templates.editor.blocks.removeRow')} ${rowIndex + 1}`}
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
      );

    case 'VoteTable':
      return (
        <Input
          id={`${prefix}-label`}
          className="template-document-block__direct-input"
          aria-label={bt('templates.editor.blocks.field.label')}
          value={block.label}
          onChange={(event) => onChange({ ...block, label: event.target.value })}
        />
      );

    case 'SignatureBlock':
      return (
        <div className="template-document-block__signature-lines">
          <Input
            id={`${prefix}-role`}
            aria-label={bt('templates.editor.blocks.field.role')}
            placeholder={bt('templates.editor.blocks.field.role')}
            value={block.role}
            onChange={(event) => onChange({ ...block, role: event.target.value })}
          />
          <Input
            id={`${prefix}-name`}
            aria-label={bt('templates.editor.blocks.field.name')}
            placeholder={bt('templates.editor.blocks.field.name')}
            value={block.name}
            onChange={(event) => onChange({ ...block, name: event.target.value })}
          />
        </div>
      );

    case 'PageBreak':
    case 'Rule':
      return (
        <div className="template-document-block__marker" aria-hidden="true">
          <span>{bt(kindCopyKey[block.kind])}</span>
        </div>
      );

    case 'NarrativeBody':
      return <MarkerExplanation kind={block.kind} />;
  }
}

function BlockAddMenu({
  disabled,
  mainLabel,
  mainAriaLabel,
  menuAriaLabel,
  onAdd,
}: {
  disabled: boolean;
  mainLabel: string;
  mainAriaLabel: string;
  menuAriaLabel: string;
  onAdd: (kind: BlockKind) => void;
}) {
  const bt = useTemplatesEditorT();
  const menuId = useId();
  const rootRef = useRef<HTMLDivElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);

  const focusTrigger = () => {
    window.setTimeout(() => {
      rootRef.current?.querySelector<HTMLButtonElement>('[aria-haspopup="menu"]')?.focus();
    }, 0);
  };
  const close = (restoreFocus = false) => {
    setOpen(false);
    if (restoreFocus) focusTrigger();
  };

  useLayoutEffect(() => {
    if (!open) return;
    menuRef.current?.querySelector<HTMLButtonElement>('[role="menuitem"]')?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    return () => document.removeEventListener('pointerdown', onPointerDown);
  }, [open]);

  useEffect(() => {
    if (disabled) setOpen(false);
  }, [disabled]);

  const moveMenuFocus = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    const items = Array.from(
      event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="menuitem"]'),
    );
    if (items.length === 0) return;
    const current = items.indexOf(document.activeElement as HTMLButtonElement);
    let next: number;
    if (event.key === 'ArrowDown') next = (current + 1 + items.length) % items.length;
    else if (event.key === 'ArrowUp') next = (current - 1 + items.length) % items.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = items.length - 1;
    else if (event.key === 'Escape') {
      event.preventDefault();
      close(true);
      return;
    } else if (event.key === 'Tab') {
      close();
      return;
    } else {
      return;
    }
    event.preventDefault();
    items[next]?.focus();
  };

  return (
    <div className="template-block-add" ref={rootRef}>
      <Button
        type="button"
        variant="secondary"
        className="template-block-add__main"
        icon={<Icon.Plus />}
        disabled={disabled}
        data-template-block-action="insert"
        aria-label={mainAriaLabel}
        onClick={() => {
          close();
          onAdd('Paragraph');
        }}
      >
        {mainLabel}
      </Button>
      <IconButton
        icon={<Icon.ArrowDown />}
        label={menuAriaLabel}
        variant="secondary"
        className="template-block-add__trigger"
        disabled={disabled}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => setOpen((current) => !current)}
        onKeyDown={(event) => {
          if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault();
            setOpen(true);
          } else if (event.key === 'Escape' && open) {
            event.preventDefault();
            close(true);
          }
        }}
      />
      {open ? (
        <div
          className="template-block-add__menu"
          id={menuId}
          ref={menuRef}
          role="menu"
          aria-label={menuAriaLabel}
          onKeyDown={moveMenuFocus}
        >
          {BLOCK_KINDS.map((kind) => (
            <button
              type="button"
              role="menuitem"
              className="template-block-add__menu-item"
              key={kind}
              onClick={() => {
                onAdd(kind);
                close();
              }}
            >
              {bt(kindCopyKey[kind])}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function BlockInspectorDrawer({
  block,
  index,
  idPrefix,
  kindOptions,
  disabled,
  onChange,
  onKindChange,
  onClose,
}: {
  block: TemplateBlockSpec | null;
  index: number | null;
  idPrefix: string;
  kindOptions: readonly { value: string; label: string }[];
  disabled: boolean;
  onChange: (next: TemplateBlockSpec) => void;
  onKindChange: (kind: BlockKind) => void;
  onClose: () => void;
}) {
  const bt = useTemplatesEditorT();
  const titleId = useId();
  const open = block !== null && index !== null;
  const trapRef = useFocusTrap<HTMLDivElement>(open);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onClose();
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [onClose, open]);

  if (!open || !block || index === null) return null;

  const closeLabel = bt('templates.editor.blocks.inspector.close');
  const blockLabel = bt('templates.editor.blocks.item', { number: index + 1 });
  return createPortal(
    <div
      className="modal-backdrop template-block-inspector__backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        className="template-block-inspector"
        ref={trapRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <header className="template-block-inspector__head">
          <div>
            <p className="card__label">{blockLabel}</p>
            <h2 id={titleId}>
              {bt('templates.editor.blocks.inspector')} · {bt(kindCopyKey[block.kind])}
            </h2>
          </div>
          <IconButton icon={<Icon.Close />} label={closeLabel} onClick={onClose} />
        </header>
        <div className="template-block-inspector__body">
          <fieldset className="template-block-inspector__fieldset" disabled={disabled}>
            <div className="form field-table">
              <Field
                label={bt('templates.editor.blocks.kind')}
                htmlFor={`${idPrefix}-inspector-${index}-kind`}
              >
                <Select
                  id={`${idPrefix}-inspector-${index}-kind`}
                  value={block.kind}
                  options={kindOptions}
                  onChange={(event) => onKindChange(event.target.value as BlockKind)}
                />
              </Field>
              <BlockFields block={block} index={index} onChange={onChange} />
            </div>
          </fieldset>
        </div>
        <footer className="template-block-inspector__foot">
          <Button type="button" variant="secondary" icon={<Icon.Close />} onClick={onClose}>
            {closeLabel}
          </Button>
        </footer>
      </div>
    </div>,
    document.body,
  );
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
  const [openBlocks, setOpenBlocks] = useState<Record<number, boolean>>({ 0: true });
  const [pendingKindChange, setPendingKindChange] = useState<PendingKindChange | null>(null);
  const [pendingRemove, setPendingRemove] = useState<number | null>(null);
  const [pendingBlockFocus, setPendingBlockFocus] = useState<PendingBlockFocus | null>(null);
  const [inspectorIndex, setInspectorIndex] = useState<number | null>(null);
  const editorRef = useRef<HTMLElement>(null);
  const parsed = useMemo(() => parseTemplateBlocksText(value), [value]);
  const blocks = parsed.blocks;
  const blockCount = blocks?.length ?? 0;
  const narrativeBodyIndex = blocks?.findIndex((block) => block.kind === 'NarrativeBody') ?? -1;
  const narrativeBodyIndexes =
    blocks?.flatMap((block, index) => (block.kind === 'NarrativeBody' ? [index] : [])) ?? [];
  const kindOptions = BLOCK_KINDS.map((kind) => ({ value: kind, label: bt(kindCopyKey[kind]) }));
  const inspectedBlock =
    inspectorIndex === null || !blocks ? null : (blocks[inspectorIndex] ?? null);

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
    const fallbackControl = movedBlock?.querySelector<HTMLElement>(
      '[data-template-block-action="configure"]:not(:disabled), select:not(:disabled), textarea:not(:disabled), input:not(:disabled)',
    );
    (preferred ?? fallback ?? fallbackControl)?.focus();
    setPendingBlockFocus(null);
  }, [disabled, pendingBlockFocus, value]);

  useEffect(() => {
    if (disabled || (inspectorIndex !== null && !inspectedBlock)) setInspectorIndex(null);
  }, [disabled, inspectedBlock, inspectorIndex]);

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
  const insertAfter = (index: number, kind: BlockKind) => {
    if (!blocks) return;
    const next = blocks.slice();
    next.splice(index + 1, 0, newTemplateBlock(kind));
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
          <IconButton
            icon={<Icon.Sliders />}
            label={`${bt('templates.editor.blocks.configure')} ${index + 1}`}
            data-template-block-action="configure"
            onClick={() => setInspectorIndex(index)}
          />
          <IconButton
            icon={<Icon.ArrowUp />}
            label={`${bt('templates.editor.blocks.moveUp')} ${index + 1}`}
            disabled={index === 0}
            data-template-block-action="up"
            onClick={() => swap(index, index - 1, 'up')}
          />
          <IconButton
            icon={<Icon.ArrowDown />}
            label={`${bt('templates.editor.blocks.moveDown')} ${index + 1}`}
            disabled={index === blockCount - 1}
            data-template-block-action="down"
            onClick={() => swap(index, index + 1, 'down')}
          />
          <IconButton
            icon={<Icon.Copy />}
            label={`${bt('templates.editor.blocks.duplicate')} ${index + 1}`}
            data-template-block-action="duplicate"
            onClick={() => duplicate(index)}
          />
          <IconButton
            icon={<Icon.Trash />}
            label={`${bt('templates.editor.blocks.remove')} ${index + 1}`}
            disabled={blockCount === 1}
            onClick={() => setPendingRemove(index)}
          />
          <BlockAddMenu
            disabled={disabled}
            mainLabel={bt('templates.editor.blocks.add')}
            mainAriaLabel={`${bt('templates.editor.blocks.insertAfter')} ${index + 1}`}
            menuAriaLabel={`${bt('templates.editor.blocks.addMenu')} ${index + 1}`}
            onAdd={(kind) => insertAfter(index, kind)}
          />
        </div>
      </div>
      <div className="template-document-block__content">
        {block.kind === 'NarrativeBody' && renderNarrativeBody ? (
          renderNarrativeBody({
            index,
            occurrence: narrativeBodyIndexes.indexOf(index) + 1,
            primary: index === narrativeBodyIndex,
          })
        ) : (
          <DocumentBlockFields
            block={block}
            index={index}
            onChange={(next) => update(index, next)}
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
              <div className="template-document-surface" data-template-document-surface>
                {blocks.map(renderDocumentBlock)}
              </div>
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
                        <BlockAddMenu
                          disabled={disabled}
                          mainLabel={bt('templates.editor.blocks.add')}
                          mainAriaLabel={`${bt('templates.editor.blocks.insertAfter')} ${index + 1}`}
                          menuAriaLabel={`${bt('templates.editor.blocks.addMenu')} ${index + 1}`}
                          onAdd={(kind) => insertAfter(index, kind)}
                        />
                        <IconButton
                          icon={<Icon.ArrowUp />}
                          label={`${bt('templates.editor.blocks.moveUp')} ${index + 1}`}
                          disabled={index === 0}
                          data-template-block-action="up"
                          onClick={() => swap(index, index - 1, 'up')}
                        />
                        <IconButton
                          icon={<Icon.ArrowDown />}
                          label={`${bt('templates.editor.blocks.moveDown')} ${index + 1}`}
                          disabled={index === blocks.length - 1}
                          data-template-block-action="down"
                          onClick={() => swap(index, index + 1, 'down')}
                        />
                        <IconButton
                          icon={<Icon.Copy />}
                          label={`${bt('templates.editor.blocks.duplicate')} ${index + 1}`}
                          data-template-block-action="duplicate"
                          onClick={() => duplicate(index)}
                        />
                        <IconButton
                          icon={<Icon.Trash />}
                          label={`${bt('templates.editor.blocks.remove')} ${index + 1}`}
                          disabled={blocks.length === 1}
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
          <div className="template-block-editor__add">
            <BlockAddMenu
              disabled={disabled}
              mainLabel={bt('templates.editor.blocks.add')}
              mainAriaLabel={bt('templates.editor.blocks.add')}
              menuAriaLabel={bt('templates.editor.blocks.addMenu')}
              onAdd={(kind) => insertAfter(blocks.length - 1, kind)}
            />
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

      <BlockInspectorDrawer
        block={inspectedBlock}
        index={inspectorIndex}
        idPrefix={idPrefix}
        kindOptions={kindOptions}
        disabled={disabled}
        onChange={(next) => {
          if (inspectorIndex !== null) update(inspectorIndex, next);
        }}
        onKindChange={(kind) => {
          if (inspectorIndex === null || !inspectedBlock) return;
          const index = inspectorIndex;
          setInspectorIndex(null);
          changeKind(index, inspectedBlock, kind);
        }}
        onClose={() => setInspectorIndex(null)}
      />

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
