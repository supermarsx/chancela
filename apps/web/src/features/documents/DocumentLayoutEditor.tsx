import type {
  DocumentFontFamily,
  DocumentFurnitureAlignment,
  DocumentLayoutOverrides,
  DocumentLayoutPolicy,
  DocumentOrientation,
  DocumentPageSize,
  DocumentSideTextEdge,
} from '../../api/types';
import { PRODUCT_DOCUMENT_FURNITURE } from '../../api/types';
import { useT, type MessageKey, type TFunction } from '../../i18n';
import { Button, ColumnHead, Field, InlineWarning, Input, Select, Table, Toggle } from '../../ui';
import {
  FURNITURE_PLACEHOLDERS,
  MAX_FURNITURE_TEXT_CHARS,
  parseFurnitureTemplate,
  previewFurnitureTemplate,
  type FurniturePlaceholder,
  type FurnitureTemplateError,
} from './furnitureTemplate';
import './documentLayoutEditor.css';

type LayoutSection = 'page' | 'typography' | 'regions' | 'furniture';
type LayoutValue = string | number | boolean;
type LayoutPath = readonly string[];

interface LayoutLeaf {
  key: string;
  section: LayoutSection;
  label: MessageKey;
  /** Path into the concrete {@link DocumentLayoutPolicy}. */
  path: LayoutPath;
  /**
   * Path into a {@link DocumentLayoutOverrides} layer, when it differs from `path`.
   *
   * It differs for every furniture leaf and nowhere else: the concrete policy nests
   * (`furniture.header.enabled`) and the override layer is flat (`furniture.header_enabled`),
   * because the server's provenance map keys one entry per authored leaf. Reading an override
   * with `path` silently finds nothing, which would make a stored furniture override invisible in
   * the pane while the server kept applying it — so every override read and write goes through
   * {@link overridePathOf}, never `leaf.path`.
   */
  overridePath?: LayoutPath;
  kind: 'select' | 'number' | 'toggle' | 'text';
  options?: { value: string; label: MessageKey }[];
  min?: number;
  max?: number;
  unit?: string;
  /** Furniture templates only: the control offers the token reference and the sample echo. */
  furnitureText?: boolean;
}

/** Where this leaf lives in an override layer. See {@link LayoutLeaf.overridePath}. */
function overridePathOf(leaf: LayoutLeaf): LayoutPath {
  return leaf.overridePath ?? leaf.path;
}

const PAGE_SIZE_OPTIONS: { value: DocumentPageSize; label: MessageKey }[] = [
  { value: 'A4', label: 'documentLayout.option.pageSize.A4' },
  { value: 'A5', label: 'documentLayout.option.pageSize.A5' },
  { value: 'Letter', label: 'documentLayout.option.pageSize.Letter' },
  { value: 'Legal', label: 'documentLayout.option.pageSize.Legal' },
];

const ORIENTATION_OPTIONS: { value: DocumentOrientation; label: MessageKey }[] = [
  { value: 'Portrait', label: 'documentLayout.option.orientation.Portrait' },
  { value: 'Landscape', label: 'documentLayout.option.orientation.Landscape' },
];

const FONT_OPTIONS: { value: DocumentFontFamily; label: MessageKey }[] = [
  { value: 'NotoSerif', label: 'documentLayout.option.font.NotoSerif' },
  { value: 'NotoSans', label: 'documentLayout.option.font.NotoSans' },
];

const ALIGNMENT_OPTIONS: { value: DocumentFurnitureAlignment; label: MessageKey }[] = [
  { value: 'Left', label: 'documentLayout.option.alignment.Left' },
  { value: 'Center', label: 'documentLayout.option.alignment.Center' },
  { value: 'Right', label: 'documentLayout.option.alignment.Right' },
];

const EDGE_OPTIONS: { value: DocumentSideTextEdge; label: MessageKey }[] = [
  { value: 'Left', label: 'documentLayout.option.edge.Left' },
  { value: 'Right', label: 'documentLayout.option.edge.Right' },
];

/** What each token stands for, for the reference table under the furniture controls. */
const PLACEHOLDER_MEANING: Record<FurniturePlaceholder, MessageKey> = {
  page: 'documentLayout.furniture.token.page',
  page_count: 'documentLayout.furniture.token.pageCount',
  page_capacity: 'documentLayout.furniture.token.pageCapacity',
  entity_name: 'documentLayout.furniture.token.entityName',
  entity_nipc: 'documentLayout.furniture.token.entityNipc',
  title: 'documentLayout.furniture.token.title',
  subject: 'documentLayout.furniture.token.subject',
  date: 'documentLayout.furniture.token.date',
};

const LEAVES: LayoutLeaf[] = [
  {
    key: 'page-size',
    section: 'page',
    label: 'documentLayout.field.pageSize',
    path: ['page', 'size'],
    kind: 'select',
    options: PAGE_SIZE_OPTIONS,
  },
  {
    key: 'page-orientation',
    section: 'page',
    label: 'documentLayout.field.orientation',
    path: ['page', 'orientation'],
    kind: 'select',
    options: ORIENTATION_OPTIONS,
  },
  {
    key: 'margin-top',
    section: 'page',
    label: 'documentLayout.field.marginTop',
    path: ['page', 'margins_mm', 'top'],
    kind: 'number',
    min: 5,
    max: 60,
    unit: 'mm',
  },
  {
    key: 'margin-right',
    section: 'page',
    label: 'documentLayout.field.marginRight',
    path: ['page', 'margins_mm', 'right'],
    kind: 'number',
    min: 5,
    max: 60,
    unit: 'mm',
  },
  {
    key: 'margin-bottom',
    section: 'page',
    label: 'documentLayout.field.marginBottom',
    path: ['page', 'margins_mm', 'bottom'],
    kind: 'number',
    min: 5,
    max: 60,
    unit: 'mm',
  },
  {
    key: 'margin-left',
    section: 'page',
    label: 'documentLayout.field.marginLeft',
    path: ['page', 'margins_mm', 'left'],
    kind: 'number',
    min: 5,
    max: 60,
    unit: 'mm',
  },
  {
    key: 'body-font',
    section: 'typography',
    label: 'documentLayout.field.bodyFont',
    path: ['typography', 'body_font_family'],
    kind: 'select',
    options: FONT_OPTIONS,
  },
  {
    key: 'body-size',
    section: 'typography',
    label: 'documentLayout.field.bodySize',
    path: ['typography', 'body_font_size_pt'],
    kind: 'number',
    min: 8,
    max: 18,
    unit: 'pt',
  },
  {
    key: 'header-font',
    section: 'typography',
    label: 'documentLayout.field.headerFont',
    path: ['typography', 'header_font_family'],
    kind: 'select',
    options: FONT_OPTIONS,
  },
  {
    key: 'header-size',
    section: 'typography',
    label: 'documentLayout.field.headerSize',
    path: ['typography', 'header_font_size_pt'],
    kind: 'number',
    min: 8,
    max: 24,
    unit: 'pt',
  },
  {
    key: 'footer-font',
    section: 'typography',
    label: 'documentLayout.field.footerFont',
    path: ['typography', 'footer_font_family'],
    kind: 'select',
    options: FONT_OPTIONS,
  },
  {
    key: 'footer-size',
    section: 'typography',
    label: 'documentLayout.field.footerSize',
    path: ['typography', 'footer_font_size_pt'],
    kind: 'number',
    min: 7,
    max: 16,
    unit: 'pt',
  },
  {
    key: 'line-spacing',
    section: 'typography',
    label: 'documentLayout.field.lineSpacing',
    path: ['typography', 'line_spacing_percent'],
    kind: 'number',
    min: 100,
    max: 200,
    unit: '%',
  },
  {
    key: 'paragraph-spacing',
    section: 'typography',
    label: 'documentLayout.field.paragraphSpacing',
    path: ['typography', 'paragraph_spacing_pt'],
    kind: 'number',
    min: 0,
    max: 24,
    unit: 'pt',
  },
  {
    key: 'heading-scale',
    section: 'typography',
    label: 'documentLayout.field.headingScale',
    path: ['typography', 'heading_scale_percent'],
    kind: 'number',
    min: 75,
    max: 200,
    unit: '%',
  },
  {
    key: 'header-gap',
    section: 'regions',
    label: 'documentLayout.field.headerGap',
    path: ['regions', 'header_gap_mm'],
    kind: 'number',
    min: 0,
    max: 30,
    unit: 'mm',
  },
  {
    key: 'footer-gap',
    section: 'regions',
    label: 'documentLayout.field.footerGap',
    path: ['regions', 'footer_gap_mm'],
    kind: 'number',
    min: 0,
    max: 30,
    unit: 'mm',
  },
  {
    key: 'furniture-header-enabled',
    section: 'furniture',
    label: 'documentLayout.field.furnitureHeaderEnabled',
    path: ['furniture', 'header', 'enabled'],
    overridePath: ['furniture', 'header_enabled'],
    kind: 'toggle',
  },
  {
    key: 'furniture-header-text',
    section: 'furniture',
    label: 'documentLayout.field.furnitureHeaderText',
    path: ['furniture', 'header', 'text'],
    overridePath: ['furniture', 'header_text'],
    kind: 'text',
    furnitureText: true,
  },
  {
    key: 'furniture-header-alignment',
    section: 'furniture',
    label: 'documentLayout.field.furnitureHeaderAlignment',
    path: ['furniture', 'header', 'alignment'],
    overridePath: ['furniture', 'header_alignment'],
    kind: 'select',
    options: ALIGNMENT_OPTIONS,
  },
  {
    key: 'furniture-header-rule',
    section: 'furniture',
    label: 'documentLayout.field.furnitureHeaderRule',
    path: ['furniture', 'header', 'rule'],
    overridePath: ['furniture', 'header_rule'],
    kind: 'toggle',
  },
  {
    key: 'furniture-footer-enabled',
    section: 'furniture',
    label: 'documentLayout.field.furnitureFooterEnabled',
    path: ['furniture', 'footer', 'enabled'],
    overridePath: ['furniture', 'footer_enabled'],
    kind: 'toggle',
  },
  {
    key: 'furniture-footer-text',
    section: 'furniture',
    label: 'documentLayout.field.furnitureFooterText',
    path: ['furniture', 'footer', 'text'],
    overridePath: ['furniture', 'footer_text'],
    kind: 'text',
    furnitureText: true,
  },
  {
    key: 'furniture-footer-alignment',
    section: 'furniture',
    label: 'documentLayout.field.furnitureFooterAlignment',
    path: ['furniture', 'footer', 'alignment'],
    overridePath: ['furniture', 'footer_alignment'],
    kind: 'select',
    options: ALIGNMENT_OPTIONS,
  },
  {
    key: 'furniture-footer-rule',
    section: 'furniture',
    label: 'documentLayout.field.furnitureFooterRule',
    path: ['furniture', 'footer', 'rule'],
    overridePath: ['furniture', 'footer_rule'],
    kind: 'toggle',
  },
  {
    key: 'furniture-side-text-enabled',
    section: 'furniture',
    label: 'documentLayout.field.furnitureSideTextEnabled',
    path: ['furniture', 'side_text', 'enabled'],
    overridePath: ['furniture', 'side_text_enabled'],
    kind: 'toggle',
  },
  {
    key: 'furniture-side-text',
    section: 'furniture',
    label: 'documentLayout.field.furnitureSideText',
    path: ['furniture', 'side_text', 'text'],
    overridePath: ['furniture', 'side_text'],
    kind: 'text',
    furnitureText: true,
  },
  {
    key: 'furniture-side-text-edge',
    section: 'furniture',
    label: 'documentLayout.field.furnitureSideTextEdge',
    path: ['furniture', 'side_text', 'edge'],
    overridePath: ['furniture', 'side_text_edge'],
    kind: 'select',
    options: EDGE_OPTIONS,
  },
];

const SECTIONS = ['page', 'typography', 'regions', 'furniture'] as const;

const SECTION_COPY: Record<LayoutSection, { title: MessageKey; description: MessageKey }> = {
  page: {
    title: 'documentLayout.section.page.title',
    description: 'documentLayout.section.page.description',
  },
  typography: {
    title: 'documentLayout.section.typography.title',
    description: 'documentLayout.section.typography.description',
  },
  regions: {
    title: 'documentLayout.section.regions.title',
    description: 'documentLayout.section.regions.description',
  },
  furniture: {
    title: 'documentLayout.section.furniture.title',
    description: 'documentLayout.section.furniture.description',
  },
};

function valueAt(value: unknown, path: LayoutPath): LayoutValue | undefined {
  let current: unknown = value;
  for (const key of path) {
    if (!current || typeof current !== 'object') return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return typeof current === 'string' || typeof current === 'number' || typeof current === 'boolean'
    ? current
    : undefined;
}

/**
 * Fill in the concrete furniture default when the wire omitted it.
 *
 * The server drops `furniture` from a policy that is still all-disabled, so an untouched
 * instance, entity or book arrives here without the key. Without this the furniture leaves would
 * read `undefined` and the pane would render nothing at all for them — the feature would look
 * absent rather than off.
 */
export function withFurnitureDefaults(policy: DocumentLayoutPolicy): DocumentLayoutPolicy {
  if (policy.furniture) return policy;
  return { ...policy, furniture: structuredClone(PRODUCT_DOCUMENT_FURNITURE) };
}

/**
 * Resolve a concrete layout for display without materialising inherited values into the
 * persisted override. The server remains authoritative for the full
 * instance → template → entity → book cascade; this helper composes the levels currently
 * visible to a detail page.
 */
export function applyDocumentLayoutOverrides(
  inherited: DocumentLayoutPolicy,
  overrides: DocumentLayoutOverrides | null | undefined,
): DocumentLayoutPolicy {
  let resolved = withFurnitureDefaults(
    JSON.parse(JSON.stringify(inherited)) as DocumentLayoutPolicy,
  );
  if (!overrides) return resolved;
  for (const leaf of LEAVES) {
    // Read flat, write nested: an override layer and a concrete policy do not share a shape.
    const override = valueAt(overrides, overridePathOf(leaf));
    if (override !== undefined) resolved = updateAt(resolved, leaf.path, override);
  }
  return resolved;
}

function updateAt<T extends object>(value: T, path: LayoutPath, nextValue: LayoutValue): T {
  const next = JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
  let current = next;
  for (const key of path.slice(0, -1)) {
    const child = current[key];
    if (!child || typeof child !== 'object' || Array.isArray(child)) current[key] = {};
    current = current[key] as Record<string, unknown>;
  }
  current[path[path.length - 1] ?? ''] = nextValue;
  return next as T;
}

function removeAt(
  value: DocumentLayoutOverrides | null | undefined,
  path: LayoutPath,
): DocumentLayoutOverrides | undefined {
  if (!value) return undefined;
  const next = JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
  const parents: Record<string, unknown>[] = [next];
  let current = next;
  for (const key of path.slice(0, -1)) {
    const child = current[key];
    if (!child || typeof child !== 'object' || Array.isArray(child)) return value;
    current = child as Record<string, unknown>;
    parents.push(current);
  }
  delete current[path[path.length - 1] ?? ''];
  for (let index = parents.length - 1; index > 0; index -= 1) {
    if (Object.keys(parents[index] ?? {}).length > 0) break;
    const parent = parents[index - 1];
    const key = path[index - 1];
    if (parent && key) delete parent[key];
  }
  return Object.keys(next).length > 0 ? (next as DocumentLayoutOverrides) : undefined;
}

function hasOverrides(value: DocumentLayoutOverrides | null | undefined): boolean {
  return !!value && Object.keys(value).length > 0;
}

function numberValue(raw: string, leaf: LayoutLeaf): number {
  const parsed = Number.parseInt(raw, 10);
  const fallback = leaf.min ?? 0;
  return Math.min(leaf.max ?? Number.MAX_SAFE_INTEGER, Math.max(fallback, parsed || fallback));
}

function formatValue(value: LayoutValue, leaf: LayoutLeaf, t: TFunction): string {
  if (typeof value === 'boolean') {
    return t(value ? 'documentLayout.value.on' : 'documentLayout.value.off');
  }
  const option = leaf.options?.find((item) => item.value === value);
  if (option) return t(option.label);
  if (leaf.kind === 'text' && String(value).trim() === '') return t('documentLayout.value.empty');
  return `${value}${leaf.unit ? ` ${leaf.unit}` : ''}`;
}

/** The translated reason a furniture template is not authorable, or `undefined` when it is. */
function furnitureTextError(value: LayoutValue, t: TFunction): string | undefined {
  const parsed = parseFurnitureTemplate(String(value));
  if (parsed.ok) return undefined;
  return furnitureErrorMessage(parsed.error, t);
}

function furnitureErrorMessage(error: FurnitureTemplateError, t: TFunction): string {
  switch (error.code) {
    case 'too_long':
      return t('documentLayout.furniture.error.tooLong', {
        maximum: error.maximum,
        actual: error.actual,
      });
    case 'line_break':
      return t('documentLayout.furniture.error.lineBreak');
    case 'unclosed_placeholder':
      return t('documentLayout.furniture.error.unclosed');
    case 'unknown_placeholder':
      return t('documentLayout.furniture.error.unknownToken', { token: error.name });
  }
}

/**
 * What a furniture template will print, resolved against the sample document.
 *
 * Kept beside the input rather than behind a preview button: the whole risk of a merge-tag field
 * is writing one that reads correctly and prints something else, and this is the cheapest place
 * to answer that. It is a text echo, not a rendering — the real page is the template PDF preview.
 *
 * Silent while the template is unauthorable: the surrounding `Field` already renders that as its
 * error, and two elements saying the same thing would be read out twice.
 */
function FurnitureTextEcho({ leafKey, value }: { leafKey: string; value: string }) {
  const t = useT();
  if (furnitureTextError(value, t)) return null;
  const trimmed = value.trim();
  const resolved = trimmed === '' ? null : previewFurnitureTemplate(value);
  return (
    <p className="document-layout-editor__furniture-echo" data-furniture-echo={leafKey}>
      <span className="document-layout-editor__furniture-echo-label">
        {t(
          trimmed === ''
            ? 'documentLayout.furniture.echo.empty'
            : 'documentLayout.furniture.echo.label',
        )}
      </span>{' '}
      {resolved === null ? null : (
        <span className="document-layout-editor__furniture-echo-value">{resolved}</span>
      )}
    </p>
  );
}

/**
 * The closed token vocabulary, spelled out.
 *
 * An operator should not have to read the crate to find out that `{{ page_capacity }}` exists and
 * `{{ pagina }}` does not. The server rejects an unknown token rather than printing nothing for
 * it, so the complete list IS the contract — there is no wider syntax to discover.
 */
function FurnitureTokenReference() {
  const t = useT();
  return (
    <Table
      className="document-layout-editor__tokens"
      caption={t('documentLayout.furniture.tokens.caption')}
      head={
        <tr>
          <ColumnHead
            label={t('documentLayout.furniture.tokens.column.token')}
            help={t('documentLayout.furniture.tokens.column.tokenHelp')}
          />
          <ColumnHead
            label={t('documentLayout.furniture.tokens.column.meaning')}
            help={t('documentLayout.furniture.tokens.column.meaningHelp')}
          />
        </tr>
      }
    >
      {FURNITURE_PLACEHOLDERS.map((placeholder) => (
        <tr key={placeholder}>
          <td>
            <code>{`{{ ${placeholder} }}`}</code>
          </td>
          <td>{t(PLACEHOLDER_MEANING[placeholder])}</td>
        </tr>
      ))}
    </Table>
  );
}

function LeafControl({
  leaf,
  value,
  id,
  disabled,
  onChange,
}: {
  leaf: LayoutLeaf;
  value: LayoutValue;
  id: string;
  disabled?: boolean;
  onChange: (value: LayoutValue) => void;
}) {
  const t = useT();
  if (leaf.kind === 'select') {
    return (
      <Select
        id={id}
        value={String(value)}
        disabled={disabled}
        options={(leaf.options ?? []).map((option) => ({
          value: option.value,
          label: t(option.label),
        }))}
        onChange={(event) => onChange(event.target.value)}
      />
    );
  }
  if (leaf.kind === 'toggle') {
    return (
      <Toggle
        id={id}
        checked={value === true}
        disabled={disabled}
        label={t(value === true ? 'documentLayout.value.on' : 'documentLayout.value.off')}
        onChange={(checked) => onChange(checked)}
      />
    );
  }
  if (leaf.kind === 'text') {
    return (
      <div className="document-layout-editor__furniture-text">
        <Input
          id={id}
          type="text"
          value={String(value)}
          disabled={disabled}
          // The server counts Unicode scalar values; the attribute counts UTF-16 code units, so it
          // is a courtesy stop only. `parseFurnitureTemplate` is what actually holds the bound.
          maxLength={MAX_FURNITURE_TEXT_CHARS}
          onChange={(event) => onChange(event.target.value)}
        />
        {leaf.furnitureText ? <FurnitureTextEcho leafKey={leaf.key} value={String(value)} /> : null}
      </div>
    );
  }
  return (
    <div className="document-layout-editor__number">
      <Input
        id={id}
        type="number"
        min={leaf.min}
        max={leaf.max}
        value={Number(value)}
        disabled={disabled}
        onChange={(event) => onChange(numberValue(event.target.value, leaf))}
      />
      {leaf.unit ? <span aria-hidden="true">{leaf.unit}</span> : null}
    </div>
  );
}

function LayoutSectionPanel({
  section,
  children,
}: {
  section: LayoutSection;
  children: React.ReactNode;
}) {
  const t = useT();
  const copy = SECTION_COPY[section];
  return (
    <section className="stack--tight document-layout-editor__section">
      <header className="stack--tight">
        <h4>{t(copy.title)}</h4>
        <p className="field__hint">{t(copy.description)}</p>
      </header>
      {section === 'furniture' ? (
        <InlineWarning tone="info" title={t('documentLayout.furniture.notice.title')}>
          <p>{t('documentLayout.furniture.notice.forward')}</p>
          <p>{t('documentLayout.furniture.notice.pinned')}</p>
        </InlineWarning>
      ) : null}
      {children}
      {section === 'furniture' ? (
        <>
          <p className="field__hint">{t('documentLayout.furniture.tokens.intro')}</p>
          <FurnitureTokenReference />
          <p className="field__hint">{t('documentLayout.furniture.tokens.absentFact')}</p>
          <p className="field__hint">{t('documentLayout.furniture.preview.pointer')}</p>
        </>
      ) : null}
    </section>
  );
}

export function DocumentLayoutDefaultsEditor({
  value,
  onChange,
  onRequestReset,
  disabled = false,
  idPrefix = 'document-layout-defaults',
}: {
  value: DocumentLayoutPolicy;
  onChange: (value: DocumentLayoutPolicy) => void;
  onRequestReset?: () => void;
  disabled?: boolean;
  idPrefix?: string;
}) {
  const t = useT();
  // A policy whose furniture the wire omitted is a policy with furniture OFF, not one without the
  // controls. Hydrating here also means the first edit emits a complete, concrete object upward.
  const policy = withFurnitureDefaults(value);
  return (
    <div className="stack document-layout-editor" data-document-layout-mode="defaults">
      {SECTIONS.map((section) => (
        <LayoutSectionPanel key={section} section={section}>
          <div className="form settings-rows">
            {LEAVES.filter((leaf) => leaf.section === section).map((leaf) => {
              const current = valueAt(policy, leaf.path);
              if (current === undefined) return null;
              const id = `${idPrefix}-${leaf.key}`;
              return (
                <Field
                  key={leaf.key}
                  label={t(leaf.label)}
                  htmlFor={id}
                  error={leaf.furnitureText ? furnitureTextError(current, t) : undefined}
                >
                  <LeafControl
                    leaf={leaf}
                    value={current}
                    id={id}
                    disabled={disabled}
                    onChange={(next) => onChange(updateAt(policy, leaf.path, next))}
                  />
                </Field>
              );
            })}
          </div>
        </LayoutSectionPanel>
      ))}
      {onRequestReset ? (
        <div className="document-layout-editor__actions">
          <Button type="button" variant="ghost" disabled={disabled} onClick={onRequestReset}>
            {t('documentLayout.action.resetProduct')}
          </Button>
        </div>
      ) : null}
    </div>
  );
}

export function DocumentLayoutOverridesEditor({
  value,
  inherited,
  inheritanceLabel,
  inheritedValueLabel,
  onChange,
  disabled = false,
  idPrefix = 'document-layout-override',
}: {
  value?: DocumentLayoutOverrides | null;
  inherited: DocumentLayoutPolicy;
  inheritanceLabel: string;
  inheritedValueLabel?: string;
  onChange: (value: DocumentLayoutOverrides | undefined) => void;
  disabled?: boolean;
  idPrefix?: string;
}) {
  const t = useT();
  const baseline = withFurnitureDefaults(inherited);
  return (
    <div className="stack document-layout-editor" data-document-layout-mode="inherit">
      <div className="document-layout-editor__inheritance">
        <span>{t('documentLayout.mode.default')}</span>
        <strong>{t('documentLayout.mode.inherit')}</strong>
        <span>{inheritanceLabel}</span>
      </div>

      {SECTIONS.map((section) => (
        <LayoutSectionPanel key={section} section={section}>
          <div className="form field-table">
            {LEAVES.filter((leaf) => leaf.section === section).map((leaf) => {
              const inheritedValue = valueAt(baseline, leaf.path);
              if (inheritedValue === undefined) return null;
              const overridePath = overridePathOf(leaf);
              const overrideValue = valueAt(value, overridePath);
              const isOverride = overrideValue !== undefined;
              const id = `${idPrefix}-${leaf.key}`;
              const modeId = `${id}-mode`;
              return (
                <Field
                  key={leaf.key}
                  label={t(leaf.label)}
                  htmlFor={isOverride ? id : modeId}
                  error={
                    isOverride && leaf.furnitureText
                      ? furnitureTextError(overrideValue, t)
                      : undefined
                  }
                  hint={
                    isOverride
                      ? t('documentLayout.hint.override', { source: inheritanceLabel })
                      : t('documentLayout.hint.inherited', {
                          label:
                            inheritedValueLabel ??
                            t('documentLayout.value.inherited', { source: inheritanceLabel }),
                          value: formatValue(inheritedValue, leaf, t),
                        })
                  }
                >
                  <div className="document-layout-editor__override-control">
                    <Select
                      id={modeId}
                      aria-label={t('documentLayout.mode.aria', { label: t(leaf.label) })}
                      value={isOverride ? 'override' : 'inherit'}
                      disabled={disabled}
                      options={[
                        { value: 'inherit', label: t('documentLayout.mode.inherit') },
                        { value: 'override', label: t('documentLayout.mode.override') },
                      ]}
                      onChange={(event) => {
                        if (event.target.value === 'inherit') {
                          onChange(removeAt(value, overridePath));
                        } else {
                          onChange(
                            updateAt(
                              value ?? {},
                              overridePath,
                              inheritedValue,
                            ) as DocumentLayoutOverrides,
                          );
                        }
                      }}
                    />
                    {isOverride ? (
                      <LeafControl
                        leaf={leaf}
                        value={overrideValue}
                        id={id}
                        disabled={disabled}
                        onChange={(next) =>
                          onChange(
                            updateAt(value ?? {}, overridePath, next) as DocumentLayoutOverrides,
                          )
                        }
                      />
                    ) : (
                      <output className="document-layout-editor__effective" htmlFor={modeId}>
                        {formatValue(inheritedValue, leaf, t)}
                      </output>
                    )}
                  </div>
                </Field>
              );
            })}
          </div>
        </LayoutSectionPanel>
      ))}

      <div className="document-layout-editor__actions">
        <Button
          type="button"
          variant="ghost"
          disabled={disabled || !hasOverrides(value)}
          onClick={() => onChange(undefined)}
        >
          {t('documentLayout.action.resetInherited')}
        </Button>
      </div>
    </div>
  );
}
