import type {
  DocumentFontFamily,
  DocumentLayoutOverrides,
  DocumentLayoutPolicy,
  DocumentOrientation,
  DocumentPageSize,
} from '../../api/types';
import { useT, type MessageKey, type TFunction } from '../../i18n';
import { Button, Field, Input, Select } from '../../ui';
import './documentLayoutEditor.css';

type LayoutSection = 'page' | 'typography' | 'regions';
type LayoutValue = string | number;
type LayoutPath = readonly string[];

interface LayoutLeaf {
  key: string;
  section: LayoutSection;
  label: MessageKey;
  path: LayoutPath;
  kind: 'select' | 'number';
  options?: { value: string; label: MessageKey }[];
  min?: number;
  max?: number;
  unit?: string;
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
];

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
};

function valueAt(value: unknown, path: LayoutPath): LayoutValue | undefined {
  let current: unknown = value;
  for (const key of path) {
    if (!current || typeof current !== 'object') return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return typeof current === 'string' || typeof current === 'number' ? current : undefined;
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
  let resolved = JSON.parse(JSON.stringify(inherited)) as DocumentLayoutPolicy;
  if (!overrides) return resolved;
  for (const leaf of LEAVES) {
    const override = valueAt(overrides, leaf.path);
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
  const option = leaf.options?.find((item) => item.value === value);
  if (option) return t(option.label);
  return `${value}${leaf.unit ? ` ${leaf.unit}` : ''}`;
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
      {children}
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
  return (
    <div className="stack document-layout-editor" data-document-layout-mode="defaults">
      {(['page', 'typography', 'regions'] as const).map((section) => (
        <LayoutSectionPanel key={section} section={section}>
          <div className="form settings-rows">
            {LEAVES.filter((leaf) => leaf.section === section).map((leaf) => {
              const current = valueAt(value, leaf.path);
              if (current === undefined) return null;
              const id = `${idPrefix}-${leaf.key}`;
              return (
                <Field key={leaf.key} label={t(leaf.label)} htmlFor={id}>
                  <LeafControl
                    leaf={leaf}
                    value={current}
                    id={id}
                    disabled={disabled}
                    onChange={(next) => onChange(updateAt(value, leaf.path, next))}
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
  return (
    <div className="stack document-layout-editor" data-document-layout-mode="inherit">
      <div className="document-layout-editor__inheritance">
        <span>{t('documentLayout.mode.default')}</span>
        <strong>{t('documentLayout.mode.inherit')}</strong>
        <span>{inheritanceLabel}</span>
      </div>

      {(['page', 'typography', 'regions'] as const).map((section) => (
        <LayoutSectionPanel key={section} section={section}>
          <div className="form field-table">
            {LEAVES.filter((leaf) => leaf.section === section).map((leaf) => {
              const inheritedValue = valueAt(inherited, leaf.path);
              if (inheritedValue === undefined) return null;
              const overrideValue = valueAt(value, leaf.path);
              const isOverride = overrideValue !== undefined;
              const id = `${idPrefix}-${leaf.key}`;
              const modeId = `${id}-mode`;
              return (
                <Field
                  key={leaf.key}
                  label={t(leaf.label)}
                  htmlFor={isOverride ? id : modeId}
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
                          onChange(removeAt(value, leaf.path));
                        } else {
                          onChange(
                            updateAt(
                              value ?? {},
                              leaf.path,
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
                            updateAt(value ?? {}, leaf.path, next) as DocumentLayoutOverrides,
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
