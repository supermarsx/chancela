import { useState, type ReactNode } from 'react';
import {
  ATTENDEE_ONLY_CAPACITIES,
  PRESENCE_MODES,
  SIGNATORY_CAPACITIES,
  TEMPLATE_PREVIEW_FAMILY_PROFILE_KEYS,
  type SignatoryCapacity,
  type TemplatePreviewAttendee,
  type TemplatePreviewFamilyProfile,
  type TemplatePreviewFamilyProfileKey,
  type TemplatePreviewSampleSettings,
  type TemplatePreviewSignatory,
  type TemplatePreviewStatement,
} from '../../api/types';
import {
  attendeeQualityLabels,
  optionsFrom,
  presenceModeLabels,
  signatoryCapacityLabels,
} from '../../api/labels';
import {
  type TemplatePreviewSamplesCopyKey,
  useTemplatePreviewSamplesT,
} from '../../i18n/templatePreviewSamplesFallback';
import { Card, Field, Icon, IconButton, Input, Select, Table, TextArea } from '../../ui';
import {
  isTemplatePreviewDocumentNumber,
  isTemplatePreviewPermilage,
  isTemplatePreviewProse,
  isTemplatePreviewShortText,
  TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX,
  TEMPLATE_PREVIEW_STATEMENTS_MAX,
} from './templatePreviewSamplesModel';
import { TemplatePreviewSampleEditModal } from './TemplatePreviewSampleEditModal';

export const ALL_TEMPLATE_PREVIEW_CAPACITIES = [
  ...SIGNATORY_CAPACITIES,
  ...ATTENDEE_ONLY_CAPACITIES,
] as const;

export function optionalTemplatePreviewText(value: string | null): string {
  return value ?? '';
}

export function nullableTemplatePreviewText(value: string): string | null {
  return value.trim() ? value : null;
}

export function TextSetting({
  id,
  label,
  value,
  onChange,
  disabled,
  maxLength = 240,
  type = 'text',
  hint,
  multiline = false,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  maxLength?: number;
  type?: 'text' | 'date' | 'time';
  hint?: string;
  multiline?: boolean;
}) {
  return (
    <Field label={label} htmlFor={id} hint={hint}>
      {multiline ? (
        <TextArea
          id={id}
          value={value}
          maxLength={maxLength}
          rows={4}
          disabled={disabled}
          onChange={(event) => onChange(event.target.value)}
        />
      ) : (
        <Input
          id={id}
          type={type}
          value={value}
          maxLength={type === 'text' ? maxLength : undefined}
          disabled={disabled}
          onChange={(event) => onChange(event.target.value)}
        />
      )}
    </Field>
  );
}

export function NumberSetting({
  id,
  label,
  value,
  onChange,
  disabled,
  min,
  max,
}: {
  id: string;
  label: string;
  value: number;
  onChange: (value: number) => void;
  disabled?: boolean;
  min: number;
  max: number;
}) {
  return (
    <Field label={label} htmlFor={id}>
      <Input
        id={id}
        type="number"
        step={1}
        min={min}
        max={max}
        value={value}
        disabled={disabled}
        onChange={(event) => {
          const parsed = Number(event.target.value);
          if (Number.isFinite(parsed)) onChange(Math.min(max, Math.max(min, Math.trunc(parsed))));
        }}
      />
    </Field>
  );
}

export function SelectSetting<T extends string>({
  id,
  label,
  value,
  options,
  onChange,
  disabled,
}: {
  id: string;
  label: string;
  value: T;
  options: readonly { value: string; label: string }[];
  onChange: (value: T) => void;
  disabled?: boolean;
}) {
  return (
    <Field label={label} htmlFor={id}>
      <Select
        id={id}
        value={value}
        options={options}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value as T)}
      />
    </Field>
  );
}

interface CollectionColumn<Row> {
  label: string;
  render: (row: Row) => ReactNode;
}

interface SampleCollectionTableProps<Row> {
  title: string;
  rows: Row[];
  columns: CollectionColumn<Row>[];
  createRow: () => Row;
  validateRow: (row: Row) => boolean;
  renderEditor: (row: Row, setRow: (row: Row) => void) => ReactNode;
  onChange: (rows: Row[]) => void;
  disabled: boolean;
  maxRows?: number;
  nested?: boolean;
}

/** One repeatable-row implementation for every preview collection, including nested statements. */
export function SampleCollectionTable<Row>({
  title,
  rows,
  columns,
  createRow,
  validateRow,
  renderEditor,
  onChange,
  disabled,
  maxRows = TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX,
  nested = false,
}: SampleCollectionTableProps<Row>) {
  const tt = useTemplatePreviewSamplesT();
  const [editing, setEditing] = useState<{ index: number | null; row: Row } | null>(null);
  const add = (
    <IconButton
      type="button"
      icon={<Icon.Plus />}
      label={tt('templatePreview.action.add', { collection: title })}
      disabled={disabled || rows.length >= maxRows}
      onClick={() => setEditing({ index: null, row: createRow() })}
    />
  );

  const move = (index: number, delta: -1 | 1) => {
    const target = index + delta;
    if (target < 0 || target >= rows.length) return;
    const next = [...rows];
    [next[index], next[target]] = [next[target], next[index]];
    onChange(next);
  };
  const content = (
    <>
      {nested ? (
        <div className="template-preview-nested-head">
          <h3>{title}</h3>
          {add}
        </div>
      ) : null}
      {rows.length === 0 ? (
        <p className="muted">{tt('templatePreview.empty')}</p>
      ) : (
        <Table
          caption={title}
          className="template-preview-sample-table"
          head={
            <tr>
              {columns.map((column) => (
                <th key={column.label} scope="col">
                  {column.label}
                </th>
              ))}
              <th scope="col">{tt('templatePreview.column.actions')}</th>
            </tr>
          }
        >
          {rows.map((row, index) => (
            <tr key={index}>
              {columns.map((column) => (
                <td key={column.label} data-label={column.label}>
                  {column.render(row)}
                </td>
              ))}
              <td
                className="template-preview-sample-table__actions"
                data-label={tt('templatePreview.column.actions')}
              >
                <span className="template-preview-sample-actions">
                  <IconButton
                    icon={<Icon.ArrowUp />}
                    label={tt('templatePreview.action.moveUp', { position: index + 1 })}
                    disabled={disabled || index === 0}
                    onClick={() => move(index, -1)}
                  />
                  <IconButton
                    icon={<Icon.ArrowDown />}
                    label={tt('templatePreview.action.moveDown', { position: index + 1 })}
                    disabled={disabled || index === rows.length - 1}
                    onClick={() => move(index, 1)}
                  />
                  <IconButton
                    icon={<Icon.Pencil />}
                    label={tt('templatePreview.action.edit', {
                      position: index + 1,
                      collection: title,
                    })}
                    disabled={disabled}
                    onClick={() => setEditing({ index, row: structuredClone(row) })}
                  />
                  <IconButton
                    icon={<Icon.Trash />}
                    label={tt('templatePreview.action.remove', {
                      position: index + 1,
                      collection: title,
                    })}
                    disabled={disabled}
                    onClick={() => onChange(rows.filter((_, candidate) => candidate !== index))}
                  />
                </span>
              </td>
            </tr>
          ))}
        </Table>
      )}
      <TemplatePreviewSampleEditModal
        open={editing !== null}
        title={
          editing?.index === null
            ? tt('templatePreview.modal.add', { collection: title })
            : tt('templatePreview.modal.edit', { collection: title })
        }
        onClose={() => setEditing(null)}
        valid={editing ? validateRow(editing.row) : false}
        onSave={() => {
          if (!editing) return;
          onChange(
            editing.index === null
              ? [...rows, editing.row]
              : rows.map((row, index) => (index === editing.index ? editing.row : row)),
          );
          setEditing(null);
        }}
      >
        {editing ? renderEditor(editing.row, (row) => setEditing({ ...editing, row })) : null}
      </TemplatePreviewSampleEditModal>
    </>
  );

  return nested ? (
    <div className="stack--tight template-preview-sample-collection">{content}</div>
  ) : (
    <Card title={title} className="template-preview-sample-collection" actions={add}>
      {content}
    </Card>
  );
}

export function FamilyProfilesTable({
  value,
  disabled,
  onChange,
}: {
  value: TemplatePreviewSampleSettings['family_profiles'];
  disabled: boolean;
  onChange: (value: TemplatePreviewSampleSettings['family_profiles']) => void;
}) {
  const tt = useTemplatePreviewSamplesT();
  const [editing, setEditing] = useState<{
    key: TemplatePreviewFamilyProfileKey;
    row: TemplatePreviewFamilyProfile;
  } | null>(null);
  return (
    <Card title={tt('templatePreview.card.familyProfiles')}>
      <Table
        caption={tt('templatePreview.card.familyProfiles')}
        className="template-preview-sample-table"
        head={
          <tr>
            <th scope="col">{tt('templatePreview.column.family')}</th>
            <th scope="col">{tt('templatePreview.column.name')}</th>
            <th scope="col">{tt('templatePreview.field.legal_form')}</th>
            <th scope="col">{tt('templatePreview.column.actions')}</th>
          </tr>
        }
      >
        {TEMPLATE_PREVIEW_FAMILY_PROFILE_KEYS.map((key) => (
          <tr key={key}>
            <th scope="row">
              {tt(`templatePreview.family.${key}` as TemplatePreviewSamplesCopyKey)}
            </th>
            <td data-label={tt('templatePreview.column.name')}>{value[key].name}</td>
            <td data-label={tt('templatePreview.field.legal_form')}>{value[key].legal_form}</td>
            <td
              className="template-preview-sample-table__actions"
              data-label={tt('templatePreview.column.actions')}
            >
              <IconButton
                icon={<Icon.Pencil />}
                label={tt('templatePreview.action.edit', {
                  position: 1,
                  collection: tt(`templatePreview.family.${key}` as TemplatePreviewSamplesCopyKey),
                })}
                disabled={disabled}
                onClick={() => setEditing({ key, row: { ...value[key] } })}
              />
            </td>
          </tr>
        ))}
      </Table>
      <TemplatePreviewSampleEditModal
        open={editing !== null}
        valid={
          !!editing &&
          isTemplatePreviewShortText(editing.row.name) &&
          isTemplatePreviewShortText(editing.row.legal_form)
        }
        title={
          editing
            ? tt('templatePreview.modal.edit', {
                collection: tt(
                  `templatePreview.family.${editing.key}` as TemplatePreviewSamplesCopyKey,
                ),
              })
            : ''
        }
        onClose={() => setEditing(null)}
        onSave={() => {
          if (!editing) return;
          onChange({ ...value, [editing.key]: editing.row });
          setEditing(null);
        }}
      >
        {editing ? (
          <>
            <TextSetting
              id="template-preview-family-name"
              label={tt('templatePreview.column.name')}
              value={editing.row.name}
              onChange={(name) => setEditing({ ...editing, row: { ...editing.row, name } })}
            />
            <TextSetting
              id="template-preview-family-legal-form"
              label={tt('templatePreview.field.legal_form')}
              value={editing.row.legal_form}
              onChange={(legal_form) =>
                setEditing({ ...editing, row: { ...editing.row, legal_form } })
              }
            />
          </>
        ) : null}
      </TemplatePreviewSampleEditModal>
    </Card>
  );
}

export function StatementsEditor({
  value,
  onChange,
}: {
  value: TemplatePreviewStatement[];
  onChange: (value: TemplatePreviewStatement[]) => void;
}) {
  const tt = useTemplatePreviewSamplesT();
  return (
    <SampleCollectionTable<TemplatePreviewStatement>
      nested
      title={tt('templatePreview.collection.statements')}
      rows={value}
      columns={[
        { label: tt('templatePreview.field.member'), render: (row) => row.member },
        { label: tt('templatePreview.field.text'), render: (row) => row.text },
      ]}
      createRow={() => ({ agenda_number: 1, member: '', text: '' })}
      validateRow={isTemplatePreviewStatementRow}
      renderEditor={(row, setRow) => (
        <>
          <NumberSetting
            id="template-preview-statement-agenda-number"
            label={tt('templatePreview.field.agenda_number')}
            value={row.agenda_number}
            min={1}
            max={999_999}
            onChange={(agenda_number) => setRow({ ...row, agenda_number })}
          />
          <TextSetting
            id="template-preview-statement-member"
            label={tt('templatePreview.field.member')}
            value={row.member}
            onChange={(member) => setRow({ ...row, member })}
          />
          <TextSetting
            id="template-preview-statement-text"
            label={tt('templatePreview.field.text')}
            value={row.text}
            maxLength={2_000}
            multiline
            onChange={(text) => setRow({ ...row, text })}
          />
        </>
      )}
      disabled={false}
      maxRows={TEMPLATE_PREVIEW_STATEMENTS_MAX}
      onChange={onChange}
    />
  );
}

export function isTemplatePreviewStatementRow(row: TemplatePreviewStatement): boolean {
  return (
    isTemplatePreviewDocumentNumber(row.agenda_number) &&
    isTemplatePreviewShortText(row.member) &&
    isTemplatePreviewProse(row.text)
  );
}

export function isTemplatePreviewAttendeeRow(row: TemplatePreviewAttendee): boolean {
  return (
    isTemplatePreviewShortText(row.name) &&
    isTemplatePreviewShortText(row.quality_note) &&
    (row.weight.capital === null || isTemplatePreviewShortText(row.weight.capital)) &&
    (row.weight.permilage === null || isTemplatePreviewPermilage(row.weight.permilage)) &&
    (row.represented_by === null || isTemplatePreviewShortText(row.represented_by))
  );
}

export function isTemplatePreviewSignatoryRow(row: TemplatePreviewSignatory): boolean {
  return isTemplatePreviewShortText(row.role) && isTemplatePreviewShortText(row.name);
}

export function AttendeeEditor({
  row,
  setRow,
}: {
  row: TemplatePreviewAttendee;
  setRow: (row: TemplatePreviewAttendee) => void;
}) {
  const tt = useTemplatePreviewSamplesT();
  return (
    <>
      <TextSetting
        id="template-preview-attendee-name"
        label={tt('templatePreview.column.name')}
        value={row.name}
        onChange={(name) => setRow({ ...row, name })}
      />
      <SelectSetting
        id="template-preview-attendee-quality"
        label={tt('templatePreview.field.quality')}
        value={row.quality}
        options={optionsFrom(ALL_TEMPLATE_PREVIEW_CAPACITIES, attendeeQualityLabels)}
        onChange={(quality) => setRow({ ...row, quality })}
      />
      <TextSetting
        id="template-preview-attendee-quality-note"
        label={tt('templatePreview.field.quality_note')}
        value={row.quality_note}
        onChange={(quality_note) => setRow({ ...row, quality_note })}
      />
      <TextSetting
        id="template-preview-attendee-capital"
        label={tt('templatePreview.field.capital_weight')}
        value={optionalTemplatePreviewText(row.weight.capital)}
        onChange={(capital) =>
          setRow({
            ...row,
            weight: { ...row.weight, capital: nullableTemplatePreviewText(capital) },
          })
        }
      />
      <Field
        label={tt('templatePreview.field.permilage')}
        htmlFor="template-preview-attendee-permilage"
      >
        <Input
          id="template-preview-attendee-permilage"
          type="number"
          min={0}
          max={1_000}
          value={row.weight.permilage ?? ''}
          onChange={(event) => {
            const parsed = event.target.value.trim() ? Number(event.target.value) : null;
            setRow({
              ...row,
              weight: {
                ...row.weight,
                permilage:
                  parsed === null || !Number.isFinite(parsed)
                    ? null
                    : Math.min(1_000, Math.max(0, Math.trunc(parsed))),
              },
            });
          }}
        />
      </Field>
      <SelectSetting
        id="template-preview-attendee-presence"
        label={tt('templatePreview.field.presence')}
        value={row.presence}
        options={optionsFrom(PRESENCE_MODES, presenceModeLabels)}
        onChange={(presence) => setRow({ ...row, presence })}
      />
      <TextSetting
        id="template-preview-attendee-represented-by"
        label={tt('templatePreview.field.represented_by')}
        value={optionalTemplatePreviewText(row.represented_by)}
        onChange={(represented_by) =>
          setRow({ ...row, represented_by: nullableTemplatePreviewText(represented_by) })
        }
      />
    </>
  );
}

export function SignatoryEditor({
  row,
  setRow,
}: {
  row: TemplatePreviewSignatory;
  setRow: (row: TemplatePreviewSignatory) => void;
}) {
  const tt = useTemplatePreviewSamplesT();
  return (
    <>
      <SelectSetting<SignatoryCapacity>
        id="template-preview-signatory-capacity"
        label={tt('templatePreview.field.capacity')}
        value={row.capacity}
        options={optionsFrom(ALL_TEMPLATE_PREVIEW_CAPACITIES, signatoryCapacityLabels)}
        onChange={(capacity) => setRow({ ...row, capacity })}
      />
      <TextSetting
        id="template-preview-signatory-role"
        label={tt('templatePreview.field.role')}
        value={row.role}
        onChange={(role) => setRow({ ...row, role })}
      />
      <TextSetting
        id="template-preview-signatory-name"
        label={tt('templatePreview.column.name')}
        value={row.name}
        onChange={(name) => setRow({ ...row, name })}
      />
    </>
  );
}
