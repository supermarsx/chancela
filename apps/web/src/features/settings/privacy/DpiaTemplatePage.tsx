/**
 * The DPIA guidance MODEL editor — `/settings/privacy/dpia-template/edit`.
 *
 * ## What this edits, and what it does not
 *
 * Two different objects share the word "DPIA" in this area and must not be conflated:
 *
 *  - A DPIA **record** is one assessment an operator fills in. It has its own register, its own
 *    pages (`/settings/privacy/dpias/…`) and its own create/patch routes. Nothing here touches it.
 *  - The DPIA **model** — this page — is the guidance document those assessments follow: its
 *    sections, its prompts, its checklist. It is a singleton, so there is no id and no `…/new`.
 *
 * Editing the model changes what THIS installation asks a reviewer to consider. It files nothing,
 * sends nothing and validates nothing, and no copy on this page may suggest otherwise.
 *
 * ## 🔒 The no-claims boundary
 *
 * The 28 `no_claims` flags are not on this page and there is no field for them, deliberately. Each
 * names a legal claim the product does not make; they are emitted from a compile-time constant in
 * `chancela-api`, the stored override has no field to hold one, and `PUT /v1/privacy/dpia-template`
 * refuses (422) a payload that tries to set one. `PutDpiaTemplateBody` correspondingly has no
 * `no_claims` member, so this client could not send one even by accident.
 *
 * ## Seeding, and why the seed is what the operator can SEE
 *
 * The shipped model's wire copy is English; the guidance panel renders it through the catalog, so a
 * Portuguese reader sees Portuguese. Seeding this form from the raw wire would therefore hand that
 * reader an English form to edit — the copy they were reading would vanish the moment they clicked
 * Edit. So a SHIPPED seed is resolved through `dpiaTemplateLabels.ts` first, exactly as the panel
 * resolves it, and the operator starts from the text on their screen.
 *
 * An OPERATOR body is seeded verbatim: it has no catalog keys, it is user content, and it is shown
 * as typed to every reader in every language. {@link dpiaTemplateUsesCatalog} is the single place
 * that distinction is made; the page and the panel both route through it.
 */
import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  usePrivacyDpiaTemplate,
  usePutPrivacyDpiaTemplate,
  useResetPrivacyDpiaTemplate,
} from '../../../api/hooks';
import type {
  DpiaTemplateFieldType,
  DpiaTemplateSection,
  DpiaTemplateView,
  PutDpiaTemplateBody,
} from '../../../api/types';
import { formatTimestamp } from '../../../format';
import { useActiveLocale, useT, type TFunction } from '../../../i18n';
import {
  dpiaChecklistLabelKey,
  dpiaOperatorActionKey,
  dpiaSectionDescKey,
  dpiaSectionPromptKey,
  dpiaSectionTitleKey,
  dpiaTemplateUsesCatalog,
} from '../../../i18n/dpiaTemplateLabels';
import { useDpiaTemplateEditorT } from '../../../i18n/dpiaTemplateEditorFallback';
import {
  Badge,
  Button,
  Card,
  Field,
  Icon,
  InlineWarning,
  Input,
  Select,
  TextArea,
  useToast,
} from '../../../ui';
import { useCan } from '../../session/permissions';
import { PrivacyFormActions } from './forms/PrivacyFormActions';
import { PrivacyRecordPageShell, type PrivacyRecordPageState } from './PrivacyRecordPageShell';
import { privacyListPath } from './privacyRoutes';
import { usePrivacyRecordDraft } from './usePrivacyRecordDraft';

/**
 * The six `field_type` wire identifiers.
 *
 * Kept verbatim in the `<select>`, in `mono`, and never translated — they are the backend's own
 * names, the same boundary the guidance panel draws for them. Authoring six Portuguese renderings
 * of a wire enum would invent copy this surface must not invent.
 */
const FIELD_TYPES: readonly DpiaTemplateFieldType[] = [
  'text',
  'textarea',
  'checklist',
  'date',
  'evidence_reference',
  'review_note',
];

interface ChecklistFormState {
  id: string;
  label: string;
  fieldType: DpiaTemplateFieldType;
  required: boolean;
}

interface SectionFormState {
  id: string;
  title: string;
  description: string;
  /** One prompt per line. Never comma-split: a prompt is a sentence and may contain commas. */
  prompts: string;
  checklist: ChecklistFormState[];
}

interface TemplateFormState {
  title: string;
  language: string;
  sections: SectionFormState[];
  /** One action per line, for the same reason as `prompts`. */
  operatorActions: string;
}

function splitLines(value: string): string[] {
  return value
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

/**
 * Build the form seed from the served template.
 *
 * `t` is applied only when {@link dpiaTemplateUsesCatalog} says the body is the shipped one; an
 * unmapped id falls back to the wire text, which is the same visible degradation the panel accepts.
 */
function seedFromTemplate(
  template: DpiaTemplateView,
  t: TFunction,
  activeLocale: string,
): TemplateFormState {
  const translate = dpiaTemplateUsesCatalog(template.source);
  return {
    title: template.title,
    // A shipped body is `language: "en"`, but the operator is about to author in their own
    // language, so the field starts on the locale they are reading in. An operator body already
    // states what it was written in and keeps it.
    language: translate ? activeLocale : template.language,
    sections: template.sections.map((section) => ({
      id: section.id,
      title: sectionTitleText(section, t, translate),
      description: sectionDescriptionText(section, t, translate),
      prompts: section.prompts
        .map((prompt, index) => {
          const key = translate ? dpiaSectionPromptKey(section.id, index) : undefined;
          return key ? t(key) : prompt;
        })
        .join('\n'),
      checklist: section.checklist.map((item) => {
        const key = translate ? dpiaChecklistLabelKey(item.id) : undefined;
        return {
          id: item.id,
          label: key ? t(key) : item.label,
          fieldType: item.field_type,
          required: item.required,
        };
      }),
    })),
    operatorActions: template.operator_actions
      .map((action, index) => {
        const key = translate ? dpiaOperatorActionKey(index) : undefined;
        return key ? t(key) : action;
      })
      .join('\n'),
  };
}

function sectionTitleText(section: DpiaTemplateSection, t: TFunction, translate: boolean): string {
  const key = translate ? dpiaSectionTitleKey(section.id) : undefined;
  return key ? t(key) : section.title;
}

function sectionDescriptionText(
  section: DpiaTemplateSection,
  t: TFunction,
  translate: boolean,
): string {
  const key = translate ? dpiaSectionDescKey(section.id) : undefined;
  return key ? t(key) : section.description;
}

function bodyFromForm(form: TemplateFormState): PutDpiaTemplateBody {
  return {
    title: form.title.trim(),
    language: form.language.trim(),
    sections: form.sections.map((section) => ({
      id: section.id.trim(),
      title: section.title.trim(),
      description: section.description.trim(),
      prompts: splitLines(section.prompts),
      checklist: section.checklist.map((item) => ({
        id: item.id.trim(),
        label: item.label.trim(),
        field_type: item.fieldType,
        required: item.required,
      })),
    })),
    operator_actions: splitLines(form.operatorActions),
  };
}

/** Every id must be present, well-formed and unique within its scope — the server's rule, mirrored. */
const ID_PATTERN = /^[A-Za-z0-9_\-.]+$/u;

function formIsSubmittable(form: TemplateFormState): boolean {
  if (form.title.trim().length === 0 || form.language.trim().length === 0) return false;
  if (form.sections.length === 0) return false;
  const sectionIds = new Set<string>();
  for (const section of form.sections) {
    const id = section.id.trim();
    if (!ID_PATTERN.test(id) || sectionIds.has(id)) return false;
    sectionIds.add(id);
    if (section.title.trim().length === 0) return false;
    const itemIds = new Set<string>();
    for (const item of section.checklist) {
      const itemId = item.id.trim();
      if (!ID_PATTERN.test(itemId) || itemIds.has(itemId)) return false;
      itemIds.add(itemId);
      if (item.label.trim().length === 0) return false;
    }
  }
  return true;
}

export function DpiaTemplatePage() {
  const t = useT();
  const et = useDpiaTemplateEditorT();
  const activeLocale = useActiveLocale();
  const toast = useToast();
  const navigate = useNavigate();
  const listPath = privacyListPath();

  const can = useCan();
  const allowed = can('privacy.manage');

  const query = usePrivacyDpiaTemplate(allowed);
  const save = usePutPrivacyDpiaTemplate();
  const reset = useResetPrivacyDpiaTemplate();
  const busy = save.isPending || reset.isPending;

  const template = query.data ?? null;
  const seed = useMemo(
    () => (template ? seedFromTemplate(template, t, activeLocale) : null),
    [template, t, activeLocale],
  );
  const draft = usePrivacyRecordDraft(seed);

  const state: PrivacyRecordPageState = query.error
    ? 'error'
    : query.isLoading || draft.form === null
      ? 'loading'
      : 'ready';

  async function submit() {
    const form = draft.form;
    if (!form || busy || !formIsSubmittable(form)) return;
    try {
      await save.mutateAsync(bodyFromForm(form));
      toast.success(et('settings.privacy.dpiaTemplateEditor.toast.saved'));
      draft.markSaved();
      void navigate(listPath);
    } catch (e) {
      toast.error(e);
    }
  }

  async function restoreShipped() {
    if (busy) return;
    // A window confirm, not a bespoke modal: this replaces authored text, and the sentence names
    // exactly what is replaced and where the previous version remains recorded.
    if (!window.confirm(et('settings.privacy.dpiaTemplateEditor.reset.confirm'))) return;
    try {
      await reset.mutateAsync();
      toast.success(et('settings.privacy.dpiaTemplateEditor.toast.reset'));
      draft.markSaved();
      void navigate(listPath);
    } catch (e) {
      toast.error(e);
    }
  }

  return (
    <PrivacyRecordPageShell
      title={et('settings.privacy.dpiaTemplateEditor.page.title')}
      listPath={listPath}
      state={state}
      error={query.error}
      // A singleton has no id to be stale, so state 4 is unreachable here; the shell still wants a
      // sentence, and this is the honest one for "the model could not be resolved".
      notFoundMessage={et('settings.privacy.dpiaTemplateEditor.section.empty')}
      allowed={allowed}
    >
      {draft.form && template ? (
        <DpiaTemplateForm
          form={draft.form}
          setForm={draft.setForm}
          template={template}
          saving={busy}
          resetting={reset.isPending}
          cancelTo={listPath}
          onSubmit={() => void submit()}
          onReset={() => void restoreShipped()}
        />
      ) : null}
    </PrivacyRecordPageShell>
  );
}

function DpiaTemplateForm({
  form,
  setForm,
  template,
  saving,
  resetting,
  cancelTo,
  onSubmit,
  onReset,
}: {
  form: TemplateFormState;
  setForm: (next: TemplateFormState) => void;
  template: DpiaTemplateView;
  saving: boolean;
  resetting: boolean;
  cancelTo: string;
  onSubmit: () => void;
  onReset: () => void;
}) {
  const et = useDpiaTemplateEditorT();
  // Section keys are stable across renders so React does not remount a whole section (losing focus
  // and caret position) when the operator edits the id field it would otherwise be keyed by.
  const [rowKeys, setRowKeys] = useState<number[]>(() => form.sections.map((_, index) => index));
  const [nextKey, setNextKey] = useState(() => form.sections.length);

  const operatorAuthored = template.source === 'operator';
  const canSubmit = formIsSubmittable(form) && !saving;

  function setSection(index: number, next: SectionFormState) {
    setForm({
      ...form,
      sections: form.sections.map((section, i) => (i === index ? next : section)),
    });
  }

  function addSection() {
    setForm({
      ...form,
      sections: [
        ...form.sections,
        { id: '', title: '', description: '', prompts: '', checklist: [] },
      ],
    });
    setRowKeys([...rowKeys, nextKey]);
    setNextKey(nextKey + 1);
  }

  function removeSection(index: number) {
    setForm({ ...form, sections: form.sections.filter((_, i) => i !== index) });
    setRowKeys(rowKeys.filter((_, i) => i !== index));
  }

  return (
    <form
      className="form settings-rows"
      onSubmit={(e) => {
        e.preventDefault();
        if (canSubmit) onSubmit();
      }}
    >
      <p className="field__hint">{et('settings.privacy.dpiaTemplateEditor.page.lede')}</p>

      {/*
        Provenance, stated before anything is editable. It is the one fact that changes what
        happens to the words typed below: a shipped model is translated into every shipped
        language, and what the operator writes here is not.
      */}
      <p className="row-wrap">
        <Badge tone={operatorAuthored ? 'accent' : 'neutral'} wrap>
          {operatorAuthored
            ? et('settings.privacy.dpiaTemplateEditor.badge.operator')
            : et('settings.privacy.dpiaTemplateEditor.badge.shipped')}
        </Badge>
      </p>
      <p className="field__hint">
        {operatorAuthored
          ? et('settings.privacy.dpiaTemplateEditor.note.operator')
          : et('settings.privacy.dpiaTemplateEditor.note.shipped')}
      </p>
      {operatorAuthored && template.updated_by && template.updated_at ? (
        <p className="field__hint">
          {et('settings.privacy.dpiaTemplateEditor.note.savedBy', {
            actor: template.updated_by,
            timestamp: formatTimestamp(template.updated_at),
          })}
        </p>
      ) : null}

      <Field
        label={et('settings.privacy.dpiaTemplateEditor.field.title')}
        htmlFor="dpia-template-title"
      >
        <Input
          id="dpia-template-title"
          value={form.title}
          onChange={(e) => setForm({ ...form, title: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field
        label={et('settings.privacy.dpiaTemplateEditor.field.language')}
        htmlFor="dpia-template-language"
        hint={et('settings.privacy.dpiaTemplateEditor.field.languageHint')}
      >
        <Input
          id="dpia-template-language"
          value={form.language}
          onChange={(e) => setForm({ ...form, language: e.target.value })}
          autoComplete="off"
        />
      </Field>

      {form.sections.length === 0 ? (
        <p className="field__hint">{et('settings.privacy.dpiaTemplateEditor.section.empty')}</p>
      ) : null}

      {form.sections.map((section, index) => (
        <SectionFields
          key={rowKeys[index] ?? index}
          section={section}
          index={index}
          setSection={(next) => setSection(index, next)}
          onRemove={() => removeSection(index)}
        />
      ))}

      <div className="row-wrap">
        <Button type="button" variant="secondary" icon={<Icon.Plus />} onClick={addSection}>
          {et('settings.privacy.dpiaTemplateEditor.action.addSection')}
        </Button>
      </div>

      <Field
        label={et('settings.privacy.dpiaTemplateEditor.field.operatorActions')}
        htmlFor="dpia-template-operator-actions"
        hint={et('settings.privacy.dpiaTemplateEditor.field.operatorActionsHint')}
      >
        <TextArea
          id="dpia-template-operator-actions"
          value={form.operatorActions}
          onChange={(e) => setForm({ ...form, operatorActions: e.target.value })}
          rows={4}
        />
      </Field>

      {/*
        The honest answer to "why is this in English?", carried in every locale. It is the reason
        the 28 no-claim identifiers and the six field-type identifiers are NOT translated: each
        no-claim flag names a legal claim the product does not make, and rendering one in
        Portuguese would be writing that claim in Portuguese.
      */}
      <InlineWarning
        tone="info"
        title={et('settings.privacy.dpiaTemplateEditor.identifiers.title')}
      >
        {et('settings.privacy.dpiaTemplateEditor.identifiers.body')}
      </InlineWarning>

      <PrivacyFormActions editing saving={saving} canSubmit={canSubmit} cancelTo={cancelTo} />

      {/* The way back for an operator who has edited the model into a corner. Only offered when
          there is an override to discard — resetting the shipped model to itself is not an action. */}
      {operatorAuthored ? (
        <div className="row-wrap">
          <Button
            type="button"
            variant="ghost"
            icon={<Icon.ArrowLeft />}
            disabled={resetting}
            onClick={onReset}
          >
            {et('settings.privacy.dpiaTemplateEditor.action.reset')}
          </Button>
        </div>
      ) : null}
    </form>
  );
}

function SectionFields({
  section,
  index,
  setSection,
  onRemove,
}: {
  section: SectionFormState;
  index: number;
  setSection: (next: SectionFormState) => void;
  onRemove: () => void;
}) {
  const t = useT();
  const et = useDpiaTemplateEditorT();
  const idPrefix = `dpia-template-section-${index}`;

  function setItem(itemIndex: number, next: ChecklistFormState) {
    setSection({
      ...section,
      checklist: section.checklist.map((item, i) => (i === itemIndex ? next : item)),
    });
  }

  return (
    <Card
      title={section.title.trim().length > 0 ? section.title : section.id}
      actions={
        <Button type="button" variant="ghost" icon={<Icon.Trash />} onClick={onRemove}>
          {et('settings.privacy.dpiaTemplateEditor.action.removeSection')}
        </Button>
      }
    >
      <div className="stack">
        <Field
          label={et('settings.privacy.dpiaTemplateEditor.field.sectionId')}
          htmlFor={`${idPrefix}-id`}
          hint={et('settings.privacy.dpiaTemplateEditor.field.sectionIdHint')}
        >
          <Input
            id={`${idPrefix}-id`}
            className="mono"
            value={section.id}
            onChange={(e) => setSection({ ...section, id: e.target.value })}
            autoComplete="off"
          />
        </Field>
        <Field
          label={et('settings.privacy.dpiaTemplateEditor.field.sectionTitle')}
          htmlFor={`${idPrefix}-title`}
        >
          <Input
            id={`${idPrefix}-title`}
            value={section.title}
            onChange={(e) => setSection({ ...section, title: e.target.value })}
            autoComplete="off"
          />
        </Field>
        <Field
          label={et('settings.privacy.dpiaTemplateEditor.field.sectionDescription')}
          htmlFor={`${idPrefix}-description`}
        >
          <TextArea
            id={`${idPrefix}-description`}
            value={section.description}
            onChange={(e) => setSection({ ...section, description: e.target.value })}
            rows={3}
          />
        </Field>
        <Field
          label={et('settings.privacy.dpiaTemplateEditor.field.prompts')}
          htmlFor={`${idPrefix}-prompts`}
          hint={et('settings.privacy.dpiaTemplateEditor.field.promptsHint')}
        >
          <TextArea
            id={`${idPrefix}-prompts`}
            value={section.prompts}
            onChange={(e) => setSection({ ...section, prompts: e.target.value })}
            rows={4}
          />
        </Field>

        <strong>{et('settings.privacy.dpiaTemplateEditor.checklist.heading')}</strong>
        {section.checklist.map((item, itemIndex) => (
          <div className="api-key-rate-grid" key={`${idPrefix}-item-${itemIndex}`}>
            <Field
              label={et('settings.privacy.dpiaTemplateEditor.field.itemId')}
              htmlFor={`${idPrefix}-item-${itemIndex}-id`}
            >
              <Input
                id={`${idPrefix}-item-${itemIndex}-id`}
                className="mono"
                value={item.id}
                onChange={(e) => setItem(itemIndex, { ...item, id: e.target.value })}
                autoComplete="off"
              />
            </Field>
            <Field
              label={et('settings.privacy.dpiaTemplateEditor.field.itemLabel')}
              htmlFor={`${idPrefix}-item-${itemIndex}-label`}
            >
              <Input
                id={`${idPrefix}-item-${itemIndex}-label`}
                value={item.label}
                onChange={(e) => setItem(itemIndex, { ...item, label: e.target.value })}
                autoComplete="off"
              />
            </Field>
            <Field
              label={et('settings.privacy.dpiaTemplateEditor.field.itemType')}
              htmlFor={`${idPrefix}-item-${itemIndex}-type`}
            >
              {/* `mono`, and the option text is the wire identifier itself — see FIELD_TYPES. */}
              <Select
                id={`${idPrefix}-item-${itemIndex}-type`}
                className="mono"
                value={item.fieldType}
                onChange={(e) =>
                  setItem(itemIndex, {
                    ...item,
                    fieldType: e.target.value as DpiaTemplateFieldType,
                  })
                }
                options={FIELD_TYPES.map((fieldType) => ({
                  value: fieldType,
                  label: fieldType,
                }))}
              />
            </Field>
            <Field
              label={et('settings.privacy.dpiaTemplateEditor.field.itemRequired')}
              htmlFor={`${idPrefix}-item-${itemIndex}-required`}
            >
              <input
                id={`${idPrefix}-item-${itemIndex}-required`}
                type="checkbox"
                checked={item.required}
                onChange={(e) => setItem(itemIndex, { ...item, required: e.target.checked })}
              />
            </Field>
            <Button
              type="button"
              variant="ghost"
              onClick={() =>
                setSection({
                  ...section,
                  checklist: section.checklist.filter((_, i) => i !== itemIndex),
                })
              }
            >
              {t('common.remove')}
            </Button>
          </div>
        ))}
        <div className="row-wrap">
          <Button
            type="button"
            variant="secondary"
            icon={<Icon.Plus />}
            onClick={() =>
              setSection({
                ...section,
                checklist: [
                  ...section.checklist,
                  { id: '', label: '', fieldType: 'text', required: false },
                ],
              })
            }
          >
            {et('settings.privacy.dpiaTemplateEditor.action.addItem')}
          </Button>
        </div>
      </div>
    </Card>
  );
}
