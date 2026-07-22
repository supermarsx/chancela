/**
 * Open-and-create a book (WFL-10/11, `POST /v1/books`). Used both on the Livros page
 * (with an entity picker) and on an entity's detail page (entity fixed). Required
 * signatories are captured as structured records in the legacy `required_signatories`
 * field. The opening date is an ISO `YYYY-MM-DD` string straight from `<input
 * type="date">`, matching §2.1.
 *
 * Two ways to open (t23): the classic **one-shot** (default) creates and opens the book in a
 * single step with a generated termo de abertura; the **two-phase** path mints a `Created` book
 * plus a `Draft` termo de abertura and routes to the termo editor, where the termo is drafted,
 * signed and only then sealed to open the book — the termo treated as an ata in its own right.
 *
 * The audit actor is NOT entered here: the current user (the topbar picker) is the
 * identity surface, so the server attributes the ledger actor from the
 * `X-Chancela-Session` header (falling back to "api" when signed out). The UI sends no
 * body `actor`.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useBooks, useOpenBook, useSettings } from '../../api/hooks';
import {
  bookKindLabels,
  numberingSchemeLabels,
  optionsFrom,
  signatoryCapacityLabels,
} from '../../api/labels';
import { allowNextNavigation, useUnsavedChanges } from '../../hooks/useUnsavedChanges';
import { useT } from '../../i18n';
import {
  BOOK_KINDS,
  NUMBERING_SCHEMES,
  SIGNATORY_CAPACITIES,
  type BookTermoSignatory,
  type BookTermoSignatoryInput,
  type BookKind,
  type Entity,
  type NumberingScheme,
  type SignatoryCapacity,
} from '../../api/types';
import {
  Button,
  Card,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  Select,
  useToast,
} from '../../ui';
import { useTermoT, type TermoCopyKey } from './termoStrings';

export function parseLines(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

/**
 * A finalidade preset per book kind (D4). UI convenience only: the chosen value goes on the wire as
 * the free-text `purpose`. `Other` books have no preset (the operator describes the book themselves).
 */
const FINALIDADE_PRESET_KEYS: Record<BookKind, TermoCopyKey[]> = {
  AssembleiaGeral: ['books.termo.purposePreset.agSocios', 'books.termo.purposePreset.agAcionistas'],
  GerenciaAdministracao: [
    'books.termo.purposePreset.gerencia',
    'books.termo.purposePreset.administracao',
  ],
  ConselhoFiscal: ['books.termo.purposePreset.fiscal'],
  Condominio: ['books.termo.purposePreset.condominio'],
  Other: [],
};

export interface TermoSignatoryDraft {
  name: string;
  capacity: SignatoryCapacity | '';
  email: string;
  /** Free-text qualidade for the `Other` capacity (D1). ASSURANCE only; never a legal capacity. */
  capacityNote?: string;
}

const emptySignatory = (): TermoSignatoryDraft => ({
  name: '',
  capacity: '',
  email: '',
  capacityNote: '',
});

export function parseTermoSignatories(rows: TermoSignatoryDraft[]): BookTermoSignatoryInput[] {
  return rows
    .map((row): BookTermoSignatory => {
      const note = row.capacity === 'Other' ? row.capacityNote?.trim() : undefined;
      return {
        name: row.name.trim(),
        capacity: row.capacity || null,
        email: row.email.trim() || null,
        ...(note ? { capacity_note: note } : {}),
      };
    })
    .filter((row) => row.name.length > 0 || row.capacity || row.email);
}

export function TermoSignatoryFields({
  idPrefix,
  rows,
  onChange,
}: {
  idPrefix: string;
  rows: TermoSignatoryDraft[];
  onChange: (rows: TermoSignatoryDraft[]) => void;
}) {
  const t = useT();
  const tt = useTermoT();
  const update = (index: number, patch: Partial<TermoSignatoryDraft>) =>
    onChange(rows.map((row, idx) => (idx === index ? { ...row, ...patch } : row)));
  const capacityOptions = [
    { value: '', label: '—' },
    ...optionsFrom(SIGNATORY_CAPACITIES, signatoryCapacityLabels),
    // D1: an out-of-list qualidade with a required note. It never satisfies the legal allow-list
    // or the management floor — the server enforces that; the copy states it plainly.
    { value: 'Other', label: tt('books.termo.signatory.other') },
  ];

  return (
    <div className="stack--tight">
      {rows.map((row, index) => {
        const rowHasDetails = row.capacity !== '' || row.email.trim().length > 0;
        const isOther = row.capacity === 'Other';
        return (
          <div className="rowline" key={index}>
            <Field
              label={t('acts.signatoryNameAria')}
              htmlFor={`${idPrefix}-name-${index}`}
              help={tt('books.termo.signatory.nameHelp')}
            >
              <Input
                id={`${idPrefix}-name-${index}`}
                value={row.name}
                required={rowHasDetails}
                onChange={(e) => update(index, { name: e.target.value })}
                placeholder={t('acts.namePlaceholder')}
              />
            </Field>
            <Field
              label={t('acts.capacityAria')}
              htmlFor={`${idPrefix}-capacity-${index}`}
              help={tt('books.termo.signatory.capacityHelp')}
            >
              <Select
                id={`${idPrefix}-capacity-${index}`}
                value={row.capacity}
                onChange={(e) =>
                  update(index, { capacity: e.target.value as SignatoryCapacity | '' })
                }
                options={capacityOptions}
              />
            </Field>
            {isOther ? (
              <Field
                label={tt('books.termo.signatory.other')}
                htmlFor={`${idPrefix}-capacity-note-${index}`}
                help={tt('books.termo.signatory.otherHelp')}
              >
                <Input
                  id={`${idPrefix}-capacity-note-${index}`}
                  value={row.capacityNote ?? ''}
                  required
                  onChange={(e) => update(index, { capacityNote: e.target.value })}
                  placeholder={tt('books.termo.signatory.otherPlaceholder')}
                />
              </Field>
            ) : null}
            <Field
              label={t('registry.email.label')}
              htmlFor={`${idPrefix}-email-${index}`}
              help={tt('books.termo.signatory.emailHelp')}
            >
              <Input
                id={`${idPrefix}-email-${index}`}
                type="email"
                value={row.email}
                autoComplete="email"
                onChange={(e) => update(index, { email: e.target.value })}
                placeholder={t('registry.email.placeholder')}
              />
            </Field>
            <Button
              type="button"
              variant="ghost"
              icon={<Icon.Trash />}
              onClick={() => onChange(rows.filter((_, idx) => idx !== index))}
            >
              {t('common.remove')}
            </Button>
          </div>
        );
      })}
      <Button
        type="button"
        variant="secondary"
        icon={<Icon.Plus />}
        onClick={() => onChange([...rows, emptySignatory()])}
      >
        {t('acts.addSignatory')}
      </Button>
    </div>
  );
}

/** How the operator opens the book: classic one-step, or the drafted-then-signed termo path. */
type OpenMode = 'oneShot' | 'twoPhase';

interface Props {
  /** When set, the book is fixed to this entity (no picker shown). */
  entityId?: string;
  /** Entities to choose from when `entityId` is not fixed. */
  entities?: Entity[];
}

export function OpenBookForm({ entityId, entities }: Props) {
  const t = useT();
  const tt = useTermoT();
  const toast = useToast();
  const navigate = useNavigate();
  const open = useOpenBook();
  const settings = useSettings();

  const [selectedEntity, setSelectedEntity] = useState(entityId ?? entities?.[0]?.id ?? '');
  const [kind, setKind] = useState<BookKind>('AssembleiaGeral');
  const [kindLabel, setKindLabel] = useState('');
  const [purpose, setPurpose] = useState('');
  const [scheme, setScheme] = useState<NumberingScheme>('Sequential');
  const [openingDate, setOpeningDate] = useState('');
  const [signatories, setSignatories] = useState<TermoSignatoryDraft[]>([emptySignatory()]);
  const [predecessor, setPredecessor] = useState('');
  const [predecessorNote, setPredecessorNote] = useState('');
  const [mode, setMode] = useState<OpenMode>('oneShot');

  // Seed the numbering scheme from the configured default once the settings document
  // loads (documents.numbering_scheme_default). Only applied once, so a later edit by
  // the user isn't clobbered.
  const seeded = useRef(false);
  useEffect(() => {
    if (settings.data && !seeded.current) {
      seeded.current = true;
      setScheme(settings.data.documents.numbering_scheme_default);
    }
  }, [settings.data]);

  const chosen = entityId ?? selectedEntity;
  const isOther = kind === 'Other';

  // The entity's existing books back the predecessor dropdown (D5): the real successor link is a
  // BookId, so the primary control picks one; the paper/legacy reference is a separate note.
  const books = useBooks(chosen || undefined, !!chosen);
  const predecessorOptions = useMemo(() => {
    const list = (Array.isArray(books.data) ? books.data : []).filter((book) => book.id !== '');
    return [
      { value: '', label: tt('books.termo.field.predecessorNone') },
      ...list.map((book) => ({
        value: book.id,
        label: `${bookKindLabels[book.kind]} — ${book.purpose ?? book.id.slice(0, 8)}`,
      })),
    ];
  }, [books.data, tt]);

  const finalidadeListId = `${entityId ?? 'book'}-finalidade-presets`;
  const finalidadePresets = FINALIDADE_PRESET_KEYS[kind].map((key) => tt(key));

  // Unsaved-work guard (t52). The termo de abertura is typed once and kept nowhere until
  // the POST succeeds, and the signatory rows are the expensive part. The pickers
  // (entity, kind, scheme) are pre-seeded defaults, not typed work, so they never count
  // as dirty — otherwise merely opening the page would arm the prompt.
  useUnsavedChanges(
    purpose.trim() !== '' ||
      openingDate !== '' ||
      predecessor.trim() !== '' ||
      predecessorNote.trim() !== '' ||
      kindLabel.trim() !== '' ||
      parseTermoSignatories(signatories).length > 0,
  );

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const twoPhase = mode === 'twoPhase';
    open.mutate(
      {
        entity_id: chosen,
        kind,
        purpose,
        numbering_scheme: scheme,
        opening_date: openingDate,
        required_signatories: parseTermoSignatories(signatories),
        predecessor: predecessor.trim() || undefined,
        predecessor_note: predecessorNote.trim() || undefined,
        kind_label: isOther ? kindLabel.trim() || undefined : undefined,
        // Omit for the one-shot default so today's request is byte-for-byte unchanged.
        ...(twoPhase ? { one_shot: false } : {}),
      },
      {
        // R6: success toast survives the navigate-away; R7: inline ErrorNote stays.
        onSuccess: (book) => {
          toast.success(twoPhase ? tt('books.termo.createdToast') : t('toast.book.opened'));
          // The form state is still populated at this point, so the guard would see a
          // dirty surface and prompt on the app's OWN post-save navigation. The work is
          // saved; exempt exactly this navigation.
          allowNextNavigation();
          // Two-phase lands on the termo editor (the opening section); one-shot on the book.
          navigate(twoPhase ? `/books/${book.id}/opening` : `/books/${book.id}`);
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  return (
    <Card title={t('books.openBook')}>
      <form className="form" onSubmit={onSubmit}>
        {/* Autonomy-oriented orientation: which book matches which body, and where the
            signature type is chosen. The per-field help glyphs cover each option in detail. */}
        <InlineWarning tone="info" title={t('books.open.guidanceTitle')}>
          <p>{t('books.open.guidanceBody')}</p>
        </InlineWarning>
        {!entityId && entities ? (
          <Field
            label={t('books.entity')}
            htmlFor="book-entity"
            help={tt('books.termo.field.entityHelp')}
          >
            <Select
              id="book-entity"
              value={selectedEntity}
              onChange={(e) => setSelectedEntity(e.target.value)}
              options={entities.map((ent) => ({ value: ent.id, label: ent.name }))}
            />
          </Field>
        ) : null}
        <Field label={t('books.bookKind')} htmlFor="book-kind" help={t('books.open.kindHelp')}>
          <Select
            id="book-kind"
            value={kind}
            onChange={(e) => setKind(e.target.value as BookKind)}
            options={optionsFrom(BOOK_KINDS, bookKindLabels)}
          />
        </Field>
        {isOther ? (
          <Field
            label={tt('books.termo.field.kindLabel')}
            htmlFor="book-kind-label"
            help={tt('books.termo.field.kindLabelHelp')}
          >
            <Input
              id="book-kind-label"
              required
              value={kindLabel}
              onChange={(e) => setKindLabel(e.target.value)}
            />
          </Field>
        ) : null}
        <Field
          label={t('books.purpose')}
          htmlFor="book-purpose"
          help={tt('books.termo.field.purposeHelp')}
          hint={tt('books.termo.field.purposeListHint')}
        >
          <Input
            id="book-purpose"
            required
            value={purpose}
            list={finalidadePresets.length ? finalidadeListId : undefined}
            onChange={(e) => setPurpose(e.target.value)}
            placeholder={t('books.purposePlaceholder')}
          />
          {finalidadePresets.length ? (
            <datalist id={finalidadeListId}>
              {finalidadePresets.map((preset) => (
                <option value={preset} key={preset} />
              ))}
            </datalist>
          ) : null}
        </Field>
        <Field
          label={t('books.numberingScheme')}
          htmlFor="book-scheme"
          help={t('books.open.schemeHelp')}
        >
          <Select
            id="book-scheme"
            value={scheme}
            onChange={(e) => setScheme(e.target.value as NumberingScheme)}
            options={optionsFrom(NUMBERING_SCHEMES, numberingSchemeLabels)}
          />
        </Field>
        <Field
          label={t('books.openingDate')}
          htmlFor="book-date"
          help={tt('books.termo.field.openingDateHelp')}
        >
          <Input
            id="book-date"
            type="date"
            required
            value={openingDate}
            onChange={(e) => setOpeningDate(e.target.value)}
          />
        </Field>
        <Field label={t('books.open.signatories')}>
          <TermoSignatoryFields
            idPrefix="book-signatories"
            rows={signatories}
            onChange={setSignatories}
          />
        </Field>
        <Field
          label={tt('books.termo.field.predecessor')}
          htmlFor="book-predecessor"
          help={tt('books.termo.field.predecessorHelp')}
        >
          <Select
            id="book-predecessor"
            value={predecessor}
            onChange={(e) => setPredecessor(e.target.value)}
            options={predecessorOptions}
          />
        </Field>
        <Field
          label={tt('books.termo.field.predecessorNote')}
          htmlFor="book-predecessor-note"
          help={tt('books.termo.field.predecessorNoteHelp')}
        >
          <Input
            id="book-predecessor-note"
            value={predecessorNote}
            onChange={(e) => setPredecessorNote(e.target.value)}
          />
        </Field>
        <Field
          label={tt('books.termo.mode.legend')}
          htmlFor="book-open-mode"
          help={
            mode === 'twoPhase'
              ? tt('books.termo.mode.twoPhaseHelp')
              : tt('books.termo.mode.oneShotHelp')
          }
        >
          <Select
            id="book-open-mode"
            value={mode}
            onChange={(e) => setMode(e.target.value as OpenMode)}
            options={[
              { value: 'oneShot', label: tt('books.termo.mode.oneShot') },
              { value: 'twoPhase', label: tt('books.termo.mode.twoPhase') },
            ]}
          />
        </Field>
        {open.error ? <ErrorNote error={open.error} /> : null}
        <div className="form__actions">
          <Button
            type="submit"
            variant="primary"
            icon={<Icon.BookPlus />}
            disabled={open.isPending || !chosen}
          >
            {open.isPending
              ? t('books.opening')
              : mode === 'twoPhase'
                ? tt('books.termo.mode.twoPhase')
                : t('books.openBook')}
          </Button>
        </div>
      </form>
    </Card>
  );
}
