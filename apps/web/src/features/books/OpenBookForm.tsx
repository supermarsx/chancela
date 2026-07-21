/**
 * Open-and-create a book (WFL-10/11, `POST /v1/books`). Used both on the Livros page
 * (with an entity picker) and on an entity's detail page (entity fixed). Required
 * signatories are captured as structured records in the legacy `required_signatories`
 * field. The opening date is an ISO `YYYY-MM-DD` string straight from `<input
 * type="date">`, matching §2.1.
 *
 * The audit actor is NOT entered here: the current user (the topbar picker) is the
 * identity surface, so the server attributes the ledger actor from the
 * `X-Chancela-Session` header (falling back to "api" when signed out). The UI sends no
 * body `actor`.
 */
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useOpenBook, useSettings } from '../../api/hooks';
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

export function parseLines(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

export interface TermoSignatoryDraft {
  name: string;
  capacity: SignatoryCapacity | '';
  email: string;
}

const emptySignatory = (): TermoSignatoryDraft => ({ name: '', capacity: '', email: '' });

export function parseTermoSignatories(rows: TermoSignatoryDraft[]): BookTermoSignatoryInput[] {
  return rows
    .map((row) => ({
      name: row.name.trim(),
      capacity: row.capacity || null,
      email: row.email.trim() || null,
    }))
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
  const update = (index: number, patch: Partial<TermoSignatoryDraft>) =>
    onChange(rows.map((row, idx) => (idx === index ? { ...row, ...patch } : row)));
  const capacityOptions = [
    { value: '', label: '—' },
    ...optionsFrom(SIGNATORY_CAPACITIES, signatoryCapacityLabels),
  ];

  return (
    <div className="stack--tight">
      {rows.map((row, index) => {
        const rowHasDetails = row.capacity !== '' || row.email.trim().length > 0;
        return (
          <div className="rowline" key={index}>
            <Field label={t('acts.signatoryNameAria')} htmlFor={`${idPrefix}-name-${index}`}>
              <Input
                id={`${idPrefix}-name-${index}`}
                value={row.name}
                required={rowHasDetails}
                onChange={(e) => update(index, { name: e.target.value })}
                placeholder={t('acts.namePlaceholder')}
              />
            </Field>
            <Field label={t('acts.capacityAria')} htmlFor={`${idPrefix}-capacity-${index}`}>
              <Select
                id={`${idPrefix}-capacity-${index}`}
                value={row.capacity}
                onChange={(e) =>
                  update(index, { capacity: e.target.value as SignatoryCapacity | '' })
                }
                options={capacityOptions}
              />
            </Field>
            <Field label={t('registry.email.label')} htmlFor={`${idPrefix}-email-${index}`}>
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

interface Props {
  /** When set, the book is fixed to this entity (no picker shown). */
  entityId?: string;
  /** Entities to choose from when `entityId` is not fixed. */
  entities?: Entity[];
}

export function OpenBookForm({ entityId, entities }: Props) {
  const t = useT();
  const toast = useToast();
  const navigate = useNavigate();
  const open = useOpenBook();
  const settings = useSettings();

  const [selectedEntity, setSelectedEntity] = useState(entityId ?? entities?.[0]?.id ?? '');
  const [kind, setKind] = useState<BookKind>('AssembleiaGeral');
  const [purpose, setPurpose] = useState('');
  const [scheme, setScheme] = useState<NumberingScheme>('Sequential');
  const [openingDate, setOpeningDate] = useState('');
  const [signatories, setSignatories] = useState<TermoSignatoryDraft[]>([emptySignatory()]);
  const [predecessor, setPredecessor] = useState('');

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

  // Unsaved-work guard (t52). The termo de abertura is typed once and kept nowhere until
  // the POST succeeds, and the signatory rows are the expensive part. The pickers
  // (entity, kind, scheme) are pre-seeded defaults, not typed work, so they never count
  // as dirty — otherwise merely opening the page would arm the prompt.
  useUnsavedChanges(
    purpose.trim() !== '' ||
      openingDate !== '' ||
      predecessor.trim() !== '' ||
      parseTermoSignatories(signatories).length > 0,
  );

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    open.mutate(
      {
        entity_id: chosen,
        kind,
        purpose,
        numbering_scheme: scheme,
        opening_date: openingDate,
        required_signatories: parseTermoSignatories(signatories),
        predecessor: predecessor.trim() || undefined,
      },
      {
        // R6: success toast survives the navigate-away; R7: inline ErrorNote stays.
        onSuccess: (book) => {
          toast.success(t('toast.book.opened'));
          // The form state is still populated at this point, so the guard would see a
          // dirty surface and prompt on the app's OWN post-save navigation. The work is
          // saved; exempt exactly this navigation.
          allowNextNavigation();
          navigate(`/books/${book.id}`);
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
          <Field label={t('books.entity')} htmlFor="book-entity">
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
        <Field label={t('books.purpose')} htmlFor="book-purpose">
          <Input
            id="book-purpose"
            required
            value={purpose}
            onChange={(e) => setPurpose(e.target.value)}
            placeholder={t('books.purposePlaceholder')}
          />
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
        <Field label={t('books.openingDate')} htmlFor="book-date">
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
          label={t('books.predecessorOptional')}
          htmlFor="book-predecessor"
          hint={t('books.predecessorHint')}
        >
          <Input
            id="book-predecessor"
            value={predecessor}
            onChange={(e) => setPredecessor(e.target.value)}
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
            {open.isPending ? t('books.opening') : t('books.openBook')}
          </Button>
        </div>
      </form>
    </Card>
  );
}
