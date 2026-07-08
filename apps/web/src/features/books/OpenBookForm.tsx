/**
 * Open-and-create a book (WFL-10/11, `POST /v1/books`). Used both on the Livros page
 * (with an entity picker) and on an entity's detail page (entity fixed). Required
 * signatories are entered one-per-line and trimmed into the `string[]` the contract
 * expects. The opening date is an ISO `YYYY-MM-DD` string straight from `<input
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
import { bookKindLabels, numberingSchemeLabels, optionsFrom } from '../../api/labels';
import { useT } from '../../i18n';
import {
  BOOK_KINDS,
  NUMBERING_SCHEMES,
  type BookKind,
  type Entity,
  type NumberingScheme,
} from '../../api/types';
import { Button, Card, ErrorNote, Field, Icon, Input, Select, TextArea, useToast } from '../../ui';

export function parseLines(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
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
  const [signatories, setSignatories] = useState('');
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

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    open.mutate(
      {
        entity_id: chosen,
        kind,
        purpose,
        numbering_scheme: scheme,
        opening_date: openingDate,
        required_signatories: parseLines(signatories),
        predecessor: predecessor.trim() || undefined,
      },
      {
        // R6: success toast survives the navigate-away; R7: inline ErrorNote stays.
        onSuccess: (book) => {
          toast.success(t('toast.book.opened'));
          navigate(`/livros/${book.id}`);
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  return (
    <Card title={t('books.openBook')}>
      <form className="form" onSubmit={onSubmit}>
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
        <Field label={t('books.bookKind')} htmlFor="book-kind">
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
        <Field label={t('books.numberingScheme')} htmlFor="book-scheme">
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
        <Field
          label={t('books.open.signatories')}
          htmlFor="book-signatories"
          hint={t('books.oneNamePerLine')}
        >
          <TextArea
            id="book-signatories"
            rows={3}
            value={signatories}
            onChange={(e) => setSignatories(e.target.value)}
            placeholder={t('books.open.signatoriesPlaceholder')}
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
