/**
 * Copy for entity archiving — the badge, the tri-state list filter, and the two guarded dialogs
 * (`features/entities/EntityArchiveGuard.tsx`, `features/entities/EntitiesPage.tsx`).
 *
 * Kept outside the shared locale catalogs for the established reason: `Catalog` is a TOTAL type, so
 * these ~20 strings would otherwise cost a key in all 14 shipped catalogs. This is the owned-fallback
 * escape valve — pt-PT anchored, English for every other locale.
 *
 * ## The copy carries a distinction the product cannot afford to blur
 *
 * `crates/chancela-api/src/entities.rs` is explicit that archiving "withdraws the invitation to
 * *start* work" and "withdraws nothing else": every book, act, document, ledger row and export
 * stays readable, searchable and exportable, and the default listing keeps returning archived rows.
 * An archive that hid records would be, in that file's words, "a delete wearing a euphemism".
 *
 * So none of the strings below may imply removal, erasure or concealment. Deliberately absent:
 * *eliminar*, *apagar*, *remover*, *excluir* — and their English counterparts. What archiving does
 * is stated positively instead ("já não está disponível para novos trabalhos", "o conteúdo está
 * fixado") and each dialog spends a whole sentence on what is *kept*. A separate deletion concept
 * is being designed elsewhere; this module must not spend its vocabulary in advance.
 *
 * The one place *"ocultar"* legitimately appears is the `exclude` filter option, which describes
 * what the FILTER does at the operator's request — not what archiving does. The filter hint says so.
 *
 * ## Why every sentence is standalone
 *
 * The entity's name appears only on its own labelled line (`'Entidade: {name}'`), never dropped into
 * a surrounding clause: Portuguese agreement cannot be assembled from a noun substituted into an
 * inflected sentence. The date in `badgeSince` is safe to interpolate because a date inflects
 * nothing around it.
 *
 * `ata` and `termo` are the legal instruments' own names and stay Portuguese in every locale, the
 * same rule `noticeDismissFallback` follows.
 */
import { useMemo } from 'react';
import { interpolate, type TParams } from './interpolate';
import { useActiveLocale } from './useT';

/** Every string the archive affordances need. Total, so a new one must be written in both locales. */
export interface EntityArchiveCopy {
  /** The list badge on an archived row. */
  badge: string;
  /** The badge's `title`, stating what archiving did and — as importantly — what it did not do. */
  badgeTitle: string;
  /** Appended to the badge title once the timestamp is known. `{date}` interpolates safely. */
  badgeSince: string;

  /** Row action opening the archive dialog. */
  archiveAction: string;
  /** Row action opening the unarchive dialog. */
  unarchiveAction: string;

  archiveTitle: string;
  /** What archiving does. */
  archiveIntro: string;
  /** What archiving keeps — never omit this half. */
  archiveKeeps: string;
  /** The subject on its own labelled line. `{name}` is never interpolated into a clause. */
  archiveSubject: string;
  archiveConfirm: string;
  archivePending: string;
  archiveDone: string;

  unarchiveTitle: string;
  unarchiveIntro: string;
  unarchiveSubject: string;
  unarchiveConfirm: string;
  unarchivePending: string;
  unarchiveDone: string;

  filterLabel: string;
  /** States that the default INCLUDES archived rows, so the filter is not mistaken for the default. */
  filterHint: string;
  filterInclude: string;
  filterExclude: string;
  filterOnly: string;
}

const PT_PT: EntityArchiveCopy = {
  badge: 'Arquivada',
  badgeTitle:
    'Entidade arquivada: já não está disponível para novos trabalhos e o seu conteúdo está fixado. Nada foi ocultado.',
  badgeSince: 'Arquivada desde {date}',

  archiveAction: 'Arquivar',
  unarchiveAction: 'Desarquivar',

  archiveTitle: 'Arquivar esta entidade',
  archiveIntro:
    'Arquivar assinala a entidade como já não disponível para novos trabalhos: deixa de ser possível abrir livros, redigir novas atas ou alterar o conteúdo já existente. O arquivamento é reversível e fica registado no diário.',
  archiveKeeps:
    'Nada é ocultado. Os livros, as atas, os documentos e o registo no diário mantêm-se visíveis, pesquisáveis e exportáveis. Um livro já aberto pode ainda ser encerrado; uma ata já redigida pode ainda ser assinada e selada.',
  archiveSubject: 'Entidade: {name}',
  archiveConfirm: 'Arquivar',
  archivePending: 'A arquivar…',
  archiveDone: 'Entidade arquivada.',

  unarchiveTitle: 'Desarquivar esta entidade',
  unarchiveIntro:
    'Desarquivar devolve a entidade aos novos trabalhos: volta a ser possível abrir livros, redigir novas atas e alterar o conteúdo. Também fica registado no diário, tal como o arquivamento.',
  unarchiveSubject: 'Entidade: {name}',
  unarchiveConfirm: 'Desarquivar',
  unarchivePending: 'A desarquivar…',
  unarchiveDone: 'Entidade desarquivada.',

  filterLabel: 'Entidades arquivadas',
  filterHint:
    'Por predefinição a lista inclui as entidades arquivadas — arquivar não as oculta. Ocultá-las aqui é uma escolha desta lista.',
  filterInclude: 'Incluir arquivadas',
  filterExclude: 'Ocultar arquivadas',
  filterOnly: 'Apenas arquivadas',
};

const ENGLISH: EntityArchiveCopy = {
  badge: 'Archived',
  badgeTitle:
    'Archived entity: no longer available for new work, and its content is frozen. Nothing has been hidden.',
  badgeSince: 'Archived since {date}',

  archiveAction: 'Archive',
  unarchiveAction: 'Unarchive',

  archiveTitle: 'Archive this entity',
  archiveIntro:
    'Archiving marks the entity as no longer available for new work: books can no longer be opened, new atas can no longer be drafted, and existing content can no longer be edited. Archiving is reversible and is recorded in the ledger.',
  archiveKeeps:
    'Nothing is hidden. Books, atas, documents and the ledger record stay visible, searchable and exportable. A book already open can still be closed; an ata already drafted can still be signed and sealed.',
  archiveSubject: 'Entity: {name}',
  archiveConfirm: 'Archive',
  archivePending: 'Archiving…',
  archiveDone: 'Entity archived.',

  unarchiveTitle: 'Unarchive this entity',
  unarchiveIntro:
    'Unarchiving returns the entity to new work: books can be opened again, new atas drafted, and content edited. It is recorded in the ledger too, just as archiving is.',
  unarchiveSubject: 'Entity: {name}',
  unarchiveConfirm: 'Unarchive',
  unarchivePending: 'Unarchiving…',
  unarchiveDone: 'Entity unarchived.',

  filterLabel: 'Archived entities',
  filterHint:
    'By default the list includes archived entities — archiving does not hide them. Hiding them here is this list’s own choice.',
  filterInclude: 'Include archived',
  filterExclude: 'Hide archived',
  filterOnly: 'Archived only',
};

/** Resolve one string, interpolating its params. Mirrors `useT`'s call shape. */
export type EntityArchiveT = (key: keyof EntityArchiveCopy, params?: TParams) => string;

/** The archive copy for the active locale, as a `t`-shaped function. */
export function useEntityArchiveT(): EntityArchiveT {
  const locale = useActiveLocale();
  return useMemo(() => {
    const copy = locale === 'pt-PT' ? PT_PT : ENGLISH;
    return (key, params) => interpolate(copy[key], params);
  }, [locale]);
}
