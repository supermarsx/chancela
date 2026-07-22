/**
 * "Termo de encerramento" copy (t44) — the two-phase book-CLOSE flow that treats the termo de
 * encerramento as its own drafted, signed ata, the mirror of the abertura's {@link ./termoStrings}.
 *
 * **Why this module is self-contained, not spread into the catalogs.** Same reason as `termoStrings`:
 * the 14 locale catalogs are held under a single-writer serial lock for this batch, so t44 owns these
 * keys end to end and exposes its own locale-aware resolver ({@link useEncerramentoT}) — the escape
 * hatch t14's `serverEnvFallback.ts`, t17's `notificationsRetentionFallback.ts` and t23's
 * `termoStrings.ts` used. Only the encerramento-SPECIFIC copy lives here; everything generic to a
 * termo (states, completion policy, signatory columns, the capacity allow-list rule, the signing
 * phase, the flow actions) is reused from `termoStrings` via `useTermoT`, so nothing is duplicated.
 * Folding these into the catalog later is a mechanical spread.
 *
 * **Honesty rules governing the copy here.** Only two things in this feature are legally required and
 * may be framed as such: the capacity **allow-list** (art. 31.º n.º 2, reused from `termoStrings`) and
 * the **at-least-one signatory** minimum. Everything else — the closing reason, the closing date, the
 * "livro esgotado" prompt — is ASSURANCE or product convenience and must never be worded as a legal
 * requirement. **Closing fixity is NEVER described as discharging the encadernação duty**: an
 * exhausted book is simply closeable, and the encerramento states facts about what the book contained.
 * The `close` step fails closed until every required slot carries a real PAdES signature; its copy
 * says so plainly rather than implying the book was closed. pt-PT is the source; interpolations here
 * are numeric only.
 */
import { useMemo } from 'react';
import { useActiveLocale } from '../../i18n/useT';
import { interpolate, type TParams } from '../../i18n/interpolate';

export const encerramentoPtPT = {
  // — Cabeçalho ————————————————————————————————————————————————————————————
  'books.encerramento.title': 'Termo de encerramento',
  'books.encerramento.subtitle':
    'Um documento próprio, redigido e assinado, que encerra o livro — distinto do ato mecânico de o encerrar.',
  'books.encerramento.none':
    'Este livro foi encerrado num único passo e não tem um termo de encerramento editável em separado.',
  'books.encerramento.state.SealedHint':
    'O termo produziu efeito e o livro foi encerrado. É imutável.',

  // — Campos do encerramento + descrições ————————————————————————————————————
  'books.encerramento.field.closingDate': 'Data de encerramento',
  'books.encerramento.field.closingDateHelp':
    'A data em que o termo de encerramento é lavrado. É necessária antes de avançar para assinatura.',
  'books.encerramento.field.closingReason': 'Motivo do encerramento',
  'books.encerramento.field.closingReasonHelp':
    'Porque é que o livro está a ser encerrado. É uma indicação sua: nenhuma norma exige um motivo declarado.',
  'books.encerramento.reason.other': 'Outro',
  'books.encerramento.reason.otherNote': 'Qual o motivo',
  'books.encerramento.reason.otherNoteHelp':
    'Descreva o motivo quando nenhum dos anteriores se aplica — uma mudança na composição do órgão, um novo exercício, uma fusão. É obrigatório e não pode ficar em branco.',
  'books.encerramento.reason.otherPlaceholder': 'Indique o motivo',

  // — Recolha de assinaturas (contexto do encerramento) ——————————————————————
  'books.encerramento.signing.intro':
    'O conteúdo está congelado. Cada signatário exigido assina pela ordem indicada; depois o livro pode ser encerrado.',

  // — Ação de encerrar ————————————————————————————————————————————————————————
  'books.encerramento.action.close': 'Encerrar livro',
  'books.encerramento.action.closeHint': 'Sela o termo assinado e encerra o livro.',
  'books.encerramento.action.closing': 'A encerrar…',

  // — Falha-fechada do encerramento (t44) ————————————————————————————————————
  'books.encerramento.close.notSignedTitle': 'O termo ainda não está assinado criptograficamente',
  'books.encerramento.close.notSignedBody':
    'O livro não pode ser encerrado: cada signatário exigido tem de ter uma assinatura PAdES real sobre o PDF do termo de encerramento. Até lá, o livro não é encerrado e o termo permanece em assinatura.',
  'books.encerramento.close.staleTitle': 'Os factos do livro mudaram durante a assinatura',
  'books.encerramento.close.staleBody':
    'Foi selada uma nova ata enquanto o termo estava a ser assinado, pelo que o termo assinado já não corresponde ao conteúdo do livro. O encerramento é recusado para não selar um documento que contradiz o registo. Reabra o termo, atualize-o e recolha as assinaturas novamente.',
  'books.encerramento.close.error': 'Não foi possível encerrar o livro a partir do termo.',

  // — Como encerrar o livro (um passo vs. termo assinável) ————————————————————
  'books.encerramento.mode.legend': 'Como encerrar o livro',
  'books.encerramento.mode.oneShot': 'Encerrar já, num único passo',
  'books.encerramento.mode.oneShotHelp':
    'Encerra o livro de imediato, com um termo de encerramento gerado a partir do que preencheu aqui. É o comportamento clássico.',
  'books.encerramento.mode.twoPhase': 'Redigir um termo de encerramento assinável',
  'books.encerramento.mode.twoPhaseHelp':
    'Mantém o livro aberto e cria um termo de encerramento em rascunho. Redige e assina o termo como uma ata própria e só depois encerra o livro.',
  'books.encerramento.createdToast': 'Termo de encerramento criado. Redija-o e assine-o.',

  // — Livro esgotado (aviso de capacidade) ——————————————————————————————————
  'books.encerramento.capacity.exhaustedTitle': 'Livro esgotado',
  'books.encerramento.capacity.exhaustedBody':
    'O livro não tem páginas disponíveis e recusa novas atas. Permanece aberto; pode encerrá-lo lavrando o termo de encerramento.',
  'books.encerramento.capacity.close': 'Encerrar livro',
} as const;

/** The key set the encerramento-specific copy resolves. */
export type EncerramentoCopyKey = keyof typeof encerramentoPtPT;

export const encerramentoEnglish = {
  'books.encerramento.title': 'Closing term',
  'books.encerramento.subtitle':
    'A document in its own right — drawn up and signed — that closes the book, distinct from the mechanical act of closing it.',
  'books.encerramento.none':
    'This book was closed in a single step and has no separately editable closing term.',
  'books.encerramento.state.SealedHint':
    'The term has taken effect and the book was closed. It is immutable.',

  'books.encerramento.field.closingDate': 'Closing date',
  'books.encerramento.field.closingDateHelp':
    'The date the closing term is drawn up. It is required before advancing to signing.',
  'books.encerramento.field.closingReason': 'Closing reason',
  'books.encerramento.field.closingReasonHelp':
    'Why the book is being closed. This is your own note: no rule requires a stated reason.',
  'books.encerramento.reason.other': 'Other',
  'books.encerramento.reason.otherNote': 'What the reason is',
  'books.encerramento.reason.otherNoteHelp':
    'Describe the reason when none of the above fits — a change in the body’s composition, a new financial year, a merger. It is required and must not be blank.',
  'books.encerramento.reason.otherPlaceholder': 'State the reason',

  'books.encerramento.signing.intro':
    'The content is frozen. Each required signatory signs in the order shown; the book can then be closed.',

  'books.encerramento.action.close': 'Close book',
  'books.encerramento.action.closeHint': 'Seals the signed term and closes the book.',
  'books.encerramento.action.closing': 'Closing…',

  'books.encerramento.close.notSignedTitle': 'The term is not yet cryptographically signed',
  'books.encerramento.close.notSignedBody':
    'The book cannot be closed: every required signatory must have a real PAdES signature over the closing term’s PDF. Until then, the book is not closed and the term stays in signing.',
  'books.encerramento.close.staleTitle': 'The book’s facts changed during signing',
  'books.encerramento.close.staleBody':
    'A new minute was sealed while the term was being signed, so the signed term no longer matches the book’s content. Closing is refused so as not to seal a document that contradicts the record. Reopen the term, update it and collect the signatures again.',
  'books.encerramento.close.error': 'Could not close the book from the term.',

  'books.encerramento.mode.legend': 'How to close the book',
  'books.encerramento.mode.oneShot': 'Close now, in a single step',
  'books.encerramento.mode.oneShotHelp':
    'Closes the book straight away, with a closing term generated from what you fill in here. This is the classic behaviour.',
  'books.encerramento.mode.twoPhase': 'Draft a signable closing term',
  'books.encerramento.mode.twoPhaseHelp':
    'Keeps the book open and creates a draft closing term. You draft and sign the term as a document in its own right, and only then close the book.',
  'books.encerramento.createdToast': 'Closing term created. Draft and sign it.',

  'books.encerramento.capacity.exhaustedTitle': 'Book full',
  'books.encerramento.capacity.exhaustedBody':
    'The book has no pages left and refuses new minutes. It stays open; you can close it by drawing up the closing term.',
  'books.encerramento.capacity.close': 'Close book',
} as const satisfies Record<EncerramentoCopyKey, string>;

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale gets the English
 * fallback — the same split the catalog spread uses, kept here because t44 may not touch the locked
 * catalogs. Folding into the catalog later is a mechanical spread.
 */
export function useEncerramentoCopy(): Record<EncerramentoCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? encerramentoPtPT : encerramentoEnglish;
}

/**
 * The encerramento copy translate hook, shaped like `useT`:
 * `const et = useEncerramentoT(); et('books.encerramento.title')`. Supports the same `{placeholder}`
 * interpolation as the catalog (used here only for numeric counts).
 */
export function useEncerramentoT(): (key: EncerramentoCopyKey, params?: TParams) => string {
  const copy = useEncerramentoCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
