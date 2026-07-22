/**
 * "Termo de abertura" copy (t23) — the two-phase book-opening flow that treats the termo as its own
 * drafted, signed ata rather than a by-product of mechanically opening the book.
 *
 * **Why this module is self-contained, not spread into the catalogs.** The 14 locale catalogs
 * (`i18n/locales/*.ts` + `reviewedIdenticalValues.ts`) are held under a single-writer serial lock for
 * the duration of this batch, so t23 is not permitted to add the usual "one import + one spread line
 * per locale" wiring for this volume of new tooltip/flow copy. Instead this module owns its keys end
 * to end and exposes its own locale-aware resolver ({@link useTermoT}) — the same escape hatch t14's
 * `serverEnvFallback.ts` and t17's `notificationsRetentionFallback.ts` used. The consuming components
 * (the termo editor + reworked "abrir livro" form, t23-e5) read copy through that resolver exactly as
 * they would through `useT`, so nothing in the shared catalog moves and the catalog-leak / literal
 * gates never see these strings. Folding these into the catalog later is a mechanical spread.
 *
 * **Honesty rules governing the copy here.** Only two things in this feature are legally required and
 * may be framed as such: the capacity **allow-list** (art. 31.º n.º 2) and the **at-least-one
 * signatory** minimum. Everything else — the fields, the "Outra qualidade" note, the custom book
 * type, the predecessor note — is ASSURANCE or product convenience and must never be worded as a
 * legal requirement. The completion policy leaves the plural-gerência question deliberately open: no
 * copy states the law requires all gerentes to sign, or that one suffices. The `open` step fails
 * closed until real per-slot signing lands; its copy says so plainly rather than implying the book
 * was opened. pt-PT is the source; interpolations here are numeric only (no noun-agreement traps).
 */
import { useMemo } from 'react';
import { useActiveLocale } from '../../i18n/useT';
import { interpolate, type TParams } from '../../i18n/interpolate';

export const termoPtPT = {
  // — Cabeçalho ————————————————————————————————————————————————————————————
  'books.termo.title': 'Termo de abertura',
  'books.termo.subtitle':
    'Um documento próprio, redigido e assinado, que abre o livro — distinto do ato mecânico de o abrir.',
  'books.termo.loading': 'A carregar o termo de abertura…',
  'books.termo.loadError': 'Não foi possível carregar o termo de abertura.',
  'books.termo.none':
    'Este livro foi aberto num único passo e não tem um termo de abertura editável em separado.',

  // — Estado do termo ——————————————————————————————————————————————————————
  'books.termo.state.Draft': 'Rascunho',
  'books.termo.state.Signing': 'Em assinatura',
  'books.termo.state.Sealed': 'Selado',
  'books.termo.state.DraftHint':
    'O título, o corpo, os campos e os signatários são livremente editáveis.',
  'books.termo.state.SigningHint':
    'O conteúdo e o conjunto de signatários estão congelados; as assinaturas estão a ser recolhidas.',
  'books.termo.state.SealedHint': 'O termo produziu efeito e o livro foi aberto. É imutável.',

  // — Espécie ————————————————————————————————————————————————————————————————
  'books.termo.kind.Abertura': 'Abertura',
  'books.termo.kind.Encerramento': 'Encerramento',

  // — Política de conclusão ————————————————————————————————————————————————
  'books.termo.policy.AllRequired': 'Todos os signatários exigidos assinam',
  'books.termo.policy.AtLeast': 'Pelo menos {n} dos signatários exigidos assinam',
  'books.termo.policy.SingleQualifying': 'Basta um signatário qualificado',
  'books.termo.completion.complete': 'Assinaturas completas.',
  'books.termo.completion.pending': 'Faltam {count} de {total} assinaturas exigidas.',

  // — Regras legais (as únicas duas que o são) ——————————————————————————————
  'books.termo.rule.allowList':
    'Para lavrar o termo, a lei admite apenas estas qualidades: gerência, administração, membros do órgão a que respeita, secretário da sociedade (quando exista) e presidente da mesa da assembleia geral.',
  'books.termo.rule.atLeastOne': 'É exigido pelo menos um signatário.',

  // — Ações do fluxo ————————————————————————————————————————————————————————
  'books.termo.action.advance': 'Avançar para assinatura',
  'books.termo.action.advanceHint':
    'Congela o conteúdo e o conjunto de signatários para começar a recolher assinaturas. A partir daqui o termo deixa de ser editável.',
  'books.termo.action.sign': 'Assinar',
  'books.termo.action.open': 'Abrir livro',
  'books.termo.action.openHint': 'Sela o termo assinado e abre o livro.',
  'books.termo.action.advancing': 'A congelar…',
  'books.termo.action.signing': 'A assinar…',
  'books.termo.action.opening': 'A abrir…',

  // — Falha-fechada da abertura (t23/t41) ————————————————————————————————————
  'books.termo.open.notSignedTitle': 'O termo ainda não está assinado criptograficamente',
  'books.termo.open.notSignedBody':
    'O livro não pode ser aberto: cada signatário exigido tem de ter uma assinatura PAdES real sobre o PDF do termo. A assinatura real por signatário é um seguimento em curso; até lá, o livro não é aberto e o termo permanece em assinatura.',
  'books.termo.open.error': 'Não foi possível abrir o livro a partir do termo.',

  // — Campos de abertura + descrições (Cluster A) ——————————————————————————
  'books.termo.field.entity': 'Entidade',
  'books.termo.field.entityHelp': 'A pessoa coletiva a que o livro pertence.',
  'books.termo.field.bookKind': 'Tipo de livro',
  'books.termo.field.bookKindHelp':
    'O órgão ou a finalidade a que o livro se destina — assembleia geral, gerência/administração, conselho fiscal ou condomínio — ou "Outro" para um tipo que descreva.',
  'books.termo.field.bookKindOther': 'Outro',
  'books.termo.field.kindLabel': 'Tipo personalizado',
  'books.termo.field.kindLabelHelp':
    'Descreva o tipo de livro. É uma indicação sua e não uma classe de livro legalmente reconhecida.',
  'books.termo.field.purpose': 'Finalidade',
  'books.termo.field.purposeHelp':
    'Para que serve o livro (por exemplo, "Livro de atas da assembleia geral"). Escolha uma sugestão ou escreva a sua.',
  'books.termo.field.purposeOther': 'Outra…',
  'books.termo.field.numberingScheme': 'Numeração',
  'books.termo.field.numberingSchemeHelp':
    'Como as atas são numeradas neste livro: sequencial ou em folhas soltas.',
  'books.termo.field.openingDate': 'Data de abertura',
  'books.termo.field.openingDateHelp':
    'A data em que o termo de abertura é lavrado. É necessária antes de avançar para assinatura.',
  'books.termo.field.pageCapacity': 'Número de páginas',
  'books.termo.field.pageCapacityHelp':
    'O tamanho declarado do livro, em páginas. Depois de selado, não muda.',
  'books.termo.field.bookNumber': 'Número do livro',
  'books.termo.field.bookNumberHelp':
    'A identificação "livro n.º N". É uma indicação sua; nenhuma norma a exige.',
  'books.termo.field.place': 'Local',
  'books.termo.field.placeHelp':
    'O local onde o termo é lavrado. A sua ausência não é uma falha de conformidade.',
  'books.termo.field.predecessor': 'Livro anterior',
  'books.termo.field.predecessorHelp':
    'O livro que este sucede, escolhido entre os livros da entidade. É o elo que forma a cadeia verificável.',
  'books.termo.field.predecessorNone': 'Nenhum',
  'books.termo.field.predecessorNote': 'Livro anterior (referência)',
  'books.termo.field.predecessorNoteHelp':
    'Referência a um livro anterior em papel ou fora do sistema. É apenas uma indicação e não substitui o elo ao livro anterior.',

  // — Colunas de signatários + qualidade "Outra" ————————————————————————————
  'books.termo.signatory.name': 'Nome',
  'books.termo.signatory.nameHelp': 'O nome de quem assina o termo.',
  'books.termo.signatory.capacity': 'Qualidade',
  'books.termo.signatory.capacityHelp':
    'A qualidade em que a pessoa assina. A lei admite gerência, administração, membros do órgão, secretário da sociedade e presidente da mesa da assembleia geral.',
  'books.termo.signatory.email': 'Correio eletrónico',
  'books.termo.signatory.emailHelp': 'Contacto opcional para coordenar a assinatura.',
  'books.termo.signatory.order': 'Ordem',
  'books.termo.signatory.orderHelp': 'A ordem pela qual os signatários assinam.',
  'books.termo.signatory.required': 'Exigido',
  'books.termo.signatory.other': 'Outra qualidade',
  'books.termo.signatory.otherPlaceholder': 'Indique qual',
  'books.termo.signatory.otherHelp':
    'Indique a qualidade quando não consta da lista. É uma indicação sua: não conta como a qualidade legalmente admitida, nem para o mínimo de gerência ou administração.',
  'books.termo.signatory.signed': 'Assinado',
  'books.termo.signatory.unsigned': 'Por assinar',
} as const;

/** The key set the termo/opening copy resolves. */
export type TermoCopyKey = keyof typeof termoPtPT;

export const termoEnglish = {
  'books.termo.title': 'Opening term',
  'books.termo.subtitle':
    'A document in its own right — drawn up and signed — that opens the book, distinct from the mechanical act of opening it.',
  'books.termo.loading': 'Loading the opening term…',
  'books.termo.loadError': 'Could not load the opening term.',
  'books.termo.none':
    'This book was opened in a single step and has no separately editable opening term.',

  'books.termo.state.Draft': 'Draft',
  'books.termo.state.Signing': 'Signing',
  'books.termo.state.Sealed': 'Sealed',
  'books.termo.state.DraftHint': 'The title, body, fields and signatories are freely editable.',
  'books.termo.state.SigningHint':
    'The content and signatory set are frozen; signatures are being collected.',
  'books.termo.state.SealedHint':
    'The term has taken effect and the book was opened. It is immutable.',

  'books.termo.kind.Abertura': 'Opening',
  'books.termo.kind.Encerramento': 'Closing',

  'books.termo.policy.AllRequired': 'Every required signatory signs',
  'books.termo.policy.AtLeast': 'At least {n} of the required signatories sign',
  'books.termo.policy.SingleQualifying': 'A single qualifying signatory is enough',
  'books.termo.completion.complete': 'Signatures complete.',
  'books.termo.completion.pending': '{count} of {total} required signatures still missing.',

  'books.termo.rule.allowList':
    'To draw up the term, the law admits only these capacities: management, administration, members of the body it concerns, the company secretary (where one exists) and the chair of the general meeting.',
  'books.termo.rule.atLeastOne': 'At least one signatory is required.',

  'books.termo.action.advance': 'Advance to signing',
  'books.termo.action.advanceHint':
    'Freezes the content and the signatory set so signatures can be collected. From here the term is no longer editable.',
  'books.termo.action.sign': 'Sign',
  'books.termo.action.open': 'Open book',
  'books.termo.action.openHint': 'Seals the signed term and opens the book.',
  'books.termo.action.advancing': 'Freezing…',
  'books.termo.action.signing': 'Signing…',
  'books.termo.action.opening': 'Opening…',

  'books.termo.open.notSignedTitle': 'The term is not yet cryptographically signed',
  'books.termo.open.notSignedBody':
    'The book cannot be opened: every required signatory must have a real PAdES signature over the term’s PDF. Real per-signatory signing is a tracked follow-up; until it lands, the book is not opened and the term stays in signing.',
  'books.termo.open.error': 'Could not open the book from the term.',

  'books.termo.field.entity': 'Entity',
  'books.termo.field.entityHelp': 'The legal person the book belongs to.',
  'books.termo.field.bookKind': 'Book type',
  'books.termo.field.bookKindHelp':
    'The body or purpose the book is for — general meeting, management/administration, audit board or condominium — or “Other” for a type you describe.',
  'books.termo.field.bookKindOther': 'Other',
  'books.termo.field.kindLabel': 'Custom type',
  'books.termo.field.kindLabelHelp':
    'Describe the book type. This is your own label, not a legally recognised book class.',
  'books.termo.field.purpose': 'Purpose',
  'books.termo.field.purposeHelp':
    'What the book is for (for example, “Minute book of the general meeting”). Pick a suggestion or write your own.',
  'books.termo.field.purposeOther': 'Other…',
  'books.termo.field.numberingScheme': 'Numbering',
  'books.termo.field.numberingSchemeHelp':
    'How minutes are numbered in this book: sequential or loose-leaf.',
  'books.termo.field.openingDate': 'Opening date',
  'books.termo.field.openingDateHelp':
    'The date the opening term is drawn up. It is required before advancing to signing.',
  'books.termo.field.pageCapacity': 'Page count',
  'books.termo.field.pageCapacityHelp':
    'The book’s declared size, in pages. Once sealed, it does not change.',
  'books.termo.field.bookNumber': 'Book number',
  'books.termo.field.bookNumberHelp':
    'The “book no. N” identity. This is your own label; no rule requires it.',
  'books.termo.field.place': 'Place',
  'books.termo.field.placeHelp': 'Where the term is drawn up. Its absence is not a compliance gap.',
  'books.termo.field.predecessor': 'Predecessor book',
  'books.termo.field.predecessorHelp':
    'The book this one succeeds, chosen from the entity’s books. It is the link that forms the verifiable chain.',
  'books.termo.field.predecessorNone': 'None',
  'books.termo.field.predecessorNote': 'Predecessor book (reference)',
  'books.termo.field.predecessorNoteHelp':
    'A reference to a paper or off-system predecessor book. It is only a note and does not stand in for the link to the predecessor book.',

  'books.termo.signatory.name': 'Name',
  'books.termo.signatory.nameHelp': 'The name of whoever signs the term.',
  'books.termo.signatory.capacity': 'Capacity',
  'books.termo.signatory.capacityHelp':
    'The capacity the person signs in. The law admits management, administration, members of the body, the company secretary and the chair of the general meeting.',
  'books.termo.signatory.email': 'Email',
  'books.termo.signatory.emailHelp': 'Optional contact for coordinating the signature.',
  'books.termo.signatory.order': 'Order',
  'books.termo.signatory.orderHelp': 'The order in which signatories sign.',
  'books.termo.signatory.required': 'Required',
  'books.termo.signatory.other': 'Other capacity',
  'books.termo.signatory.otherPlaceholder': 'State which',
  'books.termo.signatory.otherHelp':
    'State the capacity when it is not in the list. This is your own label: it does not count as a legally admitted capacity, nor toward the management/administration minimum.',
  'books.termo.signatory.signed': 'Signed',
  'books.termo.signatory.unsigned': 'Unsigned',
} as const satisfies Record<TermoCopyKey, string>;

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale gets the English
 * fallback — the exact split the catalog spread uses, kept here because t23 may not touch the locked
 * catalogs. Folding into the catalog later is a mechanical spread.
 */
export function useTermoCopy(): Record<TermoCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? termoPtPT : termoEnglish;
}

/**
 * The termo copy translate hook, shaped like `useT`:
 * `const tt = useTermoT(); tt('books.termo.title')`. Supports the same `{placeholder}` interpolation
 * as the catalog (used here only for numeric counts).
 */
export function useTermoT(): (key: TermoCopyKey, params?: TParams) => string {
  const copy = useTermoCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
