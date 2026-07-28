/**
 * Copy for the registrable-entity-types card in Configurações (t54 §6.5).
 *
 * **Why this module is self-contained, not folded into the catalogs.** The 14 locale catalogs
 * (`locales/*.ts` + `reviewedIdenticalValues.ts`) sit under a single-writer serial lock during the
 * batch, so t54 may not add the usual "one import + one spread line per locale" wiring. This module
 * owns its keys end to end and exposes its own locale-aware resolver ({@link useEntityKindsT}); a
 * page reads copy through it exactly as through `useT`, so nothing in the shared catalog moves and
 * the catalog-leak / literal-copy gates never see these strings. Same shape as its sibling
 * `tableColumnsFallback.ts`; folding these into the catalog later is a mechanical spread.
 *
 * The ten legal-type names and the five family names are NOT here — they already exist in every
 * catalog as `enum.entityKind.*` / `enum.entityFamily.*` and are read through
 * `entityKindLabels` / `entityFamilyLabels`. Only genuinely new strings live here.
 *
 * ## Two copy rules this module is written against
 *
 * 1. **No noun is interpolated into an inflected sentence** (memory
 *    `i18n-interpolated-nouns-break-agreement`). The only interpolation anywhere below is
 *    `{count}`, a number. Where a count crosses the singular/plural boundary the two readings are
 *    written out as two separate, self-contained sentences rather than patched with a suffix — a
 *    string built as `«1 entidades»` would be wrong Portuguese and wrong English alike.
 * 2. **The consequence is stated as what it is: consequential, not destructive.** Narrowing the
 *    registrable types deletes nothing, touches no sealed act and revokes no access; it stops
 *    *future* registrations. The copy says exactly that, and says the reassuring half out loud,
 *    because dressing an ordinary administrative choice in destructive vocabulary is what teaches
 *    operators to click through the guards that do matter.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const entityKindsPtPT = {
  // — O cartão ————————————————————————————————————————————————————————————
  'entityKinds.card.title': 'Tipos de entidade que podem ser registados',
  'entityKinds.card.hint':
    'Escolha que tipos legais ficam disponíveis ao registar uma nova entidade. Esta escolha aplica-se apenas ao registo: as entidades já registadas mantêm-se listadas, acessíveis, editáveis e válidas, os seus livros e atos continuam a funcionar e nenhum ato já selado é afetado.',

  // — O estado «todos» é nomeável, nunca uma seleção vazia (§6.5.1) ————————————
  // Duas opções exclusivas. Sem esta escolha explícita, desmarcar tudo produziria uma lista vazia
  // — que significa «todos os tipos» — e um administrador que desmarcasse tudo à espera de
  // *nenhum* obteria *todos*. Aqui «todos» tem um nome próprio e escolhe-se de propósito.
  'entityKinds.mode.legend': 'Tipos disponíveis',
  'entityKinds.mode.all': 'Todos os tipos',
  'entityKinds.mode.all.hint':
    'Qualquer um dos dez tipos legais pode ser registado. É a predefinição.',
  'entityKinds.mode.selected': 'Apenas os tipos selecionados',
  'entityKinds.mode.selected.hint':
    'Só os tipos assinalados em baixo aparecem no formulário de registo. Os restantes deixam de poder ser escolhidos ao registar.',

  // — A grelha ————————————————————————————————————————————————————————————
  'entityKinds.grid.aria': 'Tipos legais disponíveis para registo',
  'entityKinds.head.kind': 'Tipo',
  'entityKinds.head.available': 'Disponível',
  'entityKinds.family.all': 'Todos os desta família',

  // Seleção vazia: não é um estado gravável. A frase diz para onde ir, porque o estado pretendido
  // tem um nome e está mesmo por cima.
  'entityKinds.empty.error':
    'Selecione pelo menos um tipo. Para permitir todos, escolha «Todos os tipos» em cima.',

  // — Aviso de tipos com entidades registadas (t56, patamar T1, danger: false) ——————
  'entityKinds.inUse.title': 'Este tipo já tem entidades registadas',
  'entityKinds.inUse.body.one':
    'Uma entidade registada tem este tipo. Deixará de ser possível registar novas entidades com ele.',
  'entityKinds.inUse.body.many':
    '{count} entidades registadas têm este tipo. Deixará de ser possível registar novas entidades com ele.',
  'entityKinds.inUse.reassurance':
    'Nada é apagado. As entidades existentes continuam listadas, acessíveis e editáveis, os seus livros e atos continuam a funcionar e os atos já selados mantêm-se intactos.',
  'entityKinds.inUse.confirm': 'Deixar de oferecer este tipo',
  'entityKinds.inUse.pending': 'A aplicar…',
  'entityKinds.inUse.badge.one': '1 entidade registada',
  'entityKinds.inUse.badge.many': '{count} entidades registadas',
} as const;

/** The key set the entity-types card resolves. */
export type EntityKindsCopyKey = keyof typeof entityKindsPtPT;

export const entityKindsEnglish = {
  'entityKinds.card.title': 'Entity types that can be registered',
  'entityKinds.card.hint':
    'Choose which legal types are available when registering a new entity. This applies to registration only: entities already registered stay listed, reachable, editable and valid, their books and acts keep working, and no sealed act is affected.',
  'entityKinds.mode.legend': 'Available types',
  'entityKinds.mode.all': 'All types',
  'entityKinds.mode.all.hint': 'Any of the ten legal types can be registered. This is the default.',
  'entityKinds.mode.selected': 'Only the selected types',
  'entityKinds.mode.selected.hint':
    'Only the types ticked below appear in the registration form. The rest can no longer be chosen when registering.',
  'entityKinds.grid.aria': 'Legal types available for registration',
  'entityKinds.head.kind': 'Type',
  'entityKinds.head.available': 'Available',
  'entityKinds.family.all': 'All in this family',
  'entityKinds.empty.error':
    'Select at least one type. To allow every type, choose “All types” above.',
  'entityKinds.inUse.title': 'This type already has registered entities',
  'entityKinds.inUse.body.one':
    'One registered entity has this type. New entities can no longer be registered with it.',
  'entityKinds.inUse.body.many':
    '{count} registered entities have this type. New entities can no longer be registered with it.',
  'entityKinds.inUse.reassurance':
    'Nothing is deleted. Existing entities stay listed, reachable and editable, their books and acts keep working, and sealed acts are untouched.',
  'entityKinds.inUse.confirm': 'Stop offering this type',
  'entityKinds.inUse.pending': 'Applying…',
  'entityKinds.inUse.badge.one': '1 registered entity',
  'entityKinds.inUse.badge.many': '{count} registered entities',
} as const satisfies Record<EntityKindsCopyKey, string>;

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale gets the English
 * fallback — the same split the sibling fallback modules use while the catalogs are locked.
 */
export function useEntityKindsCopy(): Record<EntityKindsCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? entityKindsPtPT : entityKindsEnglish;
}

/**
 * The card's translate hook, shaped like `useT`:
 * `const kt = useEntityKindsT(); kt('entityKinds.card.title')`.
 */
export function useEntityKindsT(): (key: EntityKindsCopyKey, params?: TParams) => string {
  const copy = useEntityKindsCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
