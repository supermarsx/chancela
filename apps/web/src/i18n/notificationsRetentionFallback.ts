/**
 * Centro de Ações — the NEW tab, filter, and retention copy added by t17 (Dispensadas/Reconhecidas
 * sub-tabs, the entities-style free-text filter, the dismissal retention note).
 *
 * **Why this module is self-contained, not folded into the catalogs.** The 14 locale catalogs
 * (`locales/*.ts` + `reviewedIdenticalValues.ts`) are held under a single-writer serial lock across
 * successive i18n batches, so t17's web executor may not add the usual "one import + one spread line
 * per locale" wiring. Instead this module owns its keys end to end and exposes its own locale-aware
 * resolver ({@link useNotificationsExtraT}). The page reads copy through that resolver exactly as it
 * would through `useT`, so nothing in the shared catalog moves and the catalog-leak / literal-copy
 * gates never see these strings. It follows the same shape as `serverEnvFallback.ts` (a source object
 * plus per-locale maps that `satisfies` its key set); if the catalog lock later releases, folding
 * these in is a mechanical spread and the page can switch to `t()`.
 *
 * **Locale coverage (t58 D5).** The module now carries a real translation for every shipped locale,
 * not just pt-PT + an English fallback. The per-locale maps below are keyed by {@link Locale}; a
 * locale with no dedicated map falls back to English (the source-quality tier). The machine-quality
 * locales (da-DK, sv-SE, sv-FI, fi-FI, pl-PL — and to a lesser degree the Romance set) are flagged
 * for native review in TRANSLATIONS.md, matching the repo precedent for `machine`-tier copy.
 *
 * Two copy rules hold here:
 * 1. **Say only what the payload proves.** The retention interval is server configuration and is NOT
 *    carried in the triage response, so the note names the mechanism ("período de retenção definido
 *    no servidor") without asserting a specific day count the client cannot know.
 * 2. **No legal / evidentiary claim.** Dismissed triage is disposable UI state, never an instrument;
 *    the copy describes housekeeping, never "valor probatório" (memory `tagline-no-valor-probatorio`).
 *
 * No anglicisms are invented; each locale uses its own natural, correctly-inflected words.
 */
import { useMemo } from 'react';
import type { Locale } from '../api/types';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const notificationsExtraPtPT = {
  // — Sub-separadores resolvidos (D2: Dispensadas + Reconhecidas) ————————————
  // "Dispensadas"/"Reconhecidas" mirror the shipped triage vocabulary (verb "Dispensar" → status
  // "Dispensada"; verb "Reconhecer" → status "Reconhecida"), keeping the surface consistent.
  'notifications.filter.dismissed': 'Dispensadas',
  'notifications.filter.acknowledged': 'Reconhecidas',
  'notifications.empty.dismissed': 'Sem notificações dispensadas.',
  'notifications.empty.acknowledged': 'Sem notificações reconhecidas.',

  // — Nota de retenção ————————————————————————————————————————————————————
  'notifications.retention.note':
    'As notificações dispensadas são removidas automaticamente ao fim do período de retenção definido no servidor.',

  // — Filtro ao estilo das entidades ——————————————————————————————————————
  'notifications.filter.aria': 'Filtrar notificações',
  'notifications.filter.search.label': 'Pesquisar',
  'notifications.filter.search.placeholder': 'Pesquisar por título, detalhe ou etiqueta',
  'notifications.filter.tone.label': 'Tom',
  'notifications.filter.tone.all': 'Todos os tons',
  'notifications.filter.tone.error': 'Crítico',
  'notifications.filter.tone.warn': 'Aviso',
  'notifications.filter.tone.accent': 'Destaque',
  'notifications.filter.tone.neutral': 'Neutro',
  'notifications.filter.clear.aria': 'Limpar filtros',
  'notifications.filter.empty': 'Nenhuma notificação corresponde ao filtro.',
} as const;

/** The key set the Centro de Ações extra copy resolves. */
export type NotificationsExtraCopyKey = keyof typeof notificationsExtraPtPT;

type ExtraCopy = Record<NotificationsExtraCopyKey, string>;

// en-US is the authoring source (t40); en-GB shares it (no divergent spelling in this key set).
export const notificationsExtraEnglish = {
  'notifications.filter.dismissed': 'Dismissed',
  'notifications.filter.acknowledged': 'Acknowledged',
  'notifications.empty.dismissed': 'No dismissed notifications.',
  'notifications.empty.acknowledged': 'No acknowledged notifications.',

  'notifications.retention.note':
    'Dismissed notifications are removed automatically once the retention period configured on the server elapses.',

  'notifications.filter.aria': 'Filter notifications',
  'notifications.filter.search.label': 'Search',
  'notifications.filter.search.placeholder': 'Search by title, detail or badge',
  'notifications.filter.tone.label': 'Tone',
  'notifications.filter.tone.all': 'All tones',
  'notifications.filter.tone.error': 'Critical',
  'notifications.filter.tone.warn': 'Warning',
  'notifications.filter.tone.accent': 'Highlight',
  'notifications.filter.tone.neutral': 'Neutral',
  'notifications.filter.clear.aria': 'Clear filters',
  'notifications.filter.empty': 'No notification matches the filter.',
} as const satisfies ExtraCopy;

const notificationsExtraPtBR = {
  'notifications.filter.dismissed': 'Dispensadas',
  'notifications.filter.acknowledged': 'Reconhecidas',
  'notifications.empty.dismissed': 'Nenhuma notificação dispensada.',
  'notifications.empty.acknowledged': 'Nenhuma notificação reconhecida.',
  'notifications.retention.note':
    'As notificações dispensadas são removidas automaticamente ao término do período de retenção configurado no servidor.',
  'notifications.filter.aria': 'Filtrar notificações',
  'notifications.filter.search.label': 'Pesquisar',
  'notifications.filter.search.placeholder': 'Pesquisar por título, detalhe ou etiqueta',
  'notifications.filter.tone.label': 'Tom',
  'notifications.filter.tone.all': 'Todos os tons',
  'notifications.filter.tone.error': 'Crítico',
  'notifications.filter.tone.warn': 'Aviso',
  'notifications.filter.tone.accent': 'Destaque',
  'notifications.filter.tone.neutral': 'Neutro',
  'notifications.filter.clear.aria': 'Limpar filtros',
  'notifications.filter.empty': 'Nenhuma notificação corresponde ao filtro.',
} as const satisfies ExtraCopy;

const notificationsExtraEsES = {
  'notifications.filter.dismissed': 'Descartadas',
  'notifications.filter.acknowledged': 'Reconocidas',
  'notifications.empty.dismissed': 'No hay notificaciones descartadas.',
  'notifications.empty.acknowledged': 'No hay notificaciones reconocidas.',
  'notifications.retention.note':
    'Las notificaciones descartadas se eliminan automáticamente cuando transcurre el período de retención configurado en el servidor.',
  'notifications.filter.aria': 'Filtrar notificaciones',
  'notifications.filter.search.label': 'Buscar',
  'notifications.filter.search.placeholder': 'Buscar por título, detalle o etiqueta',
  'notifications.filter.tone.label': 'Tono',
  'notifications.filter.tone.all': 'Todos los tonos',
  'notifications.filter.tone.error': 'Crítico',
  'notifications.filter.tone.warn': 'Advertencia',
  'notifications.filter.tone.accent': 'Destacado',
  'notifications.filter.tone.neutral': 'Neutro',
  'notifications.filter.clear.aria': 'Limpiar filtros',
  'notifications.filter.empty': 'Ninguna notificación coincide con el filtro.',
} as const satisfies ExtraCopy;

const notificationsExtraFrFR = {
  'notifications.filter.dismissed': 'Ignorées',
  'notifications.filter.acknowledged': 'Acquittées',
  'notifications.empty.dismissed': 'Aucune notification ignorée.',
  'notifications.empty.acknowledged': 'Aucune notification acquittée.',
  'notifications.retention.note':
    'Les notifications ignorées sont supprimées automatiquement à l’expiration de la période de rétention configurée sur le serveur.',
  'notifications.filter.aria': 'Filtrer les notifications',
  'notifications.filter.search.label': 'Rechercher',
  'notifications.filter.search.placeholder': 'Rechercher par titre, détail ou étiquette',
  'notifications.filter.tone.label': 'Tonalité',
  'notifications.filter.tone.all': 'Toutes les tonalités',
  'notifications.filter.tone.error': 'Critique',
  'notifications.filter.tone.warn': 'Avertissement',
  'notifications.filter.tone.accent': 'En évidence',
  'notifications.filter.tone.neutral': 'Neutre',
  'notifications.filter.clear.aria': 'Effacer les filtres',
  'notifications.filter.empty': 'Aucune notification ne correspond au filtre.',
} as const satisfies ExtraCopy;

const notificationsExtraDeDE = {
  'notifications.filter.dismissed': 'Verworfen',
  'notifications.filter.acknowledged': 'Bestätigt',
  'notifications.empty.dismissed': 'Keine verworfenen Benachrichtigungen.',
  'notifications.empty.acknowledged': 'Keine bestätigten Benachrichtigungen.',
  'notifications.retention.note':
    'Verworfene Benachrichtigungen werden automatisch entfernt, sobald die auf dem Server konfigurierte Aufbewahrungsfrist abgelaufen ist.',
  'notifications.filter.aria': 'Benachrichtigungen filtern',
  'notifications.filter.search.label': 'Suchen',
  'notifications.filter.search.placeholder': 'Nach Titel, Detail oder Kennzeichen suchen',
  'notifications.filter.tone.label': 'Ton',
  'notifications.filter.tone.all': 'Alle Töne',
  'notifications.filter.tone.error': 'Kritisch',
  'notifications.filter.tone.warn': 'Warnung',
  'notifications.filter.tone.accent': 'Hervorhebung',
  'notifications.filter.tone.neutral': 'Neutral',
  'notifications.filter.clear.aria': 'Filter zurücksetzen',
  'notifications.filter.empty': 'Keine Benachrichtigung entspricht dem Filter.',
} as const satisfies ExtraCopy;

const notificationsExtraItIT = {
  'notifications.filter.dismissed': 'Ignorate',
  'notifications.filter.acknowledged': 'Confermate',
  'notifications.empty.dismissed': 'Nessuna notifica ignorata.',
  'notifications.empty.acknowledged': 'Nessuna notifica confermata.',
  'notifications.retention.note':
    'Le notifiche ignorate vengono rimosse automaticamente al termine del periodo di conservazione configurato sul server.',
  'notifications.filter.aria': 'Filtra le notifiche',
  'notifications.filter.search.label': 'Cerca',
  'notifications.filter.search.placeholder': 'Cerca per titolo, dettaglio o etichetta',
  'notifications.filter.tone.label': 'Tono',
  'notifications.filter.tone.all': 'Tutti i toni',
  'notifications.filter.tone.error': 'Critico',
  'notifications.filter.tone.warn': 'Avviso',
  'notifications.filter.tone.accent': 'In evidenza',
  'notifications.filter.tone.neutral': 'Neutro',
  'notifications.filter.clear.aria': 'Cancella filtri',
  'notifications.filter.empty': 'Nessuna notifica corrisponde al filtro.',
} as const satisfies ExtraCopy;

const notificationsExtraNlNL = {
  'notifications.filter.dismissed': 'Genegeerd',
  'notifications.filter.acknowledged': 'Bevestigd',
  'notifications.empty.dismissed': 'Geen genegeerde meldingen.',
  'notifications.empty.acknowledged': 'Geen bevestigde meldingen.',
  'notifications.retention.note':
    'Genegeerde meldingen worden automatisch verwijderd zodra de op de server ingestelde bewaartermijn is verstreken.',
  'notifications.filter.aria': 'Meldingen filteren',
  'notifications.filter.search.label': 'Zoeken',
  'notifications.filter.search.placeholder': 'Zoeken op titel, detail of label',
  'notifications.filter.tone.label': 'Toon',
  'notifications.filter.tone.all': 'Alle tonen',
  'notifications.filter.tone.error': 'Kritiek',
  'notifications.filter.tone.warn': 'Waarschuwing',
  'notifications.filter.tone.accent': 'Uitgelicht',
  'notifications.filter.tone.neutral': 'Neutraal',
  'notifications.filter.clear.aria': 'Filters wissen',
  'notifications.filter.empty': 'Geen melding komt overeen met het filter.',
} as const satisfies ExtraCopy;

const notificationsExtraDaDK = {
  'notifications.filter.dismissed': 'Afvist',
  'notifications.filter.acknowledged': 'Bekræftet',
  'notifications.empty.dismissed': 'Ingen afviste notifikationer.',
  'notifications.empty.acknowledged': 'Ingen bekræftede notifikationer.',
  'notifications.retention.note':
    'Afviste notifikationer fjernes automatisk, når den opbevaringsperiode, der er konfigureret på serveren, udløber.',
  'notifications.filter.aria': 'Filtrér notifikationer',
  'notifications.filter.search.label': 'Søg',
  'notifications.filter.search.placeholder': 'Søg efter titel, detalje eller mærkat',
  'notifications.filter.tone.label': 'Tone',
  'notifications.filter.tone.all': 'Alle toner',
  'notifications.filter.tone.error': 'Kritisk',
  'notifications.filter.tone.warn': 'Advarsel',
  'notifications.filter.tone.accent': 'Fremhævet',
  'notifications.filter.tone.neutral': 'Neutral',
  'notifications.filter.clear.aria': 'Ryd filtre',
  'notifications.filter.empty': 'Ingen notifikation matcher filteret.',
} as const satisfies ExtraCopy;

const notificationsExtraSvSE = {
  'notifications.filter.dismissed': 'Avfärdade',
  'notifications.filter.acknowledged': 'Bekräftade',
  'notifications.empty.dismissed': 'Inga avfärdade aviseringar.',
  'notifications.empty.acknowledged': 'Inga bekräftade aviseringar.',
  'notifications.retention.note':
    'Avfärdade aviseringar tas bort automatiskt när den lagringsperiod som konfigurerats på servern har löpt ut.',
  'notifications.filter.aria': 'Filtrera aviseringar',
  'notifications.filter.search.label': 'Sök',
  'notifications.filter.search.placeholder': 'Sök efter titel, detalj eller etikett',
  'notifications.filter.tone.label': 'Ton',
  'notifications.filter.tone.all': 'Alla toner',
  'notifications.filter.tone.error': 'Kritisk',
  'notifications.filter.tone.warn': 'Varning',
  'notifications.filter.tone.accent': 'Framhävd',
  'notifications.filter.tone.neutral': 'Neutral',
  'notifications.filter.clear.aria': 'Rensa filter',
  'notifications.filter.empty': 'Ingen avisering matchar filtret.',
} as const satisfies ExtraCopy;

const notificationsExtraFiFI = {
  'notifications.filter.dismissed': 'Hylätyt',
  'notifications.filter.acknowledged': 'Kuitatut',
  'notifications.empty.dismissed': 'Ei hylättyjä ilmoituksia.',
  'notifications.empty.acknowledged': 'Ei kuitattuja ilmoituksia.',
  'notifications.retention.note':
    'Hylätyt ilmoitukset poistetaan automaattisesti, kun palvelimeen määritetty säilytysaika päättyy.',
  'notifications.filter.aria': 'Suodata ilmoituksia',
  'notifications.filter.search.label': 'Hae',
  'notifications.filter.search.placeholder': 'Hae otsikon, tiedon tai tunnisteen mukaan',
  'notifications.filter.tone.label': 'Sävy',
  'notifications.filter.tone.all': 'Kaikki sävyt',
  'notifications.filter.tone.error': 'Kriittinen',
  'notifications.filter.tone.warn': 'Varoitus',
  'notifications.filter.tone.accent': 'Korostus',
  'notifications.filter.tone.neutral': 'Neutraali',
  'notifications.filter.clear.aria': 'Tyhjennä suodattimet',
  'notifications.filter.empty': 'Mikään ilmoitus ei vastaa suodatinta.',
} as const satisfies ExtraCopy;

const notificationsExtraPlPL = {
  'notifications.filter.dismissed': 'Odrzucone',
  'notifications.filter.acknowledged': 'Potwierdzone',
  'notifications.empty.dismissed': 'Brak odrzuconych powiadomień.',
  'notifications.empty.acknowledged': 'Brak potwierdzonych powiadomień.',
  'notifications.retention.note':
    'Odrzucone powiadomienia są usuwane automatycznie po upływie okresu przechowywania skonfigurowanego na serwerze.',
  'notifications.filter.aria': 'Filtruj powiadomienia',
  'notifications.filter.search.label': 'Szukaj',
  'notifications.filter.search.placeholder': 'Szukaj według tytułu, szczegółu lub etykiety',
  'notifications.filter.tone.label': 'Ton',
  'notifications.filter.tone.all': 'Wszystkie tony',
  'notifications.filter.tone.error': 'Krytyczny',
  'notifications.filter.tone.warn': 'Ostrzeżenie',
  'notifications.filter.tone.accent': 'Wyróżnienie',
  'notifications.filter.tone.neutral': 'Neutralny',
  'notifications.filter.clear.aria': 'Wyczyść filtry',
  'notifications.filter.empty': 'Żadne powiadomienie nie pasuje do filtra.',
} as const satisfies ExtraCopy;

/**
 * Per-locale copy. Any locale absent here (currently none) would fall through to English; the map is
 * deliberately complete so every shipped locale renders its own words. sv-FI reuses the sv-SE copy
 * (Finland-Swedish is orthographically identical for this key set).
 */
const NOTIFICATIONS_EXTRA_BY_LOCALE: Partial<Record<Locale, ExtraCopy>> = {
  'en-US': notificationsExtraEnglish,
  'en-GB': notificationsExtraEnglish,
  'pt-PT': notificationsExtraPtPT,
  'pt-BR': notificationsExtraPtBR,
  'es-ES': notificationsExtraEsES,
  'fr-FR': notificationsExtraFrFR,
  'de-DE': notificationsExtraDeDE,
  'it-IT': notificationsExtraItIT,
  'nl-NL': notificationsExtraNlNL,
  'da-DK': notificationsExtraDaDK,
  'sv-SE': notificationsExtraSvSE,
  'sv-FI': notificationsExtraSvSE,
  'fi-FI': notificationsExtraFiFI,
  'pl-PL': notificationsExtraPlPL,
};

/**
 * The active copy map: the reviewed source strings for the active locale, or the English source-tier
 * fallback for any locale not yet mapped — the same split `serverEnvFallback` uses.
 */
export function useNotificationsExtraCopy(): ExtraCopy {
  const locale = useActiveLocale();
  return NOTIFICATIONS_EXTRA_BY_LOCALE[locale] ?? notificationsExtraEnglish;
}

/**
 * The page's extra translate hook, shaped like {@link useT}:
 * `const nt = useNotificationsExtraT(); nt('notifications.filter.dismissed')`.
 */
export function useNotificationsExtraT(): (
  key: NotificationsExtraCopyKey,
  params?: TParams,
) => string {
  const copy = useNotificationsExtraCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
