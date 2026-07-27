/**
 * Copy for the five RGPD register RECORD PAGES (t55) — the page titles, the breadcrumb label, the
 * record-not-found sentences and the back-to-list link.
 *
 * **Why this module is self-contained, not folded into the catalogs.** The 14 locale catalogs
 * (`locales/*.ts` + `reviewedIdenticalValues.ts`) are held under a single-writer serial lock across
 * successive i18n batches, so t55 may not add the usual "one import + one spread line per locale"
 * wiring. This module owns its key set end to end and exposes its own locale-aware resolver
 * ({@link usePrivacyPagesT}), shaped exactly like `useT`. It follows `privacyLegalHoldFallback.ts`
 * and `trustSectionsFallback.ts`; folding these in later is a mechanical spread.
 *
 * **Everything else is REUSED from the catalogs.** Field labels, hints, help text, status and risk
 * labels, the "Cancelar"/"Guardar alterações"/"Criar registo" actions and the created/updated
 * toasts already exist in all 14 locales and are read through `t()`. Only what the pages genuinely
 * introduce lives here.
 *
 * ## Two rules this key set is shaped by
 *
 * 1. **No interpolated nouns.** The obvious design — one `'New {register}'` template with the
 *    register name substituted in — is wrong in most of these languages: `registo` is masculine and
 *    `AIPD` (avaliação) is feminine, so pt-PT alone needs both *Novo* and *Nova*; French, Spanish,
 *    Italian, German, the Nordic languages and Polish each break their own way. Every title and
 *    every not-found line is therefore a COMPLETE sentence, written per register per locale.
 * 2. **Each locale keeps its own register name.** These are not translations of the Portuguese
 *    phrasing; each locale reuses the term its catalog already ships — fr-FR *Sous-traitants RGPD*,
 *    de-DE *DSGVO-Auftragsverarbeiter*, nl-NL *AVG-verwerkers*, pl-PL *Podmioty przetwarzające
 *    RODO*. pt-PT carries the reviewed pt-PT terminology (*Registo de atividades de tratamento*,
 *    RGPD art. 30.º; *AIPD*, art. 35.º; *procedimento de resposta a violações de dados pessoais*,
 *    art. 4.º(12)); pt-BR deliberately does NOT copy it, because Brazil's statute is the LGPD and
 *    the European spellings would assert the wrong law.
 */
import { useMemo } from 'react';
import type { Locale } from '../api/types';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const privacyPagesPtPT = {
  'settings.privacy.page.crumb': 'Privacidade',

  'settings.privacy.page.new.processor': 'Novo registo de atividades de tratamento',
  'settings.privacy.page.new.dpia': 'Nova AIPD',
  'settings.privacy.page.new.breach': 'Novo procedimento de resposta a violações de dados pessoais',
  'settings.privacy.page.new.transfer': 'Novo controlo de transferência',
  'settings.privacy.page.new.retention': 'Nova política de retenção',

  'settings.privacy.page.edit.processor': 'Editar registo de atividades de tratamento',
  'settings.privacy.page.edit.dpia': 'Editar AIPD',
  'settings.privacy.page.edit.breach':
    'Editar procedimento de resposta a violações de dados pessoais',
  'settings.privacy.page.edit.transfer': 'Editar controlo de transferência',
  'settings.privacy.page.edit.retention': 'Editar política de retenção',

  'settings.privacy.page.notFound.processor':
    'Não foi encontrado nenhum registo de atividades de tratamento com este identificador.',
  'settings.privacy.page.notFound.dpia': 'Não foi encontrada nenhuma AIPD com este identificador.',
  'settings.privacy.page.notFound.breach':
    'Não foi encontrado nenhum procedimento de resposta a violações de dados pessoais com este identificador.',
  'settings.privacy.page.notFound.transfer':
    'Não foi encontrado nenhum controlo de transferência com este identificador.',
  'settings.privacy.page.notFound.retention':
    'Não foi encontrada nenhuma política de retenção com este identificador.',

  'settings.privacy.page.backToList': 'Voltar à privacidade',
} as const;

/** The key set this module resolves. */
export type PrivacyPagesCopyKey = keyof typeof privacyPagesPtPT;

type PrivacyPagesCopy = Record<PrivacyPagesCopyKey, string>;

// en-US is the authoring source (t40); en-GB shares it — no divergent spelling in this key set.
export const privacyPagesEnglish = {
  'settings.privacy.page.crumb': 'Privacy',

  'settings.privacy.page.new.processor': 'New GDPR processor',
  'settings.privacy.page.new.dpia': 'New DPIA',
  'settings.privacy.page.new.breach': 'New breach-response playbook',
  'settings.privacy.page.new.transfer': 'New transfer control',
  'settings.privacy.page.new.retention': 'New retention policy',

  'settings.privacy.page.edit.processor': 'Edit GDPR processor',
  'settings.privacy.page.edit.dpia': 'Edit DPIA',
  'settings.privacy.page.edit.breach': 'Edit breach-response playbook',
  'settings.privacy.page.edit.transfer': 'Edit transfer control',
  'settings.privacy.page.edit.retention': 'Edit retention policy',

  'settings.privacy.page.notFound.processor': 'No GDPR processor was found for this identifier.',
  'settings.privacy.page.notFound.dpia': 'No DPIA was found for this identifier.',
  'settings.privacy.page.notFound.breach':
    'No breach-response playbook was found for this identifier.',
  'settings.privacy.page.notFound.transfer': 'No transfer control was found for this identifier.',
  'settings.privacy.page.notFound.retention': 'No retention policy was found for this identifier.',

  'settings.privacy.page.backToList': 'Back to privacy',
} as const satisfies PrivacyPagesCopy;

// pt-BR keeps its own shipped terms (`Processadores GDPR`, `AIPD`, `Manuais de resposta a
// violações`, `Controles de transferência`) — Brazil is under the LGPD, and "registo"/"controlo"
// are European spellings.
const privacyPagesPtBR = {
  'settings.privacy.page.crumb': 'Privacidade',

  'settings.privacy.page.new.processor': 'Novo processador GDPR',
  'settings.privacy.page.new.dpia': 'Nova AIPD',
  'settings.privacy.page.new.breach': 'Novo manual de resposta a violações',
  'settings.privacy.page.new.transfer': 'Novo controle de transferência',
  'settings.privacy.page.new.retention': 'Nova política de retenção',

  'settings.privacy.page.edit.processor': 'Editar processador GDPR',
  'settings.privacy.page.edit.dpia': 'Editar AIPD',
  'settings.privacy.page.edit.breach': 'Editar manual de resposta a violações',
  'settings.privacy.page.edit.transfer': 'Editar controle de transferência',
  'settings.privacy.page.edit.retention': 'Editar política de retenção',

  'settings.privacy.page.notFound.processor':
    'Nenhum processador GDPR foi encontrado para este identificador.',
  'settings.privacy.page.notFound.dpia': 'Nenhuma AIPD foi encontrada para este identificador.',
  'settings.privacy.page.notFound.breach':
    'Nenhum manual de resposta a violações foi encontrado para este identificador.',
  'settings.privacy.page.notFound.transfer':
    'Nenhum controle de transferência foi encontrado para este identificador.',
  'settings.privacy.page.notFound.retention':
    'Nenhuma política de retenção foi encontrada para este identificador.',

  'settings.privacy.page.backToList': 'Voltar para privacidade',
} as const satisfies PrivacyPagesCopy;

const privacyPagesEsES = {
  'settings.privacy.page.crumb': 'Privacidad',

  'settings.privacy.page.new.processor': 'Nuevo encargado RGPD',
  'settings.privacy.page.new.dpia': 'Nueva EIPD',
  'settings.privacy.page.new.breach': 'Nuevo protocolo de respuesta a brechas',
  'settings.privacy.page.new.transfer': 'Nuevo control de transferencia',
  'settings.privacy.page.new.retention': 'Nueva política de conservación',

  'settings.privacy.page.edit.processor': 'Editar encargado RGPD',
  'settings.privacy.page.edit.dpia': 'Editar EIPD',
  'settings.privacy.page.edit.breach': 'Editar protocolo de respuesta a brechas',
  'settings.privacy.page.edit.transfer': 'Editar control de transferencia',
  'settings.privacy.page.edit.retention': 'Editar política de conservación',

  'settings.privacy.page.notFound.processor':
    'No se encontró ningún encargado RGPD con este identificador.',
  'settings.privacy.page.notFound.dpia': 'No se encontró ninguna EIPD con este identificador.',
  'settings.privacy.page.notFound.breach':
    'No se encontró ningún protocolo de respuesta a brechas con este identificador.',
  'settings.privacy.page.notFound.transfer':
    'No se encontró ningún control de transferencia con este identificador.',
  'settings.privacy.page.notFound.retention':
    'No se encontró ninguna política de conservación con este identificador.',

  'settings.privacy.page.backToList': 'Volver a privacidad',
} as const satisfies PrivacyPagesCopy;

const privacyPagesFrFR = {
  'settings.privacy.page.crumb': 'Confidentialité',

  'settings.privacy.page.new.processor': 'Nouveau sous-traitant RGPD',
  'settings.privacy.page.new.dpia': 'Nouvelle AIPD',
  'settings.privacy.page.new.breach': 'Nouveau plan d’intervention en cas de violation',
  'settings.privacy.page.new.transfer': 'Nouveau contrôle de transfert',
  'settings.privacy.page.new.retention': 'Nouvelle politique de conservation',

  'settings.privacy.page.edit.processor': 'Modifier le sous-traitant RGPD',
  'settings.privacy.page.edit.dpia': 'Modifier l’AIPD',
  'settings.privacy.page.edit.breach': 'Modifier le plan d’intervention en cas de violation',
  'settings.privacy.page.edit.transfer': 'Modifier le contrôle de transfert',
  'settings.privacy.page.edit.retention': 'Modifier la politique de conservation',

  'settings.privacy.page.notFound.processor':
    'Aucun sous-traitant RGPD ne correspond à cet identifiant.',
  'settings.privacy.page.notFound.dpia': 'Aucune AIPD ne correspond à cet identifiant.',
  'settings.privacy.page.notFound.breach':
    'Aucun plan d’intervention en cas de violation ne correspond à cet identifiant.',
  'settings.privacy.page.notFound.transfer':
    'Aucun contrôle de transfert ne correspond à cet identifiant.',
  'settings.privacy.page.notFound.retention':
    'Aucune politique de conservation ne correspond à cet identifiant.',

  'settings.privacy.page.backToList': 'Retour à la confidentialité',
} as const satisfies PrivacyPagesCopy;

const privacyPagesDeDE = {
  'settings.privacy.page.crumb': 'Datenschutz',

  'settings.privacy.page.new.processor': 'Neuer DSGVO-Auftragsverarbeiter',
  'settings.privacy.page.new.dpia': 'Neue DSFA',
  'settings.privacy.page.new.breach': 'Neues Playbook zur Reaktion auf Datenschutzverletzungen',
  'settings.privacy.page.new.transfer': 'Neue Übermittlungskontrolle',
  'settings.privacy.page.new.retention': 'Neue Aufbewahrungsrichtlinie',

  'settings.privacy.page.edit.processor': 'DSGVO-Auftragsverarbeiter bearbeiten',
  'settings.privacy.page.edit.dpia': 'DSFA bearbeiten',
  'settings.privacy.page.edit.breach':
    'Playbook zur Reaktion auf Datenschutzverletzungen bearbeiten',
  'settings.privacy.page.edit.transfer': 'Übermittlungskontrolle bearbeiten',
  'settings.privacy.page.edit.retention': 'Aufbewahrungsrichtlinie bearbeiten',

  'settings.privacy.page.notFound.processor':
    'Zu dieser Kennung wurde kein DSGVO-Auftragsverarbeiter gefunden.',
  'settings.privacy.page.notFound.dpia': 'Zu dieser Kennung wurde keine DSFA gefunden.',
  'settings.privacy.page.notFound.breach':
    'Zu dieser Kennung wurde kein Playbook zur Reaktion auf Datenschutzverletzungen gefunden.',
  'settings.privacy.page.notFound.transfer':
    'Zu dieser Kennung wurde keine Übermittlungskontrolle gefunden.',
  'settings.privacy.page.notFound.retention':
    'Zu dieser Kennung wurde keine Aufbewahrungsrichtlinie gefunden.',

  'settings.privacy.page.backToList': 'Zurück zum Datenschutz',
} as const satisfies PrivacyPagesCopy;

const privacyPagesItIT = {
  'settings.privacy.page.crumb': 'Privacy',

  'settings.privacy.page.new.processor': 'Nuovo responsabile GDPR',
  'settings.privacy.page.new.dpia': 'Nuova DPIA',
  'settings.privacy.page.new.breach': 'Nuovo playbook di risposta alle violazioni',
  'settings.privacy.page.new.transfer': 'Nuovo controllo sui trasferimenti',
  'settings.privacy.page.new.retention': 'Nuovo criterio di conservazione',

  'settings.privacy.page.edit.processor': 'Modifica responsabile GDPR',
  'settings.privacy.page.edit.dpia': 'Modifica DPIA',
  'settings.privacy.page.edit.breach': 'Modifica playbook di risposta alle violazioni',
  'settings.privacy.page.edit.transfer': 'Modifica controllo sui trasferimenti',
  'settings.privacy.page.edit.retention': 'Modifica criterio di conservazione',

  'settings.privacy.page.notFound.processor':
    'Nessun responsabile GDPR trovato per questo identificatore.',
  'settings.privacy.page.notFound.dpia': 'Nessuna DPIA trovata per questo identificatore.',
  'settings.privacy.page.notFound.breach':
    'Nessun playbook di risposta alle violazioni trovato per questo identificatore.',
  'settings.privacy.page.notFound.transfer':
    'Nessun controllo sui trasferimenti trovato per questo identificatore.',
  'settings.privacy.page.notFound.retention':
    'Nessun criterio di conservazione trovato per questo identificatore.',

  'settings.privacy.page.backToList': 'Torna alla privacy',
} as const satisfies PrivacyPagesCopy;

const privacyPagesNlNL = {
  'settings.privacy.page.crumb': 'Privacy',

  'settings.privacy.page.new.processor': 'Nieuwe AVG-verwerker',
  'settings.privacy.page.new.dpia': 'Nieuwe DPIA',
  'settings.privacy.page.new.breach': 'Nieuw draaiboek voor inbreukrespons',
  'settings.privacy.page.new.transfer': 'Nieuwe doorgiftemaatregel',
  'settings.privacy.page.new.retention': 'Nieuw bewaarbeleid',

  'settings.privacy.page.edit.processor': 'AVG-verwerker bewerken',
  'settings.privacy.page.edit.dpia': 'DPIA bewerken',
  'settings.privacy.page.edit.breach': 'Draaiboek voor inbreukrespons bewerken',
  'settings.privacy.page.edit.transfer': 'Doorgiftemaatregel bewerken',
  'settings.privacy.page.edit.retention': 'Bewaarbeleid bewerken',

  'settings.privacy.page.notFound.processor':
    'Er is geen AVG-verwerker gevonden voor deze identificatie.',
  'settings.privacy.page.notFound.dpia': 'Er is geen DPIA gevonden voor deze identificatie.',
  'settings.privacy.page.notFound.breach':
    'Er is geen draaiboek voor inbreukrespons gevonden voor deze identificatie.',
  'settings.privacy.page.notFound.transfer':
    'Er is geen doorgiftemaatregel gevonden voor deze identificatie.',
  'settings.privacy.page.notFound.retention':
    'Er is geen bewaarbeleid gevonden voor deze identificatie.',

  'settings.privacy.page.backToList': 'Terug naar privacy',
} as const satisfies PrivacyPagesCopy;

const privacyPagesDaDK = {
  'settings.privacy.page.crumb': 'Databeskyttelse',

  'settings.privacy.page.new.processor': 'Ny GDPR-databehandler',
  'settings.privacy.page.new.dpia': 'Ny DPIA',
  'settings.privacy.page.new.breach': 'Ny drejebog for brudrespons',
  'settings.privacy.page.new.transfer': 'Ny overførselskontrol',
  'settings.privacy.page.new.retention': 'Ny opbevaringspolitik',

  'settings.privacy.page.edit.processor': 'Rediger GDPR-databehandler',
  'settings.privacy.page.edit.dpia': 'Rediger DPIA',
  'settings.privacy.page.edit.breach': 'Rediger drejebog for brudrespons',
  'settings.privacy.page.edit.transfer': 'Rediger overførselskontrol',
  'settings.privacy.page.edit.retention': 'Rediger opbevaringspolitik',

  'settings.privacy.page.notFound.processor':
    'Der blev ikke fundet nogen GDPR-databehandler med dette id.',
  'settings.privacy.page.notFound.dpia': 'Der blev ikke fundet nogen DPIA med dette id.',
  'settings.privacy.page.notFound.breach':
    'Der blev ikke fundet nogen drejebog for brudrespons med dette id.',
  'settings.privacy.page.notFound.transfer':
    'Der blev ikke fundet nogen overførselskontrol med dette id.',
  'settings.privacy.page.notFound.retention':
    'Der blev ikke fundet nogen opbevaringspolitik med dette id.',

  'settings.privacy.page.backToList': 'Tilbage til databeskyttelse',
} as const satisfies PrivacyPagesCopy;

// `personuppgiftsbiträde` is a neuter noun (ett biträde), hence "Nytt" rather than "Ny".
const privacyPagesSvSE = {
  'settings.privacy.page.crumb': 'Integritet',

  'settings.privacy.page.new.processor': 'Nytt GDPR-personuppgiftsbiträde',
  'settings.privacy.page.new.dpia': 'Ny DPIA',
  'settings.privacy.page.new.breach': 'Ny åtgärdsplan vid dataintrång',
  'settings.privacy.page.new.transfer': 'Ny överföringskontroll',
  'settings.privacy.page.new.retention': 'Ny lagringspolicy',

  'settings.privacy.page.edit.processor': 'Redigera GDPR-personuppgiftsbiträde',
  'settings.privacy.page.edit.dpia': 'Redigera DPIA',
  'settings.privacy.page.edit.breach': 'Redigera åtgärdsplan vid dataintrång',
  'settings.privacy.page.edit.transfer': 'Redigera överföringskontroll',
  'settings.privacy.page.edit.retention': 'Redigera lagringspolicy',

  'settings.privacy.page.notFound.processor':
    'Inget GDPR-personuppgiftsbiträde hittades för den här identifieraren.',
  'settings.privacy.page.notFound.dpia': 'Ingen DPIA hittades för den här identifieraren.',
  'settings.privacy.page.notFound.breach':
    'Ingen åtgärdsplan vid dataintrång hittades för den här identifieraren.',
  'settings.privacy.page.notFound.transfer':
    'Ingen överföringskontroll hittades för den här identifieraren.',
  'settings.privacy.page.notFound.retention':
    'Ingen lagringspolicy hittades för den här identifieraren.',

  'settings.privacy.page.backToList': 'Tillbaka till integritet',
} as const satisfies PrivacyPagesCopy;

// sv-FI diverges from sv-SE on two register names its catalog already ships:
// `personuppgiftsincident` (not `dataintrång`) and `bevarandepolicy` (not `lagringspolicy`).
const privacyPagesSvFI = {
  ...privacyPagesSvSE,

  'settings.privacy.page.new.breach': 'Ny åtgärdsplan vid personuppgiftsincident',
  'settings.privacy.page.new.retention': 'Ny bevarandepolicy',

  'settings.privacy.page.edit.breach': 'Redigera åtgärdsplan vid personuppgiftsincident',
  'settings.privacy.page.edit.retention': 'Redigera bevarandepolicy',

  'settings.privacy.page.notFound.breach':
    'Ingen åtgärdsplan vid personuppgiftsincident hittades för den här identifieraren.',
  'settings.privacy.page.notFound.retention':
    'Ingen bevarandepolicy hittades för den här identifieraren.',
} as const satisfies PrivacyPagesCopy;

const privacyPagesFiFI = {
  'settings.privacy.page.crumb': 'Tietosuoja',

  'settings.privacy.page.new.processor': 'Uusi GDPR-käsittelijä',
  'settings.privacy.page.new.dpia': 'Uusi DPIA-arvio',
  'settings.privacy.page.new.breach': 'Uusi tietoturvaloukkauksen toimintaohje',
  'settings.privacy.page.new.transfer': 'Uusi siirron hallintakeino',
  'settings.privacy.page.new.retention': 'Uusi säilytyskäytäntö',

  'settings.privacy.page.edit.processor': 'Muokkaa GDPR-käsittelijää',
  'settings.privacy.page.edit.dpia': 'Muokkaa DPIA-arviota',
  'settings.privacy.page.edit.breach': 'Muokkaa tietoturvaloukkauksen toimintaohjetta',
  'settings.privacy.page.edit.transfer': 'Muokkaa siirron hallintakeinoa',
  'settings.privacy.page.edit.retention': 'Muokkaa säilytyskäytäntöä',

  'settings.privacy.page.notFound.processor': 'Tällä tunnisteella ei löytynyt GDPR-käsittelijää.',
  'settings.privacy.page.notFound.dpia': 'Tällä tunnisteella ei löytynyt DPIA-arviota.',
  'settings.privacy.page.notFound.breach':
    'Tällä tunnisteella ei löytynyt tietoturvaloukkauksen toimintaohjetta.',
  'settings.privacy.page.notFound.transfer':
    'Tällä tunnisteella ei löytynyt siirron hallintakeinoa.',
  'settings.privacy.page.notFound.retention': 'Tällä tunnisteella ei löytynyt säilytyskäytäntöä.',

  'settings.privacy.page.backToList': 'Takaisin tietosuojaan',
} as const satisfies PrivacyPagesCopy;

const privacyPagesPlPL = {
  'settings.privacy.page.crumb': 'Prywatność',

  'settings.privacy.page.new.processor': 'Nowy podmiot przetwarzający RODO',
  'settings.privacy.page.new.dpia': 'Nowa DPIA',
  'settings.privacy.page.new.breach': 'Nowy scenariusz reagowania na naruszenia',
  'settings.privacy.page.new.transfer': 'Nowa kontrola transferów',
  'settings.privacy.page.new.retention': 'Nowa zasada przechowywania',

  'settings.privacy.page.edit.processor': 'Edytuj podmiot przetwarzający RODO',
  'settings.privacy.page.edit.dpia': 'Edytuj DPIA',
  'settings.privacy.page.edit.breach': 'Edytuj scenariusz reagowania na naruszenia',
  'settings.privacy.page.edit.transfer': 'Edytuj kontrolę transferów',
  'settings.privacy.page.edit.retention': 'Edytuj zasadę przechowywania',

  'settings.privacy.page.notFound.processor':
    'Nie znaleziono podmiotu przetwarzającego RODO o tym identyfikatorze.',
  'settings.privacy.page.notFound.dpia': 'Nie znaleziono DPIA o tym identyfikatorze.',
  'settings.privacy.page.notFound.breach':
    'Nie znaleziono scenariusza reagowania na naruszenia o tym identyfikatorze.',
  'settings.privacy.page.notFound.transfer':
    'Nie znaleziono kontroli transferów o tym identyfikatorze.',
  'settings.privacy.page.notFound.retention':
    'Nie znaleziono zasady przechowywania o tym identyfikatorze.',

  'settings.privacy.page.backToList': 'Powrót do prywatności',
} as const satisfies PrivacyPagesCopy;

/**
 * Per-locale copy. The map is deliberately complete, so every shipped locale renders its own
 * words; a locale absent here would fall through to the English source tier.
 */
const PRIVACY_PAGES_BY_LOCALE: Partial<Record<Locale, PrivacyPagesCopy>> = {
  'en-US': privacyPagesEnglish,
  'en-GB': privacyPagesEnglish,
  'pt-PT': privacyPagesPtPT,
  'pt-BR': privacyPagesPtBR,
  'es-ES': privacyPagesEsES,
  'fr-FR': privacyPagesFrFR,
  'de-DE': privacyPagesDeDE,
  'it-IT': privacyPagesItIT,
  'nl-NL': privacyPagesNlNL,
  'da-DK': privacyPagesDaDK,
  'sv-SE': privacyPagesSvSE,
  'sv-FI': privacyPagesSvFI,
  'fi-FI': privacyPagesFiFI,
  'pl-PL': privacyPagesPlPL,
};

/** The active copy map: the active locale's reviewed strings, or the English source tier. */
export function usePrivacyPagesCopy(): PrivacyPagesCopy {
  const locale = useActiveLocale();
  return PRIVACY_PAGES_BY_LOCALE[locale] ?? privacyPagesEnglish;
}

/**
 * The record pages' translate hook, shaped like {@link useT}:
 * `const pt = usePrivacyPagesT(); pt('settings.privacy.page.new.dpia')`.
 */
export function usePrivacyPagesT(): (key: PrivacyPagesCopyKey, params?: TParams) => string {
  const copy = usePrivacyPagesCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
