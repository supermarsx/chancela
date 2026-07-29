/**
 * Copy for the DPIA GUIDANCE MODEL EDITOR — the page at `/settings/privacy/dpia-template/edit`,
 * plus the two affordances the read-only guidance sub-tab grew (the link into the editor and the
 * note explaining why some names stay in English).
 *
 * **Why this module is self-contained, not folded into the catalogs.** A concurrency call, not a
 * standing rule: three other lanes were editing all 14 `locales/*.ts` files at the same time as
 * this one, so threading 34 keys × 14 files through them would have been a merge hazard for
 * everybody. Keeping the key set here made it reviewable in one place and touched nothing anyone
 * else held. It follows the shape of `privacyPagesFallback.ts`, `privacyLegalHoldFallback.ts` and
 * `trustSectionsFallback.ts`, and owns its own locale-aware resolver
 * ({@link useDpiaTemplateEditorT}), shaped exactly like `useT`.
 *
 * Nothing about this key set requires it to stay outside the catalogs. Folding it in is a
 * mechanical spread whenever the files are quiet, and `dpiaTemplateEditorFallback.test.ts` — which
 * pins locale coverage and exact key-set parity — is what makes that move safe to do later.
 *
 * (An earlier draft of this header claimed the catalogs were "held under a single-writer serial
 * lock". That was inherited from `privacyPagesFallback.ts`, where it described t55's situation; no
 * such lock was in force here. Corrected so nobody reads it as a constraint that binds them.)
 *
 * **Everything else is REUSED from the catalogs**, through `t()`: the Cancelar / Guardar alterações
 * / A guardar actions, `common.remove`, and the whole read-only guidance vocabulary. Only what the
 * editor genuinely introduces lives here.
 *
 * ## What this copy may and may not say
 *
 * Editing this model changes what THIS instance asks a reviewer to consider. It does not file,
 * submit, validate or complete anything, and no string here may suggest that an edited model is
 * compliant, approved, sufficient or accepted by any authority. Where a sentence was tempted toward
 * assurance it describes the mechanism instead and stops.
 *
 * ## Two rules this key set is shaped by
 *
 * 1. **No interpolated nouns.** `note.savedBy` interpolates an actor name and a timestamp — never a
 *    noun that a surrounding word has to agree with. A `'{thing} saved'` template would break in
 *    every inflected language here in a different way, so each sentence is written whole.
 * 2. **Each locale keeps the register name its catalog already ships** — pt-PT/pt-BR/fr-FR *AIPD*,
 *    es-ES *EIPD*, de-DE *DSFA*, fi-FI *DPIA-arvio*, and *DPIA* elsewhere — and its own word for
 *    the ledger. pt-BR is not a copy of pt-PT: Brazil is under the LGPD, and *registo* / *secção*
 *    are European spellings.
 */
import { useMemo } from 'react';
import type { Locale } from '../api/types';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

// en-US is the authoring source (t40); en-GB shares it. The one word that would have diverged
// (organisation/organization) is deliberately absent from this key set.
export const dpiaTemplateEditorEnglish = {
  'settings.privacy.dpiaTemplateEditor.page.title': 'DPIA guidance model',
  'settings.privacy.dpiaTemplateEditor.page.lede':
    'This is the model the DPIA screens follow: its sections, its prompts and its checklist. Editing it changes what this installation asks a reviewer to consider. It files nothing, sends nothing and validates nothing.',

  'settings.privacy.dpiaTemplateEditor.badge.shipped': 'Shipped with this build',
  'settings.privacy.dpiaTemplateEditor.badge.operator': 'Written here',
  'settings.privacy.dpiaTemplateEditor.note.shipped':
    'The model shipped with this build. Its wording is translated into every language the application ships.',
  'settings.privacy.dpiaTemplateEditor.note.operator':
    'This model was written here. It is shown exactly as it was typed, in the language it was typed in, to every reader — it is not translated.',
  'settings.privacy.dpiaTemplateEditor.note.savedBy': 'Saved by {actor} on {timestamp}.',

  'settings.privacy.dpiaTemplateEditor.identifiers.title': 'Why some names stay in English',
  'settings.privacy.dpiaTemplateEditor.identifiers.body':
    'The field types and the no-claim flags are wire names, not wording. Each no-claim flag names a legal claim this product does not make, and translating a claim would amount to writing it. They are shown exactly as the server sends them, in every language.',

  'settings.privacy.dpiaTemplateEditor.field.title': 'Model title',
  'settings.privacy.dpiaTemplateEditor.field.language': 'Language you are writing in',
  'settings.privacy.dpiaTemplateEditor.field.languageHint':
    'A language tag, such as pt-PT. It records what you typed; it does not translate it.',
  'settings.privacy.dpiaTemplateEditor.field.sectionId': 'Section identifier',
  'settings.privacy.dpiaTemplateEditor.field.sectionIdHint':
    'Letters, digits, "_", "-" and "." only. It travels with the section, so reordering never moves it.',
  'settings.privacy.dpiaTemplateEditor.field.sectionTitle': 'Section title',
  'settings.privacy.dpiaTemplateEditor.field.sectionDescription': 'Section description',
  'settings.privacy.dpiaTemplateEditor.field.prompts': 'Prompts',
  'settings.privacy.dpiaTemplateEditor.field.promptsHint': 'One prompt per line.',
  'settings.privacy.dpiaTemplateEditor.field.operatorActions': 'Operator actions',
  'settings.privacy.dpiaTemplateEditor.field.operatorActionsHint': 'One action per line.',
  'settings.privacy.dpiaTemplateEditor.field.itemId': 'Item identifier',
  'settings.privacy.dpiaTemplateEditor.field.itemLabel': 'Item label',
  'settings.privacy.dpiaTemplateEditor.field.itemType': 'Field type',
  'settings.privacy.dpiaTemplateEditor.field.itemRequired': 'Required',

  'settings.privacy.dpiaTemplateEditor.checklist.heading': 'Checklist',
  'settings.privacy.dpiaTemplateEditor.section.empty': 'This model has no sections yet.',

  'settings.privacy.dpiaTemplateEditor.action.edit': 'Edit the model',
  'settings.privacy.dpiaTemplateEditor.action.addSection': 'Add a section',
  'settings.privacy.dpiaTemplateEditor.action.removeSection': 'Remove this section',
  'settings.privacy.dpiaTemplateEditor.action.addItem': 'Add a checklist item',
  'settings.privacy.dpiaTemplateEditor.action.reset': 'Restore the shipped model',
  'settings.privacy.dpiaTemplateEditor.reset.confirm':
    'Restore the model shipped with this build? The model written here will be replaced. The chronological ledger keeps a record of it.',

  'settings.privacy.dpiaTemplateEditor.toast.saved': 'DPIA guidance model saved.',
  'settings.privacy.dpiaTemplateEditor.toast.reset':
    'The shipped DPIA guidance model was restored.',
} as const;

/** The key set this module resolves. */
export type DpiaTemplateEditorCopyKey = keyof typeof dpiaTemplateEditorEnglish;

type DpiaTemplateEditorCopy = Record<DpiaTemplateEditorCopyKey, string>;

export const dpiaTemplateEditorPtPT = {
  'settings.privacy.dpiaTemplateEditor.page.title': 'Modelo de AIPD',
  'settings.privacy.dpiaTemplateEditor.page.lede':
    'Este é o modelo que os ecrãs de AIPD seguem: as suas secções, as suas perguntas e a sua lista de verificação. Editá-lo altera o que esta instalação pede a quem revê. Não submete nada, não comunica nada e não valida nada.',

  'settings.privacy.dpiaTemplateEditor.badge.shipped': 'Incluído nesta versão',
  'settings.privacy.dpiaTemplateEditor.badge.operator': 'Escrito aqui',
  'settings.privacy.dpiaTemplateEditor.note.shipped':
    'O modelo incluído nesta versão. Os seus textos estão traduzidos em todos os idiomas da aplicação.',
  'settings.privacy.dpiaTemplateEditor.note.operator':
    'Este modelo foi escrito aqui. É apresentado exatamente como foi escrito, no idioma em que foi escrito, a qualquer leitor — não é traduzido.',
  'settings.privacy.dpiaTemplateEditor.note.savedBy': 'Guardado por {actor} em {timestamp}.',

  'settings.privacy.dpiaTemplateEditor.identifiers.title':
    'Porque é que alguns nomes ficam em inglês',
  'settings.privacy.dpiaTemplateEditor.identifiers.body':
    'Os tipos de campo e as flags sem alegação são nomes técnicos, não texto corrente. Cada flag sem alegação nomeia uma alegação jurídica que este produto não faz, e traduzir uma alegação equivaleria a redigi-la. São apresentados exatamente como o servidor os envia, em todos os idiomas.',

  'settings.privacy.dpiaTemplateEditor.field.title': 'Título do modelo',
  'settings.privacy.dpiaTemplateEditor.field.language': 'Idioma em que está a escrever',
  'settings.privacy.dpiaTemplateEditor.field.languageHint':
    'Uma etiqueta de idioma, como pt-PT. Regista o que escreveu; não o traduz.',
  'settings.privacy.dpiaTemplateEditor.field.sectionId': 'Identificador da secção',
  'settings.privacy.dpiaTemplateEditor.field.sectionIdHint':
    'Apenas letras, algarismos, «_», «-» e «.». Acompanha a secção, pelo que reordenar nunca o desloca.',
  'settings.privacy.dpiaTemplateEditor.field.sectionTitle': 'Título da secção',
  'settings.privacy.dpiaTemplateEditor.field.sectionDescription': 'Descrição da secção',
  'settings.privacy.dpiaTemplateEditor.field.prompts': 'Perguntas',
  'settings.privacy.dpiaTemplateEditor.field.promptsHint': 'Uma pergunta por linha.',
  'settings.privacy.dpiaTemplateEditor.field.operatorActions': 'Ações do operador',
  'settings.privacy.dpiaTemplateEditor.field.operatorActionsHint': 'Uma ação por linha.',
  'settings.privacy.dpiaTemplateEditor.field.itemId': 'Identificador do item',
  'settings.privacy.dpiaTemplateEditor.field.itemLabel': 'Designação do item',
  'settings.privacy.dpiaTemplateEditor.field.itemType': 'Tipo de campo',
  'settings.privacy.dpiaTemplateEditor.field.itemRequired': 'Obrigatório',

  'settings.privacy.dpiaTemplateEditor.checklist.heading': 'Lista de verificação',
  'settings.privacy.dpiaTemplateEditor.section.empty': 'Este modelo ainda não tem secções.',

  'settings.privacy.dpiaTemplateEditor.action.edit': 'Editar o modelo',
  'settings.privacy.dpiaTemplateEditor.action.addSection': 'Adicionar secção',
  'settings.privacy.dpiaTemplateEditor.action.removeSection': 'Remover esta secção',
  'settings.privacy.dpiaTemplateEditor.action.addItem': 'Adicionar item à lista de verificação',
  'settings.privacy.dpiaTemplateEditor.action.reset': 'Repor o modelo incluído',
  'settings.privacy.dpiaTemplateEditor.reset.confirm':
    'Repor o modelo incluído nesta versão? O modelo escrito aqui será substituído. O registo cronológico conserva-o.',

  'settings.privacy.dpiaTemplateEditor.toast.saved': 'Modelo de AIPD guardado.',
  'settings.privacy.dpiaTemplateEditor.toast.reset': 'Foi reposto o modelo de AIPD incluído.',
} as const satisfies DpiaTemplateEditorCopy;

// pt-BR keeps Brazilian forms: `seção` (not `secção`), `registro` (not `registo`), `tela` (not
// `ecrã`), `salvar` (not `guardar`), and `está escrevendo` for the progressive.
const dpiaTemplateEditorPtBR = {
  'settings.privacy.dpiaTemplateEditor.page.title': 'Modelo de AIPD',
  'settings.privacy.dpiaTemplateEditor.page.lede':
    'Este é o modelo que as telas de AIPD seguem: suas seções, suas perguntas e sua lista de verificação. Editá-lo altera o que esta instalação pede a quem revisa. Não protocola nada, não comunica nada e não valida nada.',

  'settings.privacy.dpiaTemplateEditor.badge.shipped': 'Incluído nesta versão',
  'settings.privacy.dpiaTemplateEditor.badge.operator': 'Escrito aqui',
  'settings.privacy.dpiaTemplateEditor.note.shipped':
    'O modelo incluído nesta versão. Seus textos estão traduzidos em todos os idiomas do aplicativo.',
  'settings.privacy.dpiaTemplateEditor.note.operator':
    'Este modelo foi escrito aqui. É exibido exatamente como foi escrito, no idioma em que foi escrito, para qualquer leitor — não é traduzido.',
  'settings.privacy.dpiaTemplateEditor.note.savedBy': 'Salvo por {actor} em {timestamp}.',

  'settings.privacy.dpiaTemplateEditor.identifiers.title':
    'Por que alguns nomes permanecem em inglês',
  'settings.privacy.dpiaTemplateEditor.identifiers.body':
    'Os tipos de campo e as flags sem alegação são nomes técnicos, não texto corrido. Cada flag sem alegação nomeia uma alegação jurídica que este produto não faz, e traduzir uma alegação equivaleria a redigi-la. São exibidos exatamente como o servidor os envia, em todos os idiomas.',

  'settings.privacy.dpiaTemplateEditor.field.title': 'Título do modelo',
  'settings.privacy.dpiaTemplateEditor.field.language': 'Idioma em que você está escrevendo',
  'settings.privacy.dpiaTemplateEditor.field.languageHint':
    'Uma etiqueta de idioma, como pt-BR. Registra o que você escreveu; não o traduz.',
  'settings.privacy.dpiaTemplateEditor.field.sectionId': 'Identificador da seção',
  'settings.privacy.dpiaTemplateEditor.field.sectionIdHint':
    'Apenas letras, algarismos, «_», «-» e «.». Acompanha a seção, de modo que reordenar nunca o desloca.',
  'settings.privacy.dpiaTemplateEditor.field.sectionTitle': 'Título da seção',
  'settings.privacy.dpiaTemplateEditor.field.sectionDescription': 'Descrição da seção',
  'settings.privacy.dpiaTemplateEditor.field.prompts': 'Perguntas',
  'settings.privacy.dpiaTemplateEditor.field.promptsHint': 'Uma pergunta por linha.',
  'settings.privacy.dpiaTemplateEditor.field.operatorActions': 'Ações do operador',
  'settings.privacy.dpiaTemplateEditor.field.operatorActionsHint': 'Uma ação por linha.',
  'settings.privacy.dpiaTemplateEditor.field.itemId': 'Identificador do item',
  'settings.privacy.dpiaTemplateEditor.field.itemLabel': 'Rótulo do item',
  'settings.privacy.dpiaTemplateEditor.field.itemType': 'Tipo de campo',
  'settings.privacy.dpiaTemplateEditor.field.itemRequired': 'Obrigatório',

  'settings.privacy.dpiaTemplateEditor.checklist.heading': 'Lista de verificação',
  'settings.privacy.dpiaTemplateEditor.section.empty': 'Este modelo ainda não tem seções.',

  'settings.privacy.dpiaTemplateEditor.action.edit': 'Editar o modelo',
  'settings.privacy.dpiaTemplateEditor.action.addSection': 'Adicionar seção',
  'settings.privacy.dpiaTemplateEditor.action.removeSection': 'Remover esta seção',
  'settings.privacy.dpiaTemplateEditor.action.addItem': 'Adicionar item à lista de verificação',
  'settings.privacy.dpiaTemplateEditor.action.reset': 'Restaurar o modelo incluído',
  'settings.privacy.dpiaTemplateEditor.reset.confirm':
    'Restaurar o modelo incluído nesta versão? O modelo escrito aqui será substituído. O registro cronológico o conserva.',

  'settings.privacy.dpiaTemplateEditor.toast.saved': 'Modelo de AIPD salvo.',
  'settings.privacy.dpiaTemplateEditor.toast.reset': 'O modelo de AIPD incluído foi restaurado.',
} as const satisfies DpiaTemplateEditorCopy;

const dpiaTemplateEditorEsES = {
  'settings.privacy.dpiaTemplateEditor.page.title': 'Modelo de EIPD',
  'settings.privacy.dpiaTemplateEditor.page.lede':
    'Este es el modelo que siguen las pantallas de EIPD: sus secciones, sus preguntas y su lista de comprobación. Editarlo cambia lo que esta instalación pide que considere quien revisa. No presenta nada, no comunica nada y no valida nada.',

  'settings.privacy.dpiaTemplateEditor.badge.shipped': 'Incluido en esta versión',
  'settings.privacy.dpiaTemplateEditor.badge.operator': 'Escrito aquí',
  'settings.privacy.dpiaTemplateEditor.note.shipped':
    'El modelo incluido en esta versión. Sus textos están traducidos a todos los idiomas de la aplicación.',
  'settings.privacy.dpiaTemplateEditor.note.operator':
    'Este modelo se escribió aquí. Se muestra exactamente como se escribió, en el idioma en que se escribió, a cualquier lector: no se traduce.',
  'settings.privacy.dpiaTemplateEditor.note.savedBy': 'Guardado por {actor} el {timestamp}.',

  'settings.privacy.dpiaTemplateEditor.identifiers.title':
    'Por qué algunos nombres siguen en inglés',
  'settings.privacy.dpiaTemplateEditor.identifiers.body':
    'Los tipos de campo y los indicadores sin afirmación son nombres técnicos, no texto. Cada indicador sin afirmación nombra una afirmación jurídica que este producto no hace, y traducir una afirmación equivaldría a redactarla. Se muestran exactamente como los envía el servidor, en todos los idiomas.',

  'settings.privacy.dpiaTemplateEditor.field.title': 'Título del modelo',
  'settings.privacy.dpiaTemplateEditor.field.language': 'Idioma en el que está escribiendo',
  'settings.privacy.dpiaTemplateEditor.field.languageHint':
    'Una etiqueta de idioma, como es-ES. Registra lo que escribió; no lo traduce.',
  'settings.privacy.dpiaTemplateEditor.field.sectionId': 'Identificador de la sección',
  'settings.privacy.dpiaTemplateEditor.field.sectionIdHint':
    'Solo letras, dígitos, «_», «-» y «.». Acompaña a la sección, de modo que reordenar nunca lo desplaza.',
  'settings.privacy.dpiaTemplateEditor.field.sectionTitle': 'Título de la sección',
  'settings.privacy.dpiaTemplateEditor.field.sectionDescription': 'Descripción de la sección',
  'settings.privacy.dpiaTemplateEditor.field.prompts': 'Preguntas',
  'settings.privacy.dpiaTemplateEditor.field.promptsHint': 'Una pregunta por línea.',
  'settings.privacy.dpiaTemplateEditor.field.operatorActions': 'Acciones del operador',
  'settings.privacy.dpiaTemplateEditor.field.operatorActionsHint': 'Una acción por línea.',
  'settings.privacy.dpiaTemplateEditor.field.itemId': 'Identificador del elemento',
  'settings.privacy.dpiaTemplateEditor.field.itemLabel': 'Etiqueta del elemento',
  'settings.privacy.dpiaTemplateEditor.field.itemType': 'Tipo de campo',
  'settings.privacy.dpiaTemplateEditor.field.itemRequired': 'Obligatorio',

  'settings.privacy.dpiaTemplateEditor.checklist.heading': 'Lista de comprobación',
  'settings.privacy.dpiaTemplateEditor.section.empty': 'Este modelo aún no tiene secciones.',

  'settings.privacy.dpiaTemplateEditor.action.edit': 'Editar el modelo',
  'settings.privacy.dpiaTemplateEditor.action.addSection': 'Añadir sección',
  'settings.privacy.dpiaTemplateEditor.action.removeSection': 'Eliminar esta sección',
  'settings.privacy.dpiaTemplateEditor.action.addItem': 'Añadir elemento a la lista',
  'settings.privacy.dpiaTemplateEditor.action.reset': 'Restaurar el modelo incluido',
  'settings.privacy.dpiaTemplateEditor.reset.confirm':
    '¿Restaurar el modelo incluido en esta versión? Se sustituirá el modelo escrito aquí. El registro cronológico lo conserva.',

  'settings.privacy.dpiaTemplateEditor.toast.saved': 'Modelo de EIPD guardado.',
  'settings.privacy.dpiaTemplateEditor.toast.reset': 'Se restauró el modelo de EIPD incluido.',
} as const satisfies DpiaTemplateEditorCopy;

const dpiaTemplateEditorFrFR = {
  'settings.privacy.dpiaTemplateEditor.page.title': 'Modèle d’AIPD',
  'settings.privacy.dpiaTemplateEditor.page.lede':
    'Voici le modèle que suivent les écrans d’AIPD : ses sections, ses questions et sa liste de contrôle. Le modifier change ce que cette installation demande d’examiner. Il ne dépose rien, ne transmet rien et ne valide rien.',

  'settings.privacy.dpiaTemplateEditor.badge.shipped': 'Fourni avec cette version',
  'settings.privacy.dpiaTemplateEditor.badge.operator': 'Rédigé ici',
  'settings.privacy.dpiaTemplateEditor.note.shipped':
    'Le modèle fourni avec cette version. Ses textes sont traduits dans toutes les langues de l’application.',
  'settings.privacy.dpiaTemplateEditor.note.operator':
    'Ce modèle a été rédigé ici. Il est affiché exactement tel qu’il a été saisi, dans la langue de saisie, à tout lecteur — il n’est pas traduit.',
  'settings.privacy.dpiaTemplateEditor.note.savedBy': 'Enregistré par {actor} le {timestamp}.',

  'settings.privacy.dpiaTemplateEditor.identifiers.title':
    'Pourquoi certains noms restent en anglais',
  'settings.privacy.dpiaTemplateEditor.identifiers.body':
    'Les types de champ et les indicateurs de non-affirmation sont des noms techniques, pas du texte. Chaque indicateur de non-affirmation nomme une affirmation juridique que ce produit ne fait pas, et traduire une affirmation reviendrait à la rédiger. Ils sont affichés exactement tels que le serveur les envoie, dans toutes les langues.',

  'settings.privacy.dpiaTemplateEditor.field.title': 'Titre du modèle',
  'settings.privacy.dpiaTemplateEditor.field.language': 'Langue dans laquelle vous rédigez',
  'settings.privacy.dpiaTemplateEditor.field.languageHint':
    'Une étiquette de langue, par exemple fr-FR. Elle indique ce que vous avez saisi ; elle ne le traduit pas.',
  'settings.privacy.dpiaTemplateEditor.field.sectionId': 'Identifiant de la section',
  'settings.privacy.dpiaTemplateEditor.field.sectionIdHint':
    'Uniquement lettres, chiffres, « _ », « - » et « . ». Il suit la section : la réorganisation ne le déplace jamais.',
  'settings.privacy.dpiaTemplateEditor.field.sectionTitle': 'Titre de la section',
  'settings.privacy.dpiaTemplateEditor.field.sectionDescription': 'Description de la section',
  'settings.privacy.dpiaTemplateEditor.field.prompts': 'Questions',
  'settings.privacy.dpiaTemplateEditor.field.promptsHint': 'Une question par ligne.',
  'settings.privacy.dpiaTemplateEditor.field.operatorActions': 'Actions de l’opérateur',
  'settings.privacy.dpiaTemplateEditor.field.operatorActionsHint': 'Une action par ligne.',
  'settings.privacy.dpiaTemplateEditor.field.itemId': 'Identifiant de l’élément',
  'settings.privacy.dpiaTemplateEditor.field.itemLabel': 'Libellé de l’élément',
  'settings.privacy.dpiaTemplateEditor.field.itemType': 'Type de champ',
  'settings.privacy.dpiaTemplateEditor.field.itemRequired': 'Obligatoire',

  'settings.privacy.dpiaTemplateEditor.checklist.heading': 'Liste de contrôle',
  'settings.privacy.dpiaTemplateEditor.section.empty':
    'Ce modèle ne comporte encore aucune section.',

  'settings.privacy.dpiaTemplateEditor.action.edit': 'Modifier le modèle',
  'settings.privacy.dpiaTemplateEditor.action.addSection': 'Ajouter une section',
  'settings.privacy.dpiaTemplateEditor.action.removeSection': 'Supprimer cette section',
  'settings.privacy.dpiaTemplateEditor.action.addItem': 'Ajouter un élément à la liste',
  'settings.privacy.dpiaTemplateEditor.action.reset': 'Rétablir le modèle fourni',
  'settings.privacy.dpiaTemplateEditor.reset.confirm':
    'Rétablir le modèle fourni avec cette version ? Le modèle rédigé ici sera remplacé. Le registre chronologique en conserve la trace.',

  'settings.privacy.dpiaTemplateEditor.toast.saved': 'Modèle d’AIPD enregistré.',
  'settings.privacy.dpiaTemplateEditor.toast.reset': 'Le modèle d’AIPD fourni a été rétabli.',
} as const satisfies DpiaTemplateEditorCopy;

const dpiaTemplateEditorDeDE = {
  'settings.privacy.dpiaTemplateEditor.page.title': 'DSFA-Vorlage',
  'settings.privacy.dpiaTemplateEditor.page.lede':
    'Dies ist die Vorlage, der die DSFA-Bildschirme folgen: ihre Abschnitte, ihre Fragen und ihre Prüfliste. Wer sie bearbeitet, ändert, was diese Installation zur Prüfung vorlegt. Sie reicht nichts ein, übermittelt nichts und validiert nichts.',

  'settings.privacy.dpiaTemplateEditor.badge.shipped': 'Mit diesem Build ausgeliefert',
  'settings.privacy.dpiaTemplateEditor.badge.operator': 'Hier verfasst',
  'settings.privacy.dpiaTemplateEditor.note.shipped':
    'Die mit diesem Build ausgelieferte Vorlage. Ihre Texte sind in alle Sprachen der Anwendung übersetzt.',
  'settings.privacy.dpiaTemplateEditor.note.operator':
    'Diese Vorlage wurde hier verfasst. Sie wird jedem Lesenden genau so angezeigt, wie sie eingegeben wurde, in der Eingabesprache — sie wird nicht übersetzt.',
  'settings.privacy.dpiaTemplateEditor.note.savedBy': 'Gespeichert von {actor} am {timestamp}.',

  'settings.privacy.dpiaTemplateEditor.identifiers.title': 'Warum einige Namen englisch bleiben',
  'settings.privacy.dpiaTemplateEditor.identifiers.body':
    'Die Feldtypen und die Kennzeichen ohne Behauptung sind technische Namen, kein Fließtext. Jedes Kennzeichen ohne Behauptung benennt eine rechtliche Behauptung, die dieses Produkt nicht aufstellt; eine Behauptung zu übersetzen hieße, sie zu formulieren. Sie werden in allen Sprachen genau so angezeigt, wie der Server sie sendet.',

  'settings.privacy.dpiaTemplateEditor.field.title': 'Titel der Vorlage',
  'settings.privacy.dpiaTemplateEditor.field.language': 'Sprache, in der Sie schreiben',
  'settings.privacy.dpiaTemplateEditor.field.languageHint':
    'Ein Sprach-Tag wie de-DE. Es hält fest, was Sie eingegeben haben; es übersetzt es nicht.',
  'settings.privacy.dpiaTemplateEditor.field.sectionId': 'Kennung des Abschnitts',
  'settings.privacy.dpiaTemplateEditor.field.sectionIdHint':
    'Nur Buchstaben, Ziffern, „_“, „-“ und „.“. Sie bleibt am Abschnitt, sodass ein Umsortieren sie nie verschiebt.',
  'settings.privacy.dpiaTemplateEditor.field.sectionTitle': 'Titel des Abschnitts',
  'settings.privacy.dpiaTemplateEditor.field.sectionDescription': 'Beschreibung des Abschnitts',
  'settings.privacy.dpiaTemplateEditor.field.prompts': 'Fragen',
  'settings.privacy.dpiaTemplateEditor.field.promptsHint': 'Eine Frage pro Zeile.',
  'settings.privacy.dpiaTemplateEditor.field.operatorActions': 'Betreiberschritte',
  'settings.privacy.dpiaTemplateEditor.field.operatorActionsHint': 'Ein Schritt pro Zeile.',
  'settings.privacy.dpiaTemplateEditor.field.itemId': 'Kennung des Eintrags',
  'settings.privacy.dpiaTemplateEditor.field.itemLabel': 'Bezeichnung des Eintrags',
  'settings.privacy.dpiaTemplateEditor.field.itemType': 'Feldtyp',
  'settings.privacy.dpiaTemplateEditor.field.itemRequired': 'Pflichtfeld',

  'settings.privacy.dpiaTemplateEditor.checklist.heading': 'Prüfliste',
  'settings.privacy.dpiaTemplateEditor.section.empty': 'Diese Vorlage hat noch keine Abschnitte.',

  'settings.privacy.dpiaTemplateEditor.action.edit': 'Vorlage bearbeiten',
  'settings.privacy.dpiaTemplateEditor.action.addSection': 'Abschnitt hinzufügen',
  'settings.privacy.dpiaTemplateEditor.action.removeSection': 'Diesen Abschnitt entfernen',
  'settings.privacy.dpiaTemplateEditor.action.addItem': 'Prüflisteneintrag hinzufügen',
  'settings.privacy.dpiaTemplateEditor.action.reset': 'Ausgelieferte Vorlage wiederherstellen',
  'settings.privacy.dpiaTemplateEditor.reset.confirm':
    'Die mit diesem Build ausgelieferte Vorlage wiederherstellen? Die hier verfasste Vorlage wird ersetzt. Das chronologische Register bewahrt sie auf.',

  'settings.privacy.dpiaTemplateEditor.toast.saved': 'DSFA-Vorlage gespeichert.',
  'settings.privacy.dpiaTemplateEditor.toast.reset':
    'Die ausgelieferte DSFA-Vorlage wurde wiederhergestellt.',
} as const satisfies DpiaTemplateEditorCopy;

const dpiaTemplateEditorItIT = {
  'settings.privacy.dpiaTemplateEditor.page.title': 'Modello di DPIA',
  'settings.privacy.dpiaTemplateEditor.page.lede':
    'Questo è il modello seguito dalle schermate DPIA: le sue sezioni, le sue domande e la sua lista di controllo. Modificarlo cambia ciò che questa installazione sottopone a chi esamina. Non presenta nulla, non trasmette nulla e non convalida nulla.',

  'settings.privacy.dpiaTemplateEditor.badge.shipped': 'Incluso in questa versione',
  'settings.privacy.dpiaTemplateEditor.badge.operator': 'Redatto qui',
  'settings.privacy.dpiaTemplateEditor.note.shipped':
    'Il modello incluso in questa versione. I suoi testi sono tradotti in tutte le lingue dell’applicazione.',
  'settings.privacy.dpiaTemplateEditor.note.operator':
    'Questo modello è stato redatto qui. Viene mostrato esattamente come è stato scritto, nella lingua in cui è stato scritto, a qualsiasi lettore: non viene tradotto.',
  'settings.privacy.dpiaTemplateEditor.note.savedBy': 'Salvato da {actor} il {timestamp}.',

  'settings.privacy.dpiaTemplateEditor.identifiers.title': 'Perché alcuni nomi restano in inglese',
  'settings.privacy.dpiaTemplateEditor.identifiers.body':
    'I tipi di campo e i flag di non affermazione sono nomi tecnici, non testo. Ogni flag di non affermazione nomina un’affermazione giuridica che questo prodotto non fa, e tradurre un’affermazione equivarrebbe a formularla. Sono mostrati esattamente come li invia il server, in tutte le lingue.',

  'settings.privacy.dpiaTemplateEditor.field.title': 'Titolo del modello',
  'settings.privacy.dpiaTemplateEditor.field.language': 'Lingua in cui stai scrivendo',
  'settings.privacy.dpiaTemplateEditor.field.languageHint':
    'Un’etichetta di lingua, ad esempio it-IT. Registra ciò che hai scritto; non lo traduce.',
  'settings.privacy.dpiaTemplateEditor.field.sectionId': 'Identificatore della sezione',
  'settings.privacy.dpiaTemplateEditor.field.sectionIdHint':
    'Solo lettere, cifre, «_», «-» e «.». Segue la sezione, quindi il riordino non lo sposta mai.',
  'settings.privacy.dpiaTemplateEditor.field.sectionTitle': 'Titolo della sezione',
  'settings.privacy.dpiaTemplateEditor.field.sectionDescription': 'Descrizione della sezione',
  'settings.privacy.dpiaTemplateEditor.field.prompts': 'Domande',
  'settings.privacy.dpiaTemplateEditor.field.promptsHint': 'Una domanda per riga.',
  'settings.privacy.dpiaTemplateEditor.field.operatorActions': 'Azioni dell’operatore',
  'settings.privacy.dpiaTemplateEditor.field.operatorActionsHint': 'Un’azione per riga.',
  'settings.privacy.dpiaTemplateEditor.field.itemId': 'Identificatore dell’elemento',
  'settings.privacy.dpiaTemplateEditor.field.itemLabel': 'Etichetta dell’elemento',
  'settings.privacy.dpiaTemplateEditor.field.itemType': 'Tipo di campo',
  'settings.privacy.dpiaTemplateEditor.field.itemRequired': 'Obbligatorio',

  'settings.privacy.dpiaTemplateEditor.checklist.heading': 'Lista di controllo',
  'settings.privacy.dpiaTemplateEditor.section.empty': 'Questo modello non ha ancora sezioni.',

  'settings.privacy.dpiaTemplateEditor.action.edit': 'Modifica il modello',
  'settings.privacy.dpiaTemplateEditor.action.addSection': 'Aggiungi sezione',
  'settings.privacy.dpiaTemplateEditor.action.removeSection': 'Rimuovi questa sezione',
  'settings.privacy.dpiaTemplateEditor.action.addItem': 'Aggiungi voce alla lista',
  'settings.privacy.dpiaTemplateEditor.action.reset': 'Ripristina il modello incluso',
  'settings.privacy.dpiaTemplateEditor.reset.confirm':
    'Ripristinare il modello incluso in questa versione? Il modello redatto qui sarà sostituito. Il registro cronologico ne conserva traccia.',

  'settings.privacy.dpiaTemplateEditor.toast.saved': 'Modello di DPIA salvato.',
  'settings.privacy.dpiaTemplateEditor.toast.reset':
    'Il modello di DPIA incluso è stato ripristinato.',
} as const satisfies DpiaTemplateEditorCopy;

const dpiaTemplateEditorNlNL = {
  'settings.privacy.dpiaTemplateEditor.page.title': 'DPIA-model',
  'settings.privacy.dpiaTemplateEditor.page.lede':
    'Dit is het model dat de DPIA-schermen volgen: de secties, de vragen en de checklist. Het bewerken ervan verandert wat deze installatie ter beoordeling voorlegt. Het dient niets in, verzendt niets en valideert niets.',

  'settings.privacy.dpiaTemplateEditor.badge.shipped': 'Meegeleverd met deze build',
  'settings.privacy.dpiaTemplateEditor.badge.operator': 'Hier geschreven',
  'settings.privacy.dpiaTemplateEditor.note.shipped':
    'Het model dat met deze build wordt meegeleverd. De teksten zijn vertaald in alle talen van de applicatie.',
  'settings.privacy.dpiaTemplateEditor.note.operator':
    'Dit model is hier geschreven. Het wordt aan iedere lezer precies zo getoond als het is ingetypt, in de taal waarin het is ingetypt — het wordt niet vertaald.',
  'settings.privacy.dpiaTemplateEditor.note.savedBy': 'Opgeslagen door {actor} op {timestamp}.',

  'settings.privacy.dpiaTemplateEditor.identifiers.title':
    'Waarom sommige namen in het Engels blijven',
  'settings.privacy.dpiaTemplateEditor.identifiers.body':
    'De veldtypen en de vlaggen zonder claim zijn technische namen, geen tekst. Elke vlag zonder claim benoemt een juridische claim die dit product niet maakt, en een claim vertalen zou neerkomen op het formuleren ervan. Ze worden in alle talen precies zo getoond als de server ze verstuurt.',

  'settings.privacy.dpiaTemplateEditor.field.title': 'Titel van het model',
  'settings.privacy.dpiaTemplateEditor.field.language': 'Taal waarin u schrijft',
  'settings.privacy.dpiaTemplateEditor.field.languageHint':
    'Een taalcode, bijvoorbeeld nl-NL. Die legt vast wat u hebt getypt; hij vertaalt het niet.',
  'settings.privacy.dpiaTemplateEditor.field.sectionId': 'Identificatie van de sectie',
  'settings.privacy.dpiaTemplateEditor.field.sectionIdHint':
    'Alleen letters, cijfers, „_”, „-” en „.”. Hij blijft bij de sectie, dus herschikken verplaatst hem nooit.',
  'settings.privacy.dpiaTemplateEditor.field.sectionTitle': 'Titel van de sectie',
  'settings.privacy.dpiaTemplateEditor.field.sectionDescription': 'Beschrijving van de sectie',
  'settings.privacy.dpiaTemplateEditor.field.prompts': 'Vragen',
  'settings.privacy.dpiaTemplateEditor.field.promptsHint': 'Eén vraag per regel.',
  'settings.privacy.dpiaTemplateEditor.field.operatorActions': 'Acties van de beheerder',
  'settings.privacy.dpiaTemplateEditor.field.operatorActionsHint': 'Eén actie per regel.',
  'settings.privacy.dpiaTemplateEditor.field.itemId': 'Identificatie van het item',
  'settings.privacy.dpiaTemplateEditor.field.itemLabel': 'Label van het item',
  'settings.privacy.dpiaTemplateEditor.field.itemType': 'Veldtype',
  'settings.privacy.dpiaTemplateEditor.field.itemRequired': 'Verplicht',

  'settings.privacy.dpiaTemplateEditor.checklist.heading': 'Checklist',
  'settings.privacy.dpiaTemplateEditor.section.empty': 'Dit model heeft nog geen secties.',

  'settings.privacy.dpiaTemplateEditor.action.edit': 'Model bewerken',
  'settings.privacy.dpiaTemplateEditor.action.addSection': 'Sectie toevoegen',
  'settings.privacy.dpiaTemplateEditor.action.removeSection': 'Deze sectie verwijderen',
  'settings.privacy.dpiaTemplateEditor.action.addItem': 'Checklistitem toevoegen',
  'settings.privacy.dpiaTemplateEditor.action.reset': 'Meegeleverd model herstellen',
  'settings.privacy.dpiaTemplateEditor.reset.confirm':
    'Het met deze build meegeleverde model herstellen? Het hier geschreven model wordt vervangen. Het chronologische grootboek bewaart het.',

  'settings.privacy.dpiaTemplateEditor.toast.saved': 'DPIA-model opgeslagen.',
  'settings.privacy.dpiaTemplateEditor.toast.reset': 'Het meegeleverde DPIA-model is hersteld.',
} as const satisfies DpiaTemplateEditorCopy;

const dpiaTemplateEditorDaDK = {
  'settings.privacy.dpiaTemplateEditor.page.title': 'DPIA-model',
  'settings.privacy.dpiaTemplateEditor.page.lede':
    'Dette er den model, DPIA-skærmbillederne følger: dens afsnit, dens spørgsmål og dens tjekliste. At redigere den ændrer, hvad denne installation lægger frem til gennemgang. Den indgiver intet, sender intet og validerer intet.',

  'settings.privacy.dpiaTemplateEditor.badge.shipped': 'Leveret med denne build',
  'settings.privacy.dpiaTemplateEditor.badge.operator': 'Skrevet her',
  'settings.privacy.dpiaTemplateEditor.note.shipped':
    'Modellen, der leveres med denne build. Dens tekster er oversat til alle programmets sprog.',
  'settings.privacy.dpiaTemplateEditor.note.operator':
    'Denne model er skrevet her. Den vises for enhver læser nøjagtigt som den blev skrevet, på det sprog den blev skrevet på — den oversættes ikke.',
  'settings.privacy.dpiaTemplateEditor.note.savedBy': 'Gemt af {actor} den {timestamp}.',

  'settings.privacy.dpiaTemplateEditor.identifiers.title':
    'Hvorfor nogle navne forbliver på engelsk',
  'settings.privacy.dpiaTemplateEditor.identifiers.body':
    'Felttyperne og flagene uden påstand er tekniske navne, ikke tekst. Hvert flag uden påstand navngiver en juridisk påstand, som dette produkt ikke fremsætter, og at oversætte en påstand ville svare til at formulere den. De vises på alle sprog nøjagtigt som serveren sender dem.',

  'settings.privacy.dpiaTemplateEditor.field.title': 'Modellens titel',
  'settings.privacy.dpiaTemplateEditor.field.language': 'Sprog, du skriver på',
  'settings.privacy.dpiaTemplateEditor.field.languageHint':
    'Et sprogmærke, for eksempel da-DK. Det registrerer, hvad du skrev; det oversætter det ikke.',
  'settings.privacy.dpiaTemplateEditor.field.sectionId': 'Afsnittets id',
  'settings.privacy.dpiaTemplateEditor.field.sectionIdHint':
    'Kun bogstaver, cifre, „_“, „-“ og „.“. Det følger afsnittet, så omrokering flytter det aldrig.',
  'settings.privacy.dpiaTemplateEditor.field.sectionTitle': 'Afsnittets titel',
  'settings.privacy.dpiaTemplateEditor.field.sectionDescription': 'Afsnittets beskrivelse',
  'settings.privacy.dpiaTemplateEditor.field.prompts': 'Spørgsmål',
  'settings.privacy.dpiaTemplateEditor.field.promptsHint': 'Ét spørgsmål pr. linje.',
  'settings.privacy.dpiaTemplateEditor.field.operatorActions': 'Operatørens handlinger',
  'settings.privacy.dpiaTemplateEditor.field.operatorActionsHint': 'Én handling pr. linje.',
  'settings.privacy.dpiaTemplateEditor.field.itemId': 'Punktets id',
  'settings.privacy.dpiaTemplateEditor.field.itemLabel': 'Punktets etiket',
  'settings.privacy.dpiaTemplateEditor.field.itemType': 'Felttype',
  'settings.privacy.dpiaTemplateEditor.field.itemRequired': 'Påkrævet',

  'settings.privacy.dpiaTemplateEditor.checklist.heading': 'Tjekliste',
  'settings.privacy.dpiaTemplateEditor.section.empty': 'Denne model har endnu ingen afsnit.',

  'settings.privacy.dpiaTemplateEditor.action.edit': 'Rediger modellen',
  'settings.privacy.dpiaTemplateEditor.action.addSection': 'Tilføj afsnit',
  'settings.privacy.dpiaTemplateEditor.action.removeSection': 'Fjern dette afsnit',
  'settings.privacy.dpiaTemplateEditor.action.addItem': 'Tilføj punkt til tjeklisten',
  'settings.privacy.dpiaTemplateEditor.action.reset': 'Gendan den leverede model',
  'settings.privacy.dpiaTemplateEditor.reset.confirm':
    'Gendan den model, der leveres med denne build? Modellen, der er skrevet her, bliver erstattet. Den kronologiske journal bevarer den.',

  'settings.privacy.dpiaTemplateEditor.toast.saved': 'DPIA-modellen er gemt.',
  'settings.privacy.dpiaTemplateEditor.toast.reset': 'Den leverede DPIA-model blev gendannet.',
} as const satisfies DpiaTemplateEditorCopy;

// `modell` is a common-gender noun (en modell), hence "Den" rather than "Det".
const dpiaTemplateEditorSvSE = {
  'settings.privacy.dpiaTemplateEditor.page.title': 'DPIA-modell',
  'settings.privacy.dpiaTemplateEditor.page.lede':
    'Det här är modellen som DPIA-vyerna följer: dess avsnitt, dess frågor och dess checklista. Att redigera den ändrar vad den här installationen lägger fram för granskning. Den lämnar inte in något, skickar inte något och validerar inte något.',

  'settings.privacy.dpiaTemplateEditor.badge.shipped': 'Levereras med den här byggen',
  'settings.privacy.dpiaTemplateEditor.badge.operator': 'Skriven här',
  'settings.privacy.dpiaTemplateEditor.note.shipped':
    'Modellen som levereras med den här byggen. Dess texter är översatta till alla språk som programmet levererar.',
  'settings.privacy.dpiaTemplateEditor.note.operator':
    'Den här modellen skrevs här. Den visas för varje läsare exakt som den skrevs, på det språk den skrevs på — den översätts inte.',
  'settings.privacy.dpiaTemplateEditor.note.savedBy': 'Sparad av {actor} den {timestamp}.',

  'settings.privacy.dpiaTemplateEditor.identifiers.title':
    'Varför vissa namn står kvar på engelska',
  'settings.privacy.dpiaTemplateEditor.identifiers.body':
    'Fälttyperna och flaggorna utan påstående är tekniska namn, inte text. Varje flagga utan påstående namnger ett rättsligt påstående som den här produkten inte gör, och att översätta ett påstående vore att formulera det. De visas på alla språk exakt som servern skickar dem.',

  'settings.privacy.dpiaTemplateEditor.field.title': 'Modellens titel',
  'settings.privacy.dpiaTemplateEditor.field.language': 'Språk du skriver på',
  'settings.privacy.dpiaTemplateEditor.field.languageHint':
    'En språktagg, till exempel sv-SE. Den registrerar vad du skrev; den översätter det inte.',
  'settings.privacy.dpiaTemplateEditor.field.sectionId': 'Avsnittets identifierare',
  'settings.privacy.dpiaTemplateEditor.field.sectionIdHint':
    'Endast bokstäver, siffror, ”_”, ”-” och ”.”. Den följer avsnittet, så omordning flyttar den aldrig.',
  'settings.privacy.dpiaTemplateEditor.field.sectionTitle': 'Avsnittets titel',
  'settings.privacy.dpiaTemplateEditor.field.sectionDescription': 'Avsnittets beskrivning',
  'settings.privacy.dpiaTemplateEditor.field.prompts': 'Frågor',
  'settings.privacy.dpiaTemplateEditor.field.promptsHint': 'En fråga per rad.',
  'settings.privacy.dpiaTemplateEditor.field.operatorActions': 'Operatörens åtgärder',
  'settings.privacy.dpiaTemplateEditor.field.operatorActionsHint': 'En åtgärd per rad.',
  'settings.privacy.dpiaTemplateEditor.field.itemId': 'Postens identifierare',
  'settings.privacy.dpiaTemplateEditor.field.itemLabel': 'Postens etikett',
  'settings.privacy.dpiaTemplateEditor.field.itemType': 'Fälttyp',
  'settings.privacy.dpiaTemplateEditor.field.itemRequired': 'Obligatorisk',

  'settings.privacy.dpiaTemplateEditor.checklist.heading': 'Checklista',
  'settings.privacy.dpiaTemplateEditor.section.empty': 'Den här modellen har inga avsnitt ännu.',

  'settings.privacy.dpiaTemplateEditor.action.edit': 'Redigera modellen',
  'settings.privacy.dpiaTemplateEditor.action.addSection': 'Lägg till avsnitt',
  'settings.privacy.dpiaTemplateEditor.action.removeSection': 'Ta bort det här avsnittet',
  'settings.privacy.dpiaTemplateEditor.action.addItem': 'Lägg till post i checklistan',
  'settings.privacy.dpiaTemplateEditor.action.reset': 'Återställ den levererade modellen',
  'settings.privacy.dpiaTemplateEditor.reset.confirm':
    'Återställa modellen som levereras med den här byggen? Modellen som skrivits här ersätts. Den kronologiska liggaren bevarar den.',

  'settings.privacy.dpiaTemplateEditor.toast.saved': 'DPIA-modellen har sparats.',
  'settings.privacy.dpiaTemplateEditor.toast.reset':
    'Den levererade DPIA-modellen har återställts.',
} as const satisfies DpiaTemplateEditorCopy;

// sv-FI shares sv-SE here: this key set introduces none of the two terms on which the sv-FI
// catalog diverges (`personuppgiftsincident`, `bevarandepolicy`).
const dpiaTemplateEditorSvFI = dpiaTemplateEditorSvSE;

const dpiaTemplateEditorFiFI = {
  'settings.privacy.dpiaTemplateEditor.page.title': 'DPIA-arvion malli',
  'settings.privacy.dpiaTemplateEditor.page.lede':
    'Tämä on malli, jota DPIA-näkymät noudattavat: sen osiot, sen kysymykset ja sen tarkistuslista. Sen muokkaaminen muuttaa sitä, mitä tämä asennus antaa tarkastettavaksi. Se ei toimita mitään, ei lähetä mitään eikä vahvista mitään.',

  'settings.privacy.dpiaTemplateEditor.badge.shipped': 'Toimitettu tämän koosteen mukana',
  'settings.privacy.dpiaTemplateEditor.badge.operator': 'Kirjoitettu täällä',
  'settings.privacy.dpiaTemplateEditor.note.shipped':
    'Tämän koosteen mukana toimitettu malli. Sen tekstit on käännetty kaikille sovelluksen kielille.',
  'settings.privacy.dpiaTemplateEditor.note.operator':
    'Tämä malli on kirjoitettu täällä. Se näytetään jokaiselle lukijalle täsmälleen sellaisena kuin se kirjoitettiin, sillä kielellä jolla se kirjoitettiin — sitä ei käännetä.',
  'settings.privacy.dpiaTemplateEditor.note.savedBy': 'Tallentaja {actor}, {timestamp}.',

  'settings.privacy.dpiaTemplateEditor.identifiers.title': 'Miksi jotkin nimet pysyvät englanniksi',
  'settings.privacy.dpiaTemplateEditor.identifiers.body':
    'Kenttätyypit ja väitteettömyysliput ovat teknisiä nimiä, eivät tekstiä. Jokainen väitteettömyyslippu nimeää oikeudellisen väitteen, jota tämä tuote ei esitä, ja väitteen kääntäminen olisi sen muotoilemista. Ne näytetään kaikilla kielillä täsmälleen sellaisina kuin palvelin ne lähettää.',

  'settings.privacy.dpiaTemplateEditor.field.title': 'Mallin otsikko',
  'settings.privacy.dpiaTemplateEditor.field.language': 'Kieli, jolla kirjoitat',
  'settings.privacy.dpiaTemplateEditor.field.languageHint':
    'Kielitunniste, esimerkiksi fi-FI. Se kirjaa, mitä kirjoitit; se ei käännä sitä.',
  'settings.privacy.dpiaTemplateEditor.field.sectionId': 'Osion tunniste',
  'settings.privacy.dpiaTemplateEditor.field.sectionIdHint':
    'Vain kirjaimia, numeroita sekä merkit ”_”, ”-” ja ”.”. Se kulkee osion mukana, joten järjestyksen muuttaminen ei siirrä sitä.',
  'settings.privacy.dpiaTemplateEditor.field.sectionTitle': 'Osion otsikko',
  'settings.privacy.dpiaTemplateEditor.field.sectionDescription': 'Osion kuvaus',
  'settings.privacy.dpiaTemplateEditor.field.prompts': 'Kysymykset',
  'settings.privacy.dpiaTemplateEditor.field.promptsHint': 'Yksi kysymys riviä kohden.',
  'settings.privacy.dpiaTemplateEditor.field.operatorActions': 'Ylläpitäjän toimet',
  'settings.privacy.dpiaTemplateEditor.field.operatorActionsHint': 'Yksi toimi riviä kohden.',
  'settings.privacy.dpiaTemplateEditor.field.itemId': 'Kohdan tunniste',
  'settings.privacy.dpiaTemplateEditor.field.itemLabel': 'Kohdan nimike',
  'settings.privacy.dpiaTemplateEditor.field.itemType': 'Kenttätyyppi',
  'settings.privacy.dpiaTemplateEditor.field.itemRequired': 'Pakollinen',

  'settings.privacy.dpiaTemplateEditor.checklist.heading': 'Tarkistuslista',
  'settings.privacy.dpiaTemplateEditor.section.empty': 'Tässä mallissa ei ole vielä osioita.',

  'settings.privacy.dpiaTemplateEditor.action.edit': 'Muokkaa mallia',
  'settings.privacy.dpiaTemplateEditor.action.addSection': 'Lisää osio',
  'settings.privacy.dpiaTemplateEditor.action.removeSection': 'Poista tämä osio',
  'settings.privacy.dpiaTemplateEditor.action.addItem': 'Lisää kohta tarkistuslistaan',
  'settings.privacy.dpiaTemplateEditor.action.reset': 'Palauta toimitettu malli',
  'settings.privacy.dpiaTemplateEditor.reset.confirm':
    'Palautetaanko tämän koosteen mukana toimitettu malli? Täällä kirjoitettu malli korvataan. Kronologinen loki säilyttää sen.',

  'settings.privacy.dpiaTemplateEditor.toast.saved': 'DPIA-arvion malli tallennettiin.',
  'settings.privacy.dpiaTemplateEditor.toast.reset': 'Toimitettu DPIA-arvion malli palautettiin.',
} as const satisfies DpiaTemplateEditorCopy;

const dpiaTemplateEditorPlPL = {
  'settings.privacy.dpiaTemplateEditor.page.title': 'Wzór DPIA',
  'settings.privacy.dpiaTemplateEditor.page.lede':
    'To jest wzór, którego trzymają się ekrany DPIA: jego sekcje, jego pytania i jego lista kontrolna. Edycja zmienia to, co ta instalacja przedkłada do przeglądu. Niczego nie składa, niczego nie przesyła i niczego nie waliduje.',

  'settings.privacy.dpiaTemplateEditor.badge.shipped': 'Dostarczony z tą kompilacją',
  'settings.privacy.dpiaTemplateEditor.badge.operator': 'Napisany tutaj',
  'settings.privacy.dpiaTemplateEditor.note.shipped':
    'Wzór dostarczony z tą kompilacją. Jego teksty są przetłumaczone na wszystkie języki aplikacji.',
  'settings.privacy.dpiaTemplateEditor.note.operator':
    'Ten wzór został napisany tutaj. Każdemu czytelnikowi wyświetla się dokładnie tak, jak został wpisany, w języku, w którym go wpisano — nie jest tłumaczony.',
  'settings.privacy.dpiaTemplateEditor.note.savedBy': 'Zapisane przez: {actor}, {timestamp}.',

  'settings.privacy.dpiaTemplateEditor.identifiers.title':
    'Dlaczego niektóre nazwy pozostają po angielsku',
  'settings.privacy.dpiaTemplateEditor.identifiers.body':
    'Typy pól i flagi bez twierdzenia są nazwami technicznymi, a nie tekstem. Każda flaga bez twierdzenia nazywa twierdzenie prawne, którego ten produkt nie formułuje, a przetłumaczenie twierdzenia byłoby jego sformułowaniem. We wszystkich językach są wyświetlane dokładnie tak, jak przesyła je serwer.',

  'settings.privacy.dpiaTemplateEditor.field.title': 'Tytuł wzoru',
  'settings.privacy.dpiaTemplateEditor.field.language': 'Język, w którym piszesz',
  'settings.privacy.dpiaTemplateEditor.field.languageHint':
    'Znacznik języka, na przykład pl-PL. Zapisuje to, co wpisano; nie tłumaczy tego.',
  'settings.privacy.dpiaTemplateEditor.field.sectionId': 'Identyfikator sekcji',
  'settings.privacy.dpiaTemplateEditor.field.sectionIdHint':
    'Tylko litery, cyfry oraz „_”, „-” i „.”. Towarzyszy sekcji, więc zmiana kolejności nigdy go nie przesuwa.',
  'settings.privacy.dpiaTemplateEditor.field.sectionTitle': 'Tytuł sekcji',
  'settings.privacy.dpiaTemplateEditor.field.sectionDescription': 'Opis sekcji',
  'settings.privacy.dpiaTemplateEditor.field.prompts': 'Pytania',
  'settings.privacy.dpiaTemplateEditor.field.promptsHint': 'Jedno pytanie w wierszu.',
  'settings.privacy.dpiaTemplateEditor.field.operatorActions': 'Działania operatora',
  'settings.privacy.dpiaTemplateEditor.field.operatorActionsHint': 'Jedno działanie w wierszu.',
  'settings.privacy.dpiaTemplateEditor.field.itemId': 'Identyfikator pozycji',
  'settings.privacy.dpiaTemplateEditor.field.itemLabel': 'Etykieta pozycji',
  'settings.privacy.dpiaTemplateEditor.field.itemType': 'Typ pola',
  'settings.privacy.dpiaTemplateEditor.field.itemRequired': 'Wymagane',

  'settings.privacy.dpiaTemplateEditor.checklist.heading': 'Lista kontrolna',
  'settings.privacy.dpiaTemplateEditor.section.empty': 'Ten wzór nie ma jeszcze sekcji.',

  'settings.privacy.dpiaTemplateEditor.action.edit': 'Edytuj wzór',
  'settings.privacy.dpiaTemplateEditor.action.addSection': 'Dodaj sekcję',
  'settings.privacy.dpiaTemplateEditor.action.removeSection': 'Usuń tę sekcję',
  'settings.privacy.dpiaTemplateEditor.action.addItem': 'Dodaj pozycję do listy kontrolnej',
  'settings.privacy.dpiaTemplateEditor.action.reset': 'Przywróć dostarczony wzór',
  'settings.privacy.dpiaTemplateEditor.reset.confirm':
    'Przywrócić wzór dostarczony z tą kompilacją? Wzór napisany tutaj zostanie zastąpiony. Dziennik chronologiczny go zachowuje.',

  'settings.privacy.dpiaTemplateEditor.toast.saved': 'Wzór DPIA został zapisany.',
  'settings.privacy.dpiaTemplateEditor.toast.reset': 'Przywrócono dostarczony wzór DPIA.',
} as const satisfies DpiaTemplateEditorCopy;

/**
 * Per-locale copy. The map is deliberately complete, so every shipped locale renders its own
 * words; a locale absent here would fall through to the English source tier.
 */
const DPIA_TEMPLATE_EDITOR_BY_LOCALE: Partial<Record<Locale, DpiaTemplateEditorCopy>> = {
  'en-US': dpiaTemplateEditorEnglish,
  'en-GB': dpiaTemplateEditorEnglish,
  'pt-PT': dpiaTemplateEditorPtPT,
  'pt-BR': dpiaTemplateEditorPtBR,
  'es-ES': dpiaTemplateEditorEsES,
  'fr-FR': dpiaTemplateEditorFrFR,
  'de-DE': dpiaTemplateEditorDeDE,
  'it-IT': dpiaTemplateEditorItIT,
  'nl-NL': dpiaTemplateEditorNlNL,
  'da-DK': dpiaTemplateEditorDaDK,
  'sv-SE': dpiaTemplateEditorSvSE,
  'sv-FI': dpiaTemplateEditorSvFI,
  'fi-FI': dpiaTemplateEditorFiFI,
  'pl-PL': dpiaTemplateEditorPlPL,
};

/** The active copy map: the active locale's reviewed strings, or the English source tier. */
export function useDpiaTemplateEditorCopy(): DpiaTemplateEditorCopy {
  const locale = useActiveLocale();
  return DPIA_TEMPLATE_EDITOR_BY_LOCALE[locale] ?? dpiaTemplateEditorEnglish;
}

/**
 * The editor's translate hook, shaped like `useT`:
 * `const et = useDpiaTemplateEditorT(); et('settings.privacy.dpiaTemplateEditor.page.title')`.
 */
export function useDpiaTemplateEditorT(): (
  key: DpiaTemplateEditorCopyKey,
  params?: TParams,
) => string {
  const copy = useDpiaTemplateEditorCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}

/** Every locale this module ships copy for — read by its completeness test. */
export const DPIA_TEMPLATE_EDITOR_LOCALES = Object.keys(
  DPIA_TEMPLATE_EDITOR_BY_LOCALE,
) as readonly Locale[];

/** The per-locale maps, exposed so the completeness test can compare key sets directly. */
export const DPIA_TEMPLATE_EDITOR_COPY_BY_LOCALE: Partial<Record<Locale, DpiaTemplateEditorCopy>> =
  DPIA_TEMPLATE_EDITOR_BY_LOCALE;
