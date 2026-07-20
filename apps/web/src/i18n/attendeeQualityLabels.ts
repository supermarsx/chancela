/**
 * Attendance-roll **qualidade** labels — "na qualidade de …".
 *
 * These are the same `SignatoryCapacity` variants a signature slot uses, but read differently
 * on a roll: under a signature block `Member` is the abstract "Membro", while on a lista de
 * presenças it is the concrete membership term **Sócio**. The Rust renderer draws exactly this
 * distinction (`quality_label` vs `role_label`,
 * `crates/chancela-templates/src/lib.rs`), and this map is its UI twin so the picker shows the
 * operator the words that will land in the ata.
 *
 * Which of these an entity offers is *not* decided here: the server derives it from the legal
 * type and ships it as `EntityProfile.attendee_qualities`, so a condomínio is never offered
 * "Sócio" and a sociedade anónima never anything but "Acionista".
 *
 * Localization follows the `ledgerEventLabels.ts` / `operationsFallback.ts` boundary: pt-PT is
 * authored (it is also the legally authoritative wording, UX-21) and every other catalog
 * spreads one explicit English slice. These are Portuguese legal categories — *sócio*,
 * *acionista*, *cooperador*, *revisor oficial de contas* — and machine-translating them into
 * eleven languages nobody here can review would invent legal categories that do not exist in
 * those jurisdictions. They belong to the same native-review pass as the other pending tiers.
 *
 * The terms are the masculine singular, the generic form Portuguese legal drafting uses and the
 * one the surrounding roll prose ("presente", "representado", "ausente") already follows. No
 * gender is recorded for an attendee, so a feminine reading ("sócia") goes through the
 * free-text `quality_note` rather than being guessed from a name.
 */
export const attendeeQualityLabelsPtPT = {
  'enum.attendeeQuality.Chair': 'Presidente da mesa',
  'enum.attendeeQuality.Secretary': 'Secretário',
  'enum.attendeeQuality.Member': 'Sócio',
  'enum.attendeeQuality.Shareholder': 'Acionista',
  'enum.attendeeQuality.Associate': 'Associado',
  'enum.attendeeQuality.Cooperator': 'Cooperador',
  'enum.attendeeQuality.Manager': 'Gerente',
  'enum.attendeeQuality.Administrator': 'Administrador',
  'enum.attendeeQuality.Attorney': 'Representante (procurador)',
  'enum.attendeeQuality.CondoOwner': 'Condómino',
  'enum.attendeeQuality.StatutoryAuditor': 'Revisor oficial de contas',
  'enum.attendeeQuality.Guest': 'Convidado',
  'enum.attendeeQuality.Other': 'Outra qualidade (especificar)',
  'acts.attendees.qualityNoteAria': 'Qualidade (texto livre)',
  'acts.attendees.qualityNotePlaceholder': 'p. ex. usufrutuário da quota',
  'acts.attendees.qualityNoteMissing':
    'Indique a qualidade, ou escolha uma da lista — sem texto a ata não a menciona.',
  'fieldHelp.acts.attendeeQuality':
    'Qualidade em que a pessoa participou — «na qualidade de». As opções seguem o tipo legal da entidade: sócio numa sociedade por quotas, acionista numa sociedade anónima, condómino num condomínio.',
  'fieldHelp.acts.attendeeQualityNote':
    'Só para «Outra qualidade»: descreva-a por palavras suas. Fica guardada à parte da lista fechada, para não afetar os mapas por qualidade.',
} as const;

/**
 * The English fallback the thirteen non-pt-PT catalogs spread. The Portuguese term is kept in
 * parentheses where the English word is only an approximation of a distinct legal category.
 */
export const attendeeQualityLabelsEnglish: Record<keyof typeof attendeeQualityLabelsPtPT, string> =
  {
    'enum.attendeeQuality.Chair': 'Chair of the meeting',
    'enum.attendeeQuality.Secretary': 'Secretary',
    'enum.attendeeQuality.Member': 'Member (sócio)',
    'enum.attendeeQuality.Shareholder': 'Shareholder (acionista)',
    'enum.attendeeQuality.Associate': 'Association member (associado)',
    'enum.attendeeQuality.Cooperator': 'Cooperative member (cooperador)',
    'enum.attendeeQuality.Manager': 'Manager (gerente)',
    'enum.attendeeQuality.Administrator': 'Director (administrador)',
    'enum.attendeeQuality.Attorney': 'Representative (procurador)',
    'enum.attendeeQuality.CondoOwner': 'Condominium owner (condómino)',
    'enum.attendeeQuality.StatutoryAuditor': 'Statutory auditor (ROC)',
    'enum.attendeeQuality.Guest': 'Guest',
    'enum.attendeeQuality.Other': 'Other capacity (specify)',
    'acts.attendees.qualityNoteAria': 'Capacity (free text)',
    'acts.attendees.qualityNotePlaceholder': 'e.g. usufructuary of the quota',
    'acts.attendees.qualityNoteMissing':
      'State the capacity, or pick one from the list — with no text the minutes omit it.',
    'fieldHelp.acts.attendeeQuality':
      'The capacity the person attended in. The options follow the entity’s legal type: sócio in a sociedade por quotas, acionista in a sociedade anónima, condómino in a condomínio.',
    'fieldHelp.acts.attendeeQualityNote':
      'For “Other capacity” only: describe it in your own words. It is stored apart from the closed list so reporting by capacity stays clean.',
  };
