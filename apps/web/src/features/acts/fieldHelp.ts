/**
 * Field-help copy for the ata editor.
 *
 * Each entry resolves its sentence through i18n at access time (via the module-level,
 * non-React `t` escape hatch — the same one `api/labels.ts` uses), so the tooltips follow
 * the active locale live instead of being frozen Portuguese. Consumers keep reading
 * `ataFieldHelp.<name>` and receive an already-translated string; the surrounding editor
 * components subscribe to the locale via `useT`, so a locale flip re-renders them and
 * re-reads these getters. The source strings live in `fieldHelp.acts.*` (see pt-PT).
 */
import { t } from '../../i18n';

export const ataFieldHelp = {
  get title() {
    return t('fieldHelp.acts.title');
  },
  get channel() {
    return t('fieldHelp.acts.channel');
  },
  get meetingDate() {
    return t('fieldHelp.acts.meetingDate');
  },
  get meetingTime() {
    return t('fieldHelp.acts.meetingTime');
  },
  get place() {
    return t('fieldHelp.acts.place');
  },
  get attendanceReference() {
    return t('fieldHelp.acts.attendanceReference');
  },
  get membersPresent() {
    return t('fieldHelp.acts.membersPresent');
  },
  get membersRepresented() {
    return t('fieldHelp.acts.membersRepresented');
  },
  get attendeeName() {
    return t('fieldHelp.acts.attendeeName');
  },
  get attendeePresence() {
    return t('fieldHelp.acts.attendeePresence');
  },
  get attendeeRepresentedBy() {
    return t('fieldHelp.acts.attendeeRepresentedBy');
  },
  get attendeeWeight() {
    return t('fieldHelp.acts.attendeeWeight');
  },
  get telematicEvidence() {
    return t('fieldHelp.acts.telematicEvidence');
  },
  get conveningDispatchDate() {
    return t('fieldHelp.acts.conveningDispatchDate');
  },
  get conveningChannel() {
    return t('fieldHelp.acts.conveningChannel');
  },
  get conveningAntecedenceDays() {
    return t('fieldHelp.acts.conveningAntecedenceDays');
  },
  get conveningEvidenceReference() {
    return t('fieldHelp.acts.conveningEvidenceReference');
  },
  get mesaPresidente() {
    return t('fieldHelp.acts.mesaPresidente');
  },
  get mesaSecretarios() {
    return t('fieldHelp.acts.mesaSecretarios');
  },
  get agendaItem() {
    return t('fieldHelp.acts.agendaItem');
  },
  get deliberationsText() {
    return t('fieldHelp.acts.deliberationsText');
  },
  get structuredAgenda() {
    return t('fieldHelp.acts.structuredAgenda');
  },
  get structuredText() {
    return t('fieldHelp.acts.structuredText');
  },
  get voteMode() {
    return t('fieldHelp.acts.voteMode');
  },
  get voteCount() {
    return t('fieldHelp.acts.voteCount');
  },
  get statements() {
    return t('fieldHelp.acts.statements');
  },
  get referencedDocumentLabel() {
    return t('fieldHelp.acts.referencedDocumentLabel');
  },
  get referencedDocumentRef() {
    return t('fieldHelp.acts.referencedDocumentRef');
  },
  get signatoryName() {
    return t('fieldHelp.acts.signatoryName');
  },
  get signatoryCapacity() {
    return t('fieldHelp.acts.signatoryCapacity');
  },
  get signatoryPermilage() {
    return t('fieldHelp.acts.signatoryPermilage');
  },
  get signatorySigned() {
    return t('fieldHelp.acts.signatorySigned');
  },
  get attachmentLabel() {
    return t('fieldHelp.acts.attachmentLabel');
  },
  get attachmentKind() {
    return t('fieldHelp.acts.attachmentKind');
  },
  get beginningOfProof() {
    return t('fieldHelp.acts.beginningOfProof');
  },
};
