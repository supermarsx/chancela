/**
 * The per-entity compliance profile (read-only) and statute overlay editor (ENT-03,
 * plan t31 §2.3/R5). The profile is derived server-side from the entity's kind and shown
 * as reference — the rule pack in force, the channels a meeting may use, and the signature
 * policy hint. The statute overlay lets an operator tighten the legal minimums: a quorum
 * floor, a reinforced majority (numerator/denominator, e.g. 2/3), and a convocation-notice
 * period. Saving PATCHes `/v1/entities/{id}` (appending an `entity.statute_updated` ledger
 * event); "Repor" clears the overlay back to the family default.
 */
import { useEffect, useState } from 'react';
import { useUpdateEntity } from '../../api/hooks';
import { entityFamilyLabels, meetingChannelLabels, signaturePolicyLabels } from '../../api/labels';
import type { Entity, StatuteOverrides } from '../../api/types';
import { useT } from '../../i18n';
import { Button, Card, ErrorNote, Field, Icon, Input, useToast } from '../../ui';

// Working copy: every field a plain string so blanks read as "unset". Assembled back into
// a `StatuteOverrides` on save (a whole facet is null when its inputs are blank).
interface StatuteDraft {
  quorum: string;
  majorityNumerator: string;
  majorityDenominator: string;
  convocationNoticeDays: string;
}

function toStatuteDraft(statute: StatuteOverrides | null): StatuteDraft {
  return {
    quorum: statute?.quorum ? String(statute.quorum.min_present) : '',
    majorityNumerator: statute?.majority ? String(statute.majority.numerator) : '',
    majorityDenominator: statute?.majority ? String(statute.majority.denominator) : '',
    convocationNoticeDays:
      statute?.convocation_notice_days == null ? '' : String(statute.convocation_notice_days),
  };
}

function intOrNull(s: string): number | null {
  const trimmed = s.trim();
  if (trimmed === '') return null;
  const n = Number(trimmed);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

function draftToStatute(draft: StatuteDraft): StatuteOverrides {
  const quorum = intOrNull(draft.quorum);
  const num = intOrNull(draft.majorityNumerator);
  const den = intOrNull(draft.majorityDenominator);
  return {
    quorum: quorum == null ? null : { min_present: quorum },
    // A majority needs both terms; a partial pair is treated as unset.
    majority: num != null && den != null ? { numerator: num, denominator: den } : null,
    convocation_notice_days: intOrNull(draft.convocationNoticeDays),
  };
}

export function EntityStatuteEditor({ entity }: { entity: Entity }) {
  const t = useT();
  const toast = useToast();
  const update = useUpdateEntity(entity.id);
  const [draft, setDraft] = useState<StatuteDraft>(() => toStatuteDraft(entity.statute));

  // Save or clear the overlay; both PATCH the statute. R7: the inline ErrorNote above
  // stays; the toast is additive success/error feedback.
  function saveStatute(statute: StatuteOverrides | null) {
    update.mutate(statute === null ? { statute: null } : { statute }, {
      onSuccess: () => toast.success(t('toast.entity.statuteUpdated')),
      onError: (e) => toast.error(e),
    });
  }

  // Re-seed when the persisted statute changes (e.g. after a save round-trips).
  useEffect(() => {
    setDraft(toStatuteDraft(entity.statute));
  }, [entity.statute]);

  const set = <K extends keyof StatuteDraft>(key: K, value: string) =>
    setDraft((d) => ({ ...d, [key]: value }));

  const profile = entity.profile;
  const channels = profile.allowed_channels.map((c) => meetingChannelLabels[c]).join(', ');

  return (
    <Card title={t('entities.statuteCard')}>
      {update.error ? <ErrorNote error={update.error} /> : null}

      <dl className="deflist">
        <div>
          <dt>{t('entities.profile.rulePack')}</dt>
          <dd>
            <code className="mono">{profile.rule_pack_id}</code>
          </dd>
        </div>
        <div>
          <dt>{t('entities.field.family')}</dt>
          <dd>{entityFamilyLabels[profile.family]}</dd>
        </div>
        <div>
          <dt>{t('entities.profile.allowedChannels')}</dt>
          <dd>{channels}</dd>
        </div>
        <div>
          <dt>{t('entities.profile.signaturePolicy')}</dt>
          <dd>{signaturePolicyLabels[profile.signature_policy]}</dd>
        </div>
      </dl>

      <p className="field__hint">{t('entities.statute.hint')}</p>
      <div className="form">
        <Field
          label={t('entities.statute.quorum')}
          htmlFor="statute-quorum"
          hint={t('entities.statute.quorumHint')}
        >
          <Input
            id="statute-quorum"
            type="number"
            min={0}
            value={draft.quorum}
            onChange={(e) => set('quorum', e.target.value)}
          />
        </Field>
        <Field label={t('entities.statute.majority')} hint={t('entities.statute.majorityHint')}>
          <div className="rowline">
            <Input
              type="number"
              min={0}
              aria-label={t('entities.statute.majorityNumerator')}
              placeholder={t('entities.statute.majorityNumerator')}
              value={draft.majorityNumerator}
              onChange={(e) => set('majorityNumerator', e.target.value)}
            />
            <span aria-hidden="true">/</span>
            <Input
              type="number"
              min={1}
              aria-label={t('entities.statute.majorityDenominator')}
              placeholder={t('entities.statute.majorityDenominator')}
              value={draft.majorityDenominator}
              onChange={(e) => set('majorityDenominator', e.target.value)}
            />
          </div>
        </Field>
        <Field
          label={t('entities.statute.convocationNoticeDays')}
          htmlFor="statute-notice"
          hint={t('entities.statute.convocationNoticeHint')}
        >
          <Input
            id="statute-notice"
            type="number"
            min={0}
            value={draft.convocationNoticeDays}
            onChange={(e) => set('convocationNoticeDays', e.target.value)}
          />
        </Field>
        <div className="form__actions">
          <Button
            type="button"
            variant="primary"
            icon={<Icon.Save />}
            disabled={update.isPending}
            onClick={() => saveStatute(draftToStatute(draft))}
          >
            {update.isPending ? t('entities.statute.saving') : t('entities.statute.save')}
          </Button>
          <Button
            type="button"
            variant="ghost"
            icon={<Icon.Trash />}
            disabled={update.isPending || entity.statute == null}
            onClick={() => saveStatute(null)}
          >
            {t('entities.statute.clear')}
          </Button>
        </div>
        {entity.statute == null ? <p className="muted">{t('entities.statute.none')}</p> : null}
      </div>
    </Card>
  );
}
