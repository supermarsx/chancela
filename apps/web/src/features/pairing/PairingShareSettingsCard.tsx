import { useId } from 'react';
import { Card, Field, FieldHelp, Input, Toggle } from '../../ui';
import { usePairingShareT } from '../../i18n/pairingShareFallback';

export const MIN_EXTERNAL_SIGNATURE_NOTICE_SNOOZE_DAYS = 1;
export const MAX_EXTERNAL_SIGNATURE_NOTICE_SNOOZE_DAYS = 3650;

export interface PairingShareSettingsCardProps {
  emailEnabled: boolean;
  whatsappEnabled: boolean;
  externalSignatureNoticeSnoozeDays: number;
  onEmailEnabledChange: (enabled: boolean) => void;
  onWhatsappEnabledChange: (enabled: boolean) => void;
  onExternalSignatureNoticeSnoozeDaysChange: (days: number) => void;
}

/**
 * Instance-wide UI policy rows. These belong on the admin Services pane because changing
 * them affects every operator, while the pairing panel itself only consumes the persisted flags.
 */
export function PairingShareSettingsCard({
  emailEnabled,
  whatsappEnabled,
  externalSignatureNoticeSnoozeDays,
  onEmailEnabledChange,
  onWhatsappEnabledChange,
  onExternalSignatureNoticeSnoozeDaysChange,
}: PairingShareSettingsCardProps) {
  const pt = usePairingShareT();
  const emailHelpId = useId();
  const whatsappHelpId = useId();

  return (
    <Card title={pt('settings.pairingShare.cardTitle')}>
      <div className="form settings-rows">
        {/* What each switch turns on is background, not something the operator needs in front of
            them to flip it — so it rides the label's `FieldHelp` rather than a caption line under
            every row. `FieldHelp` renders a real `<button>`, and `describedById` puts the bubble
            on the switch's own `aria-describedby`, so the sentence is announced with the control
            and not only to whoever tabs onto the glyph. Same idiom as
            `RegistryAutoUpdateSection`: a switch has no `Field` to hang `help` on. */}
        <Toggle
          label={
            <>
              {pt('settings.pairingShare.email.label')}{' '}
              <FieldHelp
                text={pt('settings.pairingShare.email.hint')}
                describedById={emailHelpId}
              />
            </>
          }
          checked={emailEnabled}
          onChange={onEmailEnabledChange}
          aria-describedby={emailHelpId}
        />
        <Toggle
          label={
            <>
              {pt('settings.pairingShare.whatsapp.label')}{' '}
              <FieldHelp
                text={pt('settings.pairingShare.whatsapp.hint')}
                describedById={whatsappHelpId}
              />
            </>
          }
          checked={whatsappEnabled}
          onChange={onWhatsappEnabledChange}
          aria-describedby={whatsappHelpId}
        />

        <Field
          label={pt('settings.pairingShare.snooze.label')}
          htmlFor="external-signature-notice-snooze-days"
          hint={pt('settings.pairingShare.snooze.hint')}
        >
          <Input
            id="external-signature-notice-snooze-days"
            type="number"
            min={MIN_EXTERNAL_SIGNATURE_NOTICE_SNOOZE_DAYS}
            max={MAX_EXTERNAL_SIGNATURE_NOTICE_SNOOZE_DAYS}
            value={externalSignatureNoticeSnoozeDays}
            onChange={(event) => {
              const parsed = Number(event.target.value);
              if (Number.isFinite(parsed)) {
                onExternalSignatureNoticeSnoozeDaysChange(
                  Math.min(
                    MAX_EXTERNAL_SIGNATURE_NOTICE_SNOOZE_DAYS,
                    Math.max(MIN_EXTERNAL_SIGNATURE_NOTICE_SNOOZE_DAYS, Math.trunc(parsed)),
                  ),
                );
              }
            }}
          />
        </Field>
      </div>
    </Card>
  );
}
