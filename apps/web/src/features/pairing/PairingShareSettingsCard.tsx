import { Card, Field, Input, Toggle } from '../../ui';
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

  return (
    <Card title={pt('settings.pairingShare.cardTitle')}>
      <div className="form settings-rows">
        <Toggle
          label={pt('settings.pairingShare.email.label')}
          checked={emailEnabled}
          onChange={onEmailEnabledChange}
        />
        <p className="field__hint">{pt('settings.pairingShare.email.hint')}</p>
        <Toggle
          label={pt('settings.pairingShare.whatsapp.label')}
          checked={whatsappEnabled}
          onChange={onWhatsappEnabledChange}
        />
        <p className="field__hint">{pt('settings.pairingShare.whatsapp.hint')}</p>
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
