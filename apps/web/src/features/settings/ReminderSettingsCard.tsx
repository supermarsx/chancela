import type { WorkflowReminderSettings, WorkflowReminderSourceSettings } from '../../api/types';
import { useT } from '../../i18n';
import { useReminderSettingsT } from '../../i18n/reminderSettingsFallback';
import { Card, Field, Input, Toggle } from '../../ui';
import './ReminderSettingsCard.css';

export interface ReminderSettingsCardProps {
  value: WorkflowReminderSettings;
  onChange: <K extends keyof WorkflowReminderSettings>(
    key: K,
    value: WorkflowReminderSettings[K],
  ) => void;
  onSourceChange: <K extends keyof WorkflowReminderSourceSettings>(
    key: K,
    value: WorkflowReminderSourceSettings[K],
  ) => void;
}

function numberValue(value: string, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

/**
 * Compact reminder policy using the same direct-child settings-row contract as the Devices
 * policies: one aligned label/control row per setting, with descriptions in the control column.
 */
export function ReminderSettingsCard({
  value,
  onChange,
  onSourceChange,
}: ReminderSettingsCardProps) {
  const t = useT();
  const rt = useReminderSettingsT();

  return (
    <Card title={t('settings.reminders.cardTitle')}>
      <div className="form settings-rows reminder-settings-rows">
        <Toggle
          label={t('settings.reminders.enabled.label')}
          checked={value.enabled}
          onChange={(enabled) => onChange('enabled', enabled)}
          aria-describedby="reminder-settings-policy-note"
        />
        <p className="field__hint" id="reminder-settings-policy-note">
          {t('settings.reminders.note')}
        </p>

        <Field
          label={t('settings.reminders.dashboardLimit.label')}
          htmlFor="workflow-reminders-dashboard-limit"
          hint={t('settings.reminders.dashboardLimit.hint')}
        >
          <Input
            id="workflow-reminders-dashboard-limit"
            type="number"
            min={0}
            max={50}
            value={value.dashboard_limit}
            onChange={(event) =>
              onChange('dashboard_limit', numberValue(event.target.value, value.dashboard_limit))
            }
          />
        </Field>
        <Field
          label={t('settings.reminders.dueSoon.label')}
          htmlFor="workflow-reminders-due-soon-days"
          hint={t('settings.reminders.dueSoon.hint')}
        >
          <Input
            id="workflow-reminders-due-soon-days"
            type="number"
            min={0}
            max={365}
            value={value.due_soon_days}
            onChange={(event) =>
              onChange('due_soon_days', numberValue(event.target.value, value.due_soon_days))
            }
          />
        </Field>
        <Field
          label={t('settings.reminders.attendanceLookahead.label')}
          htmlFor="workflow-reminders-attendance-lookahead-days"
          hint={t('settings.reminders.attendanceLookahead.hint')}
        >
          <Input
            id="workflow-reminders-attendance-lookahead-days"
            type="number"
            min={0}
            max={365}
            value={value.attendance_lookahead_days}
            onChange={(event) =>
              onChange(
                'attendance_lookahead_days',
                numberValue(event.target.value, value.attendance_lookahead_days),
              )
            }
          />
        </Field>

        <p className="reminder-settings-rows__section" role="heading" aria-level={4}>
          {t('settings.reminders.sources.title')}
        </p>

        <Toggle
          label={t('settings.reminders.sources.profileCalendar')}
          checked={value.sources.profile_calendar}
          onChange={(checked) => onSourceChange('profile_calendar', checked)}
          aria-describedby="reminder-source-profile-calendar-hint"
        />
        <p className="field__hint" id="reminder-source-profile-calendar-hint">
          {rt('settings.reminders.sources.profileCalendar.hint')}
        </p>
        <Toggle
          label={t('settings.reminders.sources.actFollowUps')}
          checked={value.sources.act_follow_ups}
          onChange={(checked) => onSourceChange('act_follow_ups', checked)}
          aria-describedby="reminder-source-act-follow-ups-hint"
        />
        <p className="field__hint" id="reminder-source-act-follow-ups-hint">
          {rt('settings.reminders.sources.actFollowUps.hint')}
        </p>
        <Toggle
          label={t('settings.reminders.sources.attendanceHygiene')}
          checked={value.sources.attendance_hygiene}
          onChange={(checked) => onSourceChange('attendance_hygiene', checked)}
          aria-describedby="reminder-source-attendance-hygiene-hint"
        />
        <p className="field__hint" id="reminder-source-attendance-hygiene-hint">
          {rt('settings.reminders.sources.attendanceHygiene.hint')}
        </p>
        <Toggle
          label={t('settings.reminders.sources.privacyReviews')}
          checked={value.sources.privacy_control_reviews}
          onChange={(checked) => onSourceChange('privacy_control_reviews', checked)}
          aria-describedby="reminder-source-privacy-reviews-hint"
        />
        <p className="field__hint" id="reminder-source-privacy-reviews-hint">
          {rt('settings.reminders.sources.privacyReviews.hint')}
        </p>
      </div>
    </Card>
  );
}
