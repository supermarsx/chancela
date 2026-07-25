import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen } from '@testing-library/react';
import { DEFAULT_SETTINGS } from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { ReminderSettingsCard } from './ReminderSettingsCard';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('ReminderSettingsCard', () => {
  it('renders every reminder option as a direct, aligned settings row with described sources', () => {
    const onChange = vi.fn();
    const onSourceChange = vi.fn();
    const { container } = renderWithProviders(
      <ReminderSettingsCard
        value={DEFAULT_SETTINGS.workflow.reminders}
        onChange={onChange}
        onSourceChange={onSourceChange}
      />,
    );

    const rows = container.querySelector('.form.settings-rows.reminder-settings-rows');
    expect(rows).toBeTruthy();
    expect(rows?.querySelector('.registry-auto-update-grid')).toBeNull();
    expect(rows?.querySelector('.checkbox-grid')).toBeNull();
    expect(rows?.querySelectorAll(':scope > .field')).toHaveLength(3);
    expect(rows?.querySelectorAll(':scope > .toggle')).toHaveLength(5);

    const enabled = screen.getByRole('switch', { name: 'Gerar lembretes locais' });
    expect(enabled.getAttribute('aria-describedby')).toBe('reminder-settings-policy-note');
    expect(screen.getByText(/Política local e consultiva/).id).toBe(
      'reminder-settings-policy-note',
    );

    const profile = screen.getByRole('switch', { name: 'Calendário do perfil' });
    expect(profile.getAttribute('aria-describedby')).toBe('reminder-source-profile-calendar-hint');
    expect(screen.getByText(/Datas e prazos do perfil da entidade/).id).toBe(
      'reminder-source-profile-calendar-hint',
    );

    fireEvent.click(enabled);
    expect(onChange).toHaveBeenCalledWith('enabled', !DEFAULT_SETTINGS.workflow.reminders.enabled);

    fireEvent.change(screen.getByLabelText('Prazo breve'), {
      target: { value: '9' },
    });
    expect(onChange).toHaveBeenCalledWith('due_soon_days', 9);

    fireEvent.click(profile);
    expect(onSourceChange).toHaveBeenCalledWith(
      'profile_calendar',
      !DEFAULT_SETTINGS.workflow.reminders.sources.profile_calendar,
    );
  });

  it('keeps reminder-specific sizing scoped and preserves the shared mobile row breakpoint', async () => {
    const nodeFs = 'node:fs';
    const { readFileSync } = (await import(nodeFs)) as {
      readFileSync(path: string, encoding: 'utf8'): string;
    };
    const css = readFileSync('src/features/settings/ReminderSettingsCard.css', 'utf8').replace(
      /\r\n/g,
      '\n',
    );

    expect(css).toContain(".reminder-settings-rows .control[type='number']");
    expect(css).toContain('@media (max-width: 48rem)');
    expect(css).not.toMatch(/(^|[}\n])\s*\.settings-rows\s/m);
  });
});
