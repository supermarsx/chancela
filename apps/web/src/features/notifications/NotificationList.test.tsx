import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, within } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import { NotificationList } from './NotificationList';
import type { TriagedNotificationItem } from './triage';

function item(overrides: Partial<TriagedNotificationItem>): TriagedNotificationItem {
  return {
    id: 'n-1',
    kind: 'alert',
    priority: 0,
    sortTime: null,
    tone: 'accent',
    badge: 'Alerta',
    title: 'Título',
    detail: 'Detalhe',
    meta: [],
    triageStatus: 'unread',
    ...overrides,
  };
}

afterEach(() => cleanup());

describe('NotificationList leading type icons', () => {
  const cases: {
    name: string;
    item: Partial<TriagedNotificationItem>;
    icon: string;
    toneClass: string;
  }[] = [
    {
      name: 'ledger integrity (error)',
      item: { id: 'integrity', kind: 'alert', tone: 'error', badge: 'Integridade' },
      icon: 'alert',
      toneClass: 'notifications-list__icon--error',
    },
    {
      name: 'compliance review required (warn)',
      item: { id: 'compliance', kind: 'alert', tone: 'warn', badge: 'Conformidade' },
      icon: 'warn',
      toneClass: 'notifications-list__icon--warn',
    },
    {
      name: 'signing-ready advance (accent alert)',
      item: { id: 'advance', kind: 'alert', tone: 'accent', badge: 'Alerta' },
      icon: 'accent',
      toneClass: 'notifications-list__icon--accent',
    },
    {
      name: 'due-soon reminder (accent)',
      item: { id: 'reminder-soon', kind: 'reminder', tone: 'accent', badge: 'Próximo' },
      icon: 'reminder',
      toneClass: 'notifications-list__icon--accent',
    },
    {
      name: 'overdue reminder (warn wins over reminder)',
      item: { id: 'reminder-late', kind: 'reminder', tone: 'warn', badge: 'Em atraso' },
      icon: 'warn',
      toneClass: 'notifications-list__icon--warn',
    },
    {
      name: 'operation log (neutral)',
      item: { id: 'event', kind: 'operation', tone: 'neutral', badge: 'Operação' },
      icon: 'operation',
      toneClass: 'notifications-list__icon--neutral',
    },
  ];

  it.each(cases)(
    'renders a distinct $icon chip for $name',
    ({ item: overrides, icon, toneClass }) => {
      const { container } = renderWithProviders(<NotificationList items={[item(overrides)]} />);
      const chip = container.querySelector('.notifications-list__icon') as HTMLElement;
      expect(chip).toBeTruthy();
      expect(chip.getAttribute('data-notification-icon')).toBe(icon);
      expect(chip.className).toContain(toneClass);
      expect(chip.getAttribute('aria-hidden')).toBe('true');
      expect(chip.querySelector('svg')).toBeTruthy();
    },
  );

  it('gives each notification type a different icon in one list', () => {
    const { container } = renderWithProviders(
      <NotificationList items={cases.map((c) => item(c.item))} />,
    );
    const icons = Array.from(container.querySelectorAll('.notifications-list__icon')).map((el) =>
      el.getAttribute('data-notification-icon'),
    );
    expect(icons).toEqual(['alert', 'warn', 'accent', 'reminder', 'warn', 'operation']);
  });

  it('keeps the leading icon in the compact popup layout where the text badge is hidden', () => {
    const { container } = renderWithProviders(
      <NotificationList compact items={[item({ id: 'compact', tone: 'error', kind: 'alert' })]} />,
    );
    const row = container.querySelector('.notifications-list__item') as HTMLElement;
    expect(within(row).queryByText('Alerta', { selector: '.badge' })).toBeNull();
    const chip = row.querySelector('.notifications-list__icon') as HTMLElement;
    expect(chip.getAttribute('data-notification-icon')).toBe('alert');
    expect(chip.className).toContain('notifications-list__icon--error');
  });
});
