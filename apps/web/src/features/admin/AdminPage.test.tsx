import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';

// AdminPage's whole job is to render SettingsPage in admin-surface mode. The admin-surface
// BEHAVIOUR lives in SettingsPage (t36-e2); here we only pin the wrapper's contract — that it
// mounts SettingsPage with `surface="admin"` — so this stays green independent of e2's work and
// needs none of SettingsPage's data mocks.
vi.mock('../settings/SettingsPage', () => ({
  SettingsPage: ({ surface }: { surface?: string }) => (
    <div data-testid="settings-page" data-surface={surface} />
  ),
}));

import { AdminPage } from './AdminPage';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('AdminPage', () => {
  it('renders SettingsPage in admin-surface mode', () => {
    render(<AdminPage />);
    const page = screen.getByTestId('settings-page');
    expect(page.getAttribute('data-surface')).toBe('admin');
  });
});
