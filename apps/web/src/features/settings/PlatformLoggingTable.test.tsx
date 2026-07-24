import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, within } from '@testing-library/react';
import type { PlatformLoggingSettings } from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import {
  effectiveLogLevel,
  loggingSourceText,
  PlatformLoggingTable,
  type PlatformLoggingTableRow,
} from './PlatformLoggingTable';

afterEach(cleanup);

const logging: PlatformLoggingSettings = {
  global: 'info',
  app: 'debug',
  api: 'warn',
  mcp: 'error',
  service_overrides: { api: 'trace' },
};

describe('PlatformLoggingTable', () => {
  it('renders a compact real table with row headers, labelled controls, and read-only values', () => {
    const setGlobal = vi.fn();
    const setAppOverride = vi.fn();
    const rows: PlatformLoggingTableRow[] = [
      {
        id: 'global',
        scope: 'Global',
        area: {
          id: 'platform-log-global',
          label: 'Global',
          value: 'info',
          onChange: setGlobal,
        },
        override: null,
        effective: 'info',
        source: 'Global: Info',
      },
      {
        id: 'app',
        scope: 'Aplicação',
        area: {
          id: 'platform-log-app',
          label: 'Aplicação',
          value: 'debug',
        },
        override: {
          id: 'platform-log-override-app',
          label: 'Override da aplicação',
          value: '',
          onChange: setAppOverride,
        },
        effective: 'info',
        source: 'Global: Info · Aplicação: Debug',
        configuration: <a href="/admin/logs">Registos</a>,
      },
    ];

    renderWithProviders(<PlatformLoggingTable caption="Níveis de log" rows={rows} />);

    const table = screen.getByRole('table', { name: 'Níveis de log' });
    expect(within(table).getByRole('rowheader', { name: 'Global' })).toBeTruthy();
    expect(within(table).getByRole('rowheader', { name: 'Aplicação' })).toBeTruthy();
    expect(within(table).getByRole('columnheader', { name: /Serviço/ })).toBeTruthy();
    expect(within(table).getByRole('columnheader', { name: /Nível/ })).toBeTruthy();
    expect(within(table).getByRole('columnheader', { name: /Overrides por serviço/ })).toBeTruthy();
    expect(within(table).getByRole('columnheader', { name: /Log efetivo/ })).toBeTruthy();
    expect(within(table).getByRole('columnheader', { name: /Origem/ })).toBeTruthy();

    const globalSelect = within(table).getByLabelText('Global');
    const overrideSelect = within(table).getByLabelText('Override da aplicação');
    fireEvent.change(globalSelect, { target: { value: 'debug' } });
    fireEvent.change(overrideSelect, {
      target: { value: 'error' },
    });
    expect(setGlobal).toHaveBeenCalledWith('debug');
    expect(setAppOverride).toHaveBeenCalledWith('error');

    const levelHelpId = globalSelect.getAttribute('aria-describedby');
    const overrideHelpId = overrideSelect.getAttribute('aria-describedby');
    expect(levelHelpId).toBeTruthy();
    expect(overrideHelpId).toBeTruthy();
    expect(document.getElementById(levelHelpId!)?.textContent).toContain(
      'O nível global limita todos os serviços',
    );
    expect(document.getElementById(overrideHelpId!)?.textContent).toContain(
      'Um override por serviço substitui',
    );

    expect(
      within(table).getByLabelText('Sem override').textContent,
      'the global row explains the non-applicable override cell',
    ).toBe('—');
    expect(within(table).getByRole('link', { name: 'Registos' })).toBeTruthy();
    expect(table.closest('.table-wrap')?.classList.contains('platform-logging-table')).toBe(true);
  });

  it('keeps global-off and explicit override precedence in one shared calculation', () => {
    expect(effectiveLogLevel(logging, 'app')).toBe('info');
    expect(effectiveLogLevel(logging, 'api')).toBe('trace');
    expect(effectiveLogLevel({ ...logging, global: 'off' }, 'api')).toBe('off');
  });

  it('reports the exact source of effective levels', () => {
    const t = ((key: string) =>
      ({
        'settings.platform.logging.global': 'Global',
        'settings.platform.logging.overrides': 'Overrides por serviço',
        'settings.platform.logging.api': 'API',
        'settings.platform.logLevel.info': 'Info',
        'settings.platform.logLevel.trace': 'Trace',
        'settings.platform.logLevel.off': 'Off',
      })[key] ?? key) as never;

    expect(loggingSourceText(logging, 'api', t)).toBe('Overrides por serviço: Trace');
    expect(loggingSourceText({ ...logging, global: 'off' }, 'api', t)).toBe('Global: Off');
  });
});
