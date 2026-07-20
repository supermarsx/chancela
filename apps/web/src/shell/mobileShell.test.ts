import { describe, expect, it } from 'vitest';
import { getMobileShellConfig, isMobileShell, type MobileShellWindow } from './mobileShell';

describe('mobile shell detection', () => {
  it('stays false in the default browser shape', () => {
    expect(isMobileShell(undefined)).toBe(false);
    expect(isMobileShell({})).toBe(false);
  });

  it('detects the explicit Chancela mobile shell hint', () => {
    expect(isMobileShell({ __CHANCELA_MOBILE_SHELL__: true })).toBe(true);

    const win: MobileShellWindow = {
      __CHANCELA_MOBILE_SHELL__: { apiBaseUrl: 'http://10.0.2.2:8080' },
    };
    expect(isMobileShell(win)).toBe(true);
    expect(getMobileShellConfig(win)?.apiBaseUrl).toBe('http://10.0.2.2:8080');
  });

  it('allows an explicit disabled shell hint', () => {
    expect(
      isMobileShell({
        __CHANCELA_MOBILE_SHELL__: { enabled: false, apiBaseUrl: 'http://10.0.2.2:8080' },
      }),
    ).toBe(false);
  });

  it('detects common native mobile bridges', () => {
    expect(isMobileShell({ Capacitor: { isNativePlatform: () => true } })).toBe(true);
    expect(isMobileShell({ Capacitor: { getPlatform: () => 'android' } })).toBe(true);
    expect(isMobileShell({ Capacitor: { getPlatform: () => 'web' } })).toBe(false);
    expect(isMobileShell({ cordova: {} })).toBe(true);
    expect(isMobileShell({ ReactNativeWebView: {} })).toBe(true);
  });

  it('detects app-specific WKWebView message handlers', () => {
    expect(
      isMobileShell({
        webkit: { messageHandlers: { chancelaMobile: {} } },
      }),
    ).toBe(true);
    expect(isMobileShell({ webkit: { messageHandlers: { unrelated: {} } } })).toBe(false);
  });
});
