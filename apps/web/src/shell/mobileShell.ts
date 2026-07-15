export interface ChancelaMobileShellConfig {
  apiBaseUrl?: string;
  api_base_url?: string;
  enabled?: boolean;
}

export interface CapacitorLike {
  isNativePlatform?: () => boolean;
  getPlatform?: () => string;
}

export interface MobileShellWindow {
  __CHANCELA_MOBILE_SHELL__?: boolean | ChancelaMobileShellConfig;
  Capacitor?: CapacitorLike;
  cordova?: unknown;
  ReactNativeWebView?: unknown;
  webkit?: {
    messageHandlers?: Record<string, unknown>;
  };
}

function currentWindow(): MobileShellWindow | undefined {
  return typeof window === 'undefined' ? undefined : (window as unknown as MobileShellWindow);
}

function isEnabledHint(hint: boolean | ChancelaMobileShellConfig | undefined): boolean {
  if (hint === true) return true;
  if (!hint || typeof hint !== 'object') return false;
  return hint.enabled !== false;
}

function isNativeCapacitor(capacitor: CapacitorLike | undefined): boolean {
  if (!capacitor) return false;
  try {
    if (capacitor.isNativePlatform?.()) return true;
    const platform = capacitor.getPlatform?.();
    return platform === 'ios' || platform === 'android';
  } catch {
    return false;
  }
}

export function getMobileShellConfig(
  win: MobileShellWindow | undefined = currentWindow(),
): ChancelaMobileShellConfig | undefined {
  const hint = win?.__CHANCELA_MOBILE_SHELL__;
  return hint && typeof hint === 'object' ? hint : undefined;
}

export function isMobileShell(win: MobileShellWindow | undefined = currentWindow()): boolean {
  if (!win) return false;
  if (isEnabledHint(win.__CHANCELA_MOBILE_SHELL__)) return true;
  if (isNativeCapacitor(win.Capacitor)) return true;
  if (win.cordova != null) return true;
  if (win.ReactNativeWebView != null) return true;

  const handlers = win.webkit?.messageHandlers;
  return Boolean(handlers?.chancela || handlers?.chancelaMobile);
}
