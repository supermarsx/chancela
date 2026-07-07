/**
 * Safe-mode chrome (t26): the root-attribute effects that strip the app back to a
 * minimal, known-good appearance, plus the persistent banner that explains it and offers
 * the way out.
 *
 * In safe mode {@link Layout} does NOT mount {@link AppearanceEffects} or the leather
 * background, so the persisted settings are never applied. This component then forces the
 * default look directly: it removes any `data-theme` (system default), turns the button
 * texture off, and stamps `data-safe-mode="on"` which `theme.css` uses to disable all
 * animations/transitions and hide the leather layer. That way a settings document that
 * crashes the shell can still be reached and repaired.
 *
 * The file is named `SafeModeBanner` (not `SafeMode`) so it never collides with the
 * `safeMode` store module on a case-insensitive filesystem.
 */
import { useEffect } from 'react';
import { DEFAULT_SETTINGS } from '../api/types';
import { useUpdateSettings } from '../api/hooks';
import { useT } from '../i18n';
import { exitSafeMode, SAFE_MODE_QUERY_PARAM } from './safeMode';

/** Leave safe mode and reboot into the normal shell (clears the flag + the `?safe` param). */
function exitAndReload(): void {
  exitSafeMode();
  try {
    const url = new URL(window.location.href);
    url.searchParams.delete(SAFE_MODE_QUERY_PARAM);
    window.location.replace(url.toString());
  } catch {
    window.location.reload();
  }
}

export function SafeModeBanner() {
  const t = useT();
  const resetSettings = useUpdateSettings();

  // Force the default, minimal appearance for as long as safe mode is mounted, and
  // restore the attributes we changed on unmount (a clean exit reloads anyway, but this
  // keeps the effect self-contained and test-friendly).
  useEffect(() => {
    const root = document.documentElement;
    const prevTheme = root.getAttribute('data-theme');
    const prevButtonTexture = root.getAttribute('data-button-texture');

    root.setAttribute('data-safe-mode', 'on');
    root.removeAttribute('data-theme');
    root.setAttribute('data-button-texture', 'off');

    return () => {
      root.removeAttribute('data-safe-mode');
      if (prevTheme === null) root.removeAttribute('data-theme');
      else root.setAttribute('data-theme', prevTheme);
      if (prevButtonTexture === null) root.removeAttribute('data-button-texture');
      else root.setAttribute('data-button-texture', prevButtonTexture);
    };
  }, []);

  function handleReset() {
    // Destructive: repor as definições substitui a configuração guardada pelos valores
    // predefinidos. Ask before writing, then reboot into the normal shell.
    const ok = window.confirm(t('safemode.confirmReset'));
    if (!ok) return;
    resetSettings.mutate(DEFAULT_SETTINGS, {
      onSuccess: () => exitAndReload(),
    });
  }

  return (
    <div className="safe-banner" role="status">
      <div className="safe-banner__text">
        <strong className="safe-banner__title">{t('safemode.title')}</strong>
        <span className="safe-banner__detail">{t('safemode.detail')}</span>
      </div>
      <div className="safe-banner__actions">
        <button type="button" className="safe-banner__btn" onClick={exitAndReload}>
          {t('safemode.exit')}
        </button>
        <button
          type="button"
          className="safe-banner__btn safe-banner__btn--danger"
          onClick={handleReset}
          disabled={resetSettings.isPending}
        >
          {resetSettings.isPending ? t('safemode.resetting') : t('safemode.reset')}
        </button>
      </div>
    </div>
  );
}
