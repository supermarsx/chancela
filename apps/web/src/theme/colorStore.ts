/**
 * A small external store for the operator's custom colour overrides, persisted in
 * `localStorage`.
 *
 * Like {@link grainStore}, this is a cosmetic, client-only preference that lives OUTSIDE
 * the persisted §2.8 settings document — that document's `appearance` block is a fixed
 * four-key contract (theme + two leather toggles + intensity), asserted exactly by the
 * settings contract test, so custom colours cannot ride on it without a server change.
 * Storing them here keeps the wire contract untouched while still persisting the choice
 * per browser profile.
 *
 * {@link AppearanceEffects} subscribes via `useSyncExternalStore` and re-applies the
 * overrides as inline CSS custom properties whenever they change, so a picker edit on the
 * Configurações › Aparência card repaints the whole app instantly. An empty store means
 * "use the theme defaults" — {@link applyColorOverrides} then clears every property and
 * `theme.css` governs again.
 *
 * ## Why localStorage
 * A colour choice should survive a reload without a server round-trip, exactly like the
 * safe-mode flag. Access is fully guarded so a browser with storage disabled degrades to
 * "no persistence" rather than throwing.
 */
import { COLOR_OVERRIDE_FIELDS, isHexColor } from './appearance';
import type { ColorOverrides, ColorOverrideField } from './appearance';

const STORAGE_KEY = 'chancela.appearance.colors';

function readStorage(): string | null {
  try {
    return window.localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function writeStorage(value: string): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, value);
  } catch {
    // Storage unavailable — the choice simply won't persist across this reload.
  }
}

function removeStorage(): void {
  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    // A missing key is already the desired state.
  }
}

/** Keep only known fields carrying a valid hex colour; drop everything else. */
function sanitize(input: unknown): ColorOverrides {
  if (!input || typeof input !== 'object') return {};
  const record = input as Record<string, unknown>;
  const clean: ColorOverrides = {};
  for (const field of COLOR_OVERRIDE_FIELDS) {
    const value = record[field];
    if (isHexColor(value)) clean[field] = value;
  }
  return clean;
}

function load(): ColorOverrides {
  const raw = readStorage();
  if (!raw) return {};
  try {
    return sanitize(JSON.parse(raw));
  } catch {
    return {};
  }
}

let current: ColorOverrides = load();
const listeners = new Set<() => void>();

function emit(): void {
  for (const listener of listeners) listener();
}

function commit(next: ColorOverrides): void {
  current = next;
  if (Object.keys(current).length === 0) removeStorage();
  else writeStorage(JSON.stringify(current));
  emit();
}

export const colorStore = {
  /** The current overrides (stable identity between writes). */
  get(): ColorOverrides {
    return current;
  },
  /** Whether any override is currently set (false ⇒ pure theme defaults). */
  hasOverrides(): boolean {
    return Object.keys(current).length > 0;
  },
  /** Replace the whole override set (sanitised), persist and notify. */
  set(next: ColorOverrides): void {
    commit(sanitize(next));
  },
  /** Set (valid hex) or clear (anything else) one field, persist and notify. */
  setField(field: ColorOverrideField, value: string | undefined): void {
    const next = { ...current };
    if (isHexColor(value)) next[field] = value;
    else delete next[field];
    commit(next);
  },
  /** Clear every override — restore the app's default theme colours. */
  reset(): void {
    commit({});
  },
  /** Subscribe to changes; returns an unsubscribe function. */
  subscribe(listener: () => void): () => void {
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  },
};
