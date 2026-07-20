/**
 * A tiny external store holding the current leather-grain data-URI for the session.
 *
 * The grain is randomized once per load (preserving the "different hide each
 * session" promise) but can be re-rolled on demand — the Configurações › Aparência
 * "re-roll grain" button calls {@link grainStore.reroll}, and {@link LeatherBackground}
 * subscribes via `useSyncExternalStore`, so a re-roll repaints the whole background
 * immediately without threading state through the router. The grain is deliberately
 * NOT part of the persisted settings document (§2.8 has no grain field); it is a
 * cosmetic, per-session value, exactly like the original randomized seed.
 */
import { leatherGrainDataUri } from './leather';

let current = leatherGrainDataUri();
const listeners = new Set<() => void>();

export const grainStore = {
  /** The current grain data-URI (stable identity between re-rolls). */
  get(): string {
    return current;
  },
  /** Draw a fresh grain and notify subscribers. */
  reroll(): void {
    current = leatherGrainDataUri();
    for (const listener of listeners) listener();
  },
  /** Subscribe to re-rolls; returns an unsubscribe function. */
  subscribe(listener: () => void): () => void {
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  },
};
