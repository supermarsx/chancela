/**
 * The i18n type contract.
 *
 * `MessageKey` is derived from the en-US source catalog, so the key list has ONE home
 * (ruling: English is the authoring source of truth — code, identifiers and now the i18n
 * key set are English; Portuguese survives only as translation string VALUES). A locale is
 * a `Catalog` — `Record<MessageKey, string>` — which the compiler rejects if it misses a
 * key or invents one; en-US is the lone bare literal that DEFINES the set, and every other
 * locale (pt-PT included) is a `: Catalog` translation checked against it.
 *
 * Deliberate asymmetry (t40, Option A): en-US is the authoring source here, but pt-PT
 * stays the eager runtime fallback (`store.ts`) and the leak-gate reference
 * (`catalogLeakGate.test.ts`), and the per-slice fallback pairs (`operationsFallback.ts`
 * et al.) still anchor their key set on their pt-PT object. Those are independent choices,
 * not oversights — do not "fix" them into en-US without a separate decision.
 */
import type { enUS } from './locales/en-US';
import type { TParams } from './interpolate';

export type { TParams } from './interpolate';

/** The exhaustive set of translatable UI keys — the keys of the source catalog. */
export type MessageKey = keyof typeof enUS;

/** A complete per-locale catalog: every `MessageKey` mapped to a string. */
export type Catalog = Record<MessageKey, string>;

/** The translate function: a key plus optional `{name}` params. */
export type TFunction = (key: MessageKey, params?: TParams) => string;
