/**
 * The i18n type contract.
 *
 * `MessageKey` is derived from the pt-PT source catalog, so the key list has ONE home
 * (ruling: the source catalog is the completeness contract). A locale is a
 * `Catalog` — `Record<MessageKey, string>` — which the compiler rejects if it misses a
 * key or invents one. Translation executors (t19-e3b/e3c) type their files `: Catalog`
 * and get a compile error for any drift from this frozen key set.
 */
import type { ptPT } from './locales/pt-PT';
import type { TParams } from './interpolate';

export type { TParams } from './interpolate';

/** The exhaustive set of translatable UI keys — the keys of the source catalog. */
export type MessageKey = keyof typeof ptPT;

/** A complete per-locale catalog: every `MessageKey` mapped to a string. */
export type Catalog = Record<MessageKey, string>;

/** The translate function: a key plus optional `{name}` params. */
export type TFunction = (key: MessageKey, params?: TParams) => string;
