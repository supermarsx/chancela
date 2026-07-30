/**
 * The `MessageKey` set as runtime DATA, not just a type.
 *
 * `types.ts` derives `MessageKey` from the en-US source catalog, which answers "is this key
 * spelled right" at compile time but cannot answer "what keys exist" at run time. The admin
 * configuration search index needs the latter: it derives its searchable corpus FROM the
 * catalogs, so that a field label, hint or tooltip becomes findable the moment its copy lands,
 * in every locale, with no second list to maintain.
 *
 * Reading the keys off `ptPT` rather than `enUS` is deliberate and free: `store.ts` already
 * imports the pt-PT catalog eagerly (it is the runtime fallback), so this module adds no bundle
 * weight, while importing `enUS` here would pull a lazily-loaded chunk into the main graph. The
 * two key SETS are identical by construction — every locale is a `Catalog`, which the compiler
 * rejects if it misses a key or invents one — so the choice is about bundling, not about which
 * catalog is authoritative. en-US remains the authoring source of the key set.
 */
import { ptPT } from './locales/pt-PT';
import type { MessageKey } from './types';

/** Every translatable catalog key, in declaration order. */
export const MESSAGE_KEYS: readonly MessageKey[] = Object.keys(ptPT) as MessageKey[];
