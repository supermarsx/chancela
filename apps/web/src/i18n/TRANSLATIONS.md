# Translations — honesty ledger

Chancela ships a lean, hand-rolled typed i18n catalog (no runtime i18n dependency). The
UI chrome is fully localized across **14 locales**; this file records, honestly, which
locales are authoritative, which are human-authored, and which are good-faith machine
translations still pending native review.

## The completeness contract

`src/i18n/locales/pt-PT.ts` is the **source catalog**. Its keys are the `MessageKey`
union (`src/i18n/types.ts`), so every other locale is typed `Record<MessageKey, string>`
and the TypeScript compiler rejects a locale that is missing or invents a key. A runtime
completeness matrix (`src/i18n/i18n.test.ts`) additionally asserts, for every shipped
locale, an exact key-set match against the source and that no value is empty.

`~330` keys. To add a UI string: add it to `pt-PT.ts` (the compiler then flags every
other locale until they carry it) and use `t('your.key')` via `useT()`.

## Quality tiers

| Locale                   | Tag     | Tier                     | Status                                                                                                                                                                                                                                                                                     |
| ------------------------ | ------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Portuguese (Portugal)    | `pt-PT` | **source**               | Authoritative — extracted byte-for-byte from the shipped UI. The default locale.                                                                                                                                                                                                           |
| English (United States)  | `en-US` | **human**                | Human-authored (t19-e3a).                                                                                                                                                                                                                                                                  |
| English (United Kingdom) | `en-GB` | **human**                | Human-authored (t19-e3a); British spelling/terminology (catalogue, organisation, minimise).                                                                                                                                                                                                |
| Portuguese (Brazil)      | `pt-BR` | machine · pending review | Authored by t19-e3b; Brazilian usage applied over the pt-PT source (registro, usuário, gerund progressives, Salvar). Minutes term: "ata".                                                                                                                                                  |
| Danish (Denmark)         | `da-DK` | machine · pending review | Authored by t19-e3c (machine, pending native review). Minutes term: "protokol"; register extract "registerattest".                                                                                                                                                                         |
| German (Germany)         | `de-DE` | machine · pending review | Authored by t19-e3b. Minutes term: "Protokoll"; data-protection acronym "DSGVO".                                                                                                                                                                                                           |
| French (France)          | `fr-FR` | machine · pending review | Authored by t19-e3b. Minutes term: "procès-verbal".                                                                                                                                                                                                                                        |
| Finnish (Finland)        | `fi-FI` | machine · pending review | Authored by t19-e3c (machine, pending native review). Minutes term: "pöytäkirja"; register extract "rekisteriote".                                                                                                                                                                         |
| Swedish (Finland)        | `sv-FI` | machine · pending review | Authored by t19-e3c (machine). SEEDED FROM sv-SE + genuine Finland-Swedish diffs ("registerutdrag"/"utdrag" not "registerbevis"; "blanketter" not "formulär"; "andelslag"; "föredragningslista"); the rest follows sv-SE pending Finland-Swedish native review. Minutes term: "protokoll". |
| Italian (Italy)          | `it-IT` | machine · pending review | Authored by t19-e3b. Minutes term: "verbale".                                                                                                                                                                                                                                              |
| Dutch (Netherlands)      | `nl-NL` | machine · pending review | Authored by t19-e3b. Minutes term: "notulen"; data-protection acronym "AVG".                                                                                                                                                                                                               |
| Polish (Poland)          | `pl-PL` | machine · pending review | Authored by t19-e3c (machine, pending native review). Minutes term: "protokół"; data-protection acronym "GDPR".                                                                                                                                                                            |
| Swedish (Sweden)         | `sv-SE` | machine · pending review | Authored by t19-e3c (machine, pending native review). Minutes term: "protokoll"; register extract "registerbevis".                                                                                                                                                                         |
| Spanish (Spain)          | `es-ES` | machine · pending review | Authored by t19-e3b. Minutes term: "acta".                                                                                                                                                                                                                                                 |

**Seeds are placeholders.** The 11 pending locales were scaffolded by t19-e3a as complete,
type-valid catalogs that spread a sibling (`{ ...ptPT }` for pt-BR, `{ ...enUS }` for the
rest), so they compile and the completeness matrix stays green from day one. Until a
translator fills them, selecting one of these locales renders its seed language (Portuguese
for pt-BR, English for the others) — an honest, readable fallback, not a crash. The
`LOCALE_QUALITY` map in `src/i18n/registry.ts` is the machine-readable copy of this table.

The additive operator surface follows the same review boundary in
`src/i18n/operationsFallback.ts`: pt-PT is authoritative and every other shipped catalog imports
the complete English fallback slice until native review. Typed key parity and placeholder gates
still apply, so a missing safety label fails CI instead of disappearing at runtime.

### For the translation executors (t19-e3b / t19-e3c)

Each owns a disjoint set of `src/i18n/locales/<tag>.ts` files. In each: replace the
`{ ...seed }` spread with a full standalone `Record<MessageKey, string>` of real strings.
Do **not** add, rename or remove keys — the `Catalog` type and the completeness matrix are
the frozen contract (a drift fails `tsc` and `vitest`). Keep the `{name}` placeholders
intact and in a natural position for the target language. When a locale is fully authored
and reviewed, move its row to a "human" tier here.

## UX-21 boundary — what is NOT translated (by design, v1)

Backend-authored **legal / compliance content is rendered verbatim, untranslated**, because
pt-PT is legally authoritative (UX-21). This is a deliberate boundary, not a gap:

- **Compliance issues** — rule ids and legal-basis messages emitted by the backend rule
  packs (`CompliancePanel`); only the panel's own chrome (badges, "Rules:", the sealing-
  blocked note) is localized.
- **Registry / server error messages** — `ApiError.message` bodies from the server (registry
  422/502, NIPC 422, CAE refresh, law-store 409/422/502) are shown as received. Only the
  client-authored fallbacks (`error.*` keys) are ours.
- **Registry-derived data values** — a certidão's firma/NIPC/sede/objeto/CAE designations,
  officer names/roles/dates, inscrição text, provenance access-code/digest/timestamps. Only
  the surrounding field labels are localized.
- **The Legislação diploma shelf** — diploma titles, references, extracts (quotations and
  "resumo" descriptions), amendment notes and theme headings come from the `diplomas.ts`
  legal-content module and are rendered verbatim; only the page chrome (title, caveat,
  badges, PDF actions) is localized.
- **Ledger event data** — event kind/scope/actor/timestamp/hash are data, not chrome.
- **The crash diagnostics bundle** (`buildDiagnostics`) and the version-skew console warning
  are technical diagnostics kept as authored, not UI chrome.

## Date & number formatting

Locale-sensitive dates/numbers use the active BCP-47 tag via `Intl` — `useLocale()` feeds
the ledger timestamp (`LedgerTable`) and the printed-on date (`EntityPrintDocument`), and
`formatAtaNumber` renders through the catalog. So switching locale also reformats dates.
