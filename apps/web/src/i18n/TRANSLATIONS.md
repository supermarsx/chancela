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

### Ledger event-kind labels (t17) — a translated key group pending native review

`src/i18n/ledgerEventLabels.ts` holds the display labels for the ledger's event kinds
(`enum.ledgerEventKind.*`, 126 kinds) plus `dashboard.activity.sequence.title` — **127 keys**.
Unlike `operationsFallback.ts` this slice is **fully translated into all 14 locales**, one
`LedgerEventLabels` per locale in that single file, each spread by its own catalog. Keeping the
14 columns in one file is deliberate: a reviewer can diff a language against pt-PT without
opening 14 catalogs, and the shared `LedgerEventLabels` type makes a missing or invented key a
compile error.

| Tier                                | Locales          | Status                                                                                                                        |
| ----------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| source                              | `pt-PT`          | Authoritative.                                                                                                                |
| human                               | `en-US`, `en-GB` | Human-authored; en-GB overrides the 5 keys where British spelling diverges (`catalogue`, `reinitialised`, `Organisation` ×3). |
| **machine · pending native review** | the other 11     | **Translated but NOT natively reviewed.** Same tier their catalogs already carry above.                                       |

These are translated rather than left in English because an event kind is a short,
system-generated status label ("Entidade criada", "Convite de assinatura externa criado"): a
clumsy translation is an awkward phrase, not a false legal claim. Reviewers should treat the 11
pending columns as draft copy — the terminology to check first is the per-locale minutes term
(Protokoll / procès-verbal / verbale / notulen / pöytäkirja / protokół / protokoll), the
GDPR-role vocabulary (processor/controller equivalents), and the commercial-registry extract term
already fixed per locale in the table above.

`sv-FI` follows its documented rule: seeded from `sv-SE` with the genuine Finland-Swedish
divergence applied (`Registerutdrag`, not `Registerbevis`).

**Not translated, by design:** `src/features/templates/templateNames.ts`. Those are the names of
Portuguese legal document types ("Ata de assembleia geral", "Termo de abertura do livro de atas")
and every template asset declares `"locale": "pt-PT"`; they follow the Legislação-shelf rule
below and render verbatim in every locale. The distinction is _system event label_ (translate)
versus _name of a legal instrument_ (do not).

61 pt-BR labels are byte-identical to pt-PT — legitimately shared Portuguese — and are recorded
in `reviewedIdenticalValues.ts` as part of this key group. es-ES, fr-FR and it-IT contribute none,
which is the check that those columns are genuinely translated rather than copied.

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
- **Ledger event data** — scope/actor/timestamp/hash are data, not chrome, and stay verbatim.
  The event **kind** is the one exception (t17): the dotted identifier remains the filter,
  export and `title`-attribute value everywhere, but the line an operator reads is now a
  label localized into all 14 locales, resolved through `ledgerEventKindLabel`
  (`src/api/labels.ts`). An unmapped kind falls back to the raw identifier, so a newer server
  never blanks a row. See the event-kind section above for the review tiers.
- **Built-in template names** — `src/features/templates/templateNames.ts` (t17). Portuguese legal
  document types, extracted from the template assets' own authored headings and rendered verbatim
  in every locale, exactly like the diploma shelf below.
- **The shell footer** (`common.footer`, t37) — "Chancela · Livro de atas digital · v{version}".
  Both segments are names, not chrome: `Chancela` is the product and _livro de atas_ is the
  Portuguese legal instrument the product keeps, so the line renders verbatim in all 14 locales
  (the same _legal-instrument name_ rule as the template names above). Only `{version}` varies,
  and it is the real build version, not authored copy. The 13 identical values are recorded in
  `reviewedIdenticalValues.ts`.
- **The crash diagnostics bundle** (`buildDiagnostics`) and the version-skew console warning
  are technical diagnostics kept as authored, not UI chrome.

## Date & number formatting

Locale-sensitive dates/numbers use the active BCP-47 tag via `Intl` — `useLocale()` feeds
the ledger timestamp (`LedgerTable`) and the printed-on date (`EntityPrintDocument`), and
`formatAtaNumber` renders through the catalog. So switching locale also reformats dates.
