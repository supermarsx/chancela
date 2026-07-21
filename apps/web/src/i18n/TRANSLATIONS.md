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
(`enum.ledgerEventKind.*`, 135 kinds) plus `dashboard.activity.sequence.title` — **136 keys**.
The two most recent are `user.welcome_email_sent` / `user.welcome_email_failed` (t108): the
outcome of the account welcome mail, labelled by what the ledger actually records — the relay
*accepted the send* (not that the recipient received it), or the send *did not go out* (never
that the account was not created; it was, which is precisely why the outcome is recorded rather
than failing creation).
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

#### The seven kinds t77 added, and why two of them are not past-tense

An audit of every emit site in `crates/` found **133** kinds against 126 labels. The seven missing
ones (`act.reopened`, `delegation.suspended`, `delegation.resumed`, `email.password.updated`,
`email.password.cleared`, `email.test_sent`, `trust.tsl.imported`) were rendering their dotted wire
identifier in the Arquivo table, the Vista geral activity feed, the entity activity feed and the
notification centre. `src/api/labels.test.ts` now **parses the crate sources** and fails the web
suite when a kind has no label, so the next one cannot leak the same way.

Two kinds **assert an outcome the server does not guarantee**, and the labels deliberately do not
repeat the lie:

- `email.test_sent` is appended for a **failed** test send as well (the payload carries
  `ok: false` and the relay's own refusal), so the label reads "Teste de envio de email
  **efetuado**", not "enviado".
- `trust.tsl.imported` is appended for a **refused** import too — that is the whole point of the
  event (`crates/chancela-api/src/trust.rs`) — so the label reads "Importação da lista de confiança
  TSL **tentada**", following the `registry.auto_update.attempted` precedent already in the catalog
  and the `tentada`/`versucht`/`yritetty`/`Podjęto próbę` idiom each locale established there.

The `email.` prefix is doing two different jobs server-side (SMTP relay _settings_ vs an outbound
_test action_); the labels disambiguate by naming the server — "Palavra-passe do servidor de email",
reusing the wording `settings.email.password.*` already ships — rather than by renaming the kinds,
which are the on-disk append-only format.

No kind carries a `/vN` suffix, so the rule-pack version-stripping the t65 group needed does not
apply here; `ledgerEventKindLabel` looks the kind up whole.

2 further pt-BR labels are byte-identical to pt-PT ("Ata reaberta para correção", "Importação da
lista de confiança TSL tentada") and are registered by name in `reviewedIdenticalValues.ts`. The
pt-BR email labels are _not_ identical ("Senha", "e-mail"), which is the check that the column was
translated rather than copied.

### Dashboard actionable provenance labels (t65) — a translated key group pending native review

`src/i18n/dashboardSourceLabels.ts` holds the display labels for the two provenance identifiers a
dashboard actionable carries on its "Fonte" line — **23 keys**, structured exactly like the t17
group above (one `DashboardSourceLabels` per locale in one file, each spread by its own catalog,
a shared type making a missing or invented key a compile error):

- `enum.dashboardAlertSource.*` (14) — `DashboardAlert.source`, the data scope a check ran over
  (`entities.books` → "Livros da entidade") or the rule pack that raised the alert. Rule-pack keys
  drop the `/vN` suffix so a new pack version inherits its name.
- `enum.dashboardReminderRule.*` (9) — `DashboardReminder.source_rule`, the reminder generator.

| Tier                                | Locales          | Status                                                            |
| ----------------------------------- | ---------------- | ----------------------------------------------------------------- |
| source                              | `pt-PT`          | Authoritative.                                                    |
| human                               | `en-US`, `en-GB` | Human-authored; en-GB overrides the one key where usage diverges. |
| **machine · pending native review** | the other 11     | **Translated but NOT natively reviewed.**                         |

These are translated, not left verbatim: a source is a system label naming a data scope, the same
side of the UX-21 boundary as an event kind. Reviewers should check the per-locale minutes term
and registry-extract term first — the same two that dominate the t17 group. `sv-FI` again follows
its documented rule, seeded from `sv-SE` with `registerutdrag` applied.

The **diploma names inside** a label (CSC, DL 268/94, Código Civil, Código Cooperativo) stay
verbatim in every locale; only the words around them translate. So does the authored
`profile_calendar_plan.preset_label` the payload carries for profile-calendar reminders — it is
the Portuguese name of a statutory meeting, so the five profile-calendar rules are deliberately
absent from the map and render that field instead.

10 pt-BR labels are byte-identical to pt-PT (shared Portuguese) and are recorded in
`reviewedIdenticalValues.ts`. No other locale contributes any, which is the check that those
columns are genuinely translated.

### Seeded role names (t87) — a translated key group pending native review

`src/i18n/roleNameLabels.ts` holds the display names of the **seeded** roles — **15 keys** under
`enum.roleName.*`, structured exactly like the t17 and t65 groups above (one `RoleNameLabels` per
locale in one file, each spread by its own catalog, a shared type making a missing or invented key a
compile error).

The server now stores an **English** name for every seeded role (`crates/chancela-authz/src/role.rs`
— the workspace convention is English identifiers with Portuguese reserved for user-facing copy).
What a pt-PT operator reads is resolved client-side from the role's **id**, which is the stable,
language-neutral key, through `roleNameLabel` (`src/api/labels.ts`).

| Tier                                | Locales          | Status                                                                |
| ----------------------------------- | ---------------- | --------------------------------------------------------------------- |
| source                              | `pt-PT`          | Authoritative.                                                        |
| human                               | `en-US`, `en-GB` | Human-authored; en-GB overrides nothing (see the note in the file).   |
| **machine · pending native review** | the other 11     | **Translated but NOT natively reviewed.**                             |

A role name is a **job title** — a short system label, the same side of the UX-21 boundary as an
event kind — so it is translated. What is emphatically *not* translated is an **operator-authored**
role name: someone who names a role "Gerente da filial" sees exactly that in every locale. Two guards
keep the split (both asserted in `src/api/labels.test.ts`): the id must be one of the seeded ids, and
the stored name must still be the canonical English one, so renaming a seeded role makes the
operator's words win.

**Two keys name retired ids** (`retiredGestor`, `retiredSignatario`). Those roles were
Portuguese-named duplicates with byte-identical permission sets and were merged into `Company Owner`
and `Signatory`; their ids are never reused, but they survive in **append-only ledger events**, which
are never rewritten. Keeping them named — with an explicit "retired role" marker in every locale — is
what stops the merge from trading a duplicate role for unreadable history. Do not delete these keys.

`src/api/labels.test.ts` parses `role.rs` and fails when the crate's seeded ids and this map drift, so
a role added or retired server-side cannot silently render as a bare UUID.

11 pt-BR labels, 3 es-ES and 1 en-US/en-GB (`Auditor`) are byte-identical to pt-PT — shared
Portuguese and ordinary cognates, not untranslated gaps — and are recorded by name in
`reviewedIdenticalValues.ts`.

### For the translation executors (t19-e3b / t19-e3c)

Each owns a disjoint set of `src/i18n/locales/<tag>.ts` files. In each: replace the
`{ ...seed }` spread with a full standalone `Record<MessageKey, string>` of real strings.
Do **not** add, rename or remove keys — the `Catalog` type and the completeness matrix are
the frozen contract (a drift fails `tsc` and `vitest`). Keep the `{name}` placeholders
intact and in a natural position for the target language. When a locale is fully authored
and reviewed, move its row to a "human" tier here.

## Reviewing translated copy: render it, do not read it

Three rules, all learned from real defects rather than proposed in the abstract.

**1. Never interpolate a noun into a sentence containing an inflected word.** In the Romance
locales a participle or adjective must agree in gender (and often number) with the noun that lands
in the hole, and a template can only carry one ending. Write the sentence so the substituted value
is not the subject of anything inflected — an impersonal or passive form, an active first person,
or a reflexive passive — all of which are invariant.

**2. Review translated copy by rendering it with real substitutions, not by reading the catalog.**
A defect of this class is **invisible in the template**: the string reads as perfectly good
Portuguese, and only becomes wrong once a value is substituted. No amount of proofreading the
catalog surfaces it.

**3. Point later words at a locale-constant noun, never at the substituted value.** Rule 1 says the
value must not be the subject of an inflected word; this is the positive form, and it is stronger.
Give the sentence its own noun — _a função_, _die Rolle_, _roolia_ — and let every pronoun,
possessive and participle downstream agree with **that**. The noun is fixed per locale, so a
translator can inflect against it correctly without knowing what will be substituted.

This covers a failure rule 1 does not: a word that agrees with nothing can still **point** at the
wrong thing. Rule 1 catches gender; rule 3 also catches reference.

### The case that produced these rules (t69, `acts.body.paste.*`)

The markdown editor's paste report renders `{construct} ({count}) — removido.` Five of the six
construct names are feminine (`Tabela`, `Imagem`, `Lista`, `Citação`, `Ligação`; only
`Bloco de código` is masculine), so most of the report was ungrammatical in **pt-PT, pt-BR, es-ES,
fr-FR and it-IT** — `Tabela (1) — convertido`, `Image (1) — supprimé`, `Tabella (1) — convertito`.

Fixing it by adding a feminine ending would have held only until the next masculine construct, and
the next person would have hit an identical bug with no sign it had happened before. The sentences
were restructured instead (`convertemos`, `se convirtió`, `abbiamo convertito`).

### The case that produced rule 3 (t71, `users.create.role.*`)

The create-user screen interpolates a **role name** into two strings. Rendered across all 14
locales, both turned out to be immune to rule 1 — not by luck, but because every referring word
already agreed with the locale's own word for "role" (`die Rolle`, _autoridade_, _roolia_) rather
than with the substituted value. That is what rule 3 names.

Rendering still found a defect, which is the argument for rule 2 even when the verdict is "fine".
de-DE read:

> `Sie können {role} nicht vergeben: Sie enthält Berechtigungen, die Sie … nicht besitzen.`

Three `Sie` in one sentence with two referents — polite _you_ twice, _die Rolle_ once. Grammatical,
since `enthält` (3sg) and `besitzen` (2pl polite) disambiguate, but it parses on first read as
"**you** contain permissions" — in a message whose whole job is to explain why a grant was refused,
i.e. exactly when a reader is least willing to parse carefully. Fixed by naming the referent:
`Diese Rolle enthält`.

Note the class: **not** gender agreement. A pronoun that inflects for nothing can still resolve to
the wrong antecedent, and reusing a pronoun that the surrounding sentence already uses for the
reader is how it happens. Languages with a polite second person spelled like a third person (de
`Sie`, es/it _usted_/_Lei_) are where to look.

### Which locale families are structurally safe, and where to look first

| family                                          | why                                                                                                                                        | check                                                                 |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| **Polish, Finnish**                             | impersonal / passive forms (`usunięto`, `zamieniono`, `poistettu`, `muutettu`) do not inflect for the subject at all                       | lowest risk — these were correct by construction                      |
| **Germanic** (de, nl, da)                       | invariant predicative participles (`entfernt`, `verwijderd`, `fjernet`)                                                                    | low risk                                                              |
| **Swedish** (sv-SE, sv-FI)                      | participles inflect for common vs neuter gender; `omgjort`/`borttaget` are neuter forms standing against common-gender nouns (`en tabell`) | **open — flagged for a native reviewer**, deliberately not guessed at |
| **Romance** (pt-PT, pt-BR, es-ES, fr-FR, it-IT) | gender _and_ number agreement on every participle and adjective                                                                            | **look here first**                                                   |

The same instrument found the other user-facing defect of that day (a calendar-day off-by-one):
**follow the value, do not read the pattern.**

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
- **Dashboard actionable provenance** — the alert `source` and the reminder `source_rule` are
  the same exception as the event kind (t65): both are now labels localized into all 14 locales
  through `dashboardAlertSourceLabel` / `dashboardReminderRuleLabel` (`src/api/labels.ts`), with
  the raw identifier as the fallback. What stays verbatim is the reminder's
  `profile_calendar_plan.preset_label` — the backend-authored Portuguese name of a statutory
  meeting — and `source_profile`, which is data (it carries record ids) and is only ever shown
  in the unlabelled-rule fallback line.
- **Built-in template names** — `src/features/templates/templateNames.ts` (t17). Portuguese legal
  document types, extracted from the template assets' own authored headings and rendered verbatim
  in every locale, exactly like the diploma shelf below.
- **The shell footer** (`common.footer`, t37) — "Chancela · Livro de atas digital · v{version}".
  Both segments are names, not chrome: `Chancela` is the product and _livro de atas_ is the
  Portuguese legal instrument the product keeps, so the line renders verbatim in all 14 locales
  (the same _legal-instrument name_ rule as the template names above). Only `{version}` varies,
  and it is the real build version, not authored copy. The 13 identical values are recorded in
  `reviewedIdenticalValues.ts`.
- **The browser's own "leave site?" prompt** (t52) — the `beforeunload` dialog raised by
  `UnsavedChangesGuard` is drawn by the browser and its wording **cannot be set by a page**
  (every current engine ignores `returnValue`). The app controls only whether it appears, so
  there is no key for it and none should be added. The two dialogs we DO control — the in-app
  navigation confirm and the desktop window-close confirm — are fully localized under
  `unsaved.*`.
- **The crash diagnostics bundle** (`buildDiagnostics`) and the version-skew console warning
  are technical diagnostics kept as authored, not UI chrome.

## Date & number formatting

Locale-sensitive dates/numbers use the active BCP-47 tag via `Intl` — `useLocale()` feeds
the ledger timestamp (`LedgerTable`) and the printed-on date (`EntityPrintDocument`), and
`formatAtaNumber` renders through the catalog. So switching locale also reformats dates.
