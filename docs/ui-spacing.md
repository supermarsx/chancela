# UI vertical spacing (design decision)

> **Status.** All three reported defects are **fixed and guarded** (`2a538e87`, `7bb5dcd8`,
> `28050209`). Pass 2 — the container rhythm, blast radius ~156 cards — was approved by the product
> owner and landed in `28050209`, together with a fourth surface the same session turned up: modal
> bodies. **Pass 4** then answered a fourth complaint, that tables and banners are "glued to
> everything or anything that comes next and before": both primitives now own their outer edge —
> see the "Tables and banners" section under [What was fixed](#what-was-fixed). (Not an anchor
> link: that heading's em dash slugifies differently under mkdocs and GitHub, and
> `mkdocs build --strict` fails on the mismatch.) **Pass 6** then landed the two items this
> document had been holding for the product owner — the `.field__hint` conflict (Pass 3, item 1)
> and placeholder contrast. What remains open is the rest of **Pass 3**, listed under
> [What is decided](#what-is-decided-and-what-is-still-open).
>
> Component and rule counts below were measured against the tree at **`7e09cf83`** by parsing the
> TypeScript and CSS ASTs, not by grepping — the method matters, because a regex count of this same
> component family was wrong by a factor of two (see [Counting](#counting-why-the-numbers-here-are-ast-derived)).
> **Every spacing figure quoted in pixels was measured differently again**: by rendering the real
> stylesheet in headless Chromium and reading the computed box, in both colour schemes. That method
> is not decoration. Reading specificity off the page got three conclusions in this document wrong —
> see [What measurement changed](#what-measurement-changed-that-reading-the-css-did-not).

## The request

Three complaints, minutes apart, while walking the app:

> *"[Acompanhamento operacional — …] these banner dont have nice margins yet globally, this needs to
> be fixed. add tests to ensure fix"*

> *"margins in dropdown entries, should be neater like the log levels for example"*

> *"[Rede de saída dos conetores — …] fix margins from the paragraph to the action buttons too"*

They were reported as three bugs. **They are one defect with three faces, plus one unrelated
finding.** Treating them as three patches is what made the first one recur.

## The mechanism

**`.panel__body` and `.card` own padding but declare no child-spacing rule.** There is no
`.panel__body > * + *`. So the space between a card's children is not a property of the design — it
is a property of **which tag each child happens to be**:

- a `<p>` brings the user agent's own `margin-block: 1em`, so it looks roughly right *by accident*;
- a `<div>` — which is every action row — brings **nothing**, so it sits flush against whatever is
  above it.

That single sentence explains the banner complaint (block children's UA margins landing *inside* the
banner's padding and blowing the box out), the paragraph-to-buttons complaint (a `<div>` action row
after a `<p>`, with nothing owning the gap), and why both kept coming back after being "fixed".

The app compensates per surface. Each compensation repairs one screen and leaves the rest, and
several of them outrank any global rule written later, so the next person's global fix silently does
not apply where a local patch already exists.

## The codebase predicted this, in writing

This is not hindsight. Two comments in `apps/web/src/theme.css` already name the mechanism. Locate
them by content — line numbers in this file drift daily:

- `"own margin because `.panel__body` has no child-spacing rule"` (currently ~line 1560), listing
  `.settings-notes` and `.email-card .panel__body > * + *` as the existing workarounds.
- `"the reason is worth recording because it will catch the next card: `.panel__body` has NO
  child-spacing rule, and `.field__hint` sets `margin: 0` … together they mean a hint placed as a
  SIBLING of the form gets no space at all"` (currently ~line 4626, from lane t100).

t100 recorded the mechanism, predicted the recurrence, and fixed one surface
(`.settings-notes { margin-top: 1rem }`). It recurred **twice within hours** — the connector-egress
panel, and a preservation-package row in the export table where another lane hit the identical
`.field__hint`-then-button collision and had to add its own scoped override (`ff0a5f6c`).

## The numbers

Measured at `7e09cf83`.

**Containers that do not own their rhythm**

| | |
|---|---|
| `<Card>` elements | 262 |
| wrapping children in a single `stack`/`form` child (rhythm owned) | 106 |
| **not wrapped** (spacing comes from UA `<p>` margins, or nothing) | **156** |
| …of those, with more than one child, so a gap is visibly wrong today | **68** |

**There is no spacing scale.** `--space: 1rem` is the only spacing token and is referenced **5**
times in an 11k-line stylesheet. In its place are **12** separate `> * + *` re-inventions at **7**
distinct values (1.5rem, 1rem, 0.8rem, 0.75rem, 0.55rem, 0.5rem, 0, plus one `var()`):

```
.stack > * + *                        1.5rem
.split__aside > * + *                 1.5rem
.form > * + *                         1rem
.email-card .panel__body > * + *      1rem     <- a per-surface patch of the missing container rule
.data-status-section > * + *          0.8rem
.stack--tight > * + *                 0.75rem
.seal-designer__content > * + * (+2)  0.75rem
.data-status-usage-groups > div > *+* 0.55rem
.vote > * + *                         0.5rem
:where(.inline-warning__body) > * + * 0.5rem   <- added by this lane
.settings-rows > * + *                var(--settings-row-gap)
.field-table > * + *                  0
```

**Action rows have no owner for their top gap.** 75 selectors mention actions; 32 declare any
margin or gap; **20 of those 32 declare only a horizontal `gap`** and no top margin at all. Where a
top margin *is* declared the values are 0.35 / 0.5 / 0.65 / 0.75 / 0.9 / 1rem. So
paragraph-to-buttons spacing is unowned across the app, which is exactly the third complaint.

## What was fixed

### Banners — `2a538e87`

`.inline-warning` is a padded box (`0.85rem 1rem`) whose `__body` renders caller content. **62 of
its 238 call sites pass block-level children** (`<p>`, `<ul>`, `<dl>`); 20 pass more than one.

It had been zeroed once, for one surface — `.external-signing-workflows .inline-warning__body > p
{ margin: 0 }` — which repaired **1 of the 62** and, at (0,3,0), would have outranked any global rule
written afterwards. Replaced with two rules next to the primitive:

```css
:where(.inline-warning__body) > *     { margin-top: 0; margin-bottom: 0; }
:where(.inline-warning__body) > * + * { margin-top: 0.5rem; }
```

Two declarations, because collapsing the outer edge and spacing siblings are different jobs: a
blanket `margin: 0` (what the page-scoped patch did) glues consecutive paragraphs together. Both
wrapped in `:where()` to pin them at (0,0,0), matching the `margin-top` rules directly above them
(`f4e1c8c0`) — a caller or surface wanting its own rhythm still wins with a plain class selector, no
`!important`, no specificity war.

### Menu entries — `7bb5dcd8`

**This one is not the container-rhythm defect.** It is unrelated, and the finding is the useful part.

The dropdown the operator praised is a **native `<select>`** (shared `Select`,
`apps/web/src/ui/index.tsx`). `.control--select` dresses only the *closed box*; the option rows are
drawn by the operating system. **The reference reads well because the app does not style it.**

The hand-built menus cannot inherit that, so each invented its own entry padding. Enumerated by ARIA
role rather than class name — there are exactly four:

| menu | class | role | was |
|---|---|---|---|
| Topbar overflow | `.topbar__menu-item` | `menuitem` | `0.5rem 0.6rem` |
| Session picker | `.session-picker__item` | `menuitemradio` | `0.4rem 0.5rem` |
| Template block add | `.template-block-add__menu-item` | `menuitem` | `0.5rem 0.65rem` |
| Admin config finder | `.admin-config-finder__result` | `option` | `0.5rem 0.65rem` |

All four now take their row metric from one `.menu-item` class. **The value is not invented**: it is
`.control`'s own `0.55rem 0.7rem` — the padding of the very control a native option list drops out
of — so the menus track the reference if it ever moves, rather than matching a copied number.

Two things deliberately **not** changed, and recorded so nobody "finishes the job" by mistake:

- `line-height`, and the panels' inter-row `gap` (topbar 0.15rem, session picker 0.2rem, the other
  two contiguous). The menus carry different type sizes, and separated-versus-contiguous rows is a
  real design difference rather than drift.
- **`.leg-corpus__index-item` is not a dropdown.** It is a legislation index sidebar with no menu or
  listbox role. It was left alone rather than restyling something nobody complained about.

No conversion between native and custom was needed, and none should be attempted: the native options
are the target, not the problem.

### Container rhythm — `28050209` (Pass 2)

Option B, approved. Two rules beside `.panel__body`, the same shape as the banner fix:

```css
:where(.panel__body, .card) > *     { margin-top: 0; margin-bottom: 0; }
:where(.panel__body, .card) > * + * { margin-top: 1rem; }
```

**1rem is not a ninth value and not an arbitrary pick from the eight.** It is what every
per-surface patch of this exact defect already used — `.settings-notes`,
`.email-card .panel__body > * + *`, `:where(.inline-warning)`'s standalone margin — and it is
`.form > * + *`'s band, so a card of loose children reads like one whose children sit in a form.

Retired with it, all three measured byte-identical before and after: `.settings-notes`,
`.email-card .panel__body > * + *`, and
`.external-signing-workflows .panel__body > .stack--tight, > .form` (which existed to cancel the
UA's `form { margin-block-end: 1em }` — both those cards have exactly one body child, so the new
`> *` reset covers it exactly).

Measured effect, light and dark identical (it is a margin-only change): the connector-egress card's
paragraph-to-field gap 0 → 16px; a card of bare `<p>`s keeps its 16px inner gaps but loses 36px of
accidental air at its edges; a hint-then-actions row 0 → 16px. Unchanged, as required: single-child
cards, `.stack`-wrapped cards, dashboard metric tiles, `.data-status-section`, the book-export row,
a hint inside a `.field`, the banner fix, and the notification popup's footer.

### Modal bodies — `28050209`

The same defect wearing the opposite mechanism, found while verifying Pass 2 and reported as
"buttons in the credential test modal have wrong margins".

**`.modal__body` is `display: flex; flex-direction: column; gap: 0.85rem`** — unlike
`.panel__body` it *does* own its child spacing. That inverts everything: a child's own block margin
does not compete with the container in the cascade, it **adds** to the gap. So the Pass 2 rule does
not reach modals, a `:where()` rule cannot fix it the way it fixes a card, and a per-surface margin
does not merely shadow the shared rhythm — it silently doubles it.

Measured across all eight dialogs, `.modal__body` produced **six different child gaps**:

| gap | cause |
|---|---|
| 13.6px | the intended one, where the child zeroes its own margin |
| 19.98px | `.modal__foot { margin-top: 0.4rem }` — every dialog's button row |
| 25.6px / 37.6px | two dialogs putting `.stack--tight` / `.stack` on the body *itself* |
| 29.59px | `:where(.inline-warning)`'s standalone `margin-top`, adding to the gap |
| 34.38px | a `<p class="modal__intro">` carrying the UA's own block margins |

Fixed by one rule beside the primitive plus two retirements — not a per-surface patch:

```css
:where(.modal__body) > * { margin-block: 0; }
```

`.modal__foot` lost its `margin-top`, and the two dialogs that stacked a `.stack`/`.stack--tight`
on the body dropped it. All eight dialogs now render at a single 13.6px baseline in both themes.

One ordering dependency is load-bearing and is pinned by a test: the reset and
`:where(.inline-warning)` are **both** (0,0,0), so which wins is decided by source order alone. The
reset must stay below the banner primitive, or `InlineWarning`s in dialogs silently regain 1rem.

### Tables and banners — the outer edge (Pass 4)

Reported globally, in one sentence: *"table and banners with alerts dont have global neat margins
and such theyre glued to everything or anything that comes next and before."*

**This is the same defect one level out.** Pass 2 gave containers a rhythm over their *direct
children*. These two primitives are usually **not** direct children — they sit inside a plain
`<div>`, a bare `<section>`, a `<details>`, or a one-off surface class — so the shared rule never
reached them, and neither primitive owned its own outer edge:

- **`.table-wrap` declared no margin at all.** A table's entire spacing was borrowed from whichever
  container happened to hold it, and only when it was that container's direct child.
- **`:where(.inline-warning)` declared `margin-top` and nothing for its bottom edge.** A banner's
  gap to what *follows* it was always somebody else's `margin-top` — which, when the next sibling
  is a `<div>`, is zero. Measured `margin-bottom: 0px` on every one of 22 fixtures.

Measured in Chromium against the real sheet, light and dark identical throughout (it is a
margin-only change). The zeroes are the complaint:

| context | above → below, before | after |
|---|---|---|
| table then a `<div>` action row, bare `<section>` | 17 / **0** | 17 / **16** |
| banner then a `<div>` action row, plain `<div>` | 17 / **0** | 17 / **16** |
| table then `EmptyState`, plain `<div>` | **0** | **16** |
| `<details>` summary then table | **0** / 17 | **16** / 16 |
| table in a plain `<div>` or a bespoke class | 17 / 17 | 17 / 16 |
| banner in a `<td>` | 16 / 15.19 | 16 / 16 |

Unchanged, and each one deliberately: a table direct-child of `.panel__body` (16/16), `.stack`
(24/24), `.stack--tight` (17/12), `.form` (17/16), `.settings-rows` (31.39/14.39),
`.data-status-section` (12.8), the first-child and only-child cases (flush at the container's 20px
padding), all eight dialogs (13.59px), and the `.stack--tight` inside a table cell.

**The fix, at the primitives, at `:where()` zero specificity:**

```css
:where(.table-wrap)              { margin-top: 1rem; }   /* beside the table primitive   */
:where(.table-wrap:first-child)  { margin-top: 0; }
:where(.inline-warning, .table-wrap) + * { margin-top: 1rem; }   /* the bottom edge */
```

**The bottom edge is the next sibling's `margin-top`, not a `margin-bottom`, and that is the whole
design.** Adjacent siblings' block margins **collapse to the max**, and collapsing is a layout rule
that never consults specificity. A `margin-bottom: 1rem` on the primitive would sit uncontested —
nothing in the sheet sets `margin-bottom` on these boxes — and beat every container band tighter
than 1rem: `.stack--tight`'s 0.75rem under all 62 banners and tables it holds, and
`.data-status-section`'s deliberately tighter 0.8rem. `:where()` would not save it, because the two
rules are not on the same element. Setting the **next sibling's** `margin-top` puts the rule on the
same element and property a container rhythm sets, where `.stack--tight > * + *` (0,1,0) beats
(0,0,0) outright. Verified: `.stack--tight` measures 12px before and after.

**Gap containers, again — and this time there are six.** `:where(A) + *` puts a margin on a flex or
grid item, where it *adds* to the `gap` rather than competing. One rule beside the primitives
neutralises both edges for the six gap containers that hold one, `.modal__body` excepted (its own
`> *` reset is further down the sheet, equally (0,0,0), and already wins on source order):

```css
:where(.chronology-analytics, .field, .onboarding__body, .pdf-validator-report,
       .signin__form, .signing-provider-list)
  > :where(.inline-warning, .table-wrap),
:where(…same…) > :where(.inline-warning, .table-wrap) + * { margin-top: revert; }
```

Two things about that rule are load-bearing and were both found by measuring:

- **`revert`, not `0`.** `margin-top: 0` is an author declaration and so also beats the *user
  agent's*. Measured regression when it was tried: a `<p class="signing-provider-list__note">`
  after a banner collapsed 27.39px → 10.39px, because its own UA `margin-block: 1em` was zeroed
  along with ours. `revert` undoes only the author layer.
- **`.chronology-analytics` was found by the guard, not by hand.** A by-hand sweep of `<Table>` and
  `<InlineWarning>` call sites missed it, because its table is hand-rolled `.table-wrap` markup
  rather than the component. Only the tree walk saw it. Without the neutraliser it measured
  12.8px → 28.8px.

**Side effect, and it is an improvement rather than a regression, but it is a visible change on
screens nobody complained about.** Neutralising the *primitive's own* margin in those containers
also removes a **pre-existing** double-gap that
[What measurement changed](#what-measurement-changed-that-reading-the-css-did-not) item 3 predicted
and nobody had acted on. Each is exactly −16px, the banner's margin no longer adding to the gap:

| container | gap | before | after |
|---|---|---|---|
| `.pdf-validator-report` | 1rem | 49px | 33px |
| `.signin__form` | 0.9rem | 47.5px | 31.66px |
| `.signing-provider-list` | 0.65rem | 43.39px | 27.39px |
| `.onboarding__body` | 0.9rem | 30.39px | 14.39px |
| `.field` | 0.35rem | 21.59px | 5.59px |

`.field`'s 5.59px is the tightest and the one to look at first: it is the field's own
label→control band, and the banner below it already sat at 5.59px, so the box is now symmetric
where it was 21.59 above / 5.59 below. Two call sites (`ServerEnvSection`, `AtaEditorPage`).

**Retired: nothing, and one thing deliberately kept.** There was nothing to supersede — no rule in
the sheet gave either primitive a block margin, and no rule spaced a sibling of one. The single
candidate is **`.data-status-table { margin-top: 0.1rem }`** (8 tables, class passed to `<Table>`,
so it lands on `.table-wrap` at (0,1,0) and outranks the shared rule). It is **kept**, by this
document's own precedent: it is not a repair of a missing gap but a deliberate *tightening* that
pins each storage table to its section heading — the same shape as `.data-status-section > * + *`,
which this document already had to correct itself about. Measured unchanged at 1.59px, against
12.8px without it. It is registered by name in the guard so the next one is a decision, not a drift.

### Wide panes — the horizontal axis (Pass 5)

Two more reports, minutes apart, and they are one defect again:

> *"the search indexer controls in admin needs to be a bit less wide, make it normal wide."*

> *"the preview info tab shouldn't be as wide as well."*

**`WIDE_SUBSECTIONS` (`SettingsPage.tsx`) already had the principle right and could only apply it
at whole-pane granularity.** Five panes are lifted past the 1080px reading measure because each
holds a six- or seven-column grid that scrolls sideways at the normal measure. The same comment
records the counter-case: sibling panes were kept **out** of the list because widening hurt them —
*"Política de assinatura is label/control rows (measured 78ch → 126ch when widened)"*. A pane
holding **both** a grid and label/control rows had to choose, and choosing width dragged the prose
out with it.

Measured at 1920px (`.app` 1080px normal → 1472px wide), against the identical markup on a
normal-width page. All five panes had it, not the two reported:

| pane | prose | control row | banner | grid |
|---|---|---|---|---|
| normal-page baseline | 117–122ch | 90ch | 94ch | 90ch |
| `operations:search` | 171 → **122** | 128 → **94** | — | 128 → 128 |
| `operations:template-preview` | 41 → 41 | — | 132 → **94** | 132 → 132 |
| `signing:tsl` | 166 → **122** | 128 → 128 † | — | 128 → 128 |
| `signing:tsa` | 166 → **122** | 128 → 128 † | — | 128 → 128 |
| `signing:providers` | 171 → **122** | 128 → **94** | — | 128 → 128 |

Every grid keeps its full width; every capped figure lands on the normal-page measure. Three rules
beside `.app:has(.wide-page)`, all at `:where()` zero specificity:

```css
:where(.wide-page) :where(.field, .field__hint, .field__error, .inline-warning, p),
:where(.wide-page) :where(.settings-rows):not(:has(.table-wrap)) {
  max-inline-size: calc(var(--app-measure) - 2 * var(--app-gutter));
}
:where(.wide-page) :where(.control, .input-reset) {
  max-inline-size: min(100%, calc(var(--app-measure) - 2 * var(--app-gutter)));
}
```

**The cap is not a chosen number.** It is `calc(var(--app-measure) - 2 * var(--app-gutter))` — the
expression `.page-header` is already pinned to — so the target is by construction *the width this
content has on an ordinary settings tab*, and it moves if the measure ever does. Below the reading
measure the rules are inert (verified at 900px: nothing moves).

**† The two panes that could not be fully fixed, and why.** `.settings-rows` is `display: grid`
and `.settings-rows > .field` is `grid-template-columns: subgrid`. **A subgrid item takes its
tracks from its parent**, so a per-item cap computes and does not bind — measured `max-width:
984px` in the computed style against a `1334px` used width. Only the container can constrain a
subgrid row. On `signing:tsl` and `signing:tsa` that same container also holds the seven-column
table as a `grid-column: 1 / -1` child, so capping it would shrink the table back to the measure
it scrolled sideways at — trading this defect for the one `WIDE_SUBSECTIONS` was opened to fix.
Hence `:not(:has(.table-wrap))`, and hence those two rows staying at 128ch on purpose. Their
*visible* defect is fixed anyway by the third rule: the URL input goes 117ch → 96ch, and their
prose 166ch → 122ch. Fixing the row box too would mean moving the table out of that grid in
`SettingsPage.tsx`.

**Not capped, each checked before being left out:** `.table-wrap` and its grids;
`.template-preview-samples__tabs`, whose subnav rail is full-width on purpose so the editor tabs
align with the grid's left edge; and `.section-head`, a header bar *for* the grid below it whose
button aligns with the grid's right edge and whose own prose is shrink-to-fit at 16ch.

**No change to `WIDE_SUBSECTIONS` was needed**, which was the point — removing an entry would have
restored the sideways-scrolling table, and the list lives in a file another lane is restructuring.

### Consecutive hints, and placeholder contrast (Pass 6)

The two items this document had been holding for the product owner. They landed together because
they are the same kind of decision — a shared primitive whose default was wrong everywhere — and
they were both **measured in Chromium against the real sheet, in both colour schemes**, before and
after.

**The hint run.** `.field__hint { margin: 0 }` is (0,1,0); so is `.stack--tight > * + *`,
`.stack > * + *` and `.form > * + *`; and the hint's zero is declared **later in the sheet** than
all three, so it won on source order and consecutive hints rendered at **0px**. The tree walk finds
**23 adjacent hint pairs** — one of them `Field`'s own hint/error, which are mutually exclusive and
can never both render, and which the walk deliberately does not try to prove away.

The deferral was right: pinning the zero to `:where()` would have loosened `ff0a5f6c`'s
preservation-package row, whose tightness under its `Toggle` is deliberate. **The fix distinguishes
the two relationships instead of arbitrating between them** — a hint following another hint is one
explanation; a hint following the control it describes is a caption:

```css
:where(.field__hint, .field__error) + .field__hint,
:where(.field__hint, .field__error) + .field__error { margin-top: 0.5rem; }
```

**The predecessor is in `:where()` and the subject is not, and that is the whole design.** It pins
the rule at **(0,1,0)** — the same weight as the zero it overrides and as every container band — so
three things are true at once, each of them measured rather than reasoned:

- it beats `.field__hint`'s own zero **on source order**, being declared directly beneath it;
- it matches nothing that follows a control, so the caption case is untouched *by construction*
  rather than by exception. The preservation-package row measures **0px before and after**;
- it still **loses** to a container that declares a hint rhythm further down the sheet.
  `.settings-rows > * + *` (0.9rem plus its hairline) is the one that does, on five settings
  surfaces, and keeps it: **14.39px before and after**.

`0.5rem` is not a ninth value. It is `:where(.inline-warning__body) > * + *` (`2a538e87`) — what
this sheet already gives consecutive explanatory paragraphs inside a primitive, one primitive over.
`.field__error` joins on both sides because the markdown editor's byte-count line switches between
the two classes as it crosses its limit, and a gap that vanishes when text turns red is the same
defect wearing the error's class.

| context | before | after |
|---|---|---|
| diagnostics intro, three hints in `.stack--tight` | **0** | 8 |
| language card, four notes in `.settings-notes.stack--tight` | **0** | 8 |
| markdown editor, hint→hint and hint→**error** | **0** | 8 |
| preservation package, two hints in a `<td>` | **0** | 8 |
| signing OTP, two hints direct in `.form` | **0** | 8 |
| a card, a `.stack.stack--tight`, a citizen-card cell | **0** | 8 |

Unchanged, each one deliberately and each one measured: the preservation row's Toggle→hint (0px)
and its hint→button (20px, `ff0a5f6c`'s patch, which is a third relationship again and is kept);
`.field`'s control→hint and control→error (5.59px); `.settings-rows`' hint run (14.39px) and its
Toggle→hint caption (4.8px); `.signing-evidence .field__hint` (11.19px, a hint after a `<dl>`);
`.stack--tight`'s hint→banner (12px); `.stack`'s plain paragraphs (24px); a card's hint→actions row
(16px); every dialog (13.59px); the field table's control→hint (4.8px). **Nothing was retired.**
Every existing patch in this family is a different relationship from a hint run.

**Gap containers, a third time, and the walk found one nobody had.** On a `gap` container a margin
*adds* instead of competing, and `:where(.modal__body) > *` is (0,0,0) so it cannot outrank a
(0,1,0) rule: a dialog's hint run measured **13.59px → 21.59px**. The tree walk then turned up
**`.field`** — `ServerEnvSection` renders a value-context hint and an editing hint as adjacent
children of a `Field`, so every editable environment row would have gone **5.59px → 13.59px**. A
by-hand sweep would have missed it, which is the `.chronology-analytics` lesson repeating. One
neutraliser covers both, at `margin-top: 0` rather than Pass 4's `revert` — the subject here is
always a hint, whose own rule zeroes the UA's `margin-block: 1em` on purpose, so `revert` would
hand a `<p>` back 16px and make the double-gap worse.

**Placeholder contrast.** Nothing in this app declared a `::placeholder` colour, so every
placeholder was drawn by the user agent: `rgb(117, 117, 117)` in **both** themes, measured at
**4.16:1** on the light field fill and **3.53:1** on the dark one, against WCAG 1.4.3's 4.5:1 for
text. Identical on inputs and textareas, because it was never per-surface — swept from the tree,
**132 elements carry a `placeholder`, 129 through the shared `Input`/`TextArea` and 3 as
hand-written `<input class="control">`, and none outside**, so one rule beside the primitive is the
whole population.

```css
:root { --field-placeholder: var(--text-muted); }
.control::placeholder { color: var(--field-placeholder); opacity: 1; }
```

**The value is not a new colour.** It is `--text-muted`, the app's existing secondary-text
decision, already the ink of `.field__label` and `.field__hint` — the register a placeholder speaks
in. That is also why the token needs no per-theme copy and deliberately has none: `--text-muted` is
redefined by the dark media query *and* by both `[data-theme]` blocks, and `var()` resolves on the
element, so one declaration covers all four paths. All four were measured.

| | light | dark |
|---|---|---|
| placeholder, before | **4.16:1** | **3.53:1** |
| placeholder, after | **6.83:1** | **7.86:1** |
| entered text (unchanged) | 14.7:1 | 14.7:1 |
| placeholder vs entered text | 2.15:1 | 1.87:1 |

The last row is the other half of the job. A placeholder darkened until it reads as a filled value
trades an accessibility defect for a usability one, so the guard asserts both ends: at least 4.5:1
against the field, and a floor on how far the two inks are from *each other*. `opacity: 1` is
load-bearing rather than tidying — a measured ratio is only the ratio that renders if nothing below
the author layer mutes it, and this app ships to Gecko and WebKit through Tauri as well as to the
Chromium it was measured in.

## Options considered for the remaining defect

**A — keep patching per surface.** What the codebase has done four times. Each patch buys exactly
one screen, and a scoped patch outranks the eventual global rule, so it also makes the real fix
partially inert wherever it exists. This is the status quo and it is what produced three complaints
in one session.

**B — give `.panel__body`/`.card` a real child rhythm at `:where()` zero specificity, then retire
the per-surface patches.** One owned rule replaces N patches. Callers keep the ability to override
with any plain class selector. This is the fix that ends the class of complaint.

**C — introduce a full spacing-token scale and migrate everything to it.** Rejected, and the
rejection is deliberate: it is a far larger refactor than the complaints justify, and Option B
delivers the visible symptom without it. If a scale is ever wanted it should be its own decision,
not smuggled in as a bundled extra.

**Recommended: B.** The cost is that it moves spacing on ~156 cards at once — the largest visual
change available in this area — on a product being actively demonstrated. That cost is the entire
reason it is a product decision rather than an engineering one.

## What measurement changed that reading the CSS did not

Three conclusions in earlier drafts of this document were wrong, and each was caught the same way:
by rendering the real stylesheet in Chromium and reading the computed box, rather than by reasoning
about specificity. Recorded because the method is the transferable part.

**1. `.data-status-section > * + *` (0.8rem) must be KEPT.** This document previously listed it for
retirement in Pass 2. That is wrong. `.data-status-section` is a `<section>` inside a `.data-status`
flex column inside the card body, so its children are **grandchildren** of `.panel__body` — the
shared rule cannot reach them, and 0.8rem is a deliberately tighter nested band. Retiring it would
collapse those sections to zero. Likewise `ff0a5f6c`'s
`.book-export-table .stack--tight > * + .btn` is scoped inside a `.stack--tight` in a table cell,
not to a container's children, and is also not superseded. **Neither is a surface patch shadowing
the shared rule**, so keeping them does not make the global fix inert anywhere.

**2. Two comments in this repo assert something `.field__hint` does not do.** The note at
`.settings-notes` (t100) says *"`.stack--tight` on the same element spaces the notes from each
other"*, and `ff0a5f6c`'s says the hint sits tight under its control *by design*. Measured:
`.field__hint { margin: 0 }` and `.stack--tight > * + *` are **both (0,1,0)**, and `.field__hint` is
declared later in the sheet, so it wins — hints inside a `.stack--tight` render **0px apart**. The
diagnostics intro's three sentences and the language card's four notes are crammed together today.
See Pass 3.

**3. The banner primitive's margin reaches into gap containers.**
`:where(.inline-warning) { margin-top: 1rem }` is invisible in a card (a plain margin among
margins) but **adds** to a flex `gap`, which is how a dialog's banner sat 29.59px from its
neighbour. Zero specificity does not mean zero effect. **Pass 4 closed this** beyond dialogs: five
more gap containers were measured double-spacing the same way (49 / 47.5 / 43.39 / 30.39 /
21.59px) and now neutralise the primitive's own margin as well as its successor's.

## Pass 3 — the remaining work, in priority order

1. ~~**`.field__hint` in a rhythm owner.**~~ **Closed by Pass 6.** The named conflict turned out to
   be a false choice: pinning the zero to `:where()` was never the only fix, and it was the trade
   that made this a decision rather than a patch. A hint following another hint and a hint
   following the control it describes are **two different relationships**, and a rule whose
   predecessor sits in `:where()` and whose subject does not addresses the first without touching
   the second. `.signing-evidence .field__hint` and `ff0a5f6c`'s row are both kept, unchanged and
   measured. See "Consecutive hints, and placeholder contrast (Pass 6)" above.
2. **The bespoke `> * + *` re-inventions**, swept onto the shared rhythm.
3. **A spacing-token scale**, only if it is ever wanted on its own merits — see Option C.

Items 2 and 3 are restated as decisions in
[What is decided](#what-is-decided-and-what-is-still-open); that list is the canonical one.

## The guards

Six structural test files, all AST/source-level:

- `apps/web/src/ui/bannerMarginGuards.test.ts` — fails on **any** margin rule that reaches
  `.inline-warning*` through a page or surface class, including inside a media query. Zero-specificity
  `:where()` rules and the primitive's own single-class rules stay legal.
- `apps/web/src/ui/menuItemGuards.test.ts` — fails when an element with an ARIA menu role lacks the
  shared `menu-item` class, when any menu restates its own entry padding, or when `.menu-item` stops
  agreeing with `.control`.
- `apps/web/src/ui/containerRhythmGuards.test.ts` — requires the shared container rhythm to exist
  on both containers at `:where()` zero specificity at its frozen step; freezes the surface-patch
  inventory **at empty**; freezes the set of distinct rhythm values; and covers the `.modal__body`
  family, where the invariant is the opposite one — *no* child may bring a block margin, because on
  a gap container a margin adds rather than competes. The modal predicates work from the AST, since
  the offending rules (`.modal__foot { margin-top }`) never mention `.modal__body` at all. Verified
  non-vacuous against the pre-fix commit: it reports `.modal__foot` there and nothing now.
  **Pass 4 added the boxed-primitive family** to the same file: that both primitives own an outer
  rhythm at `:where()` at the frozen step; that **neither declares a block-END margin**, the one
  invariant here that cannot be expressed as specificity; that the gap containers holding a
  primitive are exactly the frozen six and each is neutralised on **both** edges; the source
  ordering against the modal reset; and the inventory of classes passed to `<Table>` that carry a
  margin, frozen at `.data-status-table`. The population is walked from the component tree rather
  than grepped for class names — which is how `.chronology-analytics` was found — behind a
  non-vacuity bound of 200 primitives and 30 host classes.
  **Pass 5 added the wide-pane measure family** to the same file: the three shared caps exist at
  `:where()` and stay anchored to the `--app-measure` expression (a re-typed literal fails, because
  it stops tracking); the per-pane width-override inventory is frozen **at empty**; and no rule
  caps a `.table-wrap` inside a wide pane. Two things it had to learn by going red first: the
  patch predicate must be **scoped to wide panes**, or it reports ~20 filter toolbars legitimately
  sizing their own inputs and demands a regression to satisfy itself; and the grid predicate must
  strip `:not(…)`/`:has(…)` before reading the selector's subject, or it reports the one rule whose
  entire purpose is to avoid the regression. The sweep reads **every** stylesheet through
  `node:fs`, not `import.meta.glob(…, '?raw')` — measured, that returns the paths but empty strings
  for CSS, so the inventory would have frozen something the walk could not see.
  **Pass 6 hardened its two source-ORDER assertions**: they `indexOf` a rule's literal selector,
  and this sheet documents its rules by quoting their selectors in prose, so against the raw text
  they could find a *comment* and compare the wrong two positions. A note added above the modal
  reset turned both red without a declaration changing. They now read a comment-stripped copy.
- `apps/web/src/ui/hintRhythmGuards.test.ts` — the hint run (Pass 6). That the rule exists at the
  frozen 0.5rem step; that its **predecessor is `:where()` and its subject is not**, which is what
  holds it at (0,1,0); that the predecessor list is exactly the hint family, so it can never widen
  into the `:where()` pin this was deferred for; **both source orderings**, since at (0,1,0) they
  are the entire cascade argument — below `.field__hint`'s zero, above `.settings-rows > * + *`;
  the gap-container neutraliser, its `0`-not-`revert` value and its position; and the inventory of
  rules that give a hint a block margin, frozen at the four that are different relationships. The
  population is walked from the component tree behind a bound of 13 runs and 6 holder classes —
  which is how `.field` was found. Two things it had to learn by going red: a selector that heads
  a **list** is followed by `,` and never by ` {`, so an `indexOf` on ` {` silently returns -1 and
  compares against a rule it could not find; and the hint run's own selector is a literal
  substring of the neutraliser's, so the search must be anchored to the start of a line or it
  reports the wrong rule's position.
- `apps/web/src/ui/placeholderContrastGuards.test.ts` — placeholder contrast (Pass 6). That
  `--field-placeholder` is declared **once** and stays anchored to `--text-muted` (a re-typed
  literal fails, because it computes identically in light today and stops tracking dark tomorrow);
  that `.control::placeholder` consumes it and pins `opacity: 1`; that the inventory of other
  placeholder colour rules across **every** stylesheet is frozen at empty; that every
  placeholder-bearing element in the tree is a `.control`, behind a bound of 100; and **the ratio
  itself**, computed from the sheet's own token values in both themes — ≥ 4.5:1 against the field
  fill, *and* a floor on the distance from the entered-text ink, so "just darken it" fails too.
  The user agent's own `rgb(117, 117, 117)` is run back through the same arithmetic as the
  red-proof.
- `apps/web/src/ui/textareaControlGuards.test.ts` — the multi-line control: that `TextArea` merges
  a caller's `className` rather than replacing it, its `rows` default and caller override, the
  height floor's exact form and its zero specificity, the padding token and its consumers, the mono
  rule, and that `field-sizing` stays out.

**Why not a rendered assertion.** jsdom does not apply stylesheet declarations to
`getComputedStyle`, so a test that mounts a component and reads its margin passes whether or not the
rule exists. Both files instead read the two sources that actually determine the outcome — the
stylesheet, and the component tree — and each proves it goes red by re-running its own predicates
against copies of the real sources with the fix removed.

### The most transferable thing in this lane

`menuItemGuards.test.ts`'s first draft recognised only `menuitem` and `option`. The session picker's
rows are **`menuitemradio`**, so that menu did not fail the guard — it **silently dropped out of the
population**. A recogniser used as a filter cannot see what it fails to recognise.

What caught it was the **non-vacuity bound** (`expect(entries).toBeGreaterThanOrEqual(4)`), which
failed with `expected 3 to be >= 4`. Both the widened role set and the bound are kept, and the
reason is recorded in the file. **Any guard that sweeps a population needs a bound asserting the
sweep found one**, or it will pass while covering less than it claims.

### A coverage gap worth knowing about

A reverted presentational `className` is nearly invisible here: it compiles, typechecks, renders, and
keeps every role, label and handler. Measured at `7e09cf83` — **0** tests reference `TopbarMenu`,
and there are **0** snapshot files in the entire web app. Class-attribute regressions are caught only
where some test happens to assert that specific class by name. This is not an argument for snapshot
tests (they would go stale faster than they would catch anything); it is an argument for structural
guards over presentational families, and it is why the Pass 2 guard is worth keeping **even if
Pass 2 itself is declined**.

## Counting: why the numbers here are AST-derived

`f4e1c8c0`'s commit message states this component has "461 call sites". The real figure is **238**.
The 461 came from a regex that counted opening and closing tags separately. Several other counts in
the same effort were wrong the same way.

Every figure in this document was produced by walking the TypeScript AST for components and a
brace-depth CSS tokeniser for rules — including `@media` nesting, which a flat regex silently
mis-parses. If you revise these numbers, do it the same way, and state which commit you measured at.

## What is decided, and what is still open

**Decided and landed:**

- Banner body spacing is owned by the primitive at zero specificity, not by any page (`2a538e87`).
- All four hand-built menus take one row metric from `.menu-item`, anchored to `.control`'s padding
  rather than a copied constant (`7bb5dcd8`).
- Menu entry populations are enumerated by **ARIA role**, never by class name — using the class under
  test to find the population makes the guard tautological.
- `.leg-corpus__index-item` is out of scope; it is not a menu.
- Native `<select>` options are the reference, not a problem to solve. No conversions.
- Menu `line-height` and inter-row gaps are intentional differences and stay.
- A full spacing-token scale is **declined** as part of this work.

- **Option B landed (Pass 2).** `:where(.panel__body, .card) > *` zeroes child margins and
  `> * + *` sets a 1rem rhythm — the value all three retired patches already used, and `.form`'s
  own band, so a card of loose children now reads like one whose children sit in a form. The
  guard flipped from asserting the rhythm's *absence* to asserting the invariant, with
  `KNOWN_SURFACE_PATCHES` frozen at empty so a fifth surface patch fails at test time.
- **`.modal__body` is a separate mechanism and Pass 2 does not reach it.** It owns its child
  spacing through `gap`, so a child's margin *adds* rather than competing in the cascade. Swept
  across all eight dialogs it produced **six** different gaps (13.6 / 19.98 / 25.6 / 29.59 / 34.38
  / 37.6px); the full table and causes are in the "Modal bodies" section above. A heading anchor is
  deliberately not linked there: its em dash slugifies differently under mkdocs and GitHub, and
  `mkdocs build --strict` fails on the mismatch. Child margins are now neutralised at `:where()`,
  `.modal__foot`'s `margin-top` is gone, and the two dialogs that stacked a `.stack`/`.stack--tight`
  on the body itself dropped it. All eight now render at one 13.6px baseline in both themes.

- **Pass 4 landed — the boxed primitives own their outer edge.** `.table-wrap` gets a
  `:where()` `margin-top` with a `:first-child` collapse, and both it and `.inline-warning` get
  their bottom edge as `:where(.inline-warning, .table-wrap) + * { margin-top: 1rem }`. It is the
  next sibling's margin and **not** a `margin-bottom` because adjacent margins collapse to the max
  and collapsing never consults specificity — a `margin-bottom` would silently raise every band
  tighter than 1rem, `.stack--tight`'s 0.75rem included. Six gap containers neutralise it with
  `margin-top: revert`, on both edges. Nothing was superseded; `.data-status-table`'s 0.1rem is
  kept as a deliberate tightening and registered by name.
- **The banner's standalone margin no longer doubles in a gap container.** The measured
  consequence of the above, on five surfaces, each exactly −16px — see the Pass 4 table. This was
  a pre-existing defect that correction 3 below predicted; Pass 4 is where it was actually fixed,
  and it is the one part of Pass 4 that changes screens nobody complained about.

- **Pass 5 landed — a wide pane no longer means 128ch prose.** Three `:where()` caps beside
  `.app:has(.wide-page)` hold prose, the label/control grid and the control to
  `calc(var(--app-measure) - 2 * var(--app-gutter))` — the measure `.page-header` already uses —
  while `.table-wrap` keeps the full wide measure. All five `WIDE_SUBSECTIONS` panes were
  measured; all five were affected, though only two were reported. **`WIDE_SUBSECTIONS` itself is
  unchanged**: removing an entry would restore the sideways-scrolling grid it exists to prevent.
- **`signing:tsl` and `signing:tsa` keep a 128ch control ROW, on purpose.** Their table is a
  `grid-column: 1 / -1` child of the same `.settings-rows` grid as their fields, and a subgrid
  item cannot be capped per-item. Their prose and controls are fixed; the row box is not. Closing
  it means moving the table out of that grid in `SettingsPage.tsx` — a decision, not a patch.

**Corrections to this document, found by measuring rather than reading specificity:**

- **`.data-status-section > * + *` must NOT be retired.** This document previously listed it as
  superseded. It is not: its children are *grandchildren* of `.panel__body`, so the shared rule
  cannot reach them, and its 0.8rem is a deliberately tighter nested band. Retiring it collapses
  those sections to zero.
- **`.diagnostics-card { margin: 0 }` had the same shape** and was measured at zero gap with
  borders touching. Its children are likewise grandchildren; the container now uses `stack` and
  the blocking rule is gone.
- Two in-repo comments (t100's and ff0a5f6c's) asserted that `.field__hint` carries spacing
  between siblings. It did not — `.field__hint { margin: 0 }` ties `.stack--tight > * + *` at
  (0,1,0) and wins on source order, so consecutive hints rendered at 0px. **Both are now
  corrected in place** (Pass 6): t100's, in `LanguagePreferenceSection.tsx`, records that
  `.stack--tight` never spaced the four notes from each other and names what does now;
  ff0a5f6c's, beside `.book-export-table .stack--tight > * + .btn` in `theme.css`, records that
  the tightness under a control was a specificity tie won on source order rather than an
  expressed intent, and drops its cross-reference to a `.settings-notes` rule Pass 2 retired.

- **Pass 6 landed — consecutive hints are spaced, and the caption case was not traded for it.**
  `:where(.field__hint, .field__error) + .field__hint` at (0,1,0), directly beneath the zero it
  overrides. The named conflict was resolved by **distinguishing the two relationships**, not by
  arbitrating between them: the rule matches nothing that follows a control, so `ff0a5f6c`'s
  preservation-package row measures 0px before and after and **nothing was retired**. Nine
  measured surfaces go 0px → 8px; `.settings-rows` keeps its 0.9rem band because the rule sits
  *above* it in the sheet, and both orderings are pinned by a test.
- **`.field` was found by the walk, not by hand.** `ServerEnvSection` puts a hint run inside a
  `Field`, a 0.35rem `gap` container where a margin adds — 5.59px → 13.59px without the
  neutraliser. `.modal__body` is the other one (13.59px → 21.59px). The neutraliser says `0`, not
  Pass 4's `revert`, because its subject is always a hint whose UA margin is zeroed on purpose.
- **Pass 6 landed — placeholders clear WCAG AA in both themes.** Left to the user agent they were
  `rgb(117, 117, 117)` in both, measured **4.16:1 light / 3.53:1 dark**. One token
  (`--field-placeholder: var(--text-muted)`, declared once and resolving per theme) and one rule
  beside `.control` take them to **6.83:1 / 7.86:1**, against 14.7:1 for entered text — and the
  guard asserts the *distance* between the two inks as well as the floor, because a placeholder
  darkened until it reads as a filled value is a usability defect bought with an accessibility fix.
  All 132 placeholder-bearing elements in the tree are `.control`s, so one rule is the population.

**Awaiting the product owner:**

- Nothing. Pass 3's remaining items are engineering decisions rather than product ones: the
  bespoke `> * + *` re-inventions (item 2), and the spacing-token scale (item 3, already declined).
