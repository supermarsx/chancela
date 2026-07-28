# UI vertical spacing (design decision)

> **Status.** Two of the three reported defects are **fixed and guarded** (`2a538e87`, `7bb5dcd8`).
> The third is **not fixed**: it needs a container-rhythm rule whose blast radius is ~156 cards, and
> that is [AWAITING DECISION](#what-is-decided-and-what-is-still-open) with the product owner. This
> document is written so that decision can be taken, and Pass 2 resumed, by someone who was not
> present. Every number below was measured against the tree at **`7e09cf83`** by parsing the
> TypeScript and CSS ASTs, not by grepping — the method matters, because a regex count of this same
> component family was wrong by a factor of two (see [Counting](#counting-why-the-numbers-here-are-ast-derived)).

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

## Pass 2, if it is approved

1. Add the container rhythm next to `.panel__body`, at `:where()` zero specificity, in the same
   shape as the banner fix.
2. **Then** retire the per-surface patches it supersedes — `.settings-notes`,
   `.email-card .panel__body > * + *`, `.data-status-section > * + *`, and the scoped overrides
   added by `ff0a5f6c` — because while they exist they shadow the shared rule at higher specificity.
   Leaving them is how a global fix ends up applying everywhere except the screens people already
   complained about.
3. Extend the structural guard (below) to the container-rhythm family, so a fifth surface-scoped
   patch fails at test time.

**Pass 3** — a broader sweep of the bespoke `> * + *` re-inventions onto the shared rhythm — is
contingent on Pass 2 landing and should not be started before it.

## The guards

Two structural test files, both AST/source-level:

- `apps/web/src/ui/bannerMarginGuards.test.ts` — fails on **any** margin rule that reaches
  `.inline-warning*` through a page or surface class, including inside a media query. Zero-specificity
  `:where()` rules and the primitive's own single-class rules stay legal.
- `apps/web/src/ui/menuItemGuards.test.ts` — fails when an element with an ARIA menu role lacks the
  shared `menu-item` class, when any menu restates its own entry padding, or when `.menu-item` stops
  agreeing with `.control`.

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

**Awaiting the product owner:**

- **Does `.panel__body`/`.card` get a real child rhythm (Option B)?** This is the fix for the
  paragraph-to-actions complaint and for the 68 visibly-affected cards. It moves spacing on ~156
  cards in one change. The alternative is a fourth report of the same class of defect, since each
  per-surface patch has so far bought exactly one surface.
