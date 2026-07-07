# 10 — UX, Design System, and Localization

Requirement prefix: `UX`

## 1. Visual direction

- **UX-01** Visual identity: **dark green + white, old-school editorial styling,
  NYT-inspired typography**, with robust light and dark themes.
- **UX-02** The identity MUST be expressed as a **theme package** layered on an
  accessibility-aware UI system — not a fragile CSS skin.
- **UX-03** Fonts: a locally bundled set of open-licensed Google Fonts across serif, sans,
  monospaced, and display families. No runtime font fetching (offline parity, privacy).
- **UX-04** The default typographic system for **formal documents** MUST remain
  conservative so archive, print, and PDF/A generation stay predictable regardless of the
  screen theme.

## 2. Accessibility

- **UX-10** The UI system MUST be accessibility-aware from the start (keyboard navigation,
  contrast targets, screen-reader semantics).
- **UX-11** Where accessible document delivery is required, output MUST follow the
  PDF/UA-aligned generation path (DOC-01).

## 3. Localization

- **UX-20** Default locale: **PT-PT** (with **EN-US** as the primary secondary). The UI
  chrome MUST be localizable across the following **14 BCP-47 locales** (language subtag
  lowercase, region subtag UPPERCASE), and the architecture MUST scale beyond them (AI-01
  multilingual drafting aligns with this):
  `pt-PT`, `pt-BR`, `da-DK`, `de-DE`, `fr-FR`, `fi-FI`, `sv-FI`, `it-IT`, `nl-NL`, `pl-PL`,
  `en-GB`, `en-US`, `sv-SE`, `es-ES`. Note the two easily-missed variants: `sv-FI`
  (Finland-Swedish, distinct from `sv-SE`) and `en-GB` (distinct from `en-US`).
- **UX-21** Legal terminology MUST NOT be machine-localized in legal outputs: templates and
  rule-pack messages are authored per locale, with PT-PT as the legally authoritative
  source for Portuguese-law content.

## 4. Mobile UX scope (v1)

- **UX-30** Mobile prioritizes: review, approval, signing, alert triage, and quick company
  lookup (SCP-21, SCP-D5).
- **UX-31** Mobile drafting is limited; archive administration is desktop/browser-only in
  v1.

## 5. Warnings and legal labeling

UI copy is part of the compliance surface:

- **UX-40** Signature-type labeling MUST follow SIG-02 (never present OTP consent as a
  qualified signature).
- **UX-41** Manual-signature flows MUST show the SIG-03 preservation warning.
- **UX-42** Working-copy exports MUST be labeled per DOC-02.
- **UX-43** Compliance findings MUST cite their legal basis (LEG-05) in plain language
  with a link to the law shelf entry (AI-22).
