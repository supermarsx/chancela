# Signing and trust — behavioural claims register

**Companion to `scripts/check-docs-claims.mjs`. Last reviewed: 2026-07-28.**

The docs-claims gate mechanises two questions: *does this identifier exist?* and *can the system
actually emit this literal?* It cannot mechanise the third, which is the one that matters most
here — **does the documented effect actually happen at runtime?**

No parser distinguishes *"unioned with the environment anchors at runtime"* (a claim that was
**false** for the signing path until t61-e1 bridged it) from *"defaults to `false`"* (true, and
asserted by a test). Both are ordinary English sentences about behaviour. Building a matcher that
pretended to check them would produce a gate that is green because it understands nothing — the
exact failure this lane exists to eliminate.

So this half is a **curated register, maintained by hand**. Every entry is in one of three states,
and there is no fourth:

| state | meaning |
|---|---|
| **PROVEN** | A named test fails if the claim stops being true. The test path and name are given. |
| **REVIEWED** | No test proves it. A human read the code against the prose on the date shown. This is a weaker guarantee and is labelled as one. |
| **FALSE** | The doc claims something the code does not do. Tracked, owned, and dated — never quietly left in place. |

## Scope — and what this register deliberately does not cover

**In scope:** runtime-behaviour claims in the signing and trust surfaces — `docs/configuration.md`
(Trusted List anchors), `docs/ARCHITECTURE.md` (signing/enforcement sections), and
`docs/capabilities.md` (signing capability). These are the evidentiary surfaces, where a claim that
is quietly false costs something real.

**Explicitly out of scope. These are not oversights; extending to them is a larger commitment than
this register can honestly carry, and claiming coverage would be the phantom-control defect in a
new substrate:**

- **Every other documentation area** — books, actas, templates, archive, HA, deployment, i18n. A
  false behavioural claim there is equally possible and is **not** tracked here.
- **Rust doc comments.** The gate reads `docs/` and root `*.md` only. A `///` comment asserting
  behaviour the code does not have is invisible to both halves of this lane.
- **Claims about absence** (*"never persisted"*, *"no endpoint sets it directly"*). A test can show
  a path does not do something; it cannot show no path does. Entries of this shape are REVIEWED at
  best, and the label is doing real work.
- **Whether a proving test is any good.** This register asserts a test exists and is coupled to the
  claim. It does not assert the test is thorough.
- **Prose without backticks**, which the mechanised halves also miss.

## Maintenance rule

Changing signing or trust behaviour means updating this file in the same change. A claim that moves
from PROVEN to FALSE without its entry moving is precisely the decay this register exists to make
visible. **A REVIEWED entry older than the behaviour it describes is stale by definition** — the
date is not decoration.

---

## Trusted List anchors — `docs/configuration.md`

### ST-1 · Settings and environment anchors are a union · **PROVEN**

> "the two sources are a **union** (a signer matching **any** configured certificate or fingerprint
> is anchored)"

`crates/chancela-api/src/trust.rs` · `resolve_lotl_trust_anchors_unions_settings_with_env`

### ST-2 · Settings anchors reach the signing-time policy, not only the LOTL bootstrap · **PROVEN**

> "on **both** trust paths: the operator-triggered LOTL bootstrap (`POST /v1/trust/refresh`) and the
> trusted-list policy consulted at **signing time**"

- `crates/chancela-api/src/signature.rs` ·
  `settings_provisioned_anchor_authenticates_trusted_list_at_signing_time` — **the citation that
  proves the claim as worded.** It signs a real Trusted List with an ephemeral XML-DSig signer and
  drives `build_trust_policy` → `issuer_status` end to end: a settings-only certificate anchor and a
  settings-only SHA-256 anchor each reach `Granted`.
- `crates/chancela-tsl/tests/tsl_fixture.rs` ·
  `client_with_explicit_anchors_authenticates_a_list_the_env_path_would_reject` — the seam beneath
  it: `TslClient` honours explicitly-supplied anchors.

The second citation alone would **not** discharge this claim, and the distinction is this entry's
whole point. `validate_tsl_signature_with_anchors` and `TslTrustPolicy::from_client` both existed
before t61-e1 — the seam was never missing, it was never *walked*. A test that exercises the seam
directly would have passed for as long as the bug existed. Only a test entering through
`build_trust_policy`, the function the signing path actually calls, can tell the two apart.

**This entry is the reason the register exists.** The claim was **false** until t61-e1: the
signing-time chain resolved anchors via `TslTrustAnchors::from_env()` inline, so no settings anchor
could enter it, and the operator saw an error naming the *signer's* trust service when the actual
fault was their own missing anchor. Three separate structural sweeps reported green over it. Only
reading the prose against the code found it.

### ST-3 · Fail-closed: an install with no anchors trusts no list · **PROVEN**

> "the union can only ever *add* anchors, and an install that provisions none in settings **or**
> environment trusts no list at all"

Five independent tests, because this is the property that must not regress — and because t61-e1
expanded the trust surface, so fail-closed is what bounds it:

- `crates/chancela-api/src/signature.rs` ·
  `settings_provisioned_anchor_authenticates_trusted_list_at_signing_time` — its third case is the
  signing-time half: the *identical* list that two settings anchors authenticate stays `Unknown`
  when none is provisioned. The other four prove fail-closed below the policy; only this one proves
  it at the surface t61-e1 opened.
- `crates/chancela-tsl/tests/tsl_fixture.rs` · `tsl_signature_validation_fails_closed_with_empty_anchor_set`
- `crates/chancela-tsl/tests/tsl_fixture.rs` · `tsl_signature_env_entry_point_fails_closed_without_configured_anchor`
- `crates/chancela-api/src/trust.rs` · `resolve_lotl_trust_anchors_empty_is_fail_closed`
- `crates/chancela-api/src/settings.rs` · `tsl_trust_anchors_default_is_empty_and_fail_closed`

A malformed settings anchor is also fail-closed, one step earlier — `build_trust_policy` refuses to
build rather than degrading to "unanchored"
(`crates/chancela-api/src/signature.rs` · `malformed_settings_anchor_fails_the_trust_policy_closed`).

### ST-4 · A set-but-unparseable environment anchor is a hard error · **REVIEWED 2026-07-28**

> "A variable that is *set but unparseable* is a hard error — a misconfigured anchor trusts nothing
> rather than silently degrading."

`TslTrustAnchors::from_env` returns `Result`, and fingerprint parsing rejects invalid hex
(`crates/chancela-tsl/src/source.rs`). **Gap, stated plainly:** the existing fail-closed tests cover
the anchor being *unset*. No test sets the variable to an unparseable value and asserts the error.
The distinction matters — "unset trusts nothing" and "malformed trusts nothing" are different code
paths, and only the first is proven. A test would move this to PROVEN.

### ST-5 · Invalid PEM or fingerprint is rejected on save with 422 · **PROVEN**

> "Invalid PEM or a malformed fingerprint is rejected on save with `422`."

`crates/chancela-api/src/settings.rs` · `tsl_trust_anchor_invalid_pem_is_rejected`,
`tsl_trust_anchor_invalid_sha256_is_rejected`, `tsl_trust_anchor_blank_entries_are_rejected`

### ST-6 · Anchor writes are gated on `signing.configure`, not plain `settings.manage` · **PROVEN**

> "That write is gated on the narrow `signing.configure` permission (not plain `settings.manage`)"

`crates/chancela-api/tests/signing_configure_gate.rs` ·
`put_settings_gates_the_signing_slice_on_signing_configure`

A settings-provisioned anchor is a trust root, so this is the claim that bounds the trust surface
ST-2 opened. It is the one entry here where a silent regression would be a security regression.

### ST-7 · The grandfather caveat is real and stated · **PROVEN**

> "the migration that introduced `signing.configure` grants it to every existing `settings.manage`
> holder — so in an install predating custom roles the effective audience is unchanged"

`crates/chancela-authz/src/role.rs` ·
`t50_signing_configure_grandfather_grants_to_settings_manage_holders_and_nothing_else`

Registered because it is a claim about a *limitation*. Documented limitations rot the same way
documented features do, and are less likely to be noticed when they do.

### ST-8 · Multiple anchors span a key rollover · **REVIEWED 2026-07-28**

> "configure **multiple** anchors to span a key rollover"

Follows from union semantics (ST-1) plus per-anchor matching. No test performs a rollover
end-to-end — it is an operational procedure rather than a code path, and the underlying mechanism
is the one ST-1 proves.

---

## Finalization status — `docs/ARCHITECTURE.md`, `docs/capabilities.md`

### ST-9 · `require_qualified_for_seal` defaults to `false` · **PROVEN**

> "The setting `signing.require_qualified_for_seal` defaults to **`false`**"
> (and `docs/capabilities.md`: "default **off**")

`crates/chancela-api/src/lib.rs` · `settings_get_returns_defaults`

### ST-10 · Sealing always succeeds; the flag gates the status label, never the seal · **PROVEN**

> "**sealing always succeeds and always produces the unsigned PDF/A**, regardless of the flag …
> it never blocks the seal"

- `crates/chancela-api/tests/local_pkcs12_signing.rs` · `local_pkcs12_signs_as_advanced_technical_evidence_only`
- `crates/chancela-api/tests/official_signature_import.rs` · `official_import_stores_exact_signed_pdf_as_non_qualified_evidence`
- `crates/chancela-api/tests/cmd_signing.rs` · `finalization_is_reported_only_after_the_explicit_seal`

Both of the first two set the flag **on** and assert the seal still completes. This claim is true
today — and note it stays true under t61-e3, which changes only the derived label.

### ST-11 · The documented four-way status derivation · **FALSE** · owner **t61-e3** (code), **t61-e6** (prose)

> "a qualified signature ⇒ `finalizado_qualificado`; not sealed ⇒ `rascunho`; sealed with the flag
> **on** but no qualified sig ⇒ `aguarda_assinatura_qualificada`; sealed with the flag **off** ⇒
> `finalizado`"

`finalization_status` (`crates/chancela-api/src/signature.rs`) binds the flag as
`_require_qualified` and never references it. It emits exactly three labels:

| documented | actually emitted |
|---|---|
| not sealed ⇒ `rascunho` | `em_assinatura` — **wrong label, independent of the flag** |
| flag on, unsigned ⇒ `aguarda_assinatura_qualificada` | `finalizado` — **unreachable state** |
| signed ⇒ `finalizado_qualificado` | `finalizado_qualificado` ✓ |
| flag off, sealed ⇒ `finalizado` | `finalizado` ✓ |

`apps/web/src/api/types.ts` mirrors the documented five in `FINALIZATION_STATUSES`, so the phantom
reaches the wire contract as well.

**This one is mechanised.** Unusually for this register, all four occurrences are caught by
`check-docs-claims.mjs` as `knownDefects` entries. Because registry entries are *exercised*, fixing
the code without deleting the entry fails the check — the defect cannot become permanent, and the
fix cannot quietly lose its gate. **Delete the entries in the same change that fixes the code.**

### ST-12 · Qualified status is derived, never set directly · **REVIEWED 2026-07-28**

> "No endpoint sets the qualified status directly; it is *derived* from the presence of a validated
> `Qualified` signed variant, so it is unbypassable."

`finalization_status` takes only `sealed`/`signed`, and `signed` is computed from a validated
signed variant rather than accepted from a request.

**REVIEWED, not PROVEN, and the distinction is the point.** "No endpoint does X" is a claim about
absence over the whole API surface. A test can show the three known paths derive it correctly; it
cannot show a fourth path will not be added. The mechanical guard against that decay is
`finalization_status` remaining the single producer of the label — if a second producer ever
appears, this entry is void regardless of what any test says.

### ST-13 · No "valor probatório" claim is made · **REVIEWED 2026-07-28**

> "the code and docs make **no 'valor probatório' claim** … the vocabulary is evidentiary *level* +
> trusted-list *status*, not probative-value assertions"

A claim about what the product does **not** assert, so it is unprovable by construction — the same
shape as ST-12. Related guards exist in the copy layer, but they cover user-facing strings, not this
architectural statement.

---

## Review log

| date | reviewer | scope |
|---|---|---|
| 2026-07-28 | t61-e5 | Register created. 13 claims: 8 PROVEN, 4 REVIEWED, 1 FALSE (ST-11, tracked in `scripts/docs-claims-registry.json`). ST-2 recorded as PROVEN on the strength of t61-e1's bridge; it was FALSE before that change landed. |
