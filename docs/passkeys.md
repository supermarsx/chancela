# Passkeys / WebAuthn (design ruling)

> **Status.** Nothing is implemented. `grep -rli "webauthn\|passkey\|fido"` over the tree at `b7f7a8c3`
> matches only `chancela-zk`, where WebAuthn PRF is named as a *client-side* key-wrapping scheme for
> zero-knowledge repositories — unrelated to sign-in and not reused here.
>
> This document is a **ruling**, not a plan of record for code that exists. It answers one question
> first (what unlocks the attestation key), then records four findings that will bite whoever builds
> it, then ranks the work. Every claim about this codebase was read out of the code and is cited by
> `file:symbol`; line numbers drift daily on this tree, so locate by symbol. Every claim about
> WebAuthn itself is cited to a dated external source at the end — this area moved twice in the last
> six months and a stale claim here would be expensive.

## The load-bearing question

Chancela's signed acts are attributable to a **person**, not a session, because each user holds a
P-256 attestation key whose secret scalar is **wrapped under their password** and unwrapped in memory
at sign-in. A WebAuthn assertion yields a *signature over a challenge*, not key material. So
"add passkeys" is not one feature — it is a choice about what unwraps that key, and the three
available answers differ in what a user who signs an act actually gets.

### The mechanism as it stands

Read these five before proposing anything:

| Step | Where | What happens |
|---|---|---|
| Wrap | `crates/chancela-api/src/attestation.rs` — `AttestationKeyBlob::generate` / `::wrap` | Fresh P-256 key; the 32-byte scalar is sealed with XChaCha20-Poly1305 under a KEK = `argon2id(secret, kdf_salt)` (`derive_kek`). The blob stores `public_key_sec1`, `fingerprint`, `kdf_salt`, `nonce`, `ciphertext`. The public half is in the clear; without the secret the scalar is unrecoverable. |
| Unlock | `crates/chancela-api/src/session.rs` — `create_session` | After the password verifies, `blob.unlock(&req.password)` reconstructs the `SigningKey`. It is held **in memory on the session** (`Session::unlocked_key`) and never persisted. |
| Carry | `crates/chancela-api/src/session.rs` — `PendingTwoFactor` | On a 2FA account the password step does not mint a session; the unlocked scalar is parked in a process-local pending record and handed to `mint_session` when the second factor lands. |
| Re-wrap | `crates/chancela-api/src/users.rs` — `set_secret` | A password change with the old password in hand calls `AttestationKeyBlob::rewrap(old, new)`. **The public key and fingerprint are preserved**, so every attestation the key already signed keeps verifying. |
| Recovery reset | same function, `SecretAuthz::CrossUser(ProofKind::Recovery)` arm | A recovery-phrase reset has no old password, so the key **cannot** be re-wrapped. It is dropped — `User::retire_attestation_key` moves the public half to `retired_attestation_keys` (`RetiredAttestationKey`) so the past stays verifiable and the key can never sign again. The user gets a new key only by generating one *with* the new password. |

Two consequences follow directly and constrain everything below:

1. **The wrapping secret is a `&str` and the wrap function is generic over it.** `AttestationKeyBlob::wrap(secret, sec1, fingerprint, scalar)` does not care where `secret` came from. A second wrap of the *same scalar* under a *different* secret is a small, self-contained change — not a redesign.
2. **Unwrapping happens on the server, from a secret the client transmitted.** `create_session` receives `req.password` in the request body. Any passkey-derived unwrap secret would travel the same path. This is architecturally symmetric with what already happens, but it is *not* the end-to-end model PRF was designed for, and the document must not imply otherwise.

### The three shapes

#### A — PRF-derived unwrap (true passwordless)

Use the WebAuthn PRF extension (CTAP2 `hmac-secret`) to derive a stable 32-byte secret per credential,
and keep a second wrap of the attestation scalar under it. Sign-in is a WebAuthn assertion plus the
PRF output; no password is typed, and the signed act is still attributable to the person.

- **What the signer gets:** a genuine ceremony. Touch the authenticator, the key unwraps, the act is signed under their fingerprint.
- **Cost 1 — support is real but not universal, and it is six months old on Windows.** See the matrix below.
- **Cost 2 — a lost passkey loses that wrap.** PRF output is a function of the credential; re-creating the credential (even for the same account, same authenticator) yields a different secret. There is no "restore my PRF".
- **Cost 3 — the crate does not do it.** `webauthn-rs` 0.5.5 documents no PRF/`hmac-secret` support. PRF is a *client-side* extension anyway — the browser returns the derived bytes to JS — so the server never needs to parse it; but that means the client must POST the derived secret, and we own that decision explicitly rather than inheriting it from a library.
- **Cost 4 — PRF at `create()` is not guaranteed.** The Yubico developer guide states derivation happens at `get()`; Chrome/Edge 147 added surfacing PRF results on creation (146 did not). Enrolment must therefore be prepared to do `create()` then an immediate `get()` to obtain the wrapping secret.

#### B — Passkey authenticates, password still unwraps

The passkey replaces the *password check* at sign-in but not the *unwrap*. The user still types their
password to unlock their key before they can sign.

- **What the signer gets:** phishing resistance for the login. **Nothing for the ceremony.** They type a password anyway, so the honest description is "a second way to log in", not "passwordless".
- **Cost:** it is worse than it sounds. A user who has a passkey *and* still types a password on the same screen has gained one credential and dropped none, and will reasonably ask what it bought. Shipping B alone and calling it passkey support would be the kind of overclaim this product's copy rules exist to prevent.
- **Benefit:** no PRF dependency, works on every platform in the matrix, and it is the only shape that works at all where PRF is absent.

#### C — Hybrid: PRF when available, B as fallback

Attempt PRF at enrolment. If the authenticator returns PRF output, store the PRF wrap and mark that
credential `passwordless`. If it does not, store the credential as authentication-only and tell the
user, at enrolment, in one sentence, that this authenticator will still ask for their password when
they sign.

### The evidence

PRF support as of mid-2026 (sources dated at the end; the Corbado matrix was last modified
**2026-05-19**):

| Platform | PRF status |
|---|---|
| **Windows 11 / Windows Hello** | Available only since the **February 2026** cumulative update KB5077181 (build 26200.7840+). Chrome/Edge 147+ and Firefox 148+ full support; Chrome/Edge 146 do not surface it on creation. An unpatched Windows 11 has **no** Windows Hello PRF. |
| **macOS 15+ / iCloud Keychain** | Safari 18+, Chrome 132+, Firefox 139+ — supported for the *platform* authenticator. |
| **iOS/iPadOS 18+ / iCloud Keychain** | Supported (18.0–18.3 had data-loss bugs; fixed in 18.4+). |
| **Android / Google Password Manager** | Supported by default in Chrome, Edge, Samsung Internet. **Firefox on Android: no.** |
| **Security keys (YubiKey etc.)** | Windows 11 (Feb 2026+): Chrome/Edge/Firefox yes. macOS: Chrome only — WebKit bugs 311099/314934 break CTAP2 keys in Safari. **iOS/iPadOS: no** — the platform does not pass extension data to or from external authenticators at all, so a PRF-capable YubiKey is unusable there. |
| **Chrome profile as authenticator** | No PRF. |

Read plainly: PRF is dependable on **current, patched** Windows/macOS/iOS/Android platform
authenticators in Chromium and Firefox. It is *not* dependable on an unpatched Windows 11, on any
iOS security key, on Firefox for Android, or on Safari with a security key. That is a large enough
tail that a self-hosted product cannot make PRF a precondition of signing in.

### Recommendation: **C**, built PRF-first

Build the PRF path as the primary and only *designed* experience, and let a non-PRF authenticator
degrade to B **with the degradation stated at enrolment, not discovered at sign-in**. Concretely:

- Enrol always attempts PRF. The enrolment result is recorded per credential, not per user.
- A credential with a PRF wrap signs in fully passwordless.
- A credential without one authenticates the session but leaves `Session::unlocked_key` as `None` — which is *already a supported state* (`mint_session` takes `Option<SigningKey>`; companion/pairing sessions are minted this way today). Such a session can read, and is prompted for the password at the moment it first needs to attest.

That last point is the reason C is cheap rather than expensive: **the codebase already has a
first-class "authenticated but cannot attest" session**, so B-mode is not a new concept, it is an
existing one reached by a new door.

**Do not ship B alone and call it passkeys.** If only B is funded, the honest user-facing framing is
"iniciar sessão com chave de acesso" — sign in with a passkey — and the security screen must say the
password is still required to sign. Never "sem palavra-passe".

## Finding 1 — RP ID is deployment-specific, and a domain change is unrecoverable

**The rule.** `rp.id` must be the origin's effective domain or a registrable suffix of it. For
`https://livros.example.pt`, valid values are `livros.example.pt` and `example.pt`; `com`, a
sub-subdomain, and anything carrying a scheme or port are invalid. **A credential is strictly scoped
to the RP ID it was created under and cannot be used with any other.**

**Where it must come from.** `PlatformSettings::public_base_url` in `crates/chancela-api/src/settings.rs`
is already exactly the right anchor and needs no new concept. Its doc comment states the rule this
feature needs verbatim: *"This is the only source of a link origin. There is no request-derived
variant of this function and there must never be one."* `validate_public_base_url` already refuses
plain `http`, userinfo, query strings, fragments, whitespace and control characters.

**The ruling:**

- Derive the RP ID from `public_base_url`'s host. **Never** from the `Origin` or `Host` header — a request-derived RP ID is an attacker-chosen RP ID.
- Passkey enrolment must be **refused with a clear error when `public_base_url` is unset**, exactly as `an_invitation_cannot_be_issued_without_a_configured_public_base_url` already refuses invitations (`crates/chancela-api/tests/signup_and_invites.rs`). It defaults to `None`; most instances will not have set it.
- The **expected origin** passed to verification (`WebauthnBuilder::new(rp_id, &rp_origin)`) must be the full `public_base_url` origin, and it must **not** be widened by `CHANCELA_CORS_ALLOWED_ORIGINS` (`crates/chancela-api/src/cors.rs`). Companion origins may call the API; they must not be able to satisfy a WebAuthn origin check.

**The hazard, said out loud.** If an operator moves the instance from `livros.example.pt` to
`atas.example.pt`, **every enrolled passkey stops working, permanently, and no migration is
possible.** The credentials live in the users' authenticators, bound to the old RP ID; nothing the
server does can rebind them. Options, in order of preference:

1. **Set the RP ID to the registrable parent domain** (`example.pt`) rather than the host, at first enrolment, so a subdomain move survives. This is the single highest-value decision in this feature and it is one-way: it cannot be widened later without invalidating everything.
2. **Store the RP ID on each credential record** and refuse an assertion whose credential was enrolled under a different RP ID, with a message that names the change. A silent failure here reads as "my passkey is broken"; a named one reads as "the administrator moved the instance".
3. **Refuse to change `public_base_url`'s host while any passkey is enrolled** unless the operator confirms through a typed-phrase gate (`ConfirmationStrictness::ConfirmWithReauthAndPhrase`). This is the fail-closed direction and matches how the product treats other irreversible acts.

Recommend all three. (1) and (2) are cheap; (3) is the one that stops the incident.

## Finding 2 — the step-up chain as it stands, and whether a passkey may join it

**Re-derived from the code**, not from the tracker.

`crates/chancela-api/src/data.rs`:

```rust
pub(crate) fn step_up_is_vacuous(password_hash: Option<&str>, recovery_hash: Option<&str>) -> bool {
    password_hash.is_none() && recovery_hash.is_none()
}
```

`require_step_up` resolves the acting user by session username, then:

1. no resolvable user → `403`;
2. `step_up_is_vacuous(...)` → **`Ok(())` on the session alone** (the t69 exemption: a legacy no-hash operator with no recovery phrase must not be locked out of a gate for lacking a credential they never set);
3. otherwise the supplied password **or** recovery phrase must verify, else a uniform `403`.

Callers: `bundles.rs`, `data.rs` (×2), `data_status.rs`, `privacy.rs`, `recovery.rs` (×2),
`zk_repository.rs`, and `confirmation.rs::require_confirmation` — which is the generic funnel. In
`require_confirmation`, `ConfirmationStrictness::ConfirmWithReauth` and
`ConfirmWithReauthAndPhrase` both call `require_step_up`; `Off` and `Confirm` pass unconditionally,
and the code says why (`Confirm` has no server-observable signal).

**So the exemption is real and it is a set membership test over exactly two credential kinds.** TOTP
is already outside it: a user with a confirmed TOTP factor and no password and no recovery phrase
passes step-up on their session alone today.

**The trap, stated precisely.** A passkey interacts with this in two independent directions and both
must be decided together:

- *If a passkey is added as an accepted **proof*** and `step_up_is_vacuous` is left alone, nothing widens — a credentialed user gains one more way to satisfy a gate they could already satisfy. Safe.
- *If a passkey becomes a user's **only** credential* (no password, no recovery phrase) and `step_up_is_vacuous` is left alone, that user **passes every `ConfirmWithReauth` gate in the product on their session token alone** — book close, ledger re-anchor, factory reset, privacy erasure. That is a real widening, created by the *existence* of passkey-only users, not by adding a proof.

**Ruling.** A passkey may join the step-up chain, but the two changes are inseparable and must land in
one commit:

1. Extend the vacuity predicate — it must become a function of *every* credential the user holds, passkeys included, so a passkey-only user is **not** vacuous.
2. Add a passkey proof arm to `require_step_up`, so that same user can actually satisfy the gate.

Shipping (1) without (2) locks passkey-only users out of every destructive op. Shipping (2) without
(1) is the widening. Pin both with a test that asserts the exemption's *membership*, not its two
current fields.

**Shape.** Do not add a rung to `ConfirmationStrictness`. `confirmation.rs` already argues this at
length for device pairing: *"The strictness ladder is also the wrong axis. `Off < Confirm <
ConfirmWithReauth < ConfirmWithReauthAndPhrase` answers* how hard*; the user's decision answers* with
what*. That is a set of alternatives, not a rung."* `PairingConfirmationMethod`
(`Password | TotpCode | EmailedCode`) is the existing precedent and the right one: `ReAuth` gains an
optional passkey assertion field beside `password` and `recovery_phrase`, and a deployment can narrow
the accepted set the way `PairingConfirmationSettings` already allows.

One detail that is not optional: a step-up assertion must be bound to a **server-issued, single-use,
short-TTL challenge** scoped to step-up — not a sign-in challenge, and never a client-chosen nonce.
Otherwise a passkey assertion captured at sign-in is replayable into a factory reset.

## Finding 3 — recovery and lockout

**The recovery phrase must keep working, and it already does the right thing.** It is an independent
credential (`users.rs::issue_recovery` — "not derived from, nor wrapping, the password"), it is
single-use, and a recovery-authorized reset **retires the attestation key** because it cannot re-wrap
it. Passkeys change none of that.

**What passkeys add is a new way to be stranded**, and it has three arms:

| Scenario | Outcome | Ruling |
|---|---|---|
| Passkey lost, user still has a password | Signs in with the password; key unwraps from the password wrap. | Fine. Revoke the dead credential from the security screen. |
| Passkey lost, passkey was the *only* credential | Cannot sign in at all. | **The recovery phrase is the answer, and it must therefore be mandatory before a user can drop their password.** |
| Passkey lost, recovery phrase used | Signs in, password reset — and today the recovery arm *retires the attestation key*, so their signing identity changes fingerprint. | Expected and correct. It must be said in the UI at the moment the phrase is issued, not discovered afterwards. |

**Ruling — the invariant to enforce.** A user may not remove their password while holding zero
passkeys, and may not remove their last passkey while holding no password, **and in neither case
without an established recovery phrase**. That is one predicate: *after this operation, the account
must retain at least one credential that can start a session, plus one credential that can recover
it.* Enforce it server-side in the operation, not in the UI.

**The last-Owner invariant.** `chancela_authz::last_owner_guard(current_owner_admin_holders) ->
bool` returns `false` for 0 or 1 holders; `chancela_api::roles::last_owner_guard_ok` counts
deduplicated **active** Owner/admin principals. It is enforced in `roles.rs` (unassign),
`users.rs` (disable) and `privacy.rs` (erasure execute). It guards *role holding*, not
*sign-in ability* — so it does **not** catch a last Owner who locks themselves out by revoking
their own last credential. The design must not lean on it.

The relevant precedent for the shape of the answer is `RequiredAction::EnrolTwoFactor` in
`session.rs`, whose comment is exactly right and should be copied in spirit: *"enrol-on-next-sign-in,
never a lockout, so even the last Owner can always get far enough to enrol."* Any passkey requirement
must be a **wall**, never a lockout, for the same reason.

## Finding 4 — `UserView` is a ledger payload, and the cost is avoidable

**The mechanism.** `users.rs::record_user_event` does `serde_json::to_vec(&UserView::from(user))` and
hands the bytes to `Ledger::append`, which hashes them into `Event::payload_digest`. `UserView`'s own
doc comment records the consequence: a new field changes the digest of **future** `user.created` /
`user.updated` events. Past events are untouched and the chain stays intact — a digest covers the
payload as serialized at append time and nothing recomputes an old one — but the digest for a given
logical user state moves across the commit.

**The measured cost of adding one `UserView` field.** Counting by the previous field addition
(`has_totp`) as the proxy for "carries a full `UserView` literal", at `b7f7a8c3`:

| | |
|---|---|
| files carrying a `UserView` literal | **23** |
| …canonical wire fixtures (`contracts/user.json`, `contracts/session.json`, `contracts/user.dsr-export.json`) | 3 |
| …`apps/web` sources, unit tests and e2e specs | 17 |
| …Rust (`users.rs`, `totp.rs`, `tests/totp_and_account_policy.rs`) | 3 |

The three contract fixtures are asserted from **both** ends: `crates/chancela-server/tests/e2e_contracts.rs`
does a recursive key-set match against live server bytes, and `apps/web/src/contracts/contracts.test.ts`
feeds each fixture through the real client parse path *and* pins `Record<keyof T, true>`, so a
`types.ts` that gains or loses a key fails to compile. They must move in the same commit as the Rust
change or both sides go red.

**Separately**, a new field on the `User` *record* (not the view) hits **52 struct-literal sites
across 40 files** in `crates/`. Give it `#[serde(default)]` — the store skips rows it cannot parse,
so a non-defaulted field is silent data loss on every pre-existing row — and consider whether the
test literals should move to a builder rather than growing a 53rd copy.

**Ruling: do not add a passkey field to `UserView`.** Put the passkey list on its own endpoint
(`GET /v1/users/{id}/passkeys` → `PasskeyView`) with its own contract fixture. The ledger-payload
cost then drops to **zero**, the 23-file sweep does not happen, and the listing gets a shape it needs
anyway (per-credential name, created-at, last-used, RP ID, PRF-capability). The `has_*` booleans on
`UserView` exist because the *roster* screen needs them cross-user; nothing about passkeys is needed
on a roster row.

If a `has_passkey: bool` later proves genuinely necessary for the roster, that is a deliberate,
separately-authorized digest move — and it is one field, not a family.

## Where credentials are stored

A passkey credential record is `{ credential_id, public_key (COSE), sign_count, rp_id,
transports, name, created_at, last_used_at, backup_eligible, backup_state, prf_capable }`, plus —
only in shape A/C — the PRF wrap `{ kdf_salt, nonce, ciphertext }` of the attestation scalar.

**The public key is not a secret.** `CredentialMode::TwoFactorTotp` in
`crates/chancela-api/src/secretstore_persist.rs` exists because a TOTP shared secret *is* one, and
that store gives it AEAD-at-rest, write-only access and fail-closed reads (`provider_id` = the user
id, bound into the AEAD AAD). Putting a WebAuthn public key there buys nothing and costs something
real: every read of the credential list would go through a write-only secret store that is designed
to refuse to give things back.

**Ruling — split by sensitivity, and the split follows the existing rule exactly:**

- The credential record (id, public key, counter, name, timestamps, RP ID) → the **user record**, alongside `attestation_key` and `retired_attestation_keys`. It is the same kind of thing as `AttestationKeyBlob.public_key_sec1`, which is already stored in the clear.
- The **PRF wrap ciphertext** → also the user record. It is already AEAD ciphertext under a KEK the server never holds in plaintext at rest, which is precisely the argument `AttestationKeyBlob` makes for itself; routing it through the credential store would double-encrypt to no benefit and put the signing key behind a write-only door.
- Nothing passkey-related needs a new `CredentialMode`.

## Multiple passkeys, naming, listing, revocation

- **Multiple per user: required, not optional.** One passkey is one lost phone away from a lockout. The enrolment UI must push a second one.
- **Naming.** User-supplied label, defaulted from the AAGUID where a well-known mapping exists, else the transport hint. Never trusted for anything but display.
- **Listing.** `GET /v1/users/{id}/passkeys`, self-scoped by default; cross-user read behind `user.manage`.
- **Revocation.** `DELETE /v1/users/{id}/passkeys/{credential_id}`, gated by `require_step_up` — revoking a credential is a credential operation and must not ride a session alone. Emits a `user.updated` ledger event with a justification naming the credential label, not its id.
- **Can revoking the last one strand a user? Yes** — and only in the passkey-only case. This is the same predicate as Finding 3: refuse the revocation if the account would be left with no way to start a session. Refuse in the handler with a named error, not a disabled button.
- **Revoking a passkey destroys its PRF wrap.** Say so in the confirmation copy. The attestation key survives as long as *any* wrap survives (password, or another passkey's PRF wrap); if the revoked credential held the only wrap, the key must be retired via `retire_attestation_key` the same way a recovery reset does it, so past attestations keep verifying. Do not leave an unwrappable blob on the record.

## Discoverable credentials (resident keys)

`webauthn-rs` 0.5.5 is explicitly cautious: it acknowledges resident keys but says *"the platform and
browser user experience is not good enough to justify enabling these flows at present."* That was
written about usernameless flows generally.

**There is nonetheless a Chancela-specific argument for them, and it is the strong one.** A
username-first sign-in needs to know whether to offer the passkey button — which means an endpoint
answering "does this username have a passkey?". **That is a user-enumeration oracle**, and this
codebase spends real effort closing exactly that: `create_session` verifies unknown users against a
`dummy_verifier` so a wrong password and an unknown user are indistinguishable in status, body and
timing, and `error.rs` documents the same trap for the cross-user `403`. Adding a passkey-presence
lookup would rebuild the oracle the dummy verifier exists to prevent.

**Ruling: use discoverable credentials, with conditional mediation (autofill) on the sign-in field.**
The browser decides what to offer from what it holds; the server is never asked who exists. Set
`residentKey: "required"` at enrolment. The cost is authenticator storage slots on hardware keys —
acceptable, and the alternative costs an enumeration oracle.

## Signature counter

`signCount` is dead as a clone detector for synced passkeys. iCloud Keychain and Google Password
Manager return `0` on every assertion — a synced credential has no single coherent counter to
increment — and WebAuthn L2 §6.1.1 already says that when both stored and returned counters are `0`,
the authenticator does not support the counter and the check is skipped.

**Ruling:** store `sign_count`; enforce strict monotonicity **only** when both the stored and the
returned value are non-zero; on a regression **do not fail the assertion** — record a
`user.passkey.counter_regression` ledger event naming the credential and let an operator see it.
Treating it as a hard gate would lock out users of a device that legitimately reset, and treating a
constant zero as suspicious would lock out every synced passkey in existence.

## Attestation

**A legal-instrument product does not need authenticator attestation, and requesting it makes the
product worse.** The argument:

1. **Attestation attests the authenticator model, not the person.** It answers "is this a genuine YubiKey 5". Chancela's evidentiary claim is about *who signed*, and that claim is carried by the P-256 attestation key and its fingerprint — which exists precisely because a session is not a person. Nothing about a model certificate strengthens it.
2. **`none` is the default and the clients help it stay that way.** With `attestation: "none"` the client replaces the authenticator's statement with a None attestation and avoids an extra consent round trip. Asking for `direct` costs a prompt, and users read prompts as friction.
3. **`enterprise` returns uniquely identifying information about a device.** Shipping that on by default in a self-hosted product that also ships a DPIA register would be indefensible.
4. **The instruments this product signs are not signed by the passkey.** The passkey unwraps a key; the PAdES/CAdES/XAdES signature is produced by the certificate chain the signing crates already handle. Attestation would be evidence about the wrong artefact.

**Ruling: `attestation: "none"`.** If a deployment ever genuinely needs hardware assurance, that is
an `AuthSettings` opt-in with `direct` plus an operator-managed AAGUID allowlist — a separate,
later, explicitly-argued feature, not a default.

## Sessions and the two-step sign-in

A passkey sign-in must land in the same `CreateSessionOutcome` union that exists today
(`Authenticated | TwoFactorRequired`), and must respect `required_action_for(&user)`.

- **Passkey + TOTP required.** A passkey assertion is already a multi-factor event (possession + user verification). Demanding a TOTP code after it is theatre. **Ruling:** a passkey assertion with `userVerification: "required"` and `UV` set in the authenticator data satisfies the second-factor requirement; do **not** raise a `PendingTwoFactor` challenge. If `UV` is absent, fall through to the existing TOTP challenge — and then `PendingTwoFactor.unlocked_key` carries the PRF-unwrapped scalar across exactly as it carries the password-unwrapped one today. No new mechanism.
- **`RequiredAction::EnrolTwoFactor`** must be satisfiable by enrolling a passkey once passkeys count as a factor, or a passkey user hits a TOTP wall they have no reason to accept. This is a one-line change to `required_action_for` and a considerably larger change to the enrolment wall UI.
- **`CurrentUserPicker`** (the in-session switcher, `apps/web/src/features/session/CurrentUserPicker.tsx`) already refuses accounts that return a two-factor challenge, with `signin.challenge.switcherUnsupported`. A passkey sign-in in the switcher has the same problem and needs the same honest refusal, or it silently drops the user into a broken state.

## Tauri: a first-class finding, not a footnote

**Passkeys will not work in the desktop shell as it is built, on any platform, and this is not a bug
to be fixed by us.**

Two independent reasons, either of which is sufficient:

1. **The origin is wrong, structurally.** `apps/desktop/src-tauri/tauri.conf.json` sets `frontendDist: "../../web/dist"` — the web app is bundled and served from Tauri's custom protocol, not from the deployment's domain. On Windows and Android that origin is `http://tauri.localhost`; on macOS and Linux it is `tauri://localhost`. The only RP ID a page at that origin may assert is `tauri.localhost` / `localhost`. So a passkey enrolled in the desktop app is **a different credential, under a different RP ID, from one enrolled in the browser** — they do not interoperate, and the server would have to accept `tauri.localhost` as an expected origin, which discards the phishing binding that is the entire point.
2. **The WebViews do not all implement it.** WebView2 on Windows is Chromium and does support WebAuthn including Windows Hello. **WebKitGTK does not implement WebAuthn at all** (which is why passkeys do not work in GNOME Web), so Tauri on Linux has no path. WKWebView on macOS has WebKit's limitations without Safari's platform integration. `tauri-apps/tauri#7926` ("Allow Passkeys auth support in WebView") has been **open since 2023-09-30** and is still labelled `status: needs triage`.

**Ruling.** Passkeys are a **browser-only** feature in this product. The desktop shell must:

- not render passkey enrolment or passkey sign-in at all — detect the Tauri origin and hide the affordance, rather than showing a button that throws;
- show one honest sentence in the security screen saying passkeys are managed in the browser;
- keep password + TOTP fully functional, which it does today.

Do not attempt to route this through a Tauri plugin or a native FIDO library. That would be a second,
divergent WebAuthn implementation, on the credential path, in a product whose evidentiary claims rest
on there being one.

## Library

`webauthn-rs` — latest stable **0.5.5** (crates.io shows 0.5.5 released 2026-04-30; a 0.6.x
development track exists). It is the only serious Rust option, it is MPL-2.0, and it takes
`WebauthnBuilder::new(rp_id, &rp_origin)`, which is the right shape for Finding 1. It provides
`Passkey` (any authenticator) and `SecurityKey` types.

**Known gap: no documented PRF/`hmac-secret` support.** Because PRF is evaluated client-side and the
derived bytes are returned to JS, this is not a blocker for shape A — the server verifies an ordinary
assertion and receives the PRF-derived secret as a separate field. But it does mean the PRF handling
is **ours**, not the crate's, and must be reviewed as first-party crypto-adjacent code. That is the
single largest unquantified risk in this design and is why the dependency spike is ranked first below.

Also unresolved, and to be settled in that spike: whether 0.5.5 lets us set
`residentKey: "required"` and read back `backup_eligible` / `backup_state` without patching. Marked
**unknown** rather than guessed.

## Sequencing

**Must be decided before a line is written** (all three are one-way and cheap now, expensive later):

1. **RP ID granularity** — host (`livros.example.pt`) or registrable parent (`example.pt`). Recommend parent. Cannot be widened afterwards without invalidating every credential.
2. **Shape A / B / C.** Recommend C, PRF-first. Determines the storage schema.
3. **`UserView` stays frozen** — passkeys get their own endpoint and their own contract fixture. Recommend yes; it removes the entire ledger-payload cost.

**Then, in order:**

4. **Dependency and platform spike** (task #9). Prove on real hardware: `webauthn-rs` 0.5.5 with `residentKey: "required"`; PRF at `create()` vs a follow-up `get()`; PRF output stability across sessions; `backup_eligible`/`backup_state` read-back. Everything downstream depends on this and it can start immediately.
5. **The credential-lifecycle predicate** (Finding 3's one-sentence invariant) plus the **step-up pair** (Finding 2's two inseparable changes). Server-side, test-pinned, no UI. This is the security core and must land before any enrolment endpoint exists, or there is a window in which passkey-only users can be created against an unpatched step-up gate.

**Can run in parallel once 1–3 are ruled:**

- Registration + authentication endpoints, challenge store, credential storage (task #10).
- The `RequiredAction` / `PendingTwoFactor` interaction.
- Web enrolment, sign-in and management UI (task #11) — against a stubbed server.
- The Tauri suppression and its honest copy. Small, independent, and it should not be last: shipping the web feature without it means desktop users get a button that throws.
- pt-PT copy for enrolment, degradation ("esta chave de acesso pedirá a sua palavra-passe ao assinar"), revocation and RP-ID-change failure.

**Optional polish, explicitly deferrable:**

- AAGUID → friendly authenticator name mapping for the credential list.
- Counter-regression surfacing in the security screen (the ledger event is enough at first).
- Operator-configurable accepted step-up method set, in the `PairingConfirmationSettings` mould.
- An `AuthSettings.passkeys` slice at all — the feature can ship on the presence of `public_base_url` alone, and a settings slice is a `contracts/settings.json` change with its own key-set assertions.

## What this document does not answer

- Whether `webauthn-rs` 0.5.5 can express `residentKey: "required"` and return backup flags unpatched — **unknown**, resolved by the spike.
- Whether any real authenticator produces a PRF output that is stable across an OS credential *migration* (e.g. an iCloud Keychain restore to a new device) — **unknown**; the sources describe re-creation, not restore. If it is not stable, a device restore silently costs the user their attestation key, which would be a serious finding and must be tested before shape A is committed to.
- Whether the emailed-code and passkey paths should share a challenge store. Not investigated.

## Sources

Retrieved 2026-07-30.

- [Passkeys & WebAuthn PRF for End-to-End Encryption (2026)](https://www.corbado.com/blog/passkeys-prf-webauthn) — last modified 2026-05-19. The PRF support matrix, KB5077181 / build 26200.7840, Chrome/Edge 146 vs 147, Firefox 148+, WebKit bugs 311099 and 314934.
- [A Developer's Guide to Deriving Keys with WebAuthn PRF (Yubico)](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html) — PRF derivation happens at `get()`; raw output is IKM, not a key; iOS does not pass extension data to external authenticators.
- [Intent to Ship: WebAuthn PRF extension (Chromium blink-dev)](https://groups.google.com/a/chromium.org/g/blink-dev/c/iTNOgLwD2bI)
- [MDN — `PublicKeyCredentialCreationOptions`](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions) — RP ID must be the effective domain or a registrable suffix; credentials are strictly scoped to it; `none`/`indirect`/`direct`/`enterprise` semantics.
- [ImperialViolet — Signature counters (2023-08-05)](https://www.imperialviolet.org/2023/08/05/signature-counters.html) — why synced credentials cannot maintain a coherent counter.
- [W3C public-webauthn — §6.1.1 constant-zero counter case](https://lists.w3.org/Archives/Public/public-webauthn/2022May/0097.html) — both stored and returned `0` ⇒ skip the check.
- [`webauthn-rs` on crates.io](https://crates.io/crates/webauthn-rs) — 0.5.5 (2026-04-30), MPL-2.0.
- [`webauthn-rs` API docs](https://docs.rs/webauthn-rs/latest/webauthn_rs/) — `WebauthnBuilder::new(rp_id, &rp_origin)`; the quoted caution about usernameless flows.
- [tauri-apps/tauri#7926 — Allow Passkeys auth support in WebView](https://github.com/tauri-apps/tauri/issues/7926) — open since 2023-09-30, `status: needs triage`.
- [tauri-apps/tauri — FIDO2/U2F/WebAuthn discussion #6601](https://github.com/orgs/tauri-apps/discussions/6601) — "webview-based applications seem to be in the worst shape of all options right now".
- [Tauri — Webview Versions](https://v2.tauri.app/reference/webview-versions/) — WebView2 / WKWebView / WebKitGTK per platform.
- [How to change the origin of tauri from `http://tauri.localhost` (tauri#13631)](https://github.com/tauri-apps/tauri/issues/13631) — the custom-protocol origin mapping.
- [WebKit bug 205350 — [WPE][GTK] Support WebAuthn](https://bugs.webkit.org/show_bug.cgi?id=205350) and [GNOME Web issue #1007](https://gitlab.gnome.org/GNOME/epiphany/-/work_items/1007) — WebKitGTK does not implement WebAuthn.
- [Microsoft — Support for passkeys in Windows](https://learn.microsoft.com/en-us/windows/security/identity-protection/passkeys/)

---

*Not yet listed in `mkdocs.yml`'s `nav:`. `omitted_files: info` means the build does not fail without
it, but the page is unreachable from the site until someone adds it under "Reference".*
