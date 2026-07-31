# Passkeys / WebAuthn (design ruling)

> **Status.** Nothing is implemented. `grep -rli "webauthn\|passkey\|fido"` over the tree at `b7f7a8c3`
> matches only `chancela-zk`, where WebAuthn PRF is named as a *client-side* key-wrapping scheme for
> zero-knowledge repositories — unrelated to sign-in and not reused here.
>
> This document is a **ruling**, not a plan of record for code that exists. It answers one question
> first (what unlocks the attestation key), then records the two PRF-stability invariants and the four
> findings that will bite whoever builds it, then ranks the work. Every claim about this codebase was
> read out of the code and is cited by `file:symbol`; line numbers drift daily on this tree, so locate
> by symbol. Every claim about WebAuthn itself is cited to a dated external source at the end — this
> area moved twice in the last six months and a stale claim here would be expensive.
>
> **The dependency and platform spike (task #9) has landed**, on 2026-07-30, with a follow-up on
> 2026-07-31; their results are folded in here rather than kept as separate documents. Together they
> added the Public Suffix List trap to Finding 1, corrected several rows of the platform matrix,
> produced the two PRF-stability invariants, and **settled the library on `webauthn_rp` — reversing
> an earlier ruling in this document for `webauthn-rs-core`** once it was proven that passkeys can be
> built with no OpenSSL dependency at all. Reversals are recorded rather than erased, because the
> reasoning is the part worth keeping. Claims the spikes could not establish are marked
> **unverified** in place; those markers are load-bearing and should not be quietly upgraded to fact.

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
- **Cost 2 — a lost passkey loses that wrap, but a *restored* one does not.** These are different events and the doc previously conflated them. **Re-creating** a credential — even for the same account on the same authenticator — yields a different secret; there is no "re-create my PRF". **Restoring** a synced credential (iCloud Keychain, Google Password Manager) to a new device preserves it: the PRF seed travels with the credential. For a device-bound authenticator (Windows Hello, a security key) the question does not arise, because the whole credential is lost, not merely the wrap — which is the ordinary lost-passkey case in Finding 3. See the PRF-stability invariant below for the evidence and its confidence.
- **Cost 3 — no Rust library models `prf`, and the reason matters.** This holds for **both** candidates and so is not a library-selection criterion. Correcting an earlier claim that `webauthn-rs` 0.5.5 "documents no PRF/`hmac-secret` support": it *does* model CTAP2 `hmac-secret` (`hmac_create_secret`, `hmac_get_secret`, `HmacGetSecretInput`/`Output`), and its own doc comment on `hmac_get_secret` reads *"⚠️ Browsers do not support this!"*. What does not exist is **`prf`** — proven for `webauthn-rs` by exhaustively destructuring both extension structs, which compiles; `webauthn_rp` likewise carries no `prf` member. `hmac-secret` is the authenticator-facing CTAP2 extension; `prf` is the browser-facing WebAuthn extension, and only the latter is reachable from a web page. So the conclusion holds — **PRF handling is ours whichever library we pick** — but the reason is that these crates speak to the wrong layer, not that they are silent. A future reader will otherwise re-derive this.
- **Cost 4 — PRF at `create()` is usually available, and the fallback is the minority path.** Synced providers (iCloud Keychain, Google Password Manager) return the first PRF value at `create()`. Windows Hello does too, from Chrome 147 (`WEBAUTHN_API_VERSION_8`) and Firefox 147+; Chrome/Edge 146 is authentication-only. Older security keys may only generate an hmac-secret if asked for it at creation. Enrolment must still be *prepared* to do `create()` then an immediate `get()`, but that is now the exception rather than the designed flow.

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

PRF support as verified by the task-#9 spike on **2026-07-30**. Each row is cited to a dated source
at the end. Claims the spike could not verify are marked **unverified** and must not be repeated as
fact — a stale matrix here would misprice the whole feature.

| Platform | PRF status |
|---|---|
| **Windows 10** | **No PRF at all**, in any browser. |
| **Windows 11 24H2 / 25H2 / Windows Hello** | Available only since the **February 2026** cumulative update KB5077181 (builds 26100.7840 / 26200.7840, released 2026-02-10). Firefox 148+ full support (creation support was backported to 147); Chrome/Edge 147+ full, requiring `WEBAUTHN_API_VERSION_8`; **Chrome/Edge 146 is authentication-only** — it surfaces PRF at `get()` but not at `create()`. An unpatched Windows 11 has **no** Windows Hello PRF. *That KB5077181 is specifically the update carrying `hmac-secret` into Windows Hello is asserted by Corbado; no Microsoft primary source names it in the changelog —* **unverified**. |
| **macOS / iCloud Keychain** | Safari 18+, Chrome 132+, Firefox 139+ — for the *platform* authenticator. Current Safari is 26.x; **Safari 26.4 (2026-03-24) added PRF for security keys** as well. |
| **iOS/iPadOS 18+ / iCloud Keychain** | Supported. **18.0–18.3 returned wrong PRF values**; corrected in 18.4. See the PRF-stability invariant below — this was not a crash bug, it silently changed derived key material. |
| **Android / Google Password Manager** | Supported by default in Chrome, Edge, Samsung Internet. **Firefox on Android: no.** |
| **Security keys (YubiKey etc.), Windows 11** | Yes in Chrome/Edge/Firefox, and this **predates** the February 2026 update — KB5077181 unlocked *Windows Hello*, not security keys. |
| **Security keys, macOS/Safari** | Mostly working, contrary to earlier drafts. WebKit **311099** (Safari returned the hmac-secret output still encrypted, so a Safari↔Chrome round trip failed) is **fixed** — landed in Safari Technology Preview 241, confirmed 2026-04-09. *Whether that fix has reached a stable Safari release is* **unverified**. WebKit **314934** remains open (last touched 2026-05-29) and is narrow: biometric keys performing internal user verification (YubiKey Bio) return `prf.results.first = null`. Non-Bio keys work. |
| **Security keys, iOS/iPadOS** | **No** — the platform passes no extension data to or from external authenticators at all, so a PRF-capable YubiKey is unusable there. |
| **Chrome profile as authenticator** | No PRF. **unverified** — carried from the original draft and not re-checked by the spike. |

Read plainly: PRF is dependable on **current, patched** Windows/macOS/iOS/Android platform
authenticators in Chromium and Firefox, and on security keys everywhere except iOS and Safari-with-a-
Bio-key. It is *not* dependable on Windows 10, on an unpatched Windows 11, on any iOS security key,
or on Firefox for Android. That is a large enough tail that a self-hosted product cannot make PRF a
precondition of signing in.

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

## PRF stability — two invariants, both load-bearing for key custody

The PRF output is not merely *an* input to the unwrap; it **is** the unwrap secret. Anything that
changes it turns a working account into a decryption failure. Two mechanisms can change it, and
neither is obvious from the extension's API.

### Invariant 1 — `userVerification: "required"` on **both** ceremonies, and it is not a preference

CTAP2.1 maintains **two** per-credential seeds, `CredRandomWithUV` and `CredRandomWithoutUV`, and
derives the PRF output from whichever matches the assertion. An Apple platform engineer stated the
consequence plainly on 2025-02 (developer forum thread 764730):

> "These values should match, assuming your use of UV matches in both cases. The PRF extension
> specifies to use different seeds depending on whether UV (passcode/biometrics) was performed or
> not."

**So a UV-less assertion derives a different secret from the one enrolment used.** The attestation
key then fails to unwrap, and it fails as an AEAD decryption error — **indistinguishable from a wrong
password**. That is a diagnostic dead end: the user is told their credential is wrong when in fact
their credential was right and their authenticator merely skipped biometrics.

**Ruling.** `userVerification: "required"` on `create()` *and* on every `get()` that will be used to
unwrap. Record it in the credential record which seed the wrap was made under. Treat a UV-absent
assertion as "cannot unwrap, ask for the password" — **never** as "wrong credential". The spike
confirmed the library holds this line: under `UserVerificationPolicy::Required`, an assertion with
the UV bit clear is refused with `UserNotVerified` rather than silently accepted.

### Invariant 2 — a PRF wrap may **never** be the only wrap

This is not advice; it is the invariant that keeps the feature safe to ship.

The evidence is proven and dated rather than inferred. On iOS 18.0–18.3 Apple's PRF implementation
returned **wrong values**; 18.4 corrected them. Apple confirmed the bug (thread 764730, 2025-02) —
but the correction changed derived key material on already-enrolled credentials, and the same thread
records the consequence, still unanswered by Apple:

> Applications using PRF for encryption would have data encrypted with incorrect PRF values on iOS
> 18.0–18.3. Upon upgrading to 18.4+, users cannot decrypt this data because the PRF output changes.

**An operating-system update silently changed PRF output and destroyed PRF-wrapped data on shipping
devices, with no vendor migration guidance.** That already happened, to exactly this use case. It is
a stronger and better-evidenced risk than any question about device migration.

**Ruling — the invariant.** The attestation key **always** retains its **password wrap** alongside any
PRF wrap. A PRF wrap is only ever an *additional* wrap, exactly as shape A describes it ("a *second*
wrap of the attestation scalar"). The consequence is that losing the PRF path — lost device, revoked
credential, or an OS update that moves the output from under us — degrades to **"enter your
password"**, never to key loss.

**Be precise about what the recovery phrase is here, because it is tempting to count it and it does
not count.** Per the mechanism table above, a recovery-phrase reset **cannot** re-wrap the attestation
key and therefore *retires* it. The recovery phrase is an account-recovery path, **not a second wrap**.
So it satisfies Finding 3's "can recover the account" half and contributes **nothing** to this
invariant.

Two consequences follow, and they must be enforced server-side in the operation, not in the UI:

- **Removing the password is refused while an attestation key exists.** A user may stop *typing* their password — that is what shape A buys — but the wrap stays. "Passwordless" here means "no password at sign-in", never "no password wrap".
- Finding 3's credential-lifecycle predicate therefore gains a third clause, and the two rules are one predicate: *after this operation the account must retain at least one credential that can start a session, one credential that can recover it, **and** the attestation key must retain at least one non-PRF wrap.*

This also settles the migration question that an earlier draft left open. For a **synced** credential
(iCloud Keychain, Google Password Manager) the PRF secret does survive a restore to a new device:
the W3C PRF explainer states *"the key will be constant for a given credential"*, and Apple treats
cross-device divergence for one credential as a bug — the 18.4 fix exists precisely to make hybrid
and local outputs match, which is only achievable if the seed syncs with the credential. **Confidence:
high, but this is inference from a vendor statement about an adjacent case, not a vendor statement
about restore.** What would settle it: enrol a PRF credential, erase the device, restore from iCloud,
compare the output. For a **device-bound** authenticator the question does not arise — the whole
credential is gone, which is the ordinary lost-passkey case. Under Invariant 2 neither outcome costs
the user their attestation key, which is why the invariant is what makes the answer tolerable.

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

**The trap the spike found, and it is the finding of the spike.** `WebauthnBuilder::new` validates the
RP ID against the origin with a plain dotted-suffix test and **no Public Suffix List**:

```rust
effective_domain.ends_with(&format!(".{rp_id}")) || effective_domain == rp_id
```

So `rp_id = "pt"` with origin `https://livros.example.pt` is **accepted by the crate** (`example.com`,
`wrong.example.pt` and `""` are correctly rejected). A one-line "registrable parent" derivation that
strips the first label is therefore correct for `livros.example.pt` → `example.pt` and catastrophic
for `chancela.pt` → `pt`: server-side configuration validation passes, and **every enrolment then
fails in the browser with a `SecurityError` the server never sees**. A public suffix is not a valid
RP ID, and no amount of server-side care detects it, because the crate is not the component that
enforces the rule.

**Both halves of this validation are ours, and that is now load-bearing rather than
defence-in-depth.** `webauthn_rp` does **not** cross-check the RP ID against the origin at all: the
spike completed a full ceremony with RP ID `example.com` against origin
`https://livros.example.pt`, where `webauthn-rs` refuses that pair at `WebauthnBuilder::new`. A real
browser never produces that combination, so this is a misconfiguration guard rather than an attack
surface — but with the library performing neither the suffix check nor a PSL check, **nothing else in
the stack will catch a mis-set RP ID before it reaches users.**

**The ruling — required, not recommended:**

- **The RP ID is an explicit operator setting**, not a derived value. **Never derive it by stripping a label from `public_base_url`.**
- It must be **validated against `public_base_url`** — it has to be the host or a registrable suffix of it — **and checked against the Public Suffix List** so a public suffix is refused at configuration time with a named error. Use a PSL crate (`psl` or `publicsuffix`; both are permissively licensed). Neither of these checks is optional and neither is provided by the library.
- Where the operator supplies nothing, offering `public_base_url`'s **host** as the default is safe. Offering a label-stripped parent as a default is not, for the reason above — the parent must be a deliberate, confirmed operator choice.
- **Never** take the RP ID from the `Origin` or `Host` header — a request-derived RP ID is an attacker-chosen RP ID.
- Passkey enrolment must be **refused with a clear error when `public_base_url` is unset**, exactly as `an_invitation_cannot_be_issued_without_a_configured_public_base_url` already refuses invitations (`crates/chancela-api/tests/signup_and_invites.rs`). It defaults to `None`; most instances will not have set it.
- The **expected origin** passed to verification (`WebauthnBuilder::new(rp_id, &rp_origin)`) must be the full `public_base_url` origin, and it must **not** be widened by `CHANCELA_CORS_ALLOWED_ORIGINS` (`crates/chancela-api/src/cors.rs`). Companion origins may call the API; they must not be able to satisfy a WebAuthn origin check.

**The hazard, said out loud.** If an operator moves the instance from `livros.example.pt` to
`atas.example.pt`, **every enrolled passkey stops working, permanently, and no migration is
possible.** The credentials live in the users' authenticators, bound to the old RP ID; nothing the
server does can rebind them. Options, in order of preference:

1. **Set the RP ID to the registrable parent domain** (`example.pt`) rather than the host, at first enrolment, so a subdomain move survives. This is the single highest-value decision in this feature and it is one-way: it cannot be widened later without invalidating everything. Per the ruling above this is an **operator choice validated against the PSL**, never a derivation — and the spike confirmed the pairing works: RP ID `example.pt` with origin `https://livros.example.pt` completes a full registration round trip, with `rpIdHash = SHA256("example.pt")`. Note also that `WebauthnBuilder::allow_subdomains(true)` does **not** help here and must stay `false`: it widens acceptance to origins *beneath* the configured one (`deep.livros.example.pt`), not to siblings (`atas.example.pt`), so it buys nothing for a subdomain move and only loosens the origin check.
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
without an established recovery phrase**. Joined with Invariant 2 above, that is **one** predicate:
*after this operation, the account must retain at least one credential that can start a session, one
credential that can recover it, and — where an attestation key exists — at least one non-PRF wrap of
that key.* Enforce it server-side in the operation, not in the UI.

The third clause is what makes the first two safe rather than merely tidy: without it, an account can
satisfy "can sign in" and "can recover" while its signing identity hangs on a PRF output that a vendor
can move out from under it. Note it also means **the password wrap is never removed while an
attestation key exists** — see Invariant 2 — so the "drop their password" case below is about ceasing
to *type* it, not about deleting the wrap.

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

**This ruling is one of the reasons the library choice below is `webauthn_rp`.** The spike found that
`webauthn-rs`'s `start_passkey_registration` does not merely omit the member — it emits
`residentKey: "discouraged"`, which is an *active instruction to the browser not to create a
discoverable credential*, and there is no setter to change it. `webauthn_rp`'s `passkey()` helper
emits `residentKey: "required"` with no configuration at all. See "Library".

Note that **conditional mediation has not been exercised end-to-end in a real browser** — the spike
drove a software authenticator. Marked **unverified**; it is the first thing the enrolment lane
should confirm.

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

Settled by the task-#9 spike and its follow-up, both of which exercised the crates rather than
reading their docs. Every claim below was produced by running code.

**Ruling: `webauthn_rp` 0.3.0 (crates.io, MIT OR Apache-2.0).**

An earlier draft of this section ruled for `webauthn-rs-core` with OpenSSL behind a `passkeys`
feature. That ruling was reversed after a second spike asked the obvious question — *can passkeys be
built without OpenSSL at all?* — and answered it by writing code against `webauthn_rp` rather than
reading its landing page. It can. The reversal is recorded rather than erased because the reasoning
is the useful part.

**Every capability below was proven by running code**, against the same software authenticator used
for `webauthn-rs`, so the two libraries were compared on identical bytes.

| Question | Result |
|---|---|
| Registrable-parent RP ID + subdomain origin | RP ID `example.pt`, origin `https://livros.example.pt` → verified |
| `residentKey: "required"` | `{"requireResidentKey":true,"residentKey":"required","userVerification":"required"}` with `attestation:"none"` — **the entire frozen constraint set, from `PublicKeyCredentialCreationOptions::passkey()` with no configuration** |
| Backup eligibility / state | `Exists` / `Eligible` / `NotEligible`, all three correct |
| Ceremony-state serialisation | 103 bytes via `Encode`, behind `serializable_server_state` — a feature **not** named `danger-*` |
| UV enforcement | a UV=0 registration is refused with `UserNotVerified` |
| Authentication round trip | authenticated; `sign_count` advanced |
| Tampered signature | refused with `AssertionSignature` |

Three ways it is **better** than `webauthn-rs`, not merely equivalent:

1. **The `passkey()` helper is exactly our profile**, with no escape hatch and no `danger-` feature. `webauthn-rs`'s equivalent emits `residentKey: "discouraged"` — an active instruction *not* to create a discoverable credential — and reaching `required` means dropping to `webauthn-rs-core`.
2. **`Backup` is a three-state enum** (`NotEligible | Eligible | Exists`), so the illegal BE=0/BS=1 combination is **unrepresentable** rather than merely rejected. `webauthn-rs` carries two independent bools.
3. **It derives the credential ID from `authData`** instead of trusting the client-supplied `id`/`rawId` — its `Registration` type does not accept those fields at all. Strictly stricter on the credential path.

**Dependency verdict: three crates, no C.** New to `Cargo.lock`: `webauthn_rp`, `precis-core`,
`precis-profiles` — all MIT/Apache-2.0. Every cryptographic crate it needs (`p256`, `p384`,
`ed25519-dalek`, `rsa`, `rand`) is **already in the lock**, and `p256` is what `attestation.rs`
already uses. No OpenSSL, no `openssl-sys`, no vendored C build, no Perl/NASM toolchain requirement.
By contrast `webauthn-rs-core` would have added 20 crates plus a hard, non-optional `openssl` +
`openssl-sys` pair that no feature can switch off. **No `passkeys` cargo feature is needed for
dependency-isolation reasons** — the earlier ruling's feature gate existed only to keep OpenSSL off
the default path, and there is no longer an OpenSSL to keep off.

This also removes the tension with `crates/chancela-store/Cargo.toml`, which records that rustls was
chosen for Postgres TLS specifically to gain `sslmode` support *"WITHOUT dragging in OpenSSL"*. The
passkeys path now honours that decision instead of reintroducing the dependency it was made to avoid.

### The maintenance risk, stated plainly

`webauthn_rp` has **one maintainer**, a **self-hosted repository** (`git.philomathiclife.com`), **no
release since 2025-04**, and roughly **9,500 lifetime downloads** — against `webauthn-rs`, which is
Kanidm's and widely deployed. This is a real risk and it is accepted deliberately, not overlooked.

What makes it acceptable is that it is **bounded and the escape route is costed**:

- It is **MIT OR Apache-2.0** and about **7,700 lines of pure Rust with no C**. If it were abandoned we could vendor it into the tree and maintain it ourselves. Vendoring an abandoned C OpenSSL build is not a comparable proposition.
- The fallback is not unknown. First-party verification was **seriously costed and rejected on a specific number** (below): **~45 server-side obligations**. A future reader inheriting an abandoned dependency knows exactly what walking away costs.

### Why not implement it ourselves

Asked properly, costed against the WebAuthn L3 text rather than from memory, and rejected. Recorded
here so the next person to ask "why not just implement it?" gets the count rather than an opinion.

Because the attestation-`none` ruling removes the hardest part, **the cryptography is trivial**:

- **§7.1 registration: zero signature verifications.** The `none` format's verification procedure is that `attStmt` must be empty. The only cryptographic work is one SHA-256 over `clientDataJSON`, one SHA-256 comparison for `rpIdHash`, and a COSE key decode whose on-curve check `p256` already performs.
- **§7.2 authentication: exactly one ECDSA-P256 verification**, over `authData ‖ SHA256(clientDataJSON)` with a DER-encoded signature (step 26), plus one SHA-256.

**The count: about 45 server-side obligations** — roughly 25 for registration and 20 for
authentication, after collapsing the attestation branches that `none` makes vacuous. **Four touch
cryptography. None requires implementing a primitive.**

**The reason not to is the other 41.** Every one of them fails *silently*, and they are precisely
where real relying-party vulnerabilities live: a challenge that is not single-use (replay), an origin
matched by substring rather than equality (phishing), an unchecked `type` field (a `webauthn.create`
response accepted for `webauthn.get`), a missing `alg` allow-list (algorithm confusion), an unchecked
`rpIdHash` (cross-RP credential reuse), an unchecked `credentialId` uniqueness (takeover). The happy
path is perhaps 400 lines and a day's work; **the assurance is ~45 negative tests**, and what a
library actually buys is that someone has already written them. It would also mean owning a CBOR
parser fed attacker-controlled bytes, with its duplicate-key, indefinite-length and
non-canonical-integer traps.

First-party was the right answer to "avoid OpenSSL". It stopped being the right answer the moment a
pure-Rust library was shown to meet every frozen constraint.

### What the spike did not establish

Two things remain **unverified**, and the strength of the recommendation must not quietly upgrade
them:

- **Conditional mediation end-to-end in a real browser.** The spike drove a software authenticator, not a browser autofill flow.
- **PRF.** Neither library models the `prf` extension; it is evaluated client-side and the handling is ours under either choice. Nothing about this ruling changes the PRF work described below.

**The PRF handling is ours, and it is smaller than this document previously feared.** Because PRF is
evaluated client-side and the derived bytes are returned to JS, the **server-side WebAuthn
verification needs zero PRF-specific code** — it verifies an ordinary assertion. First-party work is:

| Where | What | Crypto? |
|---|---|---|
| Web, ~40 lines | Set `extensions: { prf: { eval: { first: salt } } }` on create and get; read `getClientExtensionResults().prf`. The salt is a **fixed constant** (a domain-separation string), NOT per-credential and NOT stored on the record — **not** the challenge either. See the correction below. | None |
| Web, ~15 lines | Raw PRF output is input keying material, not a key (Yubico is explicit). `HKDF-SHA256(ikm = prf.results.first, salt = <constant>, info = "chancela-attestation-kek-v1")` → 32 bytes, via `crypto.subtle.deriveBits`. | **One WebCrypto call. Nothing hand-rolled.** |

> **Correction (t10 implementation): the salt is a constant, not per-credential.** An earlier
> draft said "per-credential salt, stored on the credential record". That is *impossible* under the
> discoverable-credentials ruling, and the two rulings are what make it so: in a discoverable
> sign-in the server does not learn which credential will answer until the assertion comes back —
> which is precisely the property that removes the user-enumeration oracle — so it cannot select a
> per-credential salt when it mints the challenge. `evalByCredential` would need a populated
> `allowCredentials` (username-first, i.e. the oracle back), and a two-ceremony get→learn→get flow
> costs two biometric prompts. A **constant** salt is not a compromise: CTAP2.1 already keeps the
> PRF seed per-credential *inside the authenticator* (`CredRandomWithUV`), so the salt only supplies
> domain separation between uses, which a fixed string does completely. Two credentials of the same
> user still derive different secrets and so still carry independent wraps of the same scalar — the
> definition of "a second wrap", so **Invariant 2 is untouched**. Consequence: **do not add a
> `prf_salt` field to `PasskeyCredential`.** The salt lives as a constant (or a settings value), not
> per row.
| Transport | The derived secret is POSTed. `create_session` already receives `req.password` on the same path, so this is architecturally symmetric — but it is a secret in a request body and needs the same redaction and zeroize treatment as `password`. | None |
| Rust | The base64url of those 32 bytes becomes the `secret: &str` for `AttestationKeyBlob::wrap` / `::unlock`. | **None.** |

One note on `derive_kek`: it is `Argon2::default()`, tuned for low-entropy passwords. Running argon2id
over a uniformly-random 256-bit secret is wasted work, but it is harmless and it keeps the blob format
byte-identical. **Accept it** rather than adding a KEK-derivation variant with a new format field and
a migration.

So the crypto-adjacent first-party surface is **one HKDF call in the browser**. The residual risk in
this feature is not code — it is operational, and it is the two invariants recorded above.

## Sequencing

**Decided. All of these are one-way; none is open:**

1. **RP ID granularity** — the registrable parent (`example.pt`) rather than the host, so a subdomain move survives. It is an **explicit operator setting**, validated against `public_base_url` and against the Public Suffix List — **never** derived by stripping a label. See Finding 1. Cannot be widened afterwards without invalidating every credential.
2. **Shape A / B / C.** **C**, PRF-first. Determines the storage schema.
3. **`UserView` stays frozen** — passkeys get their own endpoint and their own contract fixture. This removes the entire ledger-payload cost.
4. **Library** — **`webauthn_rp` 0.3.0**, no OpenSSL, no cargo feature gate needed. See "Library". (An earlier revision of this document ruled for `webauthn-rs-core` behind a `passkeys` feature; that was reversed once a pure-Rust library was proven to meet every constraint.)

**Then, in order:**

5. ~~**Dependency and platform spike** (task #9).~~ **Done, 2026-07-30, plus a follow-up on 2026-07-31.** The first settled the resident-key and backup-flag questions, the PRF platform matrix and the two PRF-stability invariants, and found the Public Suffix List trap in Finding 1. The follow-up asked whether passkeys could be built without OpenSSL at all, proved that they can, and reversed the library ruling. Both are folded into this document rather than kept separately.
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

- ~~Whether a Rust library can express `residentKey: "required"` and return backup flags unpatched.~~ **Answered, and it decided the library.** `webauthn-rs`'s passkey helper cannot — it emits `residentKey: "discouraged"`, and reaching `required` means dropping to `webauthn-rs-core`. `webauthn_rp`'s `passkey()` helper emits `required` with no configuration. Both return backup flags correctly. See "Library".
- ~~Whether any real authenticator produces a PRF output stable across an OS credential *migration*.~~ **Answered well enough to build on, and superseded by a better-evidenced risk.** For a synced credential the PRF secret does survive a restore (high confidence, by inference from a vendor statement about an adjacent case); for a device-bound one the whole credential is lost anyway. The sharper, *proven* risk is that an **OS update** can change PRF output — iOS 18.0–18.3 → 18.4 did exactly that and orphaned PRF-wrapped data on shipping devices with no vendor migration guidance. This is why a PRF wrap may never be the only wrap. See "PRF stability — two invariants".
- Whether the WebKit 311099 fix has reached a **stable** Safari release, rather than only Safari Technology Preview 241 — **unverified**.
- Whether Chrome-profile-as-authenticator still lacks PRF — carried from the original draft, **unverified**; the spike did not re-check it.
- ~~Whether `webauthn_rp` supports PRF, resident keys and backup flags.~~ **Answered by writing code against it.** Resident keys, backup flags, UV enforcement, state serialisation and a full authentication round trip all work; it is now the chosen library. PRF is not modelled by *any* Rust library and stays ours — see below.
- Whether conditional mediation works end-to-end in a real browser — **unverified**. The spike drove a software authenticator, not a browser autofill flow.
- Whether the PRF extension behaves as the platform matrix says on real hardware — **unverified** in the sense that neither library models `prf`; the client-side handling is ours regardless of library choice.
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

Added by the task-#9 spike, retrieved **2026-07-30**. Claims sourced only to the spike were produced
by running code against `webauthn-rs` 0.5.5, not by reading its documentation.

- [Apple Developer Forums thread 764730 — "Different PRF output when using platform or cross-platform authentication attachement"](https://developer.apple.com/forums/thread/764730) — reported 2024-09; **Apple Systems Engineer reply 2025-02** confirming the divergence was a bug, that hybrid and local PRF values must match, that the fix shipped in the iOS 18.4 / macOS 15.4 betas, **and** that the PRF extension uses different seeds depending on whether UV was performed. Also carries the unanswered report that the 18.4 correction made 18.0–18.3 PRF-encrypted data undecryptable. This single thread is the source for both invariants.
- [Apple Developer Forums thread 774111 — "Passkey PRF inconsistency between apple devices"](https://developer.apple.com/forums/thread/774111) — Feb–Mar 2025; the same defect observed across two devices on one iCloud account.
- [W3C WebAuthn PRF explainer](https://github.com/w3c/webauthn/blob/main/explainers/prf-extension.md) — *"the key will be constant for a given credential"*; PRF may be implemented over CTAP2 `hmac-secret`.
- [FIDO CTAP 2.1 — `hmac-secret` extension](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html) — the `CredRandomWithUV` / `CredRandomWithoutUV` pair underlying Invariant 1.
- [Microsoft — February 10, 2026 KB5077181 (OS builds 26200.7840 and 26100.7840)](https://support.microsoft.com/en-us/topic/february-10-2026-kb5077181-os-builds-26200-7840-and-26100-7840-f0fa9e54-a22a-4a06-96b6-bf5b2aded506) — confirms the update, its date and its build numbers. It does **not** name `hmac-secret`; that attribution rests on Corbado alone and is marked unverified above.
- [WebKit bug 311099](https://bugs.webkit.org/show_bug.cgi?id=311099) — Safari returned hmac-secret output undecrypted, breaking Safari↔Chrome round trips. **Fixed**; landed in Safari Technology Preview 241, confirmed 2026-04-09.
- [WebKit bug 314934](https://bugs.webkit.org/show_bug.cgi?id=314934) — PRF returns `null` for biometric security keys using internal UV (YubiKey Bio). Still open, last updated 2026-05-29. Narrower than the earlier draft implied.
- [WebKit Features for Safari 26.4](https://webkit.org/blog/17862/webkit-features-for-safari-26-4/) — 2026-03-24; PRF support extended to security keys.
- [`webauthn_rp` on crates.io](https://crates.io/crates/webauthn_rp) — 0.3.0 (2025-04-03), MIT OR Apache-2.0; pure-Rust (`p256`, `p384`, `ed25519-dalek`, `rsa`), no OpenSSL. **The chosen library**, proven against by the follow-up spike on 2026-07-31.
- [W3C WebAuthn Level 3 §7.1 "Registering a New Credential" and §7.2 "Verifying an Authentication Assertion"](https://www.w3.org/TR/webauthn-3/#sctn-rp-operations) — the two verification procedures whose step lists produced the ~45-obligation count behind the "why not implement it ourselves" ruling. Retrieved 2026-07-31.
- [tauri-apps/tauri#7926 — Allow Passkeys auth support in WebView](https://github.com/tauri-apps/tauri/issues/7926) — open since 2023-09-30, `status: needs triage`.
- [tauri-apps/tauri — FIDO2/U2F/WebAuthn discussion #6601](https://github.com/orgs/tauri-apps/discussions/6601) — "webview-based applications seem to be in the worst shape of all options right now".
- [Tauri — Webview Versions](https://v2.tauri.app/reference/webview-versions/) — WebView2 / WKWebView / WebKitGTK per platform.
- [How to change the origin of tauri from `http://tauri.localhost` (tauri#13631)](https://github.com/tauri-apps/tauri/issues/13631) — the custom-protocol origin mapping.
- [WebKit bug 205350 — [WPE][GTK] Support WebAuthn](https://bugs.webkit.org/show_bug.cgi?id=205350) and [GNOME Web issue #1007](https://gitlab.gnome.org/GNOME/epiphany/-/work_items/1007) — WebKitGTK does not implement WebAuthn.
- [Microsoft — Support for passkeys in Windows](https://learn.microsoft.com/en-us/windows/security/identity-protection/passkeys/)

---

*Not yet listed in `mkdocs.yml`'s `nav:`. `omitted_files: info` means the build does not fail without
it, but the page is unreachable from the site until someone adds it under "Reference".*
