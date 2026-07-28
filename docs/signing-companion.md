# Signing companion (design decision)

> **Status.** This is a recorded design decision, not a proposal, and **no code implements it yet**.
> Two points remain with the product owner and are marked
> [AWAITING DECISION](#what-is-decided-and-what-is-still-open) below: the rendezvous-over-loopback
> transport call, and the mitigation chosen for the [WYSIWYS gap](#the-wysiwys-gap). Everything else
> here is settled, and the findings that forced it are facts about the current tree, verified in
> code and cited by file and line.

## The problem

Hardware-backed signing — Cartão de Cidadão via PC/SC + PKCS#11, and local PKCS#12 certificates —
is today available **only** when the operator works inside the desktop application. A browser user
gets nothing.

The request was for the desktop app to become a **local mediating component**, the way the
Autenticação.gov Cartão de Cidadão middleware or a vendor updater is: the browser page stays where
it is, and a locally-running component brokers the hardware interaction and the certificate
retrieval on the page's behalf. Explicitly **not** a redirect and not "open the desktop app to
continue" — the desktop app becomes plumbing the web UI calls into.

## Why this is not called a bridge

The codebase already uses "bridge" for something with the **opposite topology**.
`CcBridgeStatusResponse` (`crates/chancela-api/src/signature.rs:2064`) reports a `transport` field
hardcoded to `"embedded_loopback"` (`signature.rs:3223`, and four further construction sites), and
its own documentation describes it as "the desktop's same-origin embedded loopback API, **never a
remote card relay**".

That existing bridge is in-process and same-origin. The component described here is out-of-process
and reached through the server. Two things called "the bridge" with opposite topologies is how a
future reader misreads both, so this is named the **signing companion**.

"Relay" was also unavailable, and deliberately so: the existing documentation uses it as a
*negation*. Adopting a word the codebase already spends to say "not this" would be worse than the
collision it avoids.

"Companion" is the noun `crates/chancela-api/src/pairing.rs` already uses for a paired device acting
for the operator ("companion session", "companion device", and `docs/mobile.md`). This extends
established vocabulary rather than introducing a third one.

The names are settled: type `SigningCompanion`, pairing device kind `signing_companion`, routes under
`/v1/signature/companion/...`. The two rejected alternatives are recorded above so that the choice is
not relitigated later on the assumption that nobody weighed them.

## Ground truth in the current tree

Established by reading the code, because the design turns on these being true.

1. **The desktop app is a Tauri v2 shell that embeds the entire API.**
   `apps/desktop/src-tauri/src/lib.rs:41-49` sets `CHANCELA_LOCAL_SIGNING=1` at process entry, then
   starts `chancela_api::app` — the web UI *and* `/v1` — on an ephemeral loopback port and navigates
   the WebView there. There is no separable signing component today; local signing works only
   because the *whole server* is on the operator's desk.

2. **`state.local_signing` is an environment boolean, nothing more.**
   `crates/chancela-api/src/signature.rs:1979-1987` parses `CHANCELA_LOCAL_SIGNING`. Eight sites gate
   on it and return `409`: `signature.rs:2273`, `termo.rs:648`, `termo.rs:1444`,
   `asic_signing.rs:142`, `batch_signing.rs:201`, `scap.rs:534`,
   `signature_pkcs12_stored.rs:136`, `xades_signature.rs:195`. It asserts *"the API process is the
   desktop shell"* — **not** *"a card is reachable"*.

3. **The hardware layer is real and already digest-shaped.**
   `chancela-smartcard` has genuine `cryptoki` PKCS#11 (`src/pkcs11.rs`), PC/SC reader detection,
   CC v1 RSA-2048 / CC v2 P-256 branching, and certificate selection by `CKA_LABEL` — never by slot
   index. Its signing boundary is already `CryptoToken::sign_digest(cert, &[u8; 32])`
   (`src/token.rs:93`), with a `MockToken` for offline tests.

4. **`sign_pdf_cc` needs the card local, but takes the whole PDF.**
   `sign_pdf_cc_with_appearance` (`crates/chancela-signing/src/cc.rs:210`) performs trusted-list gate
   → `prepare` → `sign_digest` → `assemble_cades_b` → `embed` → `validate`, all over `pdf: &[u8]`.
   **Only `sign_digest` needs hardware.** Everything else is pure computation that belongs
   server-side.

5. **PKCS#12 signing needs nothing local at all.**
   `sign_termo_slot_pkcs12` (`crates/chancela-api/src/termo.rs:753`) receives `req.pkcs12_base64`
   **and** `req.passphrase` in the request body (`termo.rs:804-822`) — the private key crosses to the
   server. It is gated on `local_signing` purely so that "the server" means "the operator's own
   machine".

## Finding A — a browser page cannot reach a loopback companion today

The server sets `default-src 'self'` with **no `connect-src` directive**
(`crates/chancela-api/src/lib.rs:3936-3941`). `connect-src` therefore inherits `'self'`, and a page
served by `chancela-server` cannot fetch `http://127.0.0.1:<port>` at all.

Enabling it is not a local change. It requires adding `connect-src http://127.0.0.1:*` to the
production Content-Security-Policy of **every deployment** — a permanent concession paid by every
customer to serve a minority path. Compounding it:

- HSTS is emitted unconditionally (`lib.rs:3947`), so real deployments are HTTPS.
- Chrome's Local/Private Network Access gating puts a CORS preflight **and a user permission
  prompt** in front of secure-origin → loopback requests.
- Safari does not exempt loopback from mixed-content blocking the way Chrome and Firefox do.

**The platform split that bites is the browser, not the OS.** Windows/macOS/Linux differences are
comparatively minor; the browser matrix is where a loopback transport actually fails.

## Finding B — a paired session structurally cannot commit a ledger event

This is the most important finding, and it **forces** the protocol shape rather than informing it.

`mint_session` is called from `crates/chancela-api/src/pairing.rs:560` with `unlocked_key = None`.
`CurrentAttestor` (`crates/chancela-api/src/actor.rs:412-438`) derives its signer from
`entry.unlocked_key`. A companion/paired session therefore yields `CurrentAttestor { signer: None }`.

**Consequence: the signing companion cannot attest a ledger event.** Only the operator's interactive
browser session holds the unlocked attestation key. The three-party protocol below is *forced by
this*, not chosen for elegance.

> **The check enforcing this must be explicit**, not a reliance on the missing attestation key.
> A guard that works by accident stops working the moment someone "fixes" the accident.

## Decision: server-mediated rendezvous

The desktop app long-polls the server over **its own authenticated TLS connection** for pending
signing jobs. The browser page talks only to the server, same-origin. No local socket exists.

The desktop app is still exactly the mediating component that was asked for — it brokers the
hardware interaction and the certificate pull, with no redirect and no "open the app to continue".
The request was about the desktop app's **role**, and rendezvous satisfies it completely.

No SSE or WebSocket infrastructure exists anywhere in the repository (zero matches for
`event-stream`, `WebSocket`, `tungstenite` across `crates/`), so this is plain HTTP long-poll on the
existing axum stack — **no new dependency**.

### What this buys

**There is no local socket for a hostile page to call.** The central risk of a loopback design — a
malicious page enumerating the operator's certificates or triggering a signature — becomes
*structurally impossible* rather than *defended against*. It also works in every browser, on a
phone, and when the operator's browser is on a different machine from the card.

### What this does NOT prove

**Rendezvous does not prove browser/card co-location.** The signature attests that the cardholder
consented in the desktop app and entered the PIN — which is what a qualified electronic signature
should attest — but the product must not claim that the browser session and the card are on the same
machine.

Accordingly, **`local_signing` stays exactly as it is and is never reused to mean "a companion is
available".** Those are different claims about different things, and collapsing them would make the
existing eight gates lie.

## Rejected transports

| Transport | Why it loses |
| --- | --- |
| **Loopback HTTP** | Finding A: a production CSP widening for every deployment, an LNA permission prompt, and Safari mixed-content breakage. It also still needs a bearer secret, because CORS is browser-enforced only — a hostile *native* process ignores origin headers entirely. |
| **WebSocket to loopback** | Everything above, plus a worse mixed-content story (`ws://` from an `https://` page). |
| **Native messaging host** | Best isolation of the four, but requires a per-browser extension through store review. Highest friction, and an extension the user must install is the opposite of "inherent". |
| **Custom URI scheme** | One-way with no return channel, and cannot enumerate certificates at all. This is precisely the redirect the request rejected. |

## The boundary: the companion signs a digest, never a document

**No document bytes ever reach the companion.** The hardware path does not merely permit this —
`CryptoToken::sign_digest` (`crates/chancela-smartcard/src/token.rs:93`) *already is* that
primitive.

What crosses:

- **Up:** certificate DER and issuer DER.
- **Down:** a 32-byte digest, plus human-readable display strings.
- **Up:** a `RawSignature`.

Two round trips are **forced by CAdES**, not by choice: the signed-attributes digest binds the
signing certificate through the ESS `signing-certificate-v2` attribute, so the server cannot compute
the digest until it knows which certificate will sign.

### Protocol

1. **Browser creates the job.** `Permission::SigningPerform` is checked on the act's scope
   (unchanged RBAC). A fail-closed audit event is written **before** any card contact, exactly as
   `test_cc_bridge` already does at `signature.rs:2446`.
2. **Companion polls**, enumerates certificates, posts descriptors plus leaf DER and issuer DER.
3. **Server runs the trusted-list gate** (SIG-11/23) **server-side**, then
   `prepare_signature_with_appearance` → byterange digest → signed-attributes digest.
4. **Companion polls**, receives the 32-byte digest and display fields, shows a **native
   confirmation**, the card signs, and it posts the `RawSignature`.
5. **Browser polls, then commits.** The server does `assemble_cades_b` → `embed_signature` →
   `validate_pdf_signature` → persist → ledger append **under the browser session's attestation
   key**. This step is forced by [Finding B](#finding-b-a-paired-session-structurally-cannot-commit-a-ledger-event).

> **The trusted-list gate stays server-side.** It is exactly the thing a later "the companion
> already has the certificate, why round-trip?" optimisation would try to move. It must not move.

### PKCS#12 over the companion stops shipping private keys

Today `sign_termo_slot_pkcs12` receives the PKCS#12 blob **and its passphrase** in the request body
(`termo.rs:804-822`); the private key crosses to the server. Over the companion, the same digest
primitive is used and **the key never leaves the operator's machine**.

This reframes the work: it is not "add a transport", it is "stop shipping private keys". The
existing upload endpoint remains `local_signing`-only permanently.

## The WYSIWYS gap

**The operator confirms against server-supplied display strings, and the companion cannot verify
that the 32-byte digest corresponds to the document described.**

This is **inherent to digest-only signing**. It is not a defect to be engineered away, and it is the
single point where the honest answer constrains what the signature attests. A future reader
evaluating this design most needs to find this paragraph.

Baseline mitigation: show the document's SHA-256 in the native confirmation dialog so the operator
can compare it against the browser. Possible follow-up: let the companion fetch and render the PDF
**over its own authenticated TLS channel to the server** — never via the page. The mitigation choice
is [AWAITING DECISION](#what-is-decided-and-what-is-still-open).

## Authentication: reuse pairing, invent nothing

`crates/chancela-api/src/pairing.rs` fits, and a second trust establishment is not being invented.
Mint a code from an authenticated session → exchange it with a **confirmed proof**
(`PairingConfirmationMethod::{Password, TotpCode, EmailedCode}`,
`crates/chancela-api/src/confirmation.rs:2229`) → durable device row, digest-only token, listable via
`GET /v1/pairing/devices`, revocable via `DELETE`. The companion enrols as a device with
`kind: "signing_companion"`.

Layered authorisation, all fail-closed:

- Job creation requires the existing `Permission::SigningPerform` on the act's scope.
- A job may be claimed **only** by a companion paired to the **same `user_id`**. Cross-user claim is
  refused.
- The companion cannot commit — enforced by an **explicit check**, per Finding B.
- Before the card is touched, the desktop app shows a **native confirmation**: OS UI a web page
  cannot spoof. That is the deliberate-authorisation gate; the card PIN is the second.

"How does the page know it is talking to the real companion?" does not arise: under rendezvous the
page never talks to the companion at all. That is the main reason this transport was preferred.

### Storage-compatibility hazard when adding the device kind

`DurablePairingDevice` (`pairing.rs:86-102`) is `#[serde(deny_unknown_fields)]`, and
`PairingRegistry::from_store` **skips** a row it cannot deserialize rather than failing loudly. The
failure mode is therefore silent: affected devices vanish from the operator's list, **taking the
ability to revoke them with them**.

This already fired once, on `confirmed_by`, and is pinned by the regression test
`a_device_row_written_before_the_confirmation_still_rehydrates` (`pairing.rs:1560`). A new `kind`
field needs `#[serde(default)]` for the same reason.

**`deny_unknown_fields` is symmetric, and `#[serde(default)]` only covers one direction.** It
protects a *new* binary reading *old* rows. It does nothing for an *old* binary reading *new* rows:
once a companion-capable build writes a `kind` field, a rollback to the previous binary hits an
unknown field, fails to parse, and — through the same silent skip — drops **every** pairing device
written by the new binary, phones included.

This is a deploy-rollback hazard **on the existing pairing feature**, independent of whether the
signing companion ever ships: it is reachable by any future field added to this struct, not just by
`kind`. It has been raised with the lane that owns `pairing.rs` as an issue on shipped code, with two
resolutions and no preference imposed:

1. **Drop `deny_unknown_fields` on this struct** — and pin the rollback direction with a test
   asserting that a row carrying an *extra* field still rehydrates, mirroring the forward-direction
   test already at `pairing.rs:1560`.
2. **Carry the discriminator inside an already-tolerated field** rather than adding a new one, so no
   unknown key is ever written.

**Resolution pending.** Whichever is chosen must be chosen *deliberately*, and if the attribute is
kept the struct's doc comment should say the strictness is intentional on the rollback side —
otherwise the next reader takes it for an oversight and the hazard survives by silence.

This design accommodates either outcome. Option 1 lets the companion add `kind` as an ordinary field
with `#[serde(default)]`. Option 2 means the companion must **not** add a field at all, and instead
encodes its device kind inside an existing tolerated one — a constraint on this design, which is why
it is recorded here rather than only in the other lane's tracker.

## Failure and refusal

Distinct codes, each with its own pt-PT operator copy. None are collapsed into a generic error:

`companion_not_paired`, `companion_offline`, `companion_version_unsupported`, `middleware_absent`,
`card_reader_absent`, `card_absent`, `signature_certificate_absent`, `pin_wrong` (carrying
`SmartcardError::PinTriesLeft`), `pin_blocked`, `operator_cancelled`, `issuer_untrusted`,
`job_expired`, `job_superseded`.

**No failure ever falls back to another signing family.** Hardware unavailable means the operation
is *refused*, never quietly downgraded to PKCS#12 or anything else.

## Discovery

`GET /v1/signature/companion/status` returns `{paired, online, protocol_version, app_version,
device_label, last_seen}`.

Not paired shows an enrolment prompt; paired-but-offline says so plainly. Neither offers a weaker
signing method as a consolation.

## Versioning

A single integer `companion_protocol_version` is sent on every poll. If it falls outside the
server's supported range the job is **refused**, not negotiated down — the page tells the operator to
update the desktop application. Drift is caught on the first poll, **before any card contact**.

## What is decided, and what is still open

**Decided:**

- The companion signs a digest and never receives the document.
- Authentication reuses the existing pairing mechanism.
- The trusted-list gate stays server-side.
- The commit runs under the browser session's attestation key (forced by Finding B), enforced by an
  explicit check.
- No failure falls back to a weaker signing method.
- `local_signing` keeps its current meaning and is not overloaded.
- The name is "signing companion".

**Awaiting the product owner:**

- **Rendezvous over loopback.** The request named the Cartão de Cidadão middleware and the Intel
  updater, and both *are* local-socket architectures. The functional difference is real and is
  theirs to weigh: rendezvous does not prove browser/card co-location. If co-location proof is a
  genuine requirement, that is a different design, and this document records exactly what choosing
  loopback would cost — the CSP concession in [Finding A](#finding-a-a-browser-page-cannot-reach-a-loopback-companion-today).
- **The WYSIWYS mitigation.** Document SHA-256 in the native dialog as the baseline, with in-app PDF
  rendering over the companion's own authenticated channel as a possible follow-up.
