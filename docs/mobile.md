# Mobile companion (foundation)

> **Scope honesty.** Chancela does **not** ship a store-installable mobile app today. What
> exists in-repo is a well-architected *foundation*: the web client can be pointed at a
> remote instance, the read surfaces reflow to phone widths, and the desktop crate is
> already shaped for a Tauri v2 Android target. The steps that turn this into a shippable
> app are **externally gated** (Android toolchain, signing keys, a Play account) and, more
> fundamentally, on **backend companion-readiness** (CORS + real persistent auth) that is
> *design-only* here. This page documents the foundation and every remaining gate exactly.

The companion model is: a phone app that talks to the user's **existing** Chancela instance
(their desktop app or a self-hosted `chancela-server`), reusing the **same web UI** rather
than a second, standalone, on-device database. This is the least-effort, single-UI-codebase
path, justified by the desktop crate already being Tauri-v2-mobile-shaped
(`crate-type = ["staticlib", "cdylib", "rlib"]`, `#[cfg_attr(mobile, tauri::mobile_entry_point)]`,
and `#[cfg(desktop)]`-gated desktop-only plugins in `apps/desktop/src-tauri/src/lib.rs`).

## What is built and verifiable today

### 1. Configurable API base URL (client indirection)

By default every API call in `apps/web/src/api/client.ts` stays **relative** (`/v1/...`,
`/health`), so the browser build, the Vite dev proxy, and the desktop embedded-server
same-origin model are byte-for-byte unchanged. A companion shell (or any cross-origin
deployment) can opt into an absolute base URL through the central resolver in
`apps/web/src/api/baseUrl.ts` (`resolveApiUrl`). Precedence, highest first:

1. `window.__CHANCELA_CONFIG__.apiBaseUrl` — an explicit runtime config object.
2. `window.__CHANCELA_MOBILE_SHELL__.apiBaseUrl` — the mobile shell's injected origin.
3. `import.meta.env.VITE_CHANCELA_API_BASE_URL` — a build-time env override.
4. `''` (relative) — the current, default behaviour.

A trailing slash is trimmed and absolute request paths (already carrying a scheme) are
passed through untouched. Example: a companion build for the *Encosto Estratégico Lda*
instance would inject `apiBaseUrl: "https://records.encosto-estrategico.example"`.

Mobile-runtime detection lives in `apps/web/src/shell/mobileShell.ts` (`isMobileShell`),
mirroring the existing desktop `isTauri()` helper — it recognises a Chancela shell hint,
Capacitor/Cordova, a React-Native WebView, or an iOS message handler.

Both are covered by `apps/web/src/api/baseUrl.test.ts` and
`apps/web/src/shell/mobileShell.test.ts`, and the relative-default regression is guarded in
`apps/web/src/api/client.test.ts`.

### 2. Mobile-responsive read surfaces

The theme (`apps/web/src/theme.css`) already ships ~30 media-query blocks; the dashboard,
lists, and detail surfaces collapse their multi-column grids at existing 520/620/640/700/720
breakpoints and use `minmax(0, 1fr)` / `overflow-wrap: anywhere` throughout so text does not
force horizontal body scroll.

The one genuine, universal phone breakage fixed in this foundation is the **fixed tab bar**
(`.topbar`): its tab group is absolute-centered on wide viewports, and at phone widths that
centered, scrolling strip painted *over* the brand (left) and the notification/session
controls (right), making them overlap and become un-tappable. A `@media (max-width: 640px)`
block now drops the absolute centering and lays the bar out as a normal flex row — the
wordmark hides (the page header already names the section), the tab strip becomes a flex
child that scrolls horizontally between brand and session, and the session controls stay
pinned right. Desktop and the Tauri shell (minimum window 900px) never match this query, so
their centered layout is unchanged.

Signing- and settings-heavy screens are intentionally **out of scope** for the mobile read
companion and were not touched.

## Building an Android target (gated)

The desktop crate is ready to grow an Android target. The remaining work is running
`tauri android init` (once) to generate the Gradle/manifest scaffold under
`apps/desktop/src-tauri/gen/android/`, then building. Three npm scripts wrap this in
`apps/desktop/package.json` — note the `--no-default-features` flag, which selects the
**bare-WebView companion** profile (no embedded server, no on-device database):

```
npm run android:init    # tauri android init  — one-time scaffold generation
npm run android:dev     # tauri android dev  --no-default-features
npm run android:build   # tauri android build --no-default-features
```

These scripts are inert until the toolchain below is present; adding them changed no Rust
code, so the existing desktop host build stays green.

### External prerequisites (not satisfiable in-repo)

`tauri android init` and the APK/AAB build could **not** be run in the current environment.
The exact, verified gaps:

| Prerequisite | Status here | How to satisfy |
| --- | --- | --- |
| **JDK on PATH** | Missing (`java` not found) | Install a JDK 17+; put `java` on PATH; set `JAVA_HOME`. |
| **Rust Android targets** | None installed | `rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android` |
| **Android SDK** | `ANDROID_HOME=C:\android-sdk` set | Present. |
| **Android NDK** | `27.0.12077973` present under `ndk/` | Set `NDK_HOME` to the NDK dir. |
| **Signing keystore** | None | Generate a release keystore (`keytool`); wire it into `gen/android` signing config. Keep the keystore + passwords out of the repo. |
| **Play Console account** | None | Required only for store distribution (listing, review). |

Notes:

- **iOS is out of reach** entirely — it needs macOS + Xcode.
- The **embedded-server on the phone** path (`--features embedded-server`) is deliberately
  **rejected**: it would cross-compile `chancela-api` + SQLCipher/rusqlite for
  `aarch64-linux-android` (a heavy, fragile NDK link) and, semantically, would make the phone
  a *second standalone instance with its own database* rather than a companion. The companion
  profile is always `--no-default-features`.
- When the scaffold is generated, commit `gen/android/**` **path-by-path** (it is large; the
  desktop crate currently has no `.gitignore`) and review it for absolute paths / secrets
  before committing.

## Backend companion-readiness (design-only)

A companion talks to the instance **cross-origin, over the network**. The server today is
built for the desktop's in-process loopback model and is **not yet safe to expose** to a
remote device. Two backend gaps must be closed in a **follow-on work package** — they are
specified here but intentionally **not implemented** in this foundation (the live
`crates/chancela-api/src/lib.rs` is owned by other tracks and is not touched here).

### Gap A — CORS

`grep -i cors` over `crates/` returns nothing: there is **no CORS layer**. The desktop app
never needs one (the WebView is navigated to the loopback origin, so `/v1/*` calls are
same-origin). A remote mobile origin cannot call `/v1/*` cross-origin without it.

**Design:** an opt-in `tower_http::cors::CorsLayer`, scoped to an explicit allow-list of
companion origins read from configuration, wrapped around the `/v1` router. It must default
to **off** (empty allow-list) so the desktop loopback and existing deployments are unchanged,
and it must echo only configured origins (never `*`) because requests carry the
`X-Chancela-Session` credential header. Preflight (`OPTIONS`) must allow the
`X-Chancela-Session` and `Content-Type` request headers.

### Gap B — real persistent auth

Sessions today are **in-memory, reset on server restart, and attribution-only, not access
control** (see the `apps/web/src/api/session.ts` docblock and the 401→clear-token handling in
`client.ts`). That is fine for a co-located desktop; it is **not acceptable** to expose
read/approve endpoints to a remote device on this model.

**Design:** replace/augment the in-memory attribution session with a **persisted,
credentialed** session/token model — durable server-side token records with expiry and
revocation, bound to a real sign-in. The `X-Chancela-Session` header *transport* is already
cross-origin-friendly; the *model behind it* is the gap. No remote read/approve surface
should be enabled until this lands.

Until both gaps are closed, the client foundation stays default-relative / loopback and does
**not** itself open this exposure — configuring an absolute base URL is an explicit operator
choice, and a production companion must not be pointed at a server that lacks A and B.

## Honest bottom line

This foundation reaches the **starting line**, not a shippable app. Landed and verified:
a default-relative, tested base-URL indirection + mobile-detection layer (zero web/desktop
regression), a phone-width responsive fix for the shared tab bar, and Android build scripts
on the already-mobile-shaped desktop crate. Still gated, in order: the Android toolchain
(JDK + Rust targets), a signing keystore, a Play account, macOS for iOS — and, before any
remote companion is safe to expose, the backend CORS + real-auth work packaged above.
Prod-ready mobile is several gated steps beyond this foundation.
