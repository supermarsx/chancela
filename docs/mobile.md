# Mobile companion

> **Scope honesty.** The repository now contains a real Tauri v2 Android project and produces
> an installable, debug-signed arm64 APK. It is not yet a production/store release: release
> signing, Play Console enrollment, and the remote-server CORS/persistent-auth gates below
> remain mandatory. The committed target is therefore buildable and testable, but must not be
> presented as a production remote companion yet.

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
passed through untouched. Example: a companion build for the _Encosto Estratégico Lda_
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
centered, scrolling strip painted _over_ the brand (left) and the notification/session
controls (right), making them overlap and become un-tappable. A `@media (max-width: 640px)`
block now drops the absolute centering and lays the bar out as a normal flex row — the
wordmark hides (the page header already names the section), the tab strip becomes a flex
child that scrolls horizontally between brand and session, and the session controls stay
pinned right. Desktop and the Tauri shell (minimum window 900px) never match this query, so
their centered layout is unchanged.

Signing- and settings-heavy screens are intentionally **out of scope** for the mobile read
companion and were not touched.

## Building the Android target

The generated Gradle project is committed under `apps/desktop/src-tauri/gen/android/`.
The scripts in `apps/desktop/package.json` select the **bare-WebView companion** profile
(no embedded server and no second on-device database):

```
npm run android:init    # tauri android init  — one-time scaffold generation
npm run android:dev     # tauri android dev  --no-default-features
npm run android:build   # arm64 APK + AAB, --no-default-features
npm run android:build:ci # debug arm64 APK used by CI
```

The application has a stable Android update identity (`pt.chancela.desktop`), `minSdk 24`,
`targetSdk 36`, and `compileSdk 37`. It uses AGP 9.3.0, Gradle 9.5.0, Java/Kotlin target 17
for the app module, Android Build Tools 36.0.0, and NDK 28.2.13676358. The direct AndroidX
and Material dependencies are the current stable releases that satisfy this target.

### Toolchain and local evidence

The scaffold and native target were built on Windows with Android Studio JBR 21, Rust 1.97,
Android SDK 37, Build Tools 36.0.0, and NDK 28.2.13676358. The Tauri command completed the
web and arm64 Rust compilation; Windows denied its final symlink creation because Developer
Mode was disabled. Packaging the emitted `.so` through the committed Gradle project then
produced and verified `app-arm64-debug.apk` with this metadata:

```
package: pt.chancela.desktop, versionCode 26001000, versionName 26.1.0
minSdk: 24; targetSdk: 36; compileSdk: 37; native-code: arm64-v8a
APK signature: valid v2 Android debug certificate
```

The normal Linux CI path in `.github/workflows/android.yml` is configured to run the complete
Tauri build without the Windows symlink restriction, check the same APK metadata and signature,
record SHA-256, and upload the APK as a short-lived test artifact. Its first hosted run awaits a
push.

| Prerequisite             | Status here                               | How to satisfy                                                                                                                     |
| ------------------------ | ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| **JDK**                  | Verified with JBR 21; CI uses Temurin 17  | Set `JAVA_HOME` to JDK 17 or newer.                                                                                                |
| **Rust Android target**  | `aarch64-linux-android` verified          | `rustup target add aarch64-linux-android`                                                                                          |
| **Android SDK**          | Platform 37 + Build Tools 36.0.0 verified | Install the exact packages used by CI.                                                                                             |
| **Android NDK**          | 28.2.13676358 verified and pinned         | Set `ANDROID_NDK_HOME` and `NDK_HOME`.                                                                                             |
| **Signing keystore**     | None                                      | Generate a release keystore (`keytool`); wire it into `gen/android` signing config. Keep the keystore + passwords out of the repo. |
| **Play Console account** | None                                      | Required only for store distribution (listing, review).                                                                            |

Notes:

- **iOS is out of reach** entirely — it needs macOS + Xcode.
- The **embedded-server on the phone** path (`--features embedded-server`) is deliberately
  **rejected**: it would cross-compile `chancela-api` + SQLCipher/rusqlite for
  `aarch64-linux-android` (a heavy, fragile NDK link) and, semantically, would make the phone
  a _second standalone instance with its own database_ rather than a companion. The companion
  profile is always `--no-default-features`.
- Gradle caches, generated Tauri settings/source, native `.so` files, local properties,
  keystore properties, and signing keys are ignored; only reviewed source/config is committed.
- Tauri 2.11.5's published Android modules still use the legacy Kotlin/AGP DSL and JVM 8.
  Kotlin 2.4.10 rejects that upstream DSL during script compilation, so the Android build
  retains Kotlin Gradle plugin 2.2.21. The Chancela app module itself is explicitly Java/Kotlin 17. Remove this compatibility boundary when Tauri migrates its published Android modules.

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
revocation, bound to a real sign-in. The `X-Chancela-Session` header _transport_ is already
cross-origin-friendly; the _model behind it_ is the gap. No remote read/approve surface
should be enabled until this lands.

Until both gaps are closed, the client foundation stays default-relative / loopback and does
**not** itself open this exposure — configuring an absolute base URL is an explicit operator
choice, and a production companion must not be pointed at a server that lacks A and B.

## Honest bottom line

The Android build now passes the **buildable companion** milestone, not the production-store
milestone. Landed and verified:
a default-relative, tested base-URL indirection + mobile-detection layer (zero web/desktop
regression), a phone-width responsive fix for the shared tab bar, a real API-36-targeting
Android project, a locally inspected arm64 APK, and a configured Linux CI APK gate (its first
hosted run awaits a push). Still gated: a production upload key/Play App Signing and Play
account; macOS/Xcode for iOS; and, before any remote companion is exposed, the backend CORS +
persistent-auth work packaged above.
