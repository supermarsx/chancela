/// <reference types="vite/client" />

/** UI build version, inlined at build time from package.json (see vite.config.ts). */
declare const __APP_VERSION__: string;

/**
 * The commit this bundle was built from, inlined at build time (see the BUILD PROVENANCE block in
 * vite.config.ts). `null` whenever the build had no repository to read — a Docker image build, a
 * source tarball, a machine without git — which is a normal outcome, not an error.
 *
 * Raw and unvalidated on purpose: `features/settings/buildProvenance.ts` is the only thing that
 * reads it, and it checks the shape before anything reaches the screen. Never used for the
 * version-skew comparison; that stays on `__APP_VERSION__`.
 */
declare const __BUILD_COMMIT__: { hash: string; committedAt: string } | null;

interface ImportMetaEnv {
  readonly VITE_CHANCELA_API_BASE_URL?: string;
}
