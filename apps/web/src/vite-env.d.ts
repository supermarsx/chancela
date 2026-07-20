/// <reference types="vite/client" />

/** UI build version, inlined at build time from package.json (see vite.config.ts). */
declare const __APP_VERSION__: string;

interface ImportMetaEnv {
  readonly VITE_CHANCELA_API_BASE_URL?: string;
}
