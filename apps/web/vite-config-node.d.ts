/**
 * The sliver of the Node runtime `vite.config.ts` uses, declared here rather than pulled in as a
 * dependency.
 *
 * This workspace has no `@types/node` — nothing in `src/` may touch Node, and the build config was
 * the only file that could, so the dependency was never worth carrying. `vite.config.ts` now reads
 * the build commit (see its BUILD PROVENANCE block), which needs exactly two things from Node: a
 * synchronous child process and `process.env`. Declaring those two by hand keeps `npm run
 * typecheck` honest without adding a package to the lockfile or widening what the app can import.
 *
 * These declarations are deliberately NARROW — the single `execFileSync` shape the config calls,
 * not the real overload set. Widen them only when the config genuinely needs more.
 *
 * Scoped to `tsconfig.node.json` (whose `include` names this file). `tsconfig.app.json` includes
 * only `src`, so nothing under it can see these globals: `src/vite-env.d.ts` still owns the app's
 * ambient surface, and an accidental `process.env` in a component is still a type error.
 */

declare module 'node:child_process' {
  /** `encoding: 'utf8'` is the only form the config uses, so the return type is plainly `string`. */
  export function execFileSync(
    file: string,
    args: readonly string[],
    options: {
      encoding: 'utf8';
      /** `['ignore', 'pipe', 'ignore']` — stdout captured, stderr discarded, no stdin. */
      stdio?: readonly ('ignore' | 'pipe' | 'inherit')[];
      /** Milliseconds before the child is killed; a hung `git` must not hang the build. */
      timeout?: number;
    },
  ): string;
}

declare const process: {
  readonly env: Readonly<Record<string, string | undefined>>;
};
