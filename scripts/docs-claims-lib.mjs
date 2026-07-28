// Shared parsing primitives for `check-docs-claims.mjs`.
//
// Every function here is written to FAIL LOUDLY. A construct the lexer does not understand
// throws; it is never skipped. A gate that silently drops what it cannot parse reports green
// over its own blind spot, which is the exact failure this check exists to prevent.

import { readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "coverage", ".orchestration"]);

/**
 * Build outputs are skipped by name AND by prefix. Peers in this repo run cargo against
 * per-agent target directories (`target-t58-e1/`, …), and those churn continuously: a walk
 * that descends into one races a live compiler and dies on a `.rcgu.o` that existed at
 * `readdir` time and was gone by `stat`. That crash surfaced as a bare ENOENT and exit 1 —
 * indistinguishable from a real finding, which is the "green/red over nothing" failure this
 * whole check exists to prevent. Nothing under a build output is ever an input here.
 */
function isSkippedDir(name) {
  return SKIP_DIRS.has(name) || name === "target" || name.startsWith("target-");
}

/**
 * Recursively collect files under `dir` matching `filter`, in a stable sorted order.
 *
 * Uses `withFileTypes` so directory classification comes from the single `readdir` syscall
 * rather than a second `stat` per entry — no window in which an entry can vanish between the
 * two. A directory that disappears wholesale mid-walk still throws, which is correct: that is
 * a tree being rewritten underneath the check, not something to paper over.
 */
export function walk(dir, filter, out = []) {
  const entries = readdirSync(dir, { withFileTypes: true });
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (isSkippedDir(entry.name)) continue;
      walk(path, filter, out);
    } else if (entry.isFile() && filter(path)) {
      out.push(path);
    }
  }
  return out;
}

/** Files directly inside `dir` matching `filter`. No recursion, so no build-output exposure. */
export function listDir(dir, filter) {
  return readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && filter(join(dir, entry.name)))
    .map((entry) => join(dir, entry.name))
    .sort();
}

/** Repo-relative path with forward slashes, so registry entries are platform-independent. */
export function repoPath(repoRoot, file) {
  return relative(repoRoot, file).split(sep).join("/");
}

/** 1-based line number of a byte offset. */
export function lineOf(source, offset) {
  let line = 1;
  for (let i = 0; i < offset && i < source.length; i += 1) {
    if (source[i] === "\n") line += 1;
  }
  return line;
}

// --- Rust ----------------------------------------------------------------------------------

/**
 * Produce a structural mask of Rust source: identical length to the input, with comments and
 * string *contents* replaced by spaces while delimiters are preserved. Brace matching and
 * pattern scanning run against the mask so that a `{` inside a comment or string literal can
 * never move an item boundary. Literal values are returned separately with their offsets.
 *
 * Throws on an unterminated comment or string rather than guessing.
 */
export function maskRust(source, file) {
  const mask = new Array(source.length);
  const literals = [];
  const blank = (from, to) => {
    for (let k = from; k < to; k += 1) mask[k] = " ";
  };
  const keep = (from, to) => {
    for (let k = from; k < to; k += 1) mask[k] = source[k];
  };

  let i = 0;
  const n = source.length;
  while (i < n) {
    const c = source[i];

    if (c === "/" && source[i + 1] === "/") {
      let j = i;
      while (j < n && source[j] !== "\n") j += 1;
      blank(i, j);
      i = j;
      continue;
    }

    if (c === "/" && source[i + 1] === "*") {
      let depth = 1;
      let j = i + 2;
      while (j < n && depth > 0) {
        if (source[j] === "/" && source[j + 1] === "*") {
          depth += 1;
          j += 2;
        } else if (source[j] === "*" && source[j + 1] === "/") {
          depth -= 1;
          j += 2;
        } else {
          j += 1;
        }
      }
      if (depth !== 0) {
        throw new Error(`${file}: unterminated block comment at offset ${i}`);
      }
      blank(i, j);
      i = j;
      continue;
    }

    // Raw strings: r"…", r#"…"#, br#"…"#. Only when not part of a longer identifier.
    const prev = source[i - 1] ?? " ";
    if ((c === "r" || c === "b") && !/[A-Za-z0-9_]/.test(prev)) {
      const rawMatch = /^(b?r)(#*)"/.exec(source.slice(i, i + 40));
      if (rawMatch) {
        const hashes = rawMatch[2];
        const openLength = rawMatch[1].length + hashes.length + 1;
        const close = `"${hashes}`;
        const end = source.indexOf(close, i + openLength);
        if (end === -1) {
          throw new Error(`${file}: unterminated raw string at offset ${i}`);
        }
        literals.push({ start: i, value: source.slice(i + openLength, end) });
        keep(i, i + openLength);
        blank(i + openLength, end);
        keep(end, end + close.length);
        i = end + close.length;
        continue;
      }
    }

    if (c === '"' || (c === "b" && source[i + 1] === '"')) {
      const start = c === "b" ? i + 2 : i + 1;
      let j = start;
      let value = "";
      while (j < n) {
        if (source[j] === "\\") {
          value += source[j + 1];
          j += 2;
          continue;
        }
        if (source[j] === '"') break;
        value += source[j];
        j += 1;
      }
      if (j >= n) {
        throw new Error(`${file}: unterminated string literal at offset ${i}`);
      }
      literals.push({ start: i, value });
      keep(i, start);
      blank(start, j);
      keep(j, j + 1);
      i = j + 1;
      continue;
    }

    if (c === "'") {
      // Char literal or lifetime. Both are structurally inert; keep them verbatim.
      if (source[i + 1] === "\\") {
        const end = source.indexOf("'", i + 2);
        if (end === -1) {
          throw new Error(`${file}: unterminated char literal at offset ${i}`);
        }
        keep(i, end + 1);
        i = end + 1;
        continue;
      }
      if (source[i + 2] === "'") {
        keep(i, i + 3);
        i += 3;
        continue;
      }
      keep(i, i + 1);
      i += 1;
      continue;
    }

    keep(i, i + 1);
    i += 1;
  }

  return { mask: mask.join(""), literals };
}

/**
 * Offsets of `#[cfg(test)]`-gated items, as [start, end) ranges over the mask.
 *
 * This codebase interleaves test modules with production code, so proximity is never a proxy
 * for test-ness — the item that follows each attribute is brace-matched exactly.
 */
export function cfgTestRanges(mask, file) {
  const ranges = [];
  const pattern = /#\[cfg\(test\)\]/g;
  let match;
  while ((match = pattern.exec(mask)) !== null) {
    let i = match.index + match[0].length;
    let depth = 0;
    let opened = false;
    let closed = false;
    while (i < mask.length) {
      const c = mask[i];
      if (c === "{") {
        depth += 1;
        opened = true;
      } else if (c === "}") {
        depth -= 1;
        if (opened && depth === 0) {
          i += 1;
          closed = true;
          break;
        }
      } else if (c === ";" && !opened) {
        i += 1;
        closed = true;
        break;
      }
      i += 1;
    }
    if (!closed) {
      throw new Error(
        `${file}: #[cfg(test)] at offset ${match.index} has no brace- or semicolon-terminated item`,
      );
    }
    ranges.push([match.index, i]);
  }
  return ranges;
}

export function inRanges(offset, ranges) {
  return ranges.some(([from, to]) => offset >= from && offset < to);
}

/** serde `rename_all` cases. An unrecognised case is an error, never a silent pass-through. */
export const SERDE_CASES = {
  lowercase: (v) => v.toLowerCase(),
  UPPERCASE: (v) => v.toUpperCase(),
  PascalCase: (v) => v,
  camelCase: (v) => v.charAt(0).toLowerCase() + v.slice(1),
  snake_case: toSnake,
  SCREAMING_SNAKE_CASE: (v) => toSnake(v).toUpperCase(),
  "kebab-case": (v) => toSnake(v).replace(/_/gu, "-"),
  "SCREAMING-KEBAB-CASE": (v) => toSnake(v).replace(/_/gu, "-").toUpperCase(),
};

function toSnake(value) {
  return value
    .replace(/([a-z0-9])([A-Z])/gu, "$1_$2")
    .replace(/([A-Z])([A-Z][a-z])/gu, "$1_$2")
    .toLowerCase();
}

/**
 * Split an item body (struct or enum) into its top-level members, at depth-0 commas.
 *
 * Rust separates struct fields and enum variants with commas, not `;` or `}`. An attribute
 * window that looks back to the previous `}`/`;` therefore reaches *across* sibling members and
 * can attribute one member's `#[serde(rename = "…")]` to the next one — silently moving a wire
 * name. Splitting the body first makes each member's attribute set exact.
 *
 * Angle brackets are tracked so `HashMap<String, u32>` is one field rather than two; `<<`, `>>`
 * and `->` are stepped over so a shift in a discriminant cannot unbalance the depth.
 *
 * Returns [start, end) ranges over `bodyMask`, one per non-empty member.
 */
export function splitMembers(bodyMask) {
  const parts = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < bodyMask.length; i += 1) {
    const c = bodyMask[i];
    const next = bodyMask[i + 1];
    if ((c === "<" && next === "<") || (c === ">" && next === ">")) {
      i += 1;
      continue;
    }
    if (c === "-" && next === ">") {
      i += 1;
      continue;
    }
    if (c === "{" || c === "(" || c === "[" || c === "<") depth += 1;
    else if (c === "}" || c === ")" || c === "]" || c === ">") depth = Math.max(0, depth - 1);
    else if (c === "," && depth === 0) {
      if (bodyMask.slice(start, i).trim().length > 0) parts.push([start, i]);
      start = i + 1;
    }
  }
  if (bodyMask.slice(start).trim().length > 0) parts.push([start, bodyMask.length]);
  return parts;
}

/** Blank `#[…]` attribute spans in a masked member chunk, preserving length so offsets hold. */
export function withoutAttributes(chunk) {
  return chunk.replace(/#\[[^\]]*\]/gu, (a) => " ".repeat(a.length));
}

/** The serde wire name for a member: per-member `rename` wins, else the item's `rename_all`. */
export function wireName(rawName, memberAttributes, renameAll) {
  const rename = /#\[serde\([^\]]*\brename\s*=\s*"([^"]+)"/u.exec(memberAttributes);
  if (rename) return rename[1];
  return renameAll ? renameAll(rawName) : rawName;
}

/**
 * The attribute block immediately preceding `offset`, read from the original source so that
 * attribute string arguments (masked out in the structural view) remain readable.
 */
export function precedingAttributes(source, mask, offset) {
  const from = Math.max(0, offset - 2000);
  const windowMask = mask.slice(from, offset);
  // An item boundary is the last `}` or `;` before the item's own attributes begin.
  const boundary = Math.max(windowMask.lastIndexOf("}"), windowMask.lastIndexOf(";"));
  return source.slice(from + boundary + 1, offset);
}

/** Brace-matched body of a block whose opening `{` is at `openOffset` in `mask`. */
export function braceBody(mask, openOffset, file) {
  let depth = 0;
  let i = openOffset;
  while (i < mask.length) {
    if (mask[i] === "{") depth += 1;
    else if (mask[i] === "}") {
      depth -= 1;
      if (depth === 0) return { start: openOffset + 1, end: i };
    }
    i += 1;
  }
  throw new Error(`${file}: unbalanced braces starting at offset ${openOffset}`);
}

// --- TypeScript ----------------------------------------------------------------------------

/**
 * Structural mask of TypeScript source: comments and string contents blanked, delimiters kept.
 * Prevents `as const` inside a comment or a Portuguese sentence ("As propostas constantes…")
 * from being read as a declaration.
 */
export function maskTs(source, file) {
  return maskTsInner(source, file, true);
}

/**
 * Comments blanked, string contents preserved. Used to read declared values out of a range
 * that `maskTs` located, without a comment inside the array contributing stray quotes.
 */
export function maskTsComments(source, file) {
  return maskTsInner(source, file, false);
}

function maskTsInner(source, file, blankStrings) {
  const mask = source.split("");
  let i = 0;
  const n = source.length;
  while (i < n) {
    const c = source[i];
    if (c === "/" && source[i + 1] === "/") {
      let j = i;
      while (j < n && source[j] !== "\n") {
        mask[j] = " ";
        j += 1;
      }
      i = j;
      continue;
    }
    if (c === "/" && source[i + 1] === "*") {
      const end = source.indexOf("*/", i + 2);
      if (end === -1) {
        throw new Error(`${file}: unterminated block comment at offset ${i}`);
      }
      for (let k = i; k < end + 2; k += 1) mask[k] = " ";
      i = end + 2;
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      let j = i + 1;
      while (j < n) {
        if (source[j] === "\\") {
          j += 2;
          continue;
        }
        if (source[j] === c) break;
        j += 1;
      }
      if (j >= n) {
        throw new Error(`${file}: unterminated string literal at offset ${i}`);
      }
      if (blankStrings) {
        for (let k = i + 1; k < j; k += 1) mask[k] = " ";
      }
      i = j + 1;
      continue;
    }
    i += 1;
  }
  return mask.join("");
}
