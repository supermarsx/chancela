#!/usr/bin/env node
//
// check-docs-claims.mjs — docs-to-code parity gates (t61 §3.3).
//
// Two mechanisable gates over the documentation corpus and the web wire contract:
//
//   Gate 1  IDENTIFIER EXISTENCE   an identifier named in docs must exist in code.
//   Gate 2  EMITTABLE-LITERAL      a literal docs (or the web contract) say the system emits
//                                  must actually be emittable by the backend.
//
// The behavioural half of the same problem — "does the documented *effect* happen?" — is not
// mechanisable and deliberately lives in `docs/signing-trust-claims.md` instead. See that file
// and the "cannot catch" notes below; an honest partial mechanism beats an over-promised one.
//
// NON-NEGOTIABLES (t61 §3.4)
//   * Unparseable input is a HARD ERROR, never a skip. A gate that silently skips what it does
//     not understand reports green over its own blind spot.
//   * Irregular cases go on an explicit registry entry with a written reason. Loosening a
//     matcher to make a stubborn case pass converts a real guard into a decorative one.
//   * Every registry entry is EXERCISED: an entry that no longer matches anything fails, so the
//     registry cannot rot into a rubber stamp.
//
// Usage:  node scripts/check-docs-claims.mjs [--json]
//         node scripts/check-docs-claims.mjs --self-test   (prove the gate still goes red)
// Exit:   0 clean, 1 findings, 2 parse failure / registry rot / self-test failure.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  SERDE_CASES,
  braceBody,
  cfgTestRanges,
  inRanges,
  lineOf,
  listDir,
  maskRust,
  maskTs,
  maskTsComments,
  precedingAttributes,
  repoPath,
  splitMembers,
  walk,
  wireName,
  withoutAttributes,
} from "./docs-claims-lib.mjs";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const jsonOutput = process.argv.includes("--json");
const selfTestMode = process.argv.includes("--self-test");

const SETTINGS_RS = join(repoRoot, "crates", "chancela-api", "src", "settings.rs");
const PERMISSION_RS = join(repoRoot, "crates", "chancela-authz", "src", "permission.rs");
const WEB_TYPES_TS = join(repoRoot, "apps", "web", "src", "api", "types.ts");
const REGISTRY_JSON = join(repoRoot, "scripts", "docs-claims-registry.json");

const findings = [];
const registryHits = new Map();

function finding(gate, location, message) {
  findings.push({ gate, location, message });
}

function hit(key) {
  registryHits.set(key, (registryHits.get(key) ?? 0) + 1);
}

function fatal(message) {
  console.error(`check-docs-claims: PARSE FAILURE — ${message}`);
  console.error("  This is a hard error by design. The gate does not skip what it cannot parse.");
  process.exit(2);
}

// =============================================================================================
// Registry
// =============================================================================================

const registry = JSON.parse(readFileSync(REGISTRY_JSON, "utf8"));

for (const [section, entries] of Object.entries(registry)) {
  if (section.startsWith("_")) continue;
  if (!Array.isArray(entries)) fatal(`registry section ${section} is not an array`);
  for (const entry of entries) {
    if (typeof entry.reason !== "string" || entry.reason.trim().length < 20) {
      fatal(`registry entry in ${section} has no substantive written reason: ${JSON.stringify(entry)}`);
    }
  }
}

const identifierAllowlist = new Map(
  registry.identifierAllowlist.map((e) => [e.identifier, e]),
);
const unionAllowlist = new Map(registry.unionAllowlist.map((e) => [e.union, e]));
const memberAllowlist = new Map(
  registry.memberAllowlist.map((e) => [`${e.union}::${e.value}`, e]),
);
const keyUnions = new Map(registry.keyUnions.map((e) => [e.union, e]));
const asConstNonUnion = new Map(registry.asConstNonUnionSites.map((e) => [e.name, e]));
const knownDefects = new Map(registry.knownDefects.map((e) => [e.key, e]));
const statusWatchlist = registry.statusWatchlist.map((e) => e.value);
const quotedLiterals = new Map(
  registry.quotedLiteralExemptions.map((e) => [`${e.file}::${e.value}`, e]),
);

// =============================================================================================
// Model 1 — the settings document, parsed from settings.rs
// =============================================================================================

// A settings section may be typed with a struct that lives in a SIBLING MODULE
// (`pub device_pairing: crate::confirmation::PairingConfirmationSettings`). Parsing settings.rs
// alone left that type unresolvable, so `structOf` treated the field as a leaf and every path
// *beneath* it was reported as a phantom setting while the setting was real and shipped. The model
// therefore follows `crate::<module>::<Struct>` into the module that declares it.
//
// This can only ever ADD resolution, never suppress a finding the gate got right: an unfollowed
// reference makes real paths unresolvable (a false RED), never a phantom one resolvable.
//
// CANNOT FOLLOW: a type qualified into another crate (`chancela_authz::RoleId`). Those are leaves
// today and paths beneath one would be reported — the fail-closed direction, not a false green.
const CRATE_QUALIFIED = /^crate::([a-z_][a-z0-9_]*)::([A-Za-z0-9_]+)$/u;

/** Strip `Option<…>`/`Box<…>` wrappers down to the named type. */
function unwrapType(type) {
  let inner = type.trim();
  for (;;) {
    const wrapper = /^(?:Option|Box)\s*<\s*([\s\S]+)\s*>$/u.exec(inner);
    if (!wrapper) return inner;
    inner = wrapper[1].trim();
  }
}

function buildSettingsModel() {
  const structs = new Map();
  const declaredIn = new Map();
  const parsed = new Set();
  const queue = [SETTINGS_RS];

  while (queue.length > 0) {
    const file = queue.shift();
    if (parsed.has(file)) continue;
    parsed.add(file);
    for (const [name, fields] of parseSettingsStructs(file)) {
      const prior = declaredIn.get(name);
      if (prior !== undefined && prior !== file) {
        fatal(
          `struct \`${name}\` is declared in both ${repoPath(repoRoot, prior)} and ` +
            `${repoPath(repoRoot, file)}. The settings model keys structs by bare name and cannot ` +
            "tell them apart; disambiguate rather than letting one silently win.",
        );
      }
      declaredIn.set(name, file);
      structs.set(name, fields);
      for (const type of fields.values()) {
        const qualified = CRATE_QUALIFIED.exec(unwrapType(type));
        if (!qualified) continue;
        const module = join(repoRoot, "crates", "chancela-api", "src", `${qualified[1]}.rs`);
        if (!existsSync(module)) {
          fatal(
            `settings type \`${unwrapType(type)}\` names module \`${qualified[1]}\`, but ` +
              `${repoPath(repoRoot, module)} does not exist. The settings model would silently ` +
              "treat the field as a leaf — find the module rather than leaving the blind spot.",
          );
        }
        queue.push(module);
      }
    }
  }

  if (!structs.has("Settings")) {
    fatal("settings.rs: root `Settings` struct not found — the settings model is unusable");
  }
  return structs;
}

function parseSettingsStructs(file) {
  const source = readFileSync(file, "utf8");
  const { mask } = maskRust(source, file);
  const skip = cfgTestRanges(mask, file);

  const structs = new Map();
  const pattern = /\bstruct\s+([A-Za-z0-9_]+)\s*(?:<[^{;]*>)?\s*\{/gu;
  let match;
  while ((match = pattern.exec(mask)) !== null) {
    if (inRanges(match.index, skip)) continue;
    const name = match[1];
    const open = match.index + match[0].length - 1;
    const { start, end } = braceBody(mask, open, file);
    const bodyMask = mask.slice(start, end);
    const bodySource = source.slice(start, end);

    const attributes = precedingAttributes(source, mask, match.index);
    const renameAll = /#\[serde\([^\]]*rename_all\s*=\s*"([^"]+)"/u.exec(attributes);
    let transform = (v) => v;
    if (renameAll) {
      const fn = SERDE_CASES[renameAll[1]];
      if (!fn) {
        fatal(
          `${repoPath(repoRoot, file)}: struct ${name} uses unknown ` +
            `serde rename_all="${renameAll[1]}"`,
        );
      }
      // Field names in this file are already snake_case; a rename_all that changes them would
      // silently move every documented path, so surface it rather than assume it is harmless.
      transform = fn;
    }

    const fields = new Map();
    const fieldPattern = /(^|\n)([ \t]*)pub\s+([a-z_][a-z0-9_]*)\s*:\s*/gu;
    let fieldMatch;
    while ((fieldMatch = fieldPattern.exec(bodyMask)) !== null) {
      const rawName = fieldMatch[3];
      const typeStart = fieldMatch.index + fieldMatch[0].length;
      const type = readFieldType(bodyMask, typeStart, name, rawName, file);
      const fieldAttrs = precedingAttributes(
        bodySource,
        bodyMask,
        fieldMatch.index + fieldMatch[1].length,
      );
      const rename = /#\[serde\([^\]]*\brename\s*=\s*"([^"]+)"/u.exec(fieldAttrs);
      const wire = rename ? rename[1] : transform(rawName);
      fields.set(wire, type);
    }
    structs.set(name, fields);
  }
  return structs;
}

/** Read a field's type text, stopping at the `,` that terminates it at angle/paren depth 0. */
function readFieldType(bodyMask, start, structName, fieldName, file) {
  let depth = 0;
  for (let i = start; i < bodyMask.length; i += 1) {
    const c = bodyMask[i];
    if (c === "<" || c === "(" || c === "[") depth += 1;
    else if (c === ">" || c === ")" || c === "]") depth -= 1;
    else if ((c === "," || c === "\n") && depth === 0) {
      const text = bodyMask.slice(start, i).trim();
      if (text.length > 0) return text;
    }
  }
  fatal(
    `${repoPath(repoRoot, file)}: cannot determine the type of ${structName}.${fieldName}`,
  );
  return "";
}

/**
 * Unwrap `Option<T>`/`Box<T>` and any `crate::<module>::` qualification to the inner struct name,
 * or null when the field is a leaf. Dropping the qualification is safe because
 * `buildSettingsModel` fails hard on two reachable structs sharing a bare name.
 */
function structOf(type, structs) {
  const inner = unwrapType(type);
  const qualified = CRATE_QUALIFIED.exec(inner);
  const name = qualified ? qualified[2] : inner;
  return structs.has(name) ? name : null;
}

function resolveSettingsPath(segments, structs) {
  let current = "Settings";
  for (let i = 0; i < segments.length; i += 1) {
    const fields = structs.get(current);
    if (!fields || !fields.has(segments[i])) return false;
    if (i === segments.length - 1) return true;
    const next = structOf(fields.get(segments[i]), structs);
    if (!next) return false;
    current = next;
  }
  return false;
}

// =============================================================================================
// Model 2 — the permission catalog
// =============================================================================================

function buildPermissionCatalog() {
  const source = readFileSync(PERMISSION_RS, "utf8");
  const { mask } = maskRust(source, PERMISSION_RS);
  const skip = cfgTestRanges(mask, PERMISSION_RS);

  const declared = /pub const ALL:\s*\[\s*Permission\s*;\s*(\d+)\s*\]/u.exec(mask);
  if (!declared) {
    fatal("permission.rs: `Permission::ALL` array declaration not found");
  }
  const expected = Number(declared[1]);

  const ids = new Map();
  const variants = new Set();
  const pattern = /Permission::([A-Za-z0-9_]+)\s*=>\s*"/gu;
  let match;
  while ((match = pattern.exec(source)) !== null) {
    if (inRanges(match.index, skip)) continue;
    const literalStart = match.index + match[0].length;
    const literalEnd = source.indexOf('"', literalStart);
    if (literalEnd === -1) {
      fatal(`permission.rs: unterminated dotted id for Permission::${match[1]}`);
    }
    const id = source.slice(literalStart, literalEnd);
    if (!/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/u.test(id)) {
      fatal(`permission.rs: Permission::${match[1]} maps to a non-dotted id "${id}"`);
    }
    ids.set(id, match[1]);
    variants.add(match[1]);
  }

  // Parse-integrity check: the catalog size is declared independently of the id mapping, so a
  // matcher that quietly stops early cannot pass unnoticed.
  if (ids.size !== expected) {
    fatal(
      `permission.rs: parsed ${ids.size} dotted ids but Permission::ALL declares ${expected}. ` +
        "The matcher is out of step with the catalog; fix the matcher, do not relax the check.",
    );
  }
  return { ids, variants };
}

// =============================================================================================
// Model 3 — the Rust wire vocabulary (what the backend can actually emit)
// =============================================================================================
//
// Two vocabularies, deliberately NOT one. A JSON *key* and a JSON *value* are different things,
// and conflating them is how this gate would manufacture green:
//
//   emittable VALUES  — what can appear on the right-hand side of a JSON pair:
//                         * a string literal in production code,
//                         * a serde enum variant's actual WIRE name — per-variant
//                           `#[serde(rename)]` if present, else the enum's `rename_all`, else
//                           the raw name. The raw PascalCase name of a `rename_all`-renamed
//                           enum is NOT emittable and is not admitted.
//   struct FIELDS     — JSON keys, indexed per struct. A field name can never justify a status
//                       value, so it is kept out of the value vocabulary entirely and consulted
//                       only for unions explicitly declared to be key vocabularies (`keyUnions`).
//
// Measured on this tree: folding field names into the value vocabulary added 3509 names and
// justified exactly ONE union member — which turned out to be a genuine key vocabulary, now
// modelled properly. The other 2801 names were pure false-green surface.
//
// `#[cfg(test)]` items and every `crates/*/tests/` file are excluded, so a literal that only a
// test writes does not count as emittable. That exclusion is what makes the known instance
// (`rascunho`, emitted by no production path) visible.

function buildRustVocabulary() {
  const files = walk(
    join(repoRoot, "crates"),
    (p) => p.endsWith(".rs") && repoPath(repoRoot, p).includes("/src/"),
  );
  if (files.length === 0) fatal("no production Rust sources found under crates/*/src");

  const emittable = new Set();
  const structFields = new Map();
  const stats = { files: files.length, literals: 0, variants: 0, fields: 0 };

  for (const file of files) {
    const source = readFileSync(file, "utf8");
    let masked;
    try {
      masked = maskRust(source, file);
    } catch (error) {
      fatal(error.message);
    }
    const { mask, literals } = masked;
    const skip = cfgTestRanges(mask, file);

    for (const literal of literals) {
      if (inRanges(literal.start, skip)) continue;
      emittable.add(literal.value);
      stats.literals += 1;
    }

    collectEnumVariants(source, mask, skip, file, emittable, stats);
    collectStructFields(source, mask, skip, file, structFields, stats);
  }

  return { emittable, structFields, stats };
}

/** The `rename_all` transform declared on an item, or null. An unknown case is a hard error. */
function renameAllOf(source, mask, offset, file, what) {
  const attributes = precedingAttributes(source, mask, offset);
  const declared = /#\[serde\([^\]]*rename_all\s*=\s*"([^"]+)"/u.exec(attributes);
  if (!declared) return null;
  const fn = SERDE_CASES[declared[1]];
  if (!fn) fatal(`${file}: unknown serde rename_all="${declared[1]}" on ${what}`);
  return fn;
}

/** Locate `kind` items, yielding {name, bodyMask, bodySource, renameAll} for each. */
function* items(source, mask, skip, file, kind) {
  const pattern = new RegExp(`\\b${kind}\\s+([A-Za-z0-9_]+)\\s*(?:<[^{;]*>)?\\s*\\{`, "gu");
  let match;
  while ((match = pattern.exec(mask)) !== null) {
    if (inRanges(match.index, skip)) continue;
    const open = match.index + match[0].length - 1;
    let body;
    try {
      body = braceBody(mask, open, file);
    } catch (error) {
      fatal(error.message);
    }
    yield {
      name: match[1],
      bodyMask: mask.slice(body.start, body.end),
      bodySource: source.slice(body.start, body.end),
      renameAll: renameAllOf(source, mask, match.index, file, `${kind} ${match[1]}`),
    };
  }
}

function collectEnumVariants(source, mask, skip, file, emittable, stats) {
  for (const item of items(source, mask, skip, file, "enum")) {
    for (const [from, to] of splitMembers(item.bodyMask)) {
      const chunk = withoutAttributes(item.bodyMask.slice(from, to));
      const named = /^\s*([A-Z][A-Za-z0-9_]*)/u.exec(chunk);
      if (!named) {
        // Fail loudly. A variant this splitter cannot name is a hole in the value vocabulary,
        // and a hole in the value vocabulary is a FALSE RED waiting to be "fixed" by loosening.
        fatal(
          `${file}: enum ${item.name} has a member this parser cannot name: ` +
            `${JSON.stringify(item.bodyMask.slice(from, to).trim().slice(0, 120))}`,
        );
      }
      emittable.add(wireName(named[1], item.bodySource.slice(from, to), item.renameAll));
      stats.variants += 1;
    }
  }
}

function collectStructFields(source, mask, skip, file, structFields, stats) {
  for (const item of items(source, mask, skip, file, "struct")) {
    const fields = structFields.get(item.name) ?? new Set();
    for (const [from, to] of splitMembers(item.bodyMask)) {
      const chunk = withoutAttributes(item.bodyMask.slice(from, to));
      const named = /^\s*(?:pub(?:\s*\([^)]*\))?\s+)?([a-z_][a-z0-9_]*)\s*:/u.exec(chunk);
      // A tuple struct's members are positional and have no names; that is not a parse failure.
      if (!named) continue;
      fields.add(wireName(named[1], item.bodySource.slice(from, to), item.renameAll));
      stats.fields += 1;
    }
    structFields.set(item.name, fields);
  }
}

// =============================================================================================
// Model 4 — the web wire contract (`as const` unions in types.ts)
// =============================================================================================

function buildWebUnions() {
  const source = readFileSync(WEB_TYPES_TS, "utf8");
  let structural;
  let commentStripped;
  try {
    structural = maskTs(source, WEB_TYPES_TS);
    commentStripped = maskTsComments(source, WEB_TYPES_TS);
  } catch (error) {
    fatal(error.message);
  }

  const unions = [];
  const claimed = [];
  // Declarations are matched structurally (delimiter-balanced), never with a lazy `[\s\S]*?`
  // spanning the file: a 10k-line module makes that quadratic, and a check that times out is a
  // check nobody runs.
  const declaration = /export const ([A-Z][A-Z0-9_]*)\s*=\s*([[{])/gu;
  let match;
  while ((match = declaration.exec(structural)) !== null) {
    const open = match.index + match[0].length - 1;
    const isArray = match[2] === "[";
    const close = matchDelimiter(structural, open, isArray ? "[" : "{", isArray ? "]" : "}");
    if (close === -1) {
      fatal(`types.ts:${lineOf(source, match.index)}: unbalanced ${match[2]} in ${match[1]}`);
    }
    const tail = structural.slice(close + 1, close + 12);
    if (!/^\s*as const;/u.test(tail)) continue; // not a frozen contract declaration
    const body = commentStripped.slice(open + 1, close);
    const values = isArray
      ? [...body.matchAll(/'([^'\n]*)'/gu)].map((v) => v[1])
      : [...body.matchAll(/:\s*'([^'\n]*)'/gu)].map((v) => v[1]);
    if (values.length === 0) {
      fatal(`types.ts:${lineOf(source, match.index)}: ${match[1]} parsed to zero string values`);
    }
    // Object-literal `as const` records (e.g. RESET_PHRASE) are wire contracts too: their values
    // are strings the server produces or enforces byte-exact. Covered by the same parity rule
    // rather than exempted, because exempting them would drop real coverage.
    unions.push({
      name: match[1],
      kind: isArray ? "union" : "record",
      values,
      line: lineOf(source, match.index),
    });
    claimed.push([match.index, close + 1 + tail.indexOf(";") + 1]);
  }

  // Parse-integrity check: every `as const` site must be accounted for. An `as const` the union
  // matcher did not consume is either a union it failed to parse (a blind spot) or a
  // deliberately non-union declaration that must be registered by name with a reason.
  for (const site of structural.matchAll(/as const/gu)) {
    if (claimed.some(([from, to]) => site.index >= from && site.index < to)) continue;
    const before = structural.slice(Math.max(0, site.index - 4000), site.index);
    const decl = /export const ([A-Za-z][A-Za-z0-9_]*)\s*=\s*(?![\s\S]*export const)/u.exec(before);
    const name = decl ? decl[1] : null;
    const entry = name ? asConstNonUnion.get(name) : null;
    if (!entry) {
      fatal(
        `types.ts:${lineOf(source, site.index)}: an \`as const\` site (${name ?? "unnamed"}) was ` +
          "not parsed as a string-union and is not registered in asConstNonUnionSites. " +
          "Register it with a reason or fix the matcher — do not loosen it.",
      );
    }
    hit(`asConstNonUnionSites::${name}`);
  }

  return unions;
}

// =============================================================================================
// Documentation corpus
// =============================================================================================

function buildDocsCorpus() {
  // Root-level `*.md` is read non-recursively. Walking the whole repo to find files at depth 0
  // scanned every peer build directory for no benefit; `listDir` cannot reach them at all.
  const files = [
    ...walk(join(repoRoot, "docs"), (p) => p.endsWith(".md")),
    ...listDir(repoRoot, (p) => p.endsWith(".md")),
  ];
  const unique = [...new Set(files)].sort();
  if (unique.length === 0) fatal("documentation corpus is empty");
  return unique.map((file) => ({
    file,
    rel: repoPath(repoRoot, file),
    text: readFileSync(file, "utf8"),
  }));
}

/** Index of the delimiter closing the one at `open`, or -1. Operates on a masked source. */
function matchDelimiter(masked, open, openChar, closeChar) {
  let depth = 0;
  for (let i = open; i < masked.length; i += 1) {
    if (masked[i] === openChar) depth += 1;
    else if (masked[i] === closeChar) {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** Backticked spans, excluding fenced code blocks (which quote code, not claims about it). */
function* backtickedTokens(doc) {
  const withoutFences = doc.text.replace(/```[\s\S]*?```/gu, (block) =>
    block.replace(/[^\n]/gu, " "),
  );
  for (const match of withoutFences.matchAll(/`([^`\n]+)`/gu)) {
    yield { value: match[1], line: lineOf(doc.text, match.index) };
  }
}

// =============================================================================================
// Gate 1 — identifier existence
// =============================================================================================
//
// Recognizer (fixed, not tuned to what happens to pass): a backticked, all-lowercase dotted
// token whose FIRST SEGMENT is a top-level settings key or a permission namespace. That
// boundary is derived from the code, so it cannot be widened to make a failure disappear.
//
// One shape exclusion, and it is about what a token IS rather than whether it resolves: a token
// whose final segment is a source/artifact file extension (`data.rs`, `template.export.json`) is
// a path, not a dotted identifier. `assertNoExtensionCollision` proves this exclusion hides
// nothing — if a real settings path or permission id ever ends in one of these, it hard-errors.
//
// Resolution — the identifier must exist in code as one of:
//   * a settings document path (optionally written with the documented `settings.` prefix),
//   * a permission dotted id,
//   * an exact string literal in production Rust (audit/event/metric names live here).
//
// CANNOT CATCH: a dotted identifier under a namespace that is neither a settings root nor a
// permission root; an identifier that exists but is documented under the wrong meaning (gate 1
// proves existence, never semantics); any claim written without backticks.

const FILE_EXTENSIONS = new Set([
  "rs", "ts", "tsx", "js", "mjs", "cjs", "json", "md", "toml", "yml", "yaml",
  "sh", "ps1", "py", "lock", "sql", "html", "css", "pdf", "xml", "png", "svg",
]);

function isFilePath(segments) {
  return FILE_EXTENSIONS.has(segments[segments.length - 1]);
}

/** The file-extension exclusion must never hide a real identifier. Prove it, do not assume it. */
function assertNoExtensionCollision(structs, permissions) {
  for (const id of permissions.ids.keys()) {
    if (isFilePath(id.split("."))) {
      fatal(
        `permission id "${id}" ends in a file extension, so gate 1's path exclusion would hide ` +
          "it. Narrow FILE_EXTENSIONS rather than leaving the blind spot.",
      );
    }
  }
  const walkFields = (structName, prefix, depth) => {
    if (depth > 6) return;
    for (const [field, type] of structs.get(structName)) {
      const path = [...prefix, field];
      if (isFilePath(path)) {
        fatal(
          `settings path "${path.join(".")}" ends in a file extension, so gate 1's path ` +
            "exclusion would hide it. Narrow FILE_EXTENSIONS rather than leaving the blind spot.",
        );
      }
      const next = structOf(type, structs);
      if (next) walkFields(next, path, depth + 1);
    }
  };
  walkFields("Settings", [], 0);
}

function gate1(docs, structs, permissions, vocabulary) {
  assertNoExtensionCollision(structs, permissions);

  const settingsRoots = new Set(structs.get("Settings").keys());
  const permissionRoots = new Set([...permissions.ids.keys()].map((id) => id.split(".")[0]));
  const shape = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/u;

  let candidates = 0;
  for (const doc of docs) {
    for (const { value, line } of backtickedTokens(doc)) {
      if (!shape.test(value)) continue;
      const segments = value.split(".");
      if (isFilePath(segments)) continue;
      const root = segments[0];
      // `settings.<path>` is the documented way to address the settings document explicitly.
      const isPrefixed = root === "settings" && segments.length > 1;
      if (!settingsRoots.has(root) && !permissionRoots.has(root)) continue;
      candidates += 1;

      const resolved =
        resolveSettingsPath(segments, structs) ||
        (isPrefixed && resolveSettingsPath(segments.slice(1), structs)) ||
        permissions.ids.has(value) ||
        vocabulary.has(value);
      if (resolved) continue;

      const allowed = identifierAllowlist.get(value);
      if (allowed) {
        hit(`identifierAllowlist::${value}`);
        continue;
      }
      const defect = knownDefects.get(`identifier::${value}`);
      if (defect) {
        hit(`knownDefects::identifier::${value}`);
        continue;
      }
      finding(
        "gate1-identifier-existence",
        `${doc.rel}:${line}`,
        `\`${value}\` is documented under the \`${root}\` namespace but exists in code as ` +
          "neither a settings path, a permission id, nor a production string literal.",
      );
    }
  }

  // Gate 1 must never report green because its recognizer matched nothing.
  if (candidates === 0) {
    fatal("gate 1 found zero candidate identifiers — the recognizer is broken, not the docs");
  }
  return candidates;
}

// =============================================================================================
// Gate 2 — emittable-literal parity
// =============================================================================================
//
// 2a  Every value in a web `as const` union must be emittable by production Rust. A client-side
//     type asserting a server state that cannot occur is a phantom wire contract.
// 2b  Every backticked occurrence in docs of a value belonging to a declared status vocabulary
//     must likewise be emittable. Documenting a status the code cannot produce is the same
//     defect in the prose substrate.
//
// The doc-side vocabulary is anchored to declared unions (plus `statusWatchlist`, which only
// ever ADDS coverage). This is the deliberate boundary — see "cannot catch" in the report.
//
// KEY UNIONS. A few unions enumerate JSON object *keys* rather than values. Their members are
// checked against the fields of the ONE Rust struct that owns those keys, named in the registry
// — not against the emittable-value set, and not exempted. This is the rule for an irregular
// case: model it against the right thing. Exempting would have dropped the union entirely, and
// folding field names into the value set would have handed every union a 3509-name false-green
// surface to pass against.

function gate2(docs, unions, emittable, structFields) {
  const statusVocabulary = new Set(statusWatchlist);

  for (const union of unions) {
    const unionExempt = unionAllowlist.get(union.name);
    if (unionExempt) hit(`unionAllowlist::${union.name}`);

    const keyUnion = keyUnions.get(union.name);
    if (keyUnion) {
      hit(`keyUnions::${union.name}`);
      const fields = structFields.get(keyUnion.struct);
      if (!fields) {
        fatal(
          `registry keyUnions: ${union.name} names Rust struct \`${keyUnion.struct}\`, which no ` +
            "production source declares. The struct was renamed or deleted; re-point the entry.",
        );
      }
      for (const value of union.values) {
        if (fields.has(value)) continue;
        finding(
          "gate2a-key-union",
          `apps/web/src/api/types.ts:${union.line}`,
          `${union.name} declares key \`${value}\`, which is not a serialised field of ` +
            `\`${keyUnion.struct}\`.`,
        );
      }
      continue;
    }

    for (const value of union.values) {
      // Only declared string UNIONS are status vocabularies; a record's values are phrases.
      if (union.kind === "union") statusVocabulary.add(value);
      if (emittable.has(value)) continue;
      if (unionExempt) continue;

      const memberExempt = memberAllowlist.get(`${union.name}::${value}`);
      if (memberExempt) {
        hit(`memberAllowlist::${union.name}::${value}`);
        continue;
      }
      const defect = knownDefects.get(`union::${union.name}::${value}`);
      if (defect) {
        hit(`knownDefects::union::${union.name}::${value}`);
        continue;
      }
      finding(
        "gate2a-wire-contract",
        `apps/web/src/api/types.ts:${union.line}`,
        `${union.name} declares \`${value}\`, which production Rust cannot emit.`,
      );
    }
  }

  for (const doc of docs) {
    for (const { value, line } of backtickedTokens(doc)) {
      if (!statusVocabulary.has(value)) continue;
      if (emittable.has(value)) continue;

      // Checked BEFORE knownDefects so the pair is exercised while the defect is still tracked,
      // rather than only becoming live — untested — on the day the defect entry is deleted.
      const quoted = quotedLiterals.get(`${doc.rel}::${value}`);
      if (quoted) {
        hit(`quotedLiteralExemptions::${doc.rel}::${value}`);
        continue;
      }
      const defect = knownDefects.get(`docs::${value}`);
      if (defect) {
        hit(`knownDefects::docs::${value}`);
        continue;
      }
      finding(
        "gate2b-docs-literal",
        `${doc.rel}:${line}`,
        `\`${value}\` is documented as a status the system reports, but production Rust ` +
          "cannot emit it.",
      );
    }
  }

  if (statusVocabulary.size === 0) {
    fatal("gate 2 assembled an empty status vocabulary — the union matcher is broken");
  }
  return statusVocabulary.size;
}

// =============================================================================================
// Gate 3 — the claims register's own test references must resolve
// =============================================================================================
//
// Half 3 (behavioural claims) is deliberately NOT mechanised: no parser tells "unioned with the
// environment anchors at runtime" (false until t61-e1) from "defaults to false" (true). That
// judgement lives in docs/signing-trust-claims.md and is made by a human.
//
// But the register makes one claim per entry that IS mechanically checkable, and it is the
// register's own weakest link: a PROVEN entry says "this named test fails if the claim stops
// being true". Rename or delete that test and the entry silently becomes a lie — a register
// asserting proof that no longer exists is the phantom-control defect in a new substrate.
//
// So: every test named by a PROVEN entry must exist. This does NOT check the claim, and does not
// check the test is any good — only that the cited proof is real.
//
// CANNOT CATCH: whether the test actually exercises the claim; whether a REVIEWED entry's date
// is still meaningful; whether the prose is true. Those stay human, by design.

const CLAIMS_REGISTER = join(repoRoot, "docs", "signing-trust-claims.md");

function gate3(textInput, readSourceInput) {
  let text = textInput;
  if (text === undefined) {
    try {
      text = readFileSync(CLAIMS_REGISTER, "utf8");
    } catch {
      fatal(
        "docs/signing-trust-claims.md is missing. It is the half-3 deliverable: the behavioural " +
          "claims this gate cannot mechanise are tracked there, or nowhere.",
      );
    }
  }
  const readSource = readSourceInput ?? ((rel) => readFileSync(join(repoRoot, rel), "utf8"));

  // EVERY `### ST-n` heading is located first, then classified. Finding entries by searching for
  // a recognised state would silently skip any entry whose state the matcher does not understand
  // — which is how this gate would come to report green over its own blind spot. (It did: a
  // REVIEWED entry carries its review date INSIDE the bold, `**REVIEWED 2026-07-28**`, and an
  // earlier `\*\*(REVIEWED)\*\*` matcher dropped all four of them without a word.)
  const headings = [...text.matchAll(/^### (ST-\d+)\b([^\n]*)$/gmu)].map((match) => {
    const state = /\*\*(PROVEN|REVIEWED|FALSE)\b[^*]*\*\*/u.exec(match[2]);
    if (!state) {
      fatal(
        `docs/signing-trust-claims.md:${lineOf(text, match.index)}: entry ${match[1]} declares no ` +
          "PROVEN/REVIEWED/FALSE state. Every claim must carry one — an unclassified entry is an " +
          "unreviewed claim wearing the register's authority.",
      );
    }
    return { index: match.index, id: match[1], state: state[1] };
  });
  if (headings.length === 0) {
    fatal(
      "docs/signing-trust-claims.md declares no `### ST-n · … · **STATE**` entries. Either the " +
        "register was emptied or the heading convention changed; a register with no entries " +
        "must not report green.",
    );
  }

  const states = { PROVEN: 0, REVIEWED: 0, FALSE: 0 };
  let references = 0;

  for (const [index, heading] of headings.entries()) {
    const start = heading.index;
    const end = index + 1 < headings.length ? headings[index + 1].index : text.length;
    const body = text.slice(start, end);
    const { id, state } = heading;
    states[state] += 1;
    if (state !== "PROVEN") continue;

    // `path.rs` · `test_name`[, `test_name`…] — one path may cite several tests.
    const cites = [
      ...body.matchAll(/`((?:crates|apps)\/[^`\n]+\.rs)`\s*·\s*((?:`[a-z_][a-z0-9_]*`[,\s]*)+)/gu),
    ];
    if (cites.length === 0) {
      finding(
        "gate3-claims-register",
        `docs/signing-trust-claims.md:${lineOf(text, start)}`,
        `${id} is marked PROVEN but cites no test. PROVEN means a named test fails when the ` +
          "claim stops being true; without one the entry is REVIEWED at best.",
      );
      continue;
    }

    for (const cite of cites) {
      const relative = cite[1];
      const names = [...cite[2].matchAll(/`([a-z_][a-z0-9_]*)`/gu)].map((m) => m[1]);
      let source;
      try {
        source = readSource(relative);
      } catch {
        finding(
          "gate3-claims-register",
          `docs/signing-trust-claims.md:${lineOf(text, start)}`,
          `${id} cites tests in \`${relative}\`, which does not exist.`,
        );
        continue;
      }
      assertCitedTestRuns(relative, id, `docs/signing-trust-claims.md:${lineOf(text, start)}`);
      for (const name of names) {
        references += 1;
        if (!new RegExp(`\\bfn\\s+${name}\\b`, "u").test(source)) {
          finding(
            "gate3-claims-register",
            `docs/signing-trust-claims.md:${lineOf(text, start)}`,
            `${id} cites \`${name}\` in \`${relative}\` as its proof, but no such function ` +
              "exists. Either the test was renamed and the entry must follow, or the proof is gone.",
          );
        }
      }
    }
  }

  if (states.PROVEN === 0) {
    fatal(
      "docs/signing-trust-claims.md contains no PROVEN entries, so gate 3 would check nothing. " +
        "A register of exclusively unproven claims must not report green.",
    );
  }
  return { states, references };
}

// ---------------------------------------------------------------------------------------------
// Is a cited test actually COMPILED? Existing on disk is not the same as running.
//
// `crates/chancela-api` sets `autotests = false` and declares 15 `[[test]]` targets for 50 files
// in `tests/`. The other 35 run only because a `suite_*.rs` aggregator `mod`-includes them. A
// file that nobody wires compiles nowhere and runs never — so a PROVEN entry citing it would
// assert a proof that CANNOT FAIL. That is this lane's own defect class, inside the register
// that exists to prevent it, and no amount of `fn <name>` grepping can see it.
//
// Modelled, not assumed: nothing about a filename says whether it is wired.

const crateReachability = new Map();

function reachableTestFiles(crateDir) {
  if (crateReachability.has(crateDir)) return crateReachability.get(crateDir);

  const manifestPath = join(repoRoot, crateDir, "Cargo.toml");
  let manifest;
  try {
    manifest = readFileSync(manifestPath, "utf8");
  } catch {
    fatal(`${crateDir}/Cargo.toml cannot be read, so test reachability cannot be established.`);
  }

  // With autotests on (the default), cargo discovers every `tests/*.rs` as its own target.
  if (!/^\s*autotests\s*=\s*false/mu.test(manifest)) {
    crateReachability.set(crateDir, null); // null = "everything is reachable"
    return null;
  }

  const declared = [...manifest.matchAll(/^\s*path\s*=\s*"(tests\/[^"]+)"/gmu)].map((m) => m[1]);
  if (declared.length === 0) {
    fatal(
      `${crateDir}/Cargo.toml sets autotests = false but declares no test paths. Every test in ` +
        "that crate is dead code; the manifest is broken, not the register.",
    );
  }

  // Walk aggregator `mod` includes transitively — a suite may include a suite.
  const reachable = new Set(declared);
  const queue = [...declared];
  while (queue.length > 0) {
    const current = queue.pop();
    let source;
    try {
      source = readFileSync(join(repoRoot, crateDir, current), "utf8");
    } catch {
      continue; // A declared path that does not exist is cargo's problem, not the register's.
    }
    const dir = current.slice(0, current.lastIndexOf("/"));
    // `#[path = "x.rs"] mod x;` and bare `mod x;` both pull a sibling file into this target.
    for (const m of source.matchAll(/#\[path\s*=\s*"([^"]+)"\]\s*(?:pub\s+)?mod\s+[a-z0-9_]+\s*;/gu)) {
      const next = `${dir}/${m[1]}`;
      if (!reachable.has(next)) {
        reachable.add(next);
        queue.push(next);
      }
    }
    for (const m of source.matchAll(/^\s*(?:pub\s+)?mod\s+([a-z0-9_]+)\s*;/gmu)) {
      for (const candidate of [`${dir}/${m[1]}.rs`, `${dir}/${m[1]}/mod.rs`]) {
        if (!reachable.has(candidate)) {
          reachable.add(candidate);
          queue.push(candidate);
        }
      }
    }
  }
  crateReachability.set(crateDir, reachable);
  return reachable;
}

/** A cited path that is not compiled into any test binary is a proof that never runs. */
function assertCitedTestRuns(relative, id, location) {
  const match = /^(crates\/[^/]+)\/(tests\/.+)$/u.exec(relative);
  if (!match) return; // `src/…` is covered by the crate's lib test target, which always exists.
  const reachable = reachableTestFiles(match[1]);
  if (reachable === null || reachable.has(match[2])) return;
  finding(
    "gate3-claims-register",
    location,
    `${id} cites tests in \`${relative}\`, which is compiled into NO test target — ` +
      `${match[1]} sets autotests = false and neither declares this file nor \`mod\`-includes ` +
      "it from a declared suite. The test never runs, so the proof cannot fail. Wire the file " +
      "into a target, or the entry is REVIEWED, not PROVEN.",
  );
}

// =============================================================================================
// Registry exercise — an entry that matches nothing is registry rot
// =============================================================================================

function assertRegistryExercised() {
  const expected = [
    ...registry.identifierAllowlist.map((e) => `identifierAllowlist::${e.identifier}`),
    ...registry.unionAllowlist.map((e) => `unionAllowlist::${e.union}`),
    ...registry.memberAllowlist.map((e) => `memberAllowlist::${e.union}::${e.value}`),
    ...registry.keyUnions.map((e) => `keyUnions::${e.union}`),
    ...registry.asConstNonUnionSites.map((e) => `asConstNonUnionSites::${e.name}`),
    ...registry.knownDefects.map((e) => `knownDefects::${e.key}`),
    ...registry.quotedLiteralExemptions.map(
      (e) => `quotedLiteralExemptions::${e.file}::${e.value}`,
    ),
  ];
  const stale = expected.filter((key) => !registryHits.has(key));
  if (stale.length > 0) {
    console.error("check-docs-claims: REGISTRY ROT — these entries no longer match anything:");
    for (const key of stale) console.error(`  - ${key}`);
    console.error(
      "  An exemption that exempts nothing is a rubber stamp. If the underlying case is gone " +
        "(for example the defect was fixed), delete the entry.",
    );
    process.exit(2);
  }
}

// =============================================================================================
// Self-test — the gate proven by breaking it, as a committed artefact
// =============================================================================================
//
// A gate that has never been seen red is not evidence. Proving it once in a transcript proves it
// for one afternoon; proving it here proves it on every CI run, and fails if someone later
// loosens a matcher until the defect stops being detected.
//
// Each case drives the real `gate1`/`gate2` decision logic over synthetic models. The synthetic
// values are deliberately nonsense tokens (`estado_fantasma`, …) so no live registry entry can
// suppress them and no real vocabulary can accidentally satisfy them — a self-test that passed
// because the real tree happened to contain its fixture would be its own phantom control.
//
// The two ACCEPTANCE CASES this lane exists for are reproduced in miniature: case 2 is the
// `types.ts` phantom wire contract, case 4 is the `ARCHITECTURE.md` phantom status. Both are
// asserted RED with the defect and GREEN once the defect is removed.

function runSelfTest() {
  const cases = [];
  const check = (name, fn) => cases.push({ name, fn });

  // Gate 1's settings resolver. `auth.device_pairing.accepted` is a REAL, shipped setting that the
  // resolver reported as a phantom, because settings.rs types the section with a struct from a
  // sibling module and the model parsed settings.rs alone. Pinned in all three directions: the
  // qualified hop resolves, a bad segment beneath it is still red, and an unfollowed module stays
  // red rather than becoming a blanket accept.
  const qualifiedModel = () =>
    new Map([
      ["Settings", new Map([["seccao_fantasma", "crate::modulo_fantasma::AjustesFantasma"]])],
      ["AjustesFantasma", new Map([["aceites", "BTreeSet<MetodoFantasma>"]])],
    ]);

  check("resolveSettingsPath follows a `crate::<module>::` qualified field type", () =>
    resolveSettingsPath(["seccao_fantasma", "aceites"], qualifiedModel())
      ? null
      : "a path under a module-qualified settings struct did not resolve, so a real setting " +
          "would be reported as a phantom");

  check("resolveSettingsPath still rejects an unknown segment under a qualified type", () =>
    resolveSettingsPath(["seccao_fantasma", "nao_e_um_campo"], qualifiedModel())
      ? "following the qualification became a blanket accept — any path under the section passes"
      : null);

  check("an unparsed module's struct stays a leaf, so paths beneath it are red", () => {
    const model = new Map([
      ["Settings", new Map([["seccao_fantasma", "crate::modulo_fantasma::NaoParseado"]])],
    ]);
    return resolveSettingsPath(["seccao_fantasma", "aceites"], model)
      ? "a path resolved through a struct the model never parsed"
      : null;
  });

  // A minimal emittable vocabulary standing in for production Rust.
  const emittable = () => new Set(["em_assinatura", "finalizado", "finalizado_qualificado"]);
  const doc = (text) => [{ rel: "docs/SELFTEST.md", file: "SELFTEST", text }];
  const union = (values, name = "SELFTEST_STATUSES") => [
    { name, kind: "union", values, line: 1 },
  ];

  const run = (docs, unions, vocab, structFields = new Map()) => {
    findings.length = 0;
    gate2(docs, unions, vocab, structFields);
    return findings.map((f) => f.gate);
  };

  check("gate2a is GREEN when every union member is emittable", () => {
    const got = run(doc(""), union(["em_assinatura", "finalizado"]), emittable());
    return got.length === 0 ? null : `expected no findings, got ${JSON.stringify(got)}`;
  });

  // ACCEPTANCE CASE — apps/web/src/api/types.ts declared 5 finalization statuses; the backend
  // emits 3. This is that defect, reduced.
  check("gate2a is RED on a union member production Rust cannot emit", () => {
    const got = run(doc(""), union(["em_assinatura", "estado_fantasma"]), emittable());
    return got.length === 1 && got[0] === "gate2a-wire-contract"
      ? null
      : `expected one gate2a-wire-contract finding, got ${JSON.stringify(got)}`;
  });

  check("gate2a goes GREEN again once the phantom member is dropped", () => {
    const got = run(doc(""), union(["em_assinatura"]), emittable());
    return got.length === 0 ? null : `expected no findings, got ${JSON.stringify(got)}`;
  });

  // ACCEPTANCE CASE — docs/ARCHITECTURE.md documents statuses the code never emits.
  check("gate2b is RED on a documented status production Rust cannot emit", () => {
    const got = run(
      doc("The API reports `estado_fantasma` once sealed."),
      union(["estado_fantasma"]),
      emittable(),
    );
    return got.includes("gate2b-docs-literal")
      ? null
      : `expected a gate2b-docs-literal finding, got ${JSON.stringify(got)}`;
  });

  check("gate2b goes GREEN once the prose names an emittable status", () => {
    const got = run(
      doc("The API reports `em_assinatura` once sealed."),
      union(["em_assinatura"]),
      emittable(),
    );
    return got.length === 0 ? null : `expected no findings, got ${JSON.stringify(got)}`;
  });

  check("gate2b ignores a status literal inside a fenced code block", () => {
    const got = run(
      doc("```\n`estado_fantasma`\n```\n"),
      union(["estado_fantasma"]),
      emittable(),
    );
    // A fence quotes code rather than claiming behaviour. Recorded as a case so that if this
    // ever changes it is a deliberate decision and not an accident of the regex.
    return got.length === 1 && got[0] === "gate2a-wire-contract"
      ? null
      : `expected only the union finding, got ${JSON.stringify(got)}`;
  });

  // A JSON key must not be justifiable by the emittable-VALUE set, and a key union must be
  // checked against its own struct. This is the guard on the tightening in Model 3.
  check("a key union is RED when a member is not a field of its struct", () => {
    const name = registry.keyUnions[0].union;
    const fields = new Map([[registry.keyUnions[0].struct, new Set(["association"])]]);
    const got = run(doc(""), union(["association", "nao_e_um_campo"], name), emittable(), fields);
    return got.length === 1 && got[0] === "gate2a-key-union"
      ? null
      : `expected one gate2a-key-union finding, got ${JSON.stringify(got)}`;
  });

  check("a key union is GREEN when every member is a field of its struct", () => {
    const name = registry.keyUnions[0].union;
    const fields = new Map([[registry.keyUnions[0].struct, new Set(["association"])]]);
    const got = run(doc(""), union(["association"], name), emittable(), fields);
    return got.length === 0 ? null : `expected no findings, got ${JSON.stringify(got)}`;
  });

  // The tightening itself: a struct field name must NOT satisfy a status value.
  check("a struct field name does not make a status value emittable", () => {
    const got = run(doc(""), union(["require_qualified_for_seal"]), emittable());
    return got.length === 1 && got[0] === "gate2a-wire-contract"
      ? null
      : `expected the field name to be rejected as a value, got ${JSON.stringify(got)}`;
  });

  // Gate 3 — the claims register's cited proofs. A PROVEN entry whose test has been renamed is
  // a register asserting proof that no longer exists.
  const registerEntry = (state, cite) =>
    `# R\n\n### ST-1 · A claim · **${state}**\n\n> "quoted"\n\n${cite}\n`;
  const sources = { "crates/x/src/a.rs": "fn claim_is_upheld() {}\n" };
  const load = (rel) => {
    if (!(rel in sources)) throw new Error("no such file");
    return sources[rel];
  };
  const runGate3 = (text) => {
    findings.length = 0;
    gate3(text, load);
    const gates = findings.map((f) => f.gate);
    findings.length = 0;
    return gates;
  };

  check("gate3 is GREEN when a PROVEN entry cites a test that exists", () => {
    const got = runGate3(registerEntry("PROVEN", "`crates/x/src/a.rs` · `claim_is_upheld`"));
    return got.length === 0 ? null : `expected no findings, got ${JSON.stringify(got)}`;
  });

  check("gate3 is RED when a PROVEN entry cites a test that does not exist", () => {
    const got = runGate3(registerEntry("PROVEN", "`crates/x/src/a.rs` · `claim_was_renamed`"));
    return got.length === 1 && got[0] === "gate3-claims-register"
      ? null
      : `expected one gate3-claims-register finding, got ${JSON.stringify(got)}`;
  });

  check("gate3 is RED when a PROVEN entry cites a file that does not exist", () => {
    const got = runGate3(registerEntry("PROVEN", "`crates/x/src/gone.rs` · `claim_is_upheld`"));
    return got.length === 1 && got[0] === "gate3-claims-register"
      ? null
      : `expected one gate3-claims-register finding, got ${JSON.stringify(got)}`;
  });

  check("gate3 is RED when an entry claims PROVEN but cites no test at all", () => {
    const got = runGate3(registerEntry("PROVEN", "It is obviously true."));
    return got.length === 1 && got[0] === "gate3-claims-register"
      ? null
      : `expected one gate3-claims-register finding, got ${JSON.stringify(got)}`;
  });

  // The silent-skip regression guard: a REVIEWED entry carries its date inside the bold marker.
  // An earlier matcher required exactly `**REVIEWED**` and dropped every dated entry in silence.
  check("gate3 classifies a REVIEWED entry whose bold marker carries a date", () => {
    findings.length = 0;
    const result = gate3(
      `${registerEntry("PROVEN", "`crates/x/src/a.rs` · `claim_is_upheld`")}\n` +
        "### ST-2 · Another claim · **REVIEWED 2026-07-28**\n\nRead by hand.\n",
      load,
    );
    findings.length = 0;
    return result.states.REVIEWED === 1
      ? null
      : `a dated REVIEWED entry was not classified (states: ${JSON.stringify(result.states)})`;
  });

  // Parsing primitives: unparseable input must throw rather than be skipped.
  check("an unterminated Rust block comment throws rather than being skipped", () => {
    try {
      maskRust("/* never closed", "selftest.rs");
    } catch {
      return null;
    }
    return "maskRust accepted an unterminated block comment";
  });

  check("splitMembers keeps a generic type with a comma as ONE member", () => {
    const parts = splitMembers("a: HashMap<String, u32>, b: u8");
    return parts.length === 2 ? null : `expected 2 members, got ${parts.length}`;
  });

  check("serde rename on one member does not leak to the next", () => {
    const body = '#[serde(rename = "primeiro")]\nAlpha,\nBeta';
    const parts = splitMembers(body);
    const names = parts.map(([from, to]) => {
      const chunk = withoutAttributes(body.slice(from, to));
      return wireName(/^\s*([A-Z][A-Za-z0-9_]*)/u.exec(chunk)[1], body.slice(from, to), null);
    });
    return names.join(",") === "primeiro,Beta"
      ? null
      : `expected "primeiro,Beta", got "${names.join(",")}"`;
  });

  // Test reachability: existing on disk is not the same as being compiled and run.
  check("a suite-included test file is recognised as compiled", () => {
    const reachable = reachableTestFiles("crates/chancela-api");
    if (reachable === null) {
      return "chancela-api no longer sets autotests = false; this model is void, not passing";
    }
    return reachable.has("tests/signing_configure_gate.rs")
      ? null
      : "signing_configure_gate.rs is mod-included by suite_signatures.rs but was not recognised, " +
          "so a real proof would be reported as never running";
  });

  check("a tests/ file wired into no target is NOT treated as compiled", () => {
    const reachable = reachableTestFiles("crates/chancela-api");
    if (reachable === null) return "autotests model unavailable";
    return reachable.has("tests/nothing_wires_this_file.rs")
      ? "an unwired test path was treated as compiled — a PROVEN entry citing a test that never " +
          "runs would pass, which is the defect this register exists to prevent"
      : null;
  });

  let failed = 0;
  for (const testCase of cases) {
    let problem;
    try {
      problem = testCase.fn();
    } catch (error) {
      problem = `threw: ${error && error.message ? error.message : String(error)}`;
    }
    if (problem) {
      failed += 1;
      console.error(`  FAIL  ${testCase.name}\n          ${problem}`);
    } else {
      console.log(`  ok    ${testCase.name}`);
    }
  }
  findings.length = 0;

  if (failed > 0) {
    console.error(`\ncheck-docs-claims self-test: ${failed} of ${cases.length} case(s) FAILED.`);
    console.error("  The gate's own decision logic is broken. Do not trust a green run.");
    process.exit(2);
  }
  console.log(`\ncheck-docs-claims self-test: ${cases.length} cases passed.`);
  process.exit(0);
}

if (selfTestMode) runSelfTest();

// =============================================================================================
// Run
// =============================================================================================

// Every model builder is inside one handler so that ANY failure to read or parse an input
// exits 2, not 1. An uncaught throw exits 1 — the code that means "findings" — which would tell
// CI the docs are wrong when in fact the gate is broken. Individual call sites wrap some of
// these already; this guarantees it for the paths nobody remembered to wrap.
let structs;
let permissions;
let emittable;
let structFields;
let stats;
let unions;
let docs;
try {
  structs = buildSettingsModel();
  permissions = buildPermissionCatalog();
  ({ emittable, structFields, stats } = buildRustVocabulary());
  unions = buildWebUnions();
  docs = buildDocsCorpus();
} catch (error) {
  fatal(error && error.message ? error.message : String(error));
}

const gate1Candidates = gate1(docs, structs, permissions, emittable);
const statusVocabularySize = gate2(docs, unions, emittable, structFields);
const register = gate3();

assertRegistryExercised();

const summary = {
  docs_files: docs.length,
  settings_structs: structs.size,
  permission_ids: permissions.ids.size,
  rust_src_files: stats.files,
  rust_emittable_values: emittable.size,
  rust_structs_with_fields: structFields.size,
  web_unions: unions.length,
  web_union_members: unions.reduce((total, u) => total + u.values.length, 0),
  gate1_candidates: gate1Candidates,
  gate2_status_vocabulary: statusVocabularySize,
  claims_register: register.states,
  claims_register_test_references: register.references,
  known_defects: registry.knownDefects.length,
  findings,
};

if (jsonOutput) {
  console.log(JSON.stringify(summary, null, 2));
} else if (findings.length > 0) {
  console.error(`check-docs-claims: ${findings.length} finding(s)\n`);
  const byGate = new Map();
  for (const f of findings) {
    if (!byGate.has(f.gate)) byGate.set(f.gate, []);
    byGate.get(f.gate).push(f);
  }
  for (const [gate, entries] of byGate) {
    console.error(`  ${gate}`);
    for (const entry of entries) {
      console.error(`    ${entry.location}\n      ${entry.message}`);
    }
    console.error("");
  }
} else {
  console.log(
    `docs claims OK: ${docs.length} docs, ${gate1Candidates} identifier claims resolved, ` +
      `${summary.web_union_members} wire-contract values across ${unions.length} unions ` +
      `checked against ${emittable.size} emittable values, ` +
      `${register.references} claims-register test reference(s) resolved ` +
      `(${register.states.PROVEN} PROVEN / ${register.states.REVIEWED} REVIEWED / ` +
      `${register.states.FALSE} FALSE), ` +
      `${registry.knownDefects.length} known defect(s) tracked.`,
  );
}

process.exit(findings.length > 0 ? 1 : 0);
