#!/usr/bin/env node
// Rust coverage gate.
//
// Reads a `cargo llvm-cov --json` report, aggregates it per workspace crate, and enforces:
//
//   * a HARD 90% line threshold for chancela-core, chancela-store, chancela-ledger and
//     chancela-authz — the four small, central crates the user ruled must not drift; and
//   * a NO-REGRESSION RATCHET at the recorded baseline for every other crate.
//
// PLATFORM: the authoritative figures are the ones CI measures on **Linux** (ubuntu-latest).
// Windows and macOS runs are advisory and must not write the baseline — the workspace has 25
// cfg(windows)/cfg(unix) sites, so the two platforms compile different code and their numbers are
// not interchangeable. `.github/rust-coverage-baseline.json` records which OS produced it.
//
// A NOTE ON WHAT THE NUMBERS MEAN — read before trusting an absolute figure.
//
// llvm-cov sums a function's coverage across every binary the function is compiled into. A crate
// with N integration-test targets is linked into N+1 binaries, and a function exercised in only one
// of them is counted covered once and uncovered N times. The effect is large and it is not uniform:
//
//   chancela-authz   0 integration targets   98.20%   undiluted
//   chancela-ledger  0 integration targets   92.34%   undiluted
//   chancela-core    3 integration targets   85.21%   diluted (floor)
//   chancela-store   4 integration targets   52.67%   heavily diluted (floor) — and one of those
//                                                     targets, postgres_backend, is #[ignore]d
//                                                     without a live server, so its entire
//                                                     instantiation counts as uncovered
//
// (Windows figures, 2026-07-21, HEAD ea75441.)
//
// Consequence: a RATCHET is sound on these numbers because it compares a measurement against
// itself. A HARD ABSOLUTE THRESHOLD is only sound where the measurement is undiluted. The four
// hard-90% crates are enforced here because the user ruled they must be, but `store` and `core`
// are expected to fail on first run for the reason above rather than because they are untested.
// Settle the dilution question before this job is made blocking; see
// `.orchestration/logs/t75-coverage.md` §2.
//
// Usage:
//   node scripts/rust-coverage-gate.mjs --report <llvm-cov.json> [--update-baseline]

import { readFileSync, writeFileSync } from 'node:fs';
import { argv, exit, platform } from 'node:process';

const BASELINE_PATH = '.github/rust-coverage-baseline.json';
const EXCLUSIONS_PATH = '.github/rust-coverage-exclusions.json';
const HARD_90 = ['chancela-core', 'chancela-store', 'chancela-ledger', 'chancela-authz'];
const HARD_THRESHOLD = 90;
// A ratcheted crate may drop by this much before the gate fails, absorbing the run-to-run jitter
// llvm-cov shows when a flaky or timing-dependent test changes which branches execute.
const RATCHET_TOLERANCE = 0.5;

function arg(name) {
  const i = argv.indexOf(name);
  return i === -1 ? undefined : argv[i + 1];
}

const reportPath = arg('--report');
if (!reportPath) {
  console.error('usage: rust-coverage-gate.mjs --report <llvm-cov.json> [--update-baseline]');
  exit(2);
}

const report = JSON.parse(readFileSync(reportPath, 'utf8'));
const exclusions = JSON.parse(readFileSync(EXCLUSIONS_PATH, 'utf8'));

// Only the two exclusions the user approved on 2026-07-19 may be applied. The pkcs11 one is
// expressed per FUNCTION, not per file, because the approval was explicitly narrower than the
// file: `default_module_path()` and the pure mapping helpers in pkcs11.rs stay in the numerator.
const excludedFns = new Set(
  exclusions.functions.map((e) => `${e.file}::${e.name}`),
);

function crateOf(filename) {
  const m = filename.replace(/\\/g, '/').match(/\/crates\/([^/]+)\/src\//);
  return m ? m[1] : undefined;
}

// Aggregate per crate. Start from per-function records so the approved pkcs11 exclusion can be
// applied at function granularity, then fall back to file summaries for line/region totals.
const crates = new Map();
function bucket(name) {
  if (!crates.has(name)) {
    crates.set(name, { lines: [0, 0], regions: [0, 0], functions: [0, 0] });
  }
  return crates.get(name);
}

for (const file of report.data[0].files) {
  const crate = crateOf(file.filename);
  if (!crate) continue; // dependency source, or a tests/ target — not gated
  const b = bucket(crate);
  for (const k of ['lines', 'regions', 'functions']) {
    b[k][0] += file.summary[k].covered;
    b[k][1] += file.summary[k].count;
  }
}

// Subtract the approved exclusions.
//
// llvm-cov emits v0-MANGLED symbol names ("_RNvMs_...12sign_digest..."), not source identifiers,
// so an exclusion cannot be matched on `fn.name` directly. v0 encodes each path segment
// length-prefixed, so `sign_digest` appears as `11sign_digest`; requiring that token AND the
// declaring filename is precise enough to be safe and is far more stable than matching line ranges,
// which drift with every edit.
//
// LIMITATION, stated rather than hidden: this adjusts the FUNCTION and REGION metrics only. The
// llvm-cov JSON attributes regions to functions but does NOT attribute lines to functions, so a
// function-scoped exclusion cannot be applied to the line metric — and `lines` is what the gate
// thresholds on. Applying it there would require excluding pkcs11.rs wholesale, which the user
// explicitly refused (it would silently drop `default_module_path()` and the tested pure helpers
// with it). So pkcs11's cryptoki functions still depress `chancela-smartcard`'s LINE figure.
// Options are in .orchestration/logs/t75-coverage.md; none may be chosen by an executor.
let excludedCount = 0;
const excludedRegions = new Map();
for (const fn of report.data[0].functions ?? []) {
  for (const filename of fn.filenames ?? []) {
    const crate = crateOf(filename);
    if (!crate) continue;
    const short = filename.replace(/\\/g, '/').split('/src/')[1];
    const hit = [...excludedFns].some((key) => {
      const [file, name] = key.split('::');
      return short === file && fn.name.includes(`${name.length}${name}`);
    });
    if (!hit) continue;
    const b = bucket(crate);
    b.functions[1] -= 1;
    if (fn.count > 0) b.functions[0] -= 1;
    const regions = fn.regions ?? [];
    const covered = regions.filter((r) => r[4] > 0).length;
    b.regions[0] -= covered;
    b.regions[1] -= regions.length;
    excludedRegions.set(crate, (excludedRegions.get(crate) ?? 0) + regions.length);
    excludedCount += 1;
  }
}

const pct = (pair) => (pair[1] === 0 ? 100 : (100 * pair[0]) / pair[1]);

const measured = {};
for (const [name, b] of [...crates].sort()) {
  measured[name] = {
    lines: Number(pct(b.lines).toFixed(2)),
    regions: Number(pct(b.regions).toFixed(2)),
    functions: Number(pct(b.functions).toFixed(2)),
    lineCount: b.lines[1],
  };
}

const os = platform === 'linux' ? 'linux' : platform;
const advisory = os !== 'linux';

if (argv.includes('--update-baseline')) {
  if (advisory) {
    console.error(
      `refusing to write the baseline from ${os}: the gate is pinned to Linux/CI and a ` +
        `non-Linux figure must never be baked into it`,
    );
    exit(2);
  }
  writeFileSync(
    BASELINE_PATH,
    `${JSON.stringify({ measuredOn: 'linux', measuredAt: new Date().toISOString(), crates: measured }, null, 2)}\n`,
  );
  console.log(`baseline written to ${BASELINE_PATH} (linux)`);
  exit(0);
}

const baseline = JSON.parse(readFileSync(BASELINE_PATH, 'utf8'));

console.log(`Rust coverage — measured on ${os}${advisory ? ' (ADVISORY, not the gate)' : ''}`);
console.log(`Approved exclusions applied: ${excludedCount} function instantiation(s)`);
console.log('');
console.log('crate'.padEnd(24) + 'lines'.padStart(9) + 'rule'.padStart(22) + '  result');

const failures = [];
const unbaselined = [];

for (const [name, m] of Object.entries(measured)) {
  let rule;
  let ok;
  if (HARD_90.includes(name)) {
    rule = `hard ${HARD_THRESHOLD}%`;
    ok = m.lines >= HARD_THRESHOLD;
  } else if (baseline.crates?.[name] === undefined) {
    rule = 'no baseline';
    ok = true;
    unbaselined.push(name);
  } else {
    const floor = baseline.crates[name].lines - RATCHET_TOLERANCE;
    rule = `ratchet >= ${floor.toFixed(2)}%`;
    ok = m.lines >= floor;
  }
  if (!ok) failures.push({ name, measured: m.lines, rule });
  console.log(
    name.padEnd(24) + `${m.lines.toFixed(2)}%`.padStart(9) + rule.padStart(22) + (ok ? '  ok' : '  FAIL'),
  );
}

if (unbaselined.length) {
  console.log('');
  console.log(
    `${unbaselined.length} crate(s) have no recorded baseline and were not gated: ` +
      `${unbaselined.join(', ')}. Run with --update-baseline on Linux to record one.`,
  );
}

if (failures.length === 0) {
  console.log('\nRust coverage gate: PASS');
  exit(0);
}

console.log('');
for (const f of failures) {
  console.log(`FAIL ${f.name}: ${f.measured.toFixed(2)}% does not meet ${f.rule}`);
}

if (advisory) {
  console.log(
    '\nMeasured off-Linux — reporting only, not failing the build. The gate is Linux/CI.',
  );
  exit(0);
}

console.log('\nRust coverage gate: FAIL');
exit(1);
