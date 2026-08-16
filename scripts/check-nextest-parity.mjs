#!/usr/bin/env node
// Proves that switching CI from `cargo test` to `cargo nextest` did not silently stop executing
// tests.
//
// This is the guard for the one failure mode that matters when a test runner is replaced for
// speed: a runner that is faster because it runs LESS. A wall-clock win bought by quietly dropping
// test binaries would look exactly like a wall-clock win bought by scheduling them better, and no
// other check in this repo can tell the two apart.
//
// The comparison is a SET comparison, not a count comparison. Two totals can agree while the sets
// differ (one test gained, one lost), so matching numbers are not evidence — matching names are.
//
// The one legitimate difference is DOCTESTS. nextest cannot run them: doctests are compiled and
// driven by rustdoc, not by libtest, and there is no libtest binary for nextest to enumerate. So
// this gate asserts:
//
//   * every non-doctest that `cargo test` lists is also listed by nextest; and
//   * nextest lists nothing that `cargo test` does not; and
//   * everything `cargo test` lists that nextest does not is a doctest, and there is at least one
//     of them (if that number ever reaches zero, the separate `--doc` CI step has become a no-op
//     and should be removed rather than left to imply cover it does not give).
//
// `--run-ignored all` is passed to nextest because `cargo test -- --list` lists ignored tests too.
// Without it the two sides disagree by exactly the ignored set, which is a difference in what is
// LISTED, not in what is RUN, and would make this gate cry wolf.
//
// Usage:
//   node scripts/check-nextest-parity.mjs [--features <list>]
//   node scripts/check-nextest-parity.mjs --self-test

import { spawnSync } from "node:child_process";
import { argv, exit } from "node:process";

// Doctest entries from `cargo test -- --list` carry a FILE, a `-`, an item path and a line:
//   crates\chancela-api\src\confirmation.rs - confirmation::require_confirmation (line 2214)
// The item path is EMPTY when the doctest lives in a `//!` module-doc block, because there is no
// item to name — and that is a real shape, not a malformed one:
//   crates\chancela-store\src\lib.rs - (line 22)
// Requiring a name there silently reclassified that doctest as a plain test and made the gate
// report a phantom drop. Unit/integration entries are Rust paths and can contain neither a space
// nor a parenthesis, so keying on "<file>.rs - ... (line N)" cannot collide with one:
//   actor::clock_tests::a_session_idle_past_the_sliding_window_is_refused
//
// `ignore`, `no_run`, `compile_fail` and `should_panic` doctests all use this same shape. An
// ignored doctest is still a doctest: `cargo test` lists it, never runs it, and nextest cannot run
// doctests at all — so it belongs in the doctest bucket, not in a special case.
const DOCTEST = /^.+\.rs - .*\(line \d+\)$/u;

export function parseCargoList(stdout) {
  const all = stdout
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.endsWith(": test"))
    .map((l) => l.slice(0, -": test".length));
  return {
    tests: all.filter((n) => !DOCTEST.test(n)),
    doctests: all.filter((n) => DOCTEST.test(n)),
  };
}

// `cargo nextest list` groups by binary:
//   chancela-api::api-auth:
//       some::test::name
export function parseNextestList(stdout) {
  return stdout
    .split("\n")
    .filter((l) => /^ {4}\S/u.test(l))
    .map((l) => l.trim());
}

export function compare(cargo, nextest) {
  const counted = new Map();
  for (const n of nextest) counted.set(n, (counted.get(n) ?? 0) + 1);
  const missing = [];
  for (const n of cargo.tests) {
    const left = counted.get(n) ?? 0;
    if (left === 0) missing.push(n);
    else counted.set(n, left - 1);
  }
  const extra = [];
  for (const [name, left] of counted)
    for (let i = 0; i < left; i += 1) extra.push(name);
  return { missing, extra };
}

/** Strip SGR escapes. See `run` for why this is not paranoia. */
function stripAnsi(text) {
  // eslint-disable-next-line no-control-regex
  return text.replace(/\u001b\[[0-9;]*m/gu, "");
}

function run(command, args) {
  // Colour off, belt and braces. `cargo nextest list` colourises its output and FORCES colour when
  // it detects CI, so the names it printed there arrived wrapped in SGR escapes while a local run
  // produced clean bytes. The comparison is by name, so every name mismatched: CI reported
  // "4177 test(s) cargo test runs and nextest does NOT" while both totals read exactly 4177 — a
  // parse failure wearing the costume of a total drop. `NO_COLOR` and `CARGO_TERM_COLOR` cover the
  // tools that honour them, `--color never` covers nextest explicitly, and `stripAnsi` covers
  // whatever ignores all three.
  const r = spawnSync(command, args, {
    encoding: "utf8",
    shell: false,
    maxBuffer: 256 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: "1", CARGO_TERM_COLOR: "never" },
  });
  if (r.error) throw r.error;
  if (r.status !== 0) {
    console.error(`${command} ${args.join(" ")} exited ${r.status}`);
    console.error(r.stderr);
    exit(2);
  }
  return stripAnsi(r.stdout);
}

if (argv.includes("--self-test")) {
  const cargo = parseCargoList(
    [
      "alpha::one: test",
      "beta::two: test",
      "crates\\chancela-api\\src\\a.rs - a::doc (line 12): test",
      // A doctest in a `//!` module-doc block has NO item name. This shape is why the gate once
      // reported a phantom drop, so it is pinned here: classify it as a plain test again and the
      // assertions below fail.
      "crates\\chancela-store\\src\\lib.rs - (line 22): test",
      "not a test line",
    ].join("\n"),
  );
  if (cargo.tests.length !== 2) {
    console.error(
      `self-test FAILED: expected 2 real tests, got ${cargo.tests.length}: ${cargo.tests.join(", ")}`,
    );
    exit(1);
  }
  if (cargo.doctests.length !== 2) {
    console.error(
      `self-test FAILED: expected 2 doctests (one of them name-less), got ${cargo.doctests.length}: ` +
        cargo.doctests.join(", "),
    );
    exit(1);
  }

  // Not `console.assert`: it writes to stderr and leaves the exit code at 0, so a self-test built
  // on it passes in CI no matter what it finds.
  const listed = parseNextestList(
    ["pkg::bin:", "    alpha::one", "    beta::two"].join("\n"),
  );
  if (listed.length !== 2) {
    console.error(
      `self-test FAILED: expected 2 listed tests, got ${listed.length}`,
    );
    exit(1);
  }

  // `stripAnsi` has exactly one caller — `run`, which the self-test never reaches — so without this
  // case, replacing its body with `return text;` leaves the self-test printing OK. The regression
  // it would miss is LOUD (every name mismatches at once, as it did in CI), not a silent green, so
  // this is one case and not a suite: it costs a confusing red rather than false confidence.
  const coloured = parseNextestList(
    stripAnsi("pkg::bin:\n    \u001b[32malpha::one\u001b[0m"),
  );
  if (coloured.length !== 1 || coloured[0] !== "alpha::one") {
    console.error(
      `self-test FAILED: a colourised name did not parse to a bare one: ${JSON.stringify(coloured)}`,
    );
    exit(1);
  }

  const clean = compare(cargo, listed);
  if (clean.missing.length !== 0 || clean.extra.length !== 0) {
    console.error(
      "self-test FAILED: identical sets were reported as differing",
    );
    exit(1);
  }
  // The gate must go RED when a test disappears from nextest. Proving that is the whole point:
  // a parity check that cannot fail is worse than none, because it reports confidence it has not
  // earned.
  const dropped = compare(cargo, ["alpha::one"]);
  if (dropped.missing.length !== 1 || dropped.missing[0] !== "beta::two") {
    console.error("self-test FAILED: a dropped test was not detected");
    exit(1);
  }
  const gained = compare(cargo, ["alpha::one", "beta::two", "gamma::three"]);
  if (gained.extra.length !== 1 || gained.extra[0] !== "gamma::three") {
    console.error(
      "self-test FAILED: an unexpected extra test was not detected",
    );
    exit(1);
  }
  console.log(
    "check-nextest-parity self-test OK (detects drops and additions)",
  );
  exit(0);
}

const featuresIndex = argv.indexOf("--features");
const features =
  featuresIndex === -1 ? [] : ["--features", argv[featuresIndex + 1]];

const cargo = parseCargoList(
  run("cargo", [
    "test",
    "--workspace",
    "--locked",
    ...features,
    "--",
    "--list",
  ]),
);
const nextest = parseNextestList(
  run("cargo", [
    "nextest",
    "list",
    "--color",
    "never",
    "--workspace",
    "--locked",
    ...features,
    "--run-ignored",
    "all",
  ]),
);

const { missing, extra } = compare(cargo, nextest);

console.log(
  `cargo test   : ${cargo.tests.length} tests + ${cargo.doctests.length} doctests`,
);
console.log(
  `cargo nextest: ${nextest.length} tests (doctests are not runnable by nextest)`,
);

if (missing.length === 0 && extra.length === 0 && cargo.doctests.length > 0) {
  console.log(
    "\nnextest parity: PASS — nextest executes every non-doctest cargo test executes.",
  );
  exit(0);
}

if (missing.length) {
  console.error(
    `\n${missing.length} test(s) cargo test runs and nextest does NOT:`,
  );
  for (const n of missing.slice(0, 50)) console.error(`  - ${n}`);
}
if (extra.length) {
  console.error(
    `\n${extra.length} test(s) nextest lists and cargo test does NOT:`,
  );
  for (const n of extra.slice(0, 50)) console.error(`  + ${n}`);
}
if (cargo.doctests.length === 0) {
  console.error(
    "\nNo doctests were found. The separate `cargo test --doc` CI step is now a no-op and " +
      "should be removed rather than left implying coverage it does not provide.",
  );
}
console.error("\nnextest parity: FAIL");
exit(1);
