#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

const MODES = {
  server: ["check", "-p", "chancela-server", "--locked"],
  workspace: ["check", "--workspace", "--all-targets", "--locked"],
  tests: ["test", "--workspace", "--no-run", "--locked"],
};

function usage() {
  console.log(`Usage: node scripts/measure-rust-build.mjs [options]

Measure one clean-target and one no-change warm Cargo compile without clearing
the shared Cargo registry or the repository's normal target directory.

Options:
  --mode server|workspace|tests  Compile surface (default: server)
  --target-dir PATH             Empty directory to use instead of a temp target
  --output PATH                 JSON report path (default: dist/build-iteration/...)
  --keep-target                 Keep an automatically-created target directory
  --help                        Show this help`);
}

function parseArgs(argv) {
  const parsed = {
    mode: "server",
    targetDir: undefined,
    output: undefined,
    keepTarget: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help") {
      usage();
      process.exit(0);
    }
    if (argument === "--keep-target") {
      parsed.keepTarget = true;
      continue;
    }
    if (
      argument === "--mode" ||
      argument === "--target-dir" ||
      argument === "--output"
    ) {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        throw new Error(`${argument} requires a value`);
      }
      index += 1;
      if (argument === "--mode") parsed.mode = value;
      if (argument === "--target-dir") parsed.targetDir = value;
      if (argument === "--output") parsed.output = value;
      continue;
    }
    throw new Error(`unknown argument: ${argument}`);
  }

  if (!Object.hasOwn(MODES, parsed.mode)) {
    throw new Error(
      `unknown mode '${parsed.mode}'; expected ${Object.keys(MODES).join(", ")}`,
    );
  }
  return parsed;
}

function commandOutput(command, args) {
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    encoding: "utf8",
    windowsHide: true,
  });
  return result.status === 0 ? result.stdout.trim() : "unavailable";
}

function timedCargo(label, args, targetDir) {
  console.log(`\n${label}: cargo ${args.join(" ")}`);
  const started = process.hrtime.bigint();
  const result = spawnSync("cargo", args, {
    cwd: process.cwd(),
    env: { ...process.env, CARGO_TARGET_DIR: targetDir },
    stdio: "inherit",
    windowsHide: true,
  });
  const elapsedSeconds = Number(process.hrtime.bigint() - started) / 1e9;
  console.log(
    `${label}: ${elapsedSeconds.toFixed(2)}s (exit ${result.status ?? "spawn-error"})`,
  );
  return {
    seconds: Number(elapsedSeconds.toFixed(3)),
    status: result.status,
    signal: result.signal,
    error: result.error?.message,
  };
}

function safeRemoveAutoTarget(targetDir) {
  const tempRoot = path.resolve(os.tmpdir());
  const resolved = path.resolve(targetDir);
  if (
    path.dirname(resolved) !== tempRoot ||
    !path.basename(resolved).startsWith("chancela-build-iteration-")
  ) {
    throw new Error(
      `refusing to remove unexpected target directory: ${resolved}`,
    );
  }
  fs.rmSync(resolved, { recursive: true, force: false });
}

const options = parseArgs(process.argv.slice(2));
const repoRoot = process.cwd();
if (!fs.existsSync(path.join(repoRoot, "Cargo.toml"))) {
  throw new Error("run this command from the Chancela repository root");
}

const automaticTarget = options.targetDir === undefined;
const targetDir = automaticTarget
  ? fs.mkdtempSync(path.join(os.tmpdir(), "chancela-build-iteration-"))
  : path.resolve(repoRoot, options.targetDir);

if (!automaticTarget) {
  if (fs.existsSync(targetDir) && fs.readdirSync(targetDir).length > 0) {
    throw new Error(
      `--target-dir must be empty so the first measurement is honest: ${targetDir}`,
    );
  }
  fs.mkdirSync(targetDir, { recursive: true });
}

const timestamp = new Date().toISOString().replaceAll(":", "-");
const outputPath = path.resolve(
  repoRoot,
  options.output ?? path.join("dist", "build-iteration", `${timestamp}.json`),
);
const cargoArgs = MODES[options.mode];
const cold = timedCargo("clean target", cargoArgs, targetDir);
const warm =
  cold.status === 0 ? timedCargo("no-change warm", cargoArgs, targetDir) : null;
const succeeded = cold.status === 0 && warm?.status === 0;
const gitStatus = commandOutput("git", ["status", "--porcelain=v1"]);
const report = {
  schema_version: 1,
  measured_at: new Date().toISOString(),
  mode: options.mode,
  command: ["cargo", ...cargoArgs],
  semantics: {
    clean_target:
      "empty CARGO_TARGET_DIR; shared registry, git cache, and toolchain are retained",
    warm: "same command and target directory, with no source changes",
  },
  environment: {
    platform: process.platform,
    architecture: process.arch,
    cargo: commandOutput("cargo", ["--version"]),
    rustc: commandOutput("rustc", ["--version"]),
    git_head: commandOutput("git", ["rev-parse", "--short=12", "HEAD"]),
    git_worktree: gitStatus === "" ? "clean" : "dirty",
  },
  measurements: { cold, warm },
  warm_speedup:
    succeeded && warm.seconds > 0
      ? Number((cold.seconds / warm.seconds).toFixed(2))
      : null,
  succeeded,
  target_directory: targetDir,
  target_retained: !automaticTarget || options.keepTarget || !succeeded,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
console.log(`\nReport: ${outputPath}`);
if (report.warm_speedup !== null) {
  console.log(`No-change warm speedup: ${report.warm_speedup.toFixed(2)}x`);
}

if (automaticTarget && !options.keepTarget && succeeded) {
  safeRemoveAutoTarget(targetDir);
  console.log(`Removed isolated target: ${targetDir}`);
}

process.exit(succeeded ? 0 : 1);
