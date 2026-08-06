#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const canonicalSource = "https://github.com/supermarsx/chancela";
const sourceLabelFiles = [
  "docker/Dockerfile.search-projector",
  "docker/Dockerfile.worker",
  "Dockerfile.hardened",
];

function fail(message) {
  throw new Error(message);
}

function readRepoFile(relativePath) {
  try {
    return fs
      .readFileSync(path.join(repoRoot, relativePath), "utf8")
      .replace(/^\uFEFF/u, "")
      .replace(/\r\n/gu, "\n");
  } catch (error) {
    fail(`${relativePath}: unable to read Dockerfile: ${error.message}`);
  }
}

function parseInstructions(text) {
  const instructions = [];
  let fragments = [];
  let startLine = 0;

  for (const [index, sourceLine] of text.split("\n").entries()) {
    const line = sourceLine.trim();
    if (line.length === 0 || line.startsWith("#")) continue;
    if (fragments.length === 0) startLine = index + 1;

    const continued = /\\\s*$/u.test(line);
    const fragment = continued ? line.replace(/\\\s*$/u, "").trim() : line;
    fragments.push(fragment);
    if (continued) continue;

    const logical = fragments.join(" ").replace(/\s+/gu, " ").trim();
    fragments = [];
    const match = /^(?<keyword>[A-Za-z]+)(?:\s+(?<body>.*))?$/u.exec(logical);
    if (!match?.groups?.keyword) {
      fail(`invalid Dockerfile instruction beginning at line ${startLine}`);
    }
    instructions.push({
      keyword: match.groups.keyword.toUpperCase(),
      body: match.groups.body ?? "",
      line: startLine,
    });
  }
  if (fragments.length > 0) {
    fail(`unterminated Dockerfile continuation beginning at line ${startLine}`);
  }
  return instructions;
}

function parseStages(instructions) {
  const stages = [];
  let currentStage;
  for (const instruction of instructions) {
    if (instruction.keyword === "FROM") {
      const aliasMatch = /\s+AS\s+(?<alias>[A-Za-z0-9_.-]+)$/iu.exec(
        instruction.body,
      );
      currentStage = {
        alias: aliasMatch?.groups?.alias?.toLowerCase() ?? null,
        line: instruction.line,
        instructions: [],
      };
      stages.push(currentStage);
      continue;
    }
    if (!currentStage) {
      fail(
        `projector Dockerfile instruction ${instruction.keyword} at line ${instruction.line} appears before its first FROM`,
      );
    }
    currentStage.instructions.push(instruction);
  }
  return stages;
}

function isSystemPackageInstall(instruction) {
  if (instruction.keyword !== "RUN") return false;
  const tokens = instruction.body
    .toLowerCase()
    .replace(/[^a-z0-9+_.-]+/gu, " ")
    .trim();
  return [
    /\bapt(?:-get)?(?:\s+-[a-z0-9-]+)*\s+install\b/u,
    /\bapk(?:\s+-[a-z0-9-]+)*\s+(?:add|install)\b/u,
    /\b(?:micro)?dnf(?:\s+-[a-z0-9-]+)*\s+install\b/u,
    /\byum(?:\s+-[a-z0-9-]+)*\s+install\b/u,
  ].some((pattern) => pattern.test(tokens));
}

function validateCanonicalSourceLabel(relativePath, text) {
  const labels = [
    ...text.matchAll(/org\.opencontainers\.image\.source="(?<source>[^"]+)"/gu),
  ].map((match) => match.groups.source);
  assert.deepEqual(
    labels,
    [canonicalSource],
    `${relativePath} must declare exactly one canonical OCI source label`,
  );
}

function validateProjectorDockerfile(text) {
  const instructions = parseInstructions(text);
  const stages = parseStages(instructions);
  assert.deepEqual(
    stages.map((stage) => stage.alias),
    ["rust-build", "runtime"],
    "docker/Dockerfile.search-projector stages must be exactly rust-build then runtime",
  );

  const packageInstalls = instructions.filter(isSystemPackageInstall);
  assert.equal(
    packageInstalls.length,
    1,
    "docker/Dockerfile.search-projector must contain exactly one OS package installation instruction",
  );
  // `perl make` is the whole build-stage package set, and both are load-bearing: vendored
  // OpenSSL's `Configure` needs FindBin, Pod::Usage, File::Compare, File::Copy and IPC::Cmd,
  // which the base image's `perl-base` does not carry. `058b26e3` repinned this from `make`
  // alone after splitting the BuildKit target caches showed the projector stage had never been
  // independently buildable — it had been silently consuming vendored-OpenSSL artefacts the
  // server stage left in a shared mount, and alone against pristine mounts it failed in 15
  // seconds. Do NOT "slim" `perl` back out; the exact match below is what keeps anything ELSE
  // (PC/SC headers above all) from joining the list.
  assert.equal(
    packageInstalls[0].body,
    "DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends perl make && rm -rf /var/lib/apt/lists/*",
    "docker/Dockerfile.search-projector OS package installation must be the exact normalized build-dependency contract",
  );

  const executable = instructions
    .map((instruction) => `${instruction.keyword} ${instruction.body}`)
    .join("\n");
  const forbidden = [
    [/\blibpcsclite(?:-dev|1)?\b/iu, "libpcsclite package or library"],
    [/\bpcsc(?:d|lite)?\b/iu, "PC/SC package or runtime reference"],
    [/\bruntime-libs\b/iu, "copied runtime-libs staging directory"],
    [/\bLD_LIBRARY_PATH\b/u, "LD_LIBRARY_PATH override"],
    [
      /COPY\s+--from=rust-build\s+\/[^\n]*\s+\/usr\/local\/lib\/?/iu,
      "Rust-build runtime library copy",
    ],
  ];
  for (const [pattern, description] of forbidden) {
    if (pattern.test(executable)) {
      fail(
        `docker/Dockerfile.search-projector must not contain ${description}`,
      );
    }
  }

  const runtime = stages[1];
  const runtimeCopies = runtime.instructions
    .filter((instruction) => instruction.keyword === "COPY")
    .map((instruction) => instruction.body);
  assert.deepEqual(
    runtimeCopies,
    [
      "--from=rust-build /chancela-search-projector /usr/local/bin/chancela-search-projector",
      "--chown=nonroot:nonroot docker/.chancela-data.keep /var/lib/chancela/.keep",
      "--chown=nonroot:nonroot docker/.chancela-data.keep /var/lib/chancela/search-projector/.keep",
    ],
    "docker/Dockerfile.search-projector runtime COPY instructions must match the exact source contract",
  );
  assert.equal(
    runtime.instructions.filter((instruction) => instruction.keyword === "ADD")
      .length,
    0,
    "docker/Dockerfile.search-projector runtime must not contain ADD instructions",
  );
  if (
    !/cargo build --release --locked -p chancela-search-projector --features "\$\{CARGO_FEATURES\}"/u.test(
      executable,
    )
  ) {
    fail(
      "docker/Dockerfile.search-projector must retain the locked dual-backend projector build",
    );
  }
}

function validateRepository() {
  const texts = new Map(
    sourceLabelFiles.map((relativePath) => [
      relativePath,
      readRepoFile(relativePath),
    ]),
  );
  for (const [relativePath, text] of texts) {
    validateCanonicalSourceLabel(relativePath, text);
  }
  validateProjectorDockerfile(texts.get("docker/Dockerfile.search-projector"));
}

function expectFailure(action, expectedMessage) {
  try {
    action();
  } catch (error) {
    if (!error.message.includes(expectedMessage)) {
      fail(
        `expected failure containing "${expectedMessage}", got "${error.message}"`,
      );
    }
    return;
  }
  fail(`expected failure containing "${expectedMessage}"`);
}

function projectorFixture() {
  return `FROM rust AS rust-build
RUN DEBIAN_FRONTEND=noninteractive apt-get update \\
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \\
        perl make \\
    && rm -rf /var/lib/apt/lists/*
RUN cargo build --release --locked -p chancela-search-projector --features "\${CARGO_FEATURES}"
FROM distroless AS runtime
LABEL org.opencontainers.image.source="${canonicalSource}"
COPY --from=rust-build /chancela-search-projector /usr/local/bin/chancela-search-projector
COPY --chown=nonroot:nonroot docker/.chancela-data.keep /var/lib/chancela/.keep
COPY --chown=nonroot:nonroot docker/.chancela-data.keep /var/lib/chancela/search-projector/.keep
`;
}

function runSelfTest() {
  const valid = projectorFixture();
  validateCanonicalSourceLabel("fixture", valid);
  validateProjectorDockerfile(valid);

  expectFailure(
    () =>
      validateProjectorDockerfile(
        valid.replace("perl make \\", "perl make libpcsclite-dev \\"),
      ),
    "exact normalized build-dependency contract",
  );
  for (const install of [
    "apt install curl",
    "apt-get -qq install curl",
    "apk add curl",
    "dnf install curl",
    "microdnf install curl",
    "yum install curl",
  ]) {
    expectFailure(
      () =>
        validateProjectorDockerfile(
          valid.replace("RUN cargo build", `RUN ${install}\nRUN cargo build`),
        ),
      "exactly one OS package installation",
    );
  }
  expectFailure(
    () =>
      validateProjectorDockerfile(
        valid.replace("--from=rust-build", "--from=0"),
      ),
    "runtime COPY instructions must match",
  );
  expectFailure(
    () =>
      validateProjectorDockerfile(
        valid
          .replace(
            "FROM distroless AS runtime",
            "FROM rust-build AS projector-copy\nFROM distroless AS runtime",
          )
          .replace("--from=rust-build", "--from=projector-copy"),
      ),
    "stages must be exactly",
  );
  expectFailure(
    () =>
      validateProjectorDockerfile(
        valid.replace(
          "FROM distroless AS runtime",
          "RUN mkdir /runtime-libs\nFROM distroless AS runtime",
        ),
      ),
    "runtime-libs",
  );
  expectFailure(
    () =>
      validateProjectorDockerfile(
        valid.replace(
          "FROM distroless AS runtime",
          "FROM distroless AS runtime\nENV LD_LIBRARY_PATH=/usr/local/lib",
        ),
      ),
    "LD_LIBRARY_PATH",
  );
  expectFailure(
    () =>
      validateProjectorDockerfile(
        valid.replace(
          "COPY --from=rust-build /chancela-search-projector",
          "COPY --from=rust-build /libpcsclite.so.1 /usr/local/lib/\n" +
            "COPY --from=rust-build /chancela-search-projector",
        ),
      ),
    "libpcsclite",
  );
  expectFailure(
    () =>
      validateCanonicalSourceLabel(
        "fixture",
        valid.replace(canonicalSource, "https://github.com/chancela/chancela"),
      ),
    "canonical OCI source label",
  );

  console.log("[docker-image-contracts] Self-test passed");
}

try {
  const command = process.argv[2] ?? "check";
  if (process.argv.length > 3 || !["check", "self-test"].includes(command)) {
    fail(
      "usage: node scripts/check-docker-image-contracts.mjs [check|self-test]",
    );
  }
  if (command === "self-test") {
    runSelfTest();
  } else {
    validateRepository();
    console.log(
      "[docker-image-contracts] Canonical labels and projector dependency/runtime boundary passed",
    );
  }
} catch (error) {
  console.error(`[docker-image-contracts] ${error.message}`);
  process.exit(1);
}
