#!/usr/bin/env node

import { spawnSync } from "node:child_process";

const MAX_UNIQUE_PACKAGES = 230;
const MAX_INTERNAL_PACKAGES = 13;
const MAX_ALL_FEATURE_UNIQUE_PACKAGES = 250;
const MAX_ALL_FEATURE_INTERNAL_PACKAGES = 13;
const FORBIDDEN = [
  /^chancela-api$/,
  /^chancela-(?:signing|smartcard|cades|pades|xades|tsa|tsl|cmd|csc|doc)$/,
  /^(?:pcsc|cryptoki|pkcs11|cms|rsa|x509)(?:-|$)/,
  /^(?:signature|lopdf)(?:-|$)/,
];

function cargoTree(extraArguments = []) {
  const result = spawnSync(
    "cargo",
    [
      "tree",
      "-p",
      "chancela-search-projector",
      "--edges",
      "normal",
      "--prefix",
      "none",
      "--format",
      "{p}",
      "--no-dedupe",
      ...extraArguments,
    ],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, shell: false },
  );

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.stderr.write(result.stderr);
    process.exit(result.status ?? 1);
  }
  return [
    ...new Set(
      result.stdout
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter(Boolean),
    ),
  ].sort();
}

const packages = cargoTree();
const allFeaturePackages = cargoTree(["--all-features"]);
const names = packages.map((line) => line.split(/\s+/u, 1)[0]);
const allFeatureNames = allFeaturePackages.map(
  (line) => line.split(/\s+/u, 1)[0],
);
const internal = names.filter((name) => name.startsWith("chancela-"));
const allFeatureInternal = allFeatureNames.filter((name) =>
  name.startsWith("chancela-"),
);
const forbidden = [
  ...new Set(
    allFeatureNames.filter((name) => FORBIDDEN.some((rule) => rule.test(name))),
  ),
];

const failures = [];
if (packages.length > MAX_UNIQUE_PACKAGES) {
  failures.push(
    `unique normal-graph packages ${packages.length} exceed ${MAX_UNIQUE_PACKAGES}`,
  );
}
if (internal.length > MAX_INTERNAL_PACKAGES) {
  failures.push(
    `internal normal-graph packages ${internal.length} exceed ${MAX_INTERNAL_PACKAGES}`,
  );
}
if (allFeaturePackages.length > MAX_ALL_FEATURE_UNIQUE_PACKAGES) {
  failures.push(
    `unique all-features normal-graph packages ${allFeaturePackages.length} exceed ${MAX_ALL_FEATURE_UNIQUE_PACKAGES}`,
  );
}
if (allFeatureInternal.length > MAX_ALL_FEATURE_INTERNAL_PACKAGES) {
  failures.push(
    `internal all-features normal-graph packages ${allFeatureInternal.length} exceed ${MAX_ALL_FEATURE_INTERNAL_PACKAGES}`,
  );
}
if (forbidden.length > 0) {
  failures.push(`forbidden normal dependencies: ${forbidden.join(", ")}`);
}

if (failures.length > 0) {
  console.error("search-projector dependency boundary failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log(
  `search-projector dependency boundary OK: default ${packages.length}/${MAX_UNIQUE_PACKAGES} unique, ` +
    `${internal.length}/${MAX_INTERNAL_PACKAGES} internal; all-features ` +
    `${allFeaturePackages.length}/${MAX_ALL_FEATURE_UNIQUE_PACKAGES} unique, ` +
    `${allFeatureInternal.length}/${MAX_ALL_FEATURE_INTERNAL_PACKAGES} internal; 0 forbidden`,
);
