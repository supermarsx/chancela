import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

const checks = [
  {
    label: "root package.json",
    file: "package.json",
    read: () => readJsonVersion("package.json"),
  },
  {
    label: "apps/web/package.json",
    file: "apps/web/package.json",
    read: () => readJsonVersion("apps/web/package.json"),
  },
  {
    label: "apps/desktop/package.json",
    file: "apps/desktop/package.json",
    read: () => readJsonVersion("apps/desktop/package.json"),
  },
  {
    label: "Cargo.toml [workspace.package]",
    file: "Cargo.toml",
    read: () => readTomlString("Cargo.toml", "workspace.package", "version"),
  },
  {
    label: "apps/desktop/src-tauri/Cargo.toml [package]",
    file: "apps/desktop/src-tauri/Cargo.toml",
    read: () =>
      readTomlString("apps/desktop/src-tauri/Cargo.toml", "package", "version"),
  },
  {
    label: "apps/desktop/src-tauri/tauri.conf.json",
    file: "apps/desktop/src-tauri/tauri.conf.json",
    read: () => readJsonVersion("apps/desktop/src-tauri/tauri.conf.json"),
  },
];

try {
  const versions = checks.map((check) => ({
    label: check.label,
    file: check.file,
    version: check.read(),
  }));

  const distinctVersions = new Set(versions.map(({ version }) => version));
  if (distinctVersions.size === 1) {
    const [version] = distinctVersions;
    console.log(`Release metadata versions are consistent: ${version}`);
    for (const item of versions) {
      console.log(`  ${item.label}: ${item.version}`);
    }
    process.exit(0);
  }

  console.error("Release metadata version mismatch.");
  console.error("All release metadata version fields must match exactly:");
  for (const item of versions) {
    console.error(`  ${item.label}: ${item.version}`);
  }

  const groups = new Map();
  for (const item of versions) {
    const group = groups.get(item.version) ?? [];
    group.push(item.label);
    groups.set(item.version, group);
  }

  console.error("");
  console.error("Versions found:");
  for (const [version, labels] of groups) {
    console.error(`  ${version}: ${labels.join(", ")}`);
  }

  process.exit(1);
} catch (error) {
  console.error(`Version check failed: ${error.message}`);
  process.exit(1);
}

function readJsonVersion(relativePath) {
  const data = JSON.parse(readFile(relativePath));
  if (typeof data.version !== "string" || data.version.length === 0) {
    throw new Error(
      `${relativePath} is missing a non-empty string "version" field`,
    );
  }
  return data.version;
}

function readTomlString(relativePath, sectionName, key) {
  let currentSection = "";
  const lines = readFile(relativePath)
    .replace(/^\uFEFF/, "")
    .split(/\r?\n/);

  for (const line of lines) {
    const sectionMatch = line.match(/^\s*\[([^\]]+)\]\s*(?:#.*)?$/);
    if (sectionMatch) {
      currentSection = sectionMatch[1].trim();
      continue;
    }

    if (currentSection !== sectionName) {
      continue;
    }

    const keyMatch = line.match(
      new RegExp(`^\\s*${escapeRegExp(key)}\\s*=\\s*"([^"]*)"\\s*(?:#.*)?$`),
    );
    if (keyMatch) {
      if (keyMatch[1].length === 0) {
        throw new Error(`${relativePath} [${sectionName}] ${key} is empty`);
      }
      return keyMatch[1];
    }
  }

  throw new Error(`${relativePath} is missing [${sectionName}] ${key}`);
}

function readFile(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
