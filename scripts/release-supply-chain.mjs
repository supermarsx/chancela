#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(scriptPath), "..");

function usage() {
  console.error(`Usage:
  node scripts/release-supply-chain.mjs sbom --output <file> [--package <tarball>]
  node scripts/release-supply-chain.mjs check --input <file>`);
}

function fail(message) {
  console.error(`[release-supply-chain] ${message}`);
  process.exit(1);
}

function parseOptions(args) {
  const options = new Map();
  for (let i = 0; i < args.length; i += 1) {
    const key = args[i];
    if (!key.startsWith("--")) fail(`Unexpected argument: ${key}`);
    const value = args[i + 1];
    if (!value || value.startsWith("--")) fail(`Missing value for ${key}`);
    options.set(key.slice(2), value);
    i += 1;
  }
  return options;
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(repoRoot, relativePath), "utf8"));
}

function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

function shortHash(value) {
  return crypto.createHash("sha1").update(value).digest("hex").slice(0, 12);
}

function purlEncode(value) {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function npmNameFromLockPath(lockPath) {
  const parts = lockPath.split("/node_modules/");
  return parts[parts.length - 1];
}

function npmBomRef(lockPath, name, version) {
  return `npm:${name}@${version}:${shortHash(lockPath)}`;
}

function npmPurl(name, version) {
  if (name.startsWith("@") && name.includes("/")) {
    const [scope, packageName] = name.split("/");
    return `pkg:npm/${purlEncode(scope)}/${purlEncode(packageName)}@${purlEncode(version)}`;
  }
  return `pkg:npm/${purlEncode(name)}@${purlEncode(version)}`;
}

function cargoBomRef(pkg) {
  return `cargo:${pkg.name}@${pkg.version}:${shortHash(pkg.id)}`;
}

function cargoPurl(pkg) {
  return `pkg:cargo/${purlEncode(pkg.name)}@${purlEncode(pkg.version)}`;
}

function licenseField(license) {
  if (!license) return undefined;
  return [{ expression: license }];
}

function loadNpmLockComponents() {
  const lockPath = path.join(repoRoot, "package-lock.json");
  if (!fs.existsSync(lockPath)) return { components: [], dependencies: [] };

  const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  const packages = lock.packages ?? {};
  const componentByPath = new Map();
  const components = [];

  for (const [lockPackagePath, entry] of Object.entries(packages)) {
    if (!lockPackagePath || !entry.version) continue;
    const name = entry.name ?? npmNameFromLockPath(lockPackagePath);
    if (!name || name.startsWith("node_modules/")) continue;

    const bomRef = npmBomRef(lockPackagePath, name, entry.version);
    componentByPath.set(lockPackagePath, {
      bomRef,
      name,
      version: entry.version,
    });

    const component = {
      type: "library",
      "bom-ref": bomRef,
      name,
      version: entry.version,
      purl: npmPurl(name, entry.version),
      scope: entry.dev ? "optional" : "required",
      properties: [
        { name: "chancela:ecosystem", value: "npm" },
        { name: "chancela:npm:lockPath", value: lockPackagePath },
        {
          name: "chancela:npm:devDependency",
          value: String(Boolean(entry.dev)),
        },
      ],
    };
    if (entry.license) component.licenses = licenseField(entry.license);
    if (entry.resolved) {
      component.externalReferences = [
        { type: "distribution", url: entry.resolved },
      ];
    }
    components.push(component);
  }

  const dependencies = [];
  for (const [lockPackagePath, entry] of Object.entries(packages)) {
    if (!lockPackagePath || !entry.version) continue;
    const from = componentByPath.get(lockPackagePath);
    if (!from) continue;

    const names = new Set([
      ...Object.keys(entry.dependencies ?? {}),
      ...Object.keys(entry.optionalDependencies ?? {}),
      ...Object.keys(entry.peerDependencies ?? {}),
    ]);
    const dependsOn = [];
    for (const name of names) {
      const directPath = `${lockPackagePath}/node_modules/${name}`;
      const hoistedPath = `node_modules/${name}`;
      const target =
        componentByPath.get(directPath) ?? componentByPath.get(hoistedPath);
      if (target) dependsOn.push(target.bomRef);
    }

    dependencies.push({
      ref: from.bomRef,
      dependsOn: [...new Set(dependsOn)].sort(),
    });
  }

  return { components, dependencies };
}

function loadCargoComponents() {
  const lockPath = path.join(repoRoot, "Cargo.lock");
  if (!fs.existsSync(lockPath)) return { components: [], dependencies: [] };

  let metadata;
  try {
    const stdout = execFileSync(
      "cargo",
      ["metadata", "--locked", "--format-version", "1"],
      {
        cwd: repoRoot,
        encoding: "utf8",
        maxBuffer: 128 * 1024 * 1024,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    metadata = JSON.parse(stdout);
  } catch (error) {
    fail(
      `cargo metadata failed: ${error.stderr?.toString().trim() || error.message}`,
    );
  }

  const workspaceMembers = new Set(metadata.workspace_members ?? []);
  const packageById = new Map(metadata.packages.map((pkg) => [pkg.id, pkg]));
  const components = metadata.packages.map((pkg) => {
    const component = {
      type: workspaceMembers.has(pkg.id) ? "application" : "library",
      "bom-ref": cargoBomRef(pkg),
      name: pkg.name,
      version: pkg.version,
      purl: cargoPurl(pkg),
      scope: "required",
      properties: [
        { name: "chancela:ecosystem", value: "cargo" },
        { name: "chancela:cargo:source", value: pkg.source ?? "workspace" },
      ],
    };
    const licenses = licenseField(pkg.license);
    if (licenses) component.licenses = licenses;
    return component;
  });

  const dependencies = (metadata.resolve?.nodes ?? [])
    .map((node) => {
      const pkg = packageById.get(node.id);
      if (!pkg) return null;
      const dependsOn = (node.deps ?? [])
        .map((dep) => packageById.get(dep.pkg))
        .filter(Boolean)
        .map((depPkg) => cargoBomRef(depPkg));
      return {
        ref: cargoBomRef(pkg),
        dependsOn: [...new Set(dependsOn)].sort(),
      };
    })
    .filter(Boolean);

  return { components, dependencies };
}

function releasePackageProperties(packagePath) {
  if (!packagePath) return [];
  const absolutePath = path.resolve(repoRoot, packagePath);
  if (!fs.existsSync(absolutePath))
    fail(`Release package not found: ${packagePath}`);
  const relativePath = path
    .relative(repoRoot, absolutePath)
    .split(path.sep)
    .join("/");
  return [
    { name: "chancela:release-package:path", value: relativePath },
    {
      name: "chancela:release-package:sizeBytes",
      value: String(fs.statSync(absolutePath).size),
    },
    {
      name: "chancela:release-package:sha256",
      value: sha256File(absolutePath),
    },
  ];
}

function generateSbom(outputPath, packagePath) {
  const rootPackage = readJson("package.json");
  const npm = loadNpmLockComponents();
  const cargo = loadCargoComponents();
  const components = [...npm.components, ...cargo.components].sort((a, b) =>
    `${a.name}@${a.version}:${a["bom-ref"]}`.localeCompare(
      `${b.name}@${b.version}:${b["bom-ref"]}`,
    ),
  );
  const dependencies = [...npm.dependencies, ...cargo.dependencies].sort(
    (a, b) => a.ref.localeCompare(b.ref),
  );

  const bom = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: "Chancela",
          name: "release-supply-chain",
          version: rootPackage.version ?? "0.0.0",
        },
      ],
      component: {
        type: "application",
        "bom-ref": `application:${rootPackage.name}@${rootPackage.version ?? "0.0.0"}`,
        name: rootPackage.name,
        version: rootPackage.version ?? "0.0.0",
      },
      properties: [
        {
          name: "chancela:sbom:source",
          value: "package-lock.json and cargo metadata --locked",
        },
        ...releasePackageProperties(packagePath),
      ],
    },
    components,
    dependencies,
  };

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(bom, null, 2)}\n`, "utf8");
  console.log(
    `[release-supply-chain] Wrote ${path.relative(repoRoot, outputPath)} with ${components.length} components`,
  );
}

function checkSbom(inputPath) {
  const bom = JSON.parse(fs.readFileSync(inputPath, "utf8"));
  const errors = [];
  if (bom.bomFormat !== "CycloneDX") errors.push("bomFormat is not CycloneDX");
  if (!bom.metadata?.component?.name)
    errors.push("metadata.component.name is missing");
  if (!Array.isArray(bom.components) || bom.components.length === 0) {
    errors.push("components array is empty");
  }

  const refs = new Set();
  for (const component of bom.components ?? []) {
    if (!component["bom-ref"])
      errors.push(`component ${component.name ?? "<unnamed>"} has no bom-ref`);
    if (component["bom-ref"] && refs.has(component["bom-ref"])) {
      errors.push(`duplicate bom-ref: ${component["bom-ref"]}`);
    }
    refs.add(component["bom-ref"]);
  }

  if (fs.existsSync(path.join(repoRoot, "package-lock.json"))) {
    const hasNpm = bom.components.some((component) =>
      component.purl?.startsWith("pkg:npm/"),
    );
    if (!hasNpm)
      errors.push(
        "package-lock.json exists but no npm components were emitted",
      );
  }
  if (fs.existsSync(path.join(repoRoot, "Cargo.lock"))) {
    const hasCargo = bom.components.some((component) =>
      component.purl?.startsWith("pkg:cargo/"),
    );
    if (!hasCargo)
      errors.push("Cargo.lock exists but no cargo components were emitted");
  }

  if (errors.length > 0) fail(`SBOM check failed:\n- ${errors.join("\n- ")}`);
  console.log(
    `[release-supply-chain] SBOM check passed for ${path.relative(repoRoot, inputPath)}`,
  );
}

const [command, ...rest] = process.argv.slice(2);
if (!command) {
  usage();
  process.exit(1);
}

const options = parseOptions(rest);
if (command === "sbom") {
  const output = options.get("output");
  if (!output) fail("Missing --output");
  generateSbom(path.resolve(repoRoot, output), options.get("package"));
} else if (command === "check") {
  const input = options.get("input");
  if (!input) fail("Missing --input");
  checkSbom(path.resolve(repoRoot, input));
} else {
  usage();
  fail(`Unknown command: ${command}`);
}
