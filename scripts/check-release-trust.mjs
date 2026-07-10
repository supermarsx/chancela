#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function usage() {
  console.error(`Usage:
  node scripts/check-release-trust.mjs package --input <release-artifact.json> [--manifest <manifest.json>] [--expect-mode <unsigned-dev|production>]
  node scripts/check-release-trust.mjs docker --input <signing-status.json> [--expect-mode <local-ci|production>]
  node scripts/check-release-trust.mjs self-test`);
}

function fail(message) {
  throw new Error(message);
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

function resolveInput(inputPath) {
  return path.resolve(repoRoot, inputPath);
}

function readJson(inputPath, label) {
  try {
    return JSON.parse(fs.readFileSync(inputPath, "utf8").replace(/^\uFEFF/, ""));
  } catch (error) {
    fail(`${label}: invalid JSON: ${error.message}`);
  }
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireRecord(value, label) {
  if (!isRecord(value)) fail(`${label} must be an object`);
  return value;
}

function requireNonEmptyString(value, label) {
  if (typeof value !== "string" || value.trim().length === 0) {
    fail(`${label} must be a non-empty string`);
  }
  return value;
}

function requireBoolean(value, label) {
  if (typeof value !== "boolean") fail(`${label} must be a boolean`);
  return value;
}

function requireEnum(value, allowed, label) {
  if (!allowed.includes(value)) {
    fail(`${label} must be one of: ${allowed.join(", ")}`);
  }
  return value;
}

function isSha256(value) {
  return typeof value === "string" && /^[a-fA-F0-9]{64}$/.test(value);
}

function requireReason(claim, label) {
  requireNonEmptyString(claim.reason, `${label}.reason`);
}

function evidenceHasAnchor(evidence) {
  const anchorFields = [
    "path",
    "url",
    "uri",
    "sha256",
    "digest",
    "artifactDigest",
    "certificateSha256",
    "certificateFingerprint",
    "issuer",
    "subject",
    "predicateType",
    "runId",
    "workflowRunUrl",
    "transparencyLogEntry",
    "notarizationTicket",
  ];

  return anchorFields.some((field) => {
    const value = evidence[field];
    return typeof value === "string"
      ? value.trim().length > 0
      : typeof value === "number" || typeof value === "boolean";
  });
}

function validateEvidenceObject(evidence, label) {
  requireRecord(evidence, label);
  if (!evidenceHasAnchor(evidence)) {
    fail(
      `${label} must include at least one concrete evidence anchor such as path, url, sha256, digest, issuer, subject, predicateType, or runId`,
    );
  }
}

function requireEvidence(claim, label) {
  if (Array.isArray(claim.evidence)) {
    if (claim.evidence.length === 0) fail(`${label}.evidence must not be empty`);
    claim.evidence.forEach((entry, index) =>
      validateEvidenceObject(entry, `${label}.evidence[${index}]`),
    );
    return;
  }
  validateEvidenceObject(claim.evidence, `${label}.evidence`);
}

function validateCodeSigning(claim, { label, mode, allowUnsignedMode }) {
  requireRecord(claim, label);
  const status = requireEnum(claim.status, ["unsigned", "signed"], `${label}.status`);

  if (status === "unsigned") {
    requireReason(claim, label);
  } else {
    requireNonEmptyString(claim.signer, `${label}.signer`);
    requireEvidence(claim, label);
  }

  if (mode === "production" && status !== "signed") {
    fail(`${label}.status must be signed in production mode`);
  }
  if (mode === allowUnsignedMode && status !== "unsigned") {
    fail(`${label}.status must be unsigned in ${allowUnsignedMode} mode`);
  }

  return status;
}

function validateNotarization(claim, { label, mode, platform, requireForProduction }) {
  requireRecord(claim, label);
  const status = requireEnum(
    claim.status,
    ["not_applicable", "not_notarized", "notarized"],
    `${label}.status`,
  );

  if (status === "notarized") {
    requireEvidence(claim, label);
  } else {
    requireReason(claim, label);
  }

  if (mode === "production" && requireForProduction && status !== "notarized") {
    fail(`${label}.status must be notarized in production mode`);
  }
  if (mode !== "production" && status === "notarized") {
    fail(`${label}.status must not claim notarized outside production mode`);
  }
  if (platform && platform !== "macos" && status === "notarized") {
    fail(`${label}.status cannot be notarized for non-macOS platform ${platform}`);
  }

  return status;
}

function validateAttestation(claim, { label, mode, allowMissingMode }) {
  requireRecord(claim, label);
  const status = requireEnum(claim.status, ["not_attested", "attested"], `${label}.status`);

  if (status === "attested") {
    requireEvidence(claim, label);
  } else {
    requireReason(claim, label);
  }

  if (mode === "production" && status !== "attested") {
    fail(`${label}.status must be attested in production mode`);
  }
  if (mode === allowMissingMode && status !== "not_attested") {
    fail(`${label}.status must be not_attested in ${allowMissingMode} mode`);
  }

  return status;
}

function validatePublication(claim, { label, mode }) {
  requireRecord(claim, label);
  const status = requireEnum(claim.status, ["not_pushed", "pushed"], `${label}.status`);

  if (status === "pushed") {
    requireEvidence(claim, label);
  } else {
    requireReason(claim, label);
  }

  if (mode === "production" && status !== "pushed") {
    fail(`${label}.status must be pushed in production mode`);
  }
  if (mode === "local-ci" && status !== "not_pushed") {
    fail(`${label}.status must be not_pushed in local-ci mode`);
  }

  return status;
}

function validateManifestTrust(manifest, mode) {
  requireRecord(manifest, "manifest");
  const platform = requireNonEmptyString(manifest.platform, "manifest.platform");
  const integrity = requireRecord(manifest.releaseIntegrity, "manifest.releaseIntegrity");
  validateCodeSigning(integrity.codeSigning, {
    label: "manifest.releaseIntegrity.codeSigning",
    mode,
    allowUnsignedMode: "unsigned-dev",
  });
  validateNotarization(integrity.notarization, {
    label: "manifest.releaseIntegrity.notarization",
    mode,
    platform,
    requireForProduction: platform === "macos",
  });
}

function compareManifestSummary(manifest, summary) {
  const summaryTrust = summary.releaseTrust;
  const manifestIntegrity = manifest.releaseIntegrity;
  const manifestPlatform = manifest.platform;

  if (summary.platform !== undefined && summary.platform !== manifestPlatform) {
    fail(
      `release artifact platform ${summary.platform} does not match manifest platform ${manifestPlatform}`,
    );
  }
  if (
    manifestIntegrity.codeSigning.status !== summaryTrust.codeSigning.status ||
    manifestIntegrity.notarization.status !== summaryTrust.notarization.status
  ) {
    fail("release artifact trust status does not match manifest.releaseIntegrity");
  }
}

function validatePackageSummary(summary, { manifest, expectedMode }) {
  requireRecord(summary, "release artifact");
  requireNonEmptyString(summary.package, "release artifact.package");
  if (!isSha256(summary.packageSha256)) {
    fail("release artifact.packageSha256 must be a SHA-256 hex digest");
  }

  const trust = requireRecord(summary.releaseTrust, "release artifact.releaseTrust");
  const mode = requireEnum(
    trust.mode,
    ["unsigned-dev", "production"],
    "release artifact.releaseTrust.mode",
  );
  if (expectedMode && mode !== expectedMode) {
    fail(`release artifact.releaseTrust.mode must be ${expectedMode}, got ${mode}`);
  }

  const platform = summary.platform ?? manifest?.platform;
  if (platform !== undefined) {
    requireNonEmptyString(platform, "release artifact.platform");
  }

  validateCodeSigning(trust.codeSigning, {
    label: "release artifact.releaseTrust.codeSigning",
    mode,
    allowUnsignedMode: "unsigned-dev",
  });
  validateNotarization(trust.notarization, {
    label: "release artifact.releaseTrust.notarization",
    mode,
    platform,
    requireForProduction: platform === "macos",
  });
  validateAttestation(trust.attestation, {
    label: "release artifact.releaseTrust.attestation",
    mode,
    allowMissingMode: "unsigned-dev",
  });

  if (manifest) {
    validateManifestTrust(manifest, mode);
    compareManifestSummary(manifest, summary);
  }

  return mode;
}

function validateDockerStatus(status, { expectedMode }) {
  requireRecord(status, "docker signing status");
  requireNonEmptyString(status.image, "docker signing status.image");

  const trust = requireRecord(status.releaseTrust, "docker signing status.releaseTrust");
  const mode = requireEnum(
    trust.mode,
    ["local-ci", "production"],
    "docker signing status.releaseTrust.mode",
  );
  if (expectedMode && mode !== expectedMode) {
    fail(`docker signing status.releaseTrust.mode must be ${expectedMode}, got ${mode}`);
  }

  const publicationStatus = validatePublication(trust.imagePublication, {
    label: "docker signing status.releaseTrust.imagePublication",
    mode,
  });
  const signingStatus = validateCodeSigning(trust.signing, {
    label: "docker signing status.releaseTrust.signing",
    mode,
    allowUnsignedMode: "local-ci",
  });
  const notarizationStatus = validateNotarization(trust.notarization, {
    label: "docker signing status.releaseTrust.notarization",
    mode,
    platform: "container",
    requireForProduction: false,
  });
  const attestationStatus = validateAttestation(trust.attestation, {
    label: "docker signing status.releaseTrust.attestation",
    mode,
    allowMissingMode: "local-ci",
  });

  if ("imagePushed" in status) {
    const imagePushed = requireBoolean(status.imagePushed, "docker signing status.imagePushed");
    if (imagePushed !== (publicationStatus === "pushed")) {
      fail("docker signing status.imagePushed disagrees with releaseTrust.imagePublication.status");
    }
  }
  if ("signingPerformed" in status) {
    const signingPerformed = requireBoolean(
      status.signingPerformed,
      "docker signing status.signingPerformed",
    );
    if (signingPerformed !== (signingStatus === "signed")) {
      fail("docker signing status.signingPerformed disagrees with releaseTrust.signing.status");
    }
  }
  if ("notarizationPerformed" in status) {
    const notarizationPerformed = requireBoolean(
      status.notarizationPerformed,
      "docker signing status.notarizationPerformed",
    );
    if (notarizationPerformed !== (notarizationStatus === "notarized")) {
      fail("docker signing status.notarizationPerformed disagrees with releaseTrust.notarization.status");
    }
  }
  if ("attestationPerformed" in status) {
    const attestationPerformed = requireBoolean(
      status.attestationPerformed,
      "docker signing status.attestationPerformed",
    );
    if (attestationPerformed !== (attestationStatus === "attested")) {
      fail("docker signing status.attestationPerformed disagrees with releaseTrust.attestation.status");
    }
  }

  return mode;
}

function devPackageFixture() {
  return {
    summary: {
      package: "chancela-0.1.0-linux-x64.tar.gz",
      packageSha256: "a".repeat(64),
      version: "0.1.0",
      platform: "linux",
      arch: "x64",
      releaseTrust: {
        mode: "unsigned-dev",
        codeSigning: {
          status: "unsigned",
          reason: "No code signing step is configured for this workflow.",
        },
        notarization: {
          status: "not_applicable",
          reason: "Notarization applies to macOS release artifacts only.",
        },
        attestation: {
          status: "not_attested",
          reason: "Artifact attestations are not configured for this workflow.",
        },
      },
    },
    manifest: {
      version: "0.1.0",
      platform: "linux",
      arch: "x64",
      releaseIntegrity: {
        codeSigning: {
          status: "unsigned",
          reason: "No code signing step is configured for this workflow.",
        },
        notarization: {
          status: "not_applicable",
          reason: "Notarization applies to macOS release artifacts only.",
        },
      },
    },
  };
}

function localDockerFixture() {
  return {
    image: "chancela-server:ci",
    imagePushed: false,
    signingPerformed: false,
    notarizationPerformed: false,
    attestationPerformed: false,
    releaseTrust: {
      mode: "local-ci",
      imagePublication: {
        status: "not_pushed",
        reason: "The CI image is loaded locally and not pushed to a registry.",
      },
      signing: {
        status: "unsigned",
        reason: "No container signing identity is configured.",
      },
      notarization: {
        status: "not_applicable",
        reason: "Container images are not notarized by this workflow.",
      },
      attestation: {
        status: "not_attested",
        reason: "No image attestation step is configured.",
      },
    },
  };
}

function expectFail(fn, expectedSubstring) {
  try {
    fn();
  } catch (error) {
    if (!error.message.includes(expectedSubstring)) {
      fail(`Expected failure containing "${expectedSubstring}", got "${error.message}"`);
    }
    return;
  }
  fail(`Expected failure containing "${expectedSubstring}"`);
}

function runSelfTest() {
  const { summary, manifest } = devPackageFixture();
  validatePackageSummary(summary, {
    manifest,
    expectedMode: "unsigned-dev",
  });
  validateDockerStatus(localDockerFixture(), { expectedMode: "local-ci" });

  const productionUnsigned = structuredClone(summary);
  productionUnsigned.releaseTrust.mode = "production";
  expectFail(
    () => validatePackageSummary(productionUnsigned, { manifest, expectedMode: "production" }),
    "must be signed in production mode",
  );

  const missingEvidence = structuredClone(summary);
  missingEvidence.releaseTrust.mode = "production";
  missingEvidence.releaseTrust.codeSigning = {
    status: "signed",
    signer: "Example Production Signer",
  };
  missingEvidence.releaseTrust.attestation = {
    status: "attested",
    evidence: { predicateType: "https://slsa.dev/provenance/v1" },
  };
  expectFail(
    () => validatePackageSummary(missingEvidence, { manifest, expectedMode: "production" }),
    "codeSigning.evidence must be an object",
  );

  const dockerOverclaim = localDockerFixture();
  dockerOverclaim.releaseTrust.mode = "production";
  expectFail(
    () => validateDockerStatus(dockerOverclaim, { expectedMode: "production" }),
    "must be pushed in production mode",
  );

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "chancela-release-trust-"));
  try {
    const packagePath = path.join(tmpDir, "release-artifact.json");
    const manifestPath = path.join(tmpDir, "manifest.json");
    fs.writeFileSync(packagePath, `${JSON.stringify(summary, null, 2)}\n`);
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const fileSummary = readJson(packagePath, "self-test release artifact");
    const fileManifest = readJson(manifestPath, "self-test manifest");
    validatePackageSummary(fileSummary, {
      manifest: fileManifest,
      expectedMode: "unsigned-dev",
    });
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  console.log("[release-trust] Self-test passed");
}

try {
  const [command, ...rest] = process.argv.slice(2);
  if (!command) {
    usage();
    process.exit(1);
  }

  if (command === "self-test") {
    if (rest.length > 0) fail("self-test does not accept arguments");
    runSelfTest();
    process.exit(0);
  }

  const options = parseOptions(rest);
  const input = options.get("input");
  if (!input) fail("Missing --input");
  const inputPath = resolveInput(input);
  const expectedMode = options.get("expect-mode");

  if (command === "package") {
    const summary = readJson(inputPath, input);
    const manifestPath = options.get("manifest")
      ? resolveInput(options.get("manifest"))
      : undefined;
    const manifest = manifestPath ? readJson(manifestPath, options.get("manifest")) : undefined;
    const mode = validatePackageSummary(summary, { manifest, expectedMode });
    console.log(`[release-trust] Package trust declaration passed (${mode})`);
  } else if (command === "docker") {
    const status = readJson(inputPath, input);
    const mode = validateDockerStatus(status, { expectedMode });
    console.log(`[release-trust] Docker trust declaration passed (${mode})`);
  } else {
    usage();
    fail(`Unknown command: ${command}`);
  }
} catch (error) {
  console.error(`[release-trust] ${error.message}`);
  process.exit(1);
}
