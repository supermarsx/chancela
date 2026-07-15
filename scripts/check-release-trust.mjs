#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function usage() {
  console.error(`Usage:
  node scripts/check-release-trust.mjs package --input <release-artifact.json> [--manifest <manifest.json>] [--package <tarball>] [--expect-mode <unsigned-dev|production>]
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

function sha256File(inputPath, label) {
  try {
    return crypto.createHash("sha256").update(fs.readFileSync(inputPath)).digest("hex");
  } catch (error) {
    fail(`${label}: unable to hash package file: ${error.message}`);
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

function isSha256Digest(value) {
  return typeof value === "string" && /^sha256:[a-fA-F0-9]{64}$/.test(value);
}

function isGitSha(value) {
  return typeof value === "string" && /^[a-fA-F0-9]{40}$/.test(value);
}

function isHttpsUrl(value) {
  if (typeof value !== "string" || value.trim().length === 0) return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:";
  } catch {
    return false;
  }
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

function evidenceEntries(claim) {
  return Array.isArray(claim.evidence) ? claim.evidence : [claim.evidence];
}

function fieldPathMatches(entry, fieldPath, predicate) {
  const value = fieldPath
    .split(".")
    .reduce((current, key) => (isRecord(current) ? current[key] : undefined), entry);
  return predicate(value);
}

function evidenceHasOneOf(claim, fieldPaths, predicate) {
  return evidenceEntries(claim).some((entry) =>
    fieldPaths.some((fieldPath) => fieldPathMatches(entry, fieldPath, predicate)),
  );
}

function requireDockerProductionEvidenceAnchor(claim, label, fieldPaths, description, predicate) {
  if (!evidenceHasOneOf(claim, fieldPaths, predicate)) {
    fail(`${label}.evidence must include ${description} for production Docker metadata`);
  }
}

function requireDockerProductionImagePublication(claim, label) {
  requireDockerProductionEvidenceAnchor(
    claim,
    label,
    ["imageDigest", "digest", "subject.digest"],
    "an image digest such as sha256:<64 hex characters>",
    (value) => isSha256Digest(value),
  );
  requireDockerProductionEvidenceAnchor(
    claim,
    label,
    ["workflowRunUrl", "runUrl"],
    "an HTTPS workflow/run URL",
    isHttpsUrl,
  );
}

function requireDockerProductionSigning(claim, label) {
  requireDockerProductionEvidenceAnchor(
    claim,
    label,
    ["imageDigest", "artifactDigest", "digest", "subject.digest"],
    "an image or artifact digest such as sha256:<64 hex characters>",
    (value) => isSha256Digest(value),
  );
  requireDockerProductionEvidenceAnchor(
    claim,
    label,
    [
      "signingIdentity",
      "identity",
      "subject",
      "certificateSubject",
      "certificateSha256",
      "certificateFingerprint",
    ],
    "a signing identity or certificate fingerprint",
    (value) => typeof value === "string" && value.trim().length > 0,
  );
  requireDockerProductionEvidenceAnchor(
    claim,
    label,
    ["workflowRunUrl", "runUrl"],
    "an HTTPS workflow/run URL",
    isHttpsUrl,
  );
}

function requireDockerProductionAttestation(claim, label) {
  requireDockerProductionEvidenceAnchor(
    claim,
    label,
    ["predicateType", "attestation.predicateType"],
    "an attestation predicate type",
    (value) => typeof value === "string" && value.trim().length > 0,
  );
  requireDockerProductionEvidenceAnchor(
    claim,
    label,
    ["artifactDigest", "subject.digest", "imageDigest", "digest"],
    "an artifact digest such as sha256:<64 hex characters>",
    (value) => isSha256Digest(value),
  );
  requireDockerProductionEvidenceAnchor(
    claim,
    label,
    ["workflowRunUrl", "runUrl"],
    "an HTTPS workflow/run URL",
    isHttpsUrl,
  );
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
  const sourceProvenance = requireRecord(
    manifest.sourceProvenance,
    "manifest.sourceProvenance",
  );
  if (!isGitSha(sourceProvenance.commitSha)) {
    fail("manifest.sourceProvenance.commitSha must be a 40-character Git commit SHA");
  }
  if (manifest.gitCommit !== sourceProvenance.commitSha) {
    fail("manifest.gitCommit must mirror manifest.sourceProvenance.commitSha");
  }
  requireEnum(
    sourceProvenance.sourceTreeState,
    ["clean", "dirty", "unknown"],
    "manifest.sourceProvenance.sourceTreeState",
  );
  requireEnum(sourceProvenance.buildMode, ["release"], "manifest.sourceProvenance.buildMode");

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

  const source = requireRecord(summary.source, "release artifact.source");
  if (!isGitSha(source.sha)) {
    fail("release artifact.source.sha must be a 40-character Git commit SHA");
  }
  if (source.sha !== manifest.sourceProvenance.commitSha) {
    fail("release artifact source SHA does not match manifest.sourceProvenance.commitSha");
  }
}

function validatePackageSummary(summary, { manifest, expectedMode, packagePath }) {
  requireRecord(summary, "release artifact");
  requireNonEmptyString(summary.package, "release artifact.package");
  if (!isSha256(summary.packageSha256)) {
    fail("release artifact.packageSha256 must be a SHA-256 hex digest");
  }

  if (packagePath) {
    const actualPackage = path.basename(packagePath);
    const actualPackageSha256 = sha256File(packagePath, packagePath);
    if (summary.package !== actualPackage) {
      fail(
        `release artifact.package ${summary.package} does not match package file ${actualPackage}`,
      );
    }
    if (summary.packageSha256.toLowerCase() !== actualPackageSha256) {
      fail(
        `release artifact.packageSha256 does not match package file SHA-256 ${actualPackageSha256}`,
      );
    }
  }

  const trust = requireRecord(summary.releaseTrust, "release artifact.releaseTrust");
  const mode = requireEnum(
    trust.mode,
    ["unsigned-dev", "production"],
    "release artifact.releaseTrust.mode",
  );
  if ((mode === "production" || expectedMode === "production") && !manifest) {
    fail("Production package validation requires --manifest");
  }
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

  if (mode === "production") {
    requireDockerProductionImagePublication(
      trust.imagePublication,
      "docker signing status.releaseTrust.imagePublication",
    );
    requireDockerProductionSigning(trust.signing, "docker signing status.releaseTrust.signing");
    requireDockerProductionAttestation(
      trust.attestation,
      "docker signing status.releaseTrust.attestation",
    );
  }

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
      package: "chancela-26.1.0-linux-x64.tar.gz",
      packageSha256: "a".repeat(64),
      version: "26.1.0",
      platform: "linux",
      arch: "x64",
      source: {
        ref: "refs/heads/main",
        sha: "b".repeat(40),
        runId: "123",
      },
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
      version: "26.1.0",
      platform: "linux",
      arch: "x64",
      gitCommit: "b".repeat(40),
      sourceProvenance: {
        commitSha: "b".repeat(40),
        sourceTreeState: "clean",
        buildMode: "release",
      },
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

function productionDockerFixture() {
  const imageDigest = `sha256:${"c".repeat(64)}`;
  const workflowRunUrl = "https://github.com/example/chancela/actions/runs/123456789";
  return {
    image: `ghcr.io/example/chancela-server@${imageDigest}`,
    imagePushed: true,
    signingPerformed: true,
    notarizationPerformed: false,
    attestationPerformed: true,
    releaseTrust: {
      mode: "production",
      imagePublication: {
        status: "pushed",
        evidence: {
          registry: "ghcr.io",
          repository: "example/chancela-server",
          imageDigest,
          workflowRunUrl,
        },
      },
      signing: {
        status: "signed",
        signer: "github-actions:example/chancela/.github/workflows/release.yml",
        evidence: {
          imageDigest,
          signingIdentity: "https://github.com/example/chancela/.github/workflows/release.yml",
          certificateFingerprint: `SHA256:${"d".repeat(64)}`,
          workflowRunUrl,
        },
      },
      notarization: {
        status: "not_applicable",
        reason: "Container images are not notarized by this workflow.",
      },
      attestation: {
        status: "attested",
        evidence: {
          predicateType: "https://slsa.dev/provenance/v1",
          artifactDigest: imageDigest,
          workflowRunUrl,
        },
      },
    },
    note: "This declaration validates Docker release trust metadata only; it does not verify the actual registry push, signature, or attestation.",
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

function readRepoText(relativePath) {
  const inputPath = path.join(repoRoot, relativePath);
  try {
    return fs.readFileSync(inputPath, "utf8").replace(/^\uFEFF/, "").replace(/\r\n/g, "\n");
  } catch (error) {
    fail(`${relativePath}: unable to read workflow for static guard: ${error.message}`);
  }
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function requireTextIncludes(text, needle, message) {
  if (!text.includes(needle)) fail(message);
}

function requireTextMatches(text, pattern, message) {
  if (!pattern.test(text)) fail(message);
}

function requireTextNotMatches(text, pattern, message) {
  if (pattern.test(text)) fail(message);
}

function requireJsonHeredoc(text, outputPath, label) {
  const heredocPattern = new RegExp(
    `cat\\s*>\\s*["']?${escapeRegExp(outputPath)}["']?\\s*<<\\s*(?<quote>['"]?)(?<marker>[A-Za-z_][A-Za-z0-9_]*)\\k<quote>[ \\t]*\\n(?<body>[\\s\\S]*?)\\n[ \\t]*\\k<marker>[ \\t]*(?:\\n|$)`,
    "m",
  );
  const match = heredocPattern.exec(text);
  if (!match?.groups?.body) {
    fail(`${label} must write ${outputPath} with a static JSON heredoc`);
  }

  try {
    return JSON.parse(match.groups.body.replace(/^\uFEFF/, ""));
  } catch (error) {
    fail(`${label} ${outputPath} heredoc must contain valid JSON: ${error.message}`);
  }
}

function requireJsonPathValue(document, fieldPath, expected, label) {
  const keys = fieldPath.split(".");
  let current = document;

  for (const [index, key] of keys.entries()) {
    const currentPath = keys.slice(0, index).join(".") || "<root>";
    if (!isRecord(current)) {
      fail(`${label} must include object ${currentPath} before ${fieldPath}`);
    }
    if (!(key in current)) {
      fail(`${label} must include ${fieldPath}`);
    }
    current = current[key];
  }

  if (current !== expected) {
    fail(`${label} must keep ${fieldPath}=${expected}, got ${JSON.stringify(current)}`);
  }
}

function workflowJobBlock(workflowText, workflowPath, jobName) {
  const jobsMatch = /^jobs:\s*$/m.exec(workflowText);
  if (!jobsMatch) fail(`${workflowPath}: missing top-level jobs block`);

  const jobsText = workflowText.slice(jobsMatch.index);
  const jobPattern = new RegExp(`^  ${escapeRegExp(jobName)}:\\s*(?:#.*)?$`, "m");
  const jobMatch = jobPattern.exec(jobsText);
  if (!jobMatch) fail(`${workflowPath}: missing jobs.${jobName} workflow guard target`);

  const start = jobsMatch.index + jobMatch.index;
  const afterJobHeader = workflowText.slice(start + jobMatch[0].length);
  const nextJobMatch = /^\n  [A-Za-z0-9_-]+:\s*(?:#.*)?$/m.exec(afterJobHeader);
  const end = nextJobMatch ? start + jobMatch[0].length + nextJobMatch.index : workflowText.length;
  return workflowText.slice(start, end);
}

function requireWorkflowCommand(block, pattern, message) {
  requireTextMatches(block, pattern, message);
}

function guardCiMetadataWorkflow(ciText) {
  const metadataJob = workflowJobBlock(ciText, ".github/workflows/ci.yml", "metadata");

  requireWorkflowCommand(
    metadataJob,
    /run:\s*node\s+scripts\/check-release-trust\.mjs\s+self-test\b/,
    ".github/workflows/ci.yml jobs.metadata must run release trust validator self-test",
  );
  requireWorkflowCommand(
    metadataJob,
    /run:\s*node\s+scripts\/release-supply-chain\.mjs\s+self-test\b/,
    ".github/workflows/ci.yml jobs.metadata must run SBOM package linkage self-test",
  );
  requireWorkflowCommand(
    metadataJob,
    /run:\s*node\s+scripts\/check-package-artifacts\.mjs\s+--fixture\s+--skip-dist\b/,
    ".github/workflows/ci.yml jobs.metadata must run package provenance fixture checks",
  );
}

function guardCiDockerWorkflow(ciText) {
  const dockerJob = workflowJobBlock(ciText, ".github/workflows/ci.yml", "docker");
  const dockerSigningStatus = requireJsonHeredoc(
    dockerJob,
    "dist/docker-security/chancela-server-signing-status.json",
    ".github/workflows/ci.yml jobs.docker signing status",
  );

  requireTextIncludes(
    dockerJob,
    "uses: docker/build-push-action@v6",
    ".github/workflows/ci.yml jobs.docker must build through docker/build-push-action",
  );
  requireTextMatches(
    dockerJob,
    /^\s+push:\s*false\s*$/m,
    ".github/workflows/ci.yml jobs.docker must keep Docker push disabled",
  );
  requireTextMatches(
    dockerJob,
    /^\s+load:\s*true\s*$/m,
    ".github/workflows/ci.yml jobs.docker must load the CI image locally",
  );
  requireTextMatches(
    dockerJob,
    /^\s+tags:\s*chancela-server:ci\s*$/m,
    ".github/workflows/ci.yml jobs.docker must use the local chancela-server:ci image tag",
  );
  requireTextIncludes(
    dockerJob,
    "dist/docker-security/chancela-server-signing-status.json",
    ".github/workflows/ci.yml jobs.docker must emit the Docker signing status artifact",
  );
  for (const [field, value] of [
    ["imagePushed", "false"],
    ["signingPerformed", "false"],
    ["notarizationPerformed", "false"],
    ["attestationPerformed", "false"],
  ]) {
    requireTextMatches(
      dockerJob,
      new RegExp(`"${field}"\\s*:\\s*${value}\\b`),
      `.github/workflows/ci.yml jobs.docker signing status must keep ${field}=${value}`,
    );
  }
  for (const [fieldPath, status] of [
    ["releaseTrust.mode", "local-ci"],
    ["releaseTrust.imagePublication.status", "not_pushed"],
    ["releaseTrust.signing.status", "unsigned"],
    ["releaseTrust.notarization.status", "not_applicable"],
    ["releaseTrust.attestation.status", "not_attested"],
  ]) {
    requireJsonPathValue(
      dockerSigningStatus,
      fieldPath,
      status,
      ".github/workflows/ci.yml jobs.docker signing status",
    );
  }
  requireWorkflowCommand(
    dockerJob,
    /node\s+scripts\/check-release-trust\.mjs\s+docker\s+--input\s+dist\/docker-security\/chancela-server-signing-status\.json\s+--expect-mode\s+local-ci\b/,
    ".github/workflows/ci.yml jobs.docker must validate Docker trust metadata in local-ci mode",
  );
}

function guardReleaseWorkflow(releaseText) {
  const packageJob = workflowJobBlock(releaseText, ".github/workflows/release.yml", "package");

  requireWorkflowCommand(
    packageJob,
    /run:\s*npm\s+run\s+test:package-integrity\s+--\s+--require-clean-source\b/,
    ".github/workflows/release.yml jobs.package must run package artifact integrity checks with --require-clean-source",
  );
  requireTextMatches(
    packageJob,
    /releaseTrust\s*=\s*\[ordered\]@\{[\s\S]*?\bmode\s*=\s*'unsigned-dev'/,
    ".github/workflows/release.yml jobs.package must emit releaseTrust.mode = unsigned-dev",
  );
  requireTextMatches(
    packageJob,
    /attestation\s*=\s*\[ordered\]@\{[\s\S]*?\bstatus\s*=\s*'not_attested'/,
    ".github/workflows/release.yml jobs.package must mark package attestation not_attested",
  );
  requireWorkflowCommand(
    packageJob,
    /node\s+scripts\/check-release-trust\.mjs\s+package[\s\S]*--expect-mode\s+unsigned-dev\b/,
    ".github/workflows/release.yml jobs.package must validate release trust metadata in unsigned-dev mode",
  );
  requireWorkflowCommand(
    packageJob,
    /node\s+scripts\/check-release-trust\.mjs\s+package[\s\S]*--package\s+'?\$\{\{\s*steps\.collect\.outputs\.package\s*\}\}'?/,
    ".github/workflows/release.yml jobs.package must validate release trust metadata against the collected package",
  );
  requireWorkflowCommand(
    packageJob,
    /node\s+scripts\/release-supply-chain\.mjs\s+sbom\s+--output\s+\$sbomPath\s+--package\s+'?\$\{\{\s*steps\.collect\.outputs\.package\s*\}\}'?/,
    ".github/workflows/release.yml jobs.package must generate the SBOM with --package linkage",
  );
  requireWorkflowCommand(
    packageJob,
    /node\s+scripts\/release-supply-chain\.mjs\s+check\s+--input\s+\$sbomPath\s+--package\s+'?\$\{\{\s*steps\.collect\.outputs\.package\s*\}\}'?/,
    ".github/workflows/release.yml jobs.package must check the SBOM with --package linkage",
  );
}

function guardNoProductionReleaseClaims(workflowTexts) {
  const combined = workflowTexts
    .map(({ path: workflowPath, text }) => `\n# ${workflowPath}\n${text}`)
    .join("\n");
  const forbiddenPatterns = [
    [
      /\breleaseTrust\b[\s\S]{0,400}?\bmode\s*=\s*['"]production['"]/i,
      "workflow releaseTrust metadata must not claim production mode",
    ],
    [
      /\breleaseTrust\b[\s\S]{0,400}?\b["']mode["']\s*:\s*["']production["']/i,
      "workflow releaseTrust metadata must not claim production mode",
    ],
    [
      /\bstatus\s*=\s*['"](?:signed|notarized|attested|pushed)['"]/i,
      "workflow trust metadata must not claim signed, notarized, attested, or pushed status",
    ],
    [
      /\b["']status["']\s*:\s*["'](?:signed|notarized|attested|pushed)["']/i,
      "workflow trust metadata must not claim signed, notarized, attested, or pushed status",
    ],
    [
      /\b["'](?:imagePushed|signingPerformed|notarizationPerformed|attestationPerformed)["']\s*:\s*true\b/i,
      "workflow Docker trust metadata must not claim push, signing, notarization, or attestation was performed",
    ],
    [
      /^\s*(?:id-token|attestations):\s*write\s*$/im,
      "workflow permissions must not enable OIDC signing or artifact attestations",
    ],
    [
      /^\s*push:\s*true\s*$/im,
      "workflow Docker build configuration must not enable registry push",
    ],
    [
      /uses:\s*(?:docker\/login-action|actions\/attest-build-provenance|slsa-framework\/|sigstore\/)/i,
      "workflow must not introduce registry login, signing, or attestation actions",
    ],
    [
      /\b(?:docker\s+(?:login|push)|cosign\s+(?:sign|attest)|gh\s+attestation|notarytool|stapler|codesign|signtool|osslsigncode)\b/i,
      "workflow must not introduce production signing, notarization, registry, or attestation commands",
    ],
    [
      /\b(?:ghcr\.io|docker\.io|quay\.io|gcr\.io|pkg\.dev|ecr\.)\b/i,
      "workflow must not introduce a production registry target",
    ],
  ];

  for (const [pattern, message] of forbiddenPatterns) {
    requireTextNotMatches(combined, pattern, message);
  }
}

function guardWorkflowWiring() {
  const ciText = readRepoText(".github/workflows/ci.yml");
  const releaseText = readRepoText(".github/workflows/release.yml");

  guardCiMetadataWorkflow(ciText);
  guardCiDockerWorkflow(ciText);
  guardReleaseWorkflow(releaseText);
  guardNoProductionReleaseClaims([
    { path: ".github/workflows/ci.yml", text: ciText },
    { path: ".github/workflows/release.yml", text: releaseText },
  ]);
}

function runSelfTest() {
  const { summary, manifest } = devPackageFixture();
  validatePackageSummary(summary, {
    manifest,
    expectedMode: "unsigned-dev",
  });
  validateDockerStatus(localDockerFixture(), { expectedMode: "local-ci" });
  validateDockerStatus(productionDockerFixture(), { expectedMode: "production" });
  guardWorkflowWiring();

  expectFail(
    () =>
      requireJsonPathValue(
        {
          status: "unsigned",
          releaseTrust: {
            signing: {
              reason: "Generic status fields must not satisfy nested Docker trust paths.",
            },
          },
        },
        "releaseTrust.signing.status",
        "unsigned",
        "self-test Docker signing status",
      ),
    "releaseTrust.signing.status",
  );

  const productionUnsigned = structuredClone(summary);
  productionUnsigned.releaseTrust.mode = "production";
  expectFail(
    () => validatePackageSummary(productionUnsigned, { manifest, expectedMode: "production" }),
    "must be signed in production mode",
  );

  const productionWithoutManifest = structuredClone(summary);
  productionWithoutManifest.releaseTrust.mode = "production";
  productionWithoutManifest.releaseTrust.codeSigning = {
    status: "signed",
    signer: "Example Production Signer",
    evidence: {
      certificateSha256: "c".repeat(64),
      workflowRunUrl: "https://github.com/example/chancela/actions/runs/123456789",
    },
  };
  productionWithoutManifest.releaseTrust.attestation = {
    status: "attested",
    evidence: {
      predicateType: "https://slsa.dev/provenance/v1",
      digest: `sha256:${"d".repeat(64)}`,
      workflowRunUrl: "https://github.com/example/chancela/actions/runs/123456789",
    },
  };
  expectFail(
    () =>
      validatePackageSummary(productionWithoutManifest, {
        manifest: undefined,
      }),
    "Production package validation requires --manifest",
  );
  expectFail(
    () =>
      validatePackageSummary(productionWithoutManifest, {
        manifest: undefined,
        expectedMode: "unsigned-dev",
      }),
    "Production package validation requires --manifest",
  );

  const expectedProductionWithoutManifest = structuredClone(summary);
  expectFail(
    () =>
      validatePackageSummary(expectedProductionWithoutManifest, {
        manifest: undefined,
        expectedMode: "production",
      }),
    "Production package validation requires --manifest",
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

  const dockerWeakProductionEvidence = productionDockerFixture();
  dockerWeakProductionEvidence.releaseTrust.imagePublication.evidence = {
    url: "https://github.com/example/chancela/actions/runs/123456789",
  };
  expectFail(
    () => validateDockerStatus(dockerWeakProductionEvidence, { expectedMode: "production" }),
    "imagePublication.evidence must include an image digest",
  );

  const dockerMissingSigningIdentity = productionDockerFixture();
  delete dockerMissingSigningIdentity.releaseTrust.signing.evidence.signingIdentity;
  delete dockerMissingSigningIdentity.releaseTrust.signing.evidence.certificateFingerprint;
  expectFail(
    () => validateDockerStatus(dockerMissingSigningIdentity, { expectedMode: "production" }),
    "signing.evidence must include a signing identity or certificate fingerprint",
  );

  const dockerMissingAttestationPredicate = productionDockerFixture();
  delete dockerMissingAttestationPredicate.releaseTrust.attestation.evidence.predicateType;
  expectFail(
    () => validateDockerStatus(dockerMissingAttestationPredicate, { expectedMode: "production" }),
    "attestation.evidence must include an attestation predicate type",
  );

  const dockerMissingWorkflowRunUrl = productionDockerFixture();
  delete dockerMissingWorkflowRunUrl.releaseTrust.attestation.evidence.workflowRunUrl;
  expectFail(
    () => validateDockerStatus(dockerMissingWorkflowRunUrl, { expectedMode: "production" }),
    "attestation.evidence must include an HTTPS workflow/run URL",
  );

  const dockerInsecureWorkflowRunUrl = productionDockerFixture();
  dockerInsecureWorkflowRunUrl.releaseTrust.imagePublication.evidence.workflowRunUrl =
    "http://github.com/example/chancela/actions/runs/123456789";
  expectFail(
    () => validateDockerStatus(dockerInsecureWorkflowRunUrl, { expectedMode: "production" }),
    "imagePublication.evidence must include an HTTPS workflow/run URL",
  );

  const sourceMismatch = structuredClone(summary);
  sourceMismatch.source.sha = "c".repeat(40);
  expectFail(
    () => validatePackageSummary(sourceMismatch, { manifest, expectedMode: "unsigned-dev" }),
    "source SHA does not match",
  );

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "chancela-release-trust-"));
  try {
    const packagePath = path.join(tmpDir, "release-artifact.json");
    const manifestPath = path.join(tmpDir, "manifest.json");
    const tarballPath = path.join(tmpDir, summary.package);
    fs.writeFileSync(tarballPath, "fixture package bytes\n");
    const packageBoundSummary = structuredClone(summary);
    packageBoundSummary.packageSha256 = sha256File(tarballPath, "self-test package tarball");

    fs.writeFileSync(packagePath, `${JSON.stringify(summary, null, 2)}\n`);
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const fileSummary = readJson(packagePath, "self-test release artifact");
    const fileManifest = readJson(manifestPath, "self-test manifest");
    validatePackageSummary(fileSummary, {
      manifest: fileManifest,
      expectedMode: "unsigned-dev",
    });

    validatePackageSummary(packageBoundSummary, {
      manifest,
      expectedMode: "unsigned-dev",
      packagePath: tarballPath,
    });

    const packageNameMismatch = structuredClone(packageBoundSummary);
    packageNameMismatch.package = "chancela-26.1.0-windows-x64.tar.gz";
    expectFail(
      () =>
        validatePackageSummary(packageNameMismatch, {
          manifest,
          expectedMode: "unsigned-dev",
          packagePath: tarballPath,
        }),
      "release artifact.package",
    );

    const packageHashMismatch = structuredClone(packageBoundSummary);
    packageHashMismatch.packageSha256 = "0".repeat(64);
    expectFail(
      () =>
        validatePackageSummary(packageHashMismatch, {
          manifest,
          expectedMode: "unsigned-dev",
          packagePath: tarballPath,
        }),
      "release artifact.packageSha256",
    );
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
    const packagePath = options.get("package")
      ? resolveInput(options.get("package"))
      : undefined;
    const manifest = manifestPath ? readJson(manifestPath, options.get("manifest")) : undefined;
    const mode = validatePackageSummary(summary, { manifest, expectedMode, packagePath });
    console.log(`[release-trust] Package trust declaration passed (${mode})`);
  } else if (command === "docker") {
    const status = readJson(inputPath, input);
    const mode = validateDockerStatus(status, { expectedMode });
    console.log(
      `[release-trust] Docker trust metadata declaration passed (${mode}); ` +
        "metadata only, actual registry push/signing/attestation was not verified",
    );
  } else {
    usage();
    fail(`Unknown command: ${command}`);
  }
} catch (error) {
  console.error(`[release-trust] ${error.message}`);
  process.exit(1);
}
