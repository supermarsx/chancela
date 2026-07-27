#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

function usage() {
  console.error(`Usage:
  node scripts/check-release-trust.mjs package --input <release-artifact.json> [--manifest <manifest.json>] [--package <tarball>] [--expect-mode <unsigned-dev|production>]
  node scripts/check-release-trust.mjs docker --input <signing-status.json> [--expect-mode <local-ci|published-unsigned|production>] [--image-set <chancela-image-set.json>]
  node scripts/check-release-trust.mjs image-set --input <chancela-image-set.json> [--expect-commit <40-hex-sha>]
  node scripts/check-release-trust.mjs buildkit-attestations --provenance <slsa-v1.json> --sbom <spdx.json>
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
    return JSON.parse(
      fs.readFileSync(inputPath, "utf8").replace(/^\uFEFF/, ""),
    );
  } catch (error) {
    fail(`${label}: invalid JSON: ${error.message}`);
  }
}

function sha256File(inputPath, label) {
  try {
    return crypto
      .createHash("sha256")
      .update(fs.readFileSync(inputPath))
      .digest("hex");
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

function requireNonEmptyRecord(value, label) {
  const record = requireRecord(value, label);
  if (Object.keys(record).length === 0) {
    fail(`${label} must be a non-empty object`);
  }
  return record;
}

function requireNonEmptyString(value, label) {
  if (typeof value !== "string" || value.trim().length === 0) {
    fail(`${label} must be a non-empty string`);
  }
  return value;
}

function validateBuildKitAttestationPayloads(provenance, sbom) {
  const provenanceLabel = "BuildKit provenance SLSA payload";
  const provenanceRecord = requireNonEmptyRecord(provenance, provenanceLabel);
  const buildDefinition = requireNonEmptyRecord(
    provenanceRecord.buildDefinition,
    `${provenanceLabel}.buildDefinition`,
  );
  const buildType = requireNonEmptyString(
    buildDefinition.buildType,
    `${provenanceLabel}.buildDefinition.buildType`,
  );
  if (
    buildType !==
    "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md"
  ) {
    fail(
      `${provenanceLabel}.buildDefinition.buildType must identify BuildKit SLSA v1`,
    );
  }
  requireNonEmptyRecord(
    buildDefinition.externalParameters,
    `${provenanceLabel}.buildDefinition.externalParameters`,
  );
  const internalParameters = requireNonEmptyRecord(
    buildDefinition.internalParameters,
    `${provenanceLabel}.buildDefinition.internalParameters`,
  );
  const buildConfig = requireNonEmptyRecord(
    internalParameters.buildConfig,
    `${provenanceLabel}.buildDefinition.internalParameters.buildConfig`,
  );
  if (
    !Array.isArray(buildConfig.llbDefinition) ||
    buildConfig.llbDefinition.length === 0
  ) {
    fail(
      `${provenanceLabel}.buildDefinition.internalParameters.buildConfig.llbDefinition must be a non-empty array from mode=max`,
    );
  }
  if (!Array.isArray(buildDefinition.resolvedDependencies)) {
    fail(
      `${provenanceLabel}.buildDefinition.resolvedDependencies must be an array`,
    );
  }
  const runDetails = requireNonEmptyRecord(
    provenanceRecord.runDetails,
    `${provenanceLabel}.runDetails`,
  );
  requireRecord(runDetails.builder, `${provenanceLabel}.runDetails.builder`);
  requireNonEmptyRecord(
    runDetails.metadata,
    `${provenanceLabel}.runDetails.metadata`,
  );
  const invocationId =
    runDetails.metadata.invocationId ?? runDetails.metadata.invocationID;
  requireNonEmptyString(
    invocationId,
    `${provenanceLabel}.runDetails.metadata.invocationId`,
  );

  const sbomLabel = "BuildKit SBOM SPDX payload";
  const sbomRecord = requireNonEmptyRecord(sbom, sbomLabel);
  if (sbomRecord.SPDXID !== "SPDXRef-DOCUMENT") {
    fail(`${sbomLabel}.SPDXID must be SPDXRef-DOCUMENT`);
  }
  const spdxVersion = requireNonEmptyString(
    sbomRecord.spdxVersion,
    `${sbomLabel}.spdxVersion`,
  );
  if (!/^SPDX-\d+\.\d+$/u.test(spdxVersion)) {
    fail(`${sbomLabel}.spdxVersion must identify an SPDX schema version`);
  }
  requireNonEmptyString(sbomRecord.dataLicense, `${sbomLabel}.dataLicense`);
  requireNonEmptyString(
    sbomRecord.documentNamespace,
    `${sbomLabel}.documentNamespace`,
  );
  const creationInfo = requireNonEmptyRecord(
    sbomRecord.creationInfo,
    `${sbomLabel}.creationInfo`,
  );
  if (
    !Array.isArray(creationInfo.creators) ||
    creationInfo.creators.length === 0 ||
    creationInfo.creators.some(
      (creator) => typeof creator !== "string" || creator.trim().length === 0,
    )
  ) {
    fail(`${sbomLabel}.creationInfo.creators must be a non-empty string array`);
  }
  const describedElements = [sbomRecord.packages, sbomRecord.files]
    .filter(Array.isArray)
    .flat();
  if (describedElements.length === 0) {
    fail(`${sbomLabel} must describe at least one package or file`);
  }
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
    if (claim.evidence.length === 0)
      fail(`${label}.evidence must not be empty`);
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
    .reduce(
      (current, key) => (isRecord(current) ? current[key] : undefined),
      entry,
    );
  return predicate(value);
}

function evidenceHasOneOf(claim, fieldPaths, predicate) {
  return evidenceEntries(claim).some((entry) =>
    fieldPaths.some((fieldPath) =>
      fieldPathMatches(entry, fieldPath, predicate),
    ),
  );
}

function requireDockerProductionEvidenceAnchor(
  claim,
  label,
  fieldPaths,
  description,
  predicate,
) {
  if (!evidenceHasOneOf(claim, fieldPaths, predicate)) {
    fail(
      `${label}.evidence must include ${description} for production Docker metadata`,
    );
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
  const status = requireEnum(
    claim.status,
    ["unsigned", "signed"],
    `${label}.status`,
  );

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

function validateNotarization(
  claim,
  { label, mode, platform, requireForProduction },
) {
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
    fail(
      `${label}.status cannot be notarized for non-macOS platform ${platform}`,
    );
  }

  return status;
}

function validateAttestation(claim, { label, mode, allowMissingMode }) {
  requireRecord(claim, label);
  const status = requireEnum(
    claim.status,
    ["not_attested", "attested"],
    `${label}.status`,
  );

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
  const status = requireEnum(
    claim.status,
    ["not_pushed", "pushed"],
    `${label}.status`,
  );

  if (status === "pushed") {
    requireEvidence(claim, label);
  } else {
    requireReason(claim, label);
  }

  if (
    (mode === "production" || mode === "published-unsigned") &&
    status !== "pushed"
  ) {
    fail(`${label}.status must be pushed in ${mode} mode`);
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
    fail(
      "manifest.sourceProvenance.commitSha must be a 40-character Git commit SHA",
    );
  }
  if (manifest.gitCommit !== sourceProvenance.commitSha) {
    fail("manifest.gitCommit must mirror manifest.sourceProvenance.commitSha");
  }
  requireEnum(
    sourceProvenance.sourceTreeState,
    ["clean", "dirty", "unknown"],
    "manifest.sourceProvenance.sourceTreeState",
  );
  requireEnum(
    sourceProvenance.buildMode,
    ["release"],
    "manifest.sourceProvenance.buildMode",
  );

  const platform = requireNonEmptyString(
    manifest.platform,
    "manifest.platform",
  );
  const integrity = requireRecord(
    manifest.releaseIntegrity,
    "manifest.releaseIntegrity",
  );
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
    fail(
      "release artifact trust status does not match manifest.releaseIntegrity",
    );
  }

  const source = requireRecord(summary.source, "release artifact.source");
  if (!isGitSha(source.sha)) {
    fail("release artifact.source.sha must be a 40-character Git commit SHA");
  }
  if (source.sha !== manifest.sourceProvenance.commitSha) {
    fail(
      "release artifact source SHA does not match manifest.sourceProvenance.commitSha",
    );
  }
}

function validatePackageSummary(
  summary,
  { manifest, expectedMode, packagePath },
) {
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

  const trust = requireRecord(
    summary.releaseTrust,
    "release artifact.releaseTrust",
  );
  const mode = requireEnum(
    trust.mode,
    ["unsigned-dev", "production"],
    "release artifact.releaseTrust.mode",
  );
  if ((mode === "production" || expectedMode === "production") && !manifest) {
    fail("Production package validation requires --manifest");
  }
  if (expectedMode && mode !== expectedMode) {
    fail(
      `release artifact.releaseTrust.mode must be ${expectedMode}, got ${mode}`,
    );
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

  const trust = requireRecord(
    status.releaseTrust,
    "docker signing status.releaseTrust",
  );
  const mode = requireEnum(
    trust.mode,
    ["local-ci", "published-unsigned", "production"],
    "docker signing status.releaseTrust.mode",
  );
  if (expectedMode && mode !== expectedMode) {
    fail(
      `docker signing status.releaseTrust.mode must be ${expectedMode}, got ${mode}`,
    );
  }

  const publicationStatus = validatePublication(trust.imagePublication, {
    label: "docker signing status.releaseTrust.imagePublication",
    mode,
  });
  const signingStatus = validateCodeSigning(trust.signing, {
    label: "docker signing status.releaseTrust.signing",
    mode,
    allowUnsignedMode:
      mode === "published-unsigned" ? "published-unsigned" : "local-ci",
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
    requireDockerProductionSigning(
      trust.signing,
      "docker signing status.releaseTrust.signing",
    );
    requireDockerProductionAttestation(
      trust.attestation,
      "docker signing status.releaseTrust.attestation",
    );
  }
  if (mode === "published-unsigned") {
    requireDockerProductionImagePublication(
      trust.imagePublication,
      "docker signing status.releaseTrust.imagePublication",
    );
    if (signingStatus !== "unsigned") {
      fail(
        "docker signing status.releaseTrust.signing.status must be unsigned in published-unsigned mode",
      );
    }
    requireDockerProductionAttestation(
      trust.attestation,
      "docker signing status.releaseTrust.attestation",
    );
    if (
      !status.image.endsWith(`@${trust.imagePublication.evidence.imageDigest}`)
    ) {
      fail(
        "docker signing status.image must use the exact digest in releaseTrust.imagePublication.evidence.imageDigest",
      );
    }
    if (status.imageSetManifest !== "chancela-image-set.json") {
      fail(
        "docker signing status.imageSetManifest must reference chancela-image-set.json in published-unsigned mode",
      );
    }
    if (!isSha256Digest(status.platformDigest)) {
      fail(
        "docker signing status.platformDigest must be a sha256 digest in published-unsigned mode",
      );
    }
    requireEnum(
      status.publicationResolution,
      ["preserved", "published"],
      "docker signing status.publicationResolution",
    );
  }

  if ("imagePushed" in status) {
    const imagePushed = requireBoolean(
      status.imagePushed,
      "docker signing status.imagePushed",
    );
    if (imagePushed !== (publicationStatus === "pushed")) {
      fail(
        "docker signing status.imagePushed disagrees with releaseTrust.imagePublication.status",
      );
    }
  }
  if ("signingPerformed" in status) {
    const signingPerformed = requireBoolean(
      status.signingPerformed,
      "docker signing status.signingPerformed",
    );
    if (signingPerformed !== (signingStatus === "signed")) {
      fail(
        "docker signing status.signingPerformed disagrees with releaseTrust.signing.status",
      );
    }
  }
  if ("notarizationPerformed" in status) {
    const notarizationPerformed = requireBoolean(
      status.notarizationPerformed,
      "docker signing status.notarizationPerformed",
    );
    if (notarizationPerformed !== (notarizationStatus === "notarized")) {
      fail(
        "docker signing status.notarizationPerformed disagrees with releaseTrust.notarization.status",
      );
    }
  }
  if ("attestationPerformed" in status) {
    const attestationPerformed = requireBoolean(
      status.attestationPerformed,
      "docker signing status.attestationPerformed",
    );
    if (attestationPerformed !== (attestationStatus === "attested")) {
      fail(
        "docker signing status.attestationPerformed disagrees with releaseTrust.attestation.status",
      );
    }
  }

  return mode;
}

function validateImageSet(imageSet, { expectedCommit } = {}) {
  requireRecord(imageSet, "GHCR image set");
  if (imageSet.schemaVersion !== 1) {
    fail("GHCR image set.schemaVersion must be 1");
  }
  if (imageSet.status !== "complete") {
    fail("GHCR image set.status must be complete");
  }
  if (
    imageSet.completenessBoundary !==
    "workflow-green-and-image-set-manifest-present"
  ) {
    fail(
      "GHCR image set.completenessBoundary must be workflow-green-and-image-set-manifest-present",
    );
  }

  const source = requireRecord(imageSet.source, "GHCR image set.source");
  const sourceRepository = requireNonEmptyString(
    source.repository,
    "GHCR image set.source.repository",
  );
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(sourceRepository)) {
    fail("GHCR image set.source.repository must be an owner/repository pair");
  }
  if (!isGitSha(source.commitSha)) {
    fail(
      "GHCR image set.source.commitSha must be a 40-character Git commit SHA",
    );
  }
  if (expectedCommit !== undefined) {
    if (!isGitSha(expectedCommit)) {
      fail("--expect-commit must be a 40-character Git commit SHA");
    }
    if (source.commitSha.toLowerCase() !== expectedCommit.toLowerCase()) {
      fail(
        `GHCR image set source commit ${source.commitSha} does not match expected ${expectedCommit}`,
      );
    }
  }
  if (
    !Number.isSafeInteger(source.sourceDateEpoch) ||
    source.sourceDateEpoch <= 0
  ) {
    fail(
      "GHCR image set.source.sourceDateEpoch must be a positive Unix timestamp",
    );
  }
  const expectedCreated = new Date(source.sourceDateEpoch * 1000)
    .toISOString()
    .replace(".000Z", "Z");
  if (source.created !== expectedCreated) {
    fail(
      `GHCR image set.source.created must be derived from sourceDateEpoch (${expectedCreated})`,
    );
  }
  if (!isHttpsUrl(imageSet.workflowRunUrl)) {
    fail("GHCR image set.workflowRunUrl must be an HTTPS workflow/run URL");
  }
  if (!Array.isArray(imageSet.images) || imageSet.images.length !== 3) {
    fail("GHCR image set.images must contain exactly three images");
  }

  const [sourceOwner] = sourceRepository.split("/");
  const expectedRepositories = new Map([
    ["server", `ghcr.io/${sourceOwner.toLowerCase()}/chancela-server`],
    [
      "search-projector",
      `ghcr.io/${sourceOwner.toLowerCase()}/chancela-search-projector`,
    ],
    ["worker", `ghcr.io/${sourceOwner.toLowerCase()}/chancela-worker`],
  ]);
  const seenNames = new Set();
  const seenRepositories = new Set();
  for (const [index, image] of imageSet.images.entries()) {
    const label = `GHCR image set.images[${index}]`;
    requireRecord(image, label);
    const name = requireNonEmptyString(image.name, `${label}.name`);
    const expectedRepository = expectedRepositories.get(name);
    if (!expectedRepository || seenNames.has(name)) {
      fail(`${label}.name must identify each required image exactly once`);
    }
    seenNames.add(name);
    if (image.repository !== expectedRepository) {
      fail(`${label}.repository must be ${expectedRepository}`);
    }
    if (seenRepositories.has(image.repository)) {
      fail(`${label}.repository must be unique`);
    }
    seenRepositories.add(image.repository);
    const expectedTag = `sha-${source.commitSha}`;
    if (image.tag !== expectedTag) {
      fail(`${label}.tag must be ${expectedTag}`);
    }
    if (!isSha256Digest(image.tagDigest)) {
      fail(`${label}.tagDigest must be a sha256 digest`);
    }
    if (image.platform !== "linux/amd64") {
      fail(`${label}.platform must be linux/amd64`);
    }
    if (!isSha256Digest(image.platformDigest)) {
      fail(`${label}.platformDigest must be a sha256 digest`);
    }
    if (image.reference !== `${image.repository}@${image.tagDigest}`) {
      fail(`${label}.reference must use repository@tagDigest`);
    }
    requireEnum(
      image.resolution,
      ["preserved", "published"],
      `${label}.resolution`,
    );
  }
  assert.deepEqual(
    [...seenNames].sort(),
    [...expectedRepositories.keys()].sort(),
    "GHCR image set must contain server, worker, and search-projector",
  );
  if (JSON.stringify(imageSet).toLowerCase().includes(":latest")) {
    fail("GHCR image set must not contain a moving latest tag");
  }
  return source.commitSha;
}

function validateDockerImageSetBinding(status, imageSet) {
  const image = requireNonEmptyString(
    status.image,
    "docker signing status.image",
  );
  const matchingImages = imageSet.images.filter(
    (entry) => entry.reference === image,
  );
  if (matchingImages.length !== 1) {
    fail(
      "docker signing status.image must match exactly one image-set reference",
    );
  }
  const entry = matchingImages[0];
  if (status.imageSetManifest !== "chancela-image-set.json") {
    fail(
      "docker signing status.imageSetManifest must reference chancela-image-set.json",
    );
  }
  if (status.platformDigest !== entry.platformDigest) {
    fail(
      "docker signing status.platformDigest must match the image-set platformDigest",
    );
  }
  if (status.publicationResolution !== entry.resolution) {
    fail(
      "docker signing status.publicationResolution must match the image-set resolution",
    );
  }
  const publication = requireRecord(
    status.releaseTrust?.imagePublication,
    "docker signing status.releaseTrust.imagePublication",
  );
  const evidence = requireRecord(
    publication.evidence,
    "docker signing status.releaseTrust.imagePublication.evidence",
  );
  if (evidence.imageDigest !== entry.tagDigest) {
    fail(
      "docker signing status release trust digest must match the image-set tagDigest",
    );
  }
  if (evidence.repository !== entry.repository) {
    fail(
      "docker signing status release trust repository must match the image-set repository",
    );
  }
  if (evidence.workflowRunUrl !== imageSet.workflowRunUrl) {
    fail(
      "docker signing status release trust publication workflowRunUrl must match the image-set workflowRunUrl",
    );
  }
  const signing = requireRecord(
    status.releaseTrust?.signing,
    "docker signing status.releaseTrust.signing",
  );
  if (signing.status === "signed") {
    const signingEvidence = requireRecord(
      signing.evidence,
      "docker signing status.releaseTrust.signing.evidence",
    );
    if (signingEvidence.imageDigest !== entry.tagDigest) {
      fail(
        "docker signing status release trust signing imageDigest must match the image-set tagDigest",
      );
    }
  }
  const attestation = requireRecord(
    status.releaseTrust?.attestation,
    "docker signing status.releaseTrust.attestation",
  );
  const attestationEvidence = requireRecord(
    attestation.evidence,
    "docker signing status.releaseTrust.attestation.evidence",
  );
  if (attestationEvidence.artifactDigest !== entry.platformDigest) {
    fail(
      "docker signing status release trust attestation artifactDigest must match the image-set platformDigest",
    );
  }
  if (attestationEvidence.workflowRunUrl !== imageSet.workflowRunUrl) {
    fail(
      "docker signing status release trust attestation workflowRunUrl must match the image-set workflowRunUrl",
    );
  }
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
  const workflowRunUrl =
    "https://github.com/example/chancela/actions/runs/123456789";
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
          signingIdentity:
            "https://github.com/example/chancela/.github/workflows/release.yml",
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

function publishedUnsignedDockerFixture() {
  const fixture = productionDockerFixture();
  fixture.signingPerformed = false;
  fixture.releaseTrust.mode = "published-unsigned";
  fixture.imageSetManifest = "chancela-image-set.json";
  fixture.platformDigest = `sha256:${"e".repeat(64)}`;
  fixture.publicationResolution = "published";
  fixture.releaseTrust.attestation.evidence.artifactDigest =
    fixture.platformDigest;
  fixture.releaseTrust.signing = {
    status: "unsigned",
    reason:
      "Normal CI published provenance/SBOM without a container signing identity.",
  };
  return fixture;
}

function completeImageSetFixture() {
  const commitSha = "b".repeat(40);
  const tag = `sha-${commitSha}`;
  const sourceDateEpoch = 1_768_435_200;
  const owner = "example";
  return {
    schemaVersion: 1,
    status: "complete",
    completenessBoundary: "workflow-green-and-image-set-manifest-present",
    source: {
      repository: `${owner}/chancela`,
      commitSha,
      sourceDateEpoch,
      created: "2026-01-15T00:00:00Z",
    },
    workflowRunUrl:
      "https://github.com/example/chancela/actions/runs/123456789",
    images: [
      {
        name: "search-projector",
        repository: `ghcr.io/${owner}/chancela-search-projector`,
        tag,
        tagDigest: `sha256:${"a".repeat(64)}`,
        platform: "linux/amd64",
        platformDigest: `sha256:${"b".repeat(64)}`,
        reference: `ghcr.io/${owner}/chancela-search-projector@sha256:${"a".repeat(64)}`,
        resolution: "preserved",
      },
      {
        name: "server",
        repository: `ghcr.io/${owner}/chancela-server`,
        tag,
        tagDigest: `sha256:${"c".repeat(64)}`,
        platform: "linux/amd64",
        platformDigest: `sha256:${"d".repeat(64)}`,
        reference: `ghcr.io/${owner}/chancela-server@sha256:${"c".repeat(64)}`,
        resolution: "published",
      },
      {
        name: "worker",
        repository: `ghcr.io/${owner}/chancela-worker`,
        tag,
        tagDigest: `sha256:${"e".repeat(64)}`,
        platform: "linux/amd64",
        platformDigest: `sha256:${"f".repeat(64)}`,
        reference: `ghcr.io/${owner}/chancela-worker@sha256:${"e".repeat(64)}`,
        resolution: "published",
      },
    ],
  };
}

function imagetoolsInspectLabels(document) {
  const image = requireRecord(document.image, "imagetools inspect image");
  const selected = image["linux/amd64"] ?? image;
  const config = requireRecord(
    selected.config,
    "imagetools inspect selected image.config",
  );
  return requireRecord(
    config.Labels,
    "imagetools inspect selected image.config.Labels",
  );
}

function directSinglePlatformImagetoolsFixture() {
  return {
    image: {
      config: {
        Labels: {
          "org.opencontainers.image.revision": "b".repeat(40),
          "org.opencontainers.image.created": "2026-01-15T00:00:00Z",
        },
      },
    },
  };
}

function indexedMultiPlatformImagetoolsFixture() {
  return {
    image: {
      "linux/amd64": directSinglePlatformImagetoolsFixture().image,
      "linux/arm64": {
        config: {
          Labels: {
            "org.opencontainers.image.revision": "c".repeat(40),
            "org.opencontainers.image.created": "2026-01-16T00:00:00Z",
          },
        },
      },
    },
  };
}

function buildKitSlsaV1Fixture() {
  return {
    buildDefinition: {
      buildType:
        "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
      externalParameters: {
        configSource: {
          path: "docker/Dockerfile.server",
        },
        request: {
          frontend: "dockerfile.v0",
          locals: [{ name: "context" }, { name: "dockerfile" }],
        },
      },
      internalParameters: {
        builderPlatform: "linux/amd64",
        buildConfig: {
          llbDefinition: [{ id: "step0", op: {} }],
        },
      },
      resolvedDependencies: [],
    },
    runDetails: {
      builder: {
        id: "https://github.com/example/chancela/actions/runs/123456789",
      },
      metadata: {
        invocationId: "fixture-build-invocation",
        startedOn: "2026-01-15T00:00:00Z",
        finishedOn: "2026-01-15T00:01:00Z",
      },
    },
  };
}

function buildKitSpdxFixture() {
  return {
    SPDXID: "SPDXRef-DOCUMENT",
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    documentNamespace:
      "https://example.invalid/chancela/sbom/fixture-build-invocation",
    creationInfo: {
      created: "2026-01-15T00:01:00Z",
      creators: ["Tool: buildkit-fixture"],
    },
    packages: [
      {
        SPDXID: "SPDXRef-Package-chancela",
        name: "chancela",
      },
    ],
  };
}

function expectFail(fn, expectedSubstring) {
  try {
    fn();
  } catch (error) {
    if (!error.message.includes(expectedSubstring)) {
      fail(
        `Expected failure containing "${expectedSubstring}", got "${error.message}"`,
      );
    }
    return;
  }
  fail(`Expected failure containing "${expectedSubstring}"`);
}

function readRepoText(relativePath) {
  const inputPath = path.join(repoRoot, relativePath);
  try {
    return fs
      .readFileSync(inputPath, "utf8")
      .replace(/^\uFEFF/, "")
      .replace(/\r\n/g, "\n");
  } catch (error) {
    fail(
      `${relativePath}: unable to read workflow for static guard: ${error.message}`,
    );
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
    fail(
      `${label} ${outputPath} heredoc must contain valid JSON: ${error.message}`,
    );
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
    fail(
      `${label} must keep ${fieldPath}=${expected}, got ${JSON.stringify(current)}`,
    );
  }
}

function workflowJobBlock(workflowText, workflowPath, jobName) {
  const jobsMatch = /^jobs:\s*$/m.exec(workflowText);
  if (!jobsMatch) fail(`${workflowPath}: missing top-level jobs block`);

  const jobsText = workflowText.slice(jobsMatch.index);
  const jobPattern = new RegExp(
    `^  ${escapeRegExp(jobName)}:\\s*(?:#.*)?$`,
    "m",
  );
  const jobMatch = jobPattern.exec(jobsText);
  if (!jobMatch)
    fail(`${workflowPath}: missing jobs.${jobName} workflow guard target`);

  const start = jobsMatch.index + jobMatch.index;
  const afterJobHeader = workflowText.slice(start + jobMatch[0].length);
  const nextJobMatch = /^  [A-Za-z0-9_-]+:\s*(?:#.*)?$/m.exec(afterJobHeader);
  const end = nextJobMatch
    ? start + jobMatch[0].length + nextJobMatch.index
    : workflowText.length;
  return workflowText.slice(start, end);
}

function workflowWithoutJob(workflowText, workflowPath, jobName) {
  const job = workflowJobBlock(workflowText, workflowPath, jobName);
  return workflowText.replace(job, "");
}

function workflowNamedStepBlock(jobText, workflowPath, stepName) {
  const pattern = new RegExp(
    `^      - name: ${escapeRegExp(stepName)}\\s*$`,
    "m",
  );
  const match = pattern.exec(jobText);
  if (!match) {
    fail(`${workflowPath}: missing workflow step "${stepName}"`);
  }

  const afterHeader = jobText.slice(match.index + match[0].length);
  const nextStep = /^      - (?:name|uses):/mu.exec(afterHeader);
  const end = nextStep
    ? match.index + match[0].length + nextStep.index
    : jobText.length;
  return jobText.slice(match.index, end);
}

function workflowRunBlocks(jobText) {
  const lines = jobText.split(/\r?\n/u);
  const blocks = [];

  for (let index = 0; index < lines.length; index += 1) {
    const match = /^(\s*)run:\s*\|\s*$/u.exec(lines[index]);
    if (!match) continue;

    const indentation = match[1].length;
    const block = [];
    for (index += 1; index < lines.length; index += 1) {
      const line = lines[index];
      if (line.trim() === "") {
        block.push(line);
        continue;
      }
      const lineIndentation = /^\s*/u.exec(line)[0].length;
      if (lineIndentation <= indentation) {
        index -= 1;
        break;
      }
      block.push(line);
    }
    blocks.push(block.join("\n"));
  }

  return blocks.join("\n");
}

function requireWorkflowCommand(block, pattern, message) {
  requireTextMatches(block, pattern, message);
}

function guardCiMetadataWorkflow(ciText) {
  const metadataJob = workflowJobBlock(
    ciText,
    ".github/workflows/ci.yml",
    "metadata",
  );

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
  const dockerJob = workflowJobBlock(
    ciText,
    ".github/workflows/ci.yml",
    "docker",
  );
  const dockerSigningStatus = requireJsonHeredoc(
    dockerJob,
    "dist/docker-security/chancela-server-signing-status.json",
    ".github/workflows/ci.yml jobs.docker signing status",
  );

  requireTextIncludes(
    dockerJob,
    "uses: docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a # v7.3.0",
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
  requireTextMatches(
    dockerJob,
    /^\s+tags:\s*chancela-worker:ci\s*$/m,
    ".github/workflows/ci.yml jobs.docker must use the local chancela-worker:ci image tag",
  );
  requireTextMatches(
    dockerJob,
    /^\s+tags:\s*chancela-search-projector:ci\s*$/m,
    ".github/workflows/ci.yml jobs.docker must use the local search-projector image tag",
  );
  assert.equal(
    [
      ...dockerJob.matchAll(
        /uses:\s+docker\/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a\s+#\s+v7\.3\.0/gmu,
      ),
    ].length,
    3,
    ".github/workflows/ci.yml jobs.docker must build exactly three application images",
  );
  for (const [pattern, message] of [
    [/^\s+push:\s*false\s*$/gmu, "keep all three local image builds unpushed"],
    [/^\s+load:\s*true\s*$/gmu, "load all three local images for smoke checks"],
  ]) {
    assert.equal(
      [...dockerJob.matchAll(pattern)].length,
      3,
      `.github/workflows/ci.yml jobs.docker must ${message}`,
    );
  }
  requireTextIncludes(
    dockerJob,
    "dist/docker-security/chancela-server-signing-status.json",
    ".github/workflows/ci.yml jobs.docker must emit the Docker signing status artifact",
  );
  for (const image of ["chancela-worker", "chancela-search-projector"]) {
    requireTextIncludes(
      dockerJob,
      `dist/docker-security/${image}-signing-status.json`,
      `.github/workflows/ci.yml jobs.docker must emit ${image} trust status`,
    );
  }
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
  for (const image of ["chancela-worker", "chancela-search-projector"]) {
    requireWorkflowCommand(
      dockerJob,
      new RegExp(
        `node\\s+scripts/check-release-trust\\.mjs\\s+docker\\s+--input\\s+dist/docker-security/${image}-signing-status\\.json\\s+--expect-mode\\s+local-ci\\b`,
      ),
      `.github/workflows/ci.yml jobs.docker must validate ${image} trust metadata`,
    );
  }
}

function guardCiGhcrPublishWorkflow(ciText) {
  const workflowPath = ".github/workflows/ci.yml";
  const publishJob = workflowJobBlock(ciText, workflowPath, "publish-ghcr");
  requireTextIncludes(
    ciText,
    "group: ci-${{ github.workflow }}-${{ github.event_name == 'push' && github.ref == 'refs/heads/main' && github.sha || github.ref }}",
    `${workflowPath} concurrency must isolate main publications by commit`,
  );
  requireTextIncludes(
    ciText,
    "cancel-in-progress: ${{ github.event_name != 'push' || github.ref != 'refs/heads/main' }}",
    `${workflowPath} must not cancel an in-progress main push`,
  );
  const jobsMatch = /^jobs:\s*$/mu.exec(ciText);
  if (!jobsMatch) fail(`${workflowPath} must declare a jobs block`);
  const expectedNeeds = [
    ...ciText
      .slice(jobsMatch.index)
      .matchAll(/^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$/gmu),
  ]
    .map((match) => match[1])
    .filter((jobName) => jobName !== "publish-ghcr")
    .sort();
  const needsBlock =
    /^    needs:\s*\n((?:      - [A-Za-z0-9_-]+\s*\n)+)/mu.exec(publishJob);
  if (!needsBlock) {
    fail(
      `${workflowPath} jobs.publish-ghcr must declare a block-list needs dependency`,
    );
  }
  const actualNeeds = needsBlock[1]
    .trim()
    .split(/\r?\n/u)
    .map((line) => line.replace(/^\s*-\s*/u, "").trim())
    .sort();
  assert.deepEqual(
    actualNeeds,
    expectedNeeds,
    `${workflowPath} jobs.publish-ghcr must depend on every required CI job`,
  );

  for (const marker of [
    "github.event_name == 'push'",
    "github.ref == 'refs/heads/main'",
    "contents: read",
    "packages: write",
    "uses: docker/login-action@af1e73f918a031802d376d3c8bbc3fe56130a9b0 # v4.4.0",
    "registry: ghcr.io",
    "password: ${{ github.token }}",
    "ghcr.io/$owner/chancela-server",
    "ghcr.io/$owner/chancela-worker",
    "ghcr.io/$owner/chancela-search-projector",
    'local tag="sha-$GITHUB_SHA"',
    "platforms: linux/amd64",
    "provenance: mode=max,version=v1",
    "sbom: true",
    "outputs: type=image,name=${{ steps.image.outputs.server }},push-by-digest=true,name-canonical=true,push=true",
    "outputs: type=image,name=${{ steps.image.outputs.worker }},push-by-digest=true,name-canonical=true,push=true",
    "outputs: type=image,name=${{ steps.image.outputs.projector }},push-by-digest=true,name-canonical=true,push=true",
    'source_date_epoch="$(git show -s --format=%ct "$GITHUB_SHA")"',
    "SOURCE_DATE_EPOCH=${{ steps.image.outputs.source_date_epoch }}",
    "org.opencontainers.image.created=${{ steps.image.outputs.created }}",
    "org.opencontainers.image.title=Chancela Server",
    "org.opencontainers.image.description=Self-hostable ledger-backed livro de atas server",
    "org.opencontainers.image.title=Chancela Worker",
    "org.opencontainers.image.description=Dedicated background worker for Chancela",
    "org.opencontainers.image.title=Chancela Search Projector",
    "org.opencontainers.image.description=Isolated durable full-search projector for Chancela",
    "CARGO_FEATURES=chancela-server/sqlcipher chancela-server/postgres chancela-server/redis",
    "docker buildx imagetools create",
    "'(^|[[:space:]])MANIFEST_UNKNOWN([:[:space:]]|$)|manifest unknown'",
    'grep -Fqx "$reference: not found"',
    'resolution="preserved"',
    "validate_attestation_payloads()",
    "--format '{{json .Provenance.SLSA}}'",
    "--format '{{json .SBOM.SPDX}}'",
    "node scripts/check-release-trust.mjs buildkit-attestations",
    'validate_attestation_payloads "$reference"',
    "expected exactly one non-attestation linux/amd64 platform manifest",
    '(.image["linux/amd64"] // .image).config.Labels[',
    "all($attestations[];",
    "workflow-green-and-image-set-manifest-present",
    "chancela-image-set.json",
    "name: ghcr-publication-trust-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}",
    "if-no-files-found: error",
    "node scripts/check-release-trust.mjs image-set",
    '--expect-commit "$GITHUB_SHA"',
    "imageSetManifest: $manifest",
    "platformDigest: $platform_digest",
    "publicationResolution: $resolution",
    '--attestation-digest "$platform_digest"',
    '--predicate-type "https://slsa.dev/provenance/v1"',
    "--expect-mode published-unsigned",
  ]) {
    requireTextIncludes(
      publishJob,
      marker,
      `${workflowPath} jobs.publish-ghcr is missing ${marker}`,
    );
  }

  assert.equal(
    [
      ...publishJob.matchAll(
        /uses:\s+docker\/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a\s+#\s+v7\.3\.0/gmu,
      ),
    ].length,
    3,
    `${workflowPath} jobs.publish-ghcr must use the pinned build action three times`,
  );
  assert.equal(
    [...publishJob.matchAll(/\(\$runnable\s*\|\s*length\)\s*==\s*1/gmu)].length,
    2,
    `${workflowPath} jobs.publish-ghcr must require exactly one non-attestation descriptor in digest extraction and contract validation`,
  );
  assert.equal(
    [
      ...publishJob.matchAll(
        /\(\.image\["linux\/amd64"\]\s*\/\/\s*\.image\)\.config\.Labels\[/gmu,
      ),
    ].length,
    2,
    `${workflowPath} jobs.publish-ghcr must read both OCI labels from direct single-platform or indexed image shapes`,
  );
  assert.equal(
    [...publishJob.matchAll(/\.platform\.os\s*==\s*"unknown"/gmu)].length,
    3,
    `${workflowPath} jobs.publish-ghcr must classify and validate attestations only on unknown/unknown platforms`,
  );
  assert.equal(
    [...publishJob.matchAll(/\.platform\.architecture\s*==\s*"unknown"/gmu)]
      .length,
    3,
    `${workflowPath} jobs.publish-ghcr must classify and validate attestations only on unknown/unknown platforms`,
  );
  for (const [pattern, message] of [
    [
      /--format\s+'\{\{json \.Provenance\.SLSA\}\}'/gmu,
      "inspect the actual SLSA provenance payload exactly once in the shared contract validator",
    ],
    [
      /--format\s+'\{\{json \.SBOM\.SPDX\}\}'/gmu,
      "inspect the actual SPDX SBOM payload exactly once in the shared contract validator",
    ],
    [
      /node\s+scripts\/check-release-trust\.mjs\s+buildkit-attestations\b/gmu,
      "validate actual BuildKit attestation payloads exactly once in the shared contract validator",
    ],
    [
      /validate_attestation_payloads\s+"\$reference"/gmu,
      "bind actual attestation payload validation to every validated image reference",
    ],
  ]) {
    assert.equal(
      [...publishJob.matchAll(pattern)].length,
      1,
      `${workflowPath} jobs.publish-ghcr must ${message}`,
    );
  }
  const contractCalls = [
    ...publishJob.matchAll(
      /^\s+validate_contract \\\s*\n\s+"([^"]+)" \\\s*\n\s+"([^"]+)" \\\s*\n\s+"([^"]+)"\s*$/gmu,
    ),
  ].map((match) => match.slice(1));
  assert.deepEqual(
    contractCalls,
    [
      [
        "$repository@$built_digest",
        "$built_document",
        "$built_platform_digest",
      ],
      ["$tag_reference", "$tag_document", "$built_platform_digest"],
      ["$tag_reference", "$tag_document", "$built_platform_digest"],
      ["$tag_reference", "$tag_document", "$built_platform_digest"],
      ["$repository:$tag", "$final_document", "$expected_platform_digest"],
    ],
    `${workflowPath} jobs.publish-ghcr must validate actual payloads on built, preserved, published, and final image references`,
  );
  for (const [pattern, message] of [
    [
      /^\s+platforms:\s*linux\/amd64\s*$/gmu,
      "pin all three images to linux/amd64",
    ],
    [
      /^\s+provenance:\s*mode=max,version=v1\s*$/gmu,
      "enable SLSA v1 maximum provenance on all three images",
    ],
    [/^\s+sbom:\s*true\s*$/gmu, "enable SBOM attestations three times"],
    [
      /^\s+outputs:\s*type=image,name=\$\{\{\s*steps\.image\.outputs\.(?:server|worker|projector)\s*\}\},push-by-digest=true,name-canonical=true,push=true\s*$/gmu,
      "push all three builds only by canonical digest",
    ],
    [
      /^\s+SOURCE_DATE_EPOCH=\$\{\{\s*steps\.image\.outputs\.source_date_epoch\s*\}\}\s*$/gmu,
      "give all three builds the commit-derived SOURCE_DATE_EPOCH",
    ],
    [
      /^\s+org\.opencontainers\.image\.created=\$\{\{\s*steps\.image\.outputs\.created\s*\}\}\s*$/gmu,
      "give all three builds the commit-derived OCI created label",
    ],
    [
      /^\s+org\.opencontainers\.image\.licenses=LicenseRef-Chancela-NonCommercial\s*$/gmu,
      "declare the repository license on all three images",
    ],
    [
      /--expect-mode\s+published-unsigned\b/gmu,
      "validate all three unsigned declarations",
    ],
    [
      /--image-set\s+"\$STATUS_DIR\/chancela-image-set\.json"/gmu,
      "bind all three unsigned declarations to the complete image set",
    ],
  ]) {
    assert.equal(
      [...publishJob.matchAll(pattern)].length,
      3,
      `${workflowPath} jobs.publish-ghcr must ${message}`,
    );
  }
  const finalDigestBuild = publishJob.indexOf(
    "- name: Build and push search projector image by canonical digest",
  );
  const firstNamedTagWrite = publishJob.indexOf(
    "docker buildx imagetools create",
  );
  assert.ok(
    finalDigestBuild >= 0 && firstNamedTagWrite > finalDigestBuild,
    `${workflowPath} jobs.publish-ghcr must finish all canonical digest builds before creating a named tag`,
  );
  requireTextNotMatches(
    publishJob,
    /:latest\b/iu,
    `${workflowPath} jobs.publish-ghcr must not publish or advertise a moving latest tag`,
  );
  requireTextNotMatches(
    publishJob,
    /^\s+push:\s*true\s*$/gmu,
    `${workflowPath} jobs.publish-ghcr must publish only through canonical digest outputs`,
  );
  requireTextNotMatches(
    publishJob,
    /^\s+tags:\s*/gmu,
    `${workflowPath} jobs.publish-ghcr must not pass an implicit moving tag to BuildKit`,
  );
  requireTextNotMatches(
    publishJob,
    /manifest\.\*not found|['"]not found['"]/iu,
    `${workflowPath} jobs.publish-ghcr must fail closed on ambiguous inspection/network errors`,
  );
  requireTextNotMatches(
    publishJob,
    /\b(?:cosign\s+(?:sign|attest)|--signed|signingPerformed["']?\s*:\s*true)\b/iu,
    `${workflowPath} jobs.publish-ghcr must not claim or perform container signing`,
  );
  requireTextNotMatches(
    publishJob,
    /^\s+(?:id-token|attestations):\s*write\s*$/gmu,
    `${workflowPath} jobs.publish-ghcr must not request signing permissions`,
  );
}

function guardReleaseSigningWorkflow(signingText) {
  const workflowPath = ".github/workflows/release-signing.yml";
  const containerJob = workflowJobBlock(signingText, workflowPath, "container");
  const sbomReleaseJob = workflowJobBlock(
    signingText,
    workflowPath,
    "sbom-release",
  );
  const desktopJob = workflowJobBlock(signingText, workflowPath, "desktop");
  const keylessSignStep = workflowNamedStepBlock(
    containerJob,
    workflowPath,
    "Sign and verify all three exact image digests (keyless)",
  );
  const keySignStep = workflowNamedStepBlock(
    containerJob,
    workflowPath,
    "Sign and verify all three exact image digests (private key)",
  );
  const runBlocks = workflowRunBlocks(containerJob);

  for (const marker of [
    "actions: read",
    "packages: write",
    "id-token: write",
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1",
    "name: ${{ steps.cfg.outputs.artifact_name }}",
    "run-id: ${{ steps.cfg.outputs.source_run_id }}",
    "github-token: ${{ github.token }}",
    'source_run_attempt="$(',
    '.run_attempt | select(type == "number" and . >= 1 and . == floor)',
    'echo "source_run_attempt=$source_run_attempt"',
    "ghcr-publication-trust-$source_sha-$source_run_id-$source_run_attempt",
    "actions/workflows/ci.yml/runs?branch=main&event=push&status=success&head_sha=${source_sha}",
    '.head_branch == "main"',
    '.event == "push"',
    '.status == "completed"',
    '.conclusion == "success"',
    "sort_by(.id, .run_attempt)",
    'if [ "${KEYLESS:-}" = "true" ] && [ "${HAVE_COSIGN_KEY:-}" = "true" ]; then',
    "configure exactly one container signing mode: keyless or private key, not both",
    "node scripts/check-release-trust.mjs image-set",
    '--expect-commit "$EXPECTED_SOURCE_SHA"',
    "--expect-mode published-unsigned",
    "for name in server worker search-projector; do",
    "cosign sign --yes",
    "cosign verify",
    "--publication-run-url",
    "--signing-run-url",
    '--attestation-digest "$platform_digest"',
    '--predicate-type "https://slsa.dev/provenance/v1"',
    "--expect-mode production",
    "imageSetManifest: $manifest",
  ]) {
    requireTextIncludes(
      containerJob,
      marker,
      `${workflowPath} jobs.container is missing ${marker}`,
    );
  }

  requireWorkflowCommand(
    containerJob,
    /node\s+scripts\/check-release-trust\.mjs\s+docker[\s\S]*--image-set\s+"\$image_set"[\s\S]*--expect-mode\s+production\b/,
    `${workflowPath} jobs.container must bind signed declarations to the validated image set`,
  );
  requireTextMatches(
    containerJob,
    /all\(\.images\[\];[\s\S]*\.reference\s*\|\s*test\([\s\S]*@sha256:/,
    `${workflowPath} jobs.container must allow only digest references from the image set`,
  );
  requireTextMatches(
    keylessSignStep,
    /id:\s*sign-keyless\s*\n[\s\S]*?for name in server worker search-projector; do[\s\S]*?cosign sign --yes "\$reference"[\s\S]*?cosign verify[\s\S]*?--certificate-identity/,
    `${workflowPath} jobs.container keyless step must sign and verify all three image-set entries`,
  );
  requireTextMatches(
    keySignStep,
    /id:\s*sign-key\s*\n[\s\S]*?for name in server worker search-projector; do[\s\S]*?cosign sign --yes --key env:\/\/COSIGN_PRIVATE_KEY "\$reference"[\s\S]*?cosign verify --key/,
    `${workflowPath} jobs.container private-key step must sign and verify all three image-set entries`,
  );
  for (const marker of [
    'ACTIONS_ID_TOKEN_REQUEST_TOKEN: ""',
    'ACTIONS_ID_TOKEN_REQUEST_URL: ""',
    "COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}",
    "COSIGN_PASSWORD: ${{ secrets.COSIGN_PASSWORD }}",
  ]) {
    requireTextIncludes(
      keySignStep,
      marker,
      `${workflowPath} jobs.container private-key step is missing ${marker}`,
    );
  }
  requireTextMatches(
    containerJob,
    /Record and validate signed digest declarations[\s\S]*?for name in server worker search-projector; do[\s\S]*?--expect-mode production/,
    `${workflowPath} jobs.container must emit production evidence for all three image-set entries`,
  );
  requireTextNotMatches(
    runBlocks,
    /\$\{\{\s*steps\.[A-Za-z0-9_-]+\.outputs\./u,
    `${workflowPath} jobs.container must pass step outputs through env before Bash`,
  );
  requireTextNotMatches(
    keylessSignStep,
    /COSIGN_(?:PRIVATE_KEY|PASSWORD)|--key\b/u,
    `${workflowPath} jobs.container keyless step must not receive cosign private-key secrets`,
  );
  requireTextNotMatches(
    keySignStep,
    /SIGNING_WORKFLOW_IDENTITY|certificate-(?:identity|oidc-issuer)/u,
    `${workflowPath} jobs.container private-key step must not consume keyless identity material`,
  );
  assert.ok(
    [...containerJob.matchAll(/cosign\s+sign\s+--yes\b/gmu)].length === 2,
    `${workflowPath} jobs.container must sign the digest loop in exactly the keyless and key-based branches`,
  );
  assert.ok(
    [...containerJob.matchAll(/cosign\s+verify\b/gmu)].length === 2,
    `${workflowPath} jobs.container must verify the digest loop in both signing modes`,
  );

  for (const [pattern, message] of [
    [
      /docker\/(?:build-push-action|setup-buildx-action)@/iu,
      "must not use Docker image build actions",
    ],
    [/^\s+push:\s*true\s*$/gmu, "must not enable an image push"],
    [/^\s+tags:\s*/gmu, "must not create or update image tags"],
    [
      /\bdocker\s+(?:build|push)\b/iu,
      "must not run docker build or docker push",
    ],
    [/\bimagetools\b/iu, "must not mutate image manifests or tags"],
    [/\bcosign\s+attest\b/iu, "must not add replacement attestations"],
    [
      /\bRELEASE_IMAGE_REPOSITORY\b/u,
      "must not accept an independently writable image repository",
    ],
  ]) {
    requireTextNotMatches(
      containerJob,
      pattern,
      `${workflowPath} jobs.container ${message}`,
    );
  }

  for (const marker of [
    "ref: ${{ github.event_name == 'workflow_dispatch' && github.event.inputs.release_tag || github.ref }}",
    "persist-credentials: false",
    'git rev-parse --verify "refs/tags/$tag^{commit}"',
    "gh release view \"$tag\" --json tagName --jq '.tagName'",
    'if [ "$source_commit" != "$tag_commit" ]; then',
    'echo "source_commit=$source_commit"',
    "chancela:source.commit",
    "chancela:source.tag",
    'sbom_work_dir="$RUNNER_TEMP/chancela-source-sbom"',
    "docker run --rm --network none",
    '-v "$PWD:/src:ro"',
    '-v "$sbom_work_dir:/out"',
    'cp "$bound_sbom" "$sbom"',
    'gh release upload "$TAG" dist/release-signing/chancela-source-sbom.cdx.json --clobber',
  ]) {
    requireTextIncludes(
      sbomReleaseJob,
      marker,
      `${workflowPath} jobs.sbom-release is missing ${marker}`,
    );
  }
  requireTextIncludes(
    desktopJob,
    "gh release view \"$tag\" --json tagName --jq '.tagName'",
    `${workflowPath} jobs.desktop must validate the exact release before downloading artifacts`,
  );
  requireTextNotMatches(
    sbomReleaseJob,
    /-v\s+"\$PWD\/dist\/release-signing:\/out"/u,
    `${workflowPath} jobs.sbom-release must keep third-party SBOM output outside the scanned checkout`,
  );
}

function guardReleaseWorkflow(releaseText) {
  const packageJob = workflowJobBlock(
    releaseText,
    ".github/workflows/release.yml",
    "package",
  );

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
  const releaseSigningText = readRepoText(
    ".github/workflows/release-signing.yml",
  );

  guardCiMetadataWorkflow(ciText);
  guardCiDockerWorkflow(ciText);
  guardCiGhcrPublishWorkflow(ciText);
  guardReleaseWorkflow(releaseText);
  guardReleaseSigningWorkflow(releaseSigningText);
  guardNoProductionReleaseClaims([
    {
      path: ".github/workflows/ci.yml excluding jobs.publish-ghcr",
      text: workflowWithoutJob(
        ciText,
        ".github/workflows/ci.yml",
        "publish-ghcr",
      ),
    },
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
  validateDockerStatus(publishedUnsignedDockerFixture(), {
    expectedMode: "published-unsigned",
  });
  validateDockerStatus(productionDockerFixture(), {
    expectedMode: "production",
  });
  const imageSet = completeImageSetFixture();
  validateImageSet(imageSet, { expectedCommit: imageSet.source.commitSha });
  const expectedImagetoolsLabels = {
    "org.opencontainers.image.revision": "b".repeat(40),
    "org.opencontainers.image.created": "2026-01-15T00:00:00Z",
  };
  assert.deepEqual(
    imagetoolsInspectLabels(directSinglePlatformImagetoolsFixture()),
    expectedImagetoolsLabels,
    "direct single-platform imagetools output must expose OCI labels",
  );
  assert.deepEqual(
    imagetoolsInspectLabels(indexedMultiPlatformImagetoolsFixture()),
    expectedImagetoolsLabels,
    "indexed imagetools output must select linux/amd64 OCI labels",
  );
  expectFail(
    () => imagetoolsInspectLabels({ image: {} }),
    "selected image.config must be an object",
  );
  const imageSetBoundStatus = publishedUnsignedDockerFixture();
  imageSetBoundStatus.image = imageSet.images[1].reference;
  imageSetBoundStatus.platformDigest = imageSet.images[1].platformDigest;
  imageSetBoundStatus.publicationResolution = imageSet.images[1].resolution;
  imageSetBoundStatus.releaseTrust.imagePublication.evidence.imageDigest =
    imageSet.images[1].tagDigest;
  imageSetBoundStatus.releaseTrust.imagePublication.evidence.repository =
    imageSet.images[1].repository;
  imageSetBoundStatus.releaseTrust.attestation.evidence.artifactDigest =
    imageSet.images[1].platformDigest;
  validateDockerImageSetBinding(imageSetBoundStatus, imageSet);
  const signedImageSetBoundStatus = productionDockerFixture();
  signedImageSetBoundStatus.imageSetManifest = "chancela-image-set.json";
  signedImageSetBoundStatus.platformDigest = imageSet.images[1].platformDigest;
  signedImageSetBoundStatus.publicationResolution =
    imageSet.images[1].resolution;
  signedImageSetBoundStatus.releaseTrust.imagePublication.evidence.repository =
    imageSet.images[1].repository;
  signedImageSetBoundStatus.releaseTrust.attestation.evidence.artifactDigest =
    imageSet.images[1].platformDigest;
  validateDockerStatus(signedImageSetBoundStatus, {
    expectedMode: "production",
  });
  validateDockerImageSetBinding(signedImageSetBoundStatus, imageSet);
  guardWorkflowWiring();

  const buildKitProvenance = buildKitSlsaV1Fixture();
  const buildKitSbom = buildKitSpdxFixture();
  validateBuildKitAttestationPayloads(buildKitProvenance, buildKitSbom);
  expectFail(
    () => validateBuildKitAttestationPayloads(null, buildKitSbom),
    "BuildKit provenance SLSA payload must be an object",
  );
  expectFail(
    () => validateBuildKitAttestationPayloads({}, buildKitSbom),
    "BuildKit provenance SLSA payload must be a non-empty object",
  );
  expectFail(
    () =>
      validateBuildKitAttestationPayloads(
        {
          buildType: "https://mobyproject.org/buildkit@v1",
          builder: { id: "" },
          invocation: {},
          materials: [],
          metadata: {},
        },
        buildKitSbom,
      ),
    "BuildKit provenance SLSA payload.buildDefinition must be an object",
  );
  const wrongBuildTypeProvenance = structuredClone(buildKitProvenance);
  wrongBuildTypeProvenance.buildDefinition.buildType =
    "https://example.invalid/not-buildkit";
  expectFail(
    () =>
      validateBuildKitAttestationPayloads(
        wrongBuildTypeProvenance,
        buildKitSbom,
      ),
    "buildType must identify BuildKit SLSA v1",
  );
  const minimumModeProvenance = structuredClone(buildKitProvenance);
  delete minimumModeProvenance.buildDefinition.internalParameters.buildConfig;
  expectFail(
    () =>
      validateBuildKitAttestationPayloads(minimumModeProvenance, buildKitSbom),
    "internalParameters.buildConfig must be an object",
  );
  const strippedMaximumProvenance = structuredClone(buildKitProvenance);
  strippedMaximumProvenance.buildDefinition.internalParameters.buildConfig.llbDefinition =
    [];
  expectFail(
    () =>
      validateBuildKitAttestationPayloads(
        strippedMaximumProvenance,
        buildKitSbom,
      ),
    "llbDefinition must be a non-empty array from mode=max",
  );
  const partialRunDetailsProvenance = structuredClone(buildKitProvenance);
  delete partialRunDetailsProvenance.runDetails.metadata.invocationId;
  expectFail(
    () =>
      validateBuildKitAttestationPayloads(
        partialRunDetailsProvenance,
        buildKitSbom,
      ),
    "runDetails.metadata.invocationId must be a non-empty string",
  );
  expectFail(
    () => validateBuildKitAttestationPayloads(buildKitProvenance, null),
    "BuildKit SBOM SPDX payload must be an object",
  );
  expectFail(
    () => validateBuildKitAttestationPayloads(buildKitProvenance, {}),
    "BuildKit SBOM SPDX payload must be a non-empty object",
  );
  const partialSpdx = structuredClone(buildKitSbom);
  delete partialSpdx.SPDXID;
  expectFail(
    () => validateBuildKitAttestationPayloads(buildKitProvenance, partialSpdx),
    "SPDXID must be SPDXRef-DOCUMENT",
  );
  const malformedSpdxVersion = structuredClone(buildKitSbom);
  malformedSpdxVersion.spdxVersion = "2.3";
  expectFail(
    () =>
      validateBuildKitAttestationPayloads(
        buildKitProvenance,
        malformedSpdxVersion,
      ),
    "spdxVersion must identify an SPDX schema version",
  );
  const strippedSpdx = structuredClone(buildKitSbom);
  delete strippedSpdx.packages;
  expectFail(
    () => validateBuildKitAttestationPayloads(buildKitProvenance, strippedSpdx),
    "must describe at least one package or file",
  );

  const ciText = readRepoText(".github/workflows/ci.yml");
  expectFail(
    () =>
      guardCiGhcrPublishWorkflow(
        ciText.replace(
          '(.image["linux/amd64"] // .image).config.Labels[',
          '.image["linux/amd64"].config.Labels[',
        ),
      ),
    "read both OCI labels from direct single-platform or indexed image shapes",
  );
  expectFail(
    () =>
      guardCiGhcrPublishWorkflow(
        ciText.replace(
          "provenance: mode=max,version=v1",
          "provenance: mode=max",
        ),
      ),
    "enable SLSA v1 maximum provenance on all three images",
  );
  expectFail(
    () =>
      guardCiGhcrPublishWorkflow(
        ciText.replace(
          '--predicate-type "https://slsa.dev/provenance/v1"',
          '--predicate-type "https://slsa.dev/provenance/v0.2"',
        ),
      ),
    '--predicate-type "https://slsa.dev/provenance/v1"',
  );
  expectFail(
    () =>
      guardCiGhcrPublishWorkflow(
        ciText.replace(
          "name: ghcr-publication-trust-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}",
          "name: ghcr-publication-trust-${{ github.sha }}",
        ),
      ),
    "name: ghcr-publication-trust-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}",
  );
  expectFail(
    () =>
      guardCiGhcrPublishWorkflow(
        ciText.replace(
          /(name: ghcr-publication-trust-\$\{\{ github\.sha \}\}-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}[\s\S]*?if-no-files-found:) error/u,
          "$1 ignore",
        ),
      ),
    "if-no-files-found: error",
  );
  expectFail(
    () =>
      guardCiGhcrPublishWorkflow(
        ciText.replace(
          "($runnable | length) == 1",
          "($runnable | length) >= 1",
        ),
      ),
    "require exactly one non-attestation descriptor",
  );
  expectFail(
    () =>
      guardCiGhcrPublishWorkflow(
        ciText.replace("all($attestations[];", "any($attestations[];"),
      ),
    "all($attestations[];",
  );
  expectFail(
    () =>
      guardCiGhcrPublishWorkflow(
        ciText.replace(
          '.platform.architecture == "unknown"',
          '.platform.architecture == "arm64"',
        ),
      ),
    "classify and validate attestations only on unknown/unknown platforms",
  );
  expectFail(
    () =>
      guardCiGhcrPublishWorkflow(
        ciText.replace(
          "--format '{{json .Provenance.SLSA}}'",
          "--format '{{json .Provenance}}'",
        ),
      ),
    "--format '{{json .Provenance.SLSA}}'",
  );
  expectFail(
    () =>
      guardCiGhcrPublishWorkflow(
        ciText.replace(
          "--format '{{json .SBOM.SPDX}}'",
          "--format '{{json .SBOM}}'",
        ),
      ),
    "--format '{{json .SBOM.SPDX}}'",
  );
  expectFail(
    () =>
      guardCiGhcrPublishWorkflow(
        ciText.replace('validate_attestation_payloads "$reference"', ":"),
      ),
    'validate_attestation_payloads "$reference"',
  );
  expectFail(
    () =>
      guardCiGhcrPublishWorkflow(
        ciText.replace(
          '"$repository@$built_digest" \\\n              "$built_document"',
          '"$built_document" \\\n              "$built_document"',
        ),
      ),
    "validate actual payloads on built, preserved, published, and final image references",
  );

  const sourceRunSha = "b".repeat(40);
  const sourceRunOrderingFixture = [
    {
      id: 100,
      run_attempt: 2,
      head_sha: sourceRunSha,
      head_branch: "main",
      event: "push",
      status: "completed",
      conclusion: "success",
    },
    {
      id: 101,
      run_attempt: 1,
      head_sha: sourceRunSha,
      head_branch: "main",
      event: "push",
      status: "completed",
      conclusion: "success",
    },
    {
      id: 102,
      run_attempt: 1,
      head_sha: "0".repeat(40),
      head_branch: "main",
      event: "push",
      status: "completed",
      conclusion: "success",
    },
  ];
  const selectedSourceRun = sourceRunOrderingFixture
    .filter(
      (run) =>
        run.head_sha === sourceRunSha &&
        run.head_branch === "main" &&
        run.event === "push" &&
        run.status === "completed" &&
        run.conclusion === "success",
    )
    .sort(
      (left, right) =>
        left.id - right.id || left.run_attempt - right.run_attempt,
    )
    .at(-1);
  assert.deepEqual(
    [selectedSourceRun.id, selectedSourceRun.run_attempt],
    [101, 1],
    "newer successful run ID must outrank an older run with a higher attempt",
  );

  const releaseSigningText = readRepoText(
    ".github/workflows/release-signing.yml",
  );
  expectFail(
    () =>
      guardReleaseSigningWorkflow(
        releaseSigningText.replace("actions: read", "actions: none"),
      ),
    "actions: read",
  );
  expectFail(
    () =>
      guardReleaseSigningWorkflow(
        releaseSigningText.replace(
          "sort_by(.id, .run_attempt)",
          "sort_by(.run_attempt, .id)",
        ),
      ),
    "sort_by(.id, .run_attempt)",
  );
  expectFail(
    () =>
      guardReleaseSigningWorkflow(
        releaseSigningText.replace(
          'if [ "${KEYLESS:-}" = "true" ] && [ "${HAVE_COSIGN_KEY:-}" = "true" ]; then',
          'if [ "${KEYLESS:-}" = "true" ]; then',
        ),
      ),
    'if [ "${KEYLESS:-}" = "true" ] && [ "${HAVE_COSIGN_KEY:-}" = "true" ]; then',
  );
  expectFail(
    () =>
      guardReleaseSigningWorkflow(
        releaseSigningText.replace(
          "        env:\n          SIGNING_WORKFLOW_IDENTITY:",
          "        env:\n          COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}\n          SIGNING_WORKFLOW_IDENTITY:",
        ),
      ),
    "keyless step must not receive cosign private-key secrets",
  );
  expectFail(
    () =>
      guardReleaseSigningWorkflow(
        releaseSigningText.replace(
          "set -euo pipefail",
          'set -euo pipefail\n          docker push "$reference"',
        ),
      ),
    "docker build or docker push",
  );
  expectFail(
    () =>
      guardReleaseSigningWorkflow(
        releaseSigningText.replaceAll(
          "for name in server worker search-projector; do",
          "for name in server worker; do",
        ),
      ),
    "for name in server worker search-projector; do",
  );
  expectFail(
    () =>
      guardReleaseSigningWorkflow(
        releaseSigningText.replace(
          "set -euo pipefail",
          'set -euo pipefail\n          unsafe="${{ steps.cfg.outputs.identity }}"',
        ),
      ),
    "pass step outputs through env before Bash",
  );
  expectFail(
    () =>
      guardReleaseSigningWorkflow(
        releaseSigningText.replace(
          '--attestation-digest "$platform_digest"',
          '--attestation-digest "$digest"',
        ),
      ),
    '--attestation-digest "$platform_digest"',
  );
  expectFail(
    () =>
      guardReleaseSigningWorkflow(
        releaseSigningText.replace(
          '--predicate-type "https://slsa.dev/provenance/v1"',
          '--predicate-type "https://slsa.dev/provenance/v0.2"',
        ),
      ),
    '--predicate-type "https://slsa.dev/provenance/v1"',
  );
  expectFail(
    () =>
      guardReleaseSigningWorkflow(
        releaseSigningText.replace(
          "ghcr-publication-trust-$source_sha-$source_run_id-$source_run_attempt",
          "ghcr-publication-trust-$source_sha",
        ),
      ),
    "ghcr-publication-trust-$source_sha-$source_run_id-$source_run_attempt",
  );
  expectFail(
    () =>
      guardReleaseSigningWorkflow(
        releaseSigningText.replace(
          "ref: ${{ github.event_name == 'workflow_dispatch' && github.event.inputs.release_tag || github.ref }}",
          "ref: ${{ github.ref }}",
        ),
      ),
    "github.event.inputs.release_tag",
  );
  expectFail(
    () =>
      guardReleaseSigningWorkflow(
        releaseSigningText.replace(
          "gh release view \"$tag\" --json tagName --jq '.tagName'",
          'printf "%s\\n" "$tag"',
        ),
      ),
    'gh release view "$tag"',
  );
  expectFail(
    () =>
      guardReleaseSigningWorkflow(
        releaseSigningText.replaceAll(
          "chancela:source.commit",
          "chancela:source.unbound",
        ),
      ),
    "chancela:source.commit",
  );
  expectFail(
    () =>
      guardReleaseSigningWorkflow(
        releaseSigningText.replace(
          "persist-credentials: false",
          "persist-credentials: true",
        ),
      ),
    "persist-credentials: false",
  );
  expectFail(
    () =>
      guardReleaseSigningWorkflow(
        releaseSigningText.replace('-v "$PWD:/src:ro"', '-v "$PWD:/src"'),
      ),
    '-v "$PWD:/src:ro"',
  );

  expectFail(
    () =>
      requireJsonPathValue(
        {
          status: "unsigned",
          releaseTrust: {
            signing: {
              reason:
                "Generic status fields must not satisfy nested Docker trust paths.",
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
    () =>
      validatePackageSummary(productionUnsigned, {
        manifest,
        expectedMode: "production",
      }),
    "must be signed in production mode",
  );

  const productionWithoutManifest = structuredClone(summary);
  productionWithoutManifest.releaseTrust.mode = "production";
  productionWithoutManifest.releaseTrust.codeSigning = {
    status: "signed",
    signer: "Example Production Signer",
    evidence: {
      certificateSha256: "c".repeat(64),
      workflowRunUrl:
        "https://github.com/example/chancela/actions/runs/123456789",
    },
  };
  productionWithoutManifest.releaseTrust.attestation = {
    status: "attested",
    evidence: {
      predicateType: "https://slsa.dev/provenance/v1",
      digest: `sha256:${"d".repeat(64)}`,
      workflowRunUrl:
        "https://github.com/example/chancela/actions/runs/123456789",
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
    () =>
      validatePackageSummary(missingEvidence, {
        manifest,
        expectedMode: "production",
      }),
    "codeSigning.evidence must be an object",
  );

  const dockerOverclaim = localDockerFixture();
  dockerOverclaim.releaseTrust.mode = "production";
  expectFail(
    () => validateDockerStatus(dockerOverclaim, { expectedMode: "production" }),
    "must be pushed in production mode",
  );

  const publishedWrongDigestReference = publishedUnsignedDockerFixture();
  publishedWrongDigestReference.image = `ghcr.io/example/chancela-server@sha256:${"0".repeat(64)}`;
  expectFail(
    () =>
      validateDockerStatus(publishedWrongDigestReference, {
        expectedMode: "published-unsigned",
      }),
    "must use the exact digest",
  );

  const imageSetMovingTag = structuredClone(imageSet);
  imageSetMovingTag.images[0].tag = "latest";
  expectFail(() => validateImageSet(imageSetMovingTag), ".tag must be sha-");

  const imageSetIncomplete = structuredClone(imageSet);
  imageSetIncomplete.images.pop();
  expectFail(
    () => validateImageSet(imageSetIncomplete),
    "must contain exactly three images",
  );

  const imageSetEpochDrift = structuredClone(imageSet);
  imageSetEpochDrift.source.created = "2026-01-15T00:00:01Z";
  expectFail(
    () => validateImageSet(imageSetEpochDrift),
    "must be derived from sourceDateEpoch",
  );

  const imageSetDigestDrift = structuredClone(imageSet);
  imageSetDigestDrift.images[0].reference = `${imageSetDigestDrift.images[0].repository}@sha256:${"0".repeat(64)}`;
  expectFail(
    () => validateImageSet(imageSetDigestDrift),
    "reference must use repository@tagDigest",
  );

  const imageSetStatusDrift = structuredClone(imageSetBoundStatus);
  imageSetStatusDrift.platformDigest = `sha256:${"0".repeat(64)}`;
  expectFail(
    () => validateDockerImageSetBinding(imageSetStatusDrift, imageSet),
    "platformDigest must match",
  );

  const imageSetAttestationDrift = structuredClone(imageSetBoundStatus);
  imageSetAttestationDrift.releaseTrust.attestation.evidence.artifactDigest =
    imageSet.images[1].tagDigest;
  expectFail(
    () => validateDockerImageSetBinding(imageSetAttestationDrift, imageSet),
    "attestation artifactDigest must match the image-set platformDigest",
  );

  const imageSetSigningDigestDrift = structuredClone(signedImageSetBoundStatus);
  imageSetSigningDigestDrift.releaseTrust.signing.evidence.imageDigest =
    imageSet.images[1].platformDigest;
  expectFail(
    () => validateDockerImageSetBinding(imageSetSigningDigestDrift, imageSet),
    "signing imageDigest must match the image-set tagDigest",
  );

  const imageSetPublicationRunDrift = structuredClone(imageSetBoundStatus);
  imageSetPublicationRunDrift.releaseTrust.imagePublication.evidence.workflowRunUrl =
    "https://github.com/example/chancela/actions/runs/999999999";
  expectFail(
    () => validateDockerImageSetBinding(imageSetPublicationRunDrift, imageSet),
    "publication workflowRunUrl must match the image-set workflowRunUrl",
  );

  const imageSetAttestationRunDrift = structuredClone(imageSetBoundStatus);
  imageSetAttestationRunDrift.releaseTrust.attestation.evidence.workflowRunUrl =
    "https://github.com/example/chancela/actions/runs/999999999";
  expectFail(
    () => validateDockerImageSetBinding(imageSetAttestationRunDrift, imageSet),
    "attestation workflowRunUrl must match the image-set workflowRunUrl",
  );

  expectFail(
    () => validateImageSet(imageSet, { expectedCommit: "0".repeat(40) }),
    "does not match expected",
  );

  const dockerWeakProductionEvidence = productionDockerFixture();
  dockerWeakProductionEvidence.releaseTrust.imagePublication.evidence = {
    url: "https://github.com/example/chancela/actions/runs/123456789",
  };
  expectFail(
    () =>
      validateDockerStatus(dockerWeakProductionEvidence, {
        expectedMode: "production",
      }),
    "imagePublication.evidence must include an image digest",
  );

  const dockerMissingSigningIdentity = productionDockerFixture();
  delete dockerMissingSigningIdentity.releaseTrust.signing.evidence
    .signingIdentity;
  delete dockerMissingSigningIdentity.releaseTrust.signing.evidence
    .certificateFingerprint;
  expectFail(
    () =>
      validateDockerStatus(dockerMissingSigningIdentity, {
        expectedMode: "production",
      }),
    "signing.evidence must include a signing identity or certificate fingerprint",
  );

  const dockerMissingAttestationPredicate = productionDockerFixture();
  delete dockerMissingAttestationPredicate.releaseTrust.attestation.evidence
    .predicateType;
  expectFail(
    () =>
      validateDockerStatus(dockerMissingAttestationPredicate, {
        expectedMode: "production",
      }),
    "attestation.evidence must include an attestation predicate type",
  );

  const dockerMissingWorkflowRunUrl = productionDockerFixture();
  delete dockerMissingWorkflowRunUrl.releaseTrust.attestation.evidence
    .workflowRunUrl;
  expectFail(
    () =>
      validateDockerStatus(dockerMissingWorkflowRunUrl, {
        expectedMode: "production",
      }),
    "attestation.evidence must include an HTTPS workflow/run URL",
  );

  const dockerInsecureWorkflowRunUrl = productionDockerFixture();
  dockerInsecureWorkflowRunUrl.releaseTrust.imagePublication.evidence.workflowRunUrl =
    "http://github.com/example/chancela/actions/runs/123456789";
  expectFail(
    () =>
      validateDockerStatus(dockerInsecureWorkflowRunUrl, {
        expectedMode: "production",
      }),
    "imagePublication.evidence must include an HTTPS workflow/run URL",
  );

  const sourceMismatch = structuredClone(summary);
  sourceMismatch.source.sha = "c".repeat(40);
  expectFail(
    () =>
      validatePackageSummary(sourceMismatch, {
        manifest,
        expectedMode: "unsigned-dev",
      }),
    "source SHA does not match",
  );

  const tmpDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "chancela-release-trust-"),
  );
  try {
    const packagePath = path.join(tmpDir, "release-artifact.json");
    const manifestPath = path.join(tmpDir, "manifest.json");
    const tarballPath = path.join(tmpDir, summary.package);
    fs.writeFileSync(tarballPath, "fixture package bytes\n");
    const packageBoundSummary = structuredClone(summary);
    packageBoundSummary.packageSha256 = sha256File(
      tarballPath,
      "self-test package tarball",
    );

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
  if (command === "buildkit-attestations") {
    const provenanceInput = options.get("provenance");
    const sbomInput = options.get("sbom");
    if (!provenanceInput) fail("Missing --provenance");
    if (!sbomInput) fail("Missing --sbom");
    validateBuildKitAttestationPayloads(
      readJson(resolveInput(provenanceInput), provenanceInput),
      readJson(resolveInput(sbomInput), sbomInput),
    );
    console.log(
      "[release-trust] Actual BuildKit SLSA v1 provenance and SPDX SBOM payloads passed",
    );
    process.exit(0);
  }

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
    const manifest = manifestPath
      ? readJson(manifestPath, options.get("manifest"))
      : undefined;
    const mode = validatePackageSummary(summary, {
      manifest,
      expectedMode,
      packagePath,
    });
    console.log(`[release-trust] Package trust declaration passed (${mode})`);
  } else if (command === "docker") {
    const status = readJson(inputPath, input);
    const mode = validateDockerStatus(status, { expectedMode });
    const imageSetPath = options.get("image-set")
      ? resolveInput(options.get("image-set"))
      : undefined;
    if (imageSetPath) {
      const imageSet = readJson(imageSetPath, options.get("image-set"));
      validateImageSet(imageSet);
      validateDockerImageSetBinding(status, imageSet);
    }
    console.log(
      `[release-trust] Docker trust metadata declaration passed (${mode}); ` +
        "metadata only, actual registry push/signing/attestation was not verified",
    );
  } else if (command === "image-set") {
    const imageSet = readJson(inputPath, input);
    const commitSha = validateImageSet(imageSet, {
      expectedCommit: options.get("expect-commit"),
    });
    console.log(
      `[release-trust] Complete GHCR image-set manifest passed (${commitSha}); ` +
        "registry digests must still be verified by the publishing workflow",
    );
  } else {
    usage();
    fail(`Unknown command: ${command}`);
  }
} catch (error) {
  console.error(`[release-trust] ${error.message}`);
  process.exit(1);
}
