#!/usr/bin/env node
// Emit a TRUTHFUL release signing status document for the opt-in signing
// pipeline (.github/workflows/release-signing.yml).
//
// This helper exists so the signing workflow can never accidentally claim that
// an artifact was signed, pushed, notarized, or attested unless the concrete
// evidence for that claim is present. Every positive status is refused unless
// its supporting evidence anchors (digest, signing identity, workflow run URL,
// attestation predicate type, notarization ticket) are supplied. When no
// signing identity is configured the workflow calls this helper with no
// positive flags and gets an honest "unsigned / not performed" document.
//
// The emitted container document is additionally validated by
// scripts/check-release-trust.mjs (docker mode) in the workflow, so the two
// validators must agree on what counts as evidence.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

function fail(message) {
  console.error(`[release-signing-status] ${message}`);
  process.exit(1);
}

function parseOptions(args) {
  const options = new Map();
  const flags = new Set();
  for (let i = 0; i < args.length; i += 1) {
    const key = args[i];
    if (!key.startsWith("--")) fail(`Unexpected argument: ${key}`);
    const name = key.slice(2);
    const next = args[i + 1];
    if (next === undefined || next.startsWith("--")) {
      flags.add(name);
      continue;
    }
    options.set(name, next);
    i += 1;
  }
  return { options, flags };
}

function isSha256Digest(value) {
  return typeof value === "string" && /^sha256:[a-fA-F0-9]{64}$/.test(value);
}

function isHttpsUrl(value) {
  if (typeof value !== "string" || value.trim().length === 0) return false;
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

function nonEmpty(value) {
  return typeof value === "string" && value.trim().length > 0;
}

// Build a container (Docker/OCI image) signing status document. Any positive
// claim (pushed/signed/attested) is refused unless its evidence is present.
function buildContainerStatus({ options, flags }) {
  const image = options.get("image");
  if (!nonEmpty(image)) fail("container status requires --image <reference>");

  const pushed = flags.has("pushed");
  const signed = flags.has("signed");
  const attested = flags.has("attested");

  const digest = options.get("digest");
  const runUrl = options.get("run-url");
  const identity = options.get("identity");
  const certFingerprint = options.get("cert-fingerprint");
  const predicateType = options.get("predicate-type");
  const registry = options.get("registry");
  const repository = options.get("repository");
  const signer = options.get("signer");

  if (pushed) {
    if (!isSha256Digest(digest)) fail("--pushed requires --digest sha256:<64 hex>");
    if (!isHttpsUrl(runUrl)) fail("--pushed requires an HTTPS --run-url");
  }
  if (signed) {
    if (!pushed) fail("--signed requires --pushed (an image is signed by digest in the registry)");
    if (!nonEmpty(identity) && !nonEmpty(certFingerprint)) {
      fail("--signed requires --identity or --cert-fingerprint");
    }
    if (!nonEmpty(signer)) fail("--signed requires --signer");
  }
  if (attested) {
    if (!signed) fail("--attested requires --signed");
    if (!nonEmpty(predicateType)) fail("--attested requires --predicate-type");
  }

  const mode = pushed && signed && attested ? "production" : "local-ci";
  if (mode === "local-ci" && (pushed || signed || attested)) {
    fail("partial signing state cannot be represented honestly; enable push+sign+attest together");
  }

  const imagePublication = pushed
    ? {
        status: "pushed",
        evidence: {
          ...(registry ? { registry } : {}),
          ...(repository ? { repository } : {}),
          imageDigest: digest,
          workflowRunUrl: runUrl,
        },
      }
    : {
        status: "not_pushed",
        reason:
          options.get("reason-not-pushed") ??
          "No container registry or signing identity is configured; the image was not pushed.",
      };

  const signing = signed
    ? {
        status: "signed",
        signer,
        evidence: {
          imageDigest: digest,
          ...(nonEmpty(identity) ? { signingIdentity: identity } : {}),
          ...(nonEmpty(certFingerprint) ? { certificateFingerprint: certFingerprint } : {}),
          workflowRunUrl: runUrl,
        },
      }
    : {
        status: "unsigned",
        reason:
          options.get("reason-unsigned") ??
          "No container signing identity (cosign keyless OIDC or COSIGN_PRIVATE_KEY) is configured.",
      };

  const attestation = attested
    ? {
        status: "attested",
        evidence: {
          predicateType,
          artifactDigest: digest,
          workflowRunUrl: runUrl,
        },
      }
    : {
        status: "not_attested",
        reason:
          options.get("reason-not-attested") ??
          "No container attestation was produced because signing is not configured.",
      };

  return {
    image,
    imagePushed: pushed,
    signingPerformed: signed,
    notarizationPerformed: false,
    attestationPerformed: attested,
    releaseTrust: {
      mode,
      imagePublication,
      signing,
      notarization: {
        status: "not_applicable",
        reason: "Container images are not notarized by this workflow.",
      },
      attestation,
    },
    note:
      "Emitted by scripts/release-signing-status.mjs. Positive claims are backed by " +
      "the evidence anchors recorded above; absent signing identity yields an honest unsigned document.",
  };
}

// Build a desktop artifact (Windows Authenticode / macOS codesign+notarize)
// signing status document. Notarized is refused unless a ticket is supplied.
function buildDesktopStatus({ options, flags }) {
  const platform = options.get("platform");
  if (platform !== "windows" && platform !== "macos") {
    fail("desktop status requires --platform windows|macos");
  }
  const artifact = options.get("artifact");
  if (!nonEmpty(artifact)) fail("desktop status requires --artifact <name>");

  const signed = flags.has("signed");
  const notarized = flags.has("notarized");

  const signer = options.get("signer");
  const certFingerprint = options.get("cert-fingerprint");
  const notarizationTicket = options.get("notarization-ticket");
  const runUrl = options.get("run-url");

  if (signed) {
    if (!nonEmpty(signer) && !nonEmpty(certFingerprint)) {
      fail("--signed requires --signer or --cert-fingerprint");
    }
  }
  if (notarized) {
    if (platform !== "macos") fail("--notarized is only valid for --platform macos");
    if (!signed) fail("--notarized requires --signed");
    if (!nonEmpty(notarizationTicket)) fail("--notarized requires --notarization-ticket");
  }

  const codeSigning = signed
    ? {
        status: "signed",
        signer: signer ?? "configured code-signing identity",
        evidence: {
          artifact,
          ...(nonEmpty(certFingerprint) ? { certificateFingerprint: certFingerprint } : {}),
          ...(isHttpsUrl(runUrl) ? { workflowRunUrl: runUrl } : {}),
        },
      }
    : {
        status: "unsigned",
        reason:
          options.get("reason-unsigned") ??
          (platform === "windows"
            ? "No Windows Authenticode certificate secret is configured."
            : "No Apple Developer ID signing identity is configured."),
      };

  const notarization =
    platform === "macos"
      ? notarized
        ? {
            status: "notarized",
            evidence: {
              artifact,
              notarizationTicket,
              ...(isHttpsUrl(runUrl) ? { workflowRunUrl: runUrl } : {}),
            },
          }
        : {
            status: "not_notarized",
            reason:
              options.get("reason-not-notarized") ??
              "No Apple notarization credentials are configured.",
          }
      : {
          status: "not_applicable",
          reason: "Notarization applies to macOS artifacts only.",
        };

  return {
    platform,
    artifact,
    signingPerformed: signed,
    notarizationPerformed: notarized,
    releaseTrust: {
      mode: signed ? "signed" : "unsigned",
      codeSigning,
      notarization,
    },
    note:
      "Emitted by scripts/release-signing-status.mjs. Positive claims are backed by the " +
      "evidence anchors recorded above; absent a signing identity yields an honest unsigned document.",
  };
}

function writeOutput(options, document) {
  const output = options.get("output");
  const serialized = `${JSON.stringify(document, null, 2)}\n`;
  if (output) {
    fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
    fs.writeFileSync(path.resolve(output), serialized);
    console.log(`[release-signing-status] Wrote ${output} (mode=${document.releaseTrust.mode})`);
  } else {
    process.stdout.write(serialized);
  }
}

function expectFail(fn, needle) {
  const originalExit = process.exit;
  let exited = false;
  process.exit = () => {
    exited = true;
    throw new Error("__exit__");
  };
  const originalError = console.error;
  let captured = "";
  console.error = (message) => {
    captured += `${message}\n`;
  };
  try {
    fn();
  } catch (error) {
    if (error.message !== "__exit__") throw error;
  } finally {
    process.exit = originalExit;
    console.error = originalError;
  }
  if (!exited) throw new Error(`Expected failure containing "${needle}" but call succeeded`);
  if (!captured.includes(needle)) {
    throw new Error(`Expected failure containing "${needle}", got "${captured.trim()}"`);
  }
}

function runSelfTest() {
  const digest = `sha256:${"a".repeat(64)}`;
  const runUrl = "https://github.com/example/chancela/actions/runs/123456789";

  // Honest unsigned container document (no identity configured).
  const unsignedContainer = buildContainerStatus({
    options: new Map([["image", "chancela-server:local"]]),
    flags: new Set(),
  });
  if (unsignedContainer.releaseTrust.mode !== "local-ci") throw new Error("expected local-ci mode");
  if (unsignedContainer.signingPerformed !== false) throw new Error("expected signingPerformed false");

  // Fully signed container document with evidence.
  const signedContainer = buildContainerStatus({
    options: new Map([
      ["image", "ghcr.io/example/chancela-server"],
      ["digest", digest],
      ["run-url", runUrl],
      ["identity", "https://github.com/example/chancela/.github/workflows/release-signing.yml"],
      ["signer", "github-actions keyless (Fulcio)"],
      ["predicate-type", "https://cyclonedx.org/bom"],
      ["registry", "ghcr.io"],
      ["repository", "example/chancela-server"],
    ]),
    flags: new Set(["pushed", "signed", "attested"]),
  });
  if (signedContainer.releaseTrust.mode !== "production") throw new Error("expected production mode");

  // Signed without evidence must be refused.
  expectFail(
    () =>
      buildContainerStatus({
        options: new Map([["image", "chancela-server:x"]]),
        flags: new Set(["pushed", "signed", "attested"]),
      }),
    "--pushed requires --digest",
  );
  expectFail(
    () =>
      buildContainerStatus({
        options: new Map([
          ["image", "chancela-server:x"],
          ["digest", digest],
          ["run-url", runUrl],
          ["signer", "x"],
        ]),
        flags: new Set(["signed"]),
      }),
    "--signed requires --pushed",
  );

  // Desktop: unsigned Windows document.
  const unsignedWin = buildDesktopStatus({
    options: new Map([
      ["platform", "windows"],
      ["artifact", "Chancela_26.1.0_x64_en-US.msi"],
    ]),
    flags: new Set(),
  });
  if (unsignedWin.releaseTrust.codeSigning.status !== "unsigned") {
    throw new Error("expected unsigned windows artifact");
  }

  // Desktop: notarized macOS requires a ticket.
  expectFail(
    () =>
      buildDesktopStatus({
        options: new Map([
          ["platform", "macos"],
          ["artifact", "Chancela.dmg"],
          ["signer", "Developer ID Application: Example"],
        ]),
        flags: new Set(["signed", "notarized"]),
      }),
    "--notarized requires --notarization-ticket",
  );

  const notarizedMac = buildDesktopStatus({
    options: new Map([
      ["platform", "macos"],
      ["artifact", "Chancela.dmg"],
      ["signer", "Developer ID Application: Example (TEAMID)"],
      ["notarization-ticket", "2f8e...ticket"],
    ]),
    flags: new Set(["signed", "notarized"]),
  });
  if (notarizedMac.releaseTrust.notarization.status !== "notarized") {
    throw new Error("expected notarized macOS artifact");
  }

  console.log("[release-signing-status] Self-test passed");
}

const [command, ...rest] = process.argv.slice(2);
if (!command) {
  console.error(
    "Usage:\n" +
      "  node scripts/release-signing-status.mjs container --image <ref> [--output <path>] [--pushed] [--signed] [--attested] [--digest sha256:..] [--run-url <https>] [--identity <s>] [--cert-fingerprint <s>] [--signer <s>] [--predicate-type <s>] [--registry <s>] [--repository <s>]\n" +
      "  node scripts/release-signing-status.mjs desktop --platform <windows|macos> --artifact <name> [--output <path>] [--signed] [--notarized] [--signer <s>] [--cert-fingerprint <s>] [--notarization-ticket <s>] [--run-url <https>]\n" +
      "  node scripts/release-signing-status.mjs self-test",
  );
  process.exit(1);
}

if (command === "self-test") {
  runSelfTest();
  process.exit(0);
}

const parsed = parseOptions(rest);
if (command === "container") {
  writeOutput(parsed.options, buildContainerStatus(parsed));
} else if (command === "desktop") {
  writeOutput(parsed.options, buildDesktopStatus(parsed));
} else {
  fail(`Unknown command: ${command}`);
}
