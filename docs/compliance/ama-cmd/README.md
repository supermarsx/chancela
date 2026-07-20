# AMA/CMD Compliance Evidence Pack Generator

This folder is a separate documentation-only slice for AMA/CMD authority-review
demonstrability. It does not modify application, frontend, backend, or runtime
code.

Related repository context exists in `docs/CMD-LEGAL-INTEGRATION.md`, but there
was no existing compliance-documentation generator convention. This slice
therefore lives under `docs/compliance/ama-cmd/`.

## Scope

The generator creates a draft evidence pack with:

- an authority-review checklist;
- official source URL metadata;
- placeholders for signed protocol/application documents;
- placeholders for production `ApplicationId` and certificate evidence;
- placeholders for pre-production/test evidence;
- a short app-video evidence template;
- an implementation evidence map linking AMA/CMD source expectations to local
  files and verification commands;
- an explicit no-approval/no-legal-compliance claim boundary.

The generated output is for assembly and review only. It does not prove AMA
approval, production enablement, certification, or legal compliance. Those
claims require actual signed documents, AMA/SCMD production evidence, authority
feedback, and legal review.

## Run

Requires Node.js 20 or newer. No npm install is required.

```powershell
node docs/compliance/ama-cmd/generate-evidence-pack.mjs
```

If the target pack already exists and you want to refresh the generated files:

```powershell
node docs/compliance/ama-cmd/generate-evidence-pack.mjs --force
```

Generated files go under `docs/compliance/generated/ama-cmd-evidence-pack/`.
The default `generated_at` marker is deterministic so a dry run can be compared
without timestamp churn. For an authority-facing pack that needs a dated marker,
pass an explicit value:

```powershell
node docs/compliance/ama-cmd/generate-evidence-pack.mjs --generated-at 2026-07-10T12:00:00.000Z --force
```

The generator overwrites only its known files when `--force` is used; it does
not delete extra reviewer notes or attached evidence.

The generator also validates that every local path in the implementation
evidence map exists. If a mapped file moves or is deleted, generation fails
until the map is updated.

## Check

Use the read-only check mode to validate the generated pack without contacting
AMA/SCMD services and without claiming production approval or legal compliance:

```powershell
node docs/compliance/ama-cmd/generate-evidence-pack.mjs --check
```

The check verifies:

- manifest claim boundaries remain `draft_evidence_pack_only`,
  `not_claimed`, and externally evidenced;
- official source IDs, URLs, and generated source metadata match
  `source-metadata.json`;
- rendered templates and evidence placeholders match deterministic generator
  output and contain no unresolved `{{...}}` tokens;
- implementation evidence map references point to files that exist in the
  repository and are rendered in `IMPLEMENTATION-EVIDENCE-MAP.md`.

If a pack was generated with explicit `--case-name` or `--generated-at` values,
pass the same values to `--check` to assert those values.

## Claim Boundary

The pack must not claim live production CMD validity, production onboarding, or
AMA approval until all of the following are attached and reviewed:

- signed protocol/application evidence;
- AMA acceptance or activation correspondence;
- production `ApplicationId` assignment evidence;
- production certificate/public-key evidence required for CMD integration;
- technical test evidence and reviewer sign-off.

Pre-production tests, local source evidence, templates, or generated checklists
are demonstrability material only.

## Official Source Metadata

The generator includes metadata for these official source URLs:

- `https://github.com/amagovpt/doc-CMD-assinatura/raw/main/protocolos_minutas/AMA_Protocolo_CMD_Autentica%C3%A7%C3%A3o_Assinatura_Privados_.docx`
- `https://github.com/amagovpt/doc-AUTENTICACAO`
- `https://github.com/amagovpt/doc-CMD-assinatura`

## Files Changed By This Slice

- `docs/compliance/ama-cmd/.gitignore`
- `docs/compliance/ama-cmd/README.md`
- `docs/compliance/ama-cmd/generate-evidence-pack.mjs`
- `docs/compliance/ama-cmd/source-metadata.json`
- `docs/compliance/ama-cmd/templates/README.md`
- `docs/compliance/ama-cmd/templates/CHECKLIST.md`
- `docs/compliance/ama-cmd/templates/app-video-evidence.md`
- `docs/compliance/ama-cmd/templates/authority-review-summary.md`
- `docs/compliance/ama-cmd/templates/no-approval-claim.md`
- `docs/compliance/ama-cmd/templates/production-applicationid-certificate-evidence.md`
- `docs/compliance/ama-cmd/templates/signed-protocol-application-index.md`
- `docs/compliance/ama-cmd/templates/test-evidence-index.md`
