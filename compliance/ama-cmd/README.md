# AMA/CMD Compliance Evidence Pack Generator

This folder is a separate documentation-only slice for AMA/CMD authority-review
demonstrability. It does not modify application, frontend, backend, or runtime
code.

Related repository context exists in `docs/CMD-LEGAL-INTEGRATION.md`, but there
was no existing compliance-documentation generator convention. This slice
therefore lives under the requested top-level `compliance/ama-cmd/` path.

## Scope

The generator creates a draft evidence pack with:

- an authority-review checklist;
- official source URL metadata;
- placeholders for signed protocol/application documents;
- placeholders for production `ApplicationId` and certificate evidence;
- placeholders for pre-production/test evidence;
- a short app-video evidence template;
- an explicit no-approval/no-legal-compliance claim boundary.

The generated output is for assembly and review only. It does not prove AMA
approval, production enablement, certification, or legal compliance. Those
claims require actual signed documents, AMA/SCMD production evidence, authority
feedback, and legal review.

## Run

Requires Node.js 20 or newer. No npm install is required.

```powershell
node compliance/ama-cmd/generate-evidence-pack.mjs --out compliance/ama-cmd/out/evidence-pack
```

If the target pack already exists and you want to refresh the generated files:

```powershell
node compliance/ama-cmd/generate-evidence-pack.mjs --out compliance/ama-cmd/out/evidence-pack --force
```

Generated files go under `compliance/ama-cmd/out/`, which is intentionally
ignored by Git. The generator overwrites only its known files when `--force` is
used; it does not delete extra reviewer notes or attached evidence.

## Official Source Metadata

The generator includes metadata for these official source URLs:

- `https://github.com/amagovpt/doc-CMD-assinatura/raw/main/protocolos_minutas/AMA_Protocolo_CMD_Autentica%C3%A7%C3%A3o_Assinatura_Privados_.docx`
- `https://github.com/amagovpt/doc-AUTENTICACAO`
- `https://github.com/amagovpt/doc-CMD-assinatura`

## Files Changed By This Slice

- `compliance/ama-cmd/.gitignore`
- `compliance/ama-cmd/README.md`
- `compliance/ama-cmd/generate-evidence-pack.mjs`
- `compliance/ama-cmd/source-metadata.json`
- `compliance/ama-cmd/templates/README.md`
- `compliance/ama-cmd/templates/CHECKLIST.md`
- `compliance/ama-cmd/templates/app-video-evidence.md`
- `compliance/ama-cmd/templates/authority-review-summary.md`
- `compliance/ama-cmd/templates/no-approval-claim.md`
- `compliance/ama-cmd/templates/production-applicationid-certificate-evidence.md`
- `compliance/ama-cmd/templates/signed-protocol-application-index.md`
- `compliance/ama-cmd/templates/test-evidence-index.md`
