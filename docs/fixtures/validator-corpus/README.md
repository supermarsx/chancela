# External Validator Fixture Corpus

This folder is the operator-run corpus for comparing Chancela-generated PAdES
PDFs with external validators. It is a scaffold only: no external validator
result in this folder means validation passed until an operator places the PDF,
runs the named validator, and updates the sidecar.

## Layout

- `manifest.json` is the corpus index and the source of truth for case ids,
  expected generated PDF locations, validator sidecars, and pending status.
- `cases/<case-id>/input/` is reserved for the generated or tampered PDF.
- `cases/<case-id>/expected/` contains one expected-output sidecar per external
  validator family.
- `cases/<case-id>/reports/` is reserved for raw validator exports.

## Cases

The initial manifest reserves these generated PDFs:

- B-B signed PDF.
- B-T signed PDF with a signature timestamp.
- B-T PDF with caller-supplied local DSS/VRI evidence.
- Malformed or tampered PDFs for covered-byte and DSS-only tamper checks.
- Future `/DocTimeStamp` PDF for B-LTA work.

All sidecars currently use `run_status: "pending_operator_run"`. Keep that
status until the named validator has been run by an operator and the raw report
is committed or archived according to project policy.

## Validation

Run the manifest shape check from the repository root:

```sh
npm run test:validator-corpus
```

The check validates the manifest and sidecar schema, verifies that every
sidecar referenced by the manifest exists, and permits missing PDFs only when
the case is still pending generation.
