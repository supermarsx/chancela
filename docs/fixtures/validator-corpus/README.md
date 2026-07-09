# External Validator Fixture Corpus

This folder is the operator-run corpus for comparing Chancela-generated PAdES
PDFs with external validators. The input PDFs are committed deterministic local
fixtures. No external validator result in this folder means validation has not
been run until an operator runs the named validator and updates the sidecar.

## Layout

- `manifest.json` is the corpus index and the source of truth for case ids,
  generated PDF locations, hashes, sizes, validator sidecars, and pending
  external-validator status.
- `cases/<case-id>/input/` contains the generated or tampered PDF.
- `cases/<case-id>/expected/` contains one expected-output sidecar per external
  validator family.
- `cases/<case-id>/reports/` is reserved for raw validator exports.

## Cases

The manifest commits these generated PDFs:

- B-B signed PDF.
- B-T signed PDF with a signature timestamp.
- B-T PDF with caller-supplied local DSS/VRI evidence.
- Malformed or tampered PDFs for covered-byte and DSS-only tamper checks.
- `/DocTimeStamp` PDF produced by the current technical archive-timestamp
  primitive. This is still not a production B-LTA claim.

All sidecars currently use `run_status: "pending_operator_run"`. Keep that
status until the named validator has been run by an operator and the raw report
is committed or archived according to project policy.

## Recording an external validator run

Run the external validator outside this repository, export its raw report, and
then record the sidecar from the repository root:

```sh
node scripts/record-validator-sidecar.mjs \
  --case bb-basic \
  --family eu-dss \
  --report path/to/raw-eu-dss-report.xml \
  --tool "EU DSS validation" \
  --version "6.2" \
  --operator "operator@example.test" \
  --environment "Windows 11, EU DSS CLI, local trust store snapshot 2026-07-09" \
  --command "dss-cli validate bb-basic.pdf --output raw-eu-dss-report.xml"
```

Use `--family adobe` for Adobe-style exports. If a structured transcription is
available, pass `--observed-json path/to/observed.json`; otherwise the sidecar
records only that the raw report was captured, without making a pass/fail claim.

The recorder requires an actual `--report` file. It copies reports that are
outside the corpus into `cases/<case-id>/reports/`, hashes the raw report,
records the document hash, timestamp, tool name, tool version, operator,
environment, and command, and then reruns the corpus validator. It updates only
the selected sidecar; pending sidecars remain `pending_operator_run` with null
observed/report fields.

Do not mark a sidecar as `recorded` by hand unless the raw report path, hash,
timestamp, tool, and version are all preserved and `npm run test:validator-corpus`
passes.

## Validation

Generate or refresh the local PDFs and manifest hashes from the repository root:

```sh
node scripts/generate-validator-corpus.mjs
```

Run the manifest check from the repository root:

```sh
npm run test:validator-corpus
```

The check validates the manifest and sidecar schema, verifies that every
sidecar referenced by the manifest exists, and requires each generated PDF to
exist with matching byte length and SHA-256. Recorded sidecars must also point
to an existing raw report whose byte length and SHA-256 match the sidecar.
