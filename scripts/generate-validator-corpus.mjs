import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const corpusRoot = join(repoRoot, "docs", "fixtures", "validator-corpus");
const manifestPath = join(corpusRoot, "manifest.json");

const result = spawnSync(
  "cargo",
  [
    "test",
    "-p",
    "chancela-pades",
    "--test",
    "validator_corpus_fixtures",
    "--",
    "--nocapture",
  ],
  {
    cwd: repoRoot,
    env: {
      ...process.env,
      CHANCELA_WRITE_VALIDATOR_CORPUS: corpusRoot,
    },
    stdio: "inherit",
  },
);

if (result.status !== 0) {
  process.exit(result.status ?? 1);
}

const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
for (const fixtureCase of manifest.cases) {
  const pdfPath = join(corpusRoot, fixtureCase.pdf.path);
  if (!existsSync(pdfPath)) {
    throw new Error(`${fixtureCase.id} PDF was not generated at ${fixtureCase.pdf.path}`);
  }
  const bytes = readFileSync(pdfPath);
  fixtureCase.pdf.generation_status = "generated";
  fixtureCase.pdf.generated_by =
    "CHANCELA_WRITE_VALIDATOR_CORPUS=docs/fixtures/validator-corpus cargo test -p chancela-pades --test validator_corpus_fixtures";
  fixtureCase.pdf.sha256 = createHash("sha256").update(bytes).digest("hex");
  fixtureCase.pdf.bytes = bytes.length;
}

writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`validator corpus generated: ${manifest.cases.length} PDFs`);
