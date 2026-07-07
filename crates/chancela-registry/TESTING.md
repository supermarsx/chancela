# Testing `chancela-registry`

This crate consults the Portuguese **certidão permanente** (registo comercial / registo de
fundações) by 12-digit access code and parses the returned HTML into a typed `RegistryExtract`.
Because there is no sanctioned automation API, the certidão is a human-facing HTML page consulted
with the user's own code, testing is split into two tiers:

| Tier | What it proves | Network | How it runs |
|---|---|---|---|
| **Offline** (default) | code validation/masking, HTML parsing of the three entity-type specimens + the error page, client round-trip over the mock | none | `cargo test -p chancela-registry` |
| **Live** (`network-tests` + `#[ignore]`) | the real endpoint/params and the exact live HTML actually parse | yes | opt-in, never in CI |

## Offline tests (the CI gate)

```bash
cargo test -p chancela-registry
```

Covers (zero network):

- **Access code** — `parse` strips separators and requires exactly 12 digits; `masked()` →
  `****-****-NNNN`; `Debug` renders masked; `InvalidCode` never echoes the raw code
  (`src/code.rs`).
- **Fixture parsing** — `tests/registry.rs` parses each specimen in `fixtures/` and asserts on
  NIPC, firma, `Natureza Jurídica` → `LegalForm`, sede, CAE, capital, data de constituição, the
  **ordered** inscrições feed, and the best-effort officers (at least one appointment **and** one
  cessation per specimen). The error page yields `RegistryError::Unrecognized`.
- **Secret handling** — the full code never appears in the serialized extract; provenance carries
  only the masked code + a lowercase-hex sha256 of the raw HTML; the mock records only masked codes.

### Fixtures (`fixtures/`)

All fixtures are **fictional** — the example firm is always *Encosto Estratégico* and the NIPCs are
format-valid but fake. Never author a fixture from a real firm's data.

| File | Specimen |
|---|---|
| `spq_certidao.html` | Sociedade por quotas (2 gerentes: one serving, one ceased) |
| `sa_certidao.html` | Sociedade anónima (conselho de administração: presidente + administrador ceased) |
| `fundacao_certidao.html` | Fundação, LEG-21 (presidente + vogal ceased) |
| `expired_error.html` | Invalid/expired consultation page → `Unrecognized` |

The parser is **label-driven**: it flattens the DOM to text with `scraper` and extracts off the
legally-stable Portuguese field labels, tolerating optional/absent sections. Markup churn on the
live page is therefore non-fatal and, when it happens, is fixed by refreshing a fixture + the
parser only — the API/UI contract is unaffected.

## Live consultation (validate against a real access code)

The live endpoint, its parameters, and the exact live HTML can only be confirmed against a **real
certidão permanente access code** (plan t11 risk #2). This is the honest live-validation seam.

1. Obtain a valid 12-digit código de acesso for a certidão you are entitled to consult
   (`XXXX-XXXX-XXXX`).
2. Set the environment variables:

   | Variable | Meaning | Required |
   |---|---|---|
   | `CHANCELA_REGISTRY_TEST_CODE` | the real access code | yes (for the live test) |
   | `CHANCELA_REGISTRY_EMAIL` | e-mail the newer consultation platform may require | optional |
   | `CHANCELA_REGISTRY_URL` | override the consultation base URL (defaults to the legacy `consultaCertidao.aspx` endpoint) | optional |

3. Run the double-gated test (compiled only with `network-tests`, and `#[ignore]`d):

   ```bash
   CHANCELA_REGISTRY_TEST_CODE=XXXX-XXXX-XXXX \
     cargo test -p chancela-registry --features network-tests -- --ignored --nocapture
   ```

   It fetches the live certidão, parses it, and prints the extracted shape (NIPC, firma, forma
   jurídica, sede, CAE, inscrição/officer counts) plus its **masked** provenance for eyeballing.
   The full access code is used only to build the request and is never printed, logged, or stored.

If the live page has moved to the new Plataforma de Serviços do Registo SPA (which needs an e-mail
+ session/anti-forgery token), point `CHANCELA_REGISTRY_URL` at the working endpoint and, if the
HTML layout differs, refresh the fixtures + `parse_certidao` accordingly. No change is needed in
`chancela-api` or the UI — they depend only on the typed `RegistryExtract`.

## Lint/format gates

```bash
cargo clippy -p chancela-registry --all-targets -- -D warnings
cargo clippy -p chancela-registry --all-targets --features network-tests -- -D warnings
cargo fmt -p chancela-registry --check
```
