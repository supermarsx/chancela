# 09 — AI, MCP, and Integrations

Requirement prefix: `AI`

## 1. AI features (subordinate to legal controls)

- **AI-01** The AI layer MUST be helpful but subordinate to legal controls. Supported
  features:
  - template drafting from prompts;
  - extraction of meeting metadata from uploaded convocatórias and reports;
  - comparison between draft and signed version;
  - automatic generation of convocatórias and resolutions from prior acts;
  - chronology summarization;
  - multilingual drafting — PT-PT and EN-US by default, up to ten locales total (UX-20).
- **AI-02** **Provenance panels** MUST tell the user which statement in a draft came from:
  law, certificate data, registry data, prior company records, or AI suggestion.
- **AI-03** Every AI-generated act MUST pass a **human verification checkpoint** before it
  can enter the signing stage. The software helps users verify content accuracy; it must
  never imply that automation makes the act legally true.
- **AI-04** AI features MUST be disableable per tenant (relevant for sensitive tenants and
  zero-knowledge repositories, where server-side AI may be unavailable by design).

## 2. MCP server

- **AI-10** The platform MUST expose an **MCP server** so external AI clients can discover
  tools, resources, and prompts in a standardized way (no screen scraping).
- **AI-11** Exposed tools MUST be split into read-only and write-controlled sets, honoring
  the ROL permission scopes. Initial tool set:

| Tool | Access |
|---|---|
| `list_companies` | read-only |
| `get_company_timeline` | read-only |
| `search_legal_texts` | read-only |
| `generate_mermaid_graph` | read-only |
| `validate_signature_bundle` | read-only |
| `draft_minutes` | write-controlled |
| `prepare_archive_export` | write-controlled |

- **AI-12** MCP access MUST be authenticated as the **API Client** role (ROL-02) with the
  same audit-ledger events as any other actor (DAT-10).

## 3. Legal-text library ("law shelf")

- **AI-20** The product MUST ingest official legal sources from **Diário da República**
  (stable ELI-style pages) and **EUR-Lex** (search web services), store them in a search
  index, and preserve official identifiers.
- **AI-21** The law shelf MUST provide: full-text search, topic filters, pinned references
  per template, and citation insertion into drafting workspaces.
- **AI-22** Rule packs (LEG-02) SHOULD link their findings to law-shelf entries so
  compliance warnings cite the actual provision.

## 4. Registry integration

- **AI-30** Certidão permanente import by access code per LEG-20/21/22 feeds the
  chronology graph (DOC-30) and pre-fills entity data on onboarding.
- **AI-31** Registry imports are read-only integrations in v1 (SCP-41): the platform
  prepares filings but does not submit them.
