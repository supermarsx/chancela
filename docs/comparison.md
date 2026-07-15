# How Chancela compares

This page compares **Chancela** with a range of adjacent tools that Portuguese
organisations might weigh when choosing how to keep a *livro de atas* (minute
book) and related corporate acts. It is written for someone evaluating a
**self-hostable, tamper-evident** option — not as a marketing scoreboard.

!!! note "Honesty caveat — please read"
    Every competitor cell below is drawn from a **publicly verifiable source**
    (official product pages, public docs, or reputable third-party listings),
    cited in the numbered notes. Where a capability could **not** be confirmed
    from a public source, the cell is marked `?` rather than guessed. Vendor
    feature sets change often; **treat this as a snapshot and re-verify before
    deciding**. Chancela's own column describes what the project implements — it
    is **not** a claim that any tool here (Chancela included) confers legal
    validity on a document. Legal effect depends on Portuguese/EU law and how
    you operate the tool, not on the software alone.

    **Last verified: 2026-07-15.**

## What is being compared

| Tool | What it is | Category |
|---|---|---|
| **Chancela** | Self-hostable *livro de atas* / corporate-acts platform with an append-only hash-chained ledger and PT qualified e-signature integration | This project |
| **Arkeyvata** ("Livro de Atas Digital") | Portuguese cloud SaaS for digital minute books with e-signature ¹ | Atas SaaS (PT) |
| **JUFIL** | Long-standing PT manufacturer of *livro de atas* books, sold bundled with local drafting software ² | Book + local software (PT) |
| **atas.pt** | Web tool that generates atas from templates and Registo Comercial data ³ | Atas generator SaaS (PT) |
| **Diligent Boards** | Enterprise board-portal / governance suite with board-minutes management ⁴ | Board portal (global) |
| **DocuSign / Signaturit** | eIDAS QES / e-signature SaaS providers (QTSPs) ⁵ | E-signature rail (EU) |
| **OpenTimestamps / RFC 3161 TSA** | Open timestamping & notarisation primitives (proof-of-existence) ⁶ | Tamper-evidence primitive |

## Feature comparison

Legend: ✓ = supported / documented · ✗ = not offered / not applicable ·
**partial** = related but narrower than the row describes · **?** = could not
verify from a public source (see notes).

| Capability | Chancela | Arkeyvata | JUFIL | atas.pt | Diligent Boards | DocuSign / Signaturit | OpenTimestamps / TSA |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| PT *livro de atas* lifecycle (draft → seal → archive) | ✓ | ✓ ¹ | ✓ ² | partial ³ | partial ⁴ | ✗ | ✗ |
| Self-host / on-prem (you control the server) | ✓ | ✗ ¹ | partial ² | ✗ | ? ⁴ | ✗ ⁵ | ✓ ⁶ |
| Tamper-evident append-only hash-chained ledger | ✓ | partial ¹ | ✗ | ? | partial ⁴ | partial ⁵ | partial ⁶ |
| PT qualified e-signature (CMD / Cartão de Cidadão) | ✓ | ✓ ¹ | ✗ | ? | ✗ ⁴ | partial ⁵ | ✗ |
| Standard signature formats (PAdES / XAdES / CAdES) | ✓ | partial ¹ | ✗ | ? | ? | ✓ ⁵ | ✗ |
| RBAC + delegation | ✓ | ? ¹ | ✗ | ? | ✓ ⁴ | partial ⁵ | ✗ |
| Export / import with fixity verification | ✓ | ? | ✗ | ? | ? | ✗ | ✓ ⁶ |
| GDPR tooling (subject requests, redaction, etc.) | ✓ | ? ¹ | ✗ | ? | ? | partial ⁵ | ✗ |
| Multi-node / high availability (leader/follower) | ✓ | n/a ¹ | ✗ | n/a | n/a ⁴ | n/a | n/a |
| Open API / MCP integration | ✓ | ? | ✗ | ? | partial ⁴ | ✓ ⁵ | ✓ ⁶ |
| Desktop application | ✓ | ✗ ¹ | ✓ ² | ✗ | ✓ ⁴ | ✗ | partial ⁶ |
| Self-controlled data residency / DB (SQLite/Postgres) | ✓ | ✗ ¹ | ✓ ² | ✗ | ✗ ⁴ | partial ⁵ | ✓ ⁶ |
| Pricing model | Self-host ⁷ | Subscription ¹ | Per-book purchase ² | Free ³ | Enterprise quote ⁴ | Subscription ⁵ | Free / OSS ⁶ |

## Per-tool notes and sources

**Arkeyvata — "Livro de Atas Digital"** (`livrodeatasdigital.pt`,
`app.arkeyvata.pt`). A Portuguese cloud SaaS, explicitly *"sem a necessidade de
instalação de software"*, offering editable atas templates and digital signing
via **Cartão de Cidadão, Chave Móvel Digital, qualified certificate, and SMS
OTP**, using SIBS Multicert's *mTrust* signature service. It states that signed
documents and signatures "cannot be altered," but the underlying integrity
mechanism (e.g. an append-only hash chain) is not publicly documented, so that
row is marked *partial*. Self-hosting, an open API, RBAC/delegation and GDPR
tooling are not described publicly (`?`). Publicly launched around mid-2024.
Sources: [livrodeatasdigital.pt](https://livrodeatasdigital.pt/),
[app.arkeyvata.pt](https://app.arkeyvata.pt/),
[ECO/SAPO coverage (2024-06-18)](https://eco.sapo.pt/2024/06/18/conhece-a-nova-solucao-de-atas-digitais/).

**JUFIL — Júlio Santos & Filhos, Lda.** (`jufil.pt`). A long-established PT
maker of *livro de atas* and record books, sold in laser/inkjet A4 formats
**bundled with drafting software** delivered on CD or by download. The bundled
app produces opening/closing terms, page numbering, and atas from editable
templates, and the vendor states it "complies with current legislation." It is
**local desktop software tied to a purchased physical book**, not a hosted
server, so *self-host* is marked *partial* and *desktop app* ✓. No qualified
e-signature, ledger, API, RBAC or HA is documented. It is a per-unit retail
purchase (sold through stationery retailers), not a subscription. Sources:
[jufil.pt](https://www.jufil.pt/site/),
[product listing (Rei dos Livros)](https://www.reidoslivros.pt/papelaria/livro-de-atas-a4-digital-jufil-60-folhas/).

**atas.pt** (`atas.pt`). A web tool advertised as generating general-assembly,
board and management atas quickly, pulling company data from the Registo
Comercial and offering ~35 free templates. The homepage returned an access
error at verification time, so these details are **search-derived and should be
re-verified**; signature format, ledger, RBAC and API details are unconfirmed
(`?`). Source: search summary for
[atas.pt](https://atas.pt/) (page not directly fetchable on 2026-07-15).

**Diligent Boards** (`diligent.com`). An enterprise board-portal / governance
suite. Its **minutes** feature offers templates, in-platform signing and
sharing, and the platform provides electronic voting with audit trails and
granular access controls. It is not specialised to the Portuguese *livro de
atas* legal lifecycle (hence *partial*), and it is predominantly a cloud SaaS;
some third-party listings mention an on-premise/offline option, so *self-host*
is marked `?` pending vendor confirmation. Pricing is by enterprise quote.
Sources: [diligent.com/products/boards](https://www.diligent.com/products/boards),
[Diligent board-minutes feature](https://www.diligent.com/features/boards/boards-minutes),
[third-party profile (Software Advice)](https://www.softwareadvice.com/board-management/diligent-boards-profile/).

**DocuSign / Signaturit** (e-signature rail). Both are eIDAS-certified
providers that can deliver **Qualified Electronic Signatures** in standards-based
formats (PAdES/XAdES/CAdES) across the EU. They are **signing rails, not
minute-book platforms** — no atas lifecycle, ledger, or RBAC-over-a-book. Their
QES is EU-qualified but not specifically the Portuguese CMD / Cartão de Cidadão
flow (marked *partial*). Both are cloud SaaS subscriptions (Signaturit basic
tiers reported around €15/user/month; acquired by Namirial in 2025). For a
self-hostable e-signature comparator, the open-source **DocuSeal** (Docker) is
worth noting, though it does not natively provide QES or an atas lifecycle.
Sources: [DocuSign QES](https://www.docusign.com/en-gb/products/electronic-signature/qualified-electronic-signature),
[DocuSign eIDAS primer](https://www.docusign.com/learn/eidas),
[DocuSign standards-based signatures (PDF)](https://www.docusign.com/sites/default/files/DocuSign_Standards_Based_Signatures.pdf),
[DocuSeal self-host guide](https://webnestify.cloud/insights/open-source-solutions/docuseal-self-hosted-document-signing/).

**OpenTimestamps / RFC 3161 TSA** (tamper-evidence primitive). Open-source
timestamping: RFC 3161 uses a trusted Time Stamping Authority, while
OpenTimestamps produces compact `.ots` proofs anchored to the Bitcoin
blockchain and verifiable **offline without a central authority**. These give
**proof-of-existence / tamper-evidence** for a document hash (marked *partial*
on the ledger row) but are **not** a minute-book application — no atas
lifecycle, e-signature, RBAC or GDPR tooling. They are a complementary building
block Chancela-style ledgers can also anchor against. Sources:
[OpenTimestamps (Wikipedia)](https://en.wikipedia.org/wiki/OpenTimestamps),
[opentimestamps.org announcement](https://petertodd.org/2016/opentimestamps-announcement),
[sigstore RFC3161 timestamp-authority](https://github.com/sigstore/timestamp-authority).

**The Portuguese QES rail itself** — **Autenticação.gov / Chave Móvel Digital /
Cartão de Cidadão** — is not a competitor but the **national signing
infrastructure** that Chancela and Arkeyvata both integrate. The State certifies
signatures made with the Cartão de Cidadão or CMD and supports signing PDFs in
**PAdES** format (with timestamp options) via the Autenticação.gov application.
Source: [autenticacao.gov.pt — assinatura digital qualificada](https://www.autenticacao.gov.pt/assinatura-digital/assinatura-digital-qualificada).

## How to read this table

- **A `✓` is not an endorsement and a `✗`/`?` is not criticism.** Many tools
  here solve a *different* problem (a pure e-signature rail, a timestamping
  primitive, a stationery product, an enterprise board portal). The right choice
  depends on whether you need a self-hosted, ledger-backed *livro de atas* or
  just one of those pieces.
- **`partial` means "related but narrower"** than the row's full claim — read
  the note to see exactly how.
- **`?` means unverified from public sources**, not "absent." Vendors may
  support it privately; ask them and update the cell.
- Rows most decision-relevant to a **self-hosting evaluator** are self-host /
  on-prem, the append-only ledger, PT qualified e-signature, export/import with
  fixity, and self-controlled data residency.
- **Nothing here should be read as a legal-validity guarantee.** Chancela is
  designed to be tamper-evident and to integrate qualified signatures; whether a
  given act is legally effective is a matter of law and of how you operate the
  system.

## Notes

¹ Arkeyvata / *Livro de Atas Digital* — [livrodeatasdigital.pt](https://livrodeatasdigital.pt/),
[app.arkeyvata.pt](https://app.arkeyvata.pt/) (verified 2026-07-15).
² JUFIL — [jufil.pt](https://www.jufil.pt/site/) and retailer listings
(verified 2026-07-15).
³ atas.pt — search-derived; homepage not directly fetchable on 2026-07-15,
**re-verify**.
⁴ Diligent Boards — [diligent.com](https://www.diligent.com/products/boards) and
third-party listings (verified 2026-07-15).
⁵ DocuSign / Signaturit — vendor pages + eIDAS docs (verified 2026-07-15).
⁶ OpenTimestamps / RFC 3161 — project docs & Wikipedia (verified 2026-07-15).
⁷ Chancela column reflects the project's implemented capabilities; consult the
repository for current licensing and deployment details.

---

*This comparison is a point-in-time snapshot compiled on **2026-07-15** from
public sources. Competitor features change; verify each cell against the
vendor's current documentation before relying on it. Corrections and the exact
name/URL of any tool marked `?` are welcome.*
