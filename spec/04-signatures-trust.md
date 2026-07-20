# 04 — Identity, Signatures, and Trust Services

Requirement prefix: `SIG`

## 1. Model

The signing stack MUST clearly separate four concepts:

1. **Identity** — who the person is (and in what capacity);
2. **Signature method** — how the signature is produced (CC smartcard, CMD remote, imported
   certificate, handwritten);
3. **Trust service** — which QTSP and service back the certificate/timestamp;
4. **Evidentiary result** — what legal presumptions the produced artifact actually carries.

Legal grounding: eIDAS Regulation (EU) 910/2014 art. 25; DL 12/2021 (qualified electronic
signature is equivalent to a handwritten signature and creates presumptions of
identity/representation, intent to sign, and integrity; qualified timestamps carry a
presumption as to time and integrity).

## 2. Signing families

- **SIG-01** The product MUST natively support the four signing families below, each with
  its correct evidentiary labeling.

| Family | Product requirement | Evidentiary position |
|---|---|---|
| **Cartão de Cidadão** qualified signature | Smartcard-reader signing, CC signature PIN, certificate status checking, optional professional attributes | CC carries an authentication certificate and an (optional-to-activate) qualified signature certificate; qualified = handwritten-equivalent |
| **Chave Móvel Digital** qualified signature | CMD activation, CMD signature PIN, confirmation via SMS/email/gov.pt app/QR/biometrics where available | Legally regulated remote qualified signing; requires active CMD, active signature function, and the CMD signature PIN |
| **Other qualified certificates** | Import/use of qualified certificates from Portuguese or EU QTSPs, incl. representative and professional certificates | Governed by eIDAS + DL 12/2021; qualified status verified against the trusted list |
| **Manual (handwritten)** | Scanning + archival workflow with explicit warnings and original-reference metadata | Legally admissible (CSC art. 63.º; DL 268/94), but detached private documents have weaker force for company resolutions; no automation presumptions |

- **SIG-02 (OTP is not a signature).** An OTP code alone MUST NEVER be presented as a
  qualified signature. OTP-based consent/confirmation flows MAY exist but MUST be labeled
  as such. The handwritten-equivalence rule attaches to the **qualified electronic
  signature**, not to a generic OTP event; an OTP is acceptable only *inside* a qualified
  trust-service flow such as CMD remote signing. UI copy MUST enforce this distinction.
- **SIG-03** Manual-signature mode MUST display a prominent warning along the lines of:
  *"This act may still be legally valid, but the digital copy is not being finalized with a
  qualified electronic signature. Preserve the original signed paper or original digitized
  signature chain."*
- **SIG-04** Professional and representative attributes MUST be supported via **SCAP**,
  because many acts are signed by a person acting in a professional role or on behalf of a
  legal entity — the capacity is part of the evidence.

## 3. Trusted list (TSL) as the source of truth

- **SIG-10** The trust-service registry MUST be driven by the **Portuguese Trusted List**
  published by GNS (and the EU list-of-lists framework) — never by a manually curated
  spreadsheet.
- **SIG-11** The product MUST ingest the signed TSL, validate its signature, cache it, and
  expose only services whose **current status** is appropriate for the intended operation.
- **SIG-12** The provider registry MUST drive three user-facing capabilities:
  1. **Discovery** of approved providers and trust services;
  2. **Policy configuration** — admins restrict acceptable providers, certificate policy
     OIDs, and signature levels;
  3. **"Buy/add certificate" pathways** — open the provider's official landing/purchase
     page. Purchase URLs come from an admin-curated catalog (SCP-D6); qualified status
     always comes from the TSL, never a marketing page.
- **SIG-13** Known Portuguese TSL entries (illustrative, not exhaustive; always resolved at
  runtime from the TSL): CEGER/ECCE, Instituto dos Registos e do Notariado, Justiça, ECAR,
  Multicert, British Telecommunications plc, DigitalSign, ACIN iCloud Solutions/Global
  Trusted Sign, AMA, NOS.
- **SIG-14** The default trust-service endpoints ship pre-configured to the **official
  Portuguese state services**, sourced from AMA / Cartão de Cidadão and GNS, and are
  **admin-configurable** (Configurações → Assinaturas), overridable per environment, or
  clearable:
  - **TSA (RFC 3161):** `http://ts.cartaodecidadao.pt/tsa/server` — AMA's Cartão de Cidadão
    qualified timestamp service (EVC·CC). Plain `http://` is correct for RFC 3161 (the token is
    signed; integrity does not depend on TLS) and MUST NOT be "upgraded" to https. Free but
    rate-limited (~20 requests / 20-minute window; exceeding it blocks the caller for 24h).
  - **TSL:** `https://www.gns.gov.pt/media/TSLPT.xml` — the GNS-published Portuguese Trusted
    List (also resolvable from the EU LOTL). GNS renames the asset periodically, so the pinned
    URL is a default to re-verify, not a guarantee.
  - **Network-gated at rest:** pre-filling these URLs does **not** cause the product to contact
    the TSA/TSL in normal operation. Live use stays feature-gated and operator-initiated exactly
    as before; a default URL is not a "phone-home".
- **SIG-15** **Audit attestation vs. qualified signature (an honest boundary).** An optional
  per-user **audit attestation** key (P-256, unlocked at sign-in by the user's optional password)
  may sign each ledger event's chain hash (ES256), giving per-user cryptographic
  **accountability / tamper-evidence** in the DAT-11 audit trail: it proves an action was
  performed inside a session unlocked by the password-holder. It is **explicitly NOT** legal
  non-repudiation or a qualified electronic signature — the server holds the decrypted key in
  memory for the life of the session (trust-on-the-local-process, not a smartcard the server never
  sees). The **qualified signatures on the sealed acts** (Cartão de Cidadão / Chave Móvel Digital →
  CAdES/PAdES, SIG-20/21) remain the legal mechanism; the attestation is an internal audit layer on
  top of the hash chain. Correspondingly, the **password** that unlocks it is a shared-machine
  tamper *speed-bump*, not at-rest encryption: records, `users.json`, and the ledger stay readable
  and editable on disk regardless of any password (the ARC-30 at-rest-encryption gap is separate
  and out of scope). UI copy MUST state both boundaries and never oversell either.

## 4. Signature formats and long-term preservation

- **SIG-20** The signing subsystem MUST support **PAdES** for PDFs and
  **XAdES / CAdES / ASiC** for non-PDF structured or detached workflows.
- **SIG-21** Baseline profiles **B-B, B-T, B-LT, B-LTA** MUST be supported, with B-LTA (or
  equivalent long-term validation material + archival timestamps) as the default for sealed
  acts destined for the archive.
- **SIG-22** Sealing SHOULD optionally checkpoint finalization events with a **qualified
  timestamp** from a trusted provider (presumption as to time and integrity under DL
  12/2021).
- **SIG-23** Signature validation MUST cross-check against EU trusted-list data. The
  architecture MUST allow either a native Rust validator or an **EU DSS-compatible
  validation sidecar** for cross-checking long-term and edge cases (SCP-D2).
- **SIG-24** Every sealed act MUST embed or attach a **signature-validation report**
  produced at sealing time.

## 5. External signers

- **SIG-30** External signers MAY be invited by secure link, with strict expiration,
  configurable identity requirements, and the same evidentiary labeling rules (SIG-01/02).
- **SIG-31** Serial and parallel signing orders MUST both be supported within a signature
  envelope (see [05 — Data model](05-data-model-roles.md)).
