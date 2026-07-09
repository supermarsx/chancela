# CMD Legal Integration Path

Updated 2026-07-09. This note records the product position from the completed
read-only research for Chave Movel Digital (CMD), Cartao de Cidadao (CC), and
qualified remote signing.

## Position

Chancela can support legally binding signature workflows without itself becoming
a certifier only as a workflow and relying-party layer that uses outputs from
qualified signing systems:

- CMD/SCMD for Portuguese qualified remote signing.
- Cartao de Cidadao and Autenticacao.gov middleware for local qualified signing.
- A qualified trust service provider (QTSP), normally through CSC or a
  provider-specific remote-signing API.
- Qualified certificates and, where required for QES, qualified signature
  creation device (QSCD) or qualified remote QSCD-managed environments.

There is no credible implementation path where Chancela creates a
handwritten-equivalent qualified electronic signature while bypassing qualified
trust services, qualified certificates, CC hardware, CMD/SCMD onboarding, QSCD
requirements, or QTSP provider controls. Chancela must never describe an OTP,
invite acceptance, internal approval, hash, timestamp, ledger event, or TSL
lookup as a shortcut around those requirements.

## Integration Model

The viable path that avoids Chancela itself becoming a qualified trust service
provider is:

- Chancela prepares the signable PDF/PAdES byte range and DTBS/R.
- CMD/SCMD, CC middleware, or a CSC/QTSP performs the signing operation through
  its qualified certificate and qualified signing environment.
- Chancela embeds or stores the returned CMS/PAdES material according to the
  provider flow, validates the resulting artifact, records evidence, and
  preserves the signed PDF.
- Chancela uses EU/GNS trusted-list, TSA, DSS, revocation, and provider-status
  checks as policy gates and evidence, but does not represent TSL visibility as
  legal completion on its own.

This gives operators a legally usable integration route without claiming that
Chancela is the qualified provider, certificate authority, registration
authority, supervisory authority, QSCD, or certification assessor.

## Delegated Qualified-Provider Responsibilities

The following responsibilities stay with CMD/SCMD, the CC ecosystem, the QTSP,
or the competent supervisory/conformity-assessment chain. Chancela may verify
and record evidence about them, but must not claim to perform them:

- Qualified trust service provider status, supervision, conformity assessment,
  and publication in the relevant trusted list.
- Certificate policy, certification practice statements, issuance, renewal,
  suspension, revocation, and status publication for qualified certificates.
- Subscriber identity proofing, registration authority controls, and signer
  onboarding required by the provider's qualified service.
- Protection and sole/control-equivalent use of signature-creation data,
  including QSCD or qualified remote-signing controls.
- Signer authentication and signature authorization ceremonies, including CMD
  PIN/security-code flows, CC PIN flows, CSC credential authorization, and any
  provider step-up requirements.
- Secure provider-side audit trails, incident handling, key management,
  availability, and operational controls required for the qualified service.
- Provider conformance with eIDAS, ETSI profiles, national supervisory rules,
  and the provider's own published policies.
- Qualified timestamp or long-term-validation services when those services are
  bought from or delegated to a qualified provider.

## Product Guardrails

- UI and API copy may say "qualified signature via CMD", "qualified signature
  via CC", or "qualified signature via QTSP" only after the configured provider
  flow returns a valid qualified-signature artifact and Chancela's validation
  gate accepts it.
- UI and API copy must not say that Chancela "issues", "certifies", "qualifies",
  "guarantees", or "creates legal validity" for the signer, certificate,
  provider, or signature.
- OTP acknowledgement, external invite acceptance, internal approval, audit
  ledger evidence, document sealing, timestamps, or acceptance envelopes are not
  electronic signatures unless the qualified signing provider has actually
  produced the signed artifact.
- CMD production remains blocked until the relevant Autenticacao.gov/SCMD
  onboarding, credentials, production encryption certificate, and required
  integration approvals are complete.
- CC production remains blocked without a physical Cartao de Cidadao, active
  signature certificate, reader or compatible device path, signature PIN, and
  Autenticacao.gov middleware or supported OS cryptographic integration.
- CSC/QTSP production remains provider-specific and requires sandbox/prod
  onboarding, client credentials or user authorization, credential selection,
  signer authorization, contract/legal terms, and live conformance testing.
- TSL/TSA/DSS/revocation checks are validation and evidence controls. They do
  not replace the qualified certificate, qualified provider, QSCD, or signer
  authorization ceremony.
- B-LT/B-LTA, embedded DSS/VRI, revocation evidence, and archive timestamps are
  long-term-validation work after basic signature creation; they must not be
  marketed as proof that Chancela itself is a QTSP.
- The default product stance is fail-closed: if the provider status,
  certificate qualification, QSCD/remote-QSCD indication, signer authorization,
  or validation evidence cannot be established, Chancela must present the result
  as incomplete or technically signed only, not as a completed qualified
  signature.

## Why

Official eIDAS wording gives qualified electronic signatures the legal effect
equivalent to handwritten signatures. Autenticacao.gov states that Portuguese
digital signatures with Cartao de Cidadao or CMD have the same legal validity as
handwritten signatures when the user's CC/CMD signature capability is active and
used through the appropriate software/provider flows. The same source material
also makes the requirements visible: active CMD or CC signature capability,
signature PIN/security-code ceremony, middleware or service integration,
qualified certificate policy material, trusted-list status, and provider
onboarding where an integrating service is involved.

## Primary Sources

Keep these links attached to implementation copy, legal review notes, and
operator-facing documentation:

- eIDAS consolidated Regulation, especially Article 25 legal effect, Article 22
  trusted lists, and the qualified-signature/QSCD structure:
  https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX%3A02014R0910-20241018
- European Commission EU trusted lists policy page:
  https://digital-strategy.ec.europa.eu/en/policies/eu-trusted-lists
- European Commission EU/EEA Trusted List Browser:
  https://eidas.ec.europa.eu/efda/tl-browser/
- European Commission DSS project reference:
  https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/467109107/Digital%2BSignature%2BService%2B-%2BDSS
- European Commission DSS validation demonstration/reference:
  https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/validation
- GNS eIDAS supervisory page:
  https://www.gns.gov.pt/pt/regulamento-eidas-entidade
- GNS national trusted-list page:
  https://www.gns.gov.pt/pt/regulamento-eidas-lista
- GNS trusted-lists index:
  https://www.gns.gov.pt/pt/trusted-lists
- Autenticacao.gov qualified digital-signature overview:
  https://www.autenticacao.gov.pt/assinatura-digital/assinatura-digital-qualificada
- Autenticacao.gov CMD signature page:
  https://www.autenticacao.gov.pt/cmd-assinatura
- Autenticacao.gov CMD signature activation:
  https://www.autenticacao.gov.pt/ativar-a-assinatura-digital-da-chave-movel-digital
- Autenticacao.gov CMD policy and qualified-signature information:
  https://www.autenticacao.gov.pt/politicas-e-informacao-sobre-chave-movel-digital
- Autenticacao.gov CC digital-signature page:
  https://www.autenticacao.gov.pt/cartao-cidadao/assinatura-digital
- Autenticacao.gov integration overview:
  https://www.autenticacao.gov.pt/integrar-com-o-autenticacao-gov
- Autenticacao.gov entity-integration request page:
  https://www.autenticacao.gov.pt/integracao-entidade
- Autenticacao.gov desktop application manual, including middleware and
  application integration:
  https://amagovpt.github.io/docs.autenticacao.gov/user_manual.html
- Autenticacao.gov middleware SDK manual, including CMD/CC integration notes:
  https://amagovpt.github.io/docs.autenticacao.gov/manual_sdk.html

## Implementation Implications

Chancela's signing feature should be framed as orchestration, artifact handling,
validation, evidence capture, and preservation. It may be legally useful because
the underlying CMD/CC/QTSP output can be legally binding, not because Chancela
has become a certifier.

Any implementation, test fixture, demo provider, offline DSS report, cached TSL,
or local timestamp must keep explicit non-production wording until live
provider/certificate/hardware/onboarding requirements have been satisfied and
verified against the official sources above.
