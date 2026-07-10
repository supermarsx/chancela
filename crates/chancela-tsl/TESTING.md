# Testing `chancela-tsl`

`chancela-tsl` ingests the Portuguese Trusted List (ETSI TS 119 612) and answers whether a
certificate's issuer is a currently-qualified QTSP for **e-signatures** (SIG-10..13).

## Default tests — offline, no network (run in CI on all three OS)

```sh
cargo test -p chancela-tsl
```

Every default test is fully offline and deterministic. They parse the bundled fixture
`fixtures/pt-tsl-sample.xml` and resolve issuer certificates against it. Coverage:

- **Parsing** (`parse::tests`, `tsl_fixture::parses_scheme_information`): scheme territory,
  sequence number, issue/next-update timestamps, provider count; namespace-prefixed elements are
  matched by local name; multilingual/duplicated scheme, provider, trade and service names are
  retained for catalog search; malformed optional status dates are retained as raw text while the
  parsed time is `None`; service supply points and current/historical digital identities are
  structured; a missing root element is a `Structure` error; the local base64 decoder handles
  padding and wrapped/whitespace input and rejects invalid characters.
- **Status resolution** (`tsl_fixture`): a granted CA/QC for e-signatures resolves `Granted`; a
  withdrawn one `Withdrawn`; a CA/QC granted only for e-seals `Withdrawn` (not for signatures);
  an unlisted issuer `Unknown`; non-certificate garbage bytes resolve `Unknown` rather than
  erroring.
- **Issuer matching** (`query::tests`): match by full certificate DER, by Subject Key Identifier
  only, and by Subject Name only; a granted-but-not-yet-effective status resolves `Withdrawn`;
  SKI extraction from the X.509 `SubjectKeyIdentifier` extension.
- **Service history is advisory** (`tsl_fixture::service_history_is_ignored`): current
  `ServiceInformation` remains the only input to qualified-status decisions, while
  `ServiceHistory` instances are retained separately for catalog diagnostics/search.
- **Cache / validity window** (`cache::tests`, `tsl_fixture::client_caches_and_reports_staleness`):
  staleness follows the list's `NextUpdate`; a list without one uses a 24h fallback TTL.
- **Discovery** (`tsl_fixture::discovery_lists_only_the_granted_esig_service`): SIG-12 listing.
- **XML-DSig/TSL trust gate** (`tsl_fixture::tsl_signature_validation_*`,
  `tsl_fixture::client_downgrades_*`): missing signatures, malformed base64, unsupported
  canonicalization/signature algorithms, unsupported reference transforms, multiple references,
  digest mismatches, tampered `SignedInfo`, tampered referenced content, and tampered
  `SignatureValue` all fail closed. `TslClient` caches the parsed list for diagnostics but
  downgrades `Granted` to `Unknown` when validation fails.
- **Catalog edge fixture** (`fixtures/pt-tsl-sample.xml`): duplicate service names, accent-heavy
  operator/provider aliases, missing optional service names, malformed status dates, multiple TSA
  service types, withdrawn and revoked-like statuses, and service supply points.

## Network test — live TSL fetch (never runs in CI)

The live-fetch test is **double-gated**: it is compiled only under the `network-tests` feature
**and** is `#[ignore]`d. To run it:

```sh
cargo test -p chancela-tsl --features network-tests -- --ignored
```

It fetches the real Portuguese Trusted List and parses it. Prerequisites:

- Outbound HTTPS to the TSL endpoint.
- Optionally set `CHANCELA_TSL_URL` to override the pinned GNS default
  (`https://www.gns.gov.pt/media/TSLPT.xml`, verified live 2026-07-07); resolvable from the EU
  List of Trusted Lists. GNS occasionally renames the published asset (the older
  `media/2793/TSL_PT.xml` form now 404s), so re-verify this URL on future TSL work.

Nothing in CI sets the feature or passes `--ignored`, so the network is never touched there.

## XML-DSig validation boundary (SIG-11)

`source::validate_tsl_signature` validates the Trusted List's XML-DSig metadata enough for the
trust gate to reject missing/malformed signatures, unsupported algorithms, digest mismatches and
signature verification failures against the public key embedded in `<ds:KeyInfo>`. `TslClient`
records the validation result at refresh time and never reports `QualifiedStatus::Granted` when
that validation fails. The bundled fixture carries a deliberately invalid placeholder signature, so
catalog surfaces show it as advisory.

This is **not** full legal/authenticated EU TSL validation yet. Remaining blockers include signer
certificate trust anchoring to the EU LOTL or national scheme-operator trust anchor, certificate
path/revocation/policy validation for the TSL signer, full XML canonicalization/transform
processing, `URI="#id"` reference resolution, and ECDSA XML-DSig verification. Until those are
implemented, a cryptographically valid XML-DSig only proves the document matches the embedded
signer certificate's public key, not that the signer is legally trusted to publish the TSL.

## Fixtures

- `fixtures/pt-tsl-sample.xml` — a representative PT TSL authored to mirror the real ETSI TS
  119 612 structure (scheme information, four providers, current + history service information,
  digital identities as certificate/subject-name/SKI, supply points, additional-service-information
  markers, duplicate/multilingual names, malformed optional dates, revoked-like TSA status, and an
  invalid placeholder `ds:Signature`). The certificates are **ephemeral self-signed fixtures, not
  real QTSP CAs.**
- `fixtures/unlisted-ca.der` — a self-signed CA certificate absent from the sample list, used for
  the `Unknown` case.

The fixture certificates were generated with OpenSSL (`req -x509 ... -addext
subjectKeyIdentifier=hash`). No private keys are checked in — only public certificates. The SKI
byte array hard-coded in `query::tests` (`MULTICERT_SKI`) is the OpenSSL-reported SKI of the
MULTICERT fixture CA.
