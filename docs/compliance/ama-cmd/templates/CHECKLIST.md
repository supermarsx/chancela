# AMA/CMD Authority Review Checklist

Generated at: {{generatedAt}}

Status legend: `pending`, `attached`, `reviewed`, `accepted`, `rejected`,
`not applicable`.

## 1. Protocol/Application Formalization

- [ ] Status recorded for signed protocol/application documents.
- [ ] Signed protocol/application documents attached under
      `evidence/signed-protocol-application/`.
- [ ] Authority submission receipt or correspondence attached.
- [ ] Legal/security owner has reviewed whether attached documents need
      redaction before wider distribution.
- [ ] No pack text claims production approval unless an explicit AMA acceptance
      record is attached.
- [ ] No pack text claims live production CMD validity unless AMA-issued
      credentials, production `ApplicationId`, and required certificate/public-key
      evidence are attached.

## 2. Production ApplicationId and Certificate Evidence

- [ ] Production `ApplicationId` assignment evidence attached under
      `evidence/production-applicationid-certificate/`.
- [ ] Production certificate/public-key material evidence attached with secrets
      and private keys excluded.
- [ ] Certificate fingerprint, subject, issuer, validity dates, and source of
      receipt are recorded.
- [ ] Configuration screenshots or logs are redacted and do not reveal secrets,
      OTPs, PINs, private keys, or unmasked production credentials.
- [ ] Evidence distinguishes pre-production values from production values.

## 3. Test Evidence

- [ ] Signed guidelines/report document with LTV evidence attached, if required
      for the review route.
- [ ] Five pre-production signed-document examples are attached or explicitly
      marked not applicable with reviewer rationale.
- [ ] For each example, the pack includes the original document, signed
      document, cryptographic digest, signed digest, ProcessID, and validation
      notes.
- [ ] Source-code evidence for the integration component is attached as a
      reviewed excerpt, archive, commit reference, or checksum.
- [ ] Test evidence uses pre-production identifiers unless production use has
      been explicitly authorized.

## 4. Short App Video

- [ ] Demonstrative video or video-link manifest attached under
      `evidence/app-video/`.
- [ ] Video shows the relevant user flow without exposing secrets, private
      data, PINs, OTPs, unredacted `ApplicationId` values, or private keys.
- [ ] Transcript or shot list attached for reviewer navigation.
- [ ] Video filename, duration, hash, recording date, and reviewer-facing notes
      are recorded.

## 5. Honesty and Review Boundary

- [ ] Pack summary says this is demonstrability evidence, not production
      approval.
- [ ] Open gaps and missing evidence are listed.
- [ ] Any statement about legal compliance is attributed to actual legal review
      or removed.
- [ ] Any statement about AMA/CMD approval is attributed to attached authority
      correspondence or removed.
- [ ] Any production CMD claim is blocked unless production credential and
      certificate evidence is present in this pack.
- [ ] Final reviewer sign-off records the reviewer, date, scope, and evidence
      version.

## Official Source Metadata

{{sourceTable}}
