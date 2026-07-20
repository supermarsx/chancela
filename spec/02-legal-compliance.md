# 02 — Legal and Compliance Baseline

Requirement prefix: `LEG`

## 1. Guiding principle

The app helps produce compliant records; it **does not create legal validity** out of an
invalid meeting, missing powers, or a defective corporate process. The software MUST always
distinguish **substantive validity** from **documentary evidence**.

## 2. Statutory anchors

| Source | Relevance |
|---|---|
| CSC art. 63.º | Mandatory minimum contents of an ata; anti-falsification precautions for loose leaves; resolutions found only in detached private documents are merely a *beginning of proof* |
| CSC art. 376.º | Timing of the annual general meeting (sociedades anónimas) — drives legal-calendar presets |
| CSC art. 377.º | Convocation rules; permits general meetings by telematic means provided the company ensures authenticity of statements, communication security, and recording of content and participants |
| CSC art. 388.º | Sociedades anónimas: an ata is required for each general meeting |
| DL 268/94 (as amended, incl. Lei 8/2022) | Condominium assemblies: minutes mandatory; ata must summarize essential matters and each vote's result; signatures may be qualified electronic or handwritten on the original or a digitized document; email declarations of agreement are annexes to the original |
| DL 12/2021 | Portuguese execution of eIDAS: a qualified electronic signature on an electronic document is equivalent to a handwritten signature and creates presumptions of identity/representation, intent to sign, and integrity; qualified timestamps carry a presumption as to time and integrity |
| Regulation (EU) 910/2014 (eIDAS), art. 25 | Legal effect of qualified electronic signatures across the EU |
| GDPR arts. 5, 25, 32, 35 | Data minimization and purpose limitation; data protection by design and by default; security of processing; DPIA where high risk |
| Código Civil + Lei-Quadro das Fundações (Lei 24/2012) | Associations and foundations as private legal persons |

## 3. Compliance engine

- **LEG-01** The product MUST include a **compliance engine** that checks, before an ata can
  be finalized, whether it contains all legally required fields for its entity family and
  meeting type.
- **LEG-02** Compliance rules MUST be packaged as versioned **rule packs** per entity family
  (see [03 — Entity type profiles](03-entity-profiles.md)); rule packs are data + code owned
  by the Rust domain core, not UI logic.
- **LEG-03** For commercial companies, the CSC art. 63.º rule pack MUST verify at minimum:
  identity of the company; place, date, and time of the meeting; president and secretaries;
  names of those present or represented; agenda; references to submitted documents; the full
  text of resolutions; voting results; and statements requested by members.
- **LEG-04** The engine MUST support **telematic meetings** as a first-class meeting
  channel, capturing the evidence CSC art. 377.º requires (authenticity of statements,
  communication security, recording of content and participants). The same logic applies to
  board meetings where telematic means are permitted.
- **LEG-05** Compliance failures MUST be surfaced as blocking or advisory findings with the
  legal basis cited; users MAY override advisory findings with a recorded justification, but
  MUST NOT be able to silently bypass blocking findings.
- **LEG-06** Rule-pack versions in force at sealing time MUST be recorded in the sealed
  act's metadata so evidence is reproducible.

## 4. Privacy and GDPR (by design and by default)

- **LEG-10** The product MUST implement GDPR by design and by default (art. 25), not as a
  bolt-on. Concretely, the specification requires all of:
  - tenant isolation;
  - per-company access scoping;
  - field-level redaction for guest users;
  - configurable retention schedules;
  - legal-hold support;
  - data-subject rights workflows (access, rectification, erasure where applicable);
  - processor/subprocessor registry;
  - records of processing activities (art. 30);
  - breach-response playbooks;
  - transfer controls for any data leaving the EEA or stored with third-party sync providers.
- **LEG-11** A DPIA template and guidance MUST ship for deployments likely to involve
  high-risk processing (art. 35).
- **LEG-12** Security of processing (art. 32) MUST follow CNPD/EDPB guidance: incident
  management, controls over processors, encryption, and the ability to restore availability
  after technical or physical incidents (this drives the sync-vs-backup split in
  [07 — Architecture](07-architecture.md)).
- **LEG-13** The privacy architecture MUST state clearly that **zero-knowledge encryption
  reduces exposure but does not remove GDPR obligations**: encrypted personal data and usage
  metadata remain regulated processing.

## 5. Registry integration baseline

- **LEG-20** The product MUST support importing company/entity data from the **certidão
  permanente** by access code: online commercial-registry record, associated electronic
  documents, and the latest articles of association/statutes. FCPC records additionally
  expose NIPC, name, seat, CAE, legal nature, object, and status.
- **LEG-21** Foundations MUST be supported through the equivalent foundation
  permanent-certificate service.
- **LEG-22** Imported registry data MUST be stored with provenance (source, access code
  reference, retrieval timestamp) and MUST feed the chronology graph
  ([08 — Documents and archive](08-documents-archive.md)).
