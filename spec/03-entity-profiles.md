# 03 — Entity Type Profiles

Requirement prefix: `ENT`

Each entity family gets a dedicated **profile**: selectable legal types, a compliance rule
pack, a template family, a signature policy, and an archive model. Profiles are the unit of
legal behavior — a condominium is not "corporate-company lite."

- **ENT-01** The entity model MUST offer, at minimum, the families and types below.
- **ENT-02** Each profile MUST bind: (a) mandatory ata contents, (b) meeting/deliberation
  channels allowed, (c) signature requirements, (d) template family, (e) calendar presets,
  (f) registry-integration mapping.
- **ENT-03** Profiles MUST be extensible per entity by its own statutes: statute-derived
  constraints (e.g., quorum, majorities, convocation deadlines) layer on top of the legal
  rule pack and MUST be editable with an audit trail.

## 1. Commercial companies (`ENT-C`)

Legal grounding: CSC art. 1.º (types), art. 63.º (ata contents), art. 270.º-A ff.
(unipessoal regime), arts. 376.º–388.º (general meetings, SA specifics).

- **ENT-C1** Selectable types MUST include: sociedade em nome coletivo; sociedade por
  quotas; sociedade unipessoal por quotas; sociedade anónima; sociedade em comandita
  simples; sociedade em comandita por ações.
- **ENT-C2** The rule pack MUST enforce CSC art. 63.º minimum contents before sealing
  (see LEG-03).
- **ENT-C3** For sociedades anónimas, the profile MUST require an ata per general meeting
  (art. 388.º) and ship the annual-meeting calendar preset (art. 376.º).
- **ENT-C4** Telematic general meetings MUST be supported with the art. 377.º evidence
  requirements captured (authenticity, communication security, recording of content and
  participants).
- **ENT-C5** Written resolutions (deliberações unânimes por escrito / voto escrito) MUST be
  a supported deliberation channel where the CSC admits them, with their own template and
  evidence rules.
- **ENT-C6** Loose-leaf minute systems MUST implement the anti-falsification measures of
  art. 63.º (numbering, sequencing, chaining); detached private documents MUST be labeled
  as carrying only *beginning-of-proof* evidentiary weight.
- **ENT-C7** Groups of companies MUST be supported: shared template libraries and
  cross-entity dashboards, while each entity retains its own legal books and audit trail.

## 2. Condominiums (`ENT-D`)

Legal grounding: DL 268/94 as revised in 2022 (Lei 8/2022); Código Civil propriedade
horizontal regime.

- **ENT-D1** A dedicated condominium profile MUST exist with its own template family,
  signature workflow, and archive model.
- **ENT-D2** The rule pack MUST require that the ata summarize the essential matters
  discussed and the result of each vote.
- **ENT-D3** Signature policy MUST allow: qualified electronic signatures, or handwritten
  signatures on the original or on a digitized document alongside other signatures.
- **ENT-D4** Email declarations confirming agreement with the ata MUST be supported as
  **annexes to the original**, captured with sender identity evidence and timestamps.
- **ENT-D5** Remote/hybrid assemblies MUST be supported per the 2022 revision, with
  participation evidence captured.
- **ENT-D6** Signatory roles MUST include condominium-specific roles (administrator, condo
  owner, proxy) with fraction/permilage metadata for vote weighting.

## 3. Associations (`ENT-A`)

Legal grounding: Código Civil (private legal persons); ePortugal association creation and
operation flows.

- **ENT-A1** The profile MUST support associação and statute-configured subtypes.
- **ENT-A2** Mandatory ata contents derive from the Civil Code baseline plus the
  association's statutes (ENT-03 layering).
- **ENT-A3** Templates MUST cover at least: general assembly minutes, board (direção)
  resolutions, fiscal council minutes, statute amendments, and elections of governing
  bodies.

## 4. Foundations (`ENT-F`)

Legal grounding: Código Civil; Lei-Quadro das Fundações (Lei 24/2012); foundation
permanent-certificate registry services.

- **ENT-F1** The profile MUST support fundação with board (conselho de administração) and
  supervisory-organ minutes.
- **ENT-F2** Registry integration MUST use the foundation permanent-certificate service
  (LEG-21).

## 5. Cooperatives (`ENT-K`)

Legal grounding: Código Cooperativo; ePortugal treats cooperatives as a separate creation
path; permanent-certificate records include cooperative registrations.

- **ENT-K1** The profile MUST support cooperativa as a distinct type (not a company
  subtype), with general-assembly and direction-organ minutes.
- **ENT-K2** Cooperative-specific deliberation rules (one-member-one-vote defaults,
  statute-configurable variations) MUST be expressible in the statute layer.

## 6. Profile summary matrix

| Family | Types (min.) | Rule pack anchor | Distinctive requirements |
|---|---|---|---|
| Commercial companies | 6 CSC types | CSC arts. 63.º, 376.º–388.º | Art. 63.º contents; SA annual meeting; telematic evidence; written resolutions; loose-leaf anti-falsification |
| Condominiums | condomínio (prop. horizontal) | DL 268/94 (rev. 2022) | Vote-result summaries; email-agreement annexes; owner/permilage roles; remote assemblies |
| Associations | associação + statute subtypes | Código Civil + statutes | Organ elections; statute-driven quorum/majorities |
| Foundations | fundação | CC + Lei 24/2012 | Board/supervisory minutes; foundation registry certificate |
| Cooperatives | cooperativa | Código Cooperativo | Distinct creation path; cooperative voting rules |
