# 11 — Template Catalog (End-to-End)

Requirement prefix: `TPL`

This catalog covers the **entire document chain** of a corporate act — from opening the
book to certifying the sealed ata — not only the minutes. Every template is versioned,
per-locale (UX-21), and bound to the rule pack of its entity profile (WFL-31).

## 1. Principles

- **TPL-01** Templates MUST be organized by **lifecycle stage** (book → pre-meeting →
  meeting → act → post-act) and by **entity family** (ENT profiles). A template declares
  which entity families and meeting channels it applies to.
- **TPL-02 (Document chaining.)** Generated documents MUST be linked across the lifecycle:
  convocatória → lista de presenças / procurações → ata → termo instruments → certidões /
  registry packages. Each document records its predecessors' identifiers and digests, so
  the full chain is verifiable from any node (WFL-33, DAT-10).
- **TPL-03** Template fields MUST be typed and bound to the data model (entity, organ,
  meeting, participants), so documents are **generated from records**, not free-typed:
  the convocatória is generated from the meeting record, the attendance list from the
  participant records, the ata pre-filled from both.
- **TPL-04** Every template MUST declare the **signature policy** its output requires
  (who signs, in what capacity, which signing families are acceptable — SIG-01) and the
  compliance rules that gate its sealing (LEG-01).

## 2. Book instruments

| Template | Purpose | Notes |
|---|---|---|
| Termo de abertura | Opens a livro de atas (per organ) | Genesis of the book's hash chain (WFL-11) |
| Termo de encerramento | Closes a book | Records ata/page counts, closing reason (WFL-13) |
| Termo de transporte / continuação | Opens a successor book referencing the predecessor | Required when a closed book has a successor (WFL-13) |
| Termo de retificação | Formal correction instrument | Always a new act referencing the sealed one (WFL-21) |

- **TPL-10** Termo de abertura and termo de encerramento templates MUST exist for every
  entity family and organ type supported by the entity profile.
- **TPL-11** Termo instruments follow the same seal-and-chain rules as atas (WFL-10).

## 3. Pre-meeting documents

| Template | Applies to | Notes |
|---|---|---|
| Convocatória de assembleia geral | Companies | CSC art. 377.º formalities (deadlines, agenda, means) per company type |
| Convocatória de reunião de gerência/administração | Companies | Board meetings |
| Aviso convocatório de assembleia de condóminos | Condominiums | DL 268/94 / CC propriedade horizontal formalities |
| Convocatória de assembleia geral de associação | Associations | Statute-driven deadlines (ENT-A2) |
| Convocatória de órgãos de fundação / cooperativa | Foundations, cooperatives | Per ENT-F / ENT-K profiles |
| Proposta / ponto da ordem de trabalhos | All | Structured agenda items feeding the ata |
| Procuração / instrumento de representação | All | Powers of representation; feeds delegation evidence (ROL-11) |
| Carta de representação | Sociedades anónimas | Shareholder representation for general meetings |
| Circular de deliberação por escrito | Companies (where admissible) | Written-resolution circulation (ENT-C5) |

- **TPL-20** Convocatória templates MUST enforce per-profile convocation deadlines and
  content formalities as compliance rules, and MUST capture proof of dispatch (send date,
  channel, recipients) as evidence attached to the meeting record.

## 4. Meeting documents

| Template | Applies to | Notes |
|---|---|---|
| Lista de presenças | All | Generated from participant records; permilage/vote weight for condominiums (ENT-D6) |
| Declaração de voto | All | Member statements for the record (CSC art. 63.º) |
| Voto por correspondência | Where admissible | With identity/receipt evidence |
| Registo de participação telemática | All telematic meetings | The art. 377.º evidence set: authenticity, security, recording of content and participants (LEG-04) |

## 5. Act (ata) templates per entity family

### Commercial companies

**Governance and management**

- General meeting minutes (per company type); board (gerência/administração) resolutions
- Appointment (designação) and dismissal (destituição) of gerência/administração
- Renúncia de gerente/administrador (resignation, recorded with replacement appointment)
- Retoma de gerência (resumption of management)
- Remuneração da gerência/administração — including the explicit **não remuneração**
  variant (commonly required for Social Security purposes)
- Delegation of powers (atribuição de poderes) and its revocation

**Accounts and results**

- Approval of accounts and appropriation of results
- Distribution of dividends; adiantamento sobre lucros where admissible

**Capital, quotas, and shareholders**

- Increase and reduction of capital
- Entrada de novo sócio (admission of a new shareholder)
- Cessão de quotas; divisão de quotas; unificação de quotas; amortização de quotas
- Exoneração and exclusão de sócio
- Supplementary contributions (prestações suplementares)
- Suprimentos (shareholder loans — constituição/contrato de suprimentos; legally distinct
  from prestações suplementares)

**Structural changes**

- Change of registered office (alteração de sede); change of object (alteração de objeto);
  change of company name (alteração da firma); amendment of articles generally
- Transformação de sociedade (conversion between company types)
- Merger and demerger support (fusão e cisão); dissolution; liquidation steps

**Deliberation forms**

- Written resolutions (deliberações unânimes por escrito) where admissible

### Condominiums

- Assembleia de condóminos minutes (ordinary and extraordinary)
- Appointment/dismissal of the administrator; accounts approval; works and fund resolutions
- Email-agreement annex record (ENT-D4)

### Associations

- General assembly minutes; direção resolutions; conselho fiscal minutes
- Statute amendments; election of governing bodies; tomada de posse (taking of office)

### Foundations

- Conselho de administração resolutions; supervisory-organ minutes

### Cooperatives

- General assembly minutes; direction-organ resolutions

- **TPL-30** Each act template MUST be bound to its family's rule pack so sealing is gated
  by the correct mandatory-content checks (LEG-03, ENT-D2, ENT-A2).
- **TPL-31 (Market parity.)** The commercial-company act set MUST at minimum cover the
  union of templates commonly published by Portuguese practice catalogs (e.g., atas.pt,
  mibfer.pt). Before each release, the catalog is checked against those references; a
  template they publish that this catalog cannot express is a specification bug (TPL-50).

## 6. Post-act instruments

| Template | Purpose | Notes |
|---|---|---|
| Certidão de ata | Certified full copy of a sealed ata | Generated only from sealed acts; carries the validation report reference |
| Extrato / fotocópia certificada de ata | Certified extract | Scoped to selected resolutions |
| Comunicação de deliberações a condóminos ausentes | Condominiums | CC propriedade horizontal regime requires notifying absent owners; deadline preset in the reminders engine (WFL-42) |
| Comunicação / depósito para registo comercial | Companies | Registry filing package (prepared, not submitted — SCP-41) |
| Declaração de deliberação | All | For banks, notaries, and third parties |

- **TPL-40** Certidões and extracts MUST be generated exclusively from **sealed** acts,
  MUST reference the sealed act's identifier and digest (TPL-02), and MUST themselves be
  signable with the qualified-signature stack (SIG-01).
- **TPL-41** The condominium absent-owner communication MUST be generated automatically
  after sealing an assembleia ata, with its dispatch evidence attached to the act.

## 7. Coverage matrix

| Lifecycle stage | Companies | Condominiums | Associations | Foundations | Cooperatives |
|---|---|---|---|---|---|
| Book instruments (termos) | ✔ | ✔ | ✔ | ✔ | ✔ |
| Convocatória / aviso | ✔ | ✔ | ✔ | ✔ | ✔ |
| Representation / proxy | ✔ | ✔ | ✔ | ✔ | ✔ |
| Attendance / voting records | ✔ | ✔ (permilage) | ✔ | ✔ | ✔ |
| Act templates | ✔ (full set §5) | ✔ | ✔ | ✔ | ✔ |
| Certidão / extract | ✔ | ✔ | ✔ | ✔ | ✔ |
| Post-act notifications | registry package | absent owners | — | registry package | registry package |

- **TPL-50** A template gap in this matrix for a supported entity family is a
  specification bug: file it against this document.
