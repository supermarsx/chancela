//! The typed certidão extract ([`RegistryExtract`]) and its parts.

use serde::{Deserialize, Serialize};

/// Normalized legal form. Variant names are **aligned 1:1 with `chancela_core::EntityKind`** so the
/// API maps them without a lookup table (mirrors t4-e5 `QualifiedStatus`→`TrustedListStatus`). This
/// crate stays a **leaf**: it does NOT depend on `chancela-core`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum LegalForm {
    SociedadePorQuotas,
    SociedadeUnipessoalPorQuotas,
    SociedadeAnonima,
    SociedadeEmNomeColetivo,
    SociedadeEmComanditaSimples,
    SociedadeEmComanditaPorAcoes,
    Cooperativa,
    Fundacao,
    Associacao,
    /// Raw "Natureza Jurídica" text when unmapped.
    Other(String),
}

/// Whether a CAE code is the certidão's **CAE Principal** or one of its **CAE Secundário(s)**. The
/// principal is the company's main declared economic activity; the secondaries are additional ones.
/// Serialized as the bare serde variant name (`"Principal"` / `"Secundario"`, house convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaeRole {
    Principal,
    Secundario,
}

/// A single CAE code tagged with its role on the certidão. `code` is the bare code token (secção
/// letter or `NNNNN` digit code); any trailing `" - Designação"` printed on the certidão is dropped
/// here — the designation is resolved separately from the CAE catalog at the API layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaeRef {
    pub code: String,
    pub role: CaeRole,
}

/// One numbered registry entry (inscrição/averbamento/anotação) — the DOC-30 event feed, kept
/// raw-but-ordered. Not interpreted into a chronology here (that is DOC-30/31/32, a later task).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEvent {
    /// "1", "2 Av.1", …
    pub number: Option<String>,
    /// e.g. "CONSTITUIÇÃO", "DESIGNAÇÃO DE MEMBRO(S) DE ORGÃO(S)…".
    pub kind_hint: Option<String>,
    /// "Ap. 123/20240115".
    pub apresentacao: Option<String>,
    /// ISO `YYYY-MM-DD` best-effort, else `None`.
    pub date: Option<String>,
    /// The full entry text, verbatim.
    pub text: String,
    /// The structured layer read off `text` (additive; `None` when the body was not deep-parsed).
    /// Raw `text` always carries everything — the detail layer is never lossy.
    pub detail: Option<InscriptionDetail>,
}

/// A member of a social organ (gerência/administração), best-effort from designation entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryOfficer {
    pub name: String,
    /// "Gerente", "Administrador", "Presidente", …
    pub role: Option<String>,
    /// ISO, best-effort.
    pub appointment_date: Option<String>,
    /// ISO, best-effort (present ⇒ no longer in office).
    pub cessation_date: Option<String>,
    /// The inscrição number this officer came from.
    pub source_event: Option<String>,
}

/// Where an extract came from (LEG-22 provenance). Carries only the **masked** access code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryProvenance {
    /// "****-****-NNNN" — NEVER the full code.
    pub access_code_masked: String,
    /// RFC 3339 UTC.
    pub retrieved_at: String,
    pub source_url: String,
    /// Lowercase-hex sha256 of the raw certidão HTML.
    pub raw_digest: String,
    /// "Conservatória do Registo Comercial <X>" from the certidão trailer (additive).
    pub conservatoria: Option<String>,
    /// "O(A) Oficial de Registos, <name>" from the certidão trailer (additive).
    pub oficial: Option<String>,
    /// ISO `YYYY-MM-DD` from "Certidão permanente subscrita em DD/MM/YYYY".
    pub subscribed_on: Option<String>,
    /// ISO `YYYY-MM-DD` from "válida até DD/MM/YYYY". Expiry itself is clock-dependent and is
    /// computed at the API layer against "today" — never stored here (keeps the model deterministic).
    pub valid_until: Option<String>,
}

/// The typed certidão extract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryExtract {
    pub matricula: Option<String>,
    /// Raw 9-digit string as registered (the API validates via `Nipc`).
    pub nipc: Option<String>,
    /// Name / denominação.
    pub firma: Option<String>,
    /// Raw "Natureza Jurídica" text.
    pub forma_juridica: Option<String>,
    /// Normalized (`None` if the block was absent).
    pub legal_form: Option<LegalForm>,
    pub sede: Option<String>,
    /// Role-tagged CAE codes (`CAE Principal` + any `CAE Secundário(s)`), in certidão order.
    pub cae: Vec<CaeRef>,
    pub objeto: Option<String>,
    /// "5.000,00 EUR" as text (no numeric coercion in v1).
    pub capital: Option<String>,
    /// ISO `YYYY-MM-DD` best-effort.
    pub data_constituicao: Option<String>,
    pub orgaos: Vec<RegistryOfficer>,
    /// Ordered as printed.
    pub inscricoes: Vec<RegistryEvent>,
    /// The `An. N` publication annotations, ordered as printed (additive).
    pub anotacoes: Vec<RegistryAnnotation>,
    pub provenance: RegistryProvenance,
}

impl RegistryExtract {
    /// The first inscrição carrying a structured [`ConstitutionPayload`], if any. Used by the
    /// `effective_*` backfill accessors and by the API's create-from-registry fallback.
    pub fn constitution(&self) -> Option<&ConstitutionPayload> {
        self.inscricoes
            .iter()
            .find_map(|e| match e.detail.as_ref()?.payload.as_ref()? {
                InscriptionPayload::Constitution(c) => Some(c),
                _ => None,
            })
    }

    /// Firma from the matrícula block, falling back to the constitution body (backfill for a
    /// certidão whose summary block is absent). Returns an owned string for a uniform call site.
    pub fn effective_firma(&self) -> Option<String> {
        self.firma
            .clone()
            .or_else(|| self.constitution().and_then(|c| c.firma.clone()))
    }

    /// NIPC from the matrícula block, falling back to the constitution body.
    pub fn effective_nipc(&self) -> Option<String> {
        self.nipc
            .clone()
            .or_else(|| self.constitution().and_then(|c| c.nipc.clone()))
    }

    /// Sede from the matrícula block, falling back to the constitution body's structured address
    /// rendered to a single line.
    pub fn effective_sede(&self) -> Option<String> {
        self.sede.clone().or_else(|| {
            self.constitution()
                .and_then(|c| c.sede.as_ref().map(Address::to_single_line))
        })
    }

    /// Objecto from the matrícula block, falling back to the constitution body.
    pub fn effective_objecto(&self) -> Option<String> {
        self.objeto
            .clone()
            .or_else(|| self.constitution().and_then(|c| c.objecto.clone()))
    }

    /// Capital from the matrícula block, falling back to the constitution body's money figure.
    pub fn effective_capital(&self) -> Option<String> {
        self.capital.clone().or_else(|| {
            self.constitution()
                .and_then(|c| c.capital.as_ref().map(Money::to_display))
        })
    }

    /// Founding/constitution date from the matrícula block, falling back to the structured
    /// constitution body when the summary block is sparse.
    pub fn effective_data_constituicao(&self) -> Option<String> {
        self.data_constituicao.clone().or_else(|| {
            self.constitution()
                .and_then(|c| c.deliberation_date.clone())
                .or_else(|| {
                    self.inscricoes.iter().find_map(|e| {
                        let payload = e.detail.as_ref()?.payload.as_ref()?;
                        match payload {
                            InscriptionPayload::Constitution(_) => e.date.clone(),
                            _ => None,
                        }
                    })
                })
        })
    }
}

// ---- Structured inscription layer (additive; see the t21 plan §1) ----------------------------

/// A postal address as printed on a certidão — free lines plus the admin/postal breakdown when
/// present. Reused for a company SEDE and a person's Residência/Sede.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Address {
    /// Free address lines, in order (e.g. "Rua do Exemplo, n.º 11, Lugarejo").
    pub lines: Vec<String>,
    pub distrito: Option<String>,
    pub concelho: Option<String>,
    pub freguesia: Option<String>,
    /// Normalized `NNNN-NNN`.
    pub postal_code: Option<String>,
    pub locality: Option<String>,
}

impl Address {
    /// `true` when nothing at all was captured (used to drop empty accumulations).
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
            && self.distrito.is_none()
            && self.concelho.is_none()
            && self.freguesia.is_none()
            && self.postal_code.is_none()
            && self.locality.is_none()
    }

    /// Render the address to a single comma-joined line (free lines + `postal_code locality`),
    /// for the string-typed extract-level `sede` backfill.
    pub fn to_single_line(&self) -> String {
        let mut parts: Vec<String> = self.lines.clone();
        match (&self.postal_code, &self.locality) {
            (Some(pc), Some(loc)) => parts.push(format!("{pc} {loc}")),
            (Some(pc), None) => parts.push(pc.clone()),
            (None, Some(loc)) => parts.push(loc.clone()),
            (None, None) => {}
        }
        parts.join(", ")
    }
}

/// A monetary figure as printed — TEXT, no numeric coercion (v1 keeps the model coercion-free).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Money {
    /// "100,00".
    pub amount_text: String,
    /// "Euros" / "EUR".
    pub currency: Option<String>,
}

impl Money {
    /// "amount currency" (e.g. "100,00 Euros"), or just the amount when no currency was printed.
    pub fn to_display(&self) -> String {
        match &self.currency {
            Some(c) if !c.is_empty() => format!("{} {}", self.amount_text, c),
            _ => self.amount_text.clone(),
        }
    }
}

/// A named party (a sócio's titular, an organ member's identity).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Person {
    /// TITULAR / Nome-Firma value.
    pub name: String,
    /// NIF/NIPC digits.
    pub nif: Option<String>,
    pub estado_civil: Option<String>,
    pub nacionalidade: Option<String>,
    pub residencia: Option<Address>,
}

/// A quota (share) and its holder.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Quota {
    /// "QUOTA : 99,00 Euros".
    pub amount: Money,
    pub titular: Person,
}

/// A designated social organ (GERÊNCIA, CONSELHO DE ADMINISTRAÇÃO, …) and its members.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Organ {
    /// "GERÊNCIA".
    pub name: String,
    pub members: Vec<OrganMember>,
}

/// One member of a social organ, as printed under it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OrganMember {
    /// Nome/Firma.
    pub name: String,
    pub nif: Option<String>,
    /// "Gerente", "Presidente", …
    pub cargo: Option<String>,
    pub nacionalidade: Option<String>,
    pub residencia: Option<Address>,
}

/// The parsed apresentação header: `AP. N/YYYYMMDD HH:MM:SS UTC - ACT, ACT`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Apresentacao {
    /// "1".
    pub number: Option<String>,
    /// ISO `YYYY-MM-DD` (best-effort).
    pub date: Option<String>,
    /// "00:55:25 UTC" kept as printed text.
    pub time: Option<String>,
    /// Comma-split, trimmed act-kind labels.
    pub act_kinds: Vec<String>,
}

/// A `Conservatória … / O(A) Oficial de Registos, <name>` pair found inside an entry body.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RegistryOfficialSignature {
    pub conservatoria: Option<String>,
    pub oficial: Option<String>,
}

/// Structured layer on top of a [`RegistryEvent`]. `payload` is `None` when the body did not match
/// a v1-structured kind — the raw `RegistryEvent.text` still carries everything (never lossy).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InscriptionDetail {
    pub apresentacao: Option<Apresentacao>,
    pub payload: Option<InscriptionPayload>,
    /// Trailing conservatória/oficial signature line(s) found in this entry's body (0..n).
    pub signatures: Vec<RegistryOfficialSignature>,
}

/// The per-act structured payload. Internally-tagged so the wire is flat/UI-friendly
/// (`{ "type": "Constitution", … }`). Transmissão/cessão de quotas and dissolução/encerramento are
/// recognized via [`Apresentacao::act_kinds`] and kept as raw text in v1 — no payload here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "type")]
pub enum InscriptionPayload {
    Constitution(ConstitutionPayload),
    Designation(DesignationPayload),
    Cessation(CessationPayload),
    ContractAmendment(AmendmentPayload),
}

/// A `CONSTITUIÇÃO DE SOCIEDADE` (the richest act; absorbs any co-listed designação organs).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ConstitutionPayload {
    pub firma: Option<String>,
    pub nipc: Option<String>,
    pub natureza_juridica: Option<String>,
    pub sede: Option<Address>,
    /// Multi-line free text, joined.
    pub objecto: Option<String>,
    pub capital: Option<Money>,
    /// The prose "A entregar nos cofres…" CAPITAL line.
    pub capital_realization_note: Option<String>,
    /// "31 Dezembro" (kept as text).
    pub fiscal_year_end: Option<String>,
    pub socios: Vec<Quota>,
    pub forma_de_obrigar: Option<String>,
    pub orgaos: Vec<Organ>,
    /// ISO best-effort (tolerates the PT long-date quirk).
    pub deliberation_date: Option<String>,
}

/// A standalone `DESIGNAÇÃO DE MEMBRO(S) DE ORGÃO(S) SOCIAL(AIS)`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DesignationPayload {
    pub orgaos: Vec<Organ>,
    pub deliberation_date: Option<String>,
}

/// A `CESSAÇÃO DE FUNÇÕES` / renúncia / exoneração.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CessationPayload {
    /// Who ceased (name + cargo when printed).
    pub members: Vec<OrganMember>,
    /// "renúncia".
    pub cause: Option<String>,
    /// ISO best-effort.
    pub date: Option<String>,
}

/// An `ALTERAÇÕES AO CONTRATO DE SOCIEDADE` (sede/objecto/capital/firma).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AmendmentPayload {
    pub new_firma: Option<String>,
    pub new_sede: Option<Address>,
    pub new_objecto: Option<String>,
    pub new_capital: Option<Money>,
    pub deliberation_date: Option<String>,
}

/// A publication annotation (`An. N - YYYYMMDD - Publicado em <url>.`), kept ordered.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RegistryAnnotation {
    /// "1".
    pub number: Option<String>,
    /// ISO from the `YYYYMMDD` in `An. N - YYYYMMDD - …`.
    pub date: Option<String>,
    /// "http://publicacoes.mj.pt".
    pub publication_url: Option<String>,
    /// Raw.
    pub text: String,
}
