//! Legal entities and their identifiers.
//!
//! Grounding: spec 03 (Entity Type Profiles). Each [`EntityFamily`] is a distinct unit of
//! legal behavior — a condominium is not "corporate-company lite" (spec 03 intro) — and
//! carries its own selectable legal [`EntityKind`]s (ENT-01).

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::error::NipcError;

/// Opaque identifier for an [`Entity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntityId(pub Uuid);

impl EntityId {
    /// Mint a fresh random identifier.
    pub fn new() -> Self {
        EntityId(Uuid::new_v4())
    }
}

impl Default for EntityId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A Portuguese NIPC (número de identificação de pessoa coletiva), the collective-person
/// counterpart of the NIF.
///
/// # Invariant (changed — read carefully)
///
/// A `Nipc` no longer guarantees the nine-digit / control-digit format. It carries an
/// explicit `validated` flag:
///
/// - [`Nipc::parse`] enforces the format (nine digits) and the mod-11 control digit and
///   produces a value with `is_validated() == true`. This is the strict path and its
///   behavior is unchanged.
/// - [`Nipc::unvalidated`] stores a **raw** identifier that may not be nine digits (foreign
///   entities, special registrations, legacy data) with `is_validated() == false`. It runs
///   **no** format or control-digit check.
///
/// Callers that need the digit-format guarantee MUST check [`Nipc::is_validated`]; do not
/// assume [`Nipc::as_str`] is nine digits.
///
/// The control digit is the anti-typo check the registry itself relies on; on the validated
/// path we deliberately do **not** constrain the leading digit, since the valid prefix set
/// is broad and evolves, and over-constraining would reject legitimate entities. The
/// validated value is stored normalized (whitespace stripped); the unvalidated value is
/// stored trimmed but otherwise verbatim.
///
/// # Serde representation (back-compat ruling)
///
/// The wire/stored form is **asymmetric** so existing data keeps round-tripping byte for
/// byte:
///
/// - A **validated** NIPC serializes as a bare JSON string (`"503004642"`) — identical to
///   the pre-flag representation, so every stored payload, contract fixture, and wire
///   response is unchanged.
/// - An **unvalidated** NIPC serializes as an object `{"value": "...", "validated": false}`
///   so the flag survives a round trip.
///
/// Deserialization accepts **either** form: a bare string yields `validated == true` (with
/// no re-validation — this matches the previous derive, which wrapped the string without
/// checking), and the object form carries the flag as written (a missing `validated` key
/// defaults to `false`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nipc {
    value: String,
    validated: bool,
}

impl Nipc {
    /// Parse and validate a NIPC. Whitespace is stripped before validation. The result has
    /// `is_validated() == true`.
    ///
    /// The control digit is computed as `d9 = 11 - (Σ dᵢ·(9-i) for i in 0..8) mod 11`,
    /// where a remainder of 0 or 1 yields a control digit of 0.
    pub fn parse(raw: &str) -> Result<Self, NipcError> {
        let normalized: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
        if normalized.len() != 9 || !normalized.bytes().all(|b| b.is_ascii_digit()) {
            return Err(NipcError::Format(raw.to_string()));
        }
        let digits: Vec<u32> = normalized
            .chars()
            .map(|c| c.to_digit(10).unwrap())
            .collect();
        let checksum: u32 = (0..8).map(|i| digits[i] * (9 - i as u32)).sum();
        let remainder = checksum % 11;
        let control = if remainder < 2 { 0 } else { 11 - remainder };
        if control != digits[8] {
            return Err(NipcError::CheckDigit(raw.to_string()));
        }
        Ok(Nipc {
            value: normalized,
            validated: true,
        })
    }

    /// Store a raw identifier **without** NIPC validation, flagged `is_validated() == false`.
    ///
    /// This is the explicit override for entities that lack a control-digit-valid NIPC —
    /// foreign entities, special registrations, legacy data. The raw string is trimmed of
    /// surrounding whitespace but otherwise kept verbatim (it may not be nine digits). It is
    /// always unvalidated, even if `raw` happens to be a well-formed NIPC: the point of this
    /// constructor is to record that validation was deliberately skipped.
    pub fn unvalidated(raw: &str) -> Self {
        Nipc {
            value: raw.trim().to_string(),
            validated: false,
        }
    }

    /// The stored identifier string. Guaranteed nine digits only when
    /// [`is_validated`](Self::is_validated) is `true`.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Whether this NIPC passed [`Nipc::parse`] (format + control digit). `false` for values
    /// built via [`Nipc::unvalidated`] or deserialized from the object form with the flag off.
    pub fn is_validated(&self) -> bool {
        self.validated
    }
}

impl std::fmt::Display for Nipc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The raw identifier is public registry data (not a secret like an access code), so
        // it is shown verbatim in both the validated and unvalidated cases.
        f.write_str(&self.value)
    }
}

impl Serialize for Nipc {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.validated {
            // Back-compat: a validated NIPC is a bare string, byte-identical to the old
            // derive, so existing fixtures/contracts/stored payloads are unchanged.
            serializer.serialize_str(&self.value)
        } else {
            use serde::ser::SerializeStruct;
            let mut st = serializer.serialize_struct("Nipc", 2)?;
            st.serialize_field("value", &self.value)?;
            st.serialize_field("validated", &self.validated)?;
            st.end()
        }
    }
}

impl<'de> Deserialize<'de> for Nipc {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Untagged: a bare string is the legacy/validated form; the object form carries the
        // explicit flag (defaulting to unvalidated when the key is absent).
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Bare(String),
            Tagged {
                value: String,
                #[serde(default)]
                validated: bool,
            },
        }
        Ok(match Repr::deserialize(deserializer)? {
            Repr::Bare(value) => Nipc {
                value,
                validated: true,
            },
            Repr::Tagged { value, validated } => Nipc { value, validated },
        })
    }
}

/// The five entity families the platform models (spec 03; ENT-01).
///
/// Each family binds a distinct compliance rule pack, template family, signature policy,
/// and archive model (ENT-02).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityFamily {
    /// Sociedades comerciais — CSC (ENT-C).
    CommercialCompany,
    /// Condomínios — DL 268/94 rev. 2022 (ENT-D).
    Condominium,
    /// Associações — Código Civil (ENT-A).
    Association,
    /// Fundações — Lei-Quadro das Fundações, Lei 24/2012 (ENT-F).
    Foundation,
    /// Cooperativas — Código Cooperativo (ENT-K).
    Cooperative,
}

/// A concrete selectable legal type within a family.
///
/// The commercial-company variants are the six CSC art. 1.º types required by ENT-C1; the
/// remaining families each expose a single canonical type for the scaffold (their
/// statute-configured subtypes, ENT-A1/ENT-K2, layer on top later via the statute layer,
/// ENT-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityKind {
    // Commercial companies — CSC art. 1.º / ENT-C1.
    /// Sociedade em nome coletivo.
    SociedadeEmNomeColetivo,
    /// Sociedade por quotas.
    SociedadePorQuotas,
    /// Sociedade unipessoal por quotas (art. 270.º-A ff.).
    SociedadeUnipessoalPorQuotas,
    /// Sociedade anónima (arts. 376.º–388.º).
    SociedadeAnonima,
    /// Sociedade em comandita simples.
    SociedadeEmComanditaSimples,
    /// Sociedade em comandita por ações.
    SociedadeEmComanditaPorAcoes,
    // Other families.
    /// Condomínio (propriedade horizontal) — ENT-D.
    Condominio,
    /// Associação — ENT-A1.
    Associacao,
    /// Fundação — ENT-F1.
    Fundacao,
    /// Cooperativa — ENT-K1 (a distinct type, not a company subtype).
    Cooperativa,
}

impl EntityKind {
    /// The family this legal type belongs to.
    pub fn family(self) -> EntityFamily {
        use EntityKind::*;
        match self {
            SociedadeEmNomeColetivo
            | SociedadePorQuotas
            | SociedadeUnipessoalPorQuotas
            | SociedadeAnonima
            | SociedadeEmComanditaSimples
            | SociedadeEmComanditaPorAcoes => EntityFamily::CommercialCompany,
            Condominio => EntityFamily::Condominium,
            Associacao => EntityFamily::Association,
            Fundacao => EntityFamily::Foundation,
            Cooperativa => EntityFamily::Cooperative,
        }
    }
}

/// A statutory quorum requirement (ENT-03): the minimum number of members that must be
/// present (in person + represented) for a deliberation to be valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quorum {
    /// Minimum count of present + represented members.
    pub min_present: u32,
}

/// A statutory majority requirement (ENT-03), as a fraction `numerator / denominator` of the
/// votes cast (e.g. 2/3, 3/4). Applied to structured [`crate::act::VoteResult::Recorded`]
/// tallies; a unanimous vote satisfies any majority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Majority {
    /// Numerator of the required fraction.
    pub numerator: u32,
    /// Denominator of the required fraction.
    pub denominator: u32,
}

/// Per-entity **statute overlay** (ENT-03): overrides drawn from the entity's own statutes
/// that layer on top of the family baseline. Every field is optional — an entity with no
/// recorded statute knobs behaves exactly as the family default.
///
/// Scope is deliberately honest about what can be *checked* against today's data (R5):
/// `quorum` and `majority` drive real advisory checks over the structured act model, while
/// `convocation_notice_days` is stored and surfaced only (no convocatória dispatch date is
/// modeled yet).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StatuteOverrides {
    /// Statutory quorum, if the statutes set one.
    #[serde(default)]
    pub quorum: Option<Quorum>,
    /// Statutory majority for (non-unanimous) resolutions, if the statutes set one.
    #[serde(default)]
    pub majority: Option<Majority>,
    /// Statutory convocation notice period in days (stored/surfaced only; not yet enforced).
    #[serde(default)]
    pub convocation_notice_days: Option<u16>,
}

/// A legal person that owns books and produces acts (DAT-01).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entity {
    /// Stable identifier.
    pub id: EntityId,
    /// Legal name / firma.
    pub name: String,
    /// NIPC — validated ([`Nipc::parse`]) or an explicit override ([`Nipc::unvalidated`]);
    /// check [`Nipc::is_validated`] before assuming the nine-digit format.
    pub nipc: Nipc,
    /// Registered seat (sede).
    pub seat: String,
    /// Entity family (spec 03).
    pub family: EntityFamily,
    /// Concrete legal type; must belong to `family`.
    pub kind: EntityKind,
    /// Fiscal year end as `MM-DD`, when known. Optional for backward compatibility with stored
    /// entities created before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fiscal_year_end: Option<String>,
    /// Per-entity statute overlay (ENT-03). Additive; `None` on the family default. Old-shape
    /// entity JSON (no `statute` key) deserializes with this as `None`.
    #[serde(default)]
    pub statute: Option<StatuteOverrides>,
}

impl Entity {
    /// Construct an entity, deriving `family` from `kind`.
    ///
    /// Because the family is derived rather than passed in, a condominium can never be
    /// filed under a commercial-company family and similar category errors are impossible
    /// by construction; [`Entity::is_consistent`] re-checks the invariant for values that
    /// arrive by deserialization.
    pub fn new(
        name: impl Into<String>,
        nipc: Nipc,
        seat: impl Into<String>,
        kind: EntityKind,
    ) -> Self {
        Entity {
            id: EntityId::new(),
            name: name.into(),
            nipc,
            seat: seat.into(),
            family: kind.family(),
            kind,
            fiscal_year_end: None,
            statute: None,
        }
    }

    /// True when `kind` is consistent with `family` (always true for entities built via
    /// [`Entity::new`], but worth checking for deserialized values).
    pub fn is_consistent(&self) -> bool {
        self.kind.family() == self.family
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_nipc() {
        // Control digit for base 50300464: Σ = 108, 108 % 11 = 9, control = 11 - 9 = 2.
        let nipc = Nipc::parse("503004642").expect("valid NIPC");
        assert_eq!(nipc.as_str(), "503004642");
    }

    #[test]
    fn accepts_nipc_with_zero_control_digit() {
        // Base 50000000: Σ = 45, 45 % 11 = 1 (< 2) ⇒ control digit 0.
        assert!(Nipc::parse("500000000").is_ok());
    }

    #[test]
    fn strips_whitespace_before_validation() {
        assert!(Nipc::parse("503 004 642").is_ok());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(matches!(Nipc::parse("12345"), Err(NipcError::Format(_))));
        assert!(matches!(
            Nipc::parse("5030046420"),
            Err(NipcError::Format(_))
        ));
    }

    #[test]
    fn rejects_non_digits() {
        assert!(matches!(
            Nipc::parse("50300464X"),
            Err(NipcError::Format(_))
        ));
    }

    #[test]
    fn rejects_bad_control_digit() {
        // Valid base but last digit tampered from 2 to 0.
        assert!(matches!(
            Nipc::parse("503004640"),
            Err(NipcError::CheckDigit(_))
        ));
    }

    #[test]
    fn kind_maps_to_family_and_entity_is_consistent() {
        assert_eq!(
            EntityKind::SociedadeAnonima.family(),
            EntityFamily::CommercialCompany
        );
        assert_eq!(EntityKind::Condominio.family(), EntityFamily::Condominium);
        assert_eq!(EntityKind::Cooperativa.family(), EntityFamily::Cooperative);

        let entity = Entity::new(
            "Encosto Estratégico, S.A.",
            Nipc::parse("503004642").unwrap(),
            "Lisboa",
            EntityKind::SociedadeAnonima,
        );
        assert_eq!(entity.family, EntityFamily::CommercialCompany);
        assert!(entity.is_consistent());
    }

    #[test]
    fn parse_marks_the_nipc_validated() {
        assert!(Nipc::parse("503004642").unwrap().is_validated());
    }

    #[test]
    fn unvalidated_stores_raw_and_is_not_validated() {
        // A foreign identifier that is not nine digits: accepted, flagged unvalidated.
        let nipc = Nipc::unvalidated("FR-9920-XT");
        assert!(!nipc.is_validated());
        assert_eq!(nipc.as_str(), "FR-9920-XT");
    }

    #[test]
    fn unvalidated_trims_but_does_not_reject_a_would_be_valid_nipc() {
        // Even a well-formed NIPC is unvalidated when built via the override: the point is
        // to record that the control-digit check was deliberately skipped.
        let nipc = Nipc::unvalidated("  503004642  ");
        assert!(!nipc.is_validated());
        assert_eq!(nipc.as_str(), "503004642");
    }

    #[test]
    fn validated_nipc_serializes_as_a_bare_string() {
        // Back-compat: existing fixtures/contracts store `nipc` as a bare string.
        let nipc = Nipc::parse("503004642").unwrap();
        assert_eq!(
            serde_json::to_string(&nipc).unwrap(),
            r#""503004642""#,
            "a validated NIPC must stay a bare JSON string"
        );
    }

    #[test]
    fn bare_string_deserializes_as_validated() {
        // Every pre-existing stored/wire NIPC is a bare string and must keep deserializing,
        // yielding a validated value (matching the previous derive behavior).
        let nipc: Nipc = serde_json::from_str(r#""503004642""#).unwrap();
        assert!(nipc.is_validated());
        assert_eq!(nipc.as_str(), "503004642");
    }

    #[test]
    fn unvalidated_nipc_round_trips_the_flag() {
        let nipc = Nipc::unvalidated("X-123");
        let json = serde_json::to_string(&nipc).unwrap();
        assert_eq!(json, r#"{"value":"X-123","validated":false}"#);
        let back: Nipc = serde_json::from_str(&json).unwrap();
        assert_eq!(back, nipc);
        assert!(!back.is_validated());
        assert_eq!(back.as_str(), "X-123");
    }

    #[test]
    fn object_form_without_flag_defaults_to_unvalidated() {
        let nipc: Nipc = serde_json::from_str(r#"{"value":"X-123"}"#).unwrap();
        assert!(!nipc.is_validated());
        assert_eq!(nipc.as_str(), "X-123");
    }

    #[test]
    fn entity_with_unvalidated_nipc_is_still_consistent() {
        // NIPC validity is orthogonal to kind/family consistency; an override must not make
        // the entity "inconsistent" (that check is about kind vs family only).
        let entity = Entity::new(
            "Foreign Holdings Ltd.",
            Nipc::unvalidated("GB-00000000"),
            "London",
            EntityKind::SociedadeAnonima,
        );
        assert!(entity.is_consistent());
        assert!(!entity.nipc.is_validated());
    }

    #[test]
    fn entity_round_trips_an_unvalidated_nipc() {
        let entity = Entity::new(
            "Foreign Holdings Ltd.",
            Nipc::unvalidated("GB-00000000"),
            "London",
            EntityKind::SociedadeAnonima,
        );
        let json = serde_json::to_string(&entity).unwrap();
        let back: Entity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, entity);
        assert!(!back.nipc.is_validated());
    }

    #[test]
    fn deserialized_entity_with_mismatched_family_is_inconsistent() {
        // `Entity::new` derives `family` from `kind`, so a mismatch can only arrive by
        // deserialization. `is_consistent` exists to catch exactly that value (see its doc).
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000000",
            "name": "Condomínio do Edifício Sol",
            "nipc": "503004642",
            "seat": "Porto",
            "family": "CommercialCompany",
            "kind": "Condominio"
        }"#;
        let entity: Entity = serde_json::from_str(json).expect("deserializes");
        // The declared family (CommercialCompany) disagrees with the kind's family (Condominium).
        assert!(!entity.is_consistent());
    }

    #[test]
    fn old_entity_json_without_fiscal_year_end_stays_backward_compatible() {
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000000",
            "name": "Encosto Estrategico, S.A.",
            "nipc": "503004642",
            "seat": "Lisboa",
            "family": "CommercialCompany",
            "kind": "SociedadeAnonima"
        }"#;
        let entity: Entity = serde_json::from_str(json).expect("old entity JSON deserializes");
        assert_eq!(entity.fiscal_year_end, None);

        let serialized = serde_json::to_string(&entity).expect("serializes");
        assert!(
            !serialized.contains("fiscal_year_end"),
            "absent fiscal year end should not be serialized: {serialized}"
        );
    }
}
