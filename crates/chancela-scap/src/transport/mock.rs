//! The deterministic, fixture-backed mock transport — the default and the only transport tests
//! exercise.
//!
//! **The mock is structurally incapable of yielding a verified status.** Its
//! [`verify_attribute`](ScapTransport::verify_attribute) always returns
//! [`VerificationDecision::Declared`]; it never returns `Granted`, because it cannot construct the
//! [`AuthoritativeGrant`](super::AuthoritativeGrant) witness that variant requires (the witness's
//! constructor is private to the sibling [`super::http`] module). See the [`super`] module docs.
//!
//! All fixture data is **fictional** (persons, organisations, licence numbers).

use std::collections::BTreeMap;

use time::macros::datetime;

use super::{ScapTransport, VerificationDecision};
use crate::error::ScapError;
use crate::model::{AttributeProvider, CitizenRef, ProfessionalAttribute, SubAttribute};

/// Civil identifier of the fictional signing citizen used throughout the default fixtures.
pub const FIXTURE_CITIZEN_ID: &str = "199000001";
/// Name of the fictional signing citizen used throughout the default fixtures.
pub const FIXTURE_CITIZEN_NAME: &str = "Amélia Marques";

/// A deterministic, offline SCAP transport backed by in-memory fixtures.
pub struct MockScapTransport {
    providers: Vec<AttributeProvider>,
    attributes_by_citizen: BTreeMap<String, Vec<ProfessionalAttribute>>,
}

impl MockScapTransport {
    /// Build a mock from explicit fixtures.
    pub fn new(
        providers: Vec<AttributeProvider>,
        attributes_by_citizen: BTreeMap<String, Vec<ProfessionalAttribute>>,
    ) -> Self {
        MockScapTransport {
            providers,
            attributes_by_citizen,
        }
    }

    /// The default fixture set: two fictional professional-order attribute providers and one
    /// fictional signing citizen ([`FIXTURE_CITIZEN_ID`]) holding one attribute from each.
    pub fn with_default_fixtures() -> Self {
        let advogados = AttributeProvider {
            id: "OA".to_owned(),
            name: "Ordem Fictícia dos Advogados".to_owned(),
            attribute_names: vec!["Advogado".to_owned()],
        };
        let engenheiros = AttributeProvider {
            id: "OE".to_owned(),
            name: "Ordem Fictícia dos Engenheiros".to_owned(),
            attribute_names: vec!["Engenheiro".to_owned()],
        };

        let advogado_attr = ProfessionalAttribute {
            provider_id: advogados.id.clone(),
            provider_name: advogados.name.clone(),
            name: "Advogado".to_owned(),
            valid_from: Some(datetime!(2024-01-01 00:00:00 UTC)),
            valid_until: Some(datetime!(2027-12-31 23:59:59 UTC)),
            sub_attributes: vec![
                SubAttribute {
                    name: "cedula".to_owned(),
                    value: "OA-99001".to_owned(),
                },
                SubAttribute {
                    name: "organizacao".to_owned(),
                    value: "Encosto Estratégico Lda".to_owned(),
                },
            ],
        };
        let engenheiro_attr = ProfessionalAttribute {
            provider_id: engenheiros.id.clone(),
            provider_name: engenheiros.name.clone(),
            name: "Engenheiro".to_owned(),
            valid_from: Some(datetime!(2023-06-01 00:00:00 UTC)),
            valid_until: None,
            sub_attributes: vec![SubAttribute {
                name: "cedula".to_owned(),
                value: "OE-45012".to_owned(),
            }],
        };

        let mut attributes_by_citizen = BTreeMap::new();
        attributes_by_citizen.insert(
            FIXTURE_CITIZEN_ID.to_owned(),
            vec![advogado_attr, engenheiro_attr],
        );

        MockScapTransport {
            providers: vec![advogados, engenheiros],
            attributes_by_citizen,
        }
    }
}

impl Default for MockScapTransport {
    fn default() -> Self {
        Self::with_default_fixtures()
    }
}

impl ScapTransport for MockScapTransport {
    fn list_providers(&self) -> Result<Vec<AttributeProvider>, ScapError> {
        Ok(self.providers.clone())
    }

    fn fetch_attributes(
        &self,
        citizen: &CitizenRef,
    ) -> Result<Vec<ProfessionalAttribute>, ScapError> {
        Ok(self
            .attributes_by_citizen
            .get(&citizen.identifier)
            .cloned()
            .unwrap_or_default())
    }

    fn verify_attribute(
        &self,
        _attribute: &ProfessionalAttribute,
        _citizen: &CitizenRef,
    ) -> Result<VerificationDecision, ScapError> {
        // The mock is non-authoritative: it cannot construct `AuthoritativeGrant`, so it can never
        // return `Granted`. Every mock verification is declared-only, by construction.
        Ok(VerificationDecision::Declared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_fixtures_list_two_providers() {
        let mock = MockScapTransport::default();
        let providers = mock.list_providers().unwrap();
        assert_eq!(providers.len(), 2);
        assert!(providers.iter().any(|p| p.id == "OA"));
        assert!(providers.iter().any(|p| p.id == "OE"));
    }

    #[test]
    fn fixture_citizen_holds_two_attributes() {
        let mock = MockScapTransport::default();
        let attrs = mock
            .fetch_attributes(&CitizenRef::new(FIXTURE_CITIZEN_ID))
            .unwrap();
        assert_eq!(attrs.len(), 2);
    }

    #[test]
    fn unknown_citizen_has_no_attributes() {
        let mock = MockScapTransport::default();
        let attrs = mock
            .fetch_attributes(&CitizenRef::new("000000000"))
            .unwrap();
        assert!(attrs.is_empty());
    }

    #[test]
    fn mock_verification_is_always_declared() {
        let mock = MockScapTransport::default();
        let attrs = mock
            .fetch_attributes(&CitizenRef::new(FIXTURE_CITIZEN_ID))
            .unwrap();
        for attr in &attrs {
            let decision = mock
                .verify_attribute(attr, &CitizenRef::new(FIXTURE_CITIZEN_ID))
                .unwrap();
            assert!(matches!(decision, VerificationDecision::Declared));
        }
    }
}
