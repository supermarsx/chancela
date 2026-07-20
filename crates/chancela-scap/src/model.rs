//! SCAP domain model: [`AttributeProvider`], [`ProfessionalAttribute`], the signing-citizen
//! reference [`CitizenRef`], and [`ScapSignatureEvidence`] — which distinguishes a
//! **verified-by-SCAP** capacity from a **declared-only** one via [`ScapVerificationStatus`].
//!
//! ## Honesty vocabulary (t67 §1.2 — binding)
//!
//! [`ScapVerificationStatus::VerifiedByScap`] is reachable **only** from a real `Granted`
//! verification over the authoritative HTTP transport. The mock transport can never produce it —
//! that is enforced at compile time in [`crate::transport`] (the `Granted` verification decision
//! carries a witness the mock cannot construct), not merely by convention here.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// A SCAP attribute provider — an *entidade certificadora de atributos* (e.g. a professional
/// order) that is authoritative for one or more professional attributes of its members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributeProvider {
    /// AMA-assigned provider id (opaque code / NIPC-like identifier).
    pub id: String,
    /// Human-readable provider name.
    pub name: String,
    /// The professional attribute names this provider certifies (e.g. `"Advogado"`).
    pub attribute_names: Vec<String>,
}

/// A qualifying sub-attribute of a professional attribute (e.g. a professional-licence number or
/// an internal role).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubAttribute {
    /// Sub-attribute name.
    pub name: String,
    /// Sub-attribute value.
    pub value: String,
}

/// A professional attribute held by a citizen, as reported by an [`AttributeProvider`].
///
/// This is the *claim*: on its own it is declared, not verified. Verification status lives in
/// [`ScapSignatureEvidence`], produced by the client after consulting the transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfessionalAttribute {
    /// The id of the provider that reported this attribute.
    pub provider_id: String,
    /// The name of the provider that reported this attribute.
    pub provider_name: String,
    /// The professional capacity (e.g. `"Advogado"`, `"Engenheiro"`).
    pub name: String,
    /// Start of validity, if the provider reported one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<OffsetDateTime>,
    /// End of validity, if the provider reported one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<OffsetDateTime>,
    /// Qualifying sub-attributes (may be empty).
    #[serde(default)]
    pub sub_attributes: Vec<SubAttribute>,
}

impl ProfessionalAttribute {
    /// A deterministic canonical byte serialization of the attribute, used to *bind* it into a
    /// signature (a stable digest input). Field order and separators are fixed; sub-attributes are
    /// sorted so the encoding does not depend on reporting order.
    ///
    /// This is a binding encoding, **not** a wire/interchange format — do not parse it back.
    pub fn canonical_binding_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("provider_id=");
        out.push_str(&self.provider_id);
        out.push_str("\nprovider_name=");
        out.push_str(&self.provider_name);
        out.push_str("\nname=");
        out.push_str(&self.name);
        out.push_str("\nvalid_from=");
        if let Some(t) = self.valid_from {
            out.push_str(&t.unix_timestamp().to_string());
        }
        out.push_str("\nvalid_until=");
        if let Some(t) = self.valid_until {
            out.push_str(&t.unix_timestamp().to_string());
        }
        let mut subs: Vec<&SubAttribute> = self.sub_attributes.iter().collect();
        subs.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.value.cmp(&b.value)));
        for sub in subs {
            out.push_str("\nsub=");
            out.push_str(&sub.name);
            out.push('=');
            out.push_str(&sub.value);
        }
        out.into_bytes()
    }
}

/// A reference to the signing citizen whose attributes are being fetched/verified.
///
/// This identifies the *signer*, not a credential; it is not secret material, but callers should
/// still treat the civil identifier as personal data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CitizenRef {
    /// Civil identifier of the signing citizen (e.g. NIF/NIC or an opaque subject id).
    pub identifier: String,
    /// Full name, when known.
    pub full_name: Option<String>,
}

impl CitizenRef {
    /// Build a citizen reference from a civil identifier.
    pub fn new(identifier: impl Into<String>) -> Self {
        CitizenRef {
            identifier: identifier.into(),
            full_name: None,
        }
    }

    /// Set the full name.
    pub fn with_full_name(mut self, full_name: impl Into<String>) -> Self {
        self.full_name = Some(full_name.into());
        self
    }
}

/// How a professional-attribute claim was corroborated.
///
/// The vocabulary evolves *honestly* (t67 §1.2): [`Self::VerifiedByScap`] is emitted **only** on a
/// real `Granted` verification over the authoritative HTTP transport, never from the mock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScapVerificationStatus {
    /// SCAP returned a `Granted` decision over the authoritative transport. The strongest status.
    VerifiedByScap,
    /// The attribute is declared (present in the citizen's fetched attributes) but was not
    /// SCAP-verified — the transport is non-authoritative (mock), off, or unavailable.
    DeclaredOnly,
    /// SCAP was not consulted for this attribute at all.
    NotChecked,
}

impl ScapVerificationStatus {
    /// The `verification_status` marker string, aligned with the API's existing capacity-evidence
    /// vocabulary (`chancela-api` `signature.rs`).
    pub fn verification_status_marker(&self) -> &'static str {
        match self {
            ScapVerificationStatus::VerifiedByScap => "verified_by_scap",
            ScapVerificationStatus::DeclaredOnly => "declared_capacity_by_provider",
            ScapVerificationStatus::NotChecked => "not_checked_by_scap",
        }
    }

    /// The `status_scope` marker string. Only a verified status widens the scope beyond
    /// declared-capacity-evidence-only.
    pub fn status_scope_marker(&self) -> &'static str {
        match self {
            ScapVerificationStatus::VerifiedByScap => "scap_verified_capacity",
            ScapVerificationStatus::DeclaredOnly | ScapVerificationStatus::NotChecked => {
                "declared_capacity_evidence_only"
            }
        }
    }

    /// Whether this status represents a real SCAP verification.
    pub fn is_verified(&self) -> bool {
        matches!(self, ScapVerificationStatus::VerifiedByScap)
    }
}

/// Evidence attached to a signature recording the signer's professional attribute and how it was
/// corroborated. Produced by [`crate::ScapClient::build_signature_evidence`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScapSignatureEvidence {
    /// The professional attribute the signer is signing under.
    pub attribute: ProfessionalAttribute,
    /// How the attribute was corroborated.
    pub status: ScapVerificationStatus,
    /// The environment/source that produced a verification (e.g. `"scap-prod"`); `None` when
    /// declared-only or not checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_source: Option<String>,
    /// When the verification occurred; `None` unless verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<OffsetDateTime>,
    /// The granting authority reference returned by SCAP; `None` unless verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_reference: Option<String>,
}

impl ScapSignatureEvidence {
    /// A declared-only evidence record (no SCAP verification performed).
    pub fn declared(attribute: ProfessionalAttribute) -> Self {
        ScapSignatureEvidence {
            attribute,
            status: ScapVerificationStatus::DeclaredOnly,
            verification_source: None,
            verified_at: None,
            authority_reference: None,
        }
    }

    /// Whether this evidence records a real SCAP verification.
    pub fn is_verified(&self) -> bool {
        self.status.is_verified()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr() -> ProfessionalAttribute {
        ProfessionalAttribute {
            provider_id: "p".to_owned(),
            provider_name: "P".to_owned(),
            name: "Advogado".to_owned(),
            valid_from: None,
            valid_until: None,
            sub_attributes: vec![
                SubAttribute {
                    name: "cedula".to_owned(),
                    value: "12345".to_owned(),
                },
                SubAttribute {
                    name: "role".to_owned(),
                    value: "member".to_owned(),
                },
            ],
        }
    }

    #[test]
    fn canonical_binding_is_order_independent_for_sub_attributes() {
        let mut a = attr();
        let mut b = attr();
        b.sub_attributes.reverse();
        assert_eq!(a.canonical_binding_bytes(), b.canonical_binding_bytes());

        // A different attribute value changes the binding.
        a.name = "Engenheiro".to_owned();
        assert_ne!(a.canonical_binding_bytes(), b.canonical_binding_bytes());
    }

    #[test]
    fn status_markers_only_widen_scope_when_verified() {
        assert_eq!(
            ScapVerificationStatus::VerifiedByScap.status_scope_marker(),
            "scap_verified_capacity"
        );
        assert_eq!(
            ScapVerificationStatus::DeclaredOnly.status_scope_marker(),
            "declared_capacity_evidence_only"
        );
        assert_eq!(
            ScapVerificationStatus::NotChecked.status_scope_marker(),
            "declared_capacity_evidence_only"
        );
        assert!(ScapVerificationStatus::VerifiedByScap.is_verified());
        assert!(!ScapVerificationStatus::DeclaredOnly.is_verified());
    }

    #[test]
    fn declared_evidence_is_not_verified() {
        let e = ScapSignatureEvidence::declared(attr());
        assert!(!e.is_verified());
        assert_eq!(e.status, ScapVerificationStatus::DeclaredOnly);
        assert!(e.authority_reference.is_none());
    }
}
