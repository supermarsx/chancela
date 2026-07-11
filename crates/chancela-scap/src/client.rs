//! [`ScapClient`]: attribute-provider listing, attribute fetch for the signing citizen,
//! professional-attribute signature-evidence production, and evidence verification.
//!
//! The client is generic over a [`ScapTransport`]. With [`crate::MockScapTransport`] every
//! verification is declared-only; a real [`crate::HttpScapTransport`] is the only way to obtain a
//! [`ScapVerificationStatus::VerifiedByScap`] evidence — enforced by the transport types, not here.

use time::OffsetDateTime;

use chancela_cades::RawSignature;

use crate::binder::AttributeSignatureBinder;
use crate::config::{AmaScapConfig, ScapEnvironment};
use crate::error::ScapError;
use crate::model::{
    AttributeProvider, CitizenRef, ProfessionalAttribute, ScapSignatureEvidence,
    ScapVerificationStatus,
};
use crate::transport::{ScapTransport, VerificationDecision};

/// The SCAP client: a configuration + a transport.
pub struct ScapClient<T: ScapTransport> {
    config: AmaScapConfig,
    transport: T,
}

/// A verification report over a [`ScapSignatureEvidence`] record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceReport {
    /// Whether the evidence records a real SCAP verification.
    pub verified: bool,
    /// The `verification_status` marker (aligned with the API vocabulary).
    pub verification_status_marker: &'static str,
    /// The `status_scope` marker.
    pub status_scope_marker: &'static str,
    /// The professional attribute name.
    pub attribute_name: String,
    /// The reporting/granting provider id.
    pub provider_id: String,
}

impl<T: ScapTransport> ScapClient<T> {
    /// Build a client. Validates the config (PROD without credentials fails closed).
    pub fn new(config: AmaScapConfig, transport: T) -> Result<Self, ScapError> {
        config.validate()?;
        Ok(ScapClient { config, transport })
    }

    /// The configuration.
    pub fn config(&self) -> &AmaScapConfig {
        &self.config
    }

    /// The underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// List attribute providers, applying the config's provider filter when present.
    pub fn list_providers(&self) -> Result<Vec<AttributeProvider>, ScapError> {
        let mut providers = self.transport.list_providers()?;
        if let Some(filter) = &self.config.provider_filter {
            if !filter.is_empty() {
                providers.retain(|p| filter.iter().any(|id| id == &p.id));
            }
        }
        Ok(providers)
    }

    /// Fetch the professional attributes SCAP reports for `citizen`.
    pub fn fetch_attributes(
        &self,
        citizen: &CitizenRef,
    ) -> Result<Vec<ProfessionalAttribute>, ScapError> {
        self.transport.fetch_attributes(citizen)
    }

    /// Produce the signature evidence for `attribute` held by `citizen`, to attach to a signature.
    ///
    /// The honesty status is decided **by the transport**: only a `Granted` decision from an
    /// authoritative transport yields [`ScapVerificationStatus::VerifiedByScap`]; a mock/declared
    /// decision yields [`ScapVerificationStatus::DeclaredOnly`]; a `Denied` decision is an error.
    pub fn build_signature_evidence(
        &self,
        attribute: ProfessionalAttribute,
        citizen: &CitizenRef,
    ) -> Result<ScapSignatureEvidence, ScapError> {
        let decision = self.transport.verify_attribute(&attribute, citizen)?;
        match decision {
            VerificationDecision::Granted(grant) => Ok(ScapSignatureEvidence {
                attribute,
                status: ScapVerificationStatus::VerifiedByScap,
                verification_source: Some(self.verification_source().to_owned()),
                verified_at: Some(OffsetDateTime::now_utc()),
                authority_reference: Some(grant.authority_reference().to_owned()),
            }),
            VerificationDecision::Declared => Ok(ScapSignatureEvidence::declared(attribute)),
            VerificationDecision::Denied => Err(ScapError::Verification(format!(
                "SCAP denied professional attribute '{}' (provider '{}')",
                attribute.name, attribute.provider_id
            ))),
        }
    }

    /// Structurally verify an evidence record's honesty consistency and report its markers.
    ///
    /// Rejects a record that claims verification without the corroborating metadata a real
    /// verification carries (authority reference / timestamp / source), and a declared-only record
    /// that nonetheless carries verification metadata. This catches a forged `verified_by_scap`
    /// status regardless of how the record was constructed.
    pub fn verify_evidence(
        &self,
        evidence: &ScapSignatureEvidence,
    ) -> Result<EvidenceReport, ScapError> {
        if evidence.status.is_verified() {
            if evidence.authority_reference.is_none()
                || evidence.verified_at.is_none()
                || evidence.verification_source.is_none()
            {
                return Err(ScapError::Verification(
                    "verified evidence is missing corroborating metadata \
                     (authority reference / timestamp / source)"
                        .to_owned(),
                ));
            }
        } else if evidence.authority_reference.is_some() || evidence.verified_at.is_some() {
            return Err(ScapError::Verification(
                "declared-only evidence must not carry verification metadata".to_owned(),
            ));
        }
        Ok(EvidenceReport {
            verified: evidence.status.is_verified(),
            verification_status_marker: evidence.status.verification_status_marker(),
            status_scope_marker: evidence.status.status_scope_marker(),
            attribute_name: evidence.attribute.name.clone(),
            provider_id: evidence.attribute.provider_id.clone(),
        })
    }

    /// The digest a signing device must sign to bind `evidence` over `content_digest`, delegating
    /// to a [`AttributeSignatureBinder`] (the CAdES binder by default; a XAdES binder later).
    pub fn qualified_signing_digest<B: AttributeSignatureBinder>(
        &self,
        binder: &B,
        content_digest: &[u8; 32],
        evidence: &ScapSignatureEvidence,
        signing_cert_der: &[u8],
        signing_time: OffsetDateTime,
    ) -> Result<[u8; 32], ScapError> {
        binder.binding_digest(content_digest, evidence, signing_cert_der, signing_time)
    }

    /// Assemble the finished attribute-qualified signature from the device's `raw` signature.
    pub fn assemble_qualified_signature<B: AttributeSignatureBinder>(
        &self,
        binder: &B,
        raw: &RawSignature,
        content_digest: &[u8; 32],
        evidence: &ScapSignatureEvidence,
        signing_time: OffsetDateTime,
    ) -> Result<Vec<u8>, ScapError> {
        binder.assemble(raw, content_digest, evidence, signing_time)
    }

    fn verification_source(&self) -> &'static str {
        match self.config.environment {
            ScapEnvironment::Preprod => "scap-preprod",
            ScapEnvironment::Prod => "scap-prod",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockScapTransport;

    fn client() -> ScapClient<MockScapTransport> {
        ScapClient::new(AmaScapConfig::preprod(), MockScapTransport::default()).unwrap()
    }

    #[test]
    fn provider_filter_restricts_listing() {
        let cfg = AmaScapConfig::preprod().with_provider_filter(["OA".to_owned()]);
        let client = ScapClient::new(cfg, MockScapTransport::default()).unwrap();
        let providers = client.list_providers().unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].id, "OA");
    }

    #[test]
    fn verify_evidence_rejects_forged_verified_status() {
        let client = client();
        let mut forged = ScapSignatureEvidence::declared(ProfessionalAttribute {
            provider_id: "OA".to_owned(),
            provider_name: "Ordem".to_owned(),
            name: "Advogado".to_owned(),
            valid_from: None,
            valid_until: None,
            sub_attributes: vec![],
        });
        // Hand-forge a "verified" status with no corroborating metadata.
        forged.status = ScapVerificationStatus::VerifiedByScap;
        let err = client.verify_evidence(&forged).unwrap_err();
        assert!(matches!(err, ScapError::Verification(_)));
    }
}
