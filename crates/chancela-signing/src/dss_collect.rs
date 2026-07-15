//! DSS evidence collector — Phase-C frozen seam (wp26 E8 implements the body).
//!
//! Given a validated signer chain plus a live revocation provider, this module will assemble a
//! complete [`DssEvidence`] — every chain certificate and one validated revocation response per
//! issuing link — ready for PAdES `/DSS` embedding. The public signature is frozen in Phase C so
//! downstream executors compile against it; the body lands in Phase D (E8).

use time::OffsetDateTime;

use crate::DssEvidence;
use crate::SigningError;
use crate::revocation::{RevocationEvidenceProvider, RevocationHttpTransport};

/// Assemble a complete [`DssEvidence`] (every chain certificate + one validated revocation response
/// per issuing link) for a validated signer chain, ready for PAdES `/DSS` embedding. `chain_der` is
/// leaf-first, anchor-last (as produced by `chancela_tsl::certpath::build_path`). Phase-C stub.
pub fn collect_dss_evidence<T: RevocationHttpTransport>(
    chain_der: &[Vec<u8>],
    provider: &RevocationEvidenceProvider<T>,
    validation_time: OffsetDateTime,
) -> Result<DssEvidence, SigningError> {
    let _ = (chain_der, provider, validation_time);
    Err(SigningError::NotImplemented(
        "dss_collect::collect_dss_evidence",
    ))
}
