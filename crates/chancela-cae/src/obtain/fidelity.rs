//! Full-count fidelity gate (plan t23 §2.3): a per-revision obtain must hit its **exact** official
//! per-level totals or it is rejected as an [`CaeError::Integrity`], not accepted as a silently
//! short catalog. These are the same figures the embedded-dataset fidelity tests assert against —
//! t23-e1 factors those tests onto these shared consts so there is a single source of truth.

use crate::{CaeCounts, CaeError, CaeLevelCounts, CaeRevision};

/// Exact official per-level totals for **CAE-Rev.4** (22 secções / 87 divisões / 287 grupos /
/// 651 classes / 915 subclasses).
pub const EXPECTED_REV4_COUNTS: CaeLevelCounts = CaeLevelCounts {
    seccao: 22,
    divisao: 87,
    grupo: 287,
    classe: 651,
    subclasse: 915,
};

/// Exact official per-level totals for **CAE-Rev.3** (21 / 88 / 272 / 616 / 850).
pub const EXPECTED_REV3_COUNTS: CaeLevelCounts = CaeLevelCounts {
    seccao: 21,
    divisao: 88,
    grupo: 272,
    classe: 616,
    subclasse: 850,
};

/// Enforce that both revisions of an obtained dataset match their exact official per-level totals.
/// Any deviation (a truncated or scrambled parse) is a rejecting [`CaeError::Integrity`]. This is
/// the gate that makes "full" real: a dataset that passes structural integrity but is short of the
/// official totals is refused here, so it can never supersede the active catalog.
pub fn verify_fidelity(counts: &CaeCounts) -> Result<(), CaeError> {
    check_revision(CaeRevision::Rev4, &counts.rev4, &EXPECTED_REV4_COUNTS)?;
    check_revision(CaeRevision::Rev3, &counts.rev3, &EXPECTED_REV3_COUNTS)?;
    Ok(())
}

fn check_revision(
    revision: CaeRevision,
    got: &CaeLevelCounts,
    expected: &CaeLevelCounts,
) -> Result<(), CaeError> {
    if got != expected {
        return Err(CaeError::Integrity(format!(
            "{revision:?} fidelity: expected {}/{}/{}/{}/{} (total {}), obtained {}/{}/{}/{}/{} (total {})",
            expected.seccao,
            expected.divisao,
            expected.grupo,
            expected.classe,
            expected.subclasse,
            expected.total(),
            got.seccao,
            got.divisao,
            got.grupo,
            got.classe,
            got.subclasse,
            got.total(),
        )));
    }
    Ok(())
}
