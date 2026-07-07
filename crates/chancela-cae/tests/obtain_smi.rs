//! INE SMI version-catalog source — public-surface tests (user directive t33).
//!
//! Offline coverage of the SMI **version-catalog** parser and the built-in `default_official_chain`.
//! The live SMI probe (fetching the real export) is `network-tests` + `#[ignore]` in `tests/network.rs`.
//!
//! Boundary under test: SMI reliably serves only the *version catalog* non-interactively (the CAE
//! node tree `/Categoria` returns HTTP 500 for every anonymous access pattern — see
//! `src/obtain/smi.rs`). So `SmiSource` is an update-availability signal, and the no-config default
//! official chain is the digest-pinned Diário da República diploma pair, not SMI.

use chancela_cae::{
    CaeRevision, ChainEntry, SMI_CAE_REV3_VERSION, SMI_CAE_REV4_VERSION, SmiSource,
    default_official_chain, parse_smi_version_catalog,
};

/// The trimmed real capture (UTF-16LE + BOM) the parser is validated against.
const FIXTURE: &[u8] = include_bytes!("../fixtures/smi_version_catalog.csv");

#[test]
fn parses_the_smi_version_catalog_and_extracts_both_current_cae_versions() {
    let catalog = parse_smi_version_catalog(FIXTURE).expect("SMI version catalog parses");

    // The update signal: the two CAE revisions INE currently publishes, by their SMI codes.
    let cae = catalog
        .cae_versions()
        .expect("catalog carries both current CAE versions");
    assert_eq!(cae.rev4.code, SMI_CAE_REV4_VERSION); // V05497
    assert_eq!(cae.rev3.code, SMI_CAE_REV3_VERSION); // V00554
    assert_eq!(cae.rev4.revision(), Some(CaeRevision::Rev4));
    assert_eq!(cae.rev3.revision(), Some(CaeRevision::Rev3));

    // Direct lookup by revision agrees.
    assert_eq!(
        catalog
            .cae_version(CaeRevision::Rev4)
            .map(|v| v.code.as_str()),
        Some(SMI_CAE_REV4_VERSION)
    );
}

#[test]
fn smi_source_targets_the_reliable_version_export_endpoint() {
    // The endpoint the source fetches is the version catalog (chunked, cookieless), never the
    // 500-ing /Categoria code-tree endpoints.
    let url = SmiSource::official().version_export_url();
    assert_eq!(url, "https://smi.ine.pt/Versao/Exportacao?tipo=2");
    assert!(
        !url.contains("/Categoria"),
        "must not target the non-obtainable code tree"
    );
}

#[test]
fn default_official_chain_is_the_digest_pinned_dr_pair() {
    // No configured URL ⇒ the built-in official chain: exactly one entry, the Diário da República
    // diploma pair (the only reliable both-revision, fidelity-passing bulk source). SMI is NOT a
    // bulk entry (it cannot supply codes), so the chain does not include it.
    let chain = default_official_chain();
    assert_eq!(
        chain.0.len(),
        1,
        "official fallback chain is the DR pair only"
    );
    assert!(matches!(chain.0[0], ChainEntry::Official(_)));
    assert!(chain.0[0].label().contains("Diário da República"));
}

#[test]
fn a_non_smi_payload_is_rejected_not_silently_empty() {
    // Guards the funnel: garbage never yields a bogus "empty catalog" that a caller might trust.
    let err = parse_smi_version_catalog(b"<html>not an SMI export</html>")
        .expect_err("non-SMI bytes must be a parse error");
    assert!(
        matches!(err, chancela_cae::CaeError::Parse(_)),
        "got {err:?}"
    );
}
