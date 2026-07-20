//! INE SMI version-catalog source — public-surface tests (user directive t33).
//!
//! Offline coverage of the SMI **version-catalog** parser and the built-in `default_official_chain`.
//! The live SMI probe (fetching the real export) is `network-tests` + `#[ignore]` in `tests/network.rs`.
//!
//! Boundary under test: SMI reliably serves only the *version catalog* non-interactively (the CAE
//! node tree `/Categoria` returns HTTP 500 for every anonymous access pattern — see
//! `src/obtain/smi.rs`). So `SmiSource` is an update-availability signal, and the built-in official
//! chain obtains from the digest-pinned Diário da República diploma pair — with the INE-first default
//! (t37) leading with an always-failing `IneOfficialSource` entry so the DR fallback is honest, never
//! a silent substitution.

use chancela_cae::{
    CaeRevision, ChainEntry, IneOfficialSource, OfficialCaeSource, PreferredOfficialSource,
    SMI_CAE_REV3_VERSION, SMI_CAE_REV4_VERSION, SmiSource, default_official_chain,
    official_chain_for, parse_smi_version_catalog,
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
fn default_official_chain_is_ine_first_then_the_dr_pair() {
    // The default preferred source is INE (user directive t37: "default is ine"), so the no-config
    // chain leads with the INE entry and the digest-pinned Diário da República pair anchors it. INE
    // cannot supply codes (no viable bulk artifact), so at runtime it fails and DR fulfils — but it is
    // present and first, so the failure is surfaced honestly rather than silently substituted.
    let chain = default_official_chain();
    assert_eq!(chain.0.len(), 2, "INE-first + DR anchor");
    assert!(matches!(chain.0[0], ChainEntry::Ine(_)));
    assert!(chain.0[0].label().contains("INE"));
    assert!(matches!(chain.0[1], ChainEntry::Official(_)));
    assert!(chain.0[1].label().contains("Diário da República"));
}

#[test]
fn official_chain_for_orders_by_preference_with_dr_always_present() {
    // INE preferred → [INE, DR]; DR preferred → [DR] only (no pointless failing INE attempt). Either
    // way the reliable DR pair is in the chain, so the default never regresses.
    let ine = official_chain_for(PreferredOfficialSource::Ine);
    assert!(matches!(
        ine.0.as_slice(),
        [ChainEntry::Ine(_), ChainEntry::Official(_)]
    ));

    let dr = official_chain_for(PreferredOfficialSource::DiarioRepublica);
    assert!(matches!(dr.0.as_slice(), [ChainEntry::Official(_)]));

    // Default preference is INE.
    assert_eq!(
        PreferredOfficialSource::default(),
        PreferredOfficialSource::Ine
    );
}

#[test]
fn ine_official_source_always_fails_honestly() {
    // The INE bulk source cannot exist (t37): obtain never succeeds, and the error names the reason so
    // the chain `failures` are honest ("INE indisponível → Diário da República"), not a silent no-op.
    let err = IneOfficialSource
        .obtain()
        .expect_err("INE publishes no downloadable bulk CAE artifact");
    let msg = err.to_string();
    assert!(msg.contains("INE"), "error must name INE: {msg}");
    assert!(
        msg.contains("Diário da República"),
        "error must point at the DR fallback: {msg}"
    );
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
