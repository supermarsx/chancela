//! Live dataset fetch — double-gated: compiled only under `--features network-tests` AND `#[ignore]`d
//! so it never runs in CI. Point `CHANCELA_CAE_URL` at a real dataset (or a local fixture file
//! server) and run:
//!
//! ```text
//! cargo test -p chancela-cae --features network-tests -- --ignored
//! ```

#![cfg(feature = "network-tests")]

use chancela_cae::{
    CaeCatalog, CaeRevision, CaeSource, CaeVerifier, DrPdfSource, EXPECTED_REV3_COUNTS,
    EXPECTED_REV4_COUNTS, HttpCaeSource, OfficialCaeSource, OfficialSourceKind,
    SMI_CAE_REV3_VERSION, SMI_CAE_REV4_VERSION, SiconfVerifier, SmiSource, refresh,
    verify_fidelity,
};

#[test]
#[ignore = "hits CHANCELA_CAE_URL; run with --features network-tests -- --ignored"]
fn live_fetch_and_refresh() {
    let source = HttpCaeSource::from_env().expect("set CHANCELA_CAE_URL to a dataset URL");

    // Raw fetch parses into a dataset.
    let ds = source.fetch().expect("fetch + parse dataset");
    assert!(
        !ds.rev3.is_empty() || !ds.rev4.is_empty(),
        "fetched dataset must carry at least one revision's entries"
    );

    // The full pipeline validates the dataset (integrity) and reports an outcome.
    let (catalog, outcome) = refresh(&source, None).expect("refresh validates the fetched dataset");
    println!(
        "live refresh: updated={} note={}",
        outcome.updated, outcome.note
    );
    let counts = catalog.metadata().counts;
    assert!(counts.rev3.total() + counts.rev4.total() > 0);
}

/// The LIVE official obtainer: fetch both immutable Diário da República diploma PDFs from their
/// pinned URLs, digest-verify them, parse in-app (lopdf), and confirm the full official totals.
/// Double-gated (`network-tests` + `#[ignore]`) — never runs in CI; the vendored-PDF cross-check in
/// `tests/obtain.rs` is the offline equivalent.
#[test]
#[ignore = "fetches the live DR diploma PDFs; run with --features network-tests -- --ignored"]
fn live_dr_pdf_obtain() {
    let source = DrPdfSource::official();
    let obtained = source
        .obtain()
        .expect("fetch + digest-pin + parse the live DR PDFs");
    let ds = obtained.dataset;

    let catalog = CaeCatalog::from_dataset(ds.clone()).expect("obtained dataset passes integrity");
    verify_fidelity(&catalog.metadata().counts).expect("live obtain hits the official totals");
    assert_eq!(catalog.metadata().counts.rev4, EXPECTED_REV4_COUNTS);
    assert_eq!(catalog.metadata().counts.rev3, EXPECTED_REV3_COUNTS);

    let prov = ds.provenance.expect("live obtain records provenance");
    assert_eq!(prov.source_kind, OfficialSourceKind::DiarioRepublica);
    println!(
        "live DR obtain: {} nodes, artifact {}",
        catalog.metadata().counts.rev4.total() + catalog.metadata().counts.rev3.total(),
        prov.artifact_digest
    );
}

/// LIVE INE SMI version-catalog probe (user directive t33). Fetches the real
/// `https://smi.ine.pt/Versao/Exportacao?tipo=2` export (a cold, cookieless, chunked GET — the
/// endpoint SMI reliably serves), parses it, and asserts the two current CAE versions are present:
/// `V05497` (CAE Rev.4) and `V00554` (CAE Rev.3). Double-gated (`network-tests` + `#[ignore]`) — never
/// runs in CI; the parser is covered offline by `fixtures/smi_version_catalog.csv`.
///
/// This is an **update-availability signal**, not a bulk obtain: SMI's CAE node tree (`/Categoria`)
/// returns HTTP 500 non-interactively, so the codes cannot be crawled — see `src/obtain/smi.rs`.
#[test]
#[ignore = "fetches the live SMI version catalog; run with --features network-tests -- --ignored"]
fn live_smi_version_catalog_lists_the_current_cae_revisions() {
    let catalog = SmiSource::official()
        .fetch_catalog()
        .expect("fetch + parse the live SMI version catalog");
    let cae = catalog
        .cae_versions()
        .expect("live SMI catalog carries both current CAE versions");
    assert_eq!(cae.rev4.code, SMI_CAE_REV4_VERSION);
    assert_eq!(cae.rev3.code, SMI_CAE_REV3_VERSION);
    println!(
        "live SMI: {} versions; CAE Rev.4 = {} ({}), CAE Rev.3 = {} ({})",
        catalog.versions.len(),
        cae.rev4.code,
        cae.rev4.designation,
        cae.rev3.code,
        cae.rev3.designation,
    );
}

/// LIVE SICONF per-code verifier — **skeleton only** (plan t23 §2.6 / coordinator ruling). SICONF is
/// a postback-only ASP.NET WebForms `TreeView` with no per-code GET, so the live viewstate-postback
/// client is deferred; the response PARSER is covered offline by the `fixtures/siconf_node.html`
/// unit test in `src/obtain/verify.rs`. This `#[ignore]`d test marks the **missing network capture**:
/// once a real viewstate client and a captured node response exist, replace the deferral assertion
/// with a live `verify_code` lookup and assert the returned [`chancela_cae::VerifierFinding`].
#[test]
#[ignore = "SICONF live verifier transport deferred (WebForms/viewstate); parser covered by the offline fixture — no live capture yet"]
fn live_siconf_verify_code_skeleton() {
    let verifier = SiconfVerifier::official();
    // The live transport is intentionally not implemented yet; `verify_code` returns a clear config
    // error until a viewstate-postback client + a captured response are added here.
    let result = verifier.verify_code("68", CaeRevision::Rev4);
    assert!(
        result.is_err(),
        "SICONF live transport is deferred; build the viewstate client + capture, then assert a Found"
    );
}
