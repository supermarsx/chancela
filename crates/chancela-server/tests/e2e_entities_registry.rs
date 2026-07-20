//! Journey: entities — manual create + import-from-registry (create, conflict, overwrite).
//!
//! Drives the child's **real** `reqwest::blocking` registry transport against an in-process fixture
//! (`CHANCELA_REGISTRY_URL`), the composed path a live server proved but the in-process API tests
//! (which inject a mock) never exercised. Asserts the created entity, the fill-blanks / kept-conflict
//! / overwrite cross-check, CAE enrichment, and that the full código de acesso never reaches the
//! ledger or the stored extract.

mod common;

use common::*;
use serde_json::json;

const CODE: &str = "1234-5678-9012";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn entities_manual_and_registry_import() {
    let registry = spawn_registry_fixture(CERTIDAO_HTML).await;
    let h =
        ServerHarness::start_with(HarnessOptions::default().with_registry(registry.url.clone()))
            .await;
    let token = bootstrap_session(&h).await;

    // Manual create still works alongside the registry path.
    let _manual = create_entity(
        &h,
        "Manual, Lda",
        "500000000",
        "Porto",
        "SociedadePorQuotas",
        &token,
    )
    .await;

    // import-from-registry creates a consistent entity from the certidão (valid NIPC 503004642).
    let (status, report) = h
        .post_json_auth(
            "/v1/entities/import-from-registry",
            json!({ "code": CODE }),
            &token,
        )
        .await;
    assert_eq!(status, 201, "import-from-registry: {report}");
    assert_eq!(report["entity"]["name"], "Encosto Estratégico, Lda");
    assert_eq!(report["entity"]["nipc"], "503004642");
    assert_eq!(report["entity"]["kind"], "SociedadePorQuotas");
    assert_eq!(report["entity"]["family"], "CommercialCompany");
    assert_eq!(report["conflicts"].as_array().expect("conflicts").len(), 0);
    let created_id = report["entity"]["id"].as_str().expect("id").to_owned();

    // The role-tagged CAE was enriched from the catalog: Principal 68110 resolves, the uncatalogued
    // Secundário 99999 keeps its role but reports null designation/level/revision.
    let cae = report["extract"]["cae"].as_array().expect("cae array");
    assert_eq!(cae.len(), 2);
    assert_eq!(cae[0]["code"], "68110");
    assert_eq!(cae[0]["role"], "Principal");
    assert_eq!(
        cae[0]["designation"],
        "Compra e venda de bens imobiliários."
    );
    assert_eq!(cae[0]["revision"], "Rev4");
    assert_eq!(cae[1]["code"], "99999");
    assert_eq!(cae[1]["role"], "Secundario");
    assert_eq!(cae[1]["designation"], serde_json::Value::Null);

    // The stored extract is fetchable with only the masked code in its provenance.
    let (status, view) = h
        .get_json_auth(&format!("/v1/entities/{created_id}/registry"), &token)
        .await;
    assert_eq!(status, 200);
    assert_eq!(view["provenance"]["access_code_masked"], "****-****-9012");
    assert!(
        !view.to_string().contains(CODE) && !view.to_string().contains("123456789012"),
        "full access code must never appear in the stored extract"
    );

    // Conflict: a divergent name is KEPT (no overwrite), a blank seat is filled.
    let conflicted = create_entity(
        &h,
        "Nome Original, Lda",
        "503004642",
        "",
        "SociedadePorQuotas",
        &token,
    )
    .await;
    let (status, report) = h
        .post_json_auth(
            &format!("/v1/entities/{conflicted}/registry/import"),
            json!({ "code": CODE }),
            &token,
        )
        .await;
    assert_eq!(status, 200, "import into existing: {report}");
    let applied: Vec<&str> = report["applied"]
        .as_array()
        .expect("applied")
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    assert!(applied.contains(&"seat"), "blank seat filled: {applied:?}");
    let conflicts = report["conflicts"].as_array().expect("conflicts");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0]["field"], "name");
    assert_eq!(report["entity"]["name"], "Nome Original, Lda", "name kept");
    assert_eq!(report["entity"]["seat"], "Avenida da Liberdade, Lisboa");

    // Overwrite: a fresh entity whose name diverges is overwritten from the extract.
    let overwritten = create_entity(
        &h,
        "Outro Nome, Lda",
        "503004642",
        "Porto",
        "SociedadePorQuotas",
        &token,
    )
    .await;
    let (status, report) = h
        .post_json_auth(
            &format!("/v1/entities/{overwritten}/registry/import"),
            json!({ "code": CODE, "overwrite": true }),
            &token,
        )
        .await;
    assert_eq!(status, 200, "overwrite import: {report}");
    let applied: Vec<&str> = report["applied"]
        .as_array()
        .expect("applied")
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    assert!(
        applied.contains(&"name"),
        "divergent name overwritten: {applied:?}"
    );
    assert_eq!(report["conflicts"].as_array().expect("conflicts").len(), 0);
    assert_eq!(report["entity"]["name"], "Encosto Estratégico, Lda");

    // The whole ledger dump must never carry the full access code, in any grouping.
    let (status, events) = h.get_json("/v1/ledger/events").await;
    assert_eq!(status, 200);
    let dump = events.to_string();
    assert!(!dump.contains(CODE), "grouped code leaked to the ledger");
    assert!(
        !dump.contains("123456789012"),
        "bare code leaked to the ledger"
    );

    let (status, verify) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(status, 200);
    assert_eq!(verify["valid"], true);
}
