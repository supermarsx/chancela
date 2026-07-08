//! Journey: RBAC role management (t64-E4) over the real server binary.
//!
//! Proves the composed access-control flow the unit tests exercise in isolation: the bootstrap
//! **Owner** creates a second user (Amélia Marques), assigns her the **Gestor** role scoped to ONE
//! entity (Encosto Estratégico Lda), and the assignee then acts **within** that scope (opens a book
//! there → `201`) but is refused **outside** it (a book in another entity → `403`) and on the admin
//! plane (`GET /v1/users` → `403`, Gestor lacks `user.read`). This is the end-to-end role-management
//! journey: `POST /v1/users/{id}/roles` with a scoped assignment, then scoped enforcement on the
//! grantee's own session.

mod common;

use common::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn owner_assigns_scoped_gestor_and_assignee_acts_within_scope() {
    let h = ServerHarness::start().await;

    // The bootstrap first user is Owner@Global; open its session (auto-auth for reads).
    let owner_id = create_user(&h, "e2e.owner", "E2E Owner").await;
    let owner = open_session(&h, &owner_id).await;

    // The Owner creates two entities. Amélia will be Gestor of the first only.
    let e1 = create_entity(
        &h,
        "Encosto Estratégico Lda",
        "503004642",
        "Lisboa",
        "SociedadeAnonima",
        &owner,
    )
    .await;
    let e2 = create_entity(
        &h,
        "Outra Sociedade Lda",
        "503004642",
        "Porto",
        "SociedadeAnonima",
        &owner,
    )
    .await;

    // The Owner creates the assignee (non-bootstrap create requires `user.manage`).
    let (status, amelia_user) = h
        .post_json_auth(
            "/v1/users",
            json!({ "username": "amelia.marques", "display_name": "Amélia Marques" }),
            &owner,
        )
        .await;
    assert_eq!(status, 201, "create assignee: {amelia_user}");
    let amelia = amelia_user["id"].as_str().expect("amelia id").to_owned();

    // Resolve the seeded Gestor role id from the catalog (any valid session may read it).
    let (status, roles) = h.get_json("/v1/roles").await;
    assert_eq!(status, 200, "list roles: {roles}");
    let gestor_id = roles
        .as_array()
        .expect("roles array")
        .iter()
        .find(|r| r["name"] == "Gestor")
        .and_then(|r| r["id"].as_str())
        .expect("seeded Gestor role present")
        .to_owned();

    // A newly-created user defaults to Gestor@Global; the Owner first removes that broad default so
    // the scoped grant is the assignee's ONLY authority (this also exercises the unassign endpoint).
    let (status, _) = h
        .delete_auth_json(
            &format!("/v1/users/{amelia}/roles"),
            json!({ "role_id": gestor_id, "scope": { "kind": "global" } }),
            &owner,
        )
        .await;
    assert_eq!(status, 200, "remove the default Gestor@Global");

    // The Owner assigns Gestor scoped to entity 1 ONLY.
    let (status, assignments) = h
        .post_json_auth(
            &format!("/v1/users/{amelia}/roles"),
            json!({ "role_id": gestor_id, "scope": { "kind": "entity", "id": e1 } }),
            &owner,
        )
        .await;
    assert_eq!(status, 200, "assign scoped Gestor: {assignments}");
    assert!(
        assignments
            .as_array()
            .expect("assignments")
            .iter()
            .any(|a| {
                a["role_id"] == json!(gestor_id)
                    && a["scope"]["kind"] == "entity"
                    && a["scope"]["id"] == json!(e1)
            }),
        "the scoped assignment is reflected back: {assignments}"
    );

    // Amélia (passwordless) signs in and acts.
    let amelia_tok = open_session(&h, &amelia).await;

    // WITHIN scope: opening a book in entity 1 → 201.
    let (status, book) = h
        .post_json_auth(
            "/v1/books",
            json!({
                "entity_id": e1,
                "kind": "AssembleiaGeral",
                "purpose": "livro de atas",
                "opening_date": "2026-01-15",
                "required_signatories": ["Administrador"],
            }),
            &amelia_tok,
        )
        .await;
    assert_eq!(status, 201, "book within the granted entity: {book}");

    // OUTSIDE scope: opening a book in entity 2 → 403 (a scoped grant never reaches another entity).
    let (status, refused) = h
        .post_json_auth(
            "/v1/books",
            json!({
                "entity_id": e2,
                "kind": "AssembleiaGeral",
                "purpose": "livro de atas",
                "opening_date": "2026-01-15",
                "required_signatories": ["Administrador"],
            }),
            &amelia_tok,
        )
        .await;
    assert_eq!(status, 403, "book outside the granted entity is refused");
    assert!(
        refused["error"]
            .as_str()
            .unwrap_or_default()
            .contains("permissão"),
        "honest, non-enumerating refusal: {refused}"
    );

    // ADMIN plane: a scoped Gestor lacks `user.read` → 403.
    let (status, _) = h.get_json_auth("/v1/users", &amelia_tok).await;
    assert_eq!(status, 403, "Gestor cannot read the user roster");

    // The role assignment is recorded in the audit ledger (read back as the Owner).
    let kinds = {
        let (s, events) = h.get_json_auth("/v1/ledger/events", &owner).await;
        assert_eq!(s, 200);
        events
            .as_array()
            .expect("events")
            .iter()
            .map(|e| e["kind"].as_str().unwrap_or_default().to_owned())
            .collect::<Vec<_>>()
    };
    assert!(
        kinds.iter().any(|k| k == "role.assigned"),
        "role.assigned chained into the ledger: {kinds:?}"
    );
}
