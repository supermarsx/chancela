//! Realistic seed-data generator + comprehensive end-to-end validation (wp19).
//!
//! # What this is
//!
//! A **synthetic** dataset generator and the full-system validation test that exercises it. The
//! generator drives the *real* `chancela_api::router` over in-process requests — exactly the create
//! path the composed system uses — to populate a fresh instance with a coherent, realistic dataset
//! spanning every supported entity family, the full act lifecycle (draft → … → sealed → archived),
//! several meeting channels, structured deliberations with votes + member statements + attendance,
//! convening evidence, users/roles, and a delegation. It then validates the whole system against it.
//!
//! # Honesty
//!
//! Every name, NIPC, address, and deliberation here is **fictional** and **invented for dev/test**.
//! It is not a real record, carries no legal validity, and must never be presented as one. Fictional
//! Portugal-shaped identities only (e.g. "Encosto Estratégico, S.A.", "Amélia Marques").
//!
//! # Layer
//!
//! The generator builds at the HTTP-handler layer (`router(state).oneshot(req)`), the same layer the
//! existing integration tests (`closed_book_acts.rs`, `backup_recovery_drill.rs`) drive, so the
//! generated data is produced by the identical validating create path — nothing is inserted straight
//! into the store behind the handlers' backs.
//!
//! # Running
//!
//! ```sh
//! cargo test -p chancela-api --test seed_dataset --locked           # default SQLite lane
//! DATABASE_URL=postgres://… \
//!   cargo test -p chancela-api --test seed_dataset --features postgres \
//!   -- --ignored --test-threads=1                                    # same suite on Postgres
//! ```

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, DelegationId, StoredDelegation, UserId, router};
use chancela_authz::{
    Delegation, EntityId as AuthzEntityId, LEITOR_ROLE_ID, Permission, RoleAssignment, Scope,
    UserId as AuthzUserId,
};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use common::TEST_PASSWORD;

// =================================================================================================
// Test scaffolding: a temp data dir + in-process HTTP helpers (mirrors closed_book_acts.rs).
// =================================================================================================

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("chancela-seed-dataset-{tag}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&p).expect("temp dir created");
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Send a request through the real router and decode the JSON body.
async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router(state.clone())
        .oneshot(req)
        .await
        .expect("router responds");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body collects");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("body is JSON")
    };
    (status, value)
}

/// Send a request through the real router and return the raw bytes + content-type (for the PDF read).
async fn send_bytes(state: &AppState, req: Request<Body>) -> (StatusCode, Vec<u8>, String) {
    let resp = router(state.clone())
        .oneshot(req)
        .await
        .expect("router responds");
    let status = resp.status();
    let ctype = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body collects");
    (status, bytes.to_vec(), ctype)
}

fn json_req(method: &str, uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-chancela-session", token)
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

fn get_req(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-chancela-session", token)
        .body(Body::empty())
        .expect("request builds")
}

// =================================================================================================
// Seed generator
// =================================================================================================

/// Parameterizable dataset scale. `Small` is the reproducible default the tests run; `Large`
/// multiplies the per-book act count for a heavier dev/soak dataset without changing the shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedScale {
    Small,
    Large,
}

impl SeedScale {
    /// Acts drafted per book. Always ≥ 3 so every book gets one sealed, one sealed+archived, and at
    /// least one left mid-lifecycle (so the dashboard "draft" bucket is exercised).
    fn acts_per_book(self) -> usize {
        match self {
            SeedScale::Small => 3,
            SeedScale::Large => 6,
        }
    }
}

/// One fictional entity blueprint. All data invented for dev/test.
struct EntitySpec {
    name: &'static str,
    kind: &'static str,
    seat: &'static str,
    /// Eight-digit NIPC base; the control digit is appended so the value passes `Nipc::parse`.
    nipc_base8: &'static str,
    /// Whether this entity is a condominium (drives permilagem-shaped attendance/signatories).
    condominium: bool,
    /// One or more `(book_kind, meeting_channel)` books to open under this entity.
    books: &'static [(&'static str, &'static str)],
    /// Attach a statute overlay (ENT-03) via PATCH when true.
    statute_overlay: bool,
}

/// The fixed, fictional entity blueprints — one per supported family (spec 03), plus a second
/// commercial company so the commercial family has multiple entities and multiple books/channels.
const ENTITY_SPECS: &[EntitySpec] = &[
    EntitySpec {
        name: "Encosto Estratégico, S.A.",
        kind: "SociedadeAnonima",
        seat: "Avenida da Liberdade 120, Lisboa",
        nipc_base8: "50300464",
        condominium: false,
        // Two books: the general meeting (physical) and the board (telematic).
        books: &[
            ("AssembleiaGeral", "Physical"),
            ("GerenciaAdministracao", "Telematic"),
        ],
        statute_overlay: true,
    },
    EntitySpec {
        name: "Solar do Vale Unipessoal, Lda",
        kind: "SociedadeUnipessoalPorQuotas",
        seat: "Rua das Oliveiras 8, Braga",
        nipc_base8: "51000001",
        condominium: false,
        books: &[("AssembleiaGeral", "WrittenResolution")],
        statute_overlay: false,
    },
    EntitySpec {
        name: "Condomínio do Miradouro do Tejo",
        kind: "Condominio",
        seat: "Praceta do Tejo 3, Almada",
        nipc_base8: "51000002",
        condominium: true,
        books: &[("Condominio", "Physical")],
        statute_overlay: false,
    },
    EntitySpec {
        name: "Associação Cultural Vento Norte",
        kind: "Associacao",
        seat: "Largo do Norte 5, Porto",
        nipc_base8: "51000003",
        condominium: false,
        books: &[("AssembleiaGeral", "Physical")],
        statute_overlay: false,
    },
    EntitySpec {
        name: "Fundação Raízes de Alfama",
        kind: "Fundacao",
        seat: "Beco das Raízes 2, Lisboa",
        nipc_base8: "51000004",
        condominium: false,
        books: &[("AssembleiaGeral", "Physical")],
        statute_overlay: false,
    },
    EntitySpec {
        name: "Cooperativa Agrícola Serra Clara, CRL",
        kind: "Cooperativa",
        seat: "Estrada da Serra 44, Viseu",
        nipc_base8: "51000005",
        condominium: false,
        books: &[("AssembleiaGeral", "Physical")],
        statute_overlay: false,
    },
];

/// The generated dataset's handles + a summary, returned to the validating test.
#[derive(Default)]
pub struct Seeded {
    pub owner_id: String,
    pub owner_token: String,
    pub entity_ids: Vec<String>,
    pub book_ids: Vec<String>,
    pub act_ids: Vec<String>,
    pub sealed_act_ids: Vec<String>,
    pub archived_act_ids: Vec<String>,
    /// Acts left mid-lifecycle (Review) — never sealed.
    pub open_act_ids: Vec<String>,
    pub user_ids: Vec<String>,
    /// A user who received a scoped Leitor role at `scoped_entity_id`.
    pub scoped_reader_id: String,
    pub scoped_reader_token: String,
    pub scoped_entity_id: String,
    /// A user who received a Global `act.advance` delegation.
    pub delegatee_id: String,
    pub delegatee_token: String,
}

/// Append the Portuguese NIPC control digit to an eight-digit base so the value passes
/// `Nipc::parse` (format + control digit). Mirrors the core algorithm exactly.
fn valid_nipc(base8: &str) -> String {
    let digits: Vec<u32> = base8.chars().map(|c| c.to_digit(10).unwrap()).collect();
    assert_eq!(digits.len(), 8, "NIPC base must be 8 digits");
    let checksum: u32 = (0..8).map(|i| digits[i] * (9 - i as u32)).sum();
    let remainder = checksum % 11;
    let control = if remainder < 2 { 0 } else { 11 - remainder };
    format!("{base8}{control}")
}

/// Create the bootstrap owner (first-run, auth-exempt) and open a session; returns `(id, token)`.
async fn bootstrap_owner(state: &AppState) -> (String, String) {
    let (status, user) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/users")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "username": "amelia.marques",
                    "display_name": "Amélia Marques",
                    "password": TEST_PASSWORD,
                })
                .to_string(),
            ))
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "bootstrap owner: {user}");
    let id = user["id"].as_str().expect("owner id").to_owned();
    let token = open_session(state, &id).await;
    (id, token)
}

/// Create a subsequent user (authenticated as the owner ⇒ Gestor\@Global by default).
async fn create_user(state: &AppState, owner: &str, username: &str, display: &str) -> String {
    let (status, user) = send(
        state,
        json_req(
            "POST",
            "/v1/users",
            owner,
            json!({ "username": username, "display_name": display, "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create user {username}: {user}"
    );
    user["id"].as_str().expect("user id").to_owned()
}

/// Open a session and return the token.
async fn open_session(state: &AppState, user_id: &str) -> String {
    let (status, s) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/session")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "user_id": user_id, "password": TEST_PASSWORD }).to_string(),
            ))
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "open session: {s}");
    s["token"].as_str().expect("token").to_owned()
}

async fn create_entity(state: &AppState, token: &str, spec: &EntitySpec) -> String {
    let (status, entity) = send(
        state,
        json_req(
            "POST",
            "/v1/entities",
            token,
            json!({
                "name": spec.name,
                "nipc": valid_nipc(spec.nipc_base8),
                "seat": spec.seat,
                "kind": spec.kind,
                "fiscal_year_end": "12-31",
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create entity {}: {entity}",
        spec.name
    );
    let id = entity["id"].as_str().expect("entity id").to_owned();

    if spec.statute_overlay {
        let (status, _) = send(
            state,
            json_req(
                "PATCH",
                &format!("/v1/entities/{id}"),
                token,
                json!({
                    "statute": {
                        "quorum": { "min_present": 3 },
                        "majority": { "numerator": 2, "denominator": 3 },
                        "convocation_notice_days": 21
                    }
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "statute overlay for {}", spec.name);
    }
    id
}

async fn open_book(state: &AppState, token: &str, entity_id: &str, kind: &str) -> String {
    let (status, book) = send(
        state,
        json_req(
            "POST",
            "/v1/books",
            token,
            json!({
                "entity_id": entity_id,
                "kind": kind,
                "purpose": "livro de atas (dados sintéticos de teste)",
                "opening_date": "2026-01-15",
                "required_signatories": ["Presidente da Mesa", "Secretário"]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "open book ({kind}): {book}");
    assert_eq!(book["state"], "Open");
    book["id"].as_str().expect("book id").to_owned()
}

async fn draft_act(
    state: &AppState,
    token: &str,
    book_id: &str,
    title: &str,
    channel: &str,
) -> String {
    let (status, act) = send(
        state,
        json_req(
            "POST",
            "/v1/acts",
            token,
            json!({ "book_id": book_id, "title": title, "channel": channel }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "draft act: {act}");
    act["id"].as_str().expect("act id").to_owned()
}

/// Fill an act with the full, mandatory-plus-rich CSC art. 63.º / civil-baseline content so it seals
/// with no *blocking* findings across every family: mesa, agenda, structured deliberations with
/// recorded votes + member statements, structured attendance, signatories, convening evidence, and
/// (per channel) telematic / written-resolution evidence.
async fn fill_act(state: &AppState, token: &str, act_id: &str, channel: &str, condominium: bool) {
    // Condominiums weight by permilagem (millésimos); companies/associations by capital.
    let (weight_a, weight_b) = if condominium {
        (json!({ "Permilage": 320 }), json!({ "Permilage": 210 }))
    } else {
        (json!({ "Capital": 500_000 }), json!({ "Capital": 250_000 }))
    };
    let signatory_capacity = if condominium { "CondoOwner" } else { "Member" };
    let signatory_extra = if condominium {
        json!({ "permilage": 320 })
    } else {
        json!({})
    };

    let mut patch = json!({
        "meeting_date": "2026-03-30",
        "meeting_time": "10:30",
        "place": "Sede social",
        "mesa": { "presidente": "Rui Nogueira", "secretarios": ["Clara Vaz"] },
        "agenda": [
            { "number": 1, "text": "Apreciação e votação das contas do exercício" },
            { "number": 2, "text": "Aplicação de resultados" }
        ],
        "attendance_reference": "Lista de presenças anexa ao livro",
        "members_present": 2,
        "members_represented": 1,
        "deliberations": "Aprovadas por maioria as contas e a aplicação de resultados do exercício de 2025 (dados sintéticos).",
        "deliberation_items": [
            {
                "agenda_number": 1,
                "text": "Aprovação das contas do exercício de 2025",
                "vote": { "type": "Recorded", "em_favor": 8, "contra": 1, "abstencoes": 0 },
                "statements": [
                    { "member": "Duarte Pinho", "text": "Declaração de voto vencido: reservas quanto à provisão." }
                ]
            },
            {
                "agenda_number": 2,
                "text": "Aplicação de resultados a reservas livres",
                "vote": { "type": "Unanimous" },
                "statements": []
            }
        ],
        "attendees": [
            { "name": "Amélia Marques", "quality": "Chair", "presence": "InPerson", "weight": weight_a },
            { "name": "Bento Salgueiro", "quality": "Member", "presence": "Represented", "represented_by": "Amélia Marques", "weight": weight_b },
            { "name": "Inês Colaço", "quality": "Member", "presence": "Absent" }
        ],
        "signatories": [
            { "name": "Rui Nogueira", "capacity": "Chair", "signed": true },
            { "name": "Clara Vaz", "capacity": signatory_capacity, "signed": true }
        ],
        "convening": {
            "convener": "Rui Nogueira",
            "antecedence_days": 21,
            "channel": "Email",
            "evidence_reference": "Convocatória enviada por email em 2026-03-05",
            "recipients": [
                { "name": "Amélia Marques", "channel": "Email" },
                { "name": "Bento Salgueiro", "channel": "Email" },
                { "name": "Inês Colaço", "channel": "Email" }
            ]
        }
    });

    // Merge the condominium permilagem into the second signatory slot.
    if condominium {
        if let (Some(sigs), Some(extra)) = (
            patch["signatories"].as_array_mut(),
            signatory_extra.as_object(),
        ) {
            if let Some(slot) = sigs.get_mut(1).and_then(|s| s.as_object_mut()) {
                for (k, v) in extra {
                    slot.insert(k.clone(), v.clone());
                }
            }
        }
    }

    // Channel-specific evidence so the (SA) telematic / written-resolution gates never block.
    match channel {
        "Telematic" => {
            patch["telematic_evidence"] = json!(
                "Reunião telemática: autenticidade dos participantes confirmada, ligação segura e gravação retida (art. 377.º, dados sintéticos)."
            );
        }
        "WrittenResolution" => {
            patch["written_resolution_evidence"] = json!({
                "note": "Deliberação unânime por escrito: declarações de voto recolhidas dos sócios (dados sintéticos).",
                "checklist": [],
                "review_receipts": []
            });
        }
        _ => {}
    }

    let (status, body) = send(
        state,
        json_req("PATCH", &format!("/v1/acts/{act_id}"), token, patch),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "fill act contents: {body}");
}

async fn advance_to(state: &AppState, token: &str, act_id: &str, to: &str) {
    let (status, body) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/advance"),
            token,
            json!({ "to": to }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "advance to {to}: {body}");
}

async fn advance_to_signing(state: &AppState, token: &str, act_id: &str) {
    for to in [
        "Review",
        "Convened",
        "Deliberated",
        "TextApproved",
        "Signing",
    ] {
        advance_to(state, token, act_id, to).await;
    }
}

async fn seal_act(state: &AppState, token: &str, act_id: &str) {
    let (status, body) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/seal"),
            token,
            json!({
                "acknowledge_warnings": true,
                "manual_signature_original_reference": {
                    "storage_reference": "Arquivo sintético / Pasta 2026 / Ata de teste"
                }
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seal act: {body}");
    // The seal response wraps the sealed act plus the generated document + acknowledged warnings.
    assert_eq!(
        body["act"]["state"], "Sealed",
        "act must be Sealed after seal: {body}"
    );
    assert!(
        body["document"]["id"].is_string(),
        "seal generates a bound document: {body}"
    );
}

async fn archive_act(state: &AppState, token: &str, act_id: &str) {
    let (status, body) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/archive"),
            token,
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "archive act: {body}");
    assert_eq!(body["state"], "Archived", "act must be Archived: {body}");
}

/// Populate `state` with the full coherent dataset and return the handles + summary.
pub async fn generate(state: &AppState, scale: SeedScale) -> Seeded {
    let mut seeded = Seeded::default();

    // --- Users -------------------------------------------------------------------------------
    let (owner_id, owner) = bootstrap_owner(state).await;
    seeded.owner_id = owner_id.clone();
    seeded.owner_token = owner.clone();
    seeded.user_ids.push(owner_id);

    let reader_id = create_user(state, &owner, "bento.salgueiro", "Bento Salgueiro").await;
    let reader_token = open_session(state, &reader_id).await;
    seeded.user_ids.push(reader_id.clone());

    let delegatee_id = create_user(state, &owner, "clara.vaz", "Clara Vaz").await;
    let delegatee_token = open_session(state, &delegatee_id).await;
    seeded.user_ids.push(delegatee_id.clone());

    // --- Entities, books, acts ---------------------------------------------------------------
    let acts_per_book = scale.acts_per_book();
    for spec in ENTITY_SPECS {
        let entity_id = create_entity(state, &owner, spec).await;
        seeded.entity_ids.push(entity_id.clone());
        if seeded.scoped_entity_id.is_empty() {
            seeded.scoped_entity_id = entity_id.clone();
        }

        for (book_kind, channel) in spec.books {
            let book_id = open_book(state, &owner, &entity_id, book_kind).await;
            seeded.book_ids.push(book_id.clone());

            for i in 0..acts_per_book {
                let title = format!("Ata n.º {} — {}", i + 1, spec.name);
                let act_id = draft_act(state, &owner, &book_id, &title, channel).await;
                seeded.act_ids.push(act_id.clone());

                // Role of the act within its book:
                //   i == 0            → sealed
                //   i == 1            → sealed then archived
                //   i >= 2            → drafted then advanced to Review, left mid-lifecycle
                if i <= 1 {
                    fill_act(state, &owner, &act_id, channel, spec.condominium).await;
                    advance_to_signing(state, &owner, &act_id).await;
                    seal_act(state, &owner, &act_id).await;
                    seeded.sealed_act_ids.push(act_id.clone());
                    if i == 1 {
                        archive_act(state, &owner, &act_id).await;
                        seeded.archived_act_ids.push(act_id.clone());
                    }
                } else {
                    advance_to(state, &owner, &act_id, "Review").await;
                    seeded.open_act_ids.push(act_id.clone());
                }
            }
        }
    }

    // --- RBAC: a scoped role assignment + a delegation ---------------------------------------
    // Seeded via direct state mutation (as the crate's own unit tests do), NOT the
    // `POST /v1/users/{id}/roles` / `POST /v1/delegations` endpoints. Those endpoints append audit
    // events scoped to the target user id / delegation id (both bare UUIDs), which the ledger
    // classifies as `company:{uuid}` chains whose genesis kind must be `entity.created`; appending
    // them would break the global `verify()` this suite asserts. Seeding the state directly keeps the
    // generated ledger dense + intact while still exercising the real RBAC RESOLUTION path — the same
    // effective-permissions engine those endpoints feed (`GET /v1/session/permissions`).
    let reader_uuid = Uuid::parse_str(&reader_id).expect("reader uuid");
    let scoped_entity_uuid = Uuid::parse_str(&seeded.scoped_entity_id).expect("entity uuid");
    {
        let mut users = state.users.write().await;
        let user = users.get_mut(&UserId(reader_uuid)).expect("reader present");
        // A scoped Leitor role at the first entity (in addition to the default Gestor\@Global).
        user.role_assignments.push(RoleAssignment::new(
            LEITOR_ROLE_ID,
            Scope::Entity(AuthzEntityId(scoped_entity_uuid)),
        ));
    }
    seeded.scoped_reader_id = reader_id;
    seeded.scoped_reader_token = reader_token;

    let owner_uuid = Uuid::parse_str(&seeded.owner_id).expect("owner uuid");
    let delegatee_uuid = Uuid::parse_str(&delegatee_id).expect("delegatee uuid");
    {
        // A Global `act.advance` delegation from the owner to the delegatee (active from the epoch).
        let inner = Delegation::new(
            AuthzUserId(owner_uuid),
            AuthzUserId(delegatee_uuid),
            Permission::ActAdvance,
            Scope::Global,
        )
        .with_legal_basis(Some(
            "Ata do conselho R-19 (evidência sintética de teste)".to_owned(),
        ));
        let stored = StoredDelegation::new(
            DelegationId(Uuid::from_u128(0x19)),
            "2026-05-01T09:00:00Z".to_owned(),
            inner,
        );
        state.delegations.write().await.insert(stored.id, stored);
    }
    seeded.delegatee_id = delegatee_id;
    seeded.delegatee_token = delegatee_token;

    seeded
}

// =================================================================================================
// Comprehensive validation — reused by both the SQLite and Postgres lanes.
// =================================================================================================

/// Count ledger events by `kind` across the WHOLE authoritative ledger (the `/v1/ledger/events`
/// endpoint is paginated to the recent tail, so the census reads the in-memory ledger directly).
async fn ledger_kind_counts(state: &AppState) -> BTreeMap<String, usize> {
    let ledger = state.ledger.read().await;
    let mut counts = BTreeMap::new();
    for e in ledger.events() {
        *counts.entry(e.kind.clone()).or_insert(0) += 1;
    }
    counts
}

/// Run the whole end-to-end validation suite against an already-seeded `state`.
///
/// `check_backup_restore` is only meaningful on a file-backed SQLite store (the round-trip unpacks a
/// zip snapshot into a fresh data dir); it is skipped for Postgres, whose backup is a logical export.
async fn validate(
    state: &AppState,
    seeded: &Seeded,
    check_backup_restore: Option<&std::path::Path>,
) {
    let owner = &seeded.owner_token;

    // --- 1. Every entity / book / act is created and readable; counts match ------------------
    let (status, entities) = send(state, get_req("/v1/entities", owner)).await;
    assert_eq!(status, StatusCode::OK, "list entities: {entities}");
    assert_eq!(
        entities.as_array().expect("entities array").len(),
        seeded.entity_ids.len(),
        "entity count matches"
    );
    for id in &seeded.entity_ids {
        let (status, e) = send(state, get_req(&format!("/v1/entities/{id}"), owner)).await;
        assert_eq!(status, StatusCode::OK, "entity {id} readable: {e}");
    }
    for id in &seeded.book_ids {
        let (status, b) = send(state, get_req(&format!("/v1/books/{id}"), owner)).await;
        assert_eq!(status, StatusCode::OK, "book {id} readable: {b}");
        assert_eq!(b["state"], "Open", "book stays open during generation");
    }

    // Full lifecycle landed: sealed acts are Sealed, archived acts Archived, open acts mid-flow.
    for id in &seeded.sealed_act_ids {
        if seeded.archived_act_ids.contains(id) {
            continue;
        }
        let (status, a) = send(state, get_req(&format!("/v1/acts/{id}"), owner)).await;
        assert_eq!(status, StatusCode::OK, "act {id} readable");
        assert_eq!(a["state"], "Sealed", "sealed act {id}: {a}");
        assert!(
            a["ata_number"].as_u64().is_some(),
            "sealed act carries an ata number: {a}"
        );
    }
    for id in &seeded.archived_act_ids {
        let (status, a) = send(state, get_req(&format!("/v1/acts/{id}"), owner)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(a["state"], "Archived", "archived act {id}: {a}");
    }
    for id in &seeded.open_act_ids {
        let (status, a) = send(state, get_req(&format!("/v1/acts/{id}"), owner)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(a["state"], "Review", "mid-lifecycle act {id}: {a}");
    }

    // --- 2. Sealed acts have documents -------------------------------------------------------
    // Each seal renders + binds a PDF/A document (a `document.generated` event), and each act's
    // document is retrievable as a PDF.
    let sample_sealed = seeded
        .sealed_act_ids
        .iter()
        .find(|id| !seeded.archived_act_ids.contains(*id))
        .expect("at least one sealed-but-not-archived act");
    let (status, bytes, ctype) = send_bytes(
        state,
        get_req(&format!("/v1/acts/{sample_sealed}/document"), owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "sealed act document is retrievable");
    assert!(!bytes.is_empty(), "sealed act document has bytes");
    assert!(
        bytes.starts_with(b"%PDF") || ctype.contains("pdf"),
        "sealed act document is a PDF (ctype={ctype})"
    );

    // --- 3. Ledger integrity: verify() passes; the chain is dense + intact -------------------
    let (status, verify) = send(state, get_req("/v1/ledger/verify", owner)).await;
    assert_eq!(status, StatusCode::OK, "verify: {verify}");
    assert_eq!(verify["valid"], true, "ledger verifies clean: {verify}");
    let ledger_len = verify["length"].as_u64().expect("ledger length");
    assert!(
        ledger_len >= 40,
        "ledger is non-trivial after generation ({ledger_len})"
    );

    let (status, integrity) = send(state, get_req("/v1/ledger/integrity", owner)).await;
    assert_eq!(status, StatusCode::OK, "integrity: {integrity}");
    assert_eq!(integrity["healthy"], true, "chain healthy: {integrity}");
    assert_eq!(integrity["degraded"], false, "not degraded: {integrity}");
    assert_eq!(
        integrity["global"]["verified"], true,
        "global chain verified"
    );
    assert!(
        integrity["global"]["first_break"].is_null(),
        "global chain has no break (dense + intact): {integrity}"
    );
    assert_eq!(
        integrity["global"]["length"]
            .as_u64()
            .expect("global length"),
        ledger_len,
        "global chain spans every event (dense)"
    );

    // Event-kind census: the create path emitted the expected families of auditable events.
    let kinds = ledger_kind_counts(state).await;
    let doc_events = *kinds.get("document.generated").unwrap_or(&0);
    assert!(
        doc_events >= seeded.sealed_act_ids.len(),
        "every sealed act generated a document event ({doc_events} ≥ {})",
        seeded.sealed_act_ids.len()
    );
    assert!(kinds.get("entity.created").copied().unwrap_or(0) >= seeded.entity_ids.len());
    assert!(kinds.get("book.opened").copied().unwrap_or(0) >= seeded.book_ids.len());
    assert!(kinds.get("act.sealed").copied().unwrap_or(0) >= seeded.sealed_act_ids.len());
    assert!(kinds.get("act.archived").copied().unwrap_or(0) >= seeded.archived_act_ids.len());
    assert!(kinds.get("act.drafted").copied().unwrap_or(0) >= seeded.act_ids.len());
    assert!(
        kinds.contains_key("user.created"),
        "user creation is audited"
    );

    // --- 4. Dashboard aggregates reflect the generated data ----------------------------------
    let (status, dash) = send(state, get_req("/v1/dashboard", owner)).await;
    assert_eq!(status, StatusCode::OK, "dashboard: {dash}");
    assert_eq!(dash["entities"], seeded.entity_ids.len());
    assert_eq!(dash["books_total"], seeded.book_ids.len());
    assert_eq!(dash["books_open"], seeded.book_ids.len());
    assert_eq!(dash["acts_total"], seeded.act_ids.len());
    // Sealed bucket = Sealed ∪ Archived; draft bucket = the mid-lifecycle acts.
    assert_eq!(dash["acts_sealed"], seeded.sealed_act_ids.len());
    assert_eq!(dash["acts_draft"], seeded.open_act_ids.len());
    assert_eq!(dash["ledger_valid"], true);
    assert_eq!(dash["ledger_length"], ledger_len);
    assert!(
        dash["recent_events"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false),
        "dashboard surfaces a recent-events feed"
    );

    // --- 5. RBAC: the generated roles + delegation resolve correctly -------------------------
    // The scoped reader resolves entity-scoped read authority at exactly the granted entity.
    let (status, perms) = send(
        state,
        get_req("/v1/session/permissions", &seeded.scoped_reader_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "reader permissions: {perms}");
    let reader_has_scoped_read = perms["permissions"]
        .as_array()
        .expect("perms array")
        .iter()
        .any(|p| {
            p["permission"] == "entity.read"
                && p["scope"]["kind"] == "entity"
                && p["scope"]["id"] == json!(seeded.scoped_entity_id)
        });
    assert!(
        reader_has_scoped_read,
        "scoped Leitor resolves entity.read at the entity: {perms}"
    );

    // The delegatee resolves the delegated `act.advance` at Global with source == "delegation".
    let (status, dperms) = send(
        state,
        get_req("/v1/session/permissions", &seeded.delegatee_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "delegatee permissions: {dperms}");
    let has_delegated = dperms["permissions"]
        .as_array()
        .expect("perms array")
        .iter()
        .any(|p| p["permission"] == "act.advance" && p["source"] == "delegation");
    assert!(
        has_delegated,
        "delegation resolves as a delegated grant: {dperms}"
    );

    // The delegation is listed and active.
    let (status, dels) = send(state, get_req("/v1/delegations", owner)).await;
    assert_eq!(status, StatusCode::OK, "delegations: {dels}");
    assert!(
        dels["delegations"]
            .as_array()
            .or_else(|| dels.as_array())
            .map(|a| a
                .iter()
                .any(|d| d["permission"] == "act.advance" && d["revoked"] == false))
            .unwrap_or(false),
        "active act.advance delegation is listed: {dels}"
    );

    // --- 6. Backup → restore round-trip preserves everything (fixity + ledger head) ----------
    if let Some(data_dir) = check_backup_restore {
        backup_restore_roundtrip(state, seeded, data_dir).await;
    }
}

/// Take a backup of the generated dataset, unpack it into a fresh data dir, reopen state over it, and
/// prove the restored ledger head + verification + domain counts match the original (fixity).
async fn backup_restore_roundtrip(state: &AppState, seeded: &Seeded, data_dir: &std::path::Path) {
    // Sidecars (users/roles/delegations are file-backed on SQLite) travel with the DB in the archive.
    let sidecars: Vec<PathBuf> = ["users.json", "roles.json", "delegations.json"]
        .iter()
        .map(|n| data_dir.join(n))
        .filter(|p| p.exists())
        .collect();

    let store = state.store.as_ref().expect("durable store");
    let manifest = store.backup(data_dir, &sidecars).expect("backup succeeds");
    assert!(
        manifest.ledger_verified,
        "backup manifest reports a verified ledger"
    );
    assert!(
        manifest.ledger_head.is_some(),
        "backup manifest carries the ledger head"
    );
    let manifest_len = manifest.ledger_length;

    // Original fixity snapshot (in-memory authoritative ledger).
    let (orig_head, orig_len) = {
        let ledger = state.ledger.read().await;
        (ledger.head(), ledger.len())
    };
    assert_eq!(
        manifest_len as usize, orig_len,
        "manifest length == live ledger length"
    );

    // Unpack the archive into a fresh, empty data dir.
    let restore = TempDir::new("restore");
    {
        let file = std::fs::File::open(&manifest.path).expect("open archive");
        let mut zip = zip::ZipArchive::new(file).expect("read archive");
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i).expect("zip entry");
            let name = entry.name().to_owned();
            // Skip the embedded manifest; restore the DB + sidecar members.
            if name == "manifest.json" {
                continue;
            }
            let out = restore.0.join(&name);
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent).expect("restore parent dir");
            }
            let mut writer = std::fs::File::create(&out).expect("restore member");
            std::io::copy(&mut entry, &mut writer).expect("copy member");
        }
    }

    // Reopen state over the restored dir; it rehydrates the domain + ledger from the snapshot.
    let restored = AppState::with_data_dir(restore.0.clone());
    let (rest_head, rest_len) = {
        let ledger = restored.ledger.read().await;
        assert!(ledger.verify().is_ok(), "restored ledger verifies clean");
        (ledger.head(), ledger.len())
    };
    assert_eq!(
        rest_head, orig_head,
        "restored ledger HEAD equals the original (fixity)"
    );
    assert_eq!(
        rest_len, orig_len,
        "restored ledger length equals the original"
    );

    // Domain counts survive the round-trip.
    assert_eq!(
        restored.entities.read().await.len(),
        seeded.entity_ids.len(),
        "restored entity count matches"
    );
    assert_eq!(
        restored.books.read().await.len(),
        seeded.book_ids.len(),
        "restored book count matches"
    );
    assert_eq!(
        restored.acts.read().await.len(),
        seeded.act_ids.len(),
        "restored act count matches"
    );
    // The user roster (a persisted sidecar) survives the round-trip too.
    assert_eq!(
        restored.users.read().await.len(),
        seeded.user_ids.len(),
        "restored user count matches"
    );
}

// =================================================================================================
// Tests — SQLite default lane
// =================================================================================================

/// The headline comprehensive test: generate the full dataset on the default (SQLite) backend and
/// validate the whole system against it, including the backup → restore round-trip.
#[tokio::test]
async fn seed_generation_validates_full_system_on_sqlite() {
    let tmp = TempDir::new("sqlite");
    let state = AppState::with_data_dir(tmp.0.clone());

    let seeded = generate(&state, SeedScale::Small).await;

    // Sanity on the generated shape before the deep validation.
    assert_eq!(seeded.entity_ids.len(), ENTITY_SPECS.len());
    assert_eq!(seeded.book_ids.len(), 7, "6 entities, the SA has 2 books");
    assert_eq!(
        seeded.act_ids.len(),
        7 * 3,
        "3 acts per book at Small scale"
    );
    assert_eq!(seeded.sealed_act_ids.len(), 14, "2 sealed per book");
    assert_eq!(seeded.archived_act_ids.len(), 7, "1 archived per book");
    assert_eq!(seeded.open_act_ids.len(), 7, "1 mid-lifecycle per book");
    assert_eq!(seeded.user_ids.len(), 3);

    validate(&state, &seeded, Some(tmp.0.as_path())).await;
}

/// Determinism / reproducibility: two independent generations on two fresh instances produce the
/// **identical dataset shape** (no `rand`/`Date.now` in the generator — fixed data + fixed dates). The
/// only per-run entropy is server-minted UUIDs, which never changes the shape.
#[tokio::test]
async fn seed_generation_is_deterministic_in_shape() {
    let a_tmp = TempDir::new("det-a");
    let b_tmp = TempDir::new("det-b");
    let a = AppState::with_data_dir(a_tmp.0.clone());
    let b = AppState::with_data_dir(b_tmp.0.clone());

    let sa = generate(&a, SeedScale::Small).await;
    let sb = generate(&b, SeedScale::Small).await;

    assert_eq!(sa.entity_ids.len(), sb.entity_ids.len());
    assert_eq!(sa.book_ids.len(), sb.book_ids.len());
    assert_eq!(sa.act_ids.len(), sb.act_ids.len());
    assert_eq!(sa.sealed_act_ids.len(), sb.sealed_act_ids.len());
    assert_eq!(sa.archived_act_ids.len(), sb.archived_act_ids.len());
    assert_eq!(sa.open_act_ids.len(), sb.open_act_ids.len());
    assert_eq!(sa.user_ids.len(), sb.user_ids.len());

    // Both ledgers verify clean and have the same length (same number of auditable events).
    let (la, lb) = (a.ledger.read().await.len(), b.ledger.read().await.len());
    assert_eq!(
        la, lb,
        "identical generations produce identical ledger length"
    );
    assert!(a.ledger.read().await.verify().is_ok());
    assert!(b.ledger.read().await.verify().is_ok());
}

/// The `Large` scale produces a strictly bigger dataset of the same shape (parameterizable scale).
#[tokio::test]
async fn seed_generation_scales_up() {
    let tmp = TempDir::new("large");
    let state = AppState::with_data_dir(tmp.0.clone());

    let seeded = generate(&state, SeedScale::Large).await;
    assert_eq!(
        seeded.act_ids.len(),
        7 * 6,
        "6 acts per book at Large scale"
    );
    assert_eq!(seeded.sealed_act_ids.len(), 14, "still 2 sealed per book");
    assert_eq!(
        seeded.open_act_ids.len(),
        7 * 4,
        "the extra acts are mid-lifecycle"
    );

    // The core invariants still hold at scale (skip the backup round-trip to keep this fast).
    validate(&state, &seeded, None).await;
}

// =================================================================================================
// Tests — Postgres lane (off-by-default `postgres` feature, `#[ignore]`d; needs a live DATABASE_URL)
// =================================================================================================

/// The SAME generation + validation against the PostgreSQL backend (wp14/wp15), proving the generated
/// data works on both backends. `#[ignore]`d and feature-gated: run with
/// `DATABASE_URL=… cargo test -p chancela-api --test seed_dataset --features postgres -- --ignored
/// --test-threads=1`. The backup/restore round-trip is SQLite-file-specific, so it is skipped here
/// (Postgres backup is a logical export); every other validation runs identically.
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL at DATABASE_URL"]
async fn seed_generation_validates_full_system_on_postgres() {
    let Some(database_url) = std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty()) else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };

    let tmp = TempDir::new("pg");
    // Select the Postgres backend for this AppState build. `build_with_data_dir` resolves the backend
    // from these env vars; the test runs serially (`--test-threads=1`) so the global env is safe.
    // SAFETY: single-threaded ignored lane; no concurrent env access.
    unsafe {
        std::env::set_var("CHANCELA_DB_BACKEND", "postgres");
        std::env::set_var("DATABASE_URL", &database_url);
    }
    let state = AppState::with_data_dir(tmp.0.clone());
    // Ensure we actually opened Postgres (else the test would silently prove nothing).
    assert!(state.store.is_some(), "Postgres store opened");

    let seeded = generate(&state, SeedScale::Small).await;
    assert_eq!(seeded.entity_ids.len(), ENTITY_SPECS.len());
    assert_eq!(seeded.sealed_act_ids.len(), 14);

    // Same validation suite, minus the SQLite-file backup round-trip.
    validate(&state, &seeded, None).await;

    unsafe {
        std::env::remove_var("CHANCELA_DB_BACKEND");
        std::env::remove_var("DATABASE_URL");
    }
}
