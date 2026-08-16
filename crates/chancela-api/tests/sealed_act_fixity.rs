//! C1 — a sealed ata must be re-verified against the digest the ledger recorded.
//!
//! `seal_act_with_evidence` freezes a payload digest into the `act.sealed` event and copies it onto
//! the act. Nothing ever compared the two again: `Ledger::verify()` returned `Ok(n)`,
//! `integrity_report().healthy` was true, and the degraded gate stayed open over an ata whose
//! substance had been rewritten in the `acts` table. The chain only ever proved that *some* payload
//! with digest D was sealed at that position.
//!
//! These tests drive the real router and pin the three properties that close it:
//!   * `GET /v1/ledger/integrity` reports per-act fixity alongside the chain's own verdict;
//!   * an altered sealed ata is DETECTED — loudly, with the chain still reporting itself healthy,
//!     which is precisely the shape of the defect;
//!   * detection puts the instance in DEGRADED read-only mode rather than repairing anything.

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, router};
use chancela_core::act::ManualSignatureOriginalReference;
use chancela_core::rules::CscArt63RulePack;
use chancela_core::{
    Act, ActState, AgendaItem, Book, BookKind, Entity, EntityKind, MeetingChannel, Nipc,
    NumberingScheme, TermoDeAbertura, open_and_seal_book, seal_act,
};
use serde_json::{Value, json};
use time::macros::{date, time};
use tower::ServiceExt;

const TEST_PASSWORD: &str = "Teste-Forte7!X";

/// A temp data dir that seeds the role catalog (so the bootstrap Owner resolves real authority)
/// and is cleaned up on drop. Mirrors the `rbac_ledger_verify` harness.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("chancela-act-fixity-api-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).expect("temp dir created");
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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

fn get_req(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-chancela-session", token)
        .body(Body::empty())
        .expect("request builds")
}

/// Bootstrap the first (auth-exempt Owner) user and open a session; returns the token.
async fn bootstrap_owner(state: &AppState) -> String {
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
    let (status, session) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/session")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "user_id": id, "password": TEST_PASSWORD }).to_string(),
            ))
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "open session: {session}");
    session["token"].as_str().expect("token").to_owned()
}

/// Seal one ata into a fresh open book and load the entity/book/act/ledger into `state`, exactly
/// as the boot path would have rehydrated them from the store.
async fn seed_one_sealed_ata(state: &AppState) -> Act {
    let entity = Entity::new(
        "Encosto Estratégico, S.A.",
        Nipc::parse("503004642").expect("valid nipc"),
        "Lisboa",
        EntityKind::SociedadeAnonima,
    );
    let mut ledger = state.ledger.write().await;
    ledger.append(
        "amelia.marques",
        &entity.id.to_string(),
        "entity.created",
        None,
        b"entity",
    );
    let mut book = Book::new(entity.id, BookKind::AssembleiaGeral);
    let termo = TermoDeAbertura {
        entity_name: entity.name.clone(),
        entity_nipc: entity.nipc.to_string(),
        entity_seat: entity.seat.clone(),
        purpose: "livro de atas da assembleia geral".into(),
        numbering_scheme: NumberingScheme::Sequential,
        opening_date: date!(2026 - 01 - 15),
        required_signatories: vec!["Administrador".into()],
        required_signatory_records: Vec::new(),
        ..TermoDeAbertura::default()
    };
    open_and_seal_book(&mut book, &entity, termo, "amelia.marques", &mut ledger)
        .expect("book opens");

    let mut act = Act::draft(book.id, "Ata da AG anual", MeetingChannel::Physical);
    act.meeting_date = Some(date!(2026 - 03 - 30));
    act.meeting_time = Some(time!(10:00));
    act.place = Some("Sede social".into());
    act.mesa.presidente = Some("Ana Presidente".into());
    act.mesa.secretarios = vec!["Rui Secretário".into()];
    act.agenda = vec![AgendaItem {
        number: 1,
        text: "Aprovação das contas".into(),
    }];
    act.attendance_reference = Some("Lista de presenças".into());
    act.deliberations = "Aprovadas as contas do exercício.".into();
    for next in [
        ActState::Review,
        ActState::Convened,
        ActState::Deliberated,
        ActState::TextApproved,
        ActState::Signing,
    ] {
        act.advance_to(next).expect("advances");
    }
    seal_act(
        &mut book,
        &mut act,
        &entity,
        &CscArt63RulePack,
        "amelia.marques",
        false,
        Some(ManualSignatureOriginalReference {
            storage_reference: "Arquivo A / Pasta 2026 / Ata 1".to_owned(),
            custodian: None,
            note: None,
        }),
        &mut ledger,
    )
    .expect("act seals");
    drop(ledger);

    state.entities.write().await.insert(entity.id, entity);
    state.books.write().await.insert(book.id, book);
    state.acts.write().await.insert(act.id, act.clone());
    act
}

#[tokio::test]
async fn integrity_reports_sealed_act_fixity_alongside_the_chain() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.0.clone());
    let owner = bootstrap_owner(&state).await;
    let act = seed_one_sealed_ata(&state).await;

    let (status, integrity) = send(&state, get_req("/v1/ledger/integrity", &owner)).await;
    assert_eq!(status, StatusCode::OK, "{integrity}");
    let fixity = &integrity["act_fixity"];
    assert_eq!(fixity["healthy"], true, "{integrity}");
    assert_eq!(fixity["sealed_checked"], 1, "{integrity}");
    assert_eq!(fixity["verified"], 1, "{integrity}");
    assert_eq!(fixity["broken"], 0, "{integrity}");
    assert_eq!(fixity["unverifiable"], 0, "{integrity}");
    assert!(
        fixity["findings"].as_array().expect("findings").is_empty(),
        "{integrity}"
    );
    assert_eq!(integrity["degraded"], false, "{integrity}");
    assert_eq!(act.state, ActState::Sealed);
}

#[tokio::test]
async fn an_altered_sealed_ata_is_detected_while_the_chain_still_verifies() {
    // The regression test for the whole finding. Rewriting the deliberations of a sealed ata is
    // exactly what `UPDATE acts SET json = <edited deliberations>` does, and every ledger surface
    // stays green over it — which is why the fixity pass has to exist.
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.0.clone());
    let owner = bootstrap_owner(&state).await;
    let act = seed_one_sealed_ata(&state).await;

    {
        let mut acts = state.acts.write().await;
        let stored = acts.get_mut(&act.id).expect("the sealed act");
        stored.deliberations = "Rejeitadas as contas do exercício.".to_owned();
    }

    let (status, integrity) = send(&state, get_req("/v1/ledger/integrity", &owner)).await;
    assert_eq!(status, StatusCode::OK, "{integrity}");

    // The chain reports itself perfectly healthy. This is not a bug in the chain — it is the
    // limit of what a chain can attest, and the reason a separate fixity verdict is required.
    assert_eq!(
        integrity["healthy"], true,
        "the CHAIN must still verify — that is the point: {integrity}"
    );
    let (status, verify) = send(&state, get_req("/v1/ledger/verify", &owner)).await;
    assert_eq!(status, StatusCode::OK, "{verify}");
    assert_eq!(verify["valid"], true, "{verify}");

    // …and the act fixity does not.
    let fixity = &integrity["act_fixity"];
    assert_eq!(fixity["healthy"], false, "{integrity}");
    assert_eq!(fixity["broken"], 1, "{integrity}");
    assert_eq!(fixity["verified"], 0, "{integrity}");
    let findings = fixity["findings"].as_array().expect("findings");
    assert_eq!(findings.len(), 1, "{integrity}");
    assert_eq!(findings[0]["act_id"], act.id.to_string(), "{integrity}");
    assert_eq!(findings[0]["fixity"]["verdict"], "mismatch", "{integrity}");
    assert_eq!(
        findings[0]["fixity"]["expected"],
        Value::String(hex(&act.payload_digest.expect("frozen digest"))),
        "the finding must name the digest the ledger recorded: {integrity}"
    );
    assert_ne!(
        findings[0]["fixity"]["actual"], findings[0]["fixity"]["expected"],
        "{integrity}"
    );
}

#[tokio::test]
async fn altering_a_sealed_ata_and_its_own_frozen_digest_together_is_detected() {
    // **The C1 attack, through the real router.**
    //
    // The test above edits the deliberations and nothing else. It passed against a check that
    // compared the act to `Act::payload_digest` — a field of the very same row, unconditionally
    // present and unconditionally writable beside the content it was meant to bind. Extend the edit
    // to rewrite that field too and the row is internally consistent: every fixity surface returned
    // `Verified`, the degraded gate stayed open, and a generated certidão would have recited the
    // attacker's digest as its own proof of fixity.
    //
    // The authoritative bytes were always present — the `act.sealed` event, inside a chain
    // `Ledger::verify()` protects, named by `Act::seal_event_seq`. They simply had no reader.
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.0.clone());
    let owner = bootstrap_owner(&state).await;
    let act = seed_one_sealed_ata(&state).await;

    let forged_digest = {
        let mut acts = state.acts.write().await;
        let stored = acts.get_mut(&act.id).expect("the sealed act");
        stored.deliberations = "Rejeitadas as contas do exercício.".to_owned();
        // The extra clause of the one `UPDATE`.
        stored.payload_digest = chancela_core::sealed_act_digest(stored);
        assert_ne!(
            stored.payload_digest, act.payload_digest,
            "the attack rewrote the row's frozen digest"
        );
        stored.payload_digest.expect("the forged digest")
    };

    let (status, integrity) = send(&state, get_req("/v1/ledger/integrity", &owner)).await;
    assert_eq!(status, StatusCode::OK, "{integrity}");

    // The chain still verifies — nothing was done to it, and nothing needed to be.
    assert_eq!(integrity["healthy"], true, "{integrity}");
    let (status, verify) = send(&state, get_req("/v1/ledger/verify", &owner)).await;
    assert_eq!(status, StatusCode::OK, "{verify}");
    assert_eq!(verify["valid"], true, "{verify}");

    // …and the fixity verdict, now anchored to the ledger rather than to the row, does not.
    let fixity = &integrity["act_fixity"];
    assert_eq!(fixity["healthy"], false, "{integrity}");
    assert_eq!(fixity["broken"], 1, "{integrity}");
    assert_eq!(fixity["verified"], 0, "{integrity}");
    assert_eq!(fixity["unverifiable"], 0, "{integrity}");
    let findings = fixity["findings"].as_array().expect("findings");
    assert_eq!(findings.len(), 1, "{integrity}");
    assert_eq!(findings[0]["act_id"], act.id.to_string(), "{integrity}");
    assert_eq!(
        findings[0]["fixity"]["verdict"], "ledger_anchor_mismatch",
        "{integrity}"
    );
    assert_eq!(
        findings[0]["fixity"]["ledger"],
        Value::String(hex(&act
            .payload_digest
            .expect("the original frozen digest"))),
        "the finding must name the digest the LEDGER froze: {integrity}"
    );
    assert_eq!(
        findings[0]["fixity"]["row"],
        Value::String(hex(&forged_digest)),
        "…and the digest the row now claims: {integrity}"
    );
    assert_eq!(
        findings[0]["fixity"]["recomputed"], findings[0]["fixity"]["row"],
        "content and row digest moved together: {integrity}"
    );

    // Detection is the degraded gate, same as any other alteration.
    assert_eq!(integrity["degraded"], true, "{integrity}");
    assert!(*state.degraded.read().await, "the gate must be down");
}

#[tokio::test]
async fn deleting_a_sealed_atas_frozen_digest_is_broken_not_merely_counted() {
    // C2 on the live surface. `payload_digest: null` used to downgrade the verdict to
    // `Unverifiable`, whose arm incremented a counter and left `healthy == true` — so deleting the
    // one field that could convict an edited ata was strictly better for an attacker than leaving
    // it in place. The leniency it borrowed belongs to `seal_metadata` (genuinely optional,
    // genuinely absent on old rows) and never applied to this field.
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.0.clone());
    let owner = bootstrap_owner(&state).await;
    let act = seed_one_sealed_ata(&state).await;

    {
        let mut acts = state.acts.write().await;
        let stored = acts.get_mut(&act.id).expect("the sealed act");
        stored.deliberations = "Rejeitadas as contas do exercício.".to_owned();
        stored.payload_digest = None;
    }

    let (status, integrity) = send(&state, get_req("/v1/ledger/integrity", &owner)).await;
    assert_eq!(status, StatusCode::OK, "{integrity}");
    let fixity = &integrity["act_fixity"];
    assert_eq!(fixity["healthy"], false, "{integrity}");
    assert_eq!(fixity["broken"], 1, "{integrity}");
    assert_eq!(
        fixity["unverifiable"], 0,
        "a missing frozen digest is an alteration, not an unanswerable question: {integrity}"
    );
    assert_eq!(
        fixity["findings"][0]["fixity"]["verdict"], "missing_payload_digest",
        "{integrity}"
    );
    assert_eq!(integrity["degraded"], true, "{integrity}");
}

#[tokio::test]
async fn detecting_an_altered_sealed_ata_forces_read_only_mode() {
    // Detection must fail LOUD and read-only: no auto-repair, no silent log line. The degraded
    // gate is the same one a broken chain trips, so ordinary mutations get the honest-PT 503.
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.0.clone());
    let owner = bootstrap_owner(&state).await;
    let act = seed_one_sealed_ata(&state).await;
    assert!(!*state.degraded.read().await);

    {
        let mut acts = state.acts.write().await;
        acts.get_mut(&act.id).expect("the sealed act").title = "Ata adulterada".to_owned();
    }

    let (status, integrity) = send(&state, get_req("/v1/ledger/integrity", &owner)).await;
    assert_eq!(status, StatusCode::OK, "{integrity}");
    assert_eq!(integrity["act_fixity"]["healthy"], false, "{integrity}");
    assert_eq!(integrity["degraded"], true, "{integrity}");
    assert!(*state.degraded.read().await, "the gate must be down");

    // An ordinary mutation is now refused, read-only.
    let (status, refusal) = send(
        &state,
        Request::builder()
            .method("POST")
            .uri("/v1/entities")
            .header("content-type", "application/json")
            .header("x-chancela-session", &owner)
            .body(Body::from(
                json!({ "name": "Encosto Estratégico Lda", "nipc": "503004642", "seat": "Lisboa",
                        "kind": "SociedadeQuotas" })
                .to_string(),
            ))
            .expect("request builds"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "an altered sealed ata must force read-only: {refusal}"
    );
    assert_eq!(refusal["read_only"], true, "{refusal}");

    // Nothing was repaired or re-sealed: the altered content and the frozen digest are both
    // exactly as they were left.
    let acts = state.acts.read().await;
    let stored = acts.get(&act.id).expect("the sealed act");
    assert_eq!(stored.title, "Ata adulterada");
    assert_eq!(stored.payload_digest, act.payload_digest);
}

#[tokio::test]
async fn renumbering_a_sealed_ata_is_detected() {
    // C7: the sequential number used to be bound by no digest at all — it survived only inside the
    // ledger justification string, which is not hashed.
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.0.clone());
    let owner = bootstrap_owner(&state).await;
    let act = seed_one_sealed_ata(&state).await;
    assert_eq!(act.ata_number, Some(1));

    {
        let mut acts = state.acts.write().await;
        acts.get_mut(&act.id).expect("the sealed act").ata_number = Some(42);
    }

    let (status, integrity) = send(&state, get_req("/v1/ledger/integrity", &owner)).await;
    assert_eq!(status, StatusCode::OK, "{integrity}");
    assert_eq!(integrity["healthy"], true, "the chain still verifies");
    assert_eq!(integrity["act_fixity"]["healthy"], false, "{integrity}");
    let findings = integrity["act_fixity"]["findings"]
        .as_array()
        .expect("findings");
    assert_eq!(
        findings[0]["fixity"]["verdict"], "ata_number_mismatch",
        "{integrity}"
    );
    assert_eq!(findings[0]["fixity"]["sealed"], 1, "{integrity}");
    assert_eq!(findings[0]["fixity"]["stored"], 42, "{integrity}");
}

fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}
