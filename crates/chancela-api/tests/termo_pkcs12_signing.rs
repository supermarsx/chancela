//! Real cryptographic PKCS#12 PAdES signing of the termo de abertura (t41-e2).
//!
//! Proves the termo produces *genuine* per-slot PAdES signatures — not the completion-reference
//! placeholder — by driving the two-phase abertura lifecycle over a store-backed state and signing
//! each required slot with a real, in-process PFX (no checked-in keys, no network). The signatures
//! must be recorded per slot in the `instrument_signatures` history and must validate as PAdES. Each
//! signatory independently signs the SAME frozen snapshot (parallel co-signature — `chancela-pades`
//! phase-1 holds one signature per PDF), so each per-slot row extends the snapshot byte-for-byte.
//!
//! Scope note (t41-e2a): this exercises the PKCS#12 real-signing leg. Flipping the fail-closed
//! `open` gate live end-to-end (unifying the gate subject + preserving the signed bytes at open) is
//! t41-e3; the full security matrix is t41-e4. CMD/CSC two-phase real signing is t41-e2b.

mod common;

use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration as StdDuration;

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use der::Encode;
use der::asn1::{Any, BitString, ObjectIdentifier};
use p12::PFX;
use rsa::pkcs8::EncodePrivateKey;
use serde_json::{Value, json};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use tower::ServiceExt;
use uuid::Uuid;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog, Scope};
use chancela_core::ActId;
use chancela_pades::validate_pdf_signature;
use time::format_description::well_known::Rfc3339;

use common::{TEST_PASSWORD, password_hash};

const PFX_PASSWORD: &str = "correct horse battery staple";
const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// The typed phrases `ConfirmationAction::TermoAberturaOpen` and `TermoEncerramentoClose` carry, both
/// being floored at `ConfirmWithReauthAndPhrase`. **Fixed and deliberately non-localised**: they are
/// tokens to transcribe, not sentences to read, so they never come from a locale catalog. Spelling
/// them byte-exact here pins the contract a real client must reproduce.
const OPEN_PHRASE: &str = "ABRIR LIVRO";
const CLOSE_PHRASE: &str = "ENCERRAR LIVRO";

/// A self-cleaning data directory so `AppState::with_data_dir` gets a real store.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("chancela-termo-pkcs12-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp data dir");
        Self(dir)
    }
}

impl Drop for TmpDir {
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
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

async fn send_bytes(state: &AppState, req: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let resp = router(state.clone())
        .oneshot(req)
        .await
        .expect("router responds");
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec();
    (status, headers, bytes)
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

async fn disable_timestamping(state: &AppState) {
    let mut settings = state.settings.write().await;
    settings.signing.tsa_url = None;
    settings.signing.tsa_providers.clear();
}

/// A store-backed state with local PKCS#12 signing enabled and timestamping off (no network).
async fn signing_state(tmp: &TmpDir) -> AppState {
    let mut state = AppState::with_data_dir(tmp.0.clone());
    state.local_signing = true;
    disable_timestamping(&state).await;
    state
}

async fn bootstrap(state: &AppState) -> String {
    *state.roles.write().await = RoleCatalog::seeded_defaults();
    let uid = UserId(Uuid::new_v4());
    let created_at = time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("created_at");
    let user = User {
        id: uid,
        username: "amelia.marques".to_owned(),
        display_name: "Amelia Marques".to_owned(),
        email: None,
        created_at,
        active: true,
        password_hash: Some(password_hash()),
        attestation_key: None,
        retired_attestation_keys: Vec::new(),
        totp: None,
        two_factor_required: false,
        force_password_change: false,
        secret_source: Default::default(),
        recovery_hash: None,
        role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        language: Default::default(),
    };
    state.users.write().await.insert(uid, user);
    let (status, session) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/session")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "user_id": uid.to_string(), "password": TEST_PASSWORD }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "open session: {session}");
    session["token"].as_str().expect("token").to_owned()
}

/// Seed an entity + a two-phase (`one_shot: false`) book with two required signatory slots frozen
/// for signing. Returns `(book_id, slot0_id, slot1_id)`.
async fn seed_frozen_termo(state: &AppState, token: &str) -> (String, String, String) {
    let (status, entity) = send(
        state,
        json_req(
            "POST",
            "/v1/entities",
            token,
            json!({ "name": "Encosto Estrategico, S.A.", "nipc": "503004642", "seat": "Lisboa", "kind": "SociedadeAnonima" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "entity: {entity}");
    let entity_id = entity["id"].as_str().unwrap().to_owned();

    let (status, book) = send(
        state,
        json_req(
            "POST",
            "/v1/books",
            token,
            json!({
                "entity_id": entity_id,
                "kind": "AssembleiaGeral",
                "purpose": "livro de atas da assembleia geral",
                "opening_date": "2026-01-15",
                "required_signatories": [],
                "one_shot": false,
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "book: {book}");
    let book_id = book["id"].as_str().unwrap().to_owned();

    let (status, termo) = send(
        state,
        json_req(
            "PATCH",
            &format!("/v1/books/{book_id}/termo/abertura"),
            token,
            json!({
                "signatories": [
                    {"name": "Amelia Marques", "capacity": "Manager", "order": 0},
                    {"name": "Bruno Secretario", "capacity": "Secretary", "order": 1},
                ],
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch signatories: {termo}");
    let slot0 = termo["signatories"][0]["id"].as_str().unwrap().to_owned();
    let slot1 = termo["signatories"][1]["id"].as_str().unwrap().to_owned();

    let (status, advanced) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/books/{book_id}/termo/abertura/advance"),
            token,
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "advance: {advanced}");
    assert_eq!(advanced["state"], "Signing");

    (book_id, slot0, slot1)
}

fn build_self_signed(cn: &str, serial: u8, spki: SubjectPublicKeyInfoOwned) -> Vec<u8> {
    let name = Name::from_str(&format!("CN={cn}")).expect("name");
    let validity = Validity::from_now(StdDuration::from_secs(365 * 24 * 3600)).expect("validity");
    let sig_alg = AlgorithmIdentifierOwned {
        oid: OID_SHA256_WITH_RSA,
        parameters: Some(Any::null()),
    };
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[serial]).expect("serial"),
        signature: sig_alg.clone(),
        issuer: name.clone(),
        validity,
        subject: name,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
    };
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(&[0u8; 256]).expect("bitstring"),
    };
    cert.to_der().expect("cert der")
}

/// A distinct in-process PFX per signatory (`cn`/`serial` differ so the leaf certs differ).
fn local_pfx(cn: &str, serial: u8, friendly_name: &str) -> Vec<u8> {
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("rsa keygen");
    let spki =
        SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(&key)).expect("rsa spki");
    let cert = build_self_signed(cn, serial, spki);
    let issuer_key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("issuer key");
    let issuer_spki = SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(&issuer_key))
        .expect("issuer spki");
    let issuer = build_self_signed(&format!("{cn} Issuer"), serial + 100, issuer_spki);
    let key_der = key.to_pkcs8_der().expect("rsa pkcs8");
    PFX::new_with_cas(
        &cert,
        key_der.as_bytes(),
        &[&issuer],
        PFX_PASSWORD,
        friendly_name,
    )
    .expect("pfx")
    .to_der()
}

fn pkcs12_sign_req(
    book_id: &str,
    token: &str,
    slot_id: &str,
    pfx: &[u8],
    passphrase: &str,
) -> Request<Body> {
    json_req(
        "POST",
        &format!("/v1/books/{book_id}/termo/abertura/sign/pkcs12"),
        token,
        json!({
            "slot_id": slot_id,
            "pkcs12_base64": B64.encode(pfx),
            "passphrase": passphrase,
        }),
    )
}

async fn instrument_signatures(
    state: &AppState,
    book_id: &str,
) -> Vec<(i64, Option<String>, Vec<u8>)> {
    let subject = ActId(Uuid::parse_str(book_id).expect("book uuid"));
    state
        .store
        .as_ref()
        .expect("store")
        .read_blocking_async(move |s| s.instrument_signatures_for_subject(subject))
        .await
        .expect("read history")
        .into_iter()
        .map(|row| (row.seq, row.slot_id, row.document.signed_pdf_bytes))
        .collect()
}

async fn snapshot_bytes(state: &AppState, book_id: &str) -> Vec<u8> {
    let subject = ActId(Uuid::parse_str(book_id).expect("book uuid"));
    state
        .store
        .as_ref()
        .expect("store")
        .read_blocking_async(move |s| s.document_for_act(subject))
        .await
        .expect("read snapshot")
        .expect("snapshot pinned at advance")
        .pdf_bytes
}

fn open_req(book_id: &str, token: &str, body: Value) -> Request<Body> {
    json_req(
        "POST",
        &format!("/v1/books/{book_id}/termo/abertura/open"),
        token,
        body,
    )
}

/// A **complete** `POST .../termo/abertura/open` body: the T3 confirmation proof the route demands
/// (the acting operator's step-up password + the exact typed phrase), plus the optional
/// numbering-scheme assertion for the one test that exercises it.
///
/// `bootstrap` gives the operator a real argon2 hash of [`TEST_PASSWORD`], so this proof genuinely
/// passes `require_step_up` rather than merely being present. Every test that wants to reach a gate
/// *after* the confirmation gate starts from here — the same shape
/// `cmd_test_signature.rs`'s `initiate_body` uses for `ASSINAR TESTE`.
fn open_body(numbering_scheme: Option<&str>) -> Value {
    let mut body = json!({
        "confirmation": {
            "reauth": { "password": TEST_PASSWORD },
            "confirm_phrase": OPEN_PHRASE,
        },
    });
    if let Some(scheme) = numbering_scheme {
        body["numbering_scheme"] = json!(scheme);
    }
    body
}

async fn ledger_events(state: &AppState, token: &str) -> Vec<Value> {
    let (status, body) = send(state, get_req("/v1/ledger/events", token)).await;
    assert_eq!(status, StatusCode::OK, "ledger events: {body}");
    body.as_array().cloned().unwrap_or_default()
}

/// Sign every required slot of a freshly-frozen 2-slot termo with a real, distinct PFX per slot.
async fn cosign_both_slots(state: &AppState, token: &str, book_id: &str, slot0: &str, slot1: &str) {
    let pfx0 = local_pfx("Amelia Marques", 1, "amelia");
    let (status, view) = send(
        state,
        pkcs12_sign_req(book_id, token, slot0, &pfx0, PFX_PASSWORD),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "sign slot 0: {view}");
    assert_eq!(view["signatories"][0]["pades_document_available"], true);
    assert!(
        view["signatories"][1]
            .get("pades_document_available")
            .is_none(),
        "the unsigned second slot must not advertise a PAdES artifact: {view}"
    );
    let pfx1 = local_pfx("Bruno Secretario", 2, "bruno");
    let (status, view) = send(
        state,
        pkcs12_sign_req(book_id, token, slot1, &pfx1, PFX_PASSWORD),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "sign slot 1: {view}");
    assert_eq!(view["signatories"][0]["pades_document_available"], true);
    assert_eq!(view["signatories"][1]["pades_document_available"], true);
}

#[tokio::test]
async fn genuinely_cosigned_termo_opens_and_preserves_the_signed_set() {
    // The end-to-end proof (t41-e3): a termo whose every required slot carries a REAL PAdES
    // signature opens the book, seals the termo, and preserves the SET of co-signature PDF/As —
    // without re-rendering (which would discard the signatures) and without merging (which would
    // invalidate them).
    let tmp = TmpDir::new();
    let state = signing_state(&tmp).await;
    let token = bootstrap(&state).await;
    let (book_id, slot0, slot1) = seed_frozen_termo(&state, &token).await;

    let snapshot = snapshot_bytes(&state, &book_id).await;
    let opening_subject = ActId(Uuid::parse_str(&book_id).expect("book uuid"));
    let opening_document = state
        .store
        .as_ref()
        .expect("store")
        .read_blocking_async(move |store| store.documents_for_act(opening_subject))
        .await
        .expect("read opening document history")
        .into_iter()
        .next()
        .expect("opening snapshot persisted at advance");
    assert_eq!(opening_document.pdf_bytes, snapshot);
    let opening_document_id = opening_document.id.clone();
    cosign_both_slots(&state, &token, &book_id, &slot0, &slot1).await;

    // Open now succeeds — the fail-closed gate sees the real per-slot signatures at ActId(book.id).
    let (status, view) = send(&state, open_req(&book_id, &token, open_body(None))).await;
    assert_eq!(status, StatusCode::OK, "open: {view}");
    assert_eq!(view["state"], "Open", "book is Open: {view}");

    // The termo is Sealed (not fake-sealed — it was really signed).
    let (_, termo) = send(
        &state,
        get_req(&format!("/v1/books/{book_id}/termo/abertura"), &token),
    )
    .await;
    assert_eq!(termo["state"], "Sealed", "termo Sealed: {termo}");

    // The genesis `book.opened` event is on the chain, plus the co-signature manifest binding the
    // signed set (a `document.generated` event committed atomically with the open). The API exposes
    // only the payload digest, so the manifest's structure is asserted at unit level; here the
    // observable proof is that both events landed in the open commit.
    let events = ledger_events(&state, &token).await;
    assert!(
        events.iter().any(|e| e["kind"] == "book.opened"),
        "book.opened emitted: {events:?}"
    );
    assert!(
        events.iter().any(|e| e["kind"] == "document.generated"),
        "co-signature manifest (document.generated) emitted at open: {events:?}"
    );

    // The SET of signed PDF/As is preserved intact (2 rows, each still a valid PAdES over the
    // snapshot) — the open neither dropped nor merged them.
    let history = instrument_signatures(&state, &book_id).await;
    assert_eq!(history.len(), 2, "both co-signatures preserved after open");
    validate_pdf_signature(&history[0].2).expect("preserved signatory 1 still validates");
    validate_pdf_signature(&history[1].2).expect("preserved signatory 2 still validates");

    // The book-scoped artifact routes expose the preserved base and each independently-verifiable
    // per-slot revision without inventing a merged "final" PDF.
    let (status, headers, downloaded_snapshot) = send_bytes(
        &state,
        get_req(
            &format!("/v1/books/{book_id}/termo/abertura/document"),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "private, no-store");
    assert_eq!(
        headers["content-disposition"],
        "attachment; filename=\"termo-de-abertura-base-sem-assinaturas.pdf\""
    );
    assert_eq!(downloaded_snapshot, snapshot);
    for (slot_id, expected) in [(&slot0, &history[0].2), (&slot1, &history[1].2)] {
        let (status, headers, downloaded) = send_bytes(
            &state,
            get_req(
                &format!("/v1/books/{book_id}/termo/abertura/signatures/{slot_id}"),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["cache-control"], "private, no-store");
        assert_eq!(headers["x-chancela-signature-slot-id"], slot_id.as_str());
        assert!(
            headers["content-disposition"]
                .to_str()
                .expect("safe disposition")
                .contains(slot_id),
            "the safe UUID slot id identifies the downloaded signed revision"
        );
        assert_eq!(&downloaded, expected);
        validate_pdf_signature(&downloaded).expect("downloaded co-signature validates");
    }

    // The preserved base document is the FROZEN SNAPSHOT (the exact bytes that were signed), NOT a
    // re-rendered unsigned document.
    assert_eq!(
        snapshot_bytes(&state, &book_id).await,
        snapshot,
        "the preserved base PDF/A is the frozen snapshot, byte-for-byte (not re-rendered)"
    );

    // A later legacy one-shot close also writes a book-owned document. It must remain the latest
    // artifact on the backwards-compatible act-shaped route without replacing the immutable
    // abertura base or either per-slot PAdES revision.
    let (status, closed) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/books/{book_id}/close"),
            &token,
            json!({
                "reason": "BookFull",
                "closing_date": "2026-06-30",
                "required_signatories": ["Administrador"],
                "one_shot": true,
                "confirmation": {
                    "reauth": { "password": TEST_PASSWORD },
                    "confirm_phrase": CLOSE_PHRASE,
                },
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "one-shot close: {closed}");
    assert_eq!(closed["state"], "Closed");

    let preserved_opening = state
        .store
        .as_ref()
        .expect("store")
        .read_blocking_async({
            let opening_document_id = opening_document_id.clone();
            move |store| store.document_by_id(&opening_document_id)
        })
        .await
        .expect("read opening document by immutable id")
        .expect("opening document survives close");
    assert_eq!(
        preserved_opening.id, opening_document_id,
        "closing does not replace the opening document identity"
    );
    assert_eq!(
        preserved_opening.pdf_bytes, snapshot,
        "closing does not replace the opening document bytes"
    );

    let (status, _, downloaded_after_close) = send_bytes(
        &state,
        get_req(
            &format!("/v1/books/{book_id}/termo/abertura/document"),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        downloaded_after_close, snapshot,
        "the stage-specific abertura route returns the original signed base after close"
    );
    for (slot_id, expected) in [(&slot0, &history[0].2), (&slot1, &history[1].2)] {
        let (status, _, downloaded) = send_bytes(
            &state,
            get_req(
                &format!("/v1/books/{book_id}/termo/abertura/signatures/{slot_id}"),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            &downloaded, expected,
            "one-shot close preserves the exact per-slot opening PAdES artifact"
        );
        validate_pdf_signature(&downloaded)
            .expect("opening co-signature still validates after one-shot close");
    }
}

#[tokio::test]
async fn partially_cosigned_termo_still_fails_closed() {
    // M of N required slots really signed (here 1 of 2) → open stays fail-closed and retriable.
    let tmp = TmpDir::new();
    let state = signing_state(&tmp).await;
    let token = bootstrap(&state).await;
    let (book_id, slot0, _slot1) = seed_frozen_termo(&state, &token).await;

    // Only slot 0 is genuinely signed.
    let pfx0 = local_pfx("Amelia Marques", 1, "amelia");
    let (status, _view) = send(
        &state,
        pkcs12_sign_req(&book_id, &token, &slot0, &pfx0, PFX_PASSWORD),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The proof is complete, so the request clears the confirmation gate and the 409 below can only
    // come from the evidentiary co-signature gate — not from a step-up refusal upstream of it.
    let (status, body) = send(&state, open_req(&book_id, &token, open_body(None))).await;
    assert_eq!(status, StatusCode::CONFLICT, "partial-sign open: {body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("not cryptographically signed"),
        "fail-closed reason: {body}"
    );

    // The book stays Created; no genesis event.
    let (_, book) = send(&state, get_req(&format!("/v1/books/{book_id}"), &token)).await;
    assert_eq!(book["state"], "Created");
    let events = ledger_events(&state, &token).await;
    assert!(
        !events.iter().any(|e| e["kind"] == "book.opened"),
        "no book.opened on a partially-signed termo: {events:?}"
    );
}

#[tokio::test]
async fn open_rejects_a_numbering_scheme_that_contradicts_the_signed_snapshot() {
    // The snapshot was frozen (and signed) under Sequential numbering; opening under a different
    // scheme would digest a projection that disagrees with the signed bytes → rejected, not coerced.
    let tmp = TmpDir::new();
    let state = signing_state(&tmp).await;
    let token = bootstrap(&state).await;
    let (book_id, slot0, slot1) = seed_frozen_termo(&state, &token).await;
    cosign_both_slots(&state, &token, &book_id, &slot0, &slot1).await;

    // The proof is complete, so the request clears the confirmation gate and the 422 below is the
    // scheme contradiction specifically — not a step-up refusal upstream of it.
    let (status, body) = send(
        &state,
        open_req(&book_id, &token, open_body(Some("LooseLeaf"))),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "scheme mismatch: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("contradict the signed document"),
        "the 422 names the scheme contradiction: {body}"
    );

    // The book stays Created and retriable under the correct (Sequential) scheme.
    let (_, book) = send(&state, get_req(&format!("/v1/books/{book_id}"), &token)).await;
    assert_eq!(book["state"], "Created");
    let (status, view) = send(&state, open_req(&book_id, &token, open_body(None))).await;
    assert_eq!(status, StatusCode::OK, "retry under Sequential: {view}");
    assert_eq!(view["state"], "Open");
}

#[tokio::test]
async fn open_without_a_complete_confirmation_proof_appends_no_genesis() {
    // The guard that would have caught t80's gap, at the level where the gap survived.
    // `termo_abertura.open` has been floored at `ConfirmWithReauthAndPhrase` (`ABRIR LIVRO`) since
    // t56-e0, but `require_confirmation` was called nowhere in the termo handlers until b3817fc0:
    // the dialog gathered a step-up proof the request never carried and the server never checked.
    // b3817fc0's own refusal tests live in the crate's `--lib` target; `--lib` is not the crate, so
    // this is the integration-target counterpart.
    //
    // The fixture is FULLY co-signed on purpose. Every refusal below is therefore the confirmation
    // gate and nothing else (the evidentiary gate would pass), and the last request proves the gate
    // is PASSABLE on the same fixture — so a 403 can never be scored for the wrong reason.
    let tmp = TmpDir::new();
    let state = signing_state(&tmp).await;
    let token = bootstrap(&state).await;
    let (book_id, slot0, slot1) = seed_frozen_termo(&state, &token).await;
    cosign_both_slots(&state, &token, &book_id, &slot0, &slot1).await;

    let refused = [
        (
            "no confirmation object at all (the pre-t80 body)",
            json!({}),
        ),
        (
            "step-up only, no phrase",
            json!({ "confirmation": { "reauth": { "password": TEST_PASSWORD } } }),
        ),
        (
            "the right phrase but no step-up",
            json!({ "confirmation": { "confirm_phrase": OPEN_PHRASE } }),
        ),
        (
            "the phrase in the wrong case — it is compared byte-exact",
            json!({
                "confirmation": {
                    "reauth": { "password": TEST_PASSWORD },
                    "confirm_phrase": "abrir livro",
                },
            }),
        ),
        (
            "the right phrase with the wrong password",
            json!({
                "confirmation": {
                    "reauth": { "password": "nao-e-a-palavra-passe" },
                    "confirm_phrase": OPEN_PHRASE,
                },
            }),
        ),
    ];

    for (label, body) in refused {
        let (status, response) = send(&state, open_req(&book_id, &token, body)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{label}: the confirmation gate must refuse the open with 403: {response}"
        );
        assert_ne!(
            status,
            StatusCode::UNAUTHORIZED,
            "{label}: a confirmation failure must never be a 401 — that signs the operator out"
        );

        // The gate runs before anything is loaded, sealed or appended, so the refusal leaves the
        // book `Created`, the termo `Signing`, and the hash chain without a genesis.
        let (_, book) = send(&state, get_req(&format!("/v1/books/{book_id}"), &token)).await;
        assert_eq!(book["state"], "Created", "{label}: book untouched: {book}");
        let (_, termo) = send(
            &state,
            get_req(&format!("/v1/books/{book_id}/termo/abertura"), &token),
        )
        .await;
        assert_eq!(
            termo["state"], "Signing",
            "{label}: termo not sealed: {termo}"
        );
        let events = ledger_events(&state, &token).await;
        assert!(
            !events.iter().any(|e| e["kind"] == "book.opened"),
            "{label}: no book.opened genesis on an unproven open: {events:?}"
        );
    }

    // Same fixture, complete proof: the gate is passable, so every 403 above was the missing proof
    // rather than a guard that can never be satisfied.
    let (status, view) = send(&state, open_req(&book_id, &token, open_body(None))).await;
    assert_eq!(status, StatusCode::OK, "the complete proof opens: {view}");
    assert_eq!(view["state"], "Open");
}

#[tokio::test]
async fn pkcs12_signs_every_termo_slot_with_real_parallel_pades() {
    // Model note: `chancela-pades` phase-1 holds exactly one signature per PDF (it rejects adding a
    // signature to an existing /AcroForm), so each required signatory independently signs the SAME
    // frozen snapshot (parallel co-signature). Each per-slot row is its own genuine single-signature
    // PAdES revision over the canonical termo PDF.
    let tmp = TmpDir::new();
    let state = signing_state(&tmp).await;
    let token = bootstrap(&state).await;
    let (book_id, slot0, slot1) = seed_frozen_termo(&state, &token).await;

    let snapshot = snapshot_bytes(&state, &book_id).await;
    assert!(
        snapshot.starts_with(b"%PDF-"),
        "the frozen snapshot is a PDF"
    );

    // Signatory 1 signs the frozen snapshot.
    let pfx0 = local_pfx("Amelia Marques", 1, "amelia");
    let (status, view) = send(
        &state,
        pkcs12_sign_req(&book_id, &token, &slot0, &pfx0, PFX_PASSWORD),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "sign slot 0: {view}");
    assert_eq!(view["signatories"][0]["signed"], true);
    assert_eq!(view["signatories"][1]["signed"], false);

    // Signatory 2 also signs the frozen snapshot (a distinct identity).
    let pfx1 = local_pfx("Bruno Secretario", 2, "bruno");
    let (status, view) = send(
        &state,
        pkcs12_sign_req(&book_id, &token, &slot1, &pfx1, PFX_PASSWORD),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "sign slot 1: {view}");
    assert_eq!(view["signatories"][0]["signed"], true);
    assert_eq!(view["signatories"][1]["signed"], true);

    // Two REAL per-slot signatures are recorded, in order, tagged with the right slot ids.
    let history = instrument_signatures(&state, &book_id).await;
    assert_eq!(
        history.len(),
        2,
        "one instrument_signatures row per signed slot"
    );
    assert_eq!(history[0].1.as_deref(), Some(slot0.as_str()));
    assert_eq!(history[1].1.as_deref(), Some(slot1.as_str()));
    assert!(
        history[0].0 < history[1].0,
        "collection order preserved in seq"
    );

    // Each recorded signature is a genuine PAdES signature over the termo PDF.
    validate_pdf_signature(&history[0].2).expect("signatory 1 PDF validates");
    validate_pdf_signature(&history[1].2).expect("signatory 2 PDF validates");

    // Parallel co-signature: EACH signed revision extends the SAME frozen snapshot byte-for-byte.
    assert!(
        history[0].2.starts_with(&snapshot),
        "signatory 1 extends the frozen snapshot byte-for-byte"
    );
    assert!(
        history[1].2.starts_with(&snapshot),
        "signatory 2 extends the frozen snapshot byte-for-byte"
    );
    // The two signed PDFs are distinct (different signers over the same snapshot).
    assert_ne!(
        history[0].2, history[1].2,
        "distinct signers produce distinct signed revisions"
    );

    // The passphrase never leaks into persisted evidence.
    assert!(!String::from_utf8_lossy(&history[1].2).contains(PFX_PASSWORD));
}

#[tokio::test]
async fn pkcs12_termo_sign_enforces_sequential_slot_order() {
    let tmp = TmpDir::new();
    let state = signing_state(&tmp).await;
    let token = bootstrap(&state).await;
    let (book_id, _slot0, slot1) = seed_frozen_termo(&state, &token).await;

    // Signing slot 1 before the earlier required slot 0 is refused BEFORE any signature is recorded.
    let pfx = local_pfx("Bruno Secretario", 2, "bruno");
    let (status, err) = send(
        &state,
        pkcs12_sign_req(&book_id, &token, &slot1, &pfx, PFX_PASSWORD),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "out-of-order sign: {err}");
    assert!(
        instrument_signatures(&state, &book_id).await.is_empty(),
        "no signature recorded on a rejected out-of-order sign"
    );
}

#[tokio::test]
async fn pkcs12_termo_sign_wrong_passphrase_leaves_no_signature() {
    let tmp = TmpDir::new();
    let state = signing_state(&tmp).await;
    let token = bootstrap(&state).await;
    let (book_id, slot0, _slot1) = seed_frozen_termo(&state, &token).await;

    let pfx = local_pfx("Amelia Marques", 1, "amelia");
    let (status, err) = send(
        &state,
        pkcs12_sign_req(&book_id, &token, &slot0, &pfx, "not the password"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "wrong passphrase: {err}"
    );
    assert!(!err.to_string().contains("not the password"));
    // t58: the client must be able to say "retype the passphrase" without reading the English
    // prose. A wrong passphrase and an unusable certificate are both `422`s on this endpoint and
    // are indistinguishable at the status tier.
    assert_eq!(err["code"], "pkcs12_password_incorrect", "{err}");
    assert!(
        instrument_signatures(&state, &book_id).await.is_empty(),
        "no signature recorded on a failed sign"
    );

    // And the slot stays unsigned (the failed crypto never marked it).
    let (_, termo) = send(
        &state,
        get_req(&format!("/v1/books/{book_id}/termo/abertura"), &token),
    )
    .await;
    assert_eq!(termo["signatories"][0]["signed"], false);
}

/// An unusable *upload* and an unusable *certificate* are different problems with different
/// remedies, so `pkcs12_termo_sign` must not report them under one code. Both are `422`s carrying an
/// English detail, so the status tier and the prose are the only other channels — and the prose is
/// exactly what t58 stopped clients reading.
#[tokio::test]
async fn pkcs12_termo_sign_separates_a_bad_upload_from_a_bad_certificate() {
    let tmp = TmpDir::new();
    let state = signing_state(&tmp).await;
    let token = bootstrap(&state).await;
    let (book_id, slot0, _slot1) = seed_frozen_termo(&state, &token).await;
    let path = format!("/v1/books/{book_id}/termo/abertura/sign/pkcs12");

    let malformed = json_req(
        "POST",
        &path,
        &token,
        json!({
            "slot_id": &slot0,
            "pkcs12_base64": "not base64 at all!!",
            "passphrase": PFX_PASSWORD,
        }),
    );
    let (status, err) = send(&state, malformed).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{err}");
    assert_eq!(err["code"], "invalid_base64_content", "{err}");

    let empty = json_req(
        "POST",
        &path,
        &token,
        json!({
            "slot_id": &slot0,
            "pkcs12_base64": "",
            "passphrase": PFX_PASSWORD,
        }),
    );
    let (status, err) = send(&state, empty).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{err}");
    assert_eq!(err["code"], "empty_content", "{err}");

    // A real PKCS#12 that simply is not signing material reports the certificate as the fault.
    let (status, err) = send(
        &state,
        pkcs12_sign_req(&book_id, &token, &slot0, b"not a pfx at all", PFX_PASSWORD),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{err}");
    assert_eq!(err["code"], "pkcs12_material_invalid", "{err}");

    assert!(
        instrument_signatures(&state, &book_id).await.is_empty(),
        "no signature recorded on any rejected upload"
    );
}

// --- termo de encerramento (two-phase CLOSE, t44) ------------------------------------------------

/// The encerramento signing subject is the encerramento instrument's OWN id (not the book id the
/// abertura uses), so its history/snapshot are read under that subject.
async fn instrument_signatures_for(
    state: &AppState,
    subject_id: &str,
) -> Vec<(i64, Option<String>, Vec<u8>)> {
    let subject = ActId(Uuid::parse_str(subject_id).expect("subject uuid"));
    state
        .store
        .as_ref()
        .expect("store")
        .read_blocking_async(move |s| s.instrument_signatures_for_subject(subject))
        .await
        .expect("read history")
        .into_iter()
        .map(|row| (row.seq, row.slot_id, row.document.signed_pdf_bytes))
        .collect()
}

async fn snapshot_bytes_for(state: &AppState, subject_id: &str) -> Vec<u8> {
    let subject = ActId(Uuid::parse_str(subject_id).expect("subject uuid"));
    state
        .store
        .as_ref()
        .expect("store")
        .read_blocking_async(move |s| s.document_for_act(subject))
        .await
        .expect("read snapshot")
        .expect("snapshot pinned at advance")
        .pdf_bytes
}

/// Create an entity + open a book in one step (one-shot), so it is `Open` and thus closeable.
async fn open_book_one_shot(state: &AppState, token: &str) -> String {
    let (status, entity) = send(
        state,
        json_req(
            "POST",
            "/v1/entities",
            token,
            json!({ "name": "Encosto Estrategico, S.A.", "nipc": "503004642", "seat": "Lisboa", "kind": "SociedadeAnonima" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "entity: {entity}");
    let entity_id = entity["id"].as_str().unwrap().to_owned();

    let (status, book) = send(
        state,
        json_req(
            "POST",
            "/v1/books",
            token,
            json!({
                "entity_id": entity_id,
                "kind": "AssembleiaGeral",
                "purpose": "livro de atas da assembleia geral",
                "opening_date": "2026-01-15",
                "required_signatories": ["Administrador"],
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "book: {book}");
    assert_eq!(book["state"], "Open");
    book["id"].as_str().unwrap().to_owned()
}

/// Two-phase close: draft a termo de encerramento for the open book, add two required signatory
/// slots, and freeze it for signing. Returns `(encerramento_termo_id, slot0_id, slot1_id)` — the
/// termo id is the encerramento signing subject.
async fn seed_frozen_encerramento(
    state: &AppState,
    token: &str,
    book_id: &str,
) -> (String, String, String) {
    let (status, view) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/books/{book_id}/close"),
            token,
            json!({
                "reason": "BookFull",
                "closing_date": "2026-06-30",
                "required_signatories": [],
                "one_shot": false,
                // `book.close` guards BOTH arms of the route, the two-phase draft included: minting
                // the encerramento is what commits the book to closing.
                "confirmation": {
                    "reauth": { "password": TEST_PASSWORD },
                    "confirm_phrase": CLOSE_PHRASE,
                },
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "two-phase close draft: {view}");
    assert_eq!(view["state"], "Open", "book stays Open until close: {view}");

    let (status, termo) = send(
        state,
        get_req(&format!("/v1/books/{book_id}/termo/encerramento"), token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get encerramento: {termo}");
    let termo_id = termo["id"].as_str().unwrap().to_owned();

    let (status, termo) = send(
        state,
        json_req(
            "PATCH",
            &format!("/v1/books/{book_id}/termo/encerramento"),
            token,
            json!({
                "signatories": [
                    {"name": "Amelia Marques", "capacity": "Manager", "order": 0},
                    {"name": "Bruno Secretario", "capacity": "Secretary", "order": 1},
                ],
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch signatories: {termo}");
    let slot0 = termo["signatories"][0]["id"].as_str().unwrap().to_owned();
    let slot1 = termo["signatories"][1]["id"].as_str().unwrap().to_owned();

    let (status, advanced) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/books/{book_id}/termo/encerramento/advance"),
            token,
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "advance: {advanced}");
    assert_eq!(advanced["state"], "Signing");

    (termo_id, slot0, slot1)
}

fn pkcs12_sign_encerramento_req(
    book_id: &str,
    token: &str,
    slot_id: &str,
    pfx: &[u8],
    passphrase: &str,
) -> Request<Body> {
    json_req(
        "POST",
        &format!("/v1/books/{book_id}/termo/encerramento/sign/pkcs12"),
        token,
        json!({
            "slot_id": slot_id,
            "pkcs12_base64": B64.encode(pfx),
            "passphrase": passphrase,
        }),
    )
}

fn close_req(book_id: &str, token: &str, body: Value) -> Request<Body> {
    json_req(
        "POST",
        &format!("/v1/books/{book_id}/termo/encerramento/close"),
        token,
        body,
    )
}

/// A **complete** `POST .../termo/encerramento/close` body. Unlike opening, closing carries no
/// numbering scheme — the book's numbering was fixed at its abertura — so the T3 proof is the whole
/// body. See [`open_body`] for why this proof actually passes rather than merely being present.
fn close_body() -> Value {
    json!({
        "confirmation": {
            "reauth": { "password": TEST_PASSWORD },
            "confirm_phrase": CLOSE_PHRASE,
        },
    })
}

#[tokio::test]
async fn genuinely_cosigned_encerramento_closes_and_preserves_the_signed_set() {
    // The CLOSE mirror of `genuinely_cosigned_termo_opens...`: a termo de encerramento whose every
    // required slot carries a REAL PAdES signature closes the book, seals the termo, and preserves
    // the SET of co-signature PDF/As — without re-rendering or merging them.
    let tmp = TmpDir::new();
    let state = signing_state(&tmp).await;
    let token = bootstrap(&state).await;
    let book_id = open_book_one_shot(&state, &token).await;
    let opening_subject = ActId(Uuid::parse_str(&book_id).expect("book uuid"));
    let opening_document = state
        .store
        .as_ref()
        .expect("store")
        .read_blocking_async(move |store| store.documents_for_act(opening_subject))
        .await
        .expect("read opening document history")
        .into_iter()
        .next()
        .expect("one-shot opening document");
    let opening_document_id = opening_document.id.clone();
    let opening_pdf = opening_document.pdf_bytes.clone();
    let (termo_id, slot0, slot1) = seed_frozen_encerramento(&state, &token, &book_id).await;

    let snapshot = snapshot_bytes_for(&state, &termo_id).await;
    assert!(
        snapshot.starts_with(b"%PDF-"),
        "the frozen encerramento snapshot is a PDF"
    );

    // Co-sign both required slots with real, distinct PFX identities over the encerramento subject.
    let pfx0 = local_pfx("Amelia Marques", 1, "amelia");
    let (status, view) = send(
        &state,
        pkcs12_sign_encerramento_req(&book_id, &token, &slot0, &pfx0, PFX_PASSWORD),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "sign encerramento slot 0: {view}");
    let pfx1 = local_pfx("Bruno Secretario", 2, "bruno");
    let (status, view) = send(
        &state,
        pkcs12_sign_encerramento_req(&book_id, &token, &slot1, &pfx1, PFX_PASSWORD),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "sign encerramento slot 1: {view}");

    // Close now succeeds — the fail-closed gate sees the real per-slot signatures.
    let (status, view) = send(&state, close_req(&book_id, &token, close_body())).await;
    assert_eq!(status, StatusCode::OK, "close: {view}");
    assert_eq!(view["state"], "Closed", "book is Closed: {view}");

    // The termo is Sealed (really signed, not fake-sealed).
    let (_, termo) = send(
        &state,
        get_req(&format!("/v1/books/{book_id}/termo/encerramento"), &token),
    )
    .await;
    assert_eq!(termo["state"], "Sealed", "termo Sealed: {termo}");

    // `book.closed` landed, plus a co-signature manifest (`document.generated`) in the close commit.
    // (The one-shot open already emitted one `document.generated` for the abertura, so the close's
    // manifest brings the count to at least two.)
    let events = ledger_events(&state, &token).await;
    assert!(
        events.iter().any(|e| e["kind"] == "book.closed"),
        "book.closed emitted: {events:?}"
    );
    let doc_events = events
        .iter()
        .filter(|e| e["kind"] == "document.generated")
        .count();
    assert!(
        doc_events >= 2,
        "close added the encerramento co-signature manifest: {events:?}"
    );

    // The SET of signed PDF/As is preserved intact (2 rows, each a valid PAdES over the snapshot).
    let history = instrument_signatures_for(&state, &termo_id).await;
    assert_eq!(
        history.len(),
        2,
        "both encerramento co-signatures preserved after close"
    );
    validate_pdf_signature(&history[0].2).expect("preserved signatory 1 still validates");
    validate_pdf_signature(&history[1].2).expect("preserved signatory 2 still validates");

    // The preserved base document is the FROZEN SNAPSHOT (the exact bytes signed), not re-rendered.
    assert_eq!(
        snapshot_bytes_for(&state, &termo_id).await,
        snapshot,
        "the preserved base PDF/A is the frozen encerramento snapshot, byte-for-byte"
    );

    // Subject disjointness: the abertura's preserved document (under the BOOK id) is a distinct
    // document from the encerramento snapshot (under the TERMO id) — the two termos never collide.
    let abertura_doc = snapshot_bytes(&state, &book_id).await;
    assert_ne!(
        abertura_doc, snapshot,
        "the abertura and encerramento snapshots are distinct, disjoint documents"
    );
    let (status, _, downloaded_opening) = send_bytes(
        &state,
        get_req(
            &format!("/v1/books/{book_id}/termo/abertura/document"),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        downloaded_opening, opening_pdf,
        "two-phase close leaves the opening base byte-for-byte unchanged"
    );
    let preserved_opening = state
        .store
        .as_ref()
        .expect("store")
        .read_blocking_async({
            let opening_document_id = opening_document_id.clone();
            move |store| store.document_by_id(&opening_document_id)
        })
        .await
        .expect("read opening document by immutable id")
        .expect("opening document survives two-phase close");
    assert_eq!(preserved_opening.id, opening_document_id);
    assert_eq!(preserved_opening.pdf_bytes, opening_pdf);
}

#[tokio::test]
async fn partially_cosigned_encerramento_still_fails_closed() {
    // M of N required slots really signed (here 1 of 2) → close stays fail-closed and retriable; the
    // book is NEVER auto-closed on a partially-signed termo.
    let tmp = TmpDir::new();
    let state = signing_state(&tmp).await;
    let token = bootstrap(&state).await;
    let book_id = open_book_one_shot(&state, &token).await;
    let (_termo_id, slot0, _slot1) = seed_frozen_encerramento(&state, &token, &book_id).await;

    let pfx0 = local_pfx("Amelia Marques", 1, "amelia");
    let (status, _view) = send(
        &state,
        pkcs12_sign_encerramento_req(&book_id, &token, &slot0, &pfx0, PFX_PASSWORD),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The proof is complete, so the request clears the confirmation gate and the 409 below can only
    // come from the evidentiary co-signature gate — not from a step-up refusal upstream of it.
    let (status, body) = send(&state, close_req(&book_id, &token, close_body())).await;
    assert_eq!(status, StatusCode::CONFLICT, "partial-sign close: {body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("not cryptographically signed"),
        "fail-closed reason: {body}"
    );

    // The book stays Open; no `book.closed`.
    let (_, book) = send(&state, get_req(&format!("/v1/books/{book_id}"), &token)).await;
    assert_eq!(book["state"], "Open");
    let events = ledger_events(&state, &token).await;
    assert!(
        !events.iter().any(|e| e["kind"] == "book.closed"),
        "no book.closed on a partially-signed encerramento: {events:?}"
    );
}

#[tokio::test]
async fn close_without_a_complete_confirmation_proof_seals_no_termo() {
    // The CLOSE mirror of `open_without_a_complete_confirmation_proof_appends_no_genesis`.
    // `termo_encerramento.close` is floored at `ConfirmWithReauthAndPhrase` (`ENCERRAR LIVRO`)
    // because closing is irreversible in fact — `chancela_core::book` has no `Closed -> Open`
    // transition — and, like `open`, it declared that floor long before any handler checked it.
    //
    // Fully co-signed fixture for the same reason: the evidentiary gate would pass, so every
    // refusal below is the confirmation gate, and the final request proves it is passable.
    let tmp = TmpDir::new();
    let state = signing_state(&tmp).await;
    let token = bootstrap(&state).await;
    let book_id = open_book_one_shot(&state, &token).await;
    let (_termo_id, slot0, slot1) = seed_frozen_encerramento(&state, &token, &book_id).await;

    let pfx0 = local_pfx("Amelia Marques", 1, "amelia");
    let (status, view) = send(
        &state,
        pkcs12_sign_encerramento_req(&book_id, &token, &slot0, &pfx0, PFX_PASSWORD),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "sign encerramento slot 0: {view}");
    let pfx1 = local_pfx("Bruno Secretario", 2, "bruno");
    let (status, view) = send(
        &state,
        pkcs12_sign_encerramento_req(&book_id, &token, &slot1, &pfx1, PFX_PASSWORD),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "sign encerramento slot 1: {view}");

    let refused = [
        (
            "no confirmation object at all (the pre-t80 body)",
            json!({}),
        ),
        (
            "step-up only, no phrase",
            json!({ "confirmation": { "reauth": { "password": TEST_PASSWORD } } }),
        ),
        (
            "the right phrase but no step-up",
            json!({ "confirmation": { "confirm_phrase": CLOSE_PHRASE } }),
        ),
        (
            "the phrase in the wrong case — it is compared byte-exact",
            json!({
                "confirmation": {
                    "reauth": { "password": TEST_PASSWORD },
                    "confirm_phrase": "encerrar livro",
                },
            }),
        ),
        (
            "the abertura phrase on the close route",
            json!({
                "confirmation": {
                    "reauth": { "password": TEST_PASSWORD },
                    "confirm_phrase": OPEN_PHRASE,
                },
            }),
        ),
    ];

    for (label, body) in refused {
        let (status, response) = send(&state, close_req(&book_id, &token, body)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{label}: the confirmation gate must refuse the close with 403: {response}"
        );
        assert_ne!(
            status,
            StatusCode::UNAUTHORIZED,
            "{label}: a confirmation failure must never be a 401 — that signs the operator out"
        );

        // The book stays Open, the encerramento stays Signing, and nothing was closed.
        let (_, book) = send(&state, get_req(&format!("/v1/books/{book_id}"), &token)).await;
        assert_eq!(book["state"], "Open", "{label}: book still Open: {book}");
        let (_, termo) = send(
            &state,
            get_req(&format!("/v1/books/{book_id}/termo/encerramento"), &token),
        )
        .await;
        assert_eq!(
            termo["state"], "Signing",
            "{label}: encerramento not sealed: {termo}"
        );
        let events = ledger_events(&state, &token).await;
        assert!(
            !events.iter().any(|e| e["kind"] == "book.closed"),
            "{label}: no book.closed on an unproven close: {events:?}"
        );
    }

    // Same fixture, complete proof: passable, so the refusals above are the missing proof.
    let (status, view) = send(&state, close_req(&book_id, &token, close_body())).await;
    assert_eq!(status, StatusCode::OK, "the complete proof closes: {view}");
    assert_eq!(view["state"], "Closed");
}

#[tokio::test]
async fn pkcs12_termo_sign_requires_local_signing_capability() {
    let tmp = TmpDir::new();
    // Store-backed but WITHOUT local signing enabled.
    let state = AppState::with_data_dir(tmp.0.clone());
    disable_timestamping(&state).await;
    let token = bootstrap(&state).await;
    let (book_id, slot0, _slot1) = seed_frozen_termo(&state, &token).await;

    let pfx = local_pfx("Amelia Marques", 1, "amelia");
    let (status, err) = send(
        &state,
        pkcs12_sign_req(&book_id, &token, &slot0, &pfx, PFX_PASSWORD),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "local-signing gate: {err}");
    assert!(
        instrument_signatures(&state, &book_id).await.is_empty(),
        "no signature recorded when local signing is disabled"
    );
}

// =================================================================================================
// `POST /v1/books/{id}/close` — the THIRD route in this family whose declared floor was never checked
// =================================================================================================
//
// `ConfirmationAction::BookClose` has guarded the book-close route in `confirmation::ROUTE_GUARD`
// since t56-e0, floored at `ConfirmWithReauthAndPhrase` with the phrase `ENCERRAR LIVRO` — and,
// exactly as with `termo_abertura.open` and `termo_encerramento.close` before b3817fc0, no handler
// ever called `require_confirmation` for it. A compiler probe (a dummy parameter on
// `require_confirmation`, which turns every real invocation into an `E0061`) put the true call-site
// set at seven, none of them in `books.rs`: the registry declared a step-up the route did not
// verify, so any client could close a book — sealing a termo de encerramento that asserts the book's
// ata count — with no proof at all.
//
// These tests live beside the abertura/encerramento pair above because they need the same fixture
// machinery (a real PFX per slot, real PAdES co-signature) and assert the same way: the STATE is the
// assertion, never the status code alone. A `403` that had nonetheless closed the book would pass a
// status-only test, so every refusal below re-reads the book, the encerramento and the hash chain.

/// `POST /v1/books/{id}/close` — the book-lifecycle route the registry guards with
/// `ConfirmationAction::BookClose`.
///
/// Deliberately NOT [`close_req`], which drives the two-phase *seal* at
/// `.../termo/encerramento/close`. The two routes carry the same phrase and are one step apart in
/// the same flow; separate builders stop a test from silently proving the already-fixed sibling.
fn book_close_req(book_id: &str, token: &str, body: Value) -> Request<Body> {
    json_req("POST", &format!("/v1/books/{book_id}/close"), token, body)
}

/// A valid close body with **no confirmation proof** — byte-for-byte the request the shipped client
/// sent before this gate landed.
///
/// `reason`, `closing_date` and `required_signatories` have no serde defaults, so they must be
/// present or the request dies at deserialisation with a `422` and never reaches the gate at all.
/// Every refusal case below therefore starts from a fully-formed, otherwise-acceptable request: the
/// missing proof is the only thing wrong with it.
///
/// The signatory is **structured** (a name plus a capacity from the art. 31.º n.º 2 allow-list)
/// rather than a legacy label, because the two-phase arm rejects a bare string with a `422` — and a
/// case that 422s on its body would never reach the gate this file exists to test.
fn book_close_base(one_shot: bool) -> Value {
    json!({
        "reason": "BookFull",
        "closing_date": "2026-06-30",
        "required_signatories": [{ "name": "Amelia Marques", "capacity": "Manager" }],
        "one_shot": one_shot,
    })
}

/// [`book_close_base`] carrying an arbitrary `confirmation` value — the incomplete-proof cases.
fn book_close_with(one_shot: bool, confirmation: Value) -> Value {
    let mut body = book_close_base(one_shot);
    body["confirmation"] = confirmation;
    body
}

/// A **complete** close body. `bootstrap` gives the operator a real argon2 hash of [`TEST_PASSWORD`],
/// so this proof genuinely passes `require_step_up` rather than merely being present — which is what
/// lets the passable case below tell "the gate refused me" apart from "the gate can never be
/// satisfied". See [`open_body`].
fn book_close_body(one_shot: bool) -> Value {
    book_close_with(
        one_shot,
        json!({
            "reauth": { "password": TEST_PASSWORD },
            "confirm_phrase": CLOSE_PHRASE,
        }),
    )
}

/// An OPEN book whose termo de abertura was really co-signed and then sealed.
///
/// The fixture is fully co-signed **on purpose**: it leaves nothing evidentiary pending, so a `403`
/// from the close route can only be the confirmation gate and never some upstream check refusing for
/// its own reasons. A weaker fixture would let a refusal be scored for the wrong cause.
async fn open_book_via_cosigned_abertura(state: &AppState, token: &str) -> String {
    let (book_id, slot0, slot1) = seed_frozen_termo(state, token).await;
    cosign_both_slots(state, token, &book_id, &slot0, &slot1).await;
    let (status, view) = send(state, open_req(&book_id, token, open_body(None))).await;
    assert_eq!(status, StatusCode::OK, "open the fixture book: {view}");
    assert_eq!(view["state"], "Open");
    book_id
}

/// The incomplete proofs a real client can produce. Shared by both arms of the route so neither arm
/// is tested more weakly than the other. `None` means the `confirmation` key is absent entirely.
fn incomplete_close_proofs() -> [(&'static str, Option<Value>); 6] {
    [
        ("no confirmation key at all (the pre-fix client body)", None),
        (
            "step-up only, no phrase",
            Some(json!({ "reauth": { "password": TEST_PASSWORD } })),
        ),
        (
            "the right phrase but no step-up",
            Some(json!({ "confirm_phrase": CLOSE_PHRASE })),
        ),
        (
            "the phrase in the wrong case — it is compared byte-exact",
            Some(json!({
                "reauth": { "password": TEST_PASSWORD },
                "confirm_phrase": "encerrar livro",
            })),
        ),
        (
            "the abertura phrase on the close route",
            Some(json!({
                "reauth": { "password": TEST_PASSWORD },
                "confirm_phrase": OPEN_PHRASE,
            })),
        ),
        (
            "the right phrase with the wrong password",
            Some(json!({
                "reauth": { "password": "nao-e-a-palavra-passe" },
                "confirm_phrase": CLOSE_PHRASE,
            })),
        ),
    ]
}

#[tokio::test]
async fn one_shot_book_close_without_a_complete_confirmation_proof_closes_nothing() {
    // The one-shot arm is the consequential one: it seals a termo de encerramento asserting the
    // book's ata count and appends `book.closed` in a single commit. Before this gate it did all of
    // that on a request carrying no proof whatsoever.
    let tmp = TmpDir::new();
    let state = signing_state(&tmp).await;
    let token = bootstrap(&state).await;
    let book_id = open_book_via_cosigned_abertura(&state, &token).await;

    // The chain as it stands with the book merely Open. Every refusal must leave it exactly here —
    // a stronger assertion than "no `book.closed`", because it also catches a half-committed close
    // that appended a `document.generated` for the encerramento and then failed.
    let events_before = ledger_events(&state, &token).await;

    for (label, confirmation) in incomplete_close_proofs() {
        let body = match confirmation {
            Some(proof) => book_close_with(true, proof),
            None => book_close_base(true),
        };
        let (status, response) = send(&state, book_close_req(&book_id, &token, body)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{label}: the confirmation gate must refuse the close with 403: {response}"
        );
        assert_ne!(
            status,
            StatusCode::UNAUTHORIZED,
            "{label}: a confirmation failure must never be a 401 — that signs the operator out"
        );

        // THE BOOK IS UNTOUCHED — not merely "an error was returned".
        let (_, book) = send(&state, get_req(&format!("/v1/books/{book_id}"), &token)).await;
        assert_eq!(book["state"], "Open", "{label}: book still Open: {book}");
        assert!(
            book["closing_date"].is_null(),
            "{label}: a refused close records no closing date: {book}"
        );

        // NO TERMO WAS SEALED. The gate runs before the branch, so the one-shot arm minted nothing
        // and the two-phase draft the same route can create does not exist either.
        let (status, termo) = send(
            &state,
            get_req(&format!("/v1/books/{book_id}/termo/encerramento"), &token),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{label}: a refused close leaves no termo de encerramento behind: {termo}"
        );

        // THE CHAIN IS UNMOVED, and specifically free of `book.closed`.
        let events_after = ledger_events(&state, &token).await;
        assert_eq!(
            events_after, events_before,
            "{label}: a refused close appends nothing to the hash chain"
        );
        assert!(
            !events_after.iter().any(|e| e["kind"] == "book.closed"),
            "{label}: no book.closed on an unproven close: {events_after:?}"
        );
    }

    // Same fixture, complete proof: the gate is PASSABLE, so each 403 above was the missing proof
    // and not a guard that can never be satisfied.
    let (status, view) = send(
        &state,
        book_close_req(&book_id, &token, book_close_body(true)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the complete proof closes: {view}");
    assert_eq!(view["state"], "Closed");
    let events = ledger_events(&state, &token).await;
    assert!(
        events.iter().any(|e| e["kind"] == "book.closed"),
        "the proven close is the one that appends book.closed: {events:?}"
    );
}

#[tokio::test]
async fn two_phase_book_close_without_a_complete_confirmation_proof_mints_no_termo() {
    // The SAME route with `one_shot: false`. It appends nothing to the chain, which is exactly why
    // it could be dismissed as harmless — but it is the step that commits the book to closing, and
    // `RouteGuard::Actions` guards the ROUTE, not one of its arms. Gating only the one-shot arm
    // would leave the declared guard half-enforced, which is the defect this task exists to close.
    let tmp = TmpDir::new();
    let state = signing_state(&tmp).await;
    let token = bootstrap(&state).await;
    let book_id = open_book_via_cosigned_abertura(&state, &token).await;

    let events_before = ledger_events(&state, &token).await;

    for (label, confirmation) in incomplete_close_proofs() {
        let body = match confirmation {
            Some(proof) => book_close_with(false, proof),
            None => book_close_base(false),
        };
        let (status, response) = send(&state, book_close_req(&book_id, &token, body)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{label}: the two-phase draft is guarded too: {response}"
        );
        assert_ne!(
            status,
            StatusCode::UNAUTHORIZED,
            "{label}: a confirmation failure must never be a 401 — that signs the operator out"
        );

        // NOTHING WAS DRAFTED: no encerramento exists for the book to be closed through.
        let (status, termo) = send(
            &state,
            get_req(&format!("/v1/books/{book_id}/termo/encerramento"), &token),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{label}: a refused two-phase close mints no draft encerramento: {termo}"
        );
        let (_, book) = send(&state, get_req(&format!("/v1/books/{book_id}"), &token)).await;
        assert_eq!(book["state"], "Open", "{label}: book still Open: {book}");
        assert_eq!(
            ledger_events(&state, &token).await,
            events_before,
            "{label}: a refused two-phase close appends nothing to the hash chain"
        );
    }

    // Passable on the same fixture: the complete proof mints the Draft encerramento, and still
    // appends nothing to the chain (the two-phase contract).
    let (status, view) = send(
        &state,
        book_close_req(&book_id, &token, book_close_body(false)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the complete proof drafts: {view}");
    assert_eq!(
        view["state"], "Open",
        "the two-phase draft leaves the book Open: {view}"
    );
    let (status, termo) = send(
        &state,
        get_req(&format!("/v1/books/{book_id}/termo/encerramento"), &token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the draft encerramento exists: {termo}"
    );
    assert_eq!(termo["state"], "Draft");
    assert_eq!(
        ledger_events(&state, &token).await,
        events_before,
        "drafting a two-phase close still appends nothing to the hash chain"
    );
}
