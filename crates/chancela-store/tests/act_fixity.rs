//! C1 — the store load path must re-verify every sealed act against the digest its seal froze.
//!
//! `Ledger::verify()` proves the chain is internally consistent. It cannot prove that the row in
//! the `acts` table is still the payload whose digest the chain recorded, so an
//! `UPDATE acts SET json = <edited deliberations>` used to leave the chain verifying, the integrity
//! report healthy, and the degraded gate open over an altered ata.
//!
//! Everything here goes through **real persistence and raw SQL** — the exact operation an attacker
//! with database access performs — rather than mutating an in-memory struct.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chancela_core::act::ManualSignatureOriginalReference;
use chancela_core::rules::CscArt63RulePack;
use chancela_core::{
    Act, ActState, AgendaItem, Book, BookKind, Entity, EntityKind, MeetingChannel, Nipc,
    NumberingScheme, TermoDeAbertura, open_and_seal_book, seal_act, sealed_act_digest,
};
use chancela_ledger::Ledger;
use chancela_store::Store;
use chancela_store::recovery::{BundleManifest, CollisionPolicy, ImportVerdict};
use sha2::{Digest, Sha256};
use time::macros::{date, time};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique scratch directory under the OS temp dir, removed on drop.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "chancela-act-fixity-{}-{nanos}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn at() -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(1_770_000_000).expect("valid timestamp")
}

/// Seal one ata into a fresh open book and persist the entity, book, act and every ledger event.
fn seed_sealed_ata(store: &Store) -> Act {
    let entity = Entity::new(
        "Encosto Estratégico, S.A.",
        Nipc::parse("503004642").expect("valid nipc"),
        "Lisboa",
        EntityKind::SociedadeAnonima,
    );
    let mut ledger = Ledger::new();
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

    store
        .persist(|tx| {
            tx.upsert_entity(&entity)?;
            tx.upsert_book(&book)?;
            tx.upsert_act(&act)?;
            for event in ledger.events() {
                tx.append_event(event)?;
            }
            Ok(())
        })
        .expect("entity + book + act + events persist");
    act
}

/// Rewrite one JSON field of a stored act row, exactly as a database-level edit would.
fn edit_stored_act(dir: &Path, act: &Act, field: &str, value: &str) {
    let raw = rusqlite::Connection::open(dir.join("chancela.db")).expect("open raw");
    let json: String = raw
        .query_row(
            "SELECT json FROM acts WHERE id = ?1",
            rusqlite::params![act.id.to_string()],
            |row| row.get(0),
        )
        .expect("act row");
    let mut stored: serde_json::Value = serde_json::from_str(&json).expect("act json");
    stored[field] = serde_json::from_str(value).expect("replacement value");
    let changed = raw
        .execute(
            "UPDATE acts SET json = ?1 WHERE id = ?2",
            rusqlite::params![stored.to_string(), act.id.to_string()],
        )
        .expect("update");
    assert_eq!(changed, 1);
}

/// Read the stored act row back, mutate the deserialized [`Act`], and write it out again.
///
/// The database-level attacker's real tool: they hold the row, not a struct, and nothing stops them
/// rewriting any subset of its keys in one statement — including the ones that are supposed to be
/// the evidence. Returns the act as it now sits in the table.
fn rewrite_stored_act(dir: &Path, act: &Act, mutate: impl FnOnce(&mut Act)) -> Act {
    let raw = rusqlite::Connection::open(dir.join("chancela.db")).expect("open raw");
    let json: String = raw
        .query_row(
            "SELECT json FROM acts WHERE id = ?1",
            rusqlite::params![act.id.to_string()],
            |row| row.get(0),
        )
        .expect("act row");
    let mut stored: Act = serde_json::from_str(&json).expect("act json");
    mutate(&mut stored);
    let changed = raw
        .execute(
            "UPDATE acts SET json = ?1 WHERE id = ?2",
            rusqlite::params![
                serde_json::to_string(&stored).expect("act serializes"),
                act.id.to_string()
            ],
        )
        .expect("update");
    assert_eq!(changed, 1);
    stored
}

/// Rewrite one member of an exported bundle and repair everything the importer's packaging checks
/// look at: the member's `sha256` in the manifest, its byte length, and the manifest's own
/// `bundle_digest`. `events.jsonl` is left strictly alone.
///
/// This is what a producer with database access ships. Every packaging layer is recomputed for free
/// because the bundle is *built from* the edited rows; the only question that can catch it is one
/// about the act itself.
fn repackage_bundle(bytes: &[u8], member: &str, new_contents: Vec<u8>) -> Vec<u8> {
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).expect("bundle is a zip");
    let mut members: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..archive.len() {
        let mut f = archive.by_index(i).expect("member");
        let name = f.name().to_owned();
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut buf).expect("member reads");
        members.push((name, buf));
    }

    let target = members
        .iter_mut()
        .find(|(name, _)| name == member)
        .unwrap_or_else(|| panic!("bundle has no member {member}"));
    target.1 = new_contents;

    let manifest_bytes = members
        .iter()
        .find(|(name, _)| name == "manifest.json")
        .map(|(_, bytes)| bytes.clone())
        .expect("manifest.json");
    let mut manifest: BundleManifest =
        serde_json::from_slice(&manifest_bytes).expect("manifest parses");
    let (_, edited) = members
        .iter()
        .find(|(name, _)| name == member)
        .expect("the edited member");
    let entry = manifest
        .files
        .iter_mut()
        .find(|f| f.name == member)
        .unwrap_or_else(|| panic!("manifest does not list {member}"));
    entry.sha256 = hex(&Sha256::digest(edited));
    entry.bytes = edited.len() as u64;
    // The manifest's self-digest, over the canonical manifest with `bundle_digest` empty and the
    // (always-absent in v1) signature cleared — exactly what the exporter computes.
    manifest.bundle_digest = String::new();
    manifest.signature = None;
    manifest.bundle_digest = hex(&Sha256::digest(
        serde_json::to_vec(&manifest).expect("manifest serializes"),
    ));
    let repaired = serde_json::to_vec(&manifest).expect("manifest serializes");
    members
        .iter_mut()
        .find(|(name, _)| name == "manifest.json")
        .expect("manifest.json")
        .1 = repaired;

    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, bytes) in &members {
        zip.start_file(name.as_str(), opts).expect("start member");
        std::io::Write::write_all(&mut zip, bytes).expect("write member");
    }
    zip.finish().expect("finish zip").into_inner()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// The bundle member holding `act`, and its current bytes.
fn bundle_act_member(bytes: &[u8], act: &Act) -> (String, Vec<u8>) {
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).expect("bundle is a zip");
    for i in 0..archive.len() {
        let mut f = archive.by_index(i).expect("member");
        let name = f.name().to_owned();
        if !(name.starts_with("acts/") && name.ends_with(".json")) {
            continue;
        }
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut buf).expect("member reads");
        let parsed: Act = serde_json::from_slice(&buf).expect("bundled act parses");
        if parsed.id == act.id {
            return (name, buf);
        }
    }
    panic!("the bundle carries no member for act {}", act.id);
}

#[test]
fn a_freshly_sealed_act_reloads_with_verified_fixity() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let act = seed_sealed_ata(&store);

    let loaded = store.load().expect("load");
    assert!(loaded.integrity.healthy, "the chain must verify");
    assert!(
        loaded.act_fixity.healthy,
        "a freshly sealed act must re-verify: {:?}",
        loaded.act_fixity
    );
    assert_eq!(loaded.act_fixity.sealed_checked, 1);
    assert_eq!(loaded.act_fixity.verified, 1);
    assert_eq!(loaded.act_fixity.broken, 0);
    assert_eq!(loaded.act_fixity.unverifiable, 0);
    assert!(loaded.act_fixity.findings.is_empty());
    assert!(loaded.act_fixity.ata_sequence.is_empty());
    assert_eq!(act.ata_number, Some(1));
}

#[test]
fn editing_a_sealed_act_row_is_detected_on_load_while_the_chain_still_verifies() {
    // The regression test for the whole finding.
    let dir = TempDir::new();
    let act = {
        let store = Store::open(dir.path()).expect("open");
        let act = seed_sealed_ata(&store);
        assert!(store.load().expect("load").act_fixity.healthy);
        act
    };

    edit_stored_act(
        dir.path(),
        &act,
        "deliberations",
        "\"Rejeitadas as contas do exercício.\"",
    );

    let store = Store::open(dir.path()).expect("reopen");
    let loaded = store
        .load()
        .expect("load still succeeds — never refuse to start");

    // The chain is untouched and reports itself perfectly healthy. That is not a defect in the
    // chain; it is the limit of what a chain attests, and the reason this check has to exist.
    assert_eq!(loaded.chain_status, Ok(3));
    assert!(
        loaded.integrity.healthy,
        "the CHAIN must still verify — that is the point"
    );

    // The fixity pass is what notices.
    assert!(
        !loaded.act_fixity.healthy,
        "an edited sealed act must be detected: {:?}",
        loaded.act_fixity
    );
    assert_eq!(loaded.act_fixity.broken, 1);
    assert_eq!(loaded.act_fixity.verified, 0);
    assert_eq!(loaded.act_fixity.findings.len(), 1);
    let finding = &loaded.act_fixity.findings[0];
    assert_eq!(finding.act_id, act.id.to_string());
    assert!(finding.fixity.is_broken(), "{:?}", finding.fixity);

    // Nothing was repaired: the altered row is still altered and still loaded, so an operator can
    // see exactly what changed.
    let reloaded = loaded.acts.get(&act.id).expect("the act is still loaded");
    assert_eq!(reloaded.deliberations, "Rejeitadas as contas do exercício.");
    assert_eq!(reloaded.payload_digest, act.payload_digest);

    // …and the same verdict through the standalone accessor the CLI/API read.
    assert!(!store.act_fixity_report().expect("report").healthy);
}

#[test]
fn editing_a_sealed_act_row_and_its_own_frozen_digest_together_is_detected_on_load() {
    // **The C1 attack, end to end through real persistence.**
    //
    // `editing_a_sealed_act_row_is_detected_on_load_while_the_chain_still_verifies` above edits the
    // deliberations and nothing else, and passed against a check that compared the row to
    // `payload_digest` — another key of the very same JSON blob. Extend the one `UPDATE` to write
    // the recomputed digest beside the edited content and that check finds a perfectly
    // self-consistent row. The digest the ledger froze is untouched and was never consulted.
    let dir = TempDir::new();
    let act = {
        let store = Store::open(dir.path()).expect("open");
        let act = seed_sealed_ata(&store);
        assert!(store.load().expect("load").act_fixity.healthy);
        act
    };

    let forged = rewrite_stored_act(dir.path(), &act, |stored| {
        stored.deliberations = "Rejeitadas as contas do exercício.".to_owned();
        stored.payload_digest = sealed_act_digest(stored);
    });
    assert_ne!(
        forged.payload_digest, act.payload_digest,
        "the attack rewrote the row's frozen digest"
    );
    assert_eq!(
        sealed_act_digest(&forged),
        forged.payload_digest,
        "the attack's premise: the row now hashes to the digest it carries"
    );

    let store = Store::open(dir.path()).expect("reopen");
    let loaded = store.load().expect("load still succeeds");

    // The chain is untouched and verifies. So does the row, against itself. Only the ledger knows.
    assert_eq!(loaded.chain_status, Ok(3));
    assert!(loaded.integrity.healthy, "the CHAIN must still verify");

    assert!(
        !loaded.act_fixity.healthy,
        "an act edited together with its own frozen digest must be detected: {:?}",
        loaded.act_fixity
    );
    assert_eq!(loaded.act_fixity.broken, 1);
    assert_eq!(loaded.act_fixity.verified, 0);
    assert_eq!(loaded.act_fixity.findings.len(), 1);
    let finding = &loaded.act_fixity.findings[0];
    assert_eq!(finding.act_id, act.id.to_string());
    let chancela_core::ActFixity::LedgerAnchorMismatch {
        ledger,
        row,
        recomputed,
    } = &finding.fixity
    else {
        panic!(
            "the finding must name the chain/row disagreement, got {:?}",
            finding.fixity
        );
    };
    assert_eq!(
        ledger,
        &hex(&act.payload_digest.expect("the original frozen digest")),
        "the ledger side must be the digest the `act.sealed` event froze"
    );
    assert_eq!(
        row,
        &hex(&forged.payload_digest.expect("the forged digest"))
    );
    assert_eq!(
        recomputed.as_ref(),
        Some(row),
        "content and row digest moved together — the tell that the row was rewritten as a unit"
    );

    // …and the same verdict through the standalone accessor the CLI/API read.
    assert!(!store.act_fixity_report().expect("report").healthy);
}

#[test]
fn a_sealed_act_row_pointed_at_a_seal_event_that_does_not_exist_is_broken() {
    // An act's link to the chain is `seal_event_seq`. Cutting it — so the row names a seal the
    // ledger does not record — must be an affirmative finding, not an ambiguity to be counted: a
    // row that answers "which seal?" with nothing is not a historical row, it is a severed one.
    let dir = TempDir::new();
    let act = {
        let store = Store::open(dir.path()).expect("open");
        seed_sealed_ata(&store)
    };
    rewrite_stored_act(dir.path(), &act, |stored| {
        stored.seal_event_seq = Some(9_999);
    });

    let store = Store::open(dir.path()).expect("reopen");
    let loaded = store.load().expect("load");
    assert!(loaded.integrity.healthy, "the chain still verifies");
    assert!(!loaded.act_fixity.healthy, "{:?}", loaded.act_fixity);
    assert_eq!(loaded.act_fixity.broken, 1);
    assert_eq!(loaded.act_fixity.unverifiable, 0);
    assert_eq!(
        loaded.act_fixity.findings[0].fixity,
        chancela_core::ActFixity::SealEventMissing {
            seal_event_seq: Some(9_999),
        }
    );
}

#[test]
fn renumbering_a_sealed_act_row_is_detected_on_load() {
    // C7: before the number was bound into the seal metadata it lived only in the ledger
    // justification string, which is unhashed, so this edit moved nothing any digest covered.
    let dir = TempDir::new();
    let act = {
        let store = Store::open(dir.path()).expect("open");
        seed_sealed_ata(&store)
    };
    edit_stored_act(dir.path(), &act, "ata_number", "42");

    let store = Store::open(dir.path()).expect("reopen");
    let loaded = store.load().expect("load");
    assert!(loaded.integrity.healthy, "the chain still verifies");
    assert!(!loaded.act_fixity.healthy, "{:?}", loaded.act_fixity);
    assert_eq!(
        loaded.act_fixity.findings[0].fixity,
        chancela_core::ActFixity::AtaNumberMismatch {
            sealed: 1,
            stored: Some(42),
        }
    );
}

#[test]
fn a_bundle_carrying_an_altered_sealed_act_is_quarantined() {
    // The importer used to verify only the bundle's *packaging*: the manifest self-digest, each
    // member's sha256, and the book chain over `events.jsonl`. A producer whose `acts` table has
    // been edited recomputes all three for free, because the bundle is built from the edited rows
    // — so a tampered ata travelled as `Verified`. The importer never parsed an act at all.
    let src_dir = TempDir::new();
    let act = {
        let src = Store::open(src_dir.path()).expect("open source");
        seed_sealed_ata(&src)
    };
    edit_stored_act(
        src_dir.path(),
        &act,
        "deliberations",
        "\"Rejeitadas as contas do exercício.\"",
    );

    let src = Store::open(src_dir.path()).expect("reopen source");
    let mut ledger = src.load().expect("load").ledger;
    let export = src
        .export_book(
            &mut ledger,
            act.book_id,
            src_dir.path(),
            "amelia.marques",
            at(),
        )
        .expect("export");

    // Everything the old importer checked is clean: the chain the bundle carries verifies.
    assert!(
        export.manifest.book_chain.verified,
        "the packaging is self-consistent — that is exactly why the act had to be checked"
    );

    let dst_dir = TempDir::new();
    let dst = Store::open(dst_dir.path()).expect("open dest");
    let preflight = dst
        .preflight_import_book_bytes(&export.bytes, CollisionPolicy::Refuse)
        .expect("preflight");
    let ImportVerdict::Quarantined { break_ } = &preflight.verdict else {
        panic!(
            "a bundle carrying an altered sealed ata must be quarantined, got {:?}",
            preflight.verdict
        );
    };
    assert!(
        format!("{break_:?}").contains("no longer matches the digest its seal froze"),
        "the quarantine must name the fixity failure: {break_:?}"
    );
}

#[test]
fn a_bundle_whose_act_had_its_payload_digest_deleted_is_not_imported_as_verified() {
    // **The C2 attack.** `"payload_digest": null` turned an affirmative `Mismatch` into an
    // `Unverifiable`, and the unverifiable arm only incremented a counter — `healthy` stayed true,
    // and the importer gated on `healthy` alone. So: edit the ata, delete the one key that could
    // convict it, recompute the member's sha256 and the manifest's `bundle_digest`, leave
    // `events.jsonl` untouched, and the operator was told `Verified`.
    //
    // The tamper is applied to the BUNDLE, after a clean export, so every packaging layer the
    // importer checks is repaired exactly as a hostile producer repairs it.
    let src_dir = TempDir::new();
    let src = Store::open(src_dir.path()).expect("open source");
    let act = seed_sealed_ata(&src);
    let mut ledger = src.load().expect("load").ledger;
    let export = src
        .export_book(
            &mut ledger,
            act.book_id,
            src_dir.path(),
            "amelia.marques",
            at(),
        )
        .expect("export");

    let (member, bytes) = bundle_act_member(&export.bytes, &act);
    let mut bundled: serde_json::Value = serde_json::from_slice(&bytes).expect("act json");
    bundled["deliberations"] = serde_json::json!("Rejeitadas as contas do exercício.");
    bundled["payload_digest"] = serde_json::Value::Null;
    let tampered = repackage_bundle(
        &export.bytes,
        &member,
        serde_json::to_vec(&bundled).expect("act serializes"),
    );

    let dst_dir = TempDir::new();
    let dst = Store::open(dst_dir.path()).expect("open dest");
    let preflight = dst
        .preflight_import_book_bytes(&tampered, CollisionPolicy::Refuse)
        .expect("preflight");
    assert_ne!(
        preflight.verdict,
        ImportVerdict::Verified,
        "a bundle whose sealed ata has no frozen digest must never be stamped Verified"
    );
    let ImportVerdict::Quarantined { break_ } = &preflight.verdict else {
        panic!("expected quarantine, got {:?}", preflight.verdict);
    };
    assert!(
        format!("{break_:?}").contains("digest its seal froze"),
        "the quarantine must name the fixity failure: {break_:?}"
    );
}

#[test]
fn a_bundle_whose_act_had_its_seal_metadata_deleted_is_not_imported_as_verified() {
    // The companion, and the reason the importer gates on `fully_verified()` rather than on
    // `healthy` plus a special case for the digest. `seal_metadata` really is optional, so a
    // stripped row really is indistinguishable from a pre-metadata one — which is a reason not to
    // brick a running install, and no reason at all to accept an unverifiable act from outside.
    let src_dir = TempDir::new();
    let src = Store::open(src_dir.path()).expect("open source");
    let act = seed_sealed_ata(&src);
    let mut ledger = src.load().expect("load").ledger;
    let export = src
        .export_book(
            &mut ledger,
            act.book_id,
            src_dir.path(),
            "amelia.marques",
            at(),
        )
        .expect("export");

    let (member, bytes) = bundle_act_member(&export.bytes, &act);
    let mut bundled: serde_json::Value = serde_json::from_slice(&bytes).expect("act json");
    bundled["deliberations"] = serde_json::json!("Rejeitadas as contas do exercício.");
    bundled
        .as_object_mut()
        .expect("act object")
        .remove("seal_metadata");
    let tampered = repackage_bundle(
        &export.bytes,
        &member,
        serde_json::to_vec(&bundled).expect("act serializes"),
    );

    let dst_dir = TempDir::new();
    let dst = Store::open(dst_dir.path()).expect("open dest");
    let preflight = dst
        .preflight_import_book_bytes(&tampered, CollisionPolicy::Refuse)
        .expect("preflight");
    assert_ne!(
        preflight.verdict,
        ImportVerdict::Verified,
        "an act whose fixity cannot be ANSWERED must not import as verified"
    );
}

#[test]
fn a_bundle_carrying_an_act_edited_together_with_its_digest_is_quarantined() {
    // C1 through the importer: the bundled act is edited AND its `payload_digest` rewritten to
    // match, so the member is self-consistent at every layer the old importer inspected. The
    // bundle's own `events.jsonl` — chain-verified a few lines earlier — is what convicts it.
    let src_dir = TempDir::new();
    let src = Store::open(src_dir.path()).expect("open source");
    let act = seed_sealed_ata(&src);
    let mut ledger = src.load().expect("load").ledger;
    let export = src
        .export_book(
            &mut ledger,
            act.book_id,
            src_dir.path(),
            "amelia.marques",
            at(),
        )
        .expect("export");

    let (member, bytes) = bundle_act_member(&export.bytes, &act);
    let mut bundled: Act = serde_json::from_slice(&bytes).expect("act parses");
    bundled.deliberations = "Rejeitadas as contas do exercício.".to_owned();
    bundled.payload_digest = sealed_act_digest(&bundled);
    let tampered = repackage_bundle(
        &export.bytes,
        &member,
        serde_json::to_vec(&bundled).expect("act serializes"),
    );

    let dst_dir = TempDir::new();
    let dst = Store::open(dst_dir.path()).expect("open dest");
    let preflight = dst
        .preflight_import_book_bytes(&tampered, CollisionPolicy::Refuse)
        .expect("preflight");
    let ImportVerdict::Quarantined { break_ } = &preflight.verdict else {
        panic!(
            "an act edited together with its own digest must be quarantined, got {:?}",
            preflight.verdict
        );
    };
    assert!(
        format!("{break_:?}").contains("no longer matches the digest its seal froze"),
        "{break_:?}"
    );
}

#[test]
fn repackaging_a_bundle_untouched_still_imports_as_verified() {
    // The control for the three tests above: `repackage_bundle` itself must not be what makes a
    // bundle fail. Rewritten with its act member byte-identical, the bundle still verifies — so a
    // quarantine there is about the act, not about the repackaging.
    let src_dir = TempDir::new();
    let src = Store::open(src_dir.path()).expect("open source");
    let act = seed_sealed_ata(&src);
    let mut ledger = src.load().expect("load").ledger;
    let export = src
        .export_book(
            &mut ledger,
            act.book_id,
            src_dir.path(),
            "amelia.marques",
            at(),
        )
        .expect("export");

    let (member, bytes) = bundle_act_member(&export.bytes, &act);
    let repackaged = repackage_bundle(&export.bytes, &member, bytes);

    let dst_dir = TempDir::new();
    let dst = Store::open(dst_dir.path()).expect("open dest");
    let preflight = dst
        .preflight_import_book_bytes(&repackaged, CollisionPolicy::Refuse)
        .expect("preflight");
    assert_eq!(preflight.verdict, ImportVerdict::Verified);
}

#[test]
fn a_clean_bundle_still_imports_as_verified() {
    // The companion: the new check must not quarantine honest bundles.
    let src_dir = TempDir::new();
    let src = Store::open(src_dir.path()).expect("open source");
    let act = seed_sealed_ata(&src);
    let mut ledger = src.load().expect("load").ledger;
    let export = src
        .export_book(
            &mut ledger,
            act.book_id,
            src_dir.path(),
            "amelia.marques",
            at(),
        )
        .expect("export");

    let dst_dir = TempDir::new();
    let dst = Store::open(dst_dir.path()).expect("open dest");
    let preflight = dst
        .preflight_import_book_bytes(&export.bytes, CollisionPolicy::Refuse)
        .expect("preflight");
    assert_eq!(preflight.verdict, ImportVerdict::Verified);
}

#[test]
fn two_persisted_acts_cannot_hold_the_same_ata_number() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let first = seed_sealed_ata(&store);

    // A second act in the same book, renumbered onto the first's ata. Persisted through the same
    // writer the product uses, so the defect is in the rows the load path actually reads.
    let mut collided = first.clone();
    collided.id = chancela_core::ActId(uuid::Uuid::new_v4());
    store
        .persist(|tx| tx.upsert_act(&collided))
        .expect("second act persists");

    let loaded = store.load().expect("load");
    assert!(!loaded.act_fixity.healthy, "{:?}", loaded.act_fixity);
    assert_eq!(loaded.act_fixity.ata_sequence.len(), 1);
    assert_eq!(
        loaded.act_fixity.ata_sequence[0].issue,
        chancela_core::AtaSequenceIssue::Duplicate {
            ata_number: 1,
            act_ids: {
                let mut ids = vec![first.id.to_string(), collided.id.to_string()];
                ids.sort();
                ids
            },
        }
    );
}
