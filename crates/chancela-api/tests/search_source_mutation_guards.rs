//! Source-level inventory for production mutations of maps consumed by the search projector.
//!
//! The projector snapshots these maps asynchronously. Every normal production writer must hold
//! `SearchSourceMutationGuard` (or the stricter security-sensitive variant) from before its
//! durable/ledger commit through publication to the in-memory read model. Destructive reset/reload
//! and one guarded helper path are deliberately enumerated exceptions rather than silently ignored.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const SEARCH_BACKED_MAPS: &[&str] = &[
    "entities",
    "books",
    "acts",
    "follow_ups",
    "group_template_libraries",
    "group_template_library_revisions",
];

const GUARDED_MUTATORS: &[&str] = &[
    "acts.rs::advance_act",
    "acts.rs::archive_act",
    "acts.rs::convening_dispatch",
    "acts.rs::draft_act",
    "acts.rs::patch_act",
    "acts.rs::reopen_act",
    "acts.rs::revert_act",
    "acts.rs::seal_act_handler",
    "acts.rs::verify_ai_human_review",
    "books.rs::clear_legal_hold",
    "books.rs::close_book",
    "books.rs::create_book",
    "books.rs::patch_book",
    "books.rs::set_legal_hold",
    "bundles.rs::start_over_book",
    "cluster_feed.rs::cluster_swap_delta_state",
    "cluster_feed.rs::cluster_swap_loaded_state",
    "entities.rs::create_entity",
    "entities.rs::patch_entity",
    "followups.rs::complete_follow_up",
    "followups.rs::create_follow_up",
    "followups.rs::patch_follow_up",
    "groups.rs::append_template_library_revision",
    "groups.rs::archive_group",
    "groups.rs::archive_template_library",
    "groups.rs::assign_entity",
    "groups.rs::create_template_library",
    "groups.rs::patch_template_library",
    "groups.rs::remove_entity",
    "paper_import.rs::create_act_draft_from_accepted_paper_book_ocr_draft",
    "registry.rs::import_from_registry",
    "registry.rs::import_into_entity",
    "termo.rs::close_from_termo",
    "termo.rs::open_from_termo",
];

const EXCLUDED_MUTATORS: &[(&str, &str)] = &[
    (
        "books.rs::create_book_two_phase",
        "private helper is called only while create_book holds the source-mutation guard",
    ),
    (
        "cluster.rs::cluster_promotion_handoff",
        "leader promotion replaces memory from one verified durable snapshot",
    ),
    (
        "lib.rs::clear_domain_memory_raw",
        "destructive reset runs inside the explicit destructive search fence",
    ),
    (
        "lib.rs::clear_search_source_memory_after_failed_restore_with_settings_gate_held",
        "failed-restore recovery clears sources while both the destructive fence and settings gate are held",
    ),
    (
        "lib.rs::reload_domain_memory_with_settings_gate_held",
        "restore/reload replaces every source map while both the destructive fence and settings gate are held",
    ),
];

fn async_function_name(line: &str) -> Option<&str> {
    let rest = line.split_once("async fn ")?.1;
    let end = rest
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(rest.len());
    (end > 0).then_some(&rest[..end])
}

fn production_lines(source: &str) -> Vec<&str> {
    let lines = source.lines().collect::<Vec<_>>();
    let test_module = lines.iter().enumerate().find_map(|(index, line)| {
        (line.trim() == "mod tests {"
            && lines[index.saturating_sub(2)..index]
                .iter()
                .any(|prior| prior.trim() == "#[cfg(test)]"))
        .then_some(index)
    });
    lines[..test_module.unwrap_or(lines.len())].to_vec()
}

fn normalized(lines: &[&str]) -> String {
    lines
        .iter()
        .flat_map(|line| line.chars())
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[test]
fn every_production_search_source_map_writer_is_guarded_or_explicitly_excluded() {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let expected_guarded = GUARDED_MUTATORS
        .iter()
        .map(|entry| (*entry).to_owned())
        .collect::<BTreeSet<_>>();
    let expected_excluded = EXCLUDED_MUTATORS
        .iter()
        .map(|(entry, _)| (*entry).to_owned())
        .collect::<BTreeSet<_>>();
    let mut observed_guarded = BTreeSet::new();
    let mut observed_excluded = BTreeSet::new();
    let mut violations = Vec::new();

    for entry in fs::read_dir(&source_root).expect("API source directory must be readable") {
        let path = entry
            .expect("source directory entry must be readable")
            .path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("Rust source filename must be UTF-8");
        if file_name.ends_with("_tests.rs") {
            continue;
        }
        let source = fs::read_to_string(&path).expect("Rust source file must be readable");
        if source.lines().any(|line| line.trim() == "#![cfg(test)]") {
            continue;
        }
        let lines = production_lines(&source);
        let function_starts = lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| async_function_name(line).map(|name| (index, name)))
            .collect::<Vec<_>>();
        for (position, (start, function)) in function_starts.iter().enumerate() {
            let end = function_starts
                .get(position + 1)
                .map_or(lines.len(), |(index, _)| *index);
            let body = normalized(&lines[*start..end]);
            let writes_search_source = SEARCH_BACKED_MAPS.iter().any(|map| {
                body.contains(&format!("state.{map}.write().await"))
                    || body.contains(&format!("self.{map}.write().await"))
            });
            if !writes_search_source {
                continue;
            }
            let key = format!("{file_name}::{function}");
            if body.contains("begin_source_mutation")
                || body.contains("begin_security_sensitive_source_mutation")
            {
                observed_guarded.insert(key);
            } else if expected_excluded.contains(&key) {
                observed_excluded.insert(key);
            } else {
                violations.push(format!(
                    "{key} mutates a search-backed map without begin_source_mutation"
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "unguarded production search source mutations:\n{}",
        violations.join("\n")
    );
    assert_eq!(
        observed_guarded, expected_guarded,
        "update GUARDED_MUTATORS whenever a production search-source writer is added or removed"
    );
    assert_eq!(
        observed_excluded, expected_excluded,
        "EXCLUDED_MUTATORS must remain an exact, exercised exception inventory"
    );
}
