//! Source-level guard on the one lock-order pair that has already produced a hard deadlock.
//!
//! [`AppState`](chancela_api::AppState) documents a fixed acquisition order — `… → entities → books
//! → acts → … → ledger` — and every mutation handler takes `books` before `acts`. A read path that
//! took them the other way round (`refresh_act_fixity`) was an AB–BA against all of them: it held
//! `acts` for a full O(n) verification while waiting on `books`, exactly as a concurrent seal held
//! `books` and waited on `acts`. Neither task can ever be woken, and because `tokio`'s `RwLock` is
//! write-preferring the queued writer then blocks every subsequent reader too — the instance wedges
//! whole, with no timeout, no panic, and nothing in the log.
//!
//! A deadlock is a terrible thing to test for directly: the test that reproduces it *hangs* rather
//! than failing, so it reads as a stuck CI job rather than a red one, and it only reproduces under
//! an interleaving no test can force. So the ORDER is asserted structurally instead. This is the
//! whole guard: one function fixed by hand is a fix that lasts until the next person writes the
//! obvious thing, and the next person is who this file is for.
//!
//! Scope is deliberately the `books`/`acts` pair only, not the whole documented chain: it is the
//! pair with a demonstrated deadlock, and a guard whose exception list grows faster than its
//! findings stops being read.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Functions that mention both locks with `acts` first, and are NOT inversions because the first
/// guard is provably released before the second is acquired (a scope-ended `let` block, or an
/// explicit `drop`). They hold one lock at a time, so there is no hold-and-wait and no cycle.
///
/// An entry here is a claim that must be re-checked when its function changes. Nesting the two
/// acquisitions in either of these would reintroduce exactly the wedge described above.
const SEQUENTIAL_NOT_NESTED: &[(&str, &str)] = &[
    (
        "connector_jobs.rs::materialize_artifact",
        "each lookup is its own `let … = { let guard = …; }` block; the acts guard ends before books is taken",
    ),
    (
        "documents.rs::imported_document_event_scope",
        "explicit `drop(acts)` before `state.books.read()`",
    ),
];

/// Reproduces `search_source_mutation_guards.rs`: everything from a `#[cfg(test)] mod tests {` on is
/// test code, and a test is free to reach for whichever map it is asserting about.
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

fn function_name(line: &str) -> Option<&str> {
    let rest = line.split_once("fn ")?.1;
    let end = rest
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(rest.len());
    (end > 0).then_some(&rest[..end])
}

/// Strip `//` comments so the prose *describing* a lock order is never mistaken for one.
fn code_only(line: &str) -> &str {
    line.split_once("//").map_or(line, |(code, _)| code)
}

/// The line offset of the first `<map>.read()`/`.write()` acquisition in `body`, if any.
///
/// The leading `.` is the field-access boundary, and it is load-bearing: without it
/// `registry_extr*acts*.read().await` and `breach_play*books*.read().await` both match, which is how
/// this scan first "found" an inversion in a function that acquires neither lock.
fn first_acquisition(body: &[&str], map: &str) -> Option<usize> {
    let read = format!(".{map}.read().await");
    let write = format!(".{map}.write().await");
    body.iter().position(|line| {
        let code = code_only(line).replace(char::is_whitespace, "");
        code.contains(&read) || code.contains(&write)
    })
}

/// The detector, proved against synthetic bodies.
///
/// A source scan is green when it finds nothing, and a scan that has quietly stopped matching real
/// acquisitions finds nothing too. These three cases are the difference between the two.
#[test]
fn the_scan_sees_an_inverted_acquisition_and_nothing_that_merely_looks_like_one() {
    let inverted = [
        "        let acts = state.acts.read().await;",
        "        let books = state.books.write().await;",
    ];
    let acts = first_acquisition(&inverted, "acts").expect("the acts acquisition is seen");
    let books = first_acquisition(&inverted, "books").expect("the books acquisition is seen");
    assert!(
        acts < books,
        "the inverted order must be visible to the comparison the inventory makes"
    );

    // Field names that merely END in the map name are not acquisitions of it.
    let neighbours = [
        "        let extracts = state.registry_extracts.read().await.clone();",
        "        let playbooks = state.breach_playbooks.read().await.clone();",
    ];
    assert_eq!(first_acquisition(&neighbours, "acts"), None);
    assert_eq!(first_acquisition(&neighbours, "books"), None);

    // A comment describing an order is prose. This file's own subject matter is heavily commented,
    // and a scan that read those comments would report the documentation as the defect.
    let commented = ["    // takes state.acts.read().await before state.books.read().await"];
    assert_eq!(first_acquisition(&commented, "acts"), None);
    assert_eq!(first_acquisition(&commented, "books"), None);
}

#[test]
fn every_production_holder_of_books_and_acts_takes_books_first() {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let expected_sequential = SEQUENTIAL_NOT_NESTED
        .iter()
        .map(|(entry, _)| (*entry).to_owned())
        .collect::<BTreeSet<_>>();
    let mut observed_sequential = BTreeSet::new();
    let mut inversions = Vec::new();
    let mut ordered = 0_usize;

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
        let source = fs::read_to_string(&path).expect("Rust source file must be readable");
        if source.lines().any(|line| line.trim() == "#![cfg(test)]") {
            continue;
        }
        let lines = production_lines(&source);
        let function_starts = lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| function_name(line).map(|name| (index, name)))
            .collect::<Vec<_>>();
        for (position, (start, function)) in function_starts.iter().enumerate() {
            let end = function_starts
                .get(position + 1)
                .map_or(lines.len(), |(index, _)| *index);
            let body = &lines[*start..end];
            let (Some(books), Some(acts)) = (
                first_acquisition(body, "books"),
                first_acquisition(body, "acts"),
            ) else {
                continue;
            };
            let key = format!("{file_name}::{function}");
            if books < acts {
                ordered += 1;
            } else if expected_sequential.contains(&key) {
                observed_sequential.insert(key);
            } else {
                inversions.push(format!(
                    "{key} acquires `acts` (line {}) before `books` (line {}) — the reverse of the \
                     order every mutation handler takes, which is a deadlock, not a style point. \
                     Swap them; if the two guards never overlap, add the function to \
                     SEQUENTIAL_NOT_NESTED with the reason.",
                    start + acts + 1,
                    start + books + 1,
                ));
            }
        }
    }

    assert!(
        inversions.is_empty(),
        "lock-order inversions against the documented `books → acts` order:\n{}",
        inversions.join("\n")
    );
    assert_eq!(
        observed_sequential, expected_sequential,
        "SEQUENTIAL_NOT_NESTED must stay an exact, exercised inventory — an entry whose function \
         no longer takes both locks is a stale claim nobody is re-checking"
    );
    assert!(
        ordered >= 15,
        "only {ordered} functions were seen taking both locks in the correct order — the scan has \
         stopped matching real acquisitions and is now green for the wrong reason"
    );
}
