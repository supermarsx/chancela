//! **Enforcement parity: the catalog's claim vs. the crate's real authorization call sites**
//! (t56 §R8.3 / e2b).
//!
//! `Permission::enforcement()` (`chancela-authz`) tells the RBAC matrix — and therefore an
//! auditor — whether ticking a verb into a função grants real authority (`Enforced`) or grants
//! nothing because the capability was never built (`FeatureNotBuilt`). That is a statement about
//! **this crate's source**, and `chancela-authz` cannot see its own dependents, so nothing over
//! there can check it. The five tests that ship beside the enum are all self-referential: enum vs.
//! a pinned array, vs. `Permission::ALL`, vs. seeded roles, vs. the wire id.
//!
//! The unguarded direction is the one that matters:
//!
//! | direction | caught by the `chancela-authz` tests? |
//! |---|---|
//! | an arm flipped to `Enforced` without updating the pinned phantom array | yes |
//! | **a real check site added for a verb whose arm still says `FeatureNotBuilt`** | **no** |
//!
//! The second ships a catalog that tells an auditor *"this action does not exist yet"* about a
//! live, enforced feature. This file closes it, both ways, against the real call sites.
//!
//! ## What counts as a call site
//!
//! The same six textual forms the original audit enumerated ([`CHECK_ANCHORS`]) —
//! `require_permission`, `require_permission_with`, `Authorizer::{require, permits,
//! holds_at_any_scope}` and `has_permission`. Restricting the scan to `require_permission` alone
//! would be a false guard in both directions: seven enforced verbs (`search.read`,
//! `platform_logs.write`, `user.invite`, `role.manage`, `role.assign`, `delegation.grant`,
//! `delegation.revoke`) are gated **only** through `Authorizer`, and a phantom verb that acquired
//! an `authz.require(...)` site would slip past unseen.
//!
//! ## Why the "did it parse?" half is not optional
//!
//! Textual matching can produce a **false zero**: a call site that passes its verb indirectly (a
//! parameter, a locally computed `match`, a helper) carries no `Permission::X` literal in its
//! argument list, so a naive scan under-counts and then reports "zero call sites, correctly
//! `FeatureNotBuilt`" about something that is in fact enforced — manufacturing exactly the
//! confidence this file exists to provide.
//!
//! So every occurrence of every anchor must either parse to a `Permission::` literal or appear in
//! [`INDIRECT_SITES`] with a written reason and a mechanical rule for re-deriving the verbs it
//! really carries. An occurrence that does neither is a **hard failure**, never a skip. The fix
//! for a stubborn case is an allowlist entry, never a looser matcher — a matcher loosened until
//! everything passes is a decoration, not a guard.
//!
//! The one way a future change can still narrow this quietly is by introducing a **new** check form
//! and not adding it to [`CHECK_ANCHORS`] — a new `Authorizer` method, say. Nothing textual can
//! catch that, so it is stated here rather than left implicit.
//!
//! ## Production-ness
//!
//! `#[cfg(test)]` regions are removed by brace matching, not by truncating at the first test
//! module: this crate **interleaves** test blocks with production code (`search.rs` alone has 27
//! of them, with the two production `search.read` gates sitting *after* several). Stripping is
//! deliberately conservative — only the exact attribute `#[cfg(test)]` is removed, so shapes like
//! `#[cfg(all(test, feature = "postgres"))]` stay in scope. Keeping a test region can only cause
//! a loud false failure; stripping a production region could hide a real call site, so the
//! asymmetry is resolved towards noise.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use chancela_authz::{Permission, PermissionEnforcement};

/// Every textual form an authorization check takes in `chancela-api`.
///
/// `.require(` / `.permits(` / `.holds_at_any_scope(` are matched on **any** receiver, not only on
/// the `authz` binding. That is deliberate: pinning the receiver name would make a renamed binding
/// — or an inline `authorizer(..).await?.require(..)` — silently invisible. The cost is that
/// unrelated methods of the same name (there are two) need allowlist entries; that cost is the
/// guard working.
const CHECK_ANCHORS: &[&str] = &[
    "require_permission_with(",
    "require_permission(",
    ".require(",
    ".permits(",
    ".holds_at_any_scope(",
    "has_permission(",
];

/// How an occurrence that carries no `Permission::` literal gets its verbs re-derived.
#[derive(Clone, Copy)]
enum Resolution {
    /// The occurrence *is* the gate machinery; the verb belongs to whoever calls it. Contributes
    /// no verb of its own — the callers are scanned like any other call site.
    GateImplementation,
    /// A same-named method on an unrelated type. Not an authorization check at all.
    NotAnAuthorizationCheck,
    /// An in-crate forwarding helper whose verb is a parameter. The concrete verbs come from the
    /// helper's own call sites, each of which must itself parse.
    ForwardedFrom(&'static str),
    /// The verb is computed inside the named production functions of the same file. Their
    /// `Permission::` literals are the verbs this site can carry.
    LocalLiterals(&'static [&'static str]),
}

/// An anchor occurrence the matcher cannot read a verb out of.
///
/// Exhaustive and exact: an unlisted one fails, and a listed one that stops occurring fails too,
/// so this stays an exercised inventory rather than a wishlist.
struct IndirectSite {
    file: &'static str,
    function: &'static str,
    anchor: &'static str,
    occurrences: usize,
    reason: &'static str,
    resolution: Resolution,
}

const INDIRECT_SITES: &[IndirectSite] = &[
    IndirectSite {
        file: "authz.rs",
        function: "require_permission_with",
        anchor: "has_permission(",
        occurrences: 1,
        reason: "the principal-source-agnostic gate itself; `perm` is its own parameter",
        resolution: Resolution::GateImplementation,
    },
    IndirectSite {
        file: "authz.rs",
        function: "require_permission",
        anchor: ".require(",
        occurrences: 1,
        reason: "the session gate forwards its `perm` parameter to a freshly built Authorizer",
        resolution: Resolution::GateImplementation,
    },
    IndirectSite {
        file: "authz.rs",
        function: "permits",
        anchor: "has_permission(",
        occurrences: 1,
        reason: "Authorizer::permits is the predicate every other check is expressed in terms of",
        resolution: Resolution::GateImplementation,
    },
    IndirectSite {
        file: "authz.rs",
        function: "require",
        anchor: ".permits(",
        occurrences: 1,
        reason: "Authorizer::require is Authorizer::permits plus the 403; `perm` is its parameter",
        resolution: Resolution::GateImplementation,
    },
    IndirectSite {
        file: "connector_jobs.rs",
        function: "run_target",
        anchor: "require_permission(",
        occurrences: 1,
        reason: "the verb is chosen by a local `match body.purpose` over the job purposes",
        resolution: Resolution::LocalLiterals(&["run_target"]),
    },
    IndirectSite {
        file: "connector_jobs.rs",
        function: "run_target",
        anchor: ".permits(",
        occurrences: 1,
        reason: "`ConnectorTargetRecord::permits(JobPurpose)` — target enablement, not authority",
        resolution: Resolution::NotAnAuthorizationCheck,
    },
    IndirectSite {
        file: "connector_jobs.rs",
        function: "list_jobs",
        anchor: ".permits(",
        occurrences: 1,
        reason: "per-row filter; the verb comes from a local `match snapshot.job.purpose`",
        resolution: Resolution::LocalLiterals(&["list_jobs"]),
    },
    IndirectSite {
        file: "connector_jobs.rs",
        function: "authorized_job",
        anchor: "require_permission(",
        occurrences: 1,
        reason: "shared job-authorization helper; the verb comes from a local purpose `match`",
        resolution: Resolution::LocalLiterals(&["authorized_job"]),
    },
    IndirectSite {
        file: "entities.rs",
        function: "ensure_entity_kind_enabled",
        anchor: ".permits(",
        occurrences: 1,
        reason: "`EntitySettings::permits(EntityKind)` — which legal types may be created, not who",
        resolution: Resolution::NotAnAuthorizationCheck,
    },
    IndirectSite {
        file: "entities.rs",
        function: "list_entities",
        anchor: ".permits(",
        occurrences: 1,
        reason: "`ArchivedFilter::permits(&Entity)` — the `archived=` query filter deciding which \
                 rows the caller asked for, applied after the real `entity.read` check on the \
                 line above it",
        resolution: Resolution::NotAnAuthorizationCheck,
    },
    IndirectSite {
        file: "entities.rs",
        function: "list_entities_page",
        anchor: ".permits(",
        occurrences: 1,
        reason: "`ArchivedFilter::permits(&Entity)` again, on the keyset-paged listing",
        resolution: Resolution::NotAnAuthorizationCheck,
    },
    IndirectSite {
        file: "groups.rs",
        function: "require_tenant",
        anchor: "require_permission(",
        occurrences: 1,
        reason: "forwarding helper: every group handler passes its own verb at tenant scope",
        resolution: Resolution::ForwardedFrom("require_tenant("),
    },
    IndirectSite {
        file: "search.rs",
        function: "document_allowed",
        anchor: ".permits(",
        occurrences: 1,
        reason: "per-row domain verb from a local `match document.kind`, plus the \
                 `action_permission` lookup table for operational-action rows",
        resolution: Resolution::LocalLiterals(&["document_allowed", "action_permission"]),
    },
    IndirectSite {
        file: "zk_repository.rs",
        function: "repository_for_route",
        anchor: "require_permission(",
        occurrences: 2,
        reason: "forwarding helper; both branches (repository scope, then tenant scope for the \
                 not-found path so existence is not leaked) carry the caller's verb",
        resolution: Resolution::ForwardedFrom("repository_for_route("),
    },
];

/// Lower bounds that fail loudly if the scanner stops seeing the crate — a masker or stripper bug
/// that blanked everything would otherwise let both directions pass vacuously.
const MIN_FILES_SCANNED: usize = 80;
const MIN_ANCHOR_OCCURRENCES: usize = 250;

// ---------------------------------------------------------------------------------------------
// Lexing
// ---------------------------------------------------------------------------------------------

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn blank(out: &mut [u8], source: &[u8], from: usize, to: usize) {
    for index in from..to.min(source.len()) {
        if source[index] != b'\n' {
            out[index] = b' ';
        }
    }
}

/// Replace every comment and string/char literal with spaces, preserving byte offsets and line
/// breaks. Anchors inside a doc comment (`authz.rs` names `require_permission` in prose a dozen
/// times) or inside this suite's own pinned literals must not be mistaken for call sites.
fn mask_literals(source: &str) -> String {
    let src = source.as_bytes();
    let mut out = src.to_vec();
    let length = src.len();
    let mut index = 0;
    while index < length {
        let byte = src[index];
        if byte == b'/' && src.get(index + 1) == Some(&b'/') {
            let end = source[index..]
                .find('\n')
                .map_or(length, |offset| index + offset);
            blank(&mut out, src, index, end);
            index = end;
        } else if byte == b'/' && src.get(index + 1) == Some(&b'*') {
            let mut depth = 1usize;
            let mut cursor = index + 2;
            while cursor < length && depth > 0 {
                if src[cursor] == b'/' && src.get(cursor + 1) == Some(&b'*') {
                    depth += 1;
                    cursor += 2;
                } else if src[cursor] == b'*' && src.get(cursor + 1) == Some(&b'/') {
                    depth -= 1;
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            blank(&mut out, src, index, cursor);
            index = cursor;
        } else if (byte == b'r' || byte == b'b')
            && (index == 0 || !is_ident_byte(src[index - 1]))
            && matches!(src.get(index + 1), Some(b'"' | b'#' | b'r'))
        {
            let mut cursor = index + 1;
            if src[cursor] == b'r' {
                cursor += 1;
            }
            let mut hashes = 0usize;
            while src.get(cursor) == Some(&b'#') {
                hashes += 1;
                cursor += 1;
            }
            if src.get(cursor) == Some(&b'"') {
                let end = if hashes == 0 {
                    end_of_quoted(src, cursor)
                } else {
                    let terminator = format!("\"{}", "#".repeat(hashes));
                    source[cursor + 1..]
                        .find(&terminator)
                        .map_or(length, |offset| cursor + 1 + offset + terminator.len())
                };
                blank(&mut out, src, index, end);
                index = end;
            } else {
                index += 1;
            }
        } else if byte == b'"' {
            let end = end_of_quoted(src, index);
            blank(&mut out, src, index, end);
            index = end;
        } else if byte == b'\'' {
            if src.get(index + 1) == Some(&b'\\') {
                let mut cursor = index + 2;
                while cursor < length && src[cursor] != b'\'' {
                    cursor += 1;
                }
                blank(&mut out, src, index, cursor + 1);
                index = cursor + 1;
            } else if src.get(index + 2) == Some(&b'\'') {
                blank(&mut out, src, index, index + 3);
                index += 3;
            } else {
                // A lifetime (`'a`), not a char literal.
                index += 1;
            }
        } else {
            index += 1;
        }
    }
    String::from_utf8(out).expect("blanking only replaces whole ASCII-delimited spans")
}

/// End (exclusive) of the double-quoted literal opening at `open`.
fn end_of_quoted(src: &[u8], open: usize) -> usize {
    let mut cursor = open + 1;
    while cursor < src.len() {
        match src[cursor] {
            b'\\' => cursor += 2,
            b'"' => return cursor + 1,
            _ => cursor += 1,
        }
    }
    src.len()
}

/// Blank every `#[cfg(test)]` item, brace-matched. Deliberately literal — see the module docs on
/// why keeping an unrecognised test-only shape is the safe direction.
fn strip_test_regions(masked: &str) -> String {
    const ATTRIBUTE: &str = "#[cfg(test)]";
    let source = masked.as_bytes();
    let mut out = source.to_vec();
    let mut index = 0;
    while let Some(offset) = masked[index..].find(ATTRIBUTE) {
        let at = index + offset;
        if out[at] == b' ' {
            // Already inside a region blanked by an enclosing `#[cfg(test)]`.
            index = at + 1;
            continue;
        }
        let end = item_end(source, at + ATTRIBUTE.len());
        blank(&mut out, source, at, end);
        index = end;
    }
    String::from_utf8(out).expect("blanking preserves UTF-8")
}

/// End (exclusive) of the item an attribute at `from` decorates: its brace-matched body, or the
/// `;` of a bodyless item. Only `{`/`;` at bracket depth zero count, so `const X: [u8; 4] = ..;`
/// is not cut short by the `;` inside its type.
fn item_end(source: &[u8], from: usize) -> usize {
    let mut depth = 0i32;
    let mut index = from;
    while index < source.len() {
        match source[index] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b'{' if depth == 0 => {
                let mut braces = 0i32;
                let mut cursor = index;
                while cursor < source.len() {
                    match source[cursor] {
                        b'{' => braces += 1,
                        b'}' => {
                            braces -= 1;
                            if braces == 0 {
                                return cursor + 1;
                            }
                        }
                        _ => {}
                    }
                    cursor += 1;
                }
                return source.len();
            }
            b';' if depth == 0 => return index + 1,
            _ => {}
        }
        index += 1;
    }
    source.len()
}

// ---------------------------------------------------------------------------------------------
// Reading a call site
// ---------------------------------------------------------------------------------------------

/// Interior of the argument list whose `(` sits at `open`.
fn argument_span(masked: &str, open: usize) -> (usize, usize) {
    let source = masked.as_bytes();
    let mut depth = 0i32;
    let mut index = open;
    while index < source.len() {
        match source[index] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => {
                depth -= 1;
                if depth == 0 {
                    return (open + 1, index);
                }
            }
            _ => {}
        }
        index += 1;
    }
    (open + 1, source.len())
}

fn identifier_at(masked: &str, from: usize) -> &str {
    let source = masked.as_bytes();
    let mut start = from;
    while start < source.len() && source[start] == b' ' {
        start += 1;
    }
    let mut end = start;
    while end < source.len() && is_ident_byte(source[end]) {
        end += 1;
    }
    &masked[start..end]
}

/// The first `Permission::` variant named in `text`, if any.
fn permission_literal(text: &str) -> Option<&str> {
    let at = text.find("Permission::")?;
    let name = identifier_at(text, at + "Permission::".len());
    (!name.is_empty()).then_some(name)
}

/// Every `Permission::` variant named in `text`.
fn permission_literals(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut index = 0;
    while let Some(offset) = text[index..].find("Permission::") {
        let at = index + offset + "Permission::".len();
        let name = identifier_at(text, at);
        if !name.is_empty() {
            found.insert(name.to_owned());
        }
        index = at;
    }
    found
}

/// The nearest `fn` declaration preceding `at` — the enclosing production function. Nearest-`fn`
/// is used rather than proximity to a `#[cfg(test)]` marker, which this crate's interleaving makes
/// meaningless.
fn enclosing_function(masked: &str, at: usize) -> &str {
    let source = masked.as_bytes();
    let mut best = "<module>";
    let mut index = 0;
    while let Some(offset) = masked[index..at].find("fn ") {
        let position = index + offset;
        if position == 0 || !is_ident_byte(source[position - 1]) {
            let name = identifier_at(masked, position + 3);
            if !name.is_empty() {
                best = name;
            }
        }
        index = position + 3;
    }
    best
}

/// The brace-matched body of `fn name`, if the file declares one.
fn function_body<'a>(masked: &'a str, name: &str) -> Option<&'a str> {
    let source = masked.as_bytes();
    let needle = format!("fn {name}");
    let mut index = 0;
    while let Some(offset) = masked[index..].find(&needle) {
        let position = index + offset;
        let boundary_before = position == 0 || !is_ident_byte(source[position - 1]);
        let after = position + needle.len();
        let boundary_after = source.get(after).is_none_or(|byte| !is_ident_byte(*byte));
        if boundary_before && boundary_after {
            let end = item_end(source, after);
            return Some(&masked[position..end]);
        }
        index = position + needle.len();
    }
    None
}

fn line_of(masked: &str, at: usize) -> usize {
    masked[..at].matches('\n').count() + 1
}

/// Is the name starting at `at` the one being *declared* rather than called? `pub async fn
/// require_permission(` is the gate's definition, not a use of it.
fn is_declaration(masked: &str, at: usize) -> bool {
    let head = masked[..at].trim_end();
    let Some(rest) = head.strip_suffix("fn") else {
        return false;
    };
    rest.as_bytes()
        .last()
        .is_none_or(|byte| !is_ident_byte(*byte))
}

// ---------------------------------------------------------------------------------------------
// The scan
// ---------------------------------------------------------------------------------------------

struct Scan {
    /// Production source of every `chancela-api` module, comments/literals masked and
    /// `#[cfg(test)]` items removed, keyed by file name.
    sources: BTreeMap<String, String>,
    /// Verb (Rust variant identifier) → the `file:line` sites that check it.
    observed: BTreeMap<String, BTreeSet<String>>,
    /// `file::function anchor` → (occurrence count, sample `file:line`).
    unparsed: BTreeMap<String, (usize, String)>,
    anchors: usize,
}

fn scan() -> Scan {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = BTreeMap::new();
    for entry in fs::read_dir(&root).expect("the chancela-api source directory must be readable") {
        let path = entry.expect("source directory entry must be readable").path();
        assert!(
            !path.is_dir(),
            "{} contains a subdirectory: the scan walks a flat module tree and would miss it",
            root.display()
        );
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("Rust source filename must be UTF-8")
            .to_owned();
        let raw = fs::read_to_string(&path).expect("Rust source file must be readable");
        // `include_str!`/`read_to_string` yield whatever line endings the tree was checked out
        // with; `.gitattributes` is `* text=auto`, so this is LF on CI and CRLF on Windows.
        let normalized = raw.replace("\r\n", "\n");
        sources.insert(name, strip_test_regions(&mask_literals(&normalized)));
    }

    let mut observed: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut unparsed: BTreeMap<String, (usize, String)> = BTreeMap::new();
    let mut anchors = 0usize;

    for (name, source) in &sources {
        for anchor in CHECK_ANCHORS {
            let mut index = 0;
            while let Some(offset) = source[index..].find(*anchor) {
                let at = index + offset;
                index = at + 1;
                // `pub async fn require_permission(` declares the gate; it does not call it.
                if is_declaration(source, at) {
                    continue;
                }
                anchors += 1;
                let (from, to) = argument_span(source, at + anchor.len() - 1);
                let site = format!("{name}:{}", line_of(source, at));
                match permission_literal(&source[from..to]) {
                    Some(verb) => {
                        observed.entry(verb.to_owned()).or_default().insert(site);
                    }
                    None => {
                        let key =
                            format!("{name}::{} {anchor}", enclosing_function(source, at));
                        let slot = unparsed.entry(key).or_insert((0, site));
                        slot.0 += 1;
                    }
                }
            }
        }
    }

    Scan {
        sources,
        observed,
        unparsed,
        anchors,
    }
}

impl Scan {
    fn allowlist_key(site: &IndirectSite) -> String {
        format!("{}::{} {}", site.file, site.function, site.anchor)
    }

    /// Verbs the allowlisted indirect sites really carry, re-derived from the source rather than
    /// asserted. A stale claim here fails as loudly as an unlisted occurrence.
    fn resolve_indirect(&self) -> BTreeMap<String, BTreeSet<String>> {
        let mut resolved: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for site in INDIRECT_SITES {
            match site.resolution {
                Resolution::GateImplementation | Resolution::NotAnAuthorizationCheck => {}
                Resolution::ForwardedFrom(token) => {
                    let mut callers = 0usize;
                    for (name, source) in &self.sources {
                        let mut index = 0;
                        while let Some(offset) = source[index..].find(token) {
                            let at = index + offset;
                            index = at + 1;
                            if is_declaration(source, at) {
                                continue;
                            }
                            let (from, to) = argument_span(source, at + token.len() - 1);
                            let verb = permission_literal(&source[from..to]).unwrap_or_else(|| {
                                panic!(
                                    "{name}:{} calls the forwarding helper {token} without a \
                                     Permission:: literal, so the verb it carries cannot be \
                                     re-derived. Resolve it (or give it its own allowlist entry \
                                     with a reason) — do not loosen the matcher.",
                                    line_of(source, at)
                                )
                            });
                            callers += 1;
                            resolved
                                .entry(verb.to_owned())
                                .or_default()
                                .insert(format!("{name}:{} (via {token})", line_of(source, at)));
                        }
                    }
                    assert!(
                        callers > 0,
                        "{} claims verbs arrive through {token}, but nothing calls it",
                        Self::allowlist_key(site)
                    );
                }
                Resolution::LocalLiterals(functions) => {
                    let source = self
                        .sources
                        .get(site.file)
                        .unwrap_or_else(|| panic!("{} is no longer a module", site.file));
                    for function in functions {
                        let body = function_body(source, function).unwrap_or_else(|| {
                            panic!(
                                "{} names {function} as where its verbs are computed, but {} \
                                 declares no such function",
                                Self::allowlist_key(site),
                                site.file
                            )
                        });
                        let verbs = permission_literals(body);
                        assert!(
                            !verbs.is_empty(),
                            "{} claims {function} computes its verbs, but that body names no \
                             Permission:: literal",
                            Self::allowlist_key(site)
                        );
                        for verb in verbs {
                            resolved
                                .entry(verb)
                                .or_default()
                                .insert(format!("{}::{function} (computed)", site.file));
                        }
                    }
                }
            }
        }
        resolved
    }
}

// ---------------------------------------------------------------------------------------------
// The two halves
// ---------------------------------------------------------------------------------------------

/// **Half one: the matcher may not under-count.**
///
/// Every occurrence of every anchor either yields a `Permission::` literal or is a named entry in
/// [`INDIRECT_SITES`]. Both directions are asserted, so an unlisted occurrence and a listed one
/// that no longer occurs fail alike — the allowlist stays an exercised inventory. Without this,
/// [`enforcement_status_matches_the_real_authorization_call_sites`] could report a confident
/// "zero call sites" about a verb whose only gate passes the permission indirectly.
#[test]
fn every_authorization_check_occurrence_parses_or_is_explicitly_allowlisted() {
    let scan = scan();

    assert!(
        scan.sources.len() >= MIN_FILES_SCANNED,
        "only {} source files scanned — the walk likely broke",
        scan.sources.len()
    );
    assert!(
        scan.anchors >= MIN_ANCHOR_OCCURRENCES,
        "only {} authorization-check occurrences found — the masker or the test-region stripper \
         likely blanked live code, which would make every assertion below vacuous",
        scan.anchors
    );

    for site in INDIRECT_SITES {
        assert!(
            site.reason.len() >= 20,
            "{} carries no written reason. An allowlist entry without one is an unexplained \
             exemption, and the next reader cannot tell a deliberate indirection from a hole.",
            Scan::allowlist_key(site)
        );
    }

    let expected: BTreeMap<String, usize> = INDIRECT_SITES
        .iter()
        .map(|site| (Scan::allowlist_key(site), site.occurrences))
        .collect();
    assert_eq!(
        expected.len(),
        INDIRECT_SITES.len(),
        "INDIRECT_SITES has duplicate file::function+anchor keys; merge them and sum occurrences"
    );
    let actual: BTreeMap<String, usize> = scan
        .unparsed
        .iter()
        .map(|(key, (count, _))| (key.clone(), *count))
        .collect();

    for (key, (count, sample)) in &scan.unparsed {
        assert!(
            expected.contains_key(key),
            "UNRECOGNISED AUTHORIZATION CHECK: {key} ({count}x, e.g. {sample}) passes its \
             permission in a form this test cannot read, so it would be silently missed. Add an \
             INDIRECT_SITES entry naming how the verb is really derived, with a reason. Do NOT \
             widen the matcher to make it disappear."
        );
    }
    assert_eq!(
        actual, expected,
        "the indirect-call-site inventory drifted: every entry must still occur, exactly as often \
         as it claims"
    );

    // The allowlist is only sound if the resolutions it claims still hold; this panics loudly if
    // a forwarding helper or a locally computed verb can no longer be re-derived.
    let resolved = scan.resolve_indirect();
    assert!(
        !resolved.is_empty(),
        "no verb could be re-derived from any indirect site — the resolution rules broke"
    );
}

/// **Half two: the catalog's enforcement claim must match the crate.**
///
/// `Enforced` means at least one real check site; `FeatureNotBuilt` means none. The second is the
/// direction `chancela-authz` cannot guard, and the one that turns into an inverted security
/// statement — an auditor reading "this action does not exist yet" about a shipped feature.
///
/// When entity archiving ships (t60), the `entity.archive` arm must move to `Enforced` in the same
/// change as its first `require_permission`; this test is the signal if it does not.
#[test]
fn enforcement_status_matches_the_real_authorization_call_sites() {
    let scan = scan();
    let mut sites = scan.observed.clone();
    for (verb, found) in scan.resolve_indirect() {
        sites.entry(verb).or_default().extend(found);
    }

    let mut enforced_without_site = Vec::new();
    let mut not_built_with_site = Vec::new();

    for permission in Permission::ALL {
        let variant = format!("{permission:?}");
        let found = sites.get(&variant);
        match permission.enforcement() {
            PermissionEnforcement::Enforced => {
                if found.is_none() {
                    enforced_without_site.push(permission.as_str());
                }
            }
            PermissionEnforcement::FeatureNotBuilt => {
                if let Some(found) = found {
                    not_built_with_site.push(format!(
                        "{} — checked at {}",
                        permission.as_str(),
                        found.iter().cloned().collect::<Vec<_>>().join(", ")
                    ));
                }
            }
            PermissionEnforcement::ReachableUnchecked => {}
        }
    }

    assert!(
        not_built_with_site.is_empty(),
        "INVERTED SECURITY STATEMENT: these verbs gate a real handler, yet the catalog reports \
         them as FeatureNotBuilt — the RBAC matrix is telling an operator that a shipped, \
         enforced action does not exist:\n  {}\nMove each arm in \
         chancela-authz/src/permission_description.rs to Enforced, update the pinned \
         FEATURE_NOT_BUILT array, and rewrite the verb's description from its handlers.",
        not_built_with_site.join("\n  ")
    );
    assert!(
        enforced_without_site.is_empty(),
        "these verbs are advertised as Enforced but no authorization check in chancela-api names \
         them:\n  {}\nEither the gate was dropped from its handler — a live authorization hole — \
         or the arm should be FeatureNotBuilt. Do not silence this by relaxing the scan.",
        enforced_without_site.join("\n  ")
    );

    // Set equality, stated once: the verbs the crate really checks are exactly the verbs the
    // catalog calls Enforced. (`ReachableUnchecked` never ships — `chancela-authz` fails on it.)
    let checked: BTreeSet<&str> = Permission::ALL
        .into_iter()
        .filter(|permission| sites.contains_key(&format!("{permission:?}")))
        .map(Permission::as_str)
        .collect();
    let advertised: BTreeSet<&str> = Permission::ALL
        .into_iter()
        .filter(|permission| permission.enforcement() == PermissionEnforcement::Enforced)
        .map(Permission::as_str)
        .collect();
    assert_eq!(checked, advertised);
}
