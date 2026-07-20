//! Anti-leak inventory tripwire (wp27-e3, tenancy P3 — bounded audit).
//!
//! Multi-tenant isolation on the read path rests on every **tenant-reachable** `.values()`
//! read-lock scan either (a) filtering per row through the resolved `Authorizer`, (b) authorizing
//! an up-front scope and then narrowing the scan to that scope, or (c) filtering by an explicit
//! `tenant_id ==` predicate **after** a `require_tenant`/`scope_of_tenant` gate. A future edit that
//! adds a new *unfiltered* scan, or removes one of the frozen filters, would let a tenant-scoped
//! actor read another tenant's rows.
//!
//! This test freezes the audited scan surface two ways:
//!   1. **Per-handler filter freeze** — asserts each proven tenant-reachable enumeration still
//!      carries its tenant gate/filter (regression fails the build), mirroring the enumeration
//!      tripwire in `entities.rs`.
//!   2. **Inventory count freeze** — pins the number of `.values()` scans per audited file. Adding
//!      a scan trips this test, forcing the author to audit the new site for cross-tenant leakage
//!      and consciously update the inventory (with a note here) rather than slipping a leak in.
//!
//! Scope is deliberately BOUNDED (per the a1 tenancy audit): it covers the e3-owned
//! tenant-reachable handler files, NOT all ~152 `.values()` sites in the crate. Files that are
//! platform-global / `Global`-gated (unreachable by tenant-scoped users) or owner-partitioned
//! (stricter than tenant) are intentionally out of scope and documented in the wp27-e3 log.

const BOOKS: &str = include_str!("../src/books.rs");
const ACTS: &str = include_str!("../src/acts.rs");
const DOCUMENTS: &str = include_str!("../src/documents.rs");
const NOTIFICATIONS: &str = include_str!("../src/notifications.rs");
const GROUPS: &str = include_str!("../src/groups.rs");

/// Occurrences of `needle` in `haystack`.
fn count(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// The body of the function introduced by `header` (up to the next `\n    pub ` / `\nfn ` / EOF),
/// so a per-handler assertion cannot be satisfied by an unrelated function elsewhere in the file.
fn function_body<'a>(src: &'a str, header: &str) -> &'a str {
    let start = src
        .split_once(header)
        .unwrap_or_else(|| panic!("`{header}` not found — did the handler get renamed?"))
        .1;
    let end = start
        .find("\npub async fn ")
        .or_else(|| start.find("\npub(crate) async fn "))
        .or_else(|| start.find("\nasync fn "))
        .or_else(|| start.find("\nfn "))
        .unwrap_or(start.len());
    &start[..end]
}

#[test]
fn tenant_reachable_enumerations_retain_their_filters() {
    // books.rs — `list_book_acts`: up-front `book.read` on the book, then narrow to that book_id.
    let list_book_acts = function_body(BOOKS, "pub async fn list_book_acts");
    assert!(
        list_book_acts.contains("Permission::BookRead, scope_of_book(book_id)"),
        "list_book_acts lost its up-front per-book authorization — cross-tenant leak risk"
    );
    assert!(
        list_book_acts.contains("a.book_id == book_id"),
        "list_book_acts lost its narrow book_id filter — cross-tenant leak risk"
    );

    // books.rs — `list_books`: per-row `book.read` filter through the Authorizer.
    let list_books = function_body(BOOKS, "pub async fn list_books");
    assert!(
        list_books.contains("authz.permits(Permission::BookRead, scope_of_book(b.id))"),
        "list_books lost its per-row book.read tenant filter — cross-tenant leak risk"
    );

    // groups.rs — `list_groups`: tenant gate + explicit tenant_id filter.
    let list_groups = function_body(GROUPS, "pub(crate) async fn list_groups");
    assert!(
        list_groups.contains("require_tenant(&state, &actor, Permission::EntityRead, tenant_id)"),
        "list_groups lost its require_tenant gate — cross-tenant leak risk"
    );
    assert!(
        list_groups.contains("group.tenant_id == tenant_id"),
        "list_groups lost its explicit tenant_id filter — cross-tenant leak risk"
    );

    // groups.rs — `group_dashboard`: tenant gate on all read verbs + explicit tenant_id filter +
    // per-row authz on members.
    let group_dashboard = function_body(GROUPS, "pub(crate) async fn group_dashboard");
    assert!(
        group_dashboard.contains("authz.require(Permission::EntityRead, tenant_authz_scope)"),
        "group_dashboard lost its scope_of_tenant EntityRead gate — cross-tenant leak risk"
    );
    assert!(
        group_dashboard.contains("entity.tenant_id == tenant_id"),
        "group_dashboard lost its explicit tenant_id member filter — cross-tenant leak risk"
    );
    assert!(
        group_dashboard
            .contains("authz.permits(Permission::EntityRead, scope_of_entity(entity.id))"),
        "group_dashboard lost its per-row member authorization — cross-tenant leak risk"
    );

    // documents.rs — by-id generated document reads authorize on the resolved owning-act scope
    // AFTER the (global-keyed) `load_document_by_id` lookup, so a cross-tenant document id is a 403.
    let get_generated = function_body(DOCUMENTS, "pub async fn get_generated_document_pdf");
    assert!(
        get_generated.contains("load_document_by_id(&state, &document_id)"),
        "get_generated_document_pdf changed its by-id lookup — re-audit the authorization order"
    );
    assert!(
        get_generated.contains("scope_of_act(&state, doc.act_id)")
            && get_generated.contains("Permission::ActRead, scope"),
        "get_generated_document_pdf lost its post-lookup act.read authorization — cross-tenant leak risk"
    );

    // notifications.rs — triage is owner-partitioned (stricter than tenant): the owner is resolved
    // from the actor and the scan filters by it, so a user never sees another owner's entries.
    let entries_for_owner = function_body(NOTIFICATIONS, "fn entries_for_owner");
    assert!(
        entries_for_owner.contains("entry.owner == owner"),
        "entries_for_owner lost its owner filter — cross-owner (and thus cross-tenant) leak risk"
    );
    let list_triage = function_body(NOTIFICATIONS, "pub async fn list_notification_triage");
    assert!(
        list_triage.contains("owner_key(&actor)"),
        "list_notification_triage stopped deriving the owner from the actor — leak risk"
    );
}

#[test]
fn values_scan_inventory_is_frozen() {
    // (file label, live count, frozen count). Bumping a count REQUIRES auditing the new scan for
    // cross-tenant leakage (route it through the Authorizer / an explicit tenant predicate) and
    // recording the classification in `.orchestration/logs/wp27-e3.md`.
    let inventory: &[(&str, usize, usize)] = &[
        // books.rs: list_books (per-row authz) + list_book_acts (up-front authz + book filter).
        ("books.rs", count(BOOKS, ".values()"), 2),
        // acts.rs: no read-lock scan (frozen at 0 so a new one trips).
        ("acts.rs", count(ACTS, ".values()"), 0),
        // documents.rs: load_documents_for_act (up-front act authz) + load_document_by_id
        // (load-then-authorize on the owning act).
        ("documents.rs", count(DOCUMENTS, ".values()"), 2),
        // notifications.rs: owner-partitioned persistence/maintenance/list (not tenant data).
        ("notifications.rs", count(NOTIFICATIONS, ".values()"), 3),
        // groups.rs: tenant sub-resource surface — every scan is require_tenant-gated + tenant_id
        // filtered (uniqueness checks, list, dashboard, template libraries/revisions, membership).
        ("groups.rs", count(GROUPS, ".values()"), 14),
    ];

    for (file, live, frozen) in inventory {
        assert_eq!(
            live, frozen,
            "`{file}` now has {live} `.values()` scans, inventory freezes {frozen}. A new scan must \
             be audited for cross-tenant leakage (Authorizer per-row filter or explicit tenant \
             predicate) and this inventory + the wp27-e3 log updated before the count changes."
        );
    }
}
