//! **Enforcement status** of every catalog verb (t56 §R8 / §R8.1).
//!
//! The RBAC matrix lets an administrator tick a permission into a função. That checkbox is a
//! promise: "the holder may do this". For two verbs in the catalog the promise is false — they
//! are seeded into roles, rendered in the UI, and gate **nothing**, because the capability they
//! name has never been built. Describing them from their *name* would be a security misstatement,
//! so the status is a fact the catalog carries on the wire and the UI renders.
//!
//! ## How this file was derived
//!
//! Not from the verb spellings. For each of the 53 catalog verbs every authorization check across
//! `crates/` was enumerated — `require_permission`, `require_permission_with`,
//! `Authorizer::{require, permits, holds_at_any_scope}` and `has_permission` — with `#[cfg(test)]`
//! regions excluded by brace matching, and the surviving sites resolved to their enclosing
//! handler. A verb is [`PermissionEnforcement::Enforced`] iff at least one such site exists in a
//! request handler.
//!
//! For a verb with **no** site, absence of a check is not the whole answer: the question is
//! whether the capability is nevertheless *reachable*. That was settled against the router itself
//! — every `.route(...)` registration in `chancela_api::router()`, which
//! `authz::ROUTE_CLASSIFICATION` and its `router_walk_every_route_is_classified` test hold in
//! exact set-equality. That equality was re-derived independently for this audit rather than taken
//! on trust: the router's path set and the table's key set matched exactly (299 each at the time of
//! writing), with an empty symmetric difference in both directions and no duplicate path on either
//! side — duplicates matter because a set-equality test would not otherwise notice them.
//!
//! The guarantee is the mechanism, not the number: a route added without a classification is
//! test-red, so no capability can reach the wire unclassified and quietly escape this audit.
//!
//! ## The three states, and why a boolean was not enough
//!
//! | state | meaning |
//! |---|---|
//! | [`Enforced`](PermissionEnforcement::Enforced) | ≥ 1 real check site in a handler |
//! | [`FeatureNotBuilt`](PermissionEnforcement::FeatureNotBuilt) | no check site **and** no route reaching the capability |
//! | [`ReachableUnchecked`](PermissionEnforcement::ReachableUnchecked) | no check site but a live route reaches the capability |
//!
//! A boolean would have collapsed the last two, and they are opposites: one is a capability that
//! does not exist, the other is a **live authorization hole**. `ReachableUnchecked` therefore
//! exists so the audit *cannot* silently record a hole as "not built". It is not a badge to
//! render — a verb in that state is a defect to fix, and
//! [`no_verb_ships_as_reachable_unchecked`](tests) fails the suite if one ever appears here.
//!
//! **This audit found none.** Both unenforced verbs are `FeatureNotBuilt`.
//!
//! ## The two phantom verbs
//!
//! They are equally *unenforced* but not equally far from existing, which is why the reasons are
//! recorded per verb rather than shared:
//!
//! - **`book.reopen`** — no reopen route exists (the router's only `reopen` is
//!   `/v1/acts/{id}/reopen`, which is acts and unrelated), **and the domain has no reverse
//!   transition**: `Book::open` requires `Created`, `Book::close` requires `Open`, and those two
//!   methods are the only writers of `Book::state`. Unbuildable without a domain-model change.
//! - **`tenant.admin`** — the tenant surface is `GET`/`POST /v1/tenants` and `GET
//!   /v1/tenants/{tenant_id}`; `tenants.rs` has exactly three handlers (create, list, get) and no
//!   mutation handler at all. The rename / configuration / archival authority its doc comment
//!   names has no endpoint. Unbuilt.
//!
//! Neither is reachable-and-unguarded: every tenant- and book-prefixed route is classified
//! `Gated`, and no route reaches a tenant-mutation or book-reopen capability in the first place.
//!
//! **`entity.archive` was the third, until t60 built it.** It is now `Enforced` by
//! `POST /v1/entities/{id}/archive` and `.../unarchive`. That transition is the reason this file
//! records a status per verb instead of describing verbs from their names: the moment the feature
//! landed, "this verb grants nothing" became a false statement about a live, permission-gated
//! route — and a false *reassurance* is worse than no note at all, because an auditor reading it
//! would conclude the checkbox was inert.

use serde::{Deserialize, Serialize};

use crate::permission::Permission;

/// Whether a catalog verb actually gates anything, and if not, why not.
///
/// Serialises to the wire form the RBAC matrix renders (`"enforced"`, `"feature_not_built"`,
/// `"reachable_unchecked"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PermissionEnforcement {
    /// At least one request handler checks this verb. Granting it grants real authority.
    #[serde(rename = "enforced")]
    Enforced,
    /// No handler checks this verb **and** no route reaches the capability it names. Granting it
    /// grants nothing — not because a check is missing, but because the action does not exist.
    #[serde(rename = "feature_not_built")]
    FeatureNotBuilt,
    /// No handler checks this verb but a live route reaches the capability anyway.
    ///
    /// **This is a defect, not a label.** A verb in this state means the operation can be
    /// performed without holding the verb that is supposed to gate it. Nothing may ship in this
    /// state; the variant exists so an audit cannot record such a hole as "not built".
    #[serde(rename = "reachable_unchecked")]
    ReachableUnchecked,
}

impl PermissionEnforcement {
    /// The stable wire id (matches the serde representation).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            PermissionEnforcement::Enforced => "enforced",
            PermissionEnforcement::FeatureNotBuilt => "feature_not_built",
            PermissionEnforcement::ReachableUnchecked => "reachable_unchecked",
        }
    }
}

impl std::fmt::Display for PermissionEnforcement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Permission {
    /// This verb's enforcement status, derived from real authorization call sites (see the module
    /// documentation for the derivation and its exhaustiveness argument).
    ///
    /// The `match` is **wildcard-free on purpose**: adding a 54th verb fails to compile here until
    /// somebody audits it, so a new permission cannot ship with an unexamined status. Each arm
    /// names the handlers whose checks establish it — those handler names are the evidence a
    /// description must be written from, never the verb's spelling.
    ///
    /// ```
    /// use chancela_authz::{Permission, PermissionEnforcement};
    ///
    /// assert_eq!(Permission::UserRead.enforcement(), PermissionEnforcement::Enforced);
    /// // Seeded into funções and rendered in the RBAC matrix, but gates nothing.
    /// assert_eq!(
    ///     Permission::BookReopen.enforcement(),
    ///     PermissionEnforcement::FeatureNotBuilt
    /// );
    /// ```
    #[must_use]
    pub const fn enforcement(self) -> PermissionEnforcement {
        use PermissionEnforcement::{Enforced, FeatureNotBuilt};
        match self {
            // --- Tenants ---
            // tenants.rs::{list_tenants (per-row `permits`), get_tenant}
            Permission::TenantRead => Enforced,
            // tenants.rs::create_tenant
            Permission::TenantCreate => Enforced,
            // NO call site and NO route. `tenants.rs` has three handlers — create, list, get — and
            // no mutation handler; the rename/configuration/archival surface this verb names has
            // never been built.
            Permission::TenantAdmin => FeatureNotBuilt,

            // --- Entities ---
            // entities.rs::{get_entity, list_entities, list_entities_page},
            // books.rs::list_books_page, chronology.rs::get_entity_chronology,
            // groups.rs::group_dashboard,
            // registry.rs::{get_entity_registry, registry_lookup, registry_auto_update_due_plan}
            Permission::EntityRead => Enforced,
            // entities.rs::create_entity, registry.rs::import_from_registry
            Permission::EntityCreate => Enforced,
            // entities.rs::patch_entity, groups.rs::{assign_entity, remove_entity}
            Permission::EntityUpdate => Enforced,
            // registry.rs::{import_into_entity, request_registry_auto_update}
            Permission::EntityRegistryImport => Enforced,
            // entities.rs::{archive_entity, unarchive_entity} — `POST /v1/entities/{id}/archive`
            // and `.../unarchive`, both `require_permission(EntityArchive, scope_of_entity(id))`.
            // One verb in both directions, and deliberately NOT `EntityUpdate`: the seeded Records
            // Manager holds this without `entity.update`, so gating archiving on the PATCH would
            // deny the one seeded role designed to do it.
            Permission::EntityArchive => Enforced,

            // --- Books ---
            // books.rs::{get_book, list_books, list_books_page, list_book_acts},
            // entities.rs::{list_entities, list_entities_page}, groups.rs::group_dashboard,
            // termo.rs::{get_abertura, get_abertura_document, get_abertura_signature_document,
            // get_encerramento}
            Permission::BookRead => Enforced,
            // books.rs::{create_book, patch_book},
            // termo.rs::{patch_abertura, advance_abertura, sign_abertura, sign_abertura_pkcs12,
            // open_from_termo}
            Permission::BookOpen => Enforced,
            // books.rs::close_book,
            // termo.rs::{patch_encerramento, advance_encerramento, sign_encerramento,
            // sign_encerramento_pkcs12, close_from_termo}
            Permission::BookClose => Enforced,
            // bundles.rs::export_book,
            // archive_package.rs::{export_book_archive_package, get_book_disposal_status,
            // simulate_book_disposal, get_book_local_dglab_interchange_manifest},
            // books.rs::get_legal_hold, zk_repository.rs::create_readability_package
            Permission::BookExport => Enforced,
            // bundles.rs::{import_book, preflight_import_book},
            // paper_import.rs::require_permission_for_report (the paper-book import surface)
            Permission::BookImport => Enforced,
            // bundles.rs::start_over_book
            Permission::BookStartOver => Enforced,
            // NO call site and NO route — and no domain transition to reach even if one were
            // written: `Book::open` requires `Created`, `Book::close` requires `Open`, and they are
            // the only writers of `Book::state`. A closed book is closed by construction.
            Permission::BookReopen => FeatureNotBuilt,

            // --- Legal hold ---
            // books.rs::{get_legal_hold, set_legal_hold, clear_legal_hold},
            // archive_package.rs::simulate_book_disposal (the `dry_run = false` execution)
            Permission::LegalHoldManage => Enforced,

            // --- Acts ---
            // The broadest read verb in the catalog: acts.rs::{get_act, get_compliance,
            // preview_act_body}, the whole documents.rs read/preview surface, followups.rs,
            // notifications.rs triage, groups.rs template-library reads, signature.rs status and
            // signed-document reads, the signature-validation inspectors, scap.rs, dashboard.rs.
            Permission::ActRead => Enforced,
            // acts.rs::draft_act,
            // paper_import.rs::create_act_draft_from_accepted_paper_book_ocr_draft
            Permission::ActDraft => Enforced,
            // acts.rs::{patch_act, convening_dispatch, reopen_act},
            // followups.rs::{create_follow_up, patch_follow_up, complete_follow_up}
            Permission::ActEdit => Enforced,
            // acts.rs::{advance_act, verify_ai_human_review}
            Permission::ActAdvance => Enforced,
            // acts.rs::revert_act
            Permission::ActRevert => Enforced,
            // acts.rs::archive_act
            Permission::ActArchive => Enforced,

            // --- Signing ---
            // The largest gated surface: signature.rs (local PKCS#12, Cartão de Cidadão, CMD,
            // remote/batch, external-signer invites, archive timestamps, DSS/revocation evidence,
            // official-signature import), asic_signing.rs, xades_signature.rs, batch_signing.rs,
            // external_signing.rs, ltv.rs, scap.rs::sign_with_attribute,
            // acts.rs::{seal_act_handler, reopen_act},
            // termo.rs::{sign_abertura_pkcs12, sign_encerramento_pkcs12}
            Permission::SigningPerform => Enforced,
            // settings.rs::put_settings (the signing slice),
            // provider_credentials_write.rs::{create_entry, update_entry, delete_entry,
            // reorder_entries, probe_entry}, signature.rs::{get_cc_bridge_status, test_cc_bridge}
            Permission::SigningConfigure => Enforced,

            // --- Documents ---
            // documents.rs::{generate_document, import_document, review_imported_document,
            // record_generated_document_dispatch_evidence, get_generated_document_pdf}
            Permission::DocumentGenerate => Enforced,

            // --- Templates ---
            // documents.rs::{persist_created_user_template, replace_template, delete_template,
            // delete_template_version, rename_template_version, template_import_dry_run,
            // stored_user_template},
            // groups.rs::{patch_template_library, append_template_library_revision,
            // archive_template_library}
            Permission::TemplateManage => Enforced,

            // --- Full search ---
            // search.rs::query (`holds_at_any_scope` admission gate), search.rs::status,
            // search.rs::document_allowed (per-row `permits`, so no row escapes its own read verb)
            Permission::SearchRead => Enforced,
            // search.rs::{admin_command, status, query (indexer controls)},
            // settings.rs::{get_search_settings, put_search_settings}
            Permission::SearchManage => Enforced,

            // --- Ledger ---
            // ledger.rs::{list_ledger_events, list_ledger_events_page, verify_ledger,
            // get_attestation}, recovery.rs::get_integrity, arquivo.rs::export_archive_document,
            // entities.rs list views, groups.rs::group_dashboard
            Permission::LedgerRead => Enforced,
            // Read-only recovery evidence only, after the mutating halves were split off:
            // backup_recovery.rs::{create_backup_recovery_drill, list_backup_recovery_drills},
            // sync_handoff.rs::get_sync_handoff_preflight, dashboard.rs::dashboard
            Permission::LedgerRecover => Enforced,
            // recovery.rs::reanchor_ledger
            Permission::LedgerReanchor => Enforced,
            // recovery.rs::{restore_store, restore_store_preflight}
            Permission::LedgerRestore => Enforced,

            // --- Data ---
            // backup.rs::create_backup, connector_jobs.rs::materialize_artifact,
            // dashboard.rs::dashboard
            Permission::DataBackup => Enforced,
            // zk_repository.rs::object_for_route, dashboard.rs::dashboard
            Permission::DataExport => Enforced,
            // data.rs::reset_data
            Permission::DataWipe => Enforced,
            // data.rs::start_over_instance
            Permission::DataStartOver => Enforced,

            // --- Privacy & retention ---
            // privacy.rs::require_privacy_manage gates the GDPR record families (processors,
            // DPIAs + the DPIA template, breach playbooks, transfer controls); the data-subject
            // surface checks it directly (export_user, create/patch/list DSR requests,
            // complete_dsr_request, record_subject_annotation, erasure preflight/approve/execute).
            Permission::PrivacyManage => Enforced,
            // privacy.rs::require_retention_manage gates retention policies (create/patch/list),
            // due candidates, executions and their review closure, candidate resolutions and the
            // policy dry run.
            Permission::RetentionManage => Enforced,

            // --- Settings ---
            // settings.rs::get_settings plus the per-area reads: data_status.rs::get_data_status,
            // env_overrides_handler.rs::get_server_env, platform_logs.rs::list_logs,
            // platform_ops.rs::list_services, smtp_settings.rs reads, provider-credential status
            // and listing, connector target reads, zk_repository.rs status/policy/listing,
            // external_validator_evidence.rs report reads
            Permission::SettingsRead => Enforced,
            // settings.rs::put_settings plus the per-area writes: smtp_settings.rs (password,
            // test send, resend), env_overrides_handler.rs::put_server_env,
            // platform_ops.rs::control_service, data_status.rs::{cleanup_data,
            // preflight_data_key_rotation, execute_data_key_rotation}, connector target
            // create/patch/archive, zk_repository.rs repository + policy writes,
            // external_validator_evidence.rs::create_external_validator_report_metadata
            Permission::SettingsManage => Enforced,

            // --- Platform operations ---
            // platform_logs.rs::ingest_forwarded_log — a `permits` check that refuses with a 403
            // and appends a denial event, so a refusal is itself recorded.
            Permission::PlatformLogsWrite => Enforced,

            // --- Reference ---
            // cae.rs::{list_cae, get_cae, list_children, list_sections, cae_updates}, and
            // trust.rs::require_trust_read — the trust catalog is read under `cae.read`.
            Permission::CaeRead => Enforced,
            // cae.rs::refresh_cae
            Permission::CaeRefresh => Enforced,
            // law.rs::{list_law, get_law_diploma, get_law_article, get_law_pdf, list_law_corpus,
            // search_law_corpus, resolve_law_citations}
            Permission::LawRead => Enforced,
            // law.rs::{fetch_law, delete_law_pdf}
            Permission::LawManage => Enforced,

            // --- Trust services ---
            // trust.rs::require_trust_manage — one call site, `refresh_trust_tsl`. Reading the
            // trust catalog is `cae.read`; only the import is gated here.
            Permission::TrustManage => Enforced,

            // --- Users ---
            // users.rs::{list_users, list_users_page, get_user}
            Permission::UserRead => Enforced,
            // users.rs::{patch_user, set_secret, remove_secret, issue_recovery,
            // generate_attestation_key, remove_attestation_key, authorize_user_creation},
            // totp.rs::get_two_factor,
            // apikeys.rs::require_interactive_api_key_admin (list/create/revoke/rotate API keys)
            Permission::UserManage => Enforced,
            // signup.rs::issue_invite
            Permission::UserInvite => Enforced,

            // --- RBAC meta ---
            // roles.rs::{create_role, patch_role, delete_role,
            // seeded_role_reconciliation_proposal, apply_seeded_role_reconciliation}
            Permission::RoleManage => Enforced,
            // roles.rs::{assign_role, unassign_role}, users.rs::authorize_user_creation,
            // signup.rs::issue_invite
            Permission::RoleAssign => Enforced,
            // delegations.rs::grant_delegation
            Permission::DelegationGrant => Enforced,
            // delegations.rs::{revoke_delegation, set_suspended, list_delegations}
            Permission::DelegationRevoke => Enforced,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The audited set of verbs that gate nothing. Pinned as data so a future change that starts
    /// enforcing one — or that lets a third verb decay into a phantom — has to come through here.
    ///
    /// `entity.archive` was the third until t60 shipped `POST /v1/entities/{id}/archive`; this
    /// list shrinking is the intended direction of travel.
    const FEATURE_NOT_BUILT: [Permission; 2] = [Permission::TenantAdmin, Permission::BookReopen];

    #[test]
    fn the_phantom_set_is_exactly_the_audited_two() {
        let actual: Vec<Permission> = Permission::ALL
            .into_iter()
            .filter(|p| p.enforcement() == PermissionEnforcement::FeatureNotBuilt)
            .collect();
        assert_eq!(
            actual,
            FEATURE_NOT_BUILT.to_vec(),
            "the set of verbs that gate nothing changed. If a verb became enforced, move it to \
             Enforced and rewrite its description — a description that says a verb grants nothing \
             when it now grants something is a security misstatement. If a NEW verb turned up \
             here, an operator is being offered a checkbox that does nothing: fix the feature or \
             remove the verb."
        );
    }

    /// **The state that must never ship.** `ReachableUnchecked` means a live route performs an
    /// operation without checking the verb that is supposed to gate it — an authorization hole. It
    /// is representable so an audit cannot quietly record a hole as "not built"; it is not
    /// renderable, and a verb in that state is a defect to fix, never a badge to translate.
    #[test]
    fn no_verb_ships_as_reachable_unchecked() {
        for p in Permission::ALL {
            assert_ne!(
                p.enforcement(),
                PermissionEnforcement::ReachableUnchecked,
                "{p} is reachable through a live route that does not check it. This is an \
                 authorization hole, not a UI state — fix the handler; do not ship the label."
            );
        }
    }

    /// Every verb the catalog offers must have an audited status. `enforcement()`'s wildcard-free
    /// `match` makes a *new* variant a compile error; this pins the other direction, that `ALL` and
    /// the audit stay the same population.
    #[test]
    fn every_catalog_verb_has_an_enforcement_status() {
        let enforced = Permission::ALL
            .into_iter()
            .filter(|p| p.enforcement() == PermissionEnforcement::Enforced)
            .count();
        assert_eq!(
            enforced + FEATURE_NOT_BUILT.len(),
            Permission::ALL.len(),
            "every catalog verb must be either enforced or audited as not-built"
        );
        // 50 at audit time; 51 once t60 made `entity.archive` real.
        assert_eq!(enforced, 51);
    }

    /// The phantoms are seeded into real funções — that is *why* they matter. An administrator
    /// ticking one in the RBAC matrix is granting a capability that does not exist, so the UI has
    /// to say so rather than describe the verb's name.
    #[test]
    fn the_phantom_verbs_are_actually_granted_by_seeded_roles() {
        let seeded = crate::default_roles();
        for p in FEATURE_NOT_BUILT {
            let granting: Vec<&str> = seeded
                .iter()
                .filter(|r| r.permission_set.contains(&p))
                .map(|r| r.name.as_str())
                .collect();
            assert!(
                !granting.is_empty(),
                "{p} gates nothing yet is not seeded anywhere — re-check the audit"
            );
        }

        // How wide the misstatement is: seeded funções that hand out at least one verb which
        // gates nothing. Pinned so the blast radius cannot grow unnoticed.
        let affected: Vec<&str> = seeded
            .iter()
            .filter(|r| {
                FEATURE_NOT_BUILT
                    .iter()
                    .any(|p| r.permission_set.contains(p))
            })
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            affected,
            vec![
                "Owner",
                "Company Owner",
                "Platform Administrator",
                "Tenant Administrator",
            ],
            "the set of seeded funções granting a verb that gates nothing changed"
        );
    }

    #[test]
    fn enforcement_serialises_to_its_stable_wire_id() {
        for (state, wire) in [
            (PermissionEnforcement::Enforced, "\"enforced\""),
            (
                PermissionEnforcement::FeatureNotBuilt,
                "\"feature_not_built\"",
            ),
            (
                PermissionEnforcement::ReachableUnchecked,
                "\"reachable_unchecked\"",
            ),
        ] {
            assert_eq!(serde_json::to_string(&state).unwrap(), wire);
            assert_eq!(
                serde_json::from_str::<PermissionEnforcement>(wire).unwrap(),
                state
            );
            assert_eq!(format!("\"{}\"", state.as_str()), wire);
        }
    }
}
