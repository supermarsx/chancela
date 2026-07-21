//! Command implementations. Every command resolves the data dir, then drives the committed
//! store/ledger/core primitives OFFLINE — this is a host-level tool, never an api client.

use std::process::Command as ProcCommand;

use chancela_authz::{COMPANY_OWNER_ROLE_ID, OWNER_ROLE_ID, RoleAssignment, RoleId, Scope};
use chancela_core::BookId;
use chancela_ledger::{IntegrityReport, ReanchorError};
use chancela_store::recovery::{CollisionPolicy, ImportVerdict, ResetScope};
use chancela_store::schema::SCHEMA_VERSION;
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::args::{
    BackupArgs, BookExportArgs, BookImportArgs, BookStartOverArgs, PolicyArg, ReanchorArgs,
    RestoreArgs, ServeArgs, UserCreateArgs, WipeArgs,
};
use crate::util::{
    Cmd, Ctx, confirm, hex, now, read_users, server_binary, validate_username, write_users_atomic,
};

/// The chancela version (the CLI crate's version — the whole workspace shares one).
const VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------------------------
// version / serve
// ---------------------------------------------------------------------------------------------

/// `chancela version`.
pub fn version() -> Cmd {
    println!("chancela {VERSION}");
    Ok(true)
}

/// `chancela serve` — spawn the chancela-server binary, passing the resolved data dir (and addr)
/// through the env vars it reads. Inherits stdio and forwards the server's exit status.
pub fn serve(ctx: &Ctx, args: ServeArgs) -> Cmd {
    let bin = server_binary();
    let mut cmd = ProcCommand::new(&bin);
    cmd.env("CHANCELA_DATA_DIR", &ctx.data_dir);
    if let Some(addr) = &args.addr {
        cmd.env("CHANCELA_ADDR", addr);
    }
    println!(
        "Starting {} · data dir {}{}",
        bin.display(),
        ctx.data_dir.display(),
        args.addr
            .as_ref()
            .map(|a| format!(" · addr {a}"))
            .unwrap_or_default()
    );
    let status = cmd.status().map_err(|e| {
        format!(
            "failed to launch the server binary ({}): {e} — is chancela-server installed alongside chancela or on PATH?",
            bin.display()
        )
    })?;
    Ok(status.success())
}

// ---------------------------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------------------------

/// `chancela status` / `info`.
pub fn status(ctx: &Ctx) -> Cmd {
    let store = ctx.open_store()?;
    let loaded = store.load()?;
    let instance_id = store.instance_id()?;
    let report = &loaded.integrity;
    let entities = loaded.entities.len();
    let books = loaded.books.len();
    let acts = loaded.acts.len();
    let ledger_len = loaded.ledger.len();
    let healthy = report.healthy;

    if ctx.json {
        let value = json!({
            "data_dir": ctx.data_dir.to_string_lossy(),
            "instance_id": instance_id,
            "schema_version": SCHEMA_VERSION,
            "app_version": VERSION,
            "ledger_length": ledger_len,
            "healthy": healthy,
            "entities": entities,
            "books": books,
            "acts": acts,
            "integrity": report,
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(true);
    }

    println!("Chancela  v{VERSION}");
    println!("  Data dir       {}", ctx.data_dir.display());
    println!("  Instance id    {instance_id}");
    println!("  Schema         v{SCHEMA_VERSION}");
    println!(
        "  Ledger         {ledger_len} events · {}",
        if healthy {
            "chain verified"
        } else {
            "CHAIN BROKEN"
        }
    );
    if !healthy && let Some(b) = first_break(report) {
        println!(
            "  First break    {} — {} (chain_seq {:?})",
            b.chain, b.message, b.chain_seq
        );
    }
    println!("  Entities       {entities}");
    println!("  Books          {books}");
    println!("  Acts           {acts}");
    Ok(true)
}

/// The first located break across the global spine and every non-global chain, if any.
fn first_break(report: &IntegrityReport) -> Option<&chancela_ledger::ChainBreak> {
    report
        .global
        .first_break
        .as_ref()
        .or_else(|| report.chains.iter().find_map(|c| c.first_break.as_ref()))
}

// ---------------------------------------------------------------------------------------------
// migrate
// ---------------------------------------------------------------------------------------------

/// `chancela migrate` — opening the store forward-migrates it; report the resulting version.
pub fn migrate(ctx: &Ctx) -> Cmd {
    let _store = ctx.open_store()?;
    println!(
        "Store at {} is migrated to schema v{SCHEMA_VERSION}.",
        ctx.data_dir.join(chancela_store::DB_FILE).display()
    );
    Ok(true)
}

// ---------------------------------------------------------------------------------------------
// data wipe
// ---------------------------------------------------------------------------------------------

/// `chancela data wipe [--factory]`.
pub fn data_wipe(ctx: &Ctx, args: WipeArgs) -> Cmd {
    let scope = if args.factory {
        ResetScope::BackendFactory
    } else {
        ResetScope::BackendDomain
    };
    let export_first = !args.no_export;

    println!(
        "This will {}.",
        if args.factory {
            "FACTORY RESET — erase ALL data INCLUDING the ledger, to a blank first-run instance"
        } else {
            "WIPE domain data (entities/books/acts/documents/imports), PRESERVING the append-only ledger"
        }
    );
    println!("  Data dir      {}", ctx.data_dir.display());
    println!(
        "  Export-first  {}",
        if export_first {
            "yes — a full archive is written BEFORE anything is cleared"
        } else {
            "NO (--no-export)"
        }
    );
    println!(
        "  Note          if a chancela server is running against this data dir, stop it first."
    );

    let word = if args.factory {
        "factory-reset"
    } else {
        "wipe"
    };
    if !confirm(word, args.yes)? {
        println!("Aborted — nothing was changed.");
        return Ok(false);
    }

    let store = ctx.open_store()?;
    let mut ledger = store.load()?.ledger;
    let outcome = store.reset(
        &mut ledger,
        &ctx.data_dir,
        scope,
        export_first,
        &ctx.sidecars(),
        &ctx.actor,
        now(),
    )?;

    println!("Done.");
    if let Some(archive) = &outcome.export_archive {
        println!("  Archive       {}", archive.display());
    }
    println!("  Cleared       {}", outcome.cleared.join(", "));
    if args.factory {
        println!("  Ledger        destroyed (the retained archive is the record).");
    } else {
        println!(
            "  Ledger        preserved ({} events) · a data.wiped event was recorded.",
            ledger.len()
        );
    }
    Ok(true)
}

// ---------------------------------------------------------------------------------------------
// backup / restore
// ---------------------------------------------------------------------------------------------

/// `chancela backup`.
pub fn backup(ctx: &Ctx, args: BackupArgs) -> Cmd {
    let store = ctx.open_store()?;
    let manifest = store.backup(&ctx.data_dir, &ctx.sidecars())?;
    println!("Backup written.");
    println!("  Archive       {}", manifest.path);
    println!("  Size          {} bytes", manifest.bytes);
    println!(
        "  Ledger        {} events · {}",
        manifest.ledger_length,
        if manifest.ledger_verified {
            "verified"
        } else {
            "NOT verified"
        }
    );
    if let Some(out) = &args.out {
        std::fs::copy(&manifest.path, out)?;
        println!("  Copied to     {}", out.display());
    }
    Ok(true)
}

/// `chancela restore <archive>`.
pub fn restore(ctx: &Ctx, args: RestoreArgs) -> Cmd {
    println!("This will RESTORE the whole store from a backup, REPLACING the current database.");
    println!("  Archive       {}", args.archive.display());
    println!("  Data dir      {}", ctx.data_dir.display());
    println!("  Note          the archive is verified BEFORE the swap; a bad backup is refused.");
    println!(
        "  Note          if a chancela server is running against this data dir, stop it first."
    );
    if !confirm("restore", args.yes)? {
        println!("Aborted — nothing was changed.");
        return Ok(false);
    }

    let store = ctx.open_store()?;
    let mut ledger = store.load()?.ledger;
    let outcome = store.restore(&mut ledger, &args.archive, &ctx.data_dir, &ctx.actor, now())?;

    println!("Restored.");
    println!("  From          {}", outcome.restored_from.display());
    println!(
        "  Ledger        {} events · head {}",
        outcome.ledger_length,
        outcome.ledger_head.as_deref().unwrap_or("(empty)")
    );
    Ok(true)
}

// ---------------------------------------------------------------------------------------------
// book export / import / start-over
// ---------------------------------------------------------------------------------------------

/// Parse a `<book-id>` argument into a [`BookId`].
fn parse_book_id(raw: &str) -> Result<BookId, Box<dyn std::error::Error>> {
    Ok(BookId(Uuid::parse_str(raw.trim())?))
}

/// `chancela book export <book-id>`.
pub fn book_export(ctx: &Ctx, args: BookExportArgs) -> Cmd {
    let book_id = parse_book_id(&args.book_id)?;
    let store = ctx.open_store()?;
    let mut ledger = store.load()?.ledger;
    let outcome = store.export_book(&mut ledger, book_id, &ctx.data_dir, &ctx.actor, now())?;

    println!("Book exported.");
    println!("  Bundle        {}", outcome.path.display());
    println!("  Digest        {}", outcome.manifest.bundle_digest);
    println!(
        "  Book chain    {} events · {}",
        outcome.manifest.book_chain.length,
        if outcome.manifest.book_chain.verified {
            "verified"
        } else {
            "NOT verified"
        }
    );
    if let Some(out) = &args.out {
        std::fs::write(out, &outcome.bytes)?;
        println!("  Written to    {}", out.display());
    }
    Ok(true)
}

/// `chancela book import <bundle>`.
pub fn book_import(ctx: &Ctx, args: BookImportArgs) -> Cmd {
    let policy = match args.policy {
        PolicyArg::Refuse => CollisionPolicy::Refuse,
        PolicyArg::Quarantine => CollisionPolicy::QuarantineCopy,
    };
    let store = ctx.open_store()?;
    let mut ledger = store.load()?.ledger;
    let outcome = store.import_book(&mut ledger, &args.bundle, policy, &ctx.actor, now())?;

    println!("Bundle imported.");
    println!("  Import id     {}", outcome.import_id);
    println!("  Entity        {}", outcome.entity_id);
    println!("  Book          {}", outcome.book_id);
    println!("  Source        {}", outcome.source_instance_id);
    println!("  Collided      {}", outcome.collided);
    match &outcome.verdict {
        ImportVerdict::Verified => println!("  Verdict       verified"),
        ImportVerdict::Quarantined { break_ } => {
            println!("  Verdict       quarantined — {}", break_.message);
        }
    }
    Ok(true)
}

/// `chancela book start-over <book-id>`.
pub fn book_start_over(ctx: &Ctx, args: BookStartOverArgs) -> Cmd {
    let book_id = parse_book_id(&args.book_id)?;
    println!("This will ARCHIVE book {book_id} and create a fresh successor book shell.");
    println!("  The old book and its events are PRESERVED (append-only); an archive is retained.");
    if !confirm("start-over", args.yes)? {
        println!("Aborted — nothing was changed.");
        return Ok(false);
    }

    let store = ctx.open_store()?;
    let mut ledger = store.load()?.ledger;
    let outcome = store.start_over_book(
        &mut ledger,
        book_id,
        &args.reason,
        &ctx.actor,
        now(),
        &ctx.data_dir,
    )?;

    println!("Started over.");
    if let Some(old) = &outcome.old_book_id {
        println!("  Old book      {old}");
    }
    if let Some(new) = &outcome.new_book_id {
        println!("  New book      {new} (Created — open it with a termo de abertura)");
    }
    println!("  Archive       {}", outcome.archive_path.display());
    println!("  Digest        {}", outcome.archived_bundle_digest);
    Ok(true)
}

// ---------------------------------------------------------------------------------------------
// ledger verify / integrity / reanchor
// ---------------------------------------------------------------------------------------------

/// `chancela ledger verify` — a check: non-zero exit on a break.
pub fn ledger_verify(ctx: &Ctx) -> Cmd {
    let store = ctx.open_store()?;
    let loaded = store.load()?;
    match &loaded.chain_status {
        Ok(n) => {
            println!("Ledger verified: {n} events, chain intact.");
            Ok(true)
        }
        Err(e) => {
            println!("Ledger BROKEN: {e}");
            Ok(false)
        }
    }
}

/// `chancela ledger integrity` — a per-chain report.
pub fn ledger_integrity(ctx: &Ctx) -> Cmd {
    let store = ctx.open_store()?;
    let report = store.integrity_report()?;

    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(true);
    }

    println!(
        "Ledger integrity: {}",
        if report.healthy { "HEALTHY" } else { "BROKEN" }
    );
    print_chain("global", &report.global);
    for chain in &report.chains {
        print_chain(&chain.chain.to_string(), chain);
    }
    if !report.reanchored_segments.is_empty() {
        println!(
            "  Re-anchored:  {} disclosed segment(s) in the audit chain.",
            report.reanchored_segments.len()
        );
    }
    Ok(true)
}

/// Print one chain's status line, and its first break when broken.
fn print_chain(label: &str, status: &chancela_ledger::ChainStatus) {
    println!(
        "  {label}: {} events · {}{}",
        status.length,
        if status.verified {
            "verified"
        } else {
            "BROKEN"
        },
        status
            .head
            .map(|h| format!(" · head {}", &hex(&h)[..16.min(hex(&h).len())]))
            .unwrap_or_default()
    );
    if let Some(b) = &status.first_break {
        println!(
            "      first break: {} (chain_seq {:?})",
            b.message, b.chain_seq
        );
    }
}

/// `chancela ledger reanchor --reason <text>`.
pub fn ledger_reanchor(ctx: &Ctx, args: ReanchorArgs) -> Cmd {
    if args.reason.trim().is_empty() {
        return Err("--reason must not be empty".into());
    }
    println!("This will RE-ANCHOR the ledger: broken hashes are rebuilt in place (last resort).");
    println!(
        "  A permanent, chained ledger.reanchored disclosure is recorded — it is never hidden."
    );
    if !confirm("reanchor", args.yes)? {
        println!("Aborted — nothing was changed.");
        return Ok(false);
    }

    let store = ctx.open_store()?;
    let mut ledger = store.load()?.ledger;
    match ledger.reanchor(&ctx.actor, &args.reason, now()) {
        Ok(record) => {
            store.persist_reanchored_ledger(&ledger)?;
            println!("Re-anchored.");
            println!("  Reason        {}", record.reason);
            println!(
                "  Prev head     {}",
                record
                    .original_global_head
                    .map(|h| hex(&h))
                    .unwrap_or_else(|| "(empty)".to_owned())
            );
            println!("  New head      {}", hex(&record.new_global_head));
            println!("  Pre-anchor    {}", hex(&record.pre_reanchor_digest));
            println!("  Affected      {} chain segment(s)", record.affected.len());
            println!(
                "  Disclosure    a chained ledger.reanchored event permanently records this operation."
            );
            Ok(true)
        }
        Err(ReanchorError::AlreadyValid) => {
            println!("Ledger already verifies cleanly — nothing to re-anchor.");
            Ok(false)
        }
        Err(e) => Err(Box::new(e)),
    }
}

// ---------------------------------------------------------------------------------------------
// user create / ls
// ---------------------------------------------------------------------------------------------

/// The human role label for a known seeded role id.
///
/// These are the canonical **English** seeded names (t87) and match what the API stores, so CLI
/// output and `GET /v1/roles` agree. The CLI has no locale, so unlike the web client it does not
/// translate them; an unknown id falls back to the raw id rather than guessing a name.
fn role_label(role_id: RoleId) -> String {
    if role_id == OWNER_ROLE_ID {
        "Owner".to_owned()
    } else if role_id == COMPANY_OWNER_ROLE_ID {
        "Company Owner".to_owned()
    } else {
        role_id.0.to_string()
    }
}

/// The scope label for an assignment (bootstrap assignments are always `@Global`).
fn scope_label(scope: &Scope) -> String {
    match scope {
        Scope::Global => "Global".to_owned(),
        other => format!("{other:?}"),
    }
}

/// `chancela user create <username>` — first user on a fresh instance becomes Owner\@Global.
pub fn user_create(ctx: &Ctx, args: UserCreateArgs) -> Cmd {
    let username = validate_username(&args.username)?;
    let display_name = args
        .display_name
        .map(|d| d.trim().to_owned())
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| username.clone());

    let path = ctx.users_path();
    let mut users = read_users(&path)?;
    if users
        .iter()
        .any(|u| u.username.eq_ignore_ascii_case(&username))
    {
        return Err(format!("a user named {username:?} already exists").into());
    }

    let bootstrap = users.is_empty();
    let role_id = if bootstrap {
        OWNER_ROLE_ID
    } else {
        COMPANY_OWNER_ROLE_ID
    };
    let assignment = RoleAssignment::new(role_id, Scope::Global);
    let created_at = now().format(&Rfc3339).unwrap_or_default();

    // Build the profile through the committed `User` serde contract (fields we do not set —
    // password_hash / attestation_key / secret_source / recovery_hash — default via serde), so the
    // written document is exactly what the server reads. No secret material is ever set here.
    let user: chancela_api::User = serde_json::from_value(json!({
        "id": Uuid::new_v4().to_string(),
        "username": username,
        "display_name": display_name,
        "created_at": created_at,
        "active": true,
        "role_assignments": [serde_json::to_value(assignment)?],
    }))?;

    users.push(user);
    write_users_atomic(&path, &users)?;

    println!("User created.");
    println!("  Username      {username}");
    println!(
        "  Role          {}@{}",
        role_label(role_id),
        scope_label(&Scope::Global)
    );
    println!("  Profiles      {}", path.display());
    Ok(true)
}

/// `chancela user ls`.
pub fn user_ls(ctx: &Ctx) -> Cmd {
    let mut users = read_users(&ctx.users_path())?;
    users.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));

    if ctx.json {
        let view: Vec<_> = users
            .iter()
            .map(|u| {
                json!({
                    "id": u.id.to_string(),
                    "username": u.username,
                    "display_name": u.display_name,
                    "active": u.active,
                    "roles": u.role_assignments.iter().map(|a| json!({
                        "role": role_label(a.role_id),
                        "scope": scope_label(&a.scope),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&view)?);
        return Ok(true);
    }

    if users.is_empty() {
        println!("No users. Run `chancela user create <username>` to bootstrap the first Owner.");
        return Ok(true);
    }

    println!(
        "{:<24}  {:<28}  {:<7}  ROLES",
        "USERNAME", "DISPLAY NAME", "ACTIVE"
    );
    for u in &users {
        let roles = if u.role_assignments.is_empty() {
            "(none)".to_owned()
        } else {
            u.role_assignments
                .iter()
                .map(|a| format!("{}@{}", role_label(a.role_id), scope_label(&a.scope)))
                .collect::<Vec<_>>()
                .join(", ")
        };
        println!(
            "{:<24}  {:<28}  {:<7}  {roles}",
            u.username,
            u.display_name,
            if u.active { "yes" } else { "no" }
        );
    }
    Ok(true)
}
