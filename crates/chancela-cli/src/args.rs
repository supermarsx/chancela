//! The Docker-style command tree, declared with `clap` derive.
//!
//! Shape: `chancela [GLOBAL] <group> <command> [ARGS]`. Global options (`--data-dir`, `--actor`,
//! `--json`) apply to every subcommand. Destructive commands carry `-y/--yes`; `--help` is
//! generated for every command and flag by clap.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// The `chancela` host-level operations tool: it operates on the local data directory OFFLINE (via
/// the store/ledger/core crates), NOT through the HTTP API — whoever runs it already has filesystem
/// access. Destructive commands require an explicit `--yes` (or an interactive type-to-confirm).
#[derive(Debug, Parser)]
#[command(
    name = "chancela",
    version,
    about = "Chancela host-level operations tool (offline, operates on the local data dir).",
    propagate_version = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Data directory to operate on. Falls back to $CHANCELA_DATA_DIR, then an auto-detected
    /// `chancela-data/` (walking up from the current dir), then `./chancela-data`.
    #[arg(long, global = true, value_name = "DIR")]
    pub data_dir: Option<PathBuf>,

    /// Actor name recorded in the audit ledger for host-level operations.
    #[arg(long, global = true, default_value = "cli", value_name = "NAME")]
    pub actor: String,

    /// Emit machine-readable JSON (read commands: status, ledger integrity, user ls).
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// The top-level command groups (Docker-style).
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the Chancela server (HTTP API + web UI).
    #[command(alias = "up")]
    Serve(ServeArgs),

    /// Instance summary: data dir, instance id, schema, ledger + integrity, entity/book/act counts.
    #[command(alias = "info")]
    Status,

    /// Print the chancela version.
    Version,

    /// Domain-data management (wipe / factory reset).
    Data {
        #[command(subcommand)]
        command: DataCommand,
    },

    /// Take a whole-store backup archive (SQLite snapshot + sidecars + manifest).
    Backup(BackupArgs),

    /// Restore the whole store from a verified backup archive (verify-before-swap).
    Restore(RestoreArgs),

    /// Per-book bundle operations (export / import / start-over).
    Book {
        #[command(subcommand)]
        command: BookCommand,
    },

    /// Ledger verification and recovery.
    Ledger {
        #[command(subcommand)]
        command: LedgerCommand,
    },

    /// User provisioning (bootstrap the first Owner / list profiles).
    User {
        #[command(subcommand)]
        command: UserCommand,
    },

    /// Open the store, running (and reporting) any forward schema migration.
    Migrate,
}

/// `chancela serve` / `chancela up`.
#[derive(Debug, Args)]
pub struct ServeArgs {
    /// host:port to bind (passed as CHANCELA_ADDR; default 127.0.0.1:8080).
    #[arg(long, value_name = "ADDR")]
    pub addr: Option<String>,
}

/// `chancela backup`.
#[derive(Debug, Args)]
pub struct BackupArgs {
    /// Also copy the produced archive to this path (in addition to `<data-dir>/backups/`).
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
}

/// `chancela restore <archive>`.
#[derive(Debug, Args)]
pub struct RestoreArgs {
    /// The backup archive (.zip) to restore from.
    #[arg(value_name = "ARCHIVE")]
    pub archive: PathBuf,

    /// Proceed without the interactive type-to-confirm prompt.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

/// `chancela data …`.
#[derive(Debug, Subcommand)]
pub enum DataCommand {
    /// Clear domain data (default: preserve the ledger; `--factory`: full blank first-run reset).
    Wipe(WipeArgs),
}

/// `chancela data wipe`.
#[derive(Debug, Args)]
pub struct WipeArgs {
    /// Full factory reset: erase EVERYTHING including the ledger, to a blank first-run instance.
    #[arg(long)]
    pub factory: bool,

    /// Proceed without the interactive type-to-confirm prompt.
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Skip the export-first archive (by default an archive is written before anything is cleared).
    #[arg(long = "no-export")]
    pub no_export: bool,
}

/// `chancela book …`.
#[derive(Debug, Subcommand)]
pub enum BookCommand {
    /// Export one book to a self-verifying `chancela-book-bundle/v1` archive.
    Export(BookExportArgs),

    /// Import a per-book bundle (verify-before-trust; a broken bundle is quarantined, never merged).
    Import(BookImportArgs),

    /// Archive a book, then create a fresh successor book shell (the old book is preserved).
    #[command(name = "start-over")]
    StartOver(BookStartOverArgs),
}

/// `chancela book export <book-id>`.
#[derive(Debug, Args)]
pub struct BookExportArgs {
    /// The book id (uuid) to export.
    #[arg(value_name = "BOOK_ID")]
    pub book_id: String,

    /// Also write the bundle bytes to this path (in addition to `<data-dir>/exports/`).
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
}

/// `chancela book import <bundle>`.
#[derive(Debug, Args)]
pub struct BookImportArgs {
    /// The bundle archive (.zip) to import.
    #[arg(value_name = "BUNDLE")]
    pub bundle: PathBuf,

    /// What to do when the book id already exists (live or imported).
    #[arg(long, value_enum, default_value_t = PolicyArg::Refuse)]
    pub policy: PolicyArg,
}

/// `chancela book start-over <book-id>`.
#[derive(Debug, Args)]
pub struct BookStartOverArgs {
    /// The book id (uuid) to start over.
    #[arg(value_name = "BOOK_ID")]
    pub book_id: String,

    /// The reason recorded in the chained `ledger.reinitialized` disclosure.
    #[arg(long, default_value = "host-level start-over")]
    pub reason: String,

    /// Proceed without the interactive type-to-confirm prompt.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

/// Import collision policy on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PolicyArg {
    /// Refuse the import on any id collision (safe default).
    Refuse,
    /// Keep an isolated, read-only quarantine copy under the ORIGINAL ids.
    Quarantine,
}

/// `chancela ledger …`.
#[derive(Debug, Subcommand)]
pub enum LedgerCommand {
    /// Verify the whole chain; non-zero exit on a break.
    Verify,

    /// Per-chain integrity report (global spine + every chain, with the first break located).
    Integrity,

    /// Last-resort re-anchor of a broken chain (rebuilds hashes; prints the permanent disclosure).
    Reanchor(ReanchorArgs),
}

/// `chancela ledger reanchor`.
#[derive(Debug, Args)]
pub struct ReanchorArgs {
    /// The required, non-empty human reason for this last-resort operation.
    #[arg(long)]
    pub reason: String,

    /// Proceed without the interactive type-to-confirm prompt.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

/// `chancela user …`.
#[derive(Debug, Subcommand)]
pub enum UserCommand {
    /// Create a user profile (the first user on a fresh instance becomes Owner).
    Create(UserCreateArgs),

    /// List user profiles.
    Ls,
}

/// `chancela user create <username>`.
#[derive(Debug, Args)]
pub struct UserCreateArgs {
    /// The username (lowercase slug: a-z, 0-9, '.', '_', '-').
    #[arg(value_name = "USERNAME")]
    pub username: String,

    /// A human display name (defaults to the username).
    #[arg(long = "display-name", value_name = "NAME")]
    pub display_name: Option<String>,
}
