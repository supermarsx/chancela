//! `chancela` — the host-level operations CLI (Docker-style nested subcommands).
//!
//! This binary operates on the local Chancela **data directory** directly and OFFLINE, through the
//! committed `chancela-store` / `chancela-ledger` / `chancela-core` public APIs. It is **not** an
//! HTTP client of the api and does **not** go through the api's RBAC/session gate: whoever can run
//! it already has filesystem access to the data dir (= admin). Because of that, every destructive
//! command is guarded by an explicit `--yes` (or an interactive type-to-confirm), and honours the
//! store's export-first safety rail by default.
//!
//! The data dir is resolved like `chancela_api::AppState::resolve_data_dir`: `--data-dir` ›
//! `$CHANCELA_DATA_DIR` › an auto-detected `chancela-data/` › `./chancela-data`.

mod args;
mod commands;
mod util;

use std::process::ExitCode;

use clap::Parser;

use args::{BookCommand, Cli, Command, DataCommand, LedgerCommand, UserCommand};
use util::{Cmd, Ctx, resolve_data_dir};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let ctx = Ctx {
        data_dir: resolve_data_dir(cli.data_dir.clone()),
        actor: cli.actor.clone(),
        json: cli.json,
    };

    match dispatch(&ctx, cli.command) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Route a parsed command to its implementation.
fn dispatch(ctx: &Ctx, command: Command) -> Cmd {
    match command {
        Command::Serve(a) => commands::serve(ctx, a),
        Command::Status => commands::status(ctx),
        Command::Version => commands::version(),
        Command::Data { command } => match command {
            DataCommand::Wipe(a) => commands::data_wipe(ctx, a),
        },
        Command::Backup(a) => commands::backup(ctx, a),
        Command::Restore(a) => commands::restore(ctx, a),
        Command::Book { command } => match command {
            BookCommand::Export(a) => commands::book_export(ctx, a),
            BookCommand::Import(a) => commands::book_import(ctx, a),
            BookCommand::StartOver(a) => commands::book_start_over(ctx, a),
        },
        Command::Ledger { command } => match command {
            LedgerCommand::Verify => commands::ledger_verify(ctx),
            LedgerCommand::Integrity => commands::ledger_integrity(ctx),
            LedgerCommand::Reanchor(a) => commands::ledger_reanchor(ctx, a),
        },
        Command::User { command } => match command {
            UserCommand::Create(a) => commands::user_create(ctx, a),
            UserCommand::Ls => commands::user_ls(ctx),
        },
        Command::Migrate => commands::migrate(ctx),
    }
}
