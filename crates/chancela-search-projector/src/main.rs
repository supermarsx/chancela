use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use chancela_search_projector::{
    PROCESS_SHUTDOWN_GRACE, ProjectorOptions, ProjectorRunMode, bootstrap_state,
    healthcheck_from_env, resolve_health_max_age, run_projector, supervise_projector_task,
};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "chancela-search-projector", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Continuously project changed authoritative sources.
    Run {
        #[arg(long)]
        runtime_dir: Option<PathBuf>,
    },
    /// Publish at most one required generation, then exit.
    Once {
        #[arg(long)]
        runtime_dir: Option<PathBuf>,
    },
    /// Verify that the projector heartbeat exists, is valid, and is fresh.
    Healthcheck {
        #[arg(long)]
        runtime_dir: PathBuf,
        #[arg(long)]
        max_age_seconds: Option<u64>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // Persisted safe environment overrides can select the data directory/backend used by both the
    // healthcheck and the long-running projector. Apply them before either opens the narrow store.
    if let Some(data_dir) = chancela_runtime_config::resolve_data_dir() {
        chancela_runtime_config::env_overrides::apply_from_data_dir(&data_dir);
    }
    if let Command::Healthcheck {
        runtime_dir,
        max_age_seconds,
    } = &cli.command
    {
        let max_age = match resolve_health_max_age(None, *max_age_seconds) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::FAILURE;
            }
        };
        return match healthcheck_from_env(runtime_dir, max_age) {
            Ok(heartbeat) => {
                println!(
                    "healthy phase={:?} generation={} documents={} updated_at={}",
                    heartbeat.phase,
                    heartbeat.generation.unwrap_or(0),
                    heartbeat.document_count.unwrap_or(0),
                    heartbeat.updated_at
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }

    let (mode, runtime_dir) = match cli.command {
        Command::Run { runtime_dir } => (ProjectorRunMode::Run, runtime_dir),
        Command::Once { runtime_dir } => (ProjectorRunMode::Once, runtime_dir),
        Command::Healthcheck { .. } => unreachable!(),
    };
    let options = match ProjectorOptions::from_env(runtime_dir) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let bootstrap = match bootstrap_state() {
        Ok(bootstrap) => bootstrap,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let index_threads = bootstrap.config.index_threads.clamp(2, 16) as usize;
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(index_threads)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("failed to build projector runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let shutdown = Arc::new(AtomicBool::new(false));
    let projector_shutdown = shutdown.clone();
    let exit = runtime.block_on(async move {
        let projector = tokio::spawn(run_projector(bootstrap, options, mode, projector_shutdown));
        match supervise_projector_task(
            projector,
            shutdown,
            wait_for_shutdown_signal(),
            PROCESS_SHUTDOWN_GRACE,
        )
        .await
        {
            Ok(_) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        }
    });
    // The process-level supervisor already spent the one allowed grace budget. Do not add a second
    // runtime wait; any spawn_blocking call that outlived its aborted async wrapper is intentionally
    // left to process teardown and cannot bypass the durable projection CAS.
    runtime.shutdown_background();
    exit
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate()).ok();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = async {
            if let Some(signal) = &mut terminate {
                signal.recv().await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {}
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
