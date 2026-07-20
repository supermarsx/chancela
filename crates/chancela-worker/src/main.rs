use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chancela_connectors::{CancellationToken, JobPurpose};
use chancela_worker::{DurableQueue, Worker, load_config};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "chancela-worker",
    version,
    about = "Durable Chancela sync/backup worker"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Consume durable jobs until interrupted.
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Recover the queue and process at most one ready job.
    Once {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Add an immutable job to the durable queue.
    Enqueue {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long, value_enum)]
        purpose: Purpose,
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        destination: String,
        #[arg(long, default_value = "application/octet-stream")]
        content_type: String,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Request cancellation of a queued or running job.
    Cancel {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        job_id: String,
    },
    /// Print the durable status and receipt for a job.
    Status {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        job_id: String,
    },
    /// Probe every configured target without exposing credentials.
    Probe {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Check that the running worker has a recent durable heartbeat.
    Healthcheck {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long, default_value_t = 120)]
        max_age_seconds: u64,
    },
    /// Parse and validate a credential-reference-only configuration.
    ValidateConfig {
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Purpose {
    Sync,
    Backup,
}

impl From<Purpose> for JobPurpose {
    fn from(value: Purpose) -> Self {
        match value {
            Purpose::Sync => Self::Sync,
            Purpose::Backup => Self::Backup,
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Run { config, data_dir } => {
            let config = load_config(&config).await?;
            let worker = Arc::new(Worker::with_environment_secrets(config, data_dir).await?);
            let shutdown = CancellationToken::default();
            let signal = shutdown.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                signal.cancel();
            });
            worker.run_until(shutdown).await?;
        }
        Command::Once { config, data_dir } => {
            let config = load_config(&config).await?;
            let worker = Worker::with_environment_secrets(config, data_dir).await?;
            worker.queue().recover().await?;
            let processed = worker.run_once().await?;
            println!("{}", serde_json::json!({ "processed": processed }));
        }
        Command::Enqueue {
            config,
            data_dir,
            purpose,
            source,
            destination,
            content_type,
            idempotency_key,
        } => {
            let config = load_config(&config).await?;
            let queue = DurableQueue::open(data_dir).await?;
            let result = queue
                .enqueue(
                    &config.source_root,
                    purpose.into(),
                    source,
                    destination,
                    content_type,
                    idempotency_key,
                )
                .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "created": result.created,
                    "job": result.job
                }))?
            );
        }
        Command::Cancel { data_dir, job_id } => {
            DurableQueue::open(data_dir).await?.cancel(&job_id).await?;
            println!(
                "{}",
                serde_json::json!({ "job_id": job_id, "cancel_requested": true })
            );
        }
        Command::Status { data_dir, job_id } => {
            let snapshot = DurableQueue::open(data_dir)
                .await?
                .snapshot(&job_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&snapshot)?);
        }
        Command::Probe { config, data_dir } => {
            let config = load_config(&config).await?;
            let worker = Worker::with_environment_secrets(config, data_dir).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&worker.probe_targets().await)?
            );
        }
        Command::Healthcheck {
            data_dir,
            max_age_seconds,
        } => {
            let queue = DurableQueue::open(data_dir).await?;
            if !queue
                .heartbeat_is_fresh(Duration::from_secs(max_age_seconds.clamp(1, 3_600)))
                .await?
            {
                return Err("worker heartbeat is stale or missing".into());
            }
            println!("ready");
        }
        Command::ValidateConfig { config } => {
            load_config(&config).await?;
            println!("valid");
        }
    }
    Ok(())
}
