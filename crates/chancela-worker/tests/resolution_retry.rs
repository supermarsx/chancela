//! What the worker does when resolving a claimed job's target fails *transiently*.
//!
//! Its own test binary because it is the only worker test that depends on process-global state:
//! the connector allowlist is read from `CHANCELA_CONNECTOR_ALLOWED_HOSTS` and
//! `CHANCELA_DATA_DIR`, and `NetworkPolicy` caches the resolution in a static. The tests here
//! share one data directory and take [`SERIAL`] so only one of them owns the runtime allowlist
//! document at a time.
//!
//! ## Why the allowlist document, and not DNS
//!
//! The failure this file exists for is a resolver blip. A real resolver cannot be made to fail and
//! then succeed inside one process, so these tests drive the *other* transient failure on the same
//! path and by the same rule: the runtime allowlist document being momentarily unreadable. Both are
//! `ErrorClass::Transient` at their source, both reach `resolve_connector` as a
//! `TargetResolution`, and the arm under test branches on the class alone — it cannot tell them
//! apart, which is exactly why testing one tests the other. The DNS half of the same rule is
//! covered by `durable_queue.rs`, where a host the allowlist forbids still dead-letters at once.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, Response, StatusCode};
use chancela_connectors::{
    ALLOWED_HOSTS_ENV, DATA_DIR_ENV, ErrorClass, InMemorySecretProvider, JobPurpose, LocalTarget,
    PurposeTargets, RUNTIME_ALLOWLIST_FILE, TargetConfig, WebDavAuth, WebDavTarget, WorkerTargets,
};
use chancela_worker::{JobSnapshot, JobState, Worker, WorkerConfig};

/// The tests below mutate one shared data directory and one process-global policy cache.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static ENVIRONMENT: Once = Once::new();

const TOKEN_REF: &str = "CHANCELA_CONNECTOR_SECRET_WEBDAV_TOKEN";

/// Retry delay used by these fixtures. Long enough that a job put back in the queue is provably not
/// claimable on the very next poll, short enough that exhausting three attempts stays quick.
const RETRY_MS: u64 = 250;

fn shared_data_dir() -> PathBuf {
    std::env::temp_dir().join("chancela-worker-resolution-retry-data")
}

/// Pin the deployment ceiling to the loopback address the stub server binds, and point the runtime
/// allowlist at a directory these tests own.
///
/// `127.0.0.1/32` is accepted by the *ceiling* parser and refused by the administrative one, which
/// is the correct asymmetry: a deployment may aim a connector at its own host, an administrator
/// saving a setting in the UI may not.
fn configure_environment() {
    ENVIRONMENT.call_once(|| {
        let data_dir = shared_data_dir();
        std::fs::create_dir_all(&data_dir).expect("create shared data directory");
        // SAFETY: the only writes to these variables in this binary, behind a `Once`, before any
        // test has spawned a task that reads them.
        unsafe {
            std::env::set_var(ALLOWED_HOSTS_ENV, "127.0.0.1/32");
            std::env::set_var(DATA_DIR_ENV, &data_dir);
        }
    });
}

fn runtime_allowlist_path() -> PathBuf {
    shared_data_dir().join(RUNTIME_ALLOWLIST_FILE)
}

/// Make the runtime allowlist document unreadable without making it absent.
///
/// A directory where a file belongs: `metadata` succeeds, so this is not the "not configured" case,
/// and `read` then fails — `load_runtime_allowlist`'s I/O arm, classified `Transient` because a
/// document that exists but could not be read says nothing about what it contains. Absent, by
/// contrast, means "no runtime narrowing" and resolves cleanly against the ceiling.
fn break_runtime_allowlist() {
    repair_runtime_allowlist();
    std::fs::create_dir_all(runtime_allowlist_path()).expect("occupy the allowlist document path");
}

fn repair_runtime_allowlist() {
    let path = runtime_allowlist_path();
    if path.is_dir() {
        std::fs::remove_dir_all(&path).expect("free the allowlist document path");
    } else if path.exists() {
        std::fs::remove_file(&path).expect("remove the allowlist document");
    }
}

/// A WebDAV endpoint that accepts everything.
///
/// The protocol itself is contract-tested in `chancela-connectors`; all this needs to do is let a
/// resolved connector complete an upload, so that "the job succeeded on a later attempt" is a real
/// receipt rather than an inference.
async fn spawn_webdav_stub() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind WebDAV stub");
    let address = listener.local_addr().expect("WebDAV stub address");
    let app = Router::new().fallback(async |request: Request<Body>| {
        // Draining the body matters: the connector streams the PUT, and dropping it unread would
        // surface as a transport error rather than the success this stub is standing in for.
        let _ = to_bytes(request.into_body(), usize::MAX).await;
        Response::builder()
            .status(StatusCode::CREATED)
            .body(Body::empty())
            .expect("WebDAV stub response")
    });
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{address}"), server)
}

async fn fixture(label: &str, max_job_attempts: u32) -> (PathBuf, WorkerConfig, Worker) {
    let root =
        std::env::temp_dir().join(format!("chancela-worker-{label}-{}", uuid::Uuid::new_v4()));
    let source_root = root.join("source");
    tokio::fs::create_dir_all(&source_root)
        .await
        .expect("create source root");
    // Both purpose targets are local, so building the worker never consults the network policy;
    // only the job-carried WebDAV target does, which is what puts the failure after the claim.
    let config = WorkerConfig {
        source_root,
        targets: WorkerTargets {
            purposes: PurposeTargets {
                sync: "sync-local".to_owned(),
                backup: "backup-local".to_owned(),
            },
            targets: vec![
                TargetConfig::Local(LocalTarget {
                    id: "sync-local".to_owned(),
                    root: root.join("sync-target"),
                }),
                TargetConfig::Local(LocalTarget {
                    id: "backup-local".to_owned(),
                    root: root.join("backup-target"),
                }),
            ],
        },
        poll_interval_ms: 50,
        max_parallel_jobs: 1,
        max_job_attempts,
        retry_initial_ms: RETRY_MS,
        retry_max_ms: RETRY_MS,
    };
    let secrets = Arc::new(InMemorySecretProvider::default());
    secrets.insert(TOKEN_REF, "stub-token");
    let worker = Worker::new(config.clone(), root.join("queue"), secrets)
        .await
        .expect("create worker");
    (root, config, worker)
}

async fn stage_webdav_job(worker: &Worker, config: &WorkerConfig, base_url: &str) -> String {
    let path = config.source_root.join("blip.bin");
    tokio::fs::write(&path, b"payload that must survive a blip")
        .await
        .expect("write source");
    let staged = worker
        .queue()
        .stage_for_target(
            &config.source_root,
            JobPurpose::Sync,
            PathBuf::from("blip.bin"),
            "tenant/blip.bin".to_owned(),
            "application/octet-stream".to_owned(),
            "resolution-blip".to_owned(),
            "tenant-a".to_owned(),
            TargetConfig::WebDav(WebDavTarget {
                id: "dav".to_owned(),
                base_url: format!("{base_url}/dav"),
                auth: WebDavAuth::Bearer {
                    token_ref: TOKEN_REF.to_owned(),
                },
                timeout_seconds: 10,
                allow_insecure_http: true,
            }),
        )
        .await
        .expect("stage the WebDAV job");
    worker
        .queue()
        .publish_staged(&staged.job.id)
        .await
        .expect("publish the staged job");
    staged.job.id
}

/// A second, always-resolvable job so every assertion about the failing one is also an assertion
/// that the queue behind it kept moving.
async fn enqueue_local_job(worker: &Worker, config: &WorkerConfig, key: &str) -> String {
    let path = config.source_root.join(format!("{key}.bin"));
    tokio::fs::write(&path, b"queued behind the blip")
        .await
        .expect("write source");
    worker
        .queue()
        .enqueue(
            &config.source_root,
            JobPurpose::Backup,
            PathBuf::from(format!("{key}.bin")),
            format!("tenant/{key}.bin"),
            "application/octet-stream".to_owned(),
            Some(key.to_owned()),
        )
        .await
        .expect("enqueue the local job")
        .job
        .id
}

/// Drain everything currently claimable. Every call must return `Ok`: a propagated error is the
/// process exiting, which is the failure mode all of this exists to prevent.
async fn drain(worker: &Worker) {
    while worker
        .run_once()
        .await
        .expect("the worker process must survive every resolution failure")
    {}
}

async fn snapshot(worker: &Worker, job_id: &str) -> JobSnapshot {
    worker.queue().snapshot(job_id).await.expect("job snapshot")
}

async fn wait_until_claimable(snapshot: &JobSnapshot) {
    let Some(not_before) = snapshot.latest_event.not_before_unix_millis else {
        return;
    };
    loop {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before the unix epoch")
            .as_millis() as u64;
        if now > not_before {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn remove_fixture(root: &Path) {
    let _ = tokio::fs::remove_dir_all(root).await;
}

/// The regression this file was written for: a transient resolution failure must cost the job a
/// backed-off retry, not its life.
///
/// Before this, `resolve_connector`'s failure arm consulted neither the error class nor the attempt
/// cap, so every failure it caught was terminal. A thirty-second outage on the path between a
/// worker and whatever tells it where to send bytes would therefore have moved the entire queue to
/// permanent `failed` in seconds — each job recoverable only by an authenticated stage-and-confirm
/// retry. The crash-loop that arm replaced was worse, but it at least left the jobs queued.
#[tokio::test]
async fn a_transient_resolution_failure_retries_and_the_job_succeeds_on_a_later_attempt() {
    let _serial = SERIAL.lock().await;
    configure_environment();
    break_runtime_allowlist();

    let (base_url, server) = spawn_webdav_stub().await;
    let (root, config, worker) = fixture("resolution-blip", 3).await;
    let blipped = stage_webdav_job(&worker, &config, &base_url).await;
    let behind = enqueue_local_job(&worker, &config, "behind").await;

    drain(&worker).await;

    let retrying = snapshot(&worker, &blipped).await;
    assert_eq!(
        retrying.latest_event.state,
        JobState::RetryScheduled,
        "a transient resolution failure must be retried, not dead-lettered"
    );
    assert_eq!(
        retrying.latest_event.error_class,
        Some(ErrorClass::Transient)
    );
    assert_eq!(retrying.latest_event.attempt, 1);
    assert!(retrying.receipt.is_none());
    assert!(
        retrying.latest_event.not_before_unix_millis.is_some(),
        "a retry with no not-before is the tight loop, not a retry"
    );
    assert_eq!(
        worker
            .queue()
            .attempt_count(&blipped)
            .await
            .expect("attempt count"),
        1,
        "the Running event must be written before resolution, or the cap can never be reached"
    );

    // The queue behind the failure kept draining — the property the terminal-failure arm bought,
    // which retrying must not give back.
    let following = snapshot(&worker, &behind).await;
    assert_eq!(following.latest_event.state, JobState::Succeeded);
    assert_eq!(
        tokio::fs::read(root.join("backup-target/tenant/behind.bin"))
            .await
            .expect("read the job queued behind the blip"),
        b"queued behind the blip"
    );

    // The blip passes.
    repair_runtime_allowlist();
    wait_until_claimable(&retrying).await;
    drain(&worker).await;

    let recovered = snapshot(&worker, &blipped).await;
    assert_eq!(
        recovered.latest_event.state,
        JobState::Succeeded,
        "the job the blip hit must complete once resolution works again"
    );
    assert_eq!(recovered.latest_event.attempt, 2);
    assert_eq!(
        worker
            .queue()
            .attempt_count(&blipped)
            .await
            .expect("attempt count"),
        2
    );
    let receipt = recovered
        .receipt
        .expect("a succeeded job carries a receipt");
    assert_eq!(receipt.attempt, 2);
    assert_eq!(receipt.upload.target_id, "dav");

    server.abort();
    remove_fixture(&root).await;
    repair_runtime_allowlist();
}

/// The trap the retry arm had to be built around.
///
/// `attempt_count` is derived by counting `Running` events. The old arm handled resolution failures
/// *before* that event was written, so the counter never advanced on this path — harmless only
/// because the path was terminal. Adding `attempt < max_job_attempts` to an arm that still ran
/// first would have compared a permanently frozen `1` against the cap and restored the unbounded
/// loop the terminal arm was written to kill.
///
/// So the assertion that matters here is not that the job ends `Failed` — it is
/// `attempt_count == max_job_attempts`. A terminal state alone would pass with the trap wide open.
#[tokio::test]
async fn a_transient_failure_repeated_past_the_cap_dead_letters_with_the_counter_advanced() {
    let _serial = SERIAL.lock().await;
    configure_environment();
    break_runtime_allowlist();

    let (base_url, server) = spawn_webdav_stub().await;
    let (root, config, worker) = fixture("resolution-exhausted", 3).await;
    let blipped = stage_webdav_job(&worker, &config, &base_url).await;
    let behind = enqueue_local_job(&worker, &config, "behind").await;

    // Bounded by construction: if the cap were not being enforced this loop would run out of
    // iterations rather than hang, and the assertions below would name why.
    let mut terminal = snapshot(&worker, &blipped).await;
    for _ in 0..8 {
        wait_until_claimable(&terminal).await;
        drain(&worker).await;
        terminal = snapshot(&worker, &blipped).await;
        if terminal.latest_event.state == JobState::Failed {
            break;
        }
    }

    assert_eq!(
        terminal.latest_event.state,
        JobState::Failed,
        "a transient failure that never clears must still dead-letter"
    );
    assert_eq!(
        terminal.latest_event.error_class,
        Some(ErrorClass::Transient)
    );
    assert_eq!(
        worker
            .queue()
            .attempt_count(&blipped)
            .await
            .expect("attempt count"),
        config.max_job_attempts,
        "the attempt counter must actually advance; a frozen counter is the unbounded loop"
    );
    assert_eq!(terminal.latest_event.attempt, config.max_job_attempts);
    assert!(terminal.receipt.is_none());

    // Terminal means terminal: nothing is left claimable, and the queue behind it still drained.
    assert!(
        !worker
            .run_once()
            .await
            .expect("the worker survives the dead-letter"),
        "a dead-lettered job must not be claimable again"
    );
    assert_eq!(
        snapshot(&worker, &behind).await.latest_event.state,
        JobState::Succeeded
    );

    server.abort();
    remove_fixture(&root).await;
    repair_runtime_allowlist();
}
