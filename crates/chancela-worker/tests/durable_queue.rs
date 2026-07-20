use std::path::{Path, PathBuf};
use std::sync::Arc;

use chancela_connectors::{
    InMemorySecretProvider, JobPurpose, LocalTarget, PurposeTargets, TargetConfig, WorkerTargets,
};
use chancela_worker::{DurableQueue, JobState, Worker, WorkerConfig, WorkerError};

fn isolated_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("chancela-worker-{label}-{}", uuid::Uuid::new_v4()))
}

async fn fixture(label: &str) -> (PathBuf, WorkerConfig, Worker) {
    let root = isolated_root(label);
    let source_root = root.join("source");
    tokio::fs::create_dir_all(&source_root)
        .await
        .expect("create source root");
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
        max_parallel_jobs: 2,
        max_job_attempts: 3,
        retry_initial_ms: 10,
        retry_max_ms: 100,
    };
    let worker = Worker::new(
        config.clone(),
        root.join("queue"),
        Arc::new(InMemorySecretProvider::default()),
    )
    .await
    .expect("create worker");
    (root, config, worker)
}

async fn write_source(config: &WorkerConfig, relative: &str, bytes: &[u8]) {
    let path = config.source_root.join(relative);
    tokio::fs::create_dir_all(path.parent().expect("source parent"))
        .await
        .expect("create source directory");
    tokio::fs::write(path, bytes).await.expect("write source");
}

async fn enqueue(
    queue: &DurableQueue,
    config: &WorkerConfig,
    purpose: JobPurpose,
    source: &str,
    destination: &str,
    key: &str,
) -> chancela_worker::EnqueueResult {
    queue
        .enqueue(
            &config.source_root,
            purpose,
            PathBuf::from(source),
            destination.to_owned(),
            "application/octet-stream".to_owned(),
            Some(key.to_owned()),
        )
        .await
        .expect("enqueue job")
}

async fn remove_fixture(root: &Path) {
    tokio::fs::remove_dir_all(root)
        .await
        .expect("remove fixture");
}

#[tokio::test]
async fn routes_sync_and_backup_to_distinct_targets_with_durable_receipts() {
    let (root, config, worker) = fixture("routing").await;
    write_source(&config, "sync.bin", b"sync payload").await;
    write_source(&config, "backup.bin", b"backup payload").await;

    let sync = enqueue(
        worker.queue(),
        &config,
        JobPurpose::Sync,
        "sync.bin",
        "tenant/sync.bin",
        "sync-key",
    )
    .await;
    let backup = enqueue(
        worker.queue(),
        &config,
        JobPurpose::Backup,
        "backup.bin",
        "tenant/backup.bin",
        "backup-key",
    )
    .await;

    assert!(worker.run_once().await.expect("run first job"));
    assert!(worker.run_once().await.expect("run second job"));
    assert_eq!(
        tokio::fs::read(root.join("sync-target/tenant/sync.bin"))
            .await
            .expect("read synced file"),
        b"sync payload"
    );
    assert_eq!(
        tokio::fs::read(root.join("backup-target/tenant/backup.bin"))
            .await
            .expect("read backup file"),
        b"backup payload"
    );
    for job in [sync.job, backup.job] {
        let snapshot = worker
            .queue()
            .snapshot(&job.id)
            .await
            .expect("read terminal snapshot");
        assert_eq!(snapshot.latest_event.state, JobState::Succeeded);
        let receipt = snapshot.receipt.expect("durable upload receipt");
        assert_eq!(receipt.upload.source_sha256, job.source_sha256);
        assert_eq!(receipt.upload.bytes, job.bytes);
    }

    remove_fixture(&root).await;
}

#[tokio::test]
async fn enforces_idempotency_and_honours_pre_claim_cancellation() {
    let (root, config, worker) = fixture("idempotency").await;
    write_source(&config, "document.bin", b"immutable content").await;
    let first = enqueue(
        worker.queue(),
        &config,
        JobPurpose::Sync,
        "document.bin",
        "document.bin",
        "stable-key",
    )
    .await;
    let duplicate = enqueue(
        worker.queue(),
        &config,
        JobPurpose::Sync,
        "document.bin",
        "document.bin",
        "stable-key",
    )
    .await;
    assert!(first.created);
    assert!(!duplicate.created);
    assert_eq!(first.job.id, duplicate.job.id);

    let conflict = worker
        .queue()
        .enqueue(
            &config.source_root,
            JobPurpose::Sync,
            PathBuf::from("document.bin"),
            "other.bin".to_owned(),
            "application/octet-stream".to_owned(),
            Some("stable-key".to_owned()),
        )
        .await;
    assert!(matches!(conflict, Err(WorkerError::IdempotencyConflict)));

    worker
        .queue()
        .cancel(&first.job.id)
        .await
        .expect("request cancellation");
    assert!(worker.run_once().await.expect("consume cancelled job"));
    let snapshot = worker
        .queue()
        .snapshot(&first.job.id)
        .await
        .expect("cancelled snapshot");
    assert_eq!(snapshot.latest_event.state, JobState::Cancelled);
    assert!(snapshot.receipt.is_none());
    assert!(!root.join("sync-target/document.bin").exists());

    remove_fixture(&root).await;
}

/// The job id is derived from the idempotency key alone, so a reused key with *different content*
/// collides on id while describing a different upload. Returning the stale job would silently drop
/// the new content: the caller is told the work is queued, and the new bytes are never uploaded.
/// Every field that distinguishes the two uploads must force a conflict instead.
#[tokio::test]
async fn a_reused_idempotency_key_describing_different_work_conflicts_instead_of_returning_the_stale_job()
 {
    let (root, config, worker) = fixture("idempotency-divergence").await;
    write_source(&config, "document.bin", b"conteudo original").await;
    let first = enqueue(
        worker.queue(),
        &config,
        JobPurpose::Sync,
        "document.bin",
        "document.bin",
        "stable-key",
    )
    .await;
    assert!(first.created);

    // Same key, same destination, and the SAME byte count — only the content differs, so only
    // the digest can tell the two uploads apart.
    write_source(&config, "document.bin", b"conteudo revisto!").await;
    let conflict = worker
        .queue()
        .enqueue(
            &config.source_root,
            JobPurpose::Sync,
            PathBuf::from("document.bin"),
            "document.bin".to_owned(),
            "application/octet-stream".to_owned(),
            Some("stable-key".to_owned()),
        )
        .await;
    assert!(
        matches!(conflict, Err(WorkerError::IdempotencyConflict)),
        "changed source content under a reused key must conflict, got {conflict:?}"
    );

    // Restore the original bytes so the remaining divergences are isolated to one field each.
    write_source(&config, "document.bin", b"conteudo original").await;
    write_source(&config, "outro.bin", b"conteudo original").await;

    // A different purpose would route the same bytes to a different target.
    let purpose = worker
        .queue()
        .enqueue(
            &config.source_root,
            JobPurpose::Backup,
            PathBuf::from("document.bin"),
            "document.bin".to_owned(),
            "application/octet-stream".to_owned(),
            Some("stable-key".to_owned()),
        )
        .await;
    assert!(
        matches!(purpose, Err(WorkerError::IdempotencyConflict)),
        "a changed purpose must conflict, got {purpose:?}"
    );

    // A different source file that happens to hold identical bytes is still a different job.
    let source = worker
        .queue()
        .enqueue(
            &config.source_root,
            JobPurpose::Sync,
            PathBuf::from("outro.bin"),
            "document.bin".to_owned(),
            "application/octet-stream".to_owned(),
            Some("stable-key".to_owned()),
        )
        .await;
    assert!(
        matches!(source, Err(WorkerError::IdempotencyConflict)),
        "a changed source must conflict, got {source:?}"
    );

    // A different declared content type changes how the destination stores the object.
    let content_type = worker
        .queue()
        .enqueue(
            &config.source_root,
            JobPurpose::Sync,
            PathBuf::from("document.bin"),
            "document.bin".to_owned(),
            "application/pdf".to_owned(),
            Some("stable-key".to_owned()),
        )
        .await;
    assert!(
        matches!(content_type, Err(WorkerError::IdempotencyConflict)),
        "a changed content type must conflict, got {content_type:?}"
    );

    // The genuinely identical re-submission still de-duplicates, and no extra job was created by
    // any of the rejected attempts.
    let repeat = enqueue(
        worker.queue(),
        &config,
        JobPurpose::Sync,
        "document.bin",
        "document.bin",
        "stable-key",
    )
    .await;
    assert!(!repeat.created, "an identical re-submission de-duplicates");
    assert_eq!(repeat.job.id, first.job.id);
    assert_eq!(
        worker
            .queue()
            .list_snapshots(64)
            .await
            .expect("list jobs")
            .len(),
        1,
        "a rejected conflict must not leave a second job behind"
    );

    remove_fixture(&root).await;
}

/// Job ids address files under the queue directory, so a lookup id that is not the derived 64-hex
/// digest must be refused before it is ever joined onto a path.
#[tokio::test]
async fn a_job_id_that_is_not_a_sha256_digest_is_refused_by_every_lookup() {
    let (root, _config, worker) = fixture("job-id-shape").await;
    let queue = worker.queue();

    for id in [
        "",
        "..",
        "../../etc/passwd",
        "not-hex-not-hex-not-hex-not-hex-not-hex-not-hex-not-hex-not-hexx",
        &"a".repeat(63),
        &"a".repeat(65),
    ] {
        let snapshot = queue.snapshot(id).await;
        assert!(
            matches!(snapshot, Err(WorkerError::Configuration(_))),
            "snapshot({id:?}) must be a configuration refusal, got {snapshot:?}"
        );
        assert!(
            matches!(queue.cancel(id).await, Err(WorkerError::Configuration(_))),
            "cancel({id:?}) must be refused"
        );
        assert!(
            matches!(
                queue.retry_failed(id).await,
                Err(WorkerError::Configuration(_))
            ),
            "retry_failed({id:?}) must be refused"
        );
    }

    // A well-formed id that simply does not exist is a different, non-configuration error. Both
    // hex cases are well-formed shapes (`is_ascii_hexdigit` accepts A-F), even though the queue
    // only ever derives lowercase ids itself.
    for id in ["a".repeat(64), "A".repeat(64)] {
        let absent = queue.snapshot(&id).await;
        assert!(
            matches!(absent, Err(WorkerError::JobNotFound(_))),
            "a well-formed but unknown id is JobNotFound, got {absent:?}"
        );
    }

    remove_fixture(&root).await;
}

/// Every `WorkerConfig` bound exists to stop the worker from being configured into a state that
/// hammers the destination or gives up too early. The bounds are inclusive at both ends.
#[tokio::test]
async fn worker_config_bounds_are_enforced_at_their_documented_edges() {
    let (root, config, _worker) = fixture("config-bounds").await;
    config.validate().expect("the fixture config is valid");

    let with = |mutate: &dyn Fn(&mut WorkerConfig)| {
        let mut candidate = config.clone();
        mutate(&mut candidate);
        candidate.validate()
    };

    assert!(
        with(&|c| c.source_root = PathBuf::new()).is_err(),
        "empty source_root"
    );

    assert!(with(&|c| c.poll_interval_ms = 49).is_err());
    with(&|c| c.poll_interval_ms = 50).expect("50 ms is the inclusive lower bound");
    with(&|c| c.poll_interval_ms = 60_000).expect("60000 ms is the inclusive upper bound");
    assert!(with(&|c| c.poll_interval_ms = 60_001).is_err());

    assert!(with(&|c| c.max_parallel_jobs = 0).is_err());
    with(&|c| c.max_parallel_jobs = 1).expect("1 is allowed");
    with(&|c| c.max_parallel_jobs = 32).expect("32 is the inclusive upper bound");
    assert!(with(&|c| c.max_parallel_jobs = 33).is_err());

    assert!(with(&|c| c.max_job_attempts = 0).is_err());
    with(&|c| c.max_job_attempts = 1).expect("1 attempt is allowed");
    with(&|c| c.max_job_attempts = 16).expect("16 is the inclusive upper bound");
    assert!(with(&|c| c.max_job_attempts = 17).is_err());

    // A zero initial backoff would retry in a tight loop; a max below the initial is incoherent.
    assert!(with(&|c| c.retry_initial_ms = 0).is_err());
    assert!(
        with(&|c| {
            c.retry_initial_ms = 200;
            c.retry_max_ms = 199;
        })
        .is_err(),
        "retry_max_ms below retry_initial_ms is refused"
    );
    with(&|c| {
        c.retry_initial_ms = 200;
        c.retry_max_ms = 200;
    })
    .expect("equal retry bounds are coherent");

    // An invalid connector target must surface through the worker's own validation, not be skipped.
    assert!(
        with(&|c| c.targets.purposes.sync = "nao-existe".to_owned()).is_err(),
        "a purpose pointing at a missing target is rejected by the worker too"
    );

    remove_fixture(&root).await;
}

#[tokio::test]
async fn recovers_interrupted_jobs_and_terminally_fails_missing_sources() {
    let (root, config, worker) = fixture("recovery").await;
    write_source(&config, "recover.bin", b"recover me").await;
    let interrupted = enqueue(
        worker.queue(),
        &config,
        JobPurpose::Backup,
        "recover.bin",
        "recover.bin",
        "recover-key",
    )
    .await;
    let pending = worker
        .queue()
        .root()
        .join("pending")
        .join(format!("{}.json", interrupted.job.id));
    let running = worker
        .queue()
        .root()
        .join("running")
        .join(format!("{}.json", interrupted.job.id));
    tokio::fs::rename(pending, running)
        .await
        .expect("simulate interrupted claim");
    assert_eq!(worker.queue().recover().await.expect("recover queue"), 1);
    assert_eq!(
        worker
            .queue()
            .snapshot(&interrupted.job.id)
            .await
            .expect("recovered snapshot")
            .latest_event
            .state,
        JobState::Recovered
    );
    assert!(worker.run_once().await.expect("run recovered job"));

    write_source(&config, "removed.bin", b"disappearing source").await;
    let removed = enqueue(
        worker.queue(),
        &config,
        JobPurpose::Sync,
        "removed.bin",
        "removed.bin",
        "removed-key",
    )
    .await;
    tokio::fs::remove_file(config.source_root.join("removed.bin"))
        .await
        .expect("remove queued source");
    assert!(worker.run_once().await.expect("process missing source"));
    let failed = worker
        .queue()
        .snapshot(&removed.job.id)
        .await
        .expect("failed snapshot");
    assert_eq!(failed.latest_event.state, JobState::Failed);
    assert!(failed.latest_event.detail.contains("source is unavailable"));
    assert!(failed.receipt.is_none());

    remove_fixture(&root).await;
}

#[tokio::test]
async fn lists_newest_jobs_across_states_with_a_bounded_fail_closed_view() {
    let (root, config, worker) = fixture("list-snapshots").await;
    write_source(&config, "first.bin", b"first").await;
    write_source(&config, "second.bin", b"second").await;
    let first = enqueue(
        worker.queue(),
        &config,
        JobPurpose::Sync,
        "first.bin",
        "first.bin",
        "list-first",
    )
    .await;
    // Stable ordering must not depend on directory enumeration. Ensure the second job has a later
    // creation clock even on filesystems with coarse timestamp metadata.
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let second = enqueue(
        worker.queue(),
        &config,
        JobPurpose::Backup,
        "second.bin",
        "second.bin",
        "list-second",
    )
    .await;
    worker
        .queue()
        .cancel(&first.job.id)
        .await
        .expect("cancel first job");
    assert!(worker.run_once().await.expect("consume first queued job"));
    assert!(worker.run_once().await.expect("consume second queued job"));

    let all = worker
        .queue()
        .list_snapshots(10)
        .await
        .expect("list queue snapshots");
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].job.id, second.job.id);
    assert_eq!(all[0].latest_event.state, JobState::Succeeded);
    assert_eq!(all[1].job.id, first.job.id);
    assert_eq!(all[1].latest_event.state, JobState::Cancelled);

    let one = worker
        .queue()
        .list_snapshots(1)
        .await
        .expect("bounded queue snapshots");
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].job.id, second.job.id);
    assert!(matches!(
        worker.queue().list_snapshots(0).await,
        Err(WorkerError::Configuration(_))
    ));

    tokio::fs::write(worker.queue().root().join("pending/not-a-job.json"), b"{}")
        .await
        .expect("write malformed queue entry");
    assert!(matches!(
        worker.queue().list_snapshots(10).await,
        Err(WorkerError::Configuration(_))
    ));

    remove_fixture(&root).await;
}
