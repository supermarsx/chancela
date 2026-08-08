use std::path::PathBuf;

// The transport-specific constructors live in `native_connector_constructors` below, behind this
// crate's per-protocol Cargo features. Everything in *this* scope is ungated on purpose: the
// local-connector, purpose-routing and secret-provider invariants must keep running in a default
// build, which is why this file is given no blanket `required-features`.
use chancela_connectors::{
    CancellationToken, Connector, EnvSecretProvider, ErrorClass, JobPurpose, LocalConnector,
    LocalTarget, PurposeTargets, S3Target, SECRETS_DIR_ENV, SecretProvider, TargetConfig,
    UploadRequest, WorkerTargets,
};
use sha2::{Digest, Sha256};

fn isolated_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "chancela-connector-security-{label}-{}",
        uuid::Uuid::new_v4()
    ))
}

#[tokio::test]
async fn local_connector_is_idempotent_conflict_safe_and_traversal_safe() {
    let root = isolated_root("local");
    let source_root = root.join("source");
    let target_root = root.join("target");
    tokio::fs::create_dir_all(&source_root)
        .await
        .expect("source root");
    let source = source_root.join("record.bin");
    let payload = b"immutable record";
    tokio::fs::write(&source, payload).await.expect("source");
    let sha256 = format!("{:x}", Sha256::digest(payload));
    let connector = LocalConnector::new(LocalTarget {
        id: "local".to_owned(),
        root: target_root.clone(),
    })
    .expect("local connector");
    let request = UploadRequest {
        purpose: JobPurpose::Backup,
        source: source.clone(),
        destination: "archive/record.bin".to_owned(),
        source_sha256: sha256.clone(),
        bytes: payload.len() as u64,
        idempotency_key: "stable-key".to_owned(),
        content_type: "application/octet-stream".to_owned(),
    };

    connector
        .upload(&request, &CancellationToken::default())
        .await
        .expect("first upload");
    connector
        .upload(&request, &CancellationToken::default())
        .await
        .expect("idempotent replay");
    tokio::fs::write(target_root.join("archive/record.bin"), b"tampered")
        .await
        .expect("tamper target");
    let conflict = connector
        .upload(&request, &CancellationToken::default())
        .await
        .expect_err("different destination content must conflict");
    assert_eq!(conflict.class, ErrorClass::Conflict);

    let mut traversal = request.clone();
    traversal.destination = "../escape.bin".to_owned();
    assert_eq!(
        connector
            .upload(&traversal, &CancellationToken::default())
            .await
            .expect_err("reject traversal")
            .class,
        ErrorClass::Configuration
    );
    let cancelled = CancellationToken::default();
    cancelled.cancel();
    assert_eq!(
        connector
            .upload(&request, &cancelled)
            .await
            .expect_err("honour cancellation")
            .class,
        ErrorClass::Cancelled
    );
    assert!(!root.join("escape.bin").exists());

    tokio::fs::remove_dir_all(root)
        .await
        .expect("remove fixture");
}

#[test]
fn purpose_routing_forbids_s3_as_an_active_sync_target() {
    let config = WorkerTargets {
        purposes: PurposeTargets {
            sync: "s3-backup".to_owned(),
            backup: "s3-backup".to_owned(),
        },
        targets: vec![TargetConfig::S3(S3Target {
            id: "s3-backup".to_owned(),
            bucket: "archive".to_owned(),
            prefix: "tenant".to_owned(),
            region: "eu-west-1".to_owned(),
            endpoint_url: None,
            force_path_style: false,
            access_key_ref: "CHANCELA_CONNECTOR_SECRET_S3_ACCESS_KEY".to_owned(),
            secret_key_ref: "CHANCELA_CONNECTOR_SECRET_S3_SECRET_KEY".to_owned(),
            session_token_ref: None,
            timeout_seconds: 60,
            allow_insecure_http: false,
        })],
    };
    let error = config.validate().expect_err("S3 sync must be rejected");
    assert_eq!(error.class, ErrorClass::Configuration);
    assert!(error.message.contains("backup-only"));
}

/// The constructor-time security invariants of the three native transports.
///
/// Was one test asserting all three; split one-per-protocol so each runs under exactly the
/// feature that compiles the client it exercises. Every assertion is carried over unchanged — a
/// build with the feature on still proves the pin, the bounded timeout and the traversal
/// rejection, and a build with it off has no client to prove them about.
#[cfg(any(feature = "sftp", feature = "ftps", feature = "smb"))]
mod native_connector_constructors {
    use std::sync::Arc;

    use chancela_connectors::{ErrorClass, InMemorySecretProvider};

    #[cfg(feature = "sftp")]
    #[test]
    fn sftp_constructor_requires_a_host_key_pin() {
        use chancela_connectors::{SftpConnector, SftpTarget};

        let secrets = Arc::new(InMemorySecretProvider::default());
        let sftp = SftpConnector::new(
            SftpTarget {
                id: "sftp".to_owned(),
                host: "sftp.example.test".to_owned(),
                port: 22,
                username: "operator".to_owned(),
                password_ref: "CHANCELA_CONNECTOR_SECRET_SFTP_PASSWORD".to_owned(),
                host_key_sha256: "not-pinned".to_owned(),
                root: "/archive".to_owned(),
                timeout_seconds: 30,
            },
            secrets,
        )
        .expect_err("SFTP host key pin required");
        assert_eq!(sftp.class, ErrorClass::Configuration);
    }

    #[cfg(feature = "ftps")]
    #[test]
    fn ftps_constructor_requires_a_bounded_timeout() {
        use chancela_connectors::{FtpsConnector, FtpsTarget};

        let secrets = Arc::new(InMemorySecretProvider::default());
        let ftps = FtpsConnector::new(
            FtpsTarget {
                id: "ftps".to_owned(),
                host: "ftps.example.test".to_owned(),
                port: 21,
                username: "operator".to_owned(),
                password_ref: "CHANCELA_CONNECTOR_SECRET_FTPS_PASSWORD".to_owned(),
                root: "/archive".to_owned(),
                timeout_seconds: 0,
            },
            secrets,
        )
        .expect_err("bounded timeout required");
        assert_eq!(ftps.class, ErrorClass::Configuration);
    }

    #[cfg(feature = "smb")]
    #[test]
    fn smb_constructor_rejects_a_traversing_root() {
        use chancela_connectors::{SmbConnector, SmbTarget};

        let secrets = Arc::new(InMemorySecretProvider::default());
        let smb = SmbConnector::new(
            SmbTarget {
                id: "smb".to_owned(),
                host: "smb.example.test".to_owned(),
                port: 445,
                share: "archive".to_owned(),
                username: "operator".to_owned(),
                domain: String::new(),
                password_ref: "CHANCELA_CONNECTOR_SECRET_SMB_PASSWORD".to_owned(),
                root: "..\\escape".to_owned(),
                timeout_seconds: 30,
                allow_unencrypted: false,
            },
            secrets,
        )
        .expect_err("SMB root traversal rejected");
        assert_eq!(smb.class, ErrorClass::Configuration);
    }
}

#[test]
fn environment_provider_supports_runtime_secret_files_without_serializing_values() {
    let root = isolated_root("secret-file");
    std::fs::create_dir_all(&root).expect("secret fixture");
    let file = root.join("credential");
    std::fs::write(&file, b"file-secret\r\n").expect("secret file");
    let reference = format!(
        "CHANCELA_CONNECTOR_SECRET_TEST_{}",
        uuid::Uuid::new_v4().simple()
    )
    .to_uppercase();
    let file_reference = format!("{reference}_FILE");
    // SAFETY: this test uses a process-unique variable name that no other test
    // reads or writes, then removes it before returning.
    unsafe {
        std::env::set_var(SECRETS_DIR_ENV, &root);
        std::env::set_var(&file_reference, &file);
    };
    let secret = EnvSecretProvider
        .resolve(&reference)
        .expect("resolve file-backed secret");
    assert_eq!(secret.expose(), "file-secret");
    assert!(!format!("{secret:?}").contains("file-secret"));
    unsafe {
        std::env::remove_var(&file_reference);
        std::env::remove_var(SECRETS_DIR_ENV);
    };
    std::fs::remove_dir_all(root).expect("remove fixture");
}
