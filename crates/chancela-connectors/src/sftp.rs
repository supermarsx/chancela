use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use russh::client;
use russh::keys::ssh_key;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::http::{join_remote, temporary_destination, validate_relative_path, verify_source};
use crate::{
    CancellationToken, Capability, ChecksumEvidence, Connector, ConnectorError, ConnectorKind,
    ConnectorStatus, ErrorClass, ProbeState, SecretProvider, SftpTarget, UploadReceipt,
    UploadRequest,
};

const CAPABILITIES: &[Capability] = &[
    Capability::Upload,
    Capability::CreateFolder,
    Capability::SourceChecksum,
];

struct HostKeyVerifier {
    expected: String,
}

impl client::Handler for HostKeyVerifier {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        if !matches!(
            server_public_key.algorithm(),
            ssh_key::Algorithm::Ed25519 | ssh_key::Algorithm::Ecdsa { .. }
        ) {
            return Ok(false);
        }
        let actual = server_public_key
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        Ok(actual == self.expected)
    }
}

struct Connection {
    _ssh: client::Handle<HostKeyVerifier>,
    sftp: SftpSession,
}

pub struct SftpConnector {
    config: SftpTarget,
    secrets: Arc<dyn SecretProvider>,
}

impl std::fmt::Debug for SftpConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SftpConnector")
            .field("target_id", &self.config.id)
            .finish_non_exhaustive()
    }
}

impl SftpConnector {
    pub fn new(
        config: SftpTarget,
        secrets: Arc<dyn SecretProvider>,
    ) -> Result<Self, ConnectorError> {
        config.validate()?;
        if !config.host_key_sha256.starts_with("SHA256:") {
            return Err(ConnectorError::configuration(
                "SFTP host key must be pinned with an OpenSSH SHA256 fingerprint",
            ));
        }
        Ok(Self { config, secrets })
    }

    async fn connect(&self) -> Result<Connection, ConnectorError> {
        let password = self.secrets.resolve(&self.config.password_ref)?;
        let timeout = Duration::from_secs(self.config.timeout_seconds);
        let ssh_config = client::Config {
            inactivity_timeout: Some(timeout),
            ..Default::default()
        };
        let verifier = HostKeyVerifier {
            expected: self.config.host_key_sha256.clone(),
        };
        let mut ssh = tokio::time::timeout(
            timeout,
            client::connect(
                Arc::new(ssh_config),
                (self.config.host.as_str(), self.config.port),
                verifier,
            ),
        )
        .await
        .map_err(|_| ConnectorError::transient("SFTP connection timed out"))?
        .map_err(|_| ConnectorError::transient("SFTP connection failed"))?;
        let authenticated = ssh
            .authenticate_password(&self.config.username, password.expose())
            .await
            .map_err(|_| {
                ConnectorError::new(ErrorClass::Authentication, "SFTP authentication failed")
            })?;
        if !authenticated.success() {
            return Err(ConnectorError::new(
                ErrorClass::Authentication,
                "SFTP authentication was rejected",
            ));
        }
        let channel = ssh
            .channel_open_session()
            .await
            .map_err(|_| ConnectorError::transient("SFTP channel open failed"))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|_| ConnectorError::transient("SFTP subsystem request failed"))?;
        let sftp = SftpSession::new(channel.into_stream())
            .await
            .map_err(|_| ConnectorError::transient("SFTP session initialization failed"))?;
        sftp.set_timeout(self.config.timeout_seconds);
        Ok(Connection { _ssh: ssh, sftp })
    }

    async fn ensure_parent_dirs(
        &self,
        sftp: &SftpSession,
        remote_path: &str,
    ) -> Result<(), ConnectorError> {
        let Some(parent) = remote_path.rsplit_once('/').map(|(value, _)| value) else {
            return Ok(());
        };
        let absolute = parent.starts_with('/');
        let mut current = String::new();
        for component in parent.split('/').filter(|part| !part.is_empty()) {
            if (absolute && current.is_empty()) || (!current.is_empty() && !current.ends_with('/'))
            {
                current.push('/');
            }
            current.push_str(component);
            if !sftp
                .try_exists(current.clone())
                .await
                .map_err(|_| ConnectorError::transient("SFTP directory inspection failed"))?
            {
                sftp.create_dir(current.clone()).await.map_err(|_| {
                    ConnectorError::new(ErrorClass::Permanent, "SFTP directory creation failed")
                })?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Connector for SftpConnector {
    fn target_id(&self) -> &str {
        &self.config.id
    }

    fn kind(&self) -> ConnectorKind {
        ConnectorKind::Sftp
    }

    fn capabilities(&self) -> &'static [Capability] {
        CAPABILITIES
    }

    async fn probe(&self) -> Result<ConnectorStatus, ConnectorError> {
        let connection = self.connect().await?;
        let root = if self.config.root.trim().is_empty() {
            "."
        } else {
            self.config.root.as_str()
        };
        connection
            .sftp
            .canonicalize(root)
            .await
            .map_err(|_| ConnectorError::new(ErrorClass::NotFound, "SFTP root is unavailable"))?;
        let _ = connection.sftp.close().await;
        Ok(ConnectorStatus {
            target_id: self.config.id.clone(),
            kind: self.kind(),
            state: ProbeState::Ready,
            capabilities: CAPABILITIES.to_vec(),
            detail: "SFTP authentication and pinned Ed25519/ECDSA SHA-256 host-key verification succeeded"
                .to_owned(),
        })
    }

    async fn upload(
        &self,
        request: &UploadRequest,
        cancellation: &CancellationToken,
    ) -> Result<UploadReceipt, ConnectorError> {
        validate_relative_path(&request.destination)?;
        verify_source(
            &request.source,
            &request.source_sha256,
            request.bytes,
            cancellation,
        )
        .await?;
        let connection = self.connect().await?;
        let remote = join_remote(&self.config.root, &request.destination)?;
        let temporary = join_remote(
            &self.config.root,
            &temporary_destination(&request.destination, &request.idempotency_key),
        )?;
        self.ensure_parent_dirs(&connection.sftp, &remote).await?;
        if connection
            .sftp
            .try_exists(remote.clone())
            .await
            .map_err(|_| ConnectorError::transient("SFTP destination inspection failed"))?
        {
            return Err(ConnectorError::new(
                ErrorClass::Conflict,
                "SFTP destination already exists",
            ));
        }

        let mut source = tokio::fs::File::open(&request.source)
            .await
            .map_err(|error| ConnectorError::io("open SFTP source", &error))?;
        let mut target = connection
            .sftp
            .open_with_flags(
                temporary.clone(),
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await
            .map_err(|_| ConnectorError::transient("SFTP temporary upload open failed"))?;
        let mut buffer = vec![0_u8; 1024 * 1024];
        let transfer = async {
            loop {
                cancellation.check()?;
                let read = source
                    .read(&mut buffer)
                    .await
                    .map_err(|error| ConnectorError::io("read SFTP source", &error))?;
                if read == 0 {
                    break;
                }
                target
                    .write_all(&buffer[..read])
                    .await
                    .map_err(|_| ConnectorError::transient("SFTP upload write failed"))?;
            }
            target
                .sync_all()
                .await
                .map_err(|_| ConnectorError::transient("SFTP upload sync failed"))?;
            target
                .shutdown()
                .await
                .map_err(|_| ConnectorError::transient("SFTP upload close failed"))?;
            Ok::<(), ConnectorError>(())
        }
        .await;
        if let Err(error) = transfer {
            let _ = connection.sftp.remove_file(temporary).await;
            return Err(error);
        }
        connection
            .sftp
            .rename(temporary.clone(), remote.clone())
            .await
            .map_err(|_| ConnectorError::new(ErrorClass::Conflict, "SFTP atomic commit failed"))?;
        let metadata = connection
            .sftp
            .metadata(remote)
            .await
            .map_err(|_| ConnectorError::transient("SFTP committed object stat failed"))?;
        if metadata.size.unwrap_or_default() != request.bytes {
            return Err(ConnectorError::new(
                ErrorClass::Integrity,
                "SFTP committed object size does not match the source",
            ));
        }
        let _ = connection.sftp.close().await;
        Ok(UploadReceipt {
            target_id: self.config.id.clone(),
            connector: self.kind(),
            destination: request.destination.clone(),
            provider_object_id: None,
            provider_revision: None,
            etag: None,
            source_sha256: request.source_sha256.clone(),
            bytes: request.bytes,
            checksum_evidence: ChecksumEvidence::SourceOnly,
        })
    }
}
