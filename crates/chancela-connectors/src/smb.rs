use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use smb2::{ClientConfig, ErrorKind as SmbErrorKind, SmbClient, Tree};
use tokio::io::AsyncReadExt;

use crate::http::{temporary_destination, validate_relative_path, verify_source};
use crate::{
    CancellationToken, Capability, ChecksumEvidence, Connector, ConnectorError, ConnectorKind,
    ConnectorStatus, ErrorClass, ProbeState, SecretProvider, SmbTarget, UploadReceipt,
    UploadRequest,
};

const CAPABILITIES: &[Capability] = &[
    Capability::Upload,
    Capability::CreateFolder,
    Capability::SourceChecksum,
];

pub struct SmbConnector {
    config: SmbTarget,
    secrets: Arc<dyn SecretProvider>,
}

impl std::fmt::Debug for SmbConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SmbConnector")
            .field("target_id", &self.config.id)
            .finish_non_exhaustive()
    }
}

impl SmbConnector {
    pub fn new(
        config: SmbTarget,
        secrets: Arc<dyn SecretProvider>,
    ) -> Result<Self, ConnectorError> {
        config.validate()?;
        if config.host.trim().is_empty() || config.share.trim().is_empty() {
            return Err(ConnectorError::configuration(
                "SMB host and share are required",
            ));
        }
        Ok(Self { config, secrets })
    }

    fn map_error(error: &smb2::Error, operation: &str) -> ConnectorError {
        let class = match error.kind() {
            SmbErrorKind::AuthRequired
            | SmbErrorKind::SigningRequired
            | SmbErrorKind::AccessDenied => ErrorClass::Authentication,
            SmbErrorKind::NotFound => ErrorClass::NotFound,
            SmbErrorKind::AlreadyExists | SmbErrorKind::SharingViolation => ErrorClass::Conflict,
            SmbErrorKind::ConnectionLost
            | SmbErrorKind::TimedOut
            | SmbErrorKind::SessionExpired
            | SmbErrorKind::Io => ErrorClass::Transient,
            SmbErrorKind::Cancelled => ErrorClass::Cancelled,
            _ => ErrorClass::Permanent,
        };
        ConnectorError::new(class, format!("SMB {operation} failed"))
    }

    async fn connect(&self) -> Result<(SmbClient, Tree), ConnectorError> {
        let password = self.secrets.resolve(&self.config.password_ref)?;
        let mut client = SmbClient::connect(ClientConfig {
            addr: format!("{}:{}", self.config.host, self.config.port),
            timeout: Duration::from_secs(self.config.timeout_seconds),
            username: self.config.username.clone(),
            password: password.expose().to_owned(),
            domain: self.config.domain.clone(),
            auto_reconnect: false,
            compression: true,
            dfs_enabled: true,
            dfs_target_overrides: HashMap::new(),
        })
        .await
        .map_err(|error| Self::map_error(&error, "connection"))?;
        let tree = client
            .connect_share(&self.config.share)
            .await
            .map_err(|error| Self::map_error(&error, "share connection"))?;
        if !self.config.allow_unencrypted && !client.diagnostics().primary.encryption.active {
            return Err(ConnectorError::new(
                ErrorClass::Authentication,
                "SMB transport encryption is not active; require encryption on the share or explicitly allow unencrypted local transport",
            ));
        }
        Ok((client, tree))
    }

    fn remote_path(&self, destination: &str) -> Result<String, ConnectorError> {
        validate_relative_path(destination)?;
        let destination = destination.replace('/', "\\");
        let root = self.config.root.trim_matches(['/', '\\']);
        if root.is_empty() {
            Ok(destination)
        } else {
            Ok(format!("{}\\{destination}", root.replace('/', "\\")))
        }
    }

    async fn ensure_parent_dirs(
        &self,
        client: &mut SmbClient,
        tree: &mut Tree,
        remote: &str,
    ) -> Result<(), ConnectorError> {
        let Some((parent, _)) = remote.rsplit_once('\\') else {
            return Ok(());
        };
        let mut current = String::new();
        for component in parent.split('\\').filter(|part| !part.is_empty()) {
            if !current.is_empty() {
                current.push('\\');
            }
            current.push_str(component);
            match client.create_directory(tree, &current).await {
                Ok(()) => {}
                Err(error) if error.kind() == SmbErrorKind::AlreadyExists => {}
                Err(error) => return Err(Self::map_error(&error, "directory creation")),
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Connector for SmbConnector {
    fn target_id(&self) -> &str {
        &self.config.id
    }

    fn kind(&self) -> ConnectorKind {
        ConnectorKind::Smb
    }

    fn capabilities(&self) -> &'static [Capability] {
        CAPABILITIES
    }

    async fn probe(&self) -> Result<ConnectorStatus, ConnectorError> {
        let (mut client, mut tree) = self.connect().await?;
        let root = self.config.root.trim_matches(['/', '\\']);
        if !root.is_empty() {
            client
                .list_directory(&mut tree, root)
                .await
                .map_err(|error| Self::map_error(&error, "root probe"))?;
        }
        Ok(ConnectorStatus {
            target_id: self.config.id.clone(),
            kind: self.kind(),
            state: ProbeState::Ready,
            capabilities: CAPABILITIES.to_vec(),
            detail: if self.config.allow_unencrypted {
                "SMB2/3 share is ready under the explicit unencrypted-local override".to_owned()
            } else {
                "SMB2/3 share is ready with transport encryption active".to_owned()
            },
        })
    }

    async fn upload(
        &self,
        request: &UploadRequest,
        cancellation: &CancellationToken,
    ) -> Result<UploadReceipt, ConnectorError> {
        verify_source(
            &request.source,
            &request.source_sha256,
            request.bytes,
            cancellation,
        )
        .await?;
        let (mut client, mut tree) = self.connect().await?;
        let remote = self.remote_path(&request.destination)?;
        let temporary = self.remote_path(&temporary_destination(
            &request.destination,
            &request.idempotency_key,
        ))?;
        self.ensure_parent_dirs(&mut client, &mut tree, &remote)
            .await?;
        match client.stat(&mut tree, &remote).await {
            Ok(_) => {
                return Err(ConnectorError::new(
                    ErrorClass::Conflict,
                    "SMB destination already exists",
                ));
            }
            Err(error) if error.kind() == SmbErrorKind::NotFound => {}
            Err(error) => return Err(Self::map_error(&error, "destination inspection")),
        }
        let mut writer = client
            .create_file_writer(&tree, &temporary)
            .await
            .map_err(|error| Self::map_error(&error, "temporary upload open"))?;
        let mut source = tokio::fs::File::open(&request.source)
            .await
            .map_err(|error| ConnectorError::io("open SMB source", &error))?;
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            if let Err(error) = cancellation.check() {
                let _ = writer.abort().await;
                let _ = client.delete_file(&mut tree, &temporary).await;
                return Err(error);
            }
            let read = source
                .read(&mut buffer)
                .await
                .map_err(|error| ConnectorError::io("read SMB source", &error))?;
            if read == 0 {
                break;
            }
            if let Err(error) = writer.write_chunk(&buffer[..read]).await {
                let mapped = Self::map_error(&error, "upload write");
                let _ = writer.abort().await;
                let _ = client.delete_file(&mut tree, &temporary).await;
                return Err(mapped);
            }
        }
        let written = writer
            .finish()
            .await
            .map_err(|error| Self::map_error(&error, "upload finalization"))?;
        if written != request.bytes {
            let _ = client.delete_file(&mut tree, &temporary).await;
            return Err(ConnectorError::new(
                ErrorClass::Integrity,
                "SMB confirmed byte count does not match the source",
            ));
        }
        client
            .rename(&mut tree, &temporary, &remote)
            .await
            .map_err(|error| Self::map_error(&error, "atomic rename"))?;
        let info = client
            .stat(&mut tree, &remote)
            .await
            .map_err(|error| Self::map_error(&error, "committed object stat"))?;
        if info.size != request.bytes {
            return Err(ConnectorError::new(
                ErrorClass::Integrity,
                "SMB committed object size does not match the source",
            ));
        }
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
