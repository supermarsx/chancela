use std::path::{Component, Path, PathBuf};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::http::{temporary_destination, validate_relative_path, verify_source};
use crate::{
    CancellationToken, Capability, ChecksumEvidence, Connector, ConnectorError, ConnectorKind,
    ConnectorStatus, ErrorClass, LocalTarget, ProbeState, UploadReceipt, UploadRequest,
};

const CAPABILITIES: &[Capability] = &[
    Capability::Upload,
    Capability::CreateFolder,
    Capability::SourceChecksum,
    Capability::RemoteChecksum,
    Capability::Offline,
];

#[derive(Clone, Debug)]
pub struct LocalConnector {
    config: LocalTarget,
}

impl LocalConnector {
    pub fn new(config: LocalTarget) -> Result<Self, ConnectorError> {
        if config.root.as_os_str().is_empty() {
            return Err(ConnectorError::configuration("local root is empty"));
        }
        Ok(Self { config })
    }

    fn destination(&self, relative: &str) -> Result<PathBuf, ConnectorError> {
        validate_relative_path(relative)?;
        let path = Path::new(relative);
        if path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(ConnectorError::configuration(
                "local destination contains a non-normal path component",
            ));
        }
        Ok(self.config.root.join(path))
    }
}

#[async_trait]
impl Connector for LocalConnector {
    fn target_id(&self) -> &str {
        &self.config.id
    }

    fn kind(&self) -> ConnectorKind {
        ConnectorKind::Local
    }

    fn capabilities(&self) -> &'static [Capability] {
        CAPABILITIES
    }

    async fn probe(&self) -> Result<ConnectorStatus, ConnectorError> {
        tokio::fs::create_dir_all(&self.config.root)
            .await
            .map_err(|error| ConnectorError::io("create local target root", &error))?;
        Ok(ConnectorStatus {
            target_id: self.config.id.clone(),
            kind: self.kind(),
            state: ProbeState::Ready,
            capabilities: CAPABILITIES.to_vec(),
            detail: "local/NAS root is writable; new immutable objects commit by atomic rename"
                .to_owned(),
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
        let destination = self.destination(&request.destination)?;
        let parent = destination
            .parent()
            .ok_or_else(|| ConnectorError::configuration("destination has no parent"))?;
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|error| ConnectorError::io("create destination directory", &error))?;

        let temporary = self.destination(&temporary_destination(
            &request.destination,
            &request.idempotency_key,
        ))?;
        let mut source = tokio::fs::File::open(&request.source)
            .await
            .map_err(|error| ConnectorError::io("open source", &error))?;
        let mut target = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)
            .await
            .map_err(|error| ConnectorError::io("open temporary destination", &error))?;
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            cancellation.check()?;
            let read = source
                .read(&mut buffer)
                .await
                .map_err(|error| ConnectorError::io("read source", &error))?;
            if read == 0 {
                break;
            }
            target
                .write_all(&buffer[..read])
                .await
                .map_err(|error| ConnectorError::io("write temporary destination", &error))?;
        }
        target
            .sync_all()
            .await
            .map_err(|error| ConnectorError::io("sync temporary destination", &error))?;
        drop(target);

        if tokio::fs::try_exists(&destination)
            .await
            .map_err(|error| ConnectorError::io("inspect destination", &error))?
        {
            let (existing_sha256, existing_bytes) = crate::http::sha256_file(&destination).await?;
            let _ = tokio::fs::remove_file(&temporary).await;
            if existing_sha256 != request.source_sha256 || existing_bytes != request.bytes {
                return Err(ConnectorError::new(
                    ErrorClass::Conflict,
                    "destination already exists with different content",
                ));
            }
        } else if let Err(error) = tokio::fs::rename(&temporary, &destination).await {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(ConnectorError::io("commit destination", &error));
        }

        let (remote_sha256, remote_bytes) = crate::http::sha256_file(&destination).await?;
        if remote_sha256 != request.source_sha256 || remote_bytes != request.bytes {
            return Err(ConnectorError::new(
                ErrorClass::Integrity,
                "committed destination failed SHA-256 verification",
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
            checksum_evidence: ChecksumEvidence::RemoteConfirmed,
        })
    }
}
