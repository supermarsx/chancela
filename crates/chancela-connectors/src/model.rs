use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::ConnectorError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobPurpose {
    Sync,
    Backup,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorKind {
    Local,
    WebDav,
    MicrosoftGraph,
    GoogleDrive,
    Sftp,
    Ftps,
    Smb,
    S3,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Upload,
    Download,
    List,
    Search,
    CreateFolder,
    Revisions,
    MultipartUpload,
    AtomicReplace,
    ResumableUpload,
    SourceChecksum,
    RemoteChecksum,
    Offline,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeState {
    Ready,
    Degraded,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConnectorStatus {
    pub target_id: String,
    pub kind: ConnectorKind,
    pub state: ProbeState,
    pub capabilities: Vec<Capability>,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumEvidence {
    SourceOnly,
    SentToProvider,
    RemoteConfirmed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UploadReceipt {
    pub target_id: String,
    pub connector: ConnectorKind,
    pub destination: String,
    pub provider_object_id: Option<String>,
    pub provider_revision: Option<String>,
    pub etag: Option<String>,
    pub source_sha256: String,
    pub bytes: u64,
    pub checksum_evidence: ChecksumEvidence,
}

#[derive(Clone, Debug)]
pub struct UploadRequest {
    pub purpose: JobPurpose,
    pub source: PathBuf,
    pub destination: String,
    pub source_sha256: String,
    pub bytes: u64,
    pub idempotency_key: String,
    pub content_type: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectInfo {
    pub id: String,
    pub name: String,
    pub size: Option<u64>,
    pub etag: Option<String>,
    pub revision: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DownloadReceipt {
    pub target_id: String,
    pub connector: ConnectorKind,
    pub source: String,
    pub destination: PathBuf,
    pub source_sha256: Option<String>,
    pub downloaded_sha256: String,
    pub bytes: u64,
    pub checksum_evidence: ChecksumEvidence,
}

#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    pub fn check(&self) -> Result<(), ConnectorError> {
        if self.is_cancelled() {
            Err(ConnectorError::cancelled())
        } else {
            Ok(())
        }
    }
}

#[async_trait]
pub trait Connector: Send + Sync {
    fn target_id(&self) -> &str;
    fn kind(&self) -> ConnectorKind;
    fn capabilities(&self) -> &'static [Capability];
    async fn probe(&self) -> Result<ConnectorStatus, ConnectorError>;
    async fn upload(
        &self,
        request: &UploadRequest,
        cancellation: &CancellationToken,
    ) -> Result<UploadReceipt, ConnectorError>;
}
