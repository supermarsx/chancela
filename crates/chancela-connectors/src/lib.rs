//! Protocol connectors for the distinct ARC-20 sync and backup subsystems.
//!
//! Configuration contains credential *references* only. Secret values enter
//! through [`SecretProvider`] at runtime and are deliberately neither
//! serializable nor printable.

mod auth;
mod config;
mod error;
mod ftps;
mod google_drive;
mod graph;
mod http;
mod local;
mod model;
mod network;
mod retry;
mod s3;
mod sftp;
mod smb;
mod webdav;

pub use auth::{
    EnvSecretProvider, InMemorySecretProvider, SECRET_PREFIX, SECRETS_DIR_ENV, SecretProvider,
    SecretValue,
};
pub use config::{
    FtpsTarget, GoogleDriveTarget, GraphTarget, LocalTarget, PurposeTargets, S3Target, SftpTarget,
    SmbTarget, TargetConfig, WebDavAuth, WebDavTarget, WorkerTargets,
};
pub use error::{ConnectorError, ErrorClass};
pub use ftps::FtpsConnector;
pub use google_drive::{DriveFile, DriveRevision, GoogleDriveConnector};
pub use graph::GraphConnector;
pub use local::LocalConnector;
pub use model::{
    CancellationToken, Capability, ChecksumEvidence, Connector, ConnectorKind, ConnectorStatus,
    DownloadReceipt, JobPurpose, ObjectInfo, ProbeState, UploadReceipt, UploadRequest,
};
pub use network::{
    ALLOWED_HOSTS_ENV, DATA_DIR_ENV, MAX_RUNTIME_ALLOWLIST_ENTRIES, NetworkPolicy,
    RUNTIME_ALLOWLIST_FILE, RUNTIME_ALLOWLIST_SCHEMA_VERSION, RuntimeAllowlist,
    load_runtime_allowlist,
};
pub use retry::{RetryPolicy, retry_operation};
pub use s3::S3Connector;
pub use sftp::SftpConnector;
pub use smb::SmbConnector;
pub use webdav::WebDavConnector;

use std::sync::Arc;

/// Validate the shared connector destination contract without selecting a protocol.
pub fn validate_destination(value: &str) -> Result<(), ConnectorError> {
    http::validate_relative_path(value)
}

/// Build one connector without exposing credential material to configuration
/// serialization or caller logs.
pub fn build_connector(
    target: &TargetConfig,
    secrets: Arc<dyn SecretProvider>,
) -> Result<Arc<dyn Connector>, ConnectorError> {
    target.validate()?;
    match target {
        TargetConfig::Local(config) => Ok(Arc::new(LocalConnector::new(config.clone())?)),
        TargetConfig::WebDav(config) => {
            Ok(Arc::new(WebDavConnector::new(config.clone(), secrets)?))
        }
        TargetConfig::MicrosoftGraph(config) => {
            Ok(Arc::new(GraphConnector::new(config.clone(), secrets)?))
        }
        TargetConfig::GoogleDrive(config) => Ok(Arc::new(GoogleDriveConnector::new(
            config.clone(),
            secrets,
        )?)),
        TargetConfig::Sftp(config) => Ok(Arc::new(SftpConnector::new(config.clone(), secrets)?)),
        TargetConfig::Ftps(config) => Ok(Arc::new(FtpsConnector::new(config.clone(), secrets)?)),
        TargetConfig::Smb(config) => Ok(Arc::new(SmbConnector::new(config.clone(), secrets)?)),
        TargetConfig::S3(config) => Ok(Arc::new(S3Connector::new(config.clone(), secrets)?)),
    }
}
