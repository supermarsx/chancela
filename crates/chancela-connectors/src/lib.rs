//! Protocol connectors for the distinct ARC-20 sync and backup subsystems.
//!
//! Configuration contains credential *references* only. Secret values enter
//! through [`SecretProvider`] at runtime and are deliberately neither
//! serializable nor printable.

mod auth;
pub mod codes;
mod config;
mod error;
#[cfg(feature = "ftps")]
mod ftps;
mod google_drive;
mod graph;
mod http;
mod local;
mod model;
mod network;
mod retry;
#[cfg(feature = "s3")]
mod s3;
#[cfg(feature = "sftp")]
mod sftp;
#[cfg(feature = "smb")]
mod smb;
mod webdav;

pub use auth::{
    EnvSecretProvider, InMemorySecretProvider, SECRET_PREFIX, SECRETS_DIR_ENV, SecretProvider,
    SecretValue,
};
pub use codes::GatedTransport;
pub use config::{
    FtpsTarget, GoogleDriveTarget, GraphTarget, LocalTarget, PurposeTargets, S3Target, SftpTarget,
    SmbTarget, TargetConfig, WebDavAuth, WebDavTarget, WorkerTargets,
};
pub use error::{ConnectorError, ErrorClass};
#[cfg(feature = "ftps")]
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
#[cfg(feature = "s3")]
pub use s3::S3Connector;
#[cfg(feature = "sftp")]
pub use sftp::SftpConnector;
#[cfg(feature = "smb")]
pub use smb::SmbConnector;
pub use webdav::WebDavConnector;

use std::sync::Arc;

/// Validate the shared connector destination contract without selecting a protocol.
pub fn validate_destination(value: &str) -> Result<(), ConnectorError> {
    http::validate_relative_path(value)
}

/// Build one connector without exposing credential material to configuration
/// serialization or caller logs.
///
/// Four of the eight protocols are behind a Cargo feature (see `[features]` in this crate's
/// manifest). Configuration for them still parses and validates in every build — only the client
/// is optional — so a target whose transport was not compiled reaches this function and is
/// refused here, by name, via [`ConnectorError::transport_not_compiled`]. There is no fallback
/// arm and no silent success: see [`codes`] for why that is the only acceptable behaviour.
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
        #[cfg(feature = "sftp")]
        TargetConfig::Sftp(config) => Ok(Arc::new(SftpConnector::new(config.clone(), secrets)?)),
        #[cfg(not(feature = "sftp"))]
        TargetConfig::Sftp(_) => Err(ConnectorError::transport_not_compiled(GatedTransport::Sftp)),
        #[cfg(feature = "ftps")]
        TargetConfig::Ftps(config) => Ok(Arc::new(FtpsConnector::new(config.clone(), secrets)?)),
        #[cfg(not(feature = "ftps"))]
        TargetConfig::Ftps(_) => Err(ConnectorError::transport_not_compiled(GatedTransport::Ftps)),
        #[cfg(feature = "smb")]
        TargetConfig::Smb(config) => Ok(Arc::new(SmbConnector::new(config.clone(), secrets)?)),
        #[cfg(not(feature = "smb"))]
        TargetConfig::Smb(_) => Err(ConnectorError::transport_not_compiled(GatedTransport::Smb)),
        #[cfg(feature = "s3")]
        TargetConfig::S3(config) => Ok(Arc::new(S3Connector::new(config.clone(), secrets)?)),
        #[cfg(not(feature = "s3"))]
        TargetConfig::S3(_) => Err(ConnectorError::transport_not_compiled(GatedTransport::S3)),
    }
}

#[cfg(test)]
mod build_connector_tests {
    use super::*;
    use crate::auth::InMemorySecretProvider;

    /// Every gated transport this build did NOT compile must be refused by name, with its stable
    /// code, as a permanent configuration failure — never a fallback, never a silent success.
    ///
    /// Deliberately assertion-driven off [`codes::ALL_GATED_TRANSPORTS`] rather than a fixed list,
    /// and deliberately meaningful under *every* feature combination: with all four on it proves
    /// nothing is misrouted, with all four off it proves all four fail closed, and each partial
    /// build checks exactly the arms it compiled out.
    #[test]
    fn uncompiled_transports_fail_closed_by_name() {
        for transport in codes::ALL_GATED_TRANSPORTS {
            if transport.is_compiled() {
                continue;
            }
            let error = ConnectorError::transport_not_compiled(*transport);
            assert_eq!(error.class, ErrorClass::Configuration);
            assert!(
                !error.is_retryable(),
                "{:?}: a transport this build cannot speak must never be retried",
                transport
            );
            assert_eq!(error.code, Some(transport.not_compiled_code()));
            assert!(
                error.message.contains(transport.cargo_feature()),
                "{:?}: the message must name the transport and the feature that restores it",
                transport
            );
        }
    }

    /// The dispatch arm itself, not just the constructor: a validated target of an uncompiled
    /// kind must come back as the not-compiled error rather than any other outcome.
    #[test]
    fn build_connector_refuses_an_uncompiled_target() {
        let secrets: Arc<dyn SecretProvider> = Arc::new(InMemorySecretProvider::default());
        for (target, transport) in uncompiled_sample_targets() {
            let error = build_connector(&target, secrets.clone())
                .err()
                .unwrap_or_else(|| {
                    panic!("{transport:?}: an uncompiled transport must not build a connector")
                });
            assert_eq!(
                error.code,
                Some(transport.not_compiled_code()),
                "{transport:?}: dispatch must reach the not-compiled arm"
            );
        }
    }

    /// Valid targets for the gated kinds this build compiled OUT. Each must pass
    /// `TargetConfig::validate` so the failure under test is the missing transport and not a
    /// configuration complaint raised before dispatch.
    fn uncompiled_sample_targets() -> Vec<(TargetConfig, GatedTransport)> {
        let mut targets = Vec::new();
        if !GatedTransport::S3.is_compiled() {
            targets.push((
                TargetConfig::S3(S3Target {
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
                }),
                GatedTransport::S3,
            ));
        }
        if !GatedTransport::Sftp.is_compiled() {
            targets.push((
                TargetConfig::Sftp(SftpTarget {
                    id: "sftp-backup".to_owned(),
                    host: "sftp.example.test".to_owned(),
                    port: 22,
                    username: "operator".to_owned(),
                    password_ref: "CHANCELA_CONNECTOR_SECRET_SFTP_PASSWORD".to_owned(),
                    host_key_sha256: "SHA256:qwertyuiopasdfghjklzxcvbnm1234567890ABCD".to_owned(),
                    root: "/archive".to_owned(),
                    timeout_seconds: 30,
                }),
                GatedTransport::Sftp,
            ));
        }
        if !GatedTransport::Smb.is_compiled() {
            targets.push((
                TargetConfig::Smb(SmbTarget {
                    id: "smb-backup".to_owned(),
                    host: "smb.example.test".to_owned(),
                    port: 445,
                    share: "archive".to_owned(),
                    username: "operator".to_owned(),
                    domain: String::new(),
                    password_ref: "CHANCELA_CONNECTOR_SECRET_SMB_PASSWORD".to_owned(),
                    root: "archive".to_owned(),
                    timeout_seconds: 30,
                    allow_unencrypted: false,
                }),
                GatedTransport::Smb,
            ));
        }
        if !GatedTransport::Ftps.is_compiled() {
            targets.push((
                TargetConfig::Ftps(FtpsTarget {
                    id: "ftps-backup".to_owned(),
                    host: "ftps.example.test".to_owned(),
                    port: 21,
                    username: "operator".to_owned(),
                    password_ref: "CHANCELA_CONNECTOR_SECRET_FTPS_PASSWORD".to_owned(),
                    root: "/archive".to_owned(),
                    timeout_seconds: 30,
                }),
                GatedTransport::Ftps,
            ));
        }
        targets
    }
}
