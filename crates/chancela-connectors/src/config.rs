use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::auth::validate_reference as validate_secret_ref;
use crate::{ConnectorError, ConnectorKind, NetworkPolicy};

fn default_s3_region() -> String {
    "us-east-1".to_owned()
}

fn default_graph_base() -> String {
    "https://graph.microsoft.com/v1.0".to_owned()
}

fn default_google_base() -> String {
    "https://www.googleapis.com".to_owned()
}

fn default_timeout() -> u64 {
    60
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PurposeTargets {
    pub sync: String,
    pub backup: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerTargets {
    pub purposes: PurposeTargets,
    pub targets: Vec<TargetConfig>,
}

impl WorkerTargets {
    pub fn validate(&self) -> Result<(), ConnectorError> {
        let mut ids = BTreeSet::new();
        for target in &self.targets {
            target.validate()?;
            if !ids.insert(target.id()) {
                return Err(ConnectorError::configuration(format!(
                    "duplicate target id {}",
                    target.id()
                )));
            }
        }
        for (purpose, id) in [
            ("sync", self.purposes.sync.as_str()),
            ("backup", self.purposes.backup.as_str()),
        ] {
            if !ids.contains(id) {
                return Err(ConnectorError::configuration(format!(
                    "{purpose} target {id} does not exist"
                )));
            }
        }
        if matches!(self.target(&self.purposes.sync), Some(TargetConfig::S3(_))) {
            return Err(ConnectorError::configuration(
                "S3 targets are backup-only and cannot be selected for active sync",
            ));
        }
        Ok(())
    }

    pub fn target(&self, id: &str) -> Option<&TargetConfig> {
        self.targets.iter().find(|target| target.id() == id)
    }

    pub fn target_for(&self, purpose: crate::JobPurpose) -> Option<&TargetConfig> {
        let id = match purpose {
            crate::JobPurpose::Sync => &self.purposes.sync,
            crate::JobPurpose::Backup => &self.purposes.backup,
        };
        self.target(id)
    }

    pub async fn validate_network_policy(
        &self,
        policy: &NetworkPolicy,
    ) -> Result<(), ConnectorError> {
        for target in &self.targets {
            target.validate_network_policy(policy).await?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetConfig {
    Local(LocalTarget),
    WebDav(WebDavTarget),
    MicrosoftGraph(GraphTarget),
    GoogleDrive(GoogleDriveTarget),
    Sftp(SftpTarget),
    Ftps(FtpsTarget),
    Smb(SmbTarget),
    S3(S3Target),
}

impl TargetConfig {
    pub fn id(&self) -> &str {
        match self {
            Self::Local(value) => &value.id,
            Self::WebDav(value) => &value.id,
            Self::MicrosoftGraph(value) => &value.id,
            Self::GoogleDrive(value) => &value.id,
            Self::Sftp(value) => &value.id,
            Self::Ftps(value) => &value.id,
            Self::Smb(value) => &value.id,
            Self::S3(value) => &value.id,
        }
    }

    pub fn kind(&self) -> ConnectorKind {
        match self {
            Self::Local(_) => ConnectorKind::Local,
            Self::WebDav(_) => ConnectorKind::WebDav,
            Self::MicrosoftGraph(_) => ConnectorKind::MicrosoftGraph,
            Self::GoogleDrive(_) => ConnectorKind::GoogleDrive,
            Self::Sftp(_) => ConnectorKind::Sftp,
            Self::Ftps(_) => ConnectorKind::Ftps,
            Self::Smb(_) => ConnectorKind::Smb,
            Self::S3(_) => ConnectorKind::S3,
        }
    }

    pub fn with_id(mut self, id: String) -> Self {
        match &mut self {
            Self::Local(value) => value.id = id,
            Self::WebDav(value) => value.id = id,
            Self::MicrosoftGraph(value) => value.id = id,
            Self::GoogleDrive(value) => value.id = id,
            Self::Sftp(value) => value.id = id,
            Self::Ftps(value) => value.id = id,
            Self::Smb(value) => value.id = id,
            Self::S3(value) => value.id = id,
        }
        self
    }

    pub fn validate(&self) -> Result<(), ConnectorError> {
        validate_id(self.id())?;
        match self {
            Self::Local(value) if value.root.as_os_str().is_empty() => {
                Err(ConnectorError::configuration("local root is empty"))
            }
            Self::WebDav(value) => value.validate(),
            Self::MicrosoftGraph(value) => value.validate(),
            Self::GoogleDrive(value) => value.validate(),
            Self::Sftp(value) => value.validate(),
            Self::Ftps(value) => value.validate(),
            Self::Smb(value) => value.validate(),
            Self::S3(value) => value.validate(),
            _ => Ok(()),
        }
    }

    pub async fn validate_network_policy(
        &self,
        policy: &NetworkPolicy,
    ) -> Result<(), ConnectorError> {
        match self {
            Self::Local(_) => Ok(()),
            Self::WebDav(value) => policy.validate_url(&value.base_url, "WebDAV").await,
            Self::MicrosoftGraph(value) => {
                policy
                    .validate_url(&value.api_base_url, "Microsoft Graph")
                    .await
            }
            Self::GoogleDrive(value) => {
                policy
                    .validate_url(&value.api_base_url, "Google Drive")
                    .await
            }
            Self::Sftp(value) => policy.validate_host(&value.host, value.port, "SFTP").await,
            Self::Ftps(value) => policy.validate_host(&value.host, value.port, "FTPS").await,
            Self::Smb(value) => policy.validate_host(&value.host, value.port, "SMB").await,
            Self::S3(value) => {
                let endpoint = value.endpoint_url.clone().unwrap_or_else(|| {
                    format!("https://{}.s3.{}.amazonaws.com", value.bucket, value.region)
                });
                policy.validate_url(&endpoint, "S3 endpoint").await
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalTarget {
    pub id: String,
    pub root: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum WebDavAuth {
    Basic {
        username: String,
        password_ref: String,
    },
    Bearer {
        token_ref: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebDavTarget {
    pub id: String,
    pub base_url: String,
    pub auth: WebDavAuth,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// Explicitly permit clear-text HTTP for an operator-controlled local endpoint.
    #[serde(default)]
    pub allow_insecure_http: bool,
}

impl WebDavTarget {
    pub(crate) fn validate(&self) -> Result<(), ConnectorError> {
        validate_network_url(&self.base_url, "WebDAV", self.allow_insecure_http)?;
        match &self.auth {
            WebDavAuth::Basic { password_ref, .. } => validate_secret_ref(password_ref)?,
            WebDavAuth::Bearer { token_ref } => validate_secret_ref(token_ref)?,
        }
        validate_timeout(self.timeout_seconds)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphTarget {
    pub id: String,
    pub drive_id: String,
    pub parent_item_id: String,
    pub token_ref: String,
    #[serde(default = "default_graph_base")]
    pub api_base_url: String,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub allow_insecure_http: bool,
}

impl GraphTarget {
    pub(crate) fn validate(&self) -> Result<(), ConnectorError> {
        validate_network_url(
            &self.api_base_url,
            "Microsoft Graph",
            self.allow_insecure_http,
        )?;
        require_non_empty(&self.drive_id, "Graph drive_id")?;
        require_non_empty(&self.parent_item_id, "Graph parent_item_id")?;
        validate_secret_ref(&self.token_ref)?;
        validate_timeout(self.timeout_seconds)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoogleDriveTarget {
    pub id: String,
    pub parent_folder_id: String,
    pub token_ref: String,
    #[serde(default = "default_google_base")]
    pub api_base_url: String,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub allow_insecure_http: bool,
}

impl GoogleDriveTarget {
    pub(crate) fn validate(&self) -> Result<(), ConnectorError> {
        validate_network_url(&self.api_base_url, "Google Drive", self.allow_insecure_http)?;
        require_non_empty(&self.parent_folder_id, "Google parent_folder_id")?;
        validate_secret_ref(&self.token_ref)?;
        validate_timeout(self.timeout_seconds)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SftpTarget {
    pub id: String,
    pub host: String,
    #[serde(default = "default_sftp_port")]
    pub port: u16,
    pub username: String,
    pub password_ref: String,
    /// OpenSSH SHA256 fingerprint, including the `SHA256:` prefix. The server
    /// host key must be Ed25519 or ECDSA; legacy RSA host keys are rejected.
    pub host_key_sha256: String,
    pub root: String,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_sftp_port() -> u16 {
    22
}

impl SftpTarget {
    pub(crate) fn validate(&self) -> Result<(), ConnectorError> {
        require_non_empty(&self.host, "SFTP host")?;
        require_non_empty(&self.username, "SFTP username")?;
        validate_secret_ref(&self.password_ref)?;
        if !self.host_key_sha256.starts_with("SHA256:") {
            return Err(ConnectorError::configuration(
                "SFTP host_key_sha256 must be an OpenSSH SHA256 fingerprint",
            ));
        }
        validate_timeout(self.timeout_seconds)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FtpsTarget {
    pub id: String,
    pub host: String,
    #[serde(default = "default_ftps_port")]
    pub port: u16,
    pub username: String,
    pub password_ref: String,
    pub root: String,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_ftps_port() -> u16 {
    21
}

impl FtpsTarget {
    pub(crate) fn validate(&self) -> Result<(), ConnectorError> {
        require_non_empty(&self.host, "FTPS host")?;
        require_non_empty(&self.username, "FTPS username")?;
        validate_secret_ref(&self.password_ref)?;
        validate_timeout(self.timeout_seconds)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SmbTarget {
    pub id: String,
    pub host: String,
    #[serde(default = "default_smb_port")]
    pub port: u16,
    pub share: String,
    pub username: String,
    #[serde(default)]
    pub domain: String,
    pub password_ref: String,
    pub root: String,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// SMB 3 encryption is required unless this explicit local override is set.
    #[serde(default)]
    pub allow_unencrypted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct S3Target {
    pub id: String,
    pub bucket: String,
    #[serde(default)]
    pub prefix: String,
    #[serde(default = "default_s3_region")]
    pub region: String,
    /// Optional S3-compatible endpoint. Standard AWS resolution is used when omitted.
    pub endpoint_url: Option<String>,
    #[serde(default)]
    pub force_path_style: bool,
    pub access_key_ref: String,
    pub secret_key_ref: String,
    pub session_token_ref: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// Explicitly permit clear-text HTTP for operator-controlled self-hosted storage.
    #[serde(default)]
    pub allow_insecure_http: bool,
}

impl S3Target {
    pub(crate) fn validate(&self) -> Result<(), ConnectorError> {
        require_non_empty(&self.bucket, "S3 bucket")?;
        require_non_empty(&self.region, "S3 region")?;
        validate_secret_ref(&self.access_key_ref)?;
        validate_secret_ref(&self.secret_key_ref)?;
        if let Some(reference) = &self.session_token_ref {
            validate_secret_ref(reference)?;
        }
        if let Some(endpoint) = &self.endpoint_url {
            validate_network_url(endpoint, "S3 endpoint", self.allow_insecure_http)?;
        }
        if self
            .prefix
            .split(['/', '\\'])
            .any(|part| part == "." || part == "..")
        {
            return Err(ConnectorError::configuration(
                "S3 prefix contains traversal",
            ));
        }
        validate_timeout(self.timeout_seconds)
    }
}

fn default_smb_port() -> u16 {
    445
}

impl SmbTarget {
    pub(crate) fn validate(&self) -> Result<(), ConnectorError> {
        require_non_empty(&self.host, "SMB host")?;
        require_non_empty(&self.share, "SMB share")?;
        require_non_empty(&self.username, "SMB username")?;
        validate_secret_ref(&self.password_ref)?;
        if self
            .root
            .split(['/', '\\'])
            .any(|part| part == "." || part == "..")
        {
            return Err(ConnectorError::configuration("SMB root contains traversal"));
        }
        validate_timeout(self.timeout_seconds)
    }
}

fn validate_id(value: &str) -> Result<(), ConnectorError> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(ConnectorError::configuration("invalid target id"))
    }
}

fn validate_network_url(
    value: &str,
    label: &str,
    allow_insecure_http: bool,
) -> Result<(), ConnectorError> {
    let url = reqwest::Url::parse(value)
        .map_err(|_| ConnectorError::configuration(format!("invalid {label} URL")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConnectorError::configuration(format!(
            "{label} URL must not contain user information"
        )));
    }
    if url.scheme() != "https" && !(url.scheme() == "http" && allow_insecure_http) {
        return Err(ConnectorError::configuration(format!(
            "{label} URL must use HTTPS unless allow_insecure_http is explicitly enabled"
        )));
    }
    if url.host_str().is_none() {
        return Err(ConnectorError::configuration(format!(
            "{label} URL has no host"
        )));
    }
    Ok(())
}

fn validate_timeout(value: u64) -> Result<(), ConnectorError> {
    if (1..=600).contains(&value) {
        Ok(())
    } else {
        Err(ConnectorError::configuration(
            "timeout_seconds must be between 1 and 600",
        ))
    }
}

fn require_non_empty(value: &str, label: &str) -> Result<(), ConnectorError> {
    if value.trim().is_empty() {
        Err(ConnectorError::configuration(format!("{label} is empty")))
    } else {
        Ok(())
    }
}
