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

#[cfg(test)]
mod tests {
    use super::*;

    fn secret_ref(name: &str) -> String {
        format!("CHANCELA_CONNECTOR_SECRET_{name}")
    }

    fn webdav(base_url: &str, allow_insecure_http: bool) -> WebDavTarget {
        WebDavTarget {
            id: "wd".to_owned(),
            base_url: base_url.to_owned(),
            auth: WebDavAuth::Bearer {
                token_ref: secret_ref("WD"),
            },
            timeout_seconds: 60,
            allow_insecure_http,
        }
    }

    fn s3(id: &str) -> S3Target {
        S3Target {
            id: id.to_owned(),
            bucket: "arquivo".to_owned(),
            prefix: String::new(),
            region: "eu-west-1".to_owned(),
            endpoint_url: None,
            force_path_style: false,
            access_key_ref: secret_ref("S3_ACCESS"),
            secret_key_ref: secret_ref("S3_SECRET"),
            session_token_ref: None,
            timeout_seconds: 60,
            allow_insecure_http: false,
        }
    }

    fn sftp(id: &str) -> SftpTarget {
        SftpTarget {
            id: id.to_owned(),
            host: "sftp.example.pt".to_owned(),
            port: 22,
            username: "chancela".to_owned(),
            password_ref: secret_ref("SFTP"),
            host_key_sha256: "SHA256:qwertyuiopasdfghjklzxcvbnm1234567890ABCD".to_owned(),
            root: "/arquivo".to_owned(),
            timeout_seconds: 60,
        }
    }

    fn local(id: &str) -> TargetConfig {
        TargetConfig::Local(LocalTarget {
            id: id.to_owned(),
            root: PathBuf::from("/srv/arquivo"),
        })
    }

    fn message(result: Result<(), ConnectorError>) -> String {
        result
            .expect_err("expected a configuration rejection")
            .message
    }

    /// A URL carrying `user:password@` would ship those credentials to whatever host follows —
    /// and `reqwest::Url` parses it happily. Every network target must refuse it.
    #[test]
    fn a_url_carrying_user_information_is_refused_for_every_network_target() {
        let with_userinfo = "https://operador:segredo@arquivo.example.pt/dav";
        assert!(
            message(validate_network_url(with_userinfo, "WebDAV", false))
                .contains("must not contain user information")
        );
        assert!(webdav(with_userinfo, false).validate().is_err());

        let mut graph = GraphTarget {
            id: "gr".to_owned(),
            drive_id: "drive".to_owned(),
            parent_item_id: "item".to_owned(),
            token_ref: secret_ref("GRAPH"),
            api_base_url: with_userinfo.to_owned(),
            timeout_seconds: 60,
            allow_insecure_http: false,
        };
        assert!(graph.validate().is_err());
        graph.api_base_url = default_graph_base();
        graph.validate().expect("the default Graph base is valid");

        let mut s3 = s3("s3");
        s3.endpoint_url = Some(with_userinfo.to_owned());
        assert!(s3.validate().is_err());
    }

    /// Clear-text HTTP is only reachable through an explicit per-target opt-in; the flag must not
    /// leak across targets, and it must never make a non-HTTP scheme acceptable.
    #[test]
    fn plain_http_needs_the_explicit_opt_in_and_the_opt_in_does_not_admit_other_schemes() {
        assert!(
            message(validate_network_url(
                "http://arquivo.example.pt/dav",
                "WebDAV",
                false
            ))
            .contains("must use HTTPS")
        );
        validate_network_url("http://arquivo.example.pt/dav", "WebDAV", true)
            .expect("http is accepted once explicitly opted in");
        validate_network_url("https://arquivo.example.pt/dav", "WebDAV", false)
            .expect("https never needs the opt-in");

        for scheme in ["ftp", "file", "gopher", "ws"] {
            let url = format!("{scheme}://arquivo.example.pt/dav");
            assert!(
                validate_network_url(&url, "WebDAV", true).is_err(),
                "{scheme} must stay refused even with allow_insecure_http"
            );
        }
    }

    /// A relative-path prefix that escapes the configured bucket prefix, or an SMB root that
    /// escapes the share, would write evidence outside the operator's intended location.
    #[test]
    fn traversal_segments_are_refused_in_the_s3_prefix_and_the_smb_root() {
        for prefix in ["../etc", "arquivo/../../etc", "arquivo\\..\\etc", ".."] {
            let mut target = s3("s3");
            target.prefix = prefix.to_owned();
            assert!(
                message(target.validate()).contains("traversal"),
                "prefix {prefix:?} must be refused"
            );
        }
        let mut ok = s3("s3");
        ok.prefix = "arquivo/2026/..stamp".to_owned();
        ok.validate()
            .expect("a dotted name that is not a traversal segment is fine");

        let smb = |root: &str| SmbTarget {
            id: "smb".to_owned(),
            host: "fs.example.pt".to_owned(),
            port: 445,
            share: "arquivo".to_owned(),
            username: "chancela".to_owned(),
            domain: String::new(),
            password_ref: secret_ref("SMB"),
            root: root.to_owned(),
            timeout_seconds: 60,
            allow_unencrypted: false,
        };
        assert!(message(smb("livros/../../etc").validate()).contains("traversal"));
        assert!(message(smb("livros\\..\\etc").validate()).contains("traversal"));
        smb("livros/2026").validate().expect("a plain root is fine");
    }

    /// The SFTP host key pin is the only thing standing between the connector and a
    /// man-in-the-middle, so an absent or wrongly-formatted fingerprint must fail configuration.
    #[test]
    fn an_sftp_target_without_an_openssh_sha256_host_key_pin_is_refused() {
        sftp("sf").validate().expect("the pinned fixture is valid");
        for pin in [
            "",
            "MD5:aa:bb:cc",
            "sha256:lowercaseprefix",
            "qwertyuiopasdfghjklzxcvbnm1234567890ABCD",
        ] {
            let mut target = sftp("sf");
            target.host_key_sha256 = pin.to_owned();
            assert!(
                message(target.validate()).contains("OpenSSH SHA256 fingerprint"),
                "host key {pin:?} must be refused"
            );
        }
    }

    /// Secrets are referenced, never inlined. A reference that is not a `CHANCELA_CONNECTOR_SECRET_`
    /// name would otherwise be read as a literal credential sitting in the config file.
    #[test]
    fn a_credential_reference_that_is_not_a_secret_handle_is_refused() {
        for reference in [
            "",
            "hunter2",
            "CHANCELA_CONNECTOR_SECRET_",
            "CHANCELA_CONNECTOR_SECRET_lowercase",
            "CHANCELA_CONNECTOR_SECRET_WITH-DASH",
        ] {
            let mut target = s3("s3");
            target.access_key_ref = reference.to_owned();
            assert!(
                target.validate().is_err(),
                "access_key_ref {reference:?} must be refused"
            );
        }
        let mut with_bad_session_token = s3("s3");
        with_bad_session_token.session_token_ref = Some("hunter2".to_owned());
        assert!(with_bad_session_token.validate().is_err());

        let mut without_session_token = s3("s3");
        without_session_token.session_token_ref = None;
        without_session_token
            .validate()
            .expect("the session token is optional");
    }

    #[test]
    fn a_target_id_outside_the_allowed_charset_or_length_is_refused() {
        for id in [
            "",
            "with space",
            "with/slash",
            "acentuação",
            &"a".repeat(65),
        ] {
            assert!(
                message(local(id).validate()).contains("invalid target id"),
                "id {id:?} must be refused"
            );
        }
        for id in ["a", "arquivo-2026_v1.2", &"a".repeat(64)] {
            local(id).validate().expect("valid id");
        }
    }

    #[test]
    fn a_timeout_outside_one_to_six_hundred_seconds_is_refused() {
        for seconds in [0, 601, u64::MAX] {
            let mut target = webdav("https://arquivo.example.pt/dav", false);
            target.timeout_seconds = seconds;
            assert!(
                message(target.validate()).contains("between 1 and 600"),
                "timeout {seconds} must be refused"
            );
        }
        for seconds in [1, 60, 600] {
            let mut target = webdav("https://arquivo.example.pt/dav", false);
            target.timeout_seconds = seconds;
            target.validate().expect("in-range timeout");
        }
    }

    /// Two targets sharing an id make `target()` return whichever came first, so a later job would
    /// silently write to the wrong destination. The duplicate must be refused at validation.
    #[test]
    fn duplicate_target_ids_are_refused_rather_than_shadowing_one_another() {
        let targets = WorkerTargets {
            purposes: PurposeTargets {
                sync: "primary".to_owned(),
                backup: "primary".to_owned(),
            },
            targets: vec![local("primary"), local("primary")],
        };
        assert!(message(targets.validate()).contains("duplicate target id primary"));
    }

    #[test]
    fn a_purpose_pointing_at_a_target_that_does_not_exist_is_refused() {
        let targets = WorkerTargets {
            purposes: PurposeTargets {
                sync: "primary".to_owned(),
                backup: "cofre".to_owned(),
            },
            targets: vec![local("primary")],
        };
        assert!(message(targets.validate()).contains("backup target cofre does not exist"));
    }

    /// S3 is a backup-only destination. Selecting it for active sync must fail loudly rather than
    /// leave the sync purpose pointed at storage that cannot serve it.
    #[test]
    fn an_s3_target_is_refused_for_sync_but_accepted_for_backup() {
        let build = |sync: &str| WorkerTargets {
            purposes: PurposeTargets {
                sync: sync.to_owned(),
                backup: "cofre".to_owned(),
            },
            targets: vec![local("primary"), TargetConfig::S3(s3("cofre"))],
        };
        assert!(message(build("cofre").validate()).contains("backup-only"));
        build("primary")
            .validate()
            .expect("S3 is fine as the backup purpose");
    }

    #[test]
    fn target_lookup_resolves_each_purpose_to_its_configured_target() {
        let targets = WorkerTargets {
            purposes: PurposeTargets {
                sync: "primary".to_owned(),
                backup: "cofre".to_owned(),
            },
            targets: vec![local("primary"), TargetConfig::S3(s3("cofre"))],
        };
        targets.validate().expect("valid");
        assert_eq!(
            targets
                .target_for(crate::JobPurpose::Sync)
                .map(TargetConfig::id),
            Some("primary")
        );
        assert_eq!(
            targets
                .target_for(crate::JobPurpose::Backup)
                .map(TargetConfig::id),
            Some("cofre")
        );
        assert_eq!(
            targets
                .target_for(crate::JobPurpose::Backup)
                .map(TargetConfig::kind),
            Some(ConnectorKind::S3)
        );
        assert!(targets.target("desconhecido").is_none());
    }

    /// `with_id` must rewrite the id of whichever variant it is handed — a variant it silently
    /// skipped would keep an id the caller believes it replaced.
    #[test]
    fn with_id_rewrites_the_id_of_every_variant_and_kind_agrees_with_the_variant() {
        let variants = vec![
            (local("x"), ConnectorKind::Local),
            (
                TargetConfig::WebDav(webdav("https://a.example.pt", false)),
                ConnectorKind::WebDav,
            ),
            (
                TargetConfig::MicrosoftGraph(GraphTarget {
                    id: "x".to_owned(),
                    drive_id: "d".to_owned(),
                    parent_item_id: "i".to_owned(),
                    token_ref: secret_ref("G"),
                    api_base_url: default_graph_base(),
                    timeout_seconds: 60,
                    allow_insecure_http: false,
                }),
                ConnectorKind::MicrosoftGraph,
            ),
            (
                TargetConfig::GoogleDrive(GoogleDriveTarget {
                    id: "x".to_owned(),
                    parent_folder_id: "f".to_owned(),
                    token_ref: secret_ref("GD"),
                    api_base_url: default_google_base(),
                    timeout_seconds: 60,
                    allow_insecure_http: false,
                }),
                ConnectorKind::GoogleDrive,
            ),
            (TargetConfig::Sftp(sftp("x")), ConnectorKind::Sftp),
            (
                TargetConfig::Ftps(FtpsTarget {
                    id: "x".to_owned(),
                    host: "ftps.example.pt".to_owned(),
                    port: 21,
                    username: "chancela".to_owned(),
                    password_ref: secret_ref("F"),
                    root: "/arquivo".to_owned(),
                    timeout_seconds: 60,
                }),
                ConnectorKind::Ftps,
            ),
            (
                TargetConfig::Smb(SmbTarget {
                    id: "x".to_owned(),
                    host: "fs.example.pt".to_owned(),
                    port: 445,
                    share: "arquivo".to_owned(),
                    username: "chancela".to_owned(),
                    domain: String::new(),
                    password_ref: secret_ref("S"),
                    root: "/livros".to_owned(),
                    timeout_seconds: 60,
                    allow_unencrypted: false,
                }),
                ConnectorKind::Smb,
            ),
            (TargetConfig::S3(s3("x")), ConnectorKind::S3),
        ];
        for (target, kind) in variants {
            assert_eq!(target.kind(), kind);
            target
                .validate()
                .unwrap_or_else(|e| panic!("{kind:?} fixture must be valid: {}", e.message));
            let renamed = target.with_id("renomeado".to_owned());
            assert_eq!(renamed.id(), "renomeado", "{kind:?} ignored with_id");
            assert_eq!(renamed.kind(), kind, "{kind:?} changed under with_id");
        }
    }

    /// The wire format is operator-authored config. Unknown keys must not be silently dropped, and
    /// omitted keys must land on the documented defaults rather than on zero.
    #[test]
    fn target_config_deserializes_with_documented_defaults_and_rejects_unknown_keys() {
        let target: TargetConfig = serde_json::from_str(
            r#"{"kind":"s3","id":"cofre","bucket":"arquivo",
                "access_key_ref":"CHANCELA_CONNECTOR_SECRET_A",
                "secret_key_ref":"CHANCELA_CONNECTOR_SECRET_B",
                "endpoint_url":null,"session_token_ref":null}"#,
        )
        .expect("minimal S3 target");
        let TargetConfig::S3(s3) = &target else {
            panic!("expected the s3 variant, got {:?}", target.kind());
        };
        assert_eq!(s3.region, "us-east-1", "the documented default S3 region");
        assert_eq!(s3.timeout_seconds, 60, "the documented default timeout");
        assert!(!s3.allow_insecure_http, "HTTP is never on by default");
        assert!(!s3.force_path_style);
        target.validate().expect("defaults are themselves valid");

        assert!(
            serde_json::from_str::<TargetConfig>(
                r#"{"kind":"local","id":"p","root":"/srv","unexpected":1}"#
            )
            .is_err(),
            "an unknown key must not be silently ignored"
        );

        let sftp: SftpTarget = serde_json::from_str(
            r#"{"id":"sf","host":"h","username":"u",
                "password_ref":"CHANCELA_CONNECTOR_SECRET_P",
                "host_key_sha256":"SHA256:x","root":"/r"}"#,
        )
        .expect("minimal SFTP target");
        assert_eq!(sftp.port, 22, "the documented default SFTP port");
        assert_eq!(sftp.timeout_seconds, 60, "the documented default timeout");
    }

    #[test]
    fn a_local_target_with_an_empty_root_is_refused() {
        let target = TargetConfig::Local(LocalTarget {
            id: "primary".to_owned(),
            root: PathBuf::new(),
        });
        assert!(message(target.validate()).contains("local root is empty"));
    }

    /// Blank required identifiers would produce requests against an unintended path on the remote.
    #[test]
    fn blank_required_identifiers_are_refused_on_each_remote_target() {
        let mut graph = GraphTarget {
            id: "gr".to_owned(),
            drive_id: "   ".to_owned(),
            parent_item_id: "item".to_owned(),
            token_ref: secret_ref("G"),
            api_base_url: default_graph_base(),
            timeout_seconds: 60,
            allow_insecure_http: false,
        };
        assert!(message(graph.validate()).contains("drive_id is empty"));
        graph.drive_id = "drive".to_owned();
        graph.parent_item_id = String::new();
        assert!(message(graph.validate()).contains("parent_item_id is empty"));

        let mut google = GoogleDriveTarget {
            id: "gd".to_owned(),
            parent_folder_id: String::new(),
            token_ref: secret_ref("GD"),
            api_base_url: default_google_base(),
            timeout_seconds: 60,
            allow_insecure_http: false,
        };
        assert!(message(google.validate()).contains("parent_folder_id is empty"));
        google.parent_folder_id = "folder".to_owned();
        google.validate().expect("valid once the folder is set");

        let mut bucketless = s3("s3");
        bucketless.bucket = " ".to_owned();
        assert!(message(bucketless.validate()).contains("bucket is empty"));
        let mut regionless = s3("s3");
        regionless.region = String::new();
        assert!(message(regionless.validate()).contains("region is empty"));
    }

    /// `validate()` is the id gate for every variant, not only for the one that carries an explicit
    /// check — an invalid id on a network target must fail before its own field validation runs.
    #[test]
    fn the_target_id_is_validated_before_the_variants_own_fields() {
        let target = TargetConfig::WebDav(WebDavTarget {
            id: "id with spaces".to_owned(),
            ..webdav("not-a-url", false)
        });
        assert!(message(target.validate()).contains("invalid target id"));
    }

    #[test]
    fn webdav_basic_auth_validates_its_password_reference_too() {
        let mut target = webdav("https://arquivo.example.pt/dav", false);
        target.auth = WebDavAuth::Basic {
            username: "chancela".to_owned(),
            password_ref: "hunter2".to_owned(),
        };
        assert!(target.validate().is_err());
        target.auth = WebDavAuth::Basic {
            username: "chancela".to_owned(),
            password_ref: secret_ref("WD_PASSWORD"),
        };
        target.validate().expect("a proper reference is accepted");
    }
}
