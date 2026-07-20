use std::sync::Arc;

use async_trait::async_trait;
use reqwest::header::{CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, HeaderName, LOCATION};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;

use crate::http::{bearer, client, validate_upload_session_url, verify_source};
use crate::{
    CancellationToken, Capability, ChecksumEvidence, Connector, ConnectorError, ConnectorKind,
    ConnectorStatus, ErrorClass, GoogleDriveTarget, ObjectInfo, ProbeState, RetryPolicy,
    SecretProvider, UploadReceipt, UploadRequest, retry_operation,
};

const DRIVE_CHUNK: usize = 8 * 1024 * 1024;
const CAPABILITIES: &[Capability] = &[
    Capability::Upload,
    Capability::Search,
    Capability::CreateFolder,
    Capability::Revisions,
    Capability::ResumableUpload,
    Capability::SourceChecksum,
];

#[derive(Clone)]
pub struct GoogleDriveConnector {
    config: GoogleDriveTarget,
    secrets: Arc<dyn SecretProvider>,
    client: reqwest::Client,
}

impl std::fmt::Debug for GoogleDriveConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GoogleDriveConnector")
            .field("target_id", &self.config.id)
            .field("parent_folder_id", &self.config.parent_folder_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveFile {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub size: Option<String>,
    #[serde(default)]
    pub md5_checksum: Option<String>,
    #[serde(default)]
    pub head_revision_id: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveRevision {
    pub id: String,
    #[serde(default)]
    pub modified_time: Option<String>,
    #[serde(default)]
    pub keep_forever: bool,
}

#[derive(Debug, Default, Deserialize)]
struct FileList {
    #[serde(default)]
    files: Vec<DriveFile>,
}

#[derive(Debug, Default, Deserialize)]
struct RevisionList {
    #[serde(default)]
    revisions: Vec<DriveRevision>,
}

impl GoogleDriveConnector {
    pub fn new(
        config: GoogleDriveTarget,
        secrets: Arc<dyn SecretProvider>,
    ) -> Result<Self, ConnectorError> {
        config.validate()?;
        let http = client(config.timeout_seconds)?;
        Ok(Self {
            config,
            secrets,
            client: http,
        })
    }

    fn endpoint(&self, suffix: &str) -> String {
        format!(
            "{}/{}",
            self.config.api_base_url.trim_end_matches('/'),
            suffix.trim_start_matches('/')
        )
    }

    fn endpoint_with_query(
        &self,
        suffix: &str,
        pairs: &[(&str, &str)],
    ) -> Result<reqwest::Url, ConnectorError> {
        let mut url = reqwest::Url::parse(&self.endpoint(suffix))
            .map_err(|_| ConnectorError::configuration("invalid Google Drive endpoint URL"))?;
        url.query_pairs_mut().extend_pairs(pairs.iter().copied());
        Ok(url)
    }

    fn token(&self) -> Result<crate::SecretValue, ConnectorError> {
        self.secrets.resolve(&self.config.token_ref)
    }

    pub async fn search(&self, query: &str) -> Result<Vec<ObjectInfo>, ConnectorError> {
        let token = self.token()?;
        let response = bearer(
            self.client.get(self.endpoint_with_query(
                "drive/v3/files",
                &[
                    ("q", query),
                    ("fields", "files(id,name,size,headRevisionId)"),
                    ("spaces", "drive"),
                    ("supportsAllDrives", "true"),
                    ("includeItemsFromAllDrives", "true"),
                ],
            )?),
            &token,
        )
        .send()
        .await
        .map_err(|_| ConnectorError::transient("Google Drive search transport failed"))?;
        if !response.status().is_success() {
            return Err(ConnectorError::from_http(
                response.status(),
                "Google Drive search",
            ));
        }
        let list: FileList = response
            .json()
            .await
            .map_err(|_| ConnectorError::new(ErrorClass::Permanent, "invalid Drive file list"))?;
        Ok(list
            .files
            .into_iter()
            .map(|file| ObjectInfo {
                id: file.id,
                name: file.name,
                size: file.size.and_then(|value| value.parse().ok()),
                etag: None,
                revision: file.head_revision_id,
            })
            .collect())
    }

    pub async fn create_folder(
        &self,
        name: &str,
        parent: Option<&str>,
    ) -> Result<DriveFile, ConnectorError> {
        if name.trim().is_empty() {
            return Err(ConnectorError::configuration("Drive folder name is empty"));
        }
        let token = self.token()?;
        let response = bearer(
            self.client
                .post(self.endpoint_with_query(
                    "drive/v3/files",
                    &[("supportsAllDrives", "true"), ("fields", "id,name")],
                )?)
                .json(&serde_json::json!({
                    "name": name,
                    "mimeType": "application/vnd.google-apps.folder",
                    "parents": [parent.unwrap_or(&self.config.parent_folder_id)]
                })),
            &token,
        )
        .send()
        .await
        .map_err(|_| ConnectorError::transient("Google Drive folder transport failed"))?;
        if !response.status().is_success() {
            return Err(ConnectorError::from_http(
                response.status(),
                "Google Drive create folder",
            ));
        }
        response.json().await.map_err(|_| {
            ConnectorError::new(ErrorClass::Permanent, "invalid Drive folder response")
        })
    }

    pub async fn revisions(&self, file_id: &str) -> Result<Vec<DriveRevision>, ConnectorError> {
        let token = self.token()?;
        let response = bearer(
            self.client.get(self.endpoint_with_query(
                &format!("drive/v3/files/{file_id}/revisions"),
                &[
                    ("pageSize", "1000"),
                    ("fields", "revisions(id,modifiedTime,keepForever)"),
                ],
            )?),
            &token,
        )
        .send()
        .await
        .map_err(|_| ConnectorError::transient("Google Drive revisions transport failed"))?;
        if !response.status().is_success() {
            return Err(ConnectorError::from_http(
                response.status(),
                "Google Drive revisions",
            ));
        }
        let list: RevisionList = response.json().await.map_err(|_| {
            ConnectorError::new(ErrorClass::Permanent, "invalid Drive revision list")
        })?;
        Ok(list.revisions)
    }

    async fn create_upload_session(
        &self,
        request: &UploadRequest,
    ) -> Result<String, ConnectorError> {
        let token = self.token()?;
        let name =
            request.destination.rsplit('/').next().ok_or_else(|| {
                ConnectorError::configuration("Drive destination has no file name")
            })?;
        let response = bearer(
            self.client
                .post(self.endpoint_with_query(
                    "upload/drive/v3/files",
                    &[
                        ("uploadType", "resumable"),
                        ("supportsAllDrives", "true"),
                        ("fields", "id,name,size,md5Checksum,headRevisionId"),
                    ],
                )?)
                .header(
                    HeaderName::from_static("x-upload-content-type"),
                    request.content_type.as_str(),
                )
                .header(
                    HeaderName::from_static("x-upload-content-length"),
                    request.bytes,
                )
                .json(&serde_json::json!({
                    "name": name,
                    "parents": [self.config.parent_folder_id],
                    "appProperties": {
                        "chancelaIdempotencyKey": request.idempotency_key,
                        "chancelaSha256": request.source_sha256,
                        "chancelaPurpose": format!("{:?}", request.purpose).to_ascii_lowercase()
                    }
                })),
            &token,
        )
        .send()
        .await
        .map_err(|_| {
            ConnectorError::transient("Google Drive resumable session transport failed")
        })?;
        if !response.status().is_success() {
            return Err(ConnectorError::from_http(
                response.status(),
                "Google Drive create resumable session",
            ));
        }
        let upload_url = response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| {
                ConnectorError::new(
                    ErrorClass::Permanent,
                    "Drive upload session omitted Location header",
                )
            })?;
        validate_upload_session_url(&upload_url, "Google Drive", self.config.allow_insecure_http)
            .await?;
        Ok(upload_url)
    }
}

#[async_trait]
impl Connector for GoogleDriveConnector {
    fn target_id(&self) -> &str {
        &self.config.id
    }

    fn kind(&self) -> ConnectorKind {
        ConnectorKind::GoogleDrive
    }

    fn capabilities(&self) -> &'static [Capability] {
        CAPABILITIES
    }

    async fn probe(&self) -> Result<ConnectorStatus, ConnectorError> {
        let token = self.token()?;
        let response = bearer(
            self.client
                .get(self.endpoint_with_query("drive/v3/about", &[("fields", "user")])?),
            &token,
        )
        .send()
        .await
        .map_err(|_| ConnectorError::transient("Google Drive probe transport failed"))?;
        if !response.status().is_success() {
            return Err(ConnectorError::from_http(
                response.status(),
                "Google Drive probe",
            ));
        }
        Ok(ConnectorStatus {
            target_id: self.config.id.clone(),
            kind: self.kind(),
            state: ProbeState::Ready,
            capabilities: CAPABILITIES.to_vec(),
            detail: "Google Drive about resource is reachable".to_owned(),
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
        let upload_url = self.create_upload_session(request).await?;
        let mut source = tokio::fs::File::open(&request.source)
            .await
            .map_err(|error| ConnectorError::io("open Google Drive source", &error))?;
        let mut offset = 0_u64;
        let mut committed = DriveFile::default();
        let mut buffer = vec![0_u8; DRIVE_CHUNK];
        if request.bytes == 0 {
            let response = self
                .client
                .put(&upload_url)
                .header(CONTENT_LENGTH, 0)
                .header(CONTENT_TYPE, request.content_type.as_str())
                .body(Vec::<u8>::new())
                .send()
                .await
                .map_err(|_| ConnectorError::transient("Drive empty upload transport failed"))?;
            if !response.status().is_success() {
                return Err(ConnectorError::from_http(
                    response.status(),
                    "Google Drive empty upload",
                ));
            }
            committed = response.json().await.map_err(|_| {
                ConnectorError::new(ErrorClass::Permanent, "invalid Drive file response")
            })?;
        }
        while offset < request.bytes {
            cancellation.check()?;
            let wanted = usize::try_from((request.bytes - offset).min(DRIVE_CHUNK as u64))
                .map_err(|_| ConnectorError::configuration("Drive chunk size overflow"))?;
            source
                .read_exact(&mut buffer[..wanted])
                .await
                .map_err(|error| ConnectorError::io("read Drive source chunk", &error))?;
            let end = offset + wanted as u64 - 1;
            let chunk = bytes::Bytes::copy_from_slice(&buffer[..wanted]);
            let url = upload_url.clone();
            let client = self.client.clone();
            let (response, _) = retry_operation(RetryPolicy::default(), cancellation, |_| {
                let client = client.clone();
                let url = url.clone();
                let chunk = chunk.clone();
                async move {
                    let response = client
                        .put(url)
                        .header(CONTENT_LENGTH, chunk.len())
                        .header(
                            CONTENT_RANGE,
                            format!("bytes {offset}-{end}/{}", request.bytes),
                        )
                        .header(CONTENT_TYPE, request.content_type.as_str())
                        .body(chunk)
                        .send()
                        .await
                        .map_err(|_| ConnectorError::transient("Drive chunk transport failed"))?;
                    if response.status().is_success() || response.status().as_u16() == 308 {
                        Ok(response)
                    } else {
                        Err(ConnectorError::from_http(
                            response.status(),
                            "Google Drive chunk upload",
                        ))
                    }
                }
            })
            .await?;
            if response.status().is_success() && response.status().as_u16() != 308 {
                committed = response.json().await.map_err(|_| {
                    ConnectorError::new(ErrorClass::Permanent, "invalid Drive file response")
                })?;
            }
            offset = end + 1;
        }
        if let Some(size) = committed
            .size
            .as_deref()
            .and_then(|value| value.parse::<u64>().ok())
            && size != request.bytes
        {
            return Err(ConnectorError::new(
                ErrorClass::Integrity,
                "Google Drive reported a different committed item size",
            ));
        }
        Ok(UploadReceipt {
            target_id: self.config.id.clone(),
            connector: self.kind(),
            destination: request.destination.clone(),
            provider_object_id: (!committed.id.is_empty()).then_some(committed.id),
            provider_revision: committed.head_revision_id,
            etag: None,
            source_sha256: request.source_sha256.clone(),
            bytes: request.bytes,
            checksum_evidence: ChecksumEvidence::SourceOnly,
        })
    }
}
