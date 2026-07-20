use std::sync::Arc;

use async_trait::async_trait;
use reqwest::header::{CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE};
use serde::Deserialize;
use tokio::io::AsyncReadExt;

use crate::http::{bearer, client, encode_path, validate_upload_session_url, verify_source};
use crate::{
    CancellationToken, Capability, ChecksumEvidence, Connector, ConnectorError, ConnectorKind,
    ConnectorStatus, ErrorClass, GraphTarget, ProbeState, RetryPolicy, SecretProvider,
    UploadReceipt, UploadRequest, retry_operation,
};

const GRAPH_CHUNK: usize = 10 * 1024 * 1024;
const CAPABILITIES: &[Capability] = &[
    Capability::Upload,
    Capability::ResumableUpload,
    Capability::SourceChecksum,
    Capability::RemoteChecksum,
];

#[derive(Clone)]
pub struct GraphConnector {
    config: GraphTarget,
    secrets: Arc<dyn SecretProvider>,
    client: reqwest::Client,
}

impl std::fmt::Debug for GraphConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GraphConnector")
            .field("target_id", &self.config.id)
            .field("drive_id", &self.config.drive_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadSession {
    upload_url: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphHashes {
    sha256_hash: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct GraphFile {
    #[serde(default)]
    hashes: GraphHashes,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphDriveItem {
    id: Option<String>,
    e_tag: Option<String>,
    c_tag: Option<String>,
    size: Option<u64>,
    #[serde(default)]
    file: GraphFile,
}

impl GraphConnector {
    pub fn new(
        config: GraphTarget,
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

    fn token(&self) -> Result<crate::SecretValue, ConnectorError> {
        self.secrets.resolve(&self.config.token_ref)
    }

    async fn create_session(
        &self,
        request: &UploadRequest,
    ) -> Result<UploadSession, ConnectorError> {
        let drive = encode_path(&self.config.drive_id)?;
        let parent = encode_path(&self.config.parent_item_id)?;
        let destination = encode_path(&request.destination)?;
        let url = self.endpoint(&format!(
            "drives/{drive}/items/{parent}:/{destination}:/createUploadSession"
        ));
        let token = self.token()?;
        let response = bearer(
            self.client.post(url).json(&serde_json::json!({
                "item": {
                    "@microsoft.graph.conflictBehavior": "replace",
                    "description": format!("Chancela {} SHA-256 {}", request.idempotency_key, request.source_sha256),
                },
                "deferCommit": false
            })),
            &token,
        )
        .send()
        .await
        .map_err(|_| ConnectorError::transient("Graph createUploadSession transport failed"))?;
        if !response.status().is_success() {
            return Err(ConnectorError::from_http(
                response.status(),
                "Graph createUploadSession",
            ));
        }
        let session: UploadSession = response.json().await.map_err(|_| {
            ConnectorError::new(
                ErrorClass::Permanent,
                "invalid Graph upload session response",
            )
        })?;
        validate_upload_session_url(
            &session.upload_url,
            "Graph",
            self.config.allow_insecure_http,
        )
        .await?;
        Ok(session)
    }
}

#[async_trait]
impl Connector for GraphConnector {
    fn target_id(&self) -> &str {
        &self.config.id
    }

    fn kind(&self) -> ConnectorKind {
        ConnectorKind::MicrosoftGraph
    }

    fn capabilities(&self) -> &'static [Capability] {
        CAPABILITIES
    }

    async fn probe(&self) -> Result<ConnectorStatus, ConnectorError> {
        let token = self.token()?;
        let drive = encode_path(&self.config.drive_id)?;
        let response = bearer(
            self.client.get(self.endpoint(&format!("drives/{drive}"))),
            &token,
        )
        .send()
        .await
        .map_err(|_| ConnectorError::transient("Graph drive probe transport failed"))?;
        if !response.status().is_success() {
            return Err(ConnectorError::from_http(
                response.status(),
                "Graph drive probe",
            ));
        }
        Ok(ConnectorStatus {
            target_id: self.config.id.clone(),
            kind: self.kind(),
            state: ProbeState::Ready,
            capabilities: CAPABILITIES.to_vec(),
            detail: "Microsoft Graph drive metadata is reachable".to_owned(),
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
        let mut final_item = GraphDriveItem::default();
        if request.bytes == 0 {
            let drive = encode_path(&self.config.drive_id)?;
            let parent = encode_path(&self.config.parent_item_id)?;
            let destination = encode_path(&request.destination)?;
            let token = self.token()?;
            let response = bearer(
                self.client.put(self.endpoint(&format!(
                    "drives/{drive}/items/{parent}:/{destination}:/content"
                ))),
                &token,
            )
            .header(CONTENT_LENGTH, 0)
            .header(CONTENT_TYPE, request.content_type.as_str())
            .body(Vec::<u8>::new())
            .send()
            .await
            .map_err(|_| ConnectorError::transient("Graph empty upload transport failed"))?;
            if !matches!(response.status().as_u16(), 200 | 201) {
                return Err(ConnectorError::from_http(
                    response.status(),
                    "Graph empty upload",
                ));
            }
            final_item = response.json().await.map_err(|_| {
                ConnectorError::new(ErrorClass::Permanent, "invalid Graph driveItem response")
            })?;
        } else {
            let session = self.create_session(request).await?;
            let mut source = tokio::fs::File::open(&request.source)
                .await
                .map_err(|error| ConnectorError::io("open Graph source", &error))?;
            let mut offset = 0_u64;
            let mut buffer = vec![0_u8; GRAPH_CHUNK];
            while offset < request.bytes {
                cancellation.check()?;
                let wanted = usize::try_from((request.bytes - offset).min(GRAPH_CHUNK as u64))
                    .map_err(|_| ConnectorError::configuration("Graph chunk size overflow"))?;
                source
                    .read_exact(&mut buffer[..wanted])
                    .await
                    .map_err(|error| ConnectorError::io("read Graph source chunk", &error))?;
                let end = offset + wanted as u64 - 1;
                let chunk = bytes::Bytes::copy_from_slice(&buffer[..wanted]);
                let upload_url = session.upload_url.clone();
                let client = self.client.clone();
                let (response, _) = retry_operation(RetryPolicy::default(), cancellation, |_| {
                    let client = client.clone();
                    let upload_url = upload_url.clone();
                    let chunk = chunk.clone();
                    async move {
                        let response = client
                            .put(upload_url)
                            .header(CONTENT_LENGTH, chunk.len())
                            .header(
                                CONTENT_RANGE,
                                format!("bytes {offset}-{end}/{}", request.bytes),
                            )
                            .header(CONTENT_TYPE, "application/octet-stream")
                            .body(chunk)
                            .send()
                            .await
                            .map_err(|_| {
                                ConnectorError::transient("Graph chunk transport failed")
                            })?;
                        if matches!(response.status().as_u16(), 200..=202) {
                            Ok(response)
                        } else {
                            Err(ConnectorError::from_http(
                                response.status(),
                                "Graph chunk upload",
                            ))
                        }
                    }
                })
                .await?;
                if matches!(response.status().as_u16(), 200 | 201) {
                    final_item = response.json().await.map_err(|_| {
                        ConnectorError::new(
                            ErrorClass::Permanent,
                            "invalid Graph driveItem response",
                        )
                    })?;
                }
                offset = end + 1;
            }
        }

        if let Some(remote_sha256) = &final_item.file.hashes.sha256_hash
            && !remote_sha256.eq_ignore_ascii_case(&request.source_sha256)
        {
            return Err(ConnectorError::new(
                ErrorClass::Integrity,
                "Graph reported a different SHA-256 for the committed item",
            ));
        }
        if let Some(remote_size) = final_item.size
            && remote_size != request.bytes
        {
            return Err(ConnectorError::new(
                ErrorClass::Integrity,
                "Graph reported a different committed item size",
            ));
        }
        let checksum_evidence = if final_item.file.hashes.sha256_hash.is_some() {
            ChecksumEvidence::RemoteConfirmed
        } else {
            ChecksumEvidence::SourceOnly
        };
        Ok(UploadReceipt {
            target_id: self.config.id.clone(),
            connector: self.kind(),
            destination: request.destination.clone(),
            provider_object_id: final_item.id,
            provider_revision: final_item.c_tag,
            etag: final_item.e_tag,
            source_sha256: request.source_sha256.clone(),
            bytes: request.bytes,
            checksum_evidence,
        })
    }
}
