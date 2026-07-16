use std::sync::Arc;

use async_trait::async_trait;
use reqwest::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use tokio_util::io::ReaderStream;

use crate::http::{client, encode_path, temporary_destination, verify_source};
use crate::{
    CancellationToken, Capability, ChecksumEvidence, Connector, ConnectorError, ConnectorKind,
    ConnectorStatus, ProbeState, SecretProvider, UploadReceipt, UploadRequest, WebDavAuth,
    WebDavTarget,
};

const CAPABILITIES: &[Capability] = &[
    Capability::Upload,
    Capability::CreateFolder,
    Capability::AtomicReplace,
    Capability::SourceChecksum,
];

#[derive(Clone)]
pub struct WebDavConnector {
    config: WebDavTarget,
    secrets: Arc<dyn SecretProvider>,
    client: reqwest::Client,
}

impl std::fmt::Debug for WebDavConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WebDavConnector")
            .field("target_id", &self.config.id)
            .field("base_url", &self.config.base_url)
            .finish_non_exhaustive()
    }
}

impl WebDavConnector {
    pub fn new(
        config: WebDavTarget,
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

    fn url(&self, path: &str) -> Result<String, ConnectorError> {
        Ok(format!(
            "{}/{}",
            self.config.base_url.trim_end_matches('/'),
            encode_path(path)?
        ))
    }

    fn authorize(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, ConnectorError> {
        match &self.config.auth {
            WebDavAuth::Basic {
                username,
                password_ref,
            } => {
                let password = self.secrets.resolve(password_ref)?;
                Ok(builder.basic_auth(username, Some(password.expose())))
            }
            WebDavAuth::Bearer { token_ref } => {
                let token = self.secrets.resolve(token_ref)?;
                Ok(builder.bearer_auth(token.expose()))
            }
        }
    }

    async fn send(
        &self,
        builder: reqwest::RequestBuilder,
        operation: &str,
    ) -> Result<reqwest::Response, ConnectorError> {
        let response = self
            .authorize(builder)?
            .send()
            .await
            .map_err(|_| ConnectorError::transient(format!("{operation} transport failed")))?;
        if response.status().is_success() || response.status().as_u16() == 207 {
            Ok(response)
        } else {
            Err(ConnectorError::from_http(response.status(), operation))
        }
    }

    async fn ensure_parent_collections(
        &self,
        destination: &str,
        cancellation: &CancellationToken,
    ) -> Result<(), ConnectorError> {
        let components: Vec<_> = destination.split('/').collect();
        let mut parent = String::new();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            cancellation.check()?;
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(component);
            let method = reqwest::Method::from_bytes(b"MKCOL")
                .map_err(|_| ConnectorError::configuration("invalid MKCOL method"))?;
            let response = self
                .authorize(self.client.request(method, self.url(&parent)?))?
                .send()
                .await
                .map_err(|_| ConnectorError::transient("WebDAV MKCOL transport failed"))?;
            if !response.status().is_success() && response.status().as_u16() != 405 {
                return Err(ConnectorError::from_http(response.status(), "WebDAV MKCOL"));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Connector for WebDavConnector {
    fn target_id(&self) -> &str {
        &self.config.id
    }

    fn kind(&self) -> ConnectorKind {
        ConnectorKind::WebDav
    }

    fn capabilities(&self) -> &'static [Capability] {
        CAPABILITIES
    }

    async fn probe(&self) -> Result<ConnectorStatus, ConnectorError> {
        let method = reqwest::Method::from_bytes(b"PROPFIND")
            .map_err(|_| ConnectorError::configuration("invalid PROPFIND method"))?;
        self.send(
            self.client
                .request(method, self.config.base_url.trim_end_matches('/'))
                .header("Depth", "0")
                .header(CONTENT_TYPE, "application/xml")
                .body(
                    r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:getetag/></d:prop></d:propfind>"#,
                ),
            "WebDAV PROPFIND",
        )
        .await?;
        Ok(ConnectorStatus {
            target_id: self.config.id.clone(),
            kind: self.kind(),
            state: ProbeState::Ready,
            capabilities: CAPABILITIES.to_vec(),
            detail: "authenticated WebDAV collection responded to PROPFIND".to_owned(),
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
        self.ensure_parent_collections(&request.destination, cancellation)
            .await?;
        let temporary = temporary_destination(&request.destination, &request.idempotency_key);
        let temporary_url = self.url(&temporary)?;
        let destination_url = self.url(&request.destination)?;
        let source = tokio::fs::File::open(&request.source)
            .await
            .map_err(|error| ConnectorError::io("open WebDAV source", &error))?;
        cancellation.check()?;
        let put = self
            .send(
                self.client
                    .put(&temporary_url)
                    .header(CONTENT_TYPE, request.content_type.as_str())
                    .header(
                        HeaderName::from_static("oc-checksum"),
                        HeaderValue::from_str(&format!("SHA256:{}", request.source_sha256))
                            .map_err(|_| {
                                ConnectorError::configuration("invalid source checksum")
                            })?,
                    )
                    .header("OC-Total-Length", request.bytes)
                    .body(reqwest::Body::wrap_stream(ReaderStream::new(source))),
                "WebDAV PUT",
            )
            .await?;
        let put_etag = put
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);

        cancellation.check()?;
        let move_method = reqwest::Method::from_bytes(b"MOVE")
            .map_err(|_| ConnectorError::configuration("invalid MOVE method"))?;
        let moved = self
            .send(
                self.client
                    .request(move_method, &temporary_url)
                    .header("Destination", &destination_url)
                    .header("Overwrite", "T"),
                "WebDAV MOVE",
            )
            .await;
        let moved = match moved {
            Ok(response) => response,
            Err(error) => {
                if let Ok(delete) = self.authorize(self.client.delete(&temporary_url)) {
                    let _ = delete.send().await;
                }
                return Err(error);
            }
        };
        let etag = moved
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .or(put_etag);
        Ok(UploadReceipt {
            target_id: self.config.id.clone(),
            connector: self.kind(),
            destination: request.destination.clone(),
            provider_object_id: None,
            provider_revision: None,
            etag,
            source_sha256: request.source_sha256.clone(),
            bytes: request.bytes,
            checksum_evidence: ChecksumEvidence::SentToProvider,
        })
    }
}
