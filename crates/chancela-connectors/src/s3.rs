use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::retry::RetryConfig as AwsRetryConfig;
use aws_sdk_s3::config::timeout::TimeoutConfig;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::primitives::{ByteStream, Length};
use aws_sdk_s3::types::{
    ChecksumAlgorithm, ChecksumMode, ChecksumType, CompletedMultipartUpload, CompletedPart,
};
use base64::Engine;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::http::{sha256_file, validate_relative_path, verify_source};
use crate::{
    CancellationToken, Capability, ChecksumEvidence, Connector, ConnectorError, ConnectorKind,
    ConnectorStatus, DownloadReceipt, ErrorClass, JobPurpose, ObjectInfo, ProbeState, S3Target,
    SecretProvider, UploadReceipt, UploadRequest,
};

const MIN_PART_SIZE: u64 = 8 * 1024 * 1024;
const MAX_PARTS: u64 = 10_000;
const CAPABILITIES: &[Capability] = &[
    Capability::Upload,
    Capability::Download,
    Capability::List,
    Capability::MultipartUpload,
    Capability::ResumableUpload,
    Capability::SourceChecksum,
    Capability::RemoteChecksum,
];

#[derive(Clone)]
pub struct S3Connector {
    config: S3Target,
    client: Client,
}

impl std::fmt::Debug for S3Connector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("S3Connector")
            .field("target_id", &self.config.id)
            .field("path_style", &self.config.force_path_style)
            .finish_non_exhaustive()
    }
}

impl S3Connector {
    pub fn new(config: S3Target, secrets: Arc<dyn SecretProvider>) -> Result<Self, ConnectorError> {
        config.validate()?;
        if config.bucket.trim().is_empty() || config.region.trim().is_empty() {
            return Err(ConnectorError::configuration(
                "S3 bucket and region are required",
            ));
        }
        if let Some(endpoint) = &config.endpoint_url {
            let parsed = reqwest::Url::parse(endpoint)
                .map_err(|_| ConnectorError::configuration("invalid S3 endpoint URL"))?;
            if parsed.scheme() != "https"
                && !(parsed.scheme() == "http" && config.allow_insecure_http)
            {
                return Err(ConnectorError::configuration(
                    "S3 endpoint must use HTTPS unless allow_insecure_http is explicitly enabled",
                ));
            }
        }
        let access_key = secrets.resolve(&config.access_key_ref)?;
        let secret_key = secrets.resolve(&config.secret_key_ref)?;
        let session_token = config
            .session_token_ref
            .as_deref()
            .map(|reference| secrets.resolve(reference))
            .transpose()?
            .map(|secret| secret.expose().to_owned());
        let credentials = Credentials::new(
            access_key.expose(),
            secret_key.expose(),
            session_token,
            None,
            "chancela-secret-provider",
        );
        let timeout = Duration::from_secs(config.timeout_seconds);
        let mut builder = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .credentials_provider(credentials)
            .region(Region::new(config.region.clone()))
            .force_path_style(config.force_path_style)
            .retry_config(AwsRetryConfig::standard().with_max_attempts(4))
            .timeout_config(
                TimeoutConfig::builder()
                    .connect_timeout(timeout.min(Duration::from_secs(30)))
                    .read_timeout(timeout)
                    .operation_attempt_timeout(timeout)
                    .operation_timeout(timeout.saturating_mul(4))
                    .build(),
            );
        if let Some(endpoint) = &config.endpoint_url {
            builder = builder.endpoint_url(endpoint);
        }
        Ok(Self {
            config,
            client: Client::from_conf(builder.build()),
        })
    }

    fn map_code(code: Option<&str>, operation: &str) -> ConnectorError {
        let class = match code {
            Some(
                "AccessDenied"
                | "InvalidAccessKeyId"
                | "InvalidToken"
                | "SignatureDoesNotMatch"
                | "ExpiredToken",
            ) => ErrorClass::Authentication,
            Some("NoSuchBucket" | "NoSuchKey" | "NotFound") => ErrorClass::NotFound,
            Some("PreconditionFailed" | "OperationAborted" | "EntityAlreadyExists") => {
                ErrorClass::Conflict
            }
            Some("SlowDown" | "Throttling" | "ThrottlingException") => ErrorClass::RateLimited,
            Some("InternalError" | "RequestTimeout" | "ServiceUnavailable") | None => {
                ErrorClass::Transient
            }
            _ => ErrorClass::Permanent,
        };
        ConnectorError::new(class, format!("S3 {operation} failed"))
    }

    fn key(&self, destination: &str) -> Result<String, ConnectorError> {
        validate_relative_path(destination)?;
        let prefix = self.config.prefix.trim_matches('/');
        if prefix.is_empty() {
            Ok(destination.replace('\\', "/"))
        } else {
            Ok(format!("{prefix}/{}", destination.replace('\\', "/")))
        }
    }

    fn display_key(&self, key: &str) -> String {
        let prefix = self.config.prefix.trim_matches('/');
        if prefix.is_empty() {
            key.to_owned()
        } else {
            key.strip_prefix(prefix)
                .and_then(|rest| rest.strip_prefix('/'))
                .unwrap_or(key)
                .to_owned()
        }
    }

    async fn head_raw(
        &self,
        key: &str,
    ) -> Result<aws_sdk_s3::operation::head_object::HeadObjectOutput, ConnectorError> {
        self.client
            .head_object()
            .bucket(&self.config.bucket)
            .key(key)
            .checksum_mode(ChecksumMode::Enabled)
            .send()
            .await
            .map_err(|error| {
                Self::map_code(
                    error
                        .as_service_error()
                        .and_then(ProvideErrorMetadata::code),
                    "HEAD object",
                )
            })
    }

    pub async fn stat(&self, destination: &str) -> Result<ObjectInfo, ConnectorError> {
        let key = self.key(destination)?;
        let output = self.head_raw(&key).await?;
        Ok(ObjectInfo {
            id: key,
            name: destination.to_owned(),
            size: output
                .content_length()
                .and_then(|value| u64::try_from(value).ok()),
            etag: output.e_tag().map(ToOwned::to_owned),
            revision: output.version_id().map(ToOwned::to_owned),
        })
    }

    pub async fn list(
        &self,
        relative_prefix: &str,
        limit: usize,
    ) -> Result<Vec<ObjectInfo>, ConnectorError> {
        let limit = limit.clamp(1, 10_000);
        let prefix = if relative_prefix.is_empty() {
            self.config.prefix.trim_matches('/').to_owned()
        } else {
            self.key(relative_prefix)?
        };
        let mut continuation = None;
        let mut objects = Vec::with_capacity(limit.min(1_000));
        while objects.len() < limit {
            let remaining = (limit - objects.len()).min(1_000) as i32;
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.config.bucket)
                .prefix(&prefix)
                .max_keys(remaining);
            if let Some(token) = continuation.take() {
                request = request.continuation_token(token);
            }
            let page = request.send().await.map_err(|error| {
                Self::map_code(
                    error
                        .as_service_error()
                        .and_then(ProvideErrorMetadata::code),
                    "LIST objects",
                )
            })?;
            for object in page.contents() {
                let Some(key) = object.key() else {
                    continue;
                };
                objects.push(ObjectInfo {
                    id: key.to_owned(),
                    name: self.display_key(key),
                    size: object.size().and_then(|value| u64::try_from(value).ok()),
                    etag: object.e_tag().map(ToOwned::to_owned),
                    revision: None,
                });
                if objects.len() == limit {
                    break;
                }
            }
            if !page.is_truncated().unwrap_or(false) {
                break;
            }
            continuation = page.next_continuation_token().map(ToOwned::to_owned);
            if continuation.is_none() {
                break;
            }
        }
        Ok(objects)
    }

    pub async fn download(
        &self,
        source: &str,
        destination: &Path,
        cancellation: &CancellationToken,
    ) -> Result<DownloadReceipt, ConnectorError> {
        let key = self.key(source)?;
        cancellation.check()?;
        let output = self
            .client
            .get_object()
            .bucket(&self.config.bucket)
            .key(&key)
            .checksum_mode(ChecksumMode::Enabled)
            .send()
            .await
            .map_err(|error| {
                Self::map_code(
                    error
                        .as_service_error()
                        .and_then(ProvideErrorMetadata::code),
                    "GET object",
                )
            })?;
        let expected_sha256 = output
            .metadata()
            .and_then(|metadata| metadata.get("chancela-sha256"))
            .cloned();
        let parent = destination
            .parent()
            .ok_or_else(|| ConnectorError::configuration("download destination has no parent"))?;
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|error| ConnectorError::io("create S3 download directory", &error))?;
        let filename = destination
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| ConnectorError::configuration("invalid S3 download file name"))?;
        let temporary = parent.join(format!(
            ".{filename}.chancela-{}.part",
            uuid::Uuid::new_v4()
        ));
        let mut target = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .await
            .map_err(|error| ConnectorError::io("create S3 download temporary file", &error))?;
        let mut reader = output.body.into_async_read();
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            if let Err(error) = cancellation.check() {
                drop(target);
                let _ = tokio::fs::remove_file(&temporary).await;
                return Err(error);
            }
            let read = reader
                .read(&mut buffer)
                .await
                .map_err(|_| ConnectorError::transient("S3 download stream failed"))?;
            if read == 0 {
                break;
            }
            target
                .write_all(&buffer[..read])
                .await
                .map_err(|error| ConnectorError::io("write S3 download", &error))?;
        }
        target
            .sync_all()
            .await
            .map_err(|error| ConnectorError::io("sync S3 download", &error))?;
        drop(target);
        let (downloaded_sha256, bytes) = sha256_file(&temporary).await?;
        if expected_sha256
            .as_deref()
            .is_some_and(|expected| expected != downloaded_sha256)
        {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(ConnectorError::new(
                ErrorClass::Integrity,
                "S3 downloaded object failed the stored SHA-256 check",
            ));
        }
        if tokio::fs::try_exists(destination)
            .await
            .map_err(|error| ConnectorError::io("inspect S3 download destination", &error))?
        {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(ConnectorError::new(
                ErrorClass::Conflict,
                "S3 download destination already exists",
            ));
        }
        tokio::fs::rename(&temporary, destination)
            .await
            .map_err(|error| ConnectorError::io("commit S3 download", &error))?;
        Ok(DownloadReceipt {
            target_id: self.config.id.clone(),
            connector: self.kind(),
            source: source.to_owned(),
            destination: destination.to_owned(),
            source_sha256: expected_sha256.clone(),
            downloaded_sha256,
            bytes,
            checksum_evidence: if expected_sha256.is_some() {
                ChecksumEvidence::RemoteConfirmed
            } else {
                ChecksumEvidence::SourceOnly
            },
        })
    }

    async fn abort(&self, key: &str, upload_id: &str) {
        let _ = self
            .client
            .abort_multipart_upload()
            .bucket(&self.config.bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await;
    }

    fn part_size(bytes: u64) -> u64 {
        let required = bytes.div_ceil(MAX_PARTS);
        required.max(MIN_PART_SIZE).div_ceil(1024 * 1024) * 1024 * 1024
    }

    async fn multipart_upload(
        &self,
        request: &UploadRequest,
        key: &str,
        cancellation: &CancellationToken,
    ) -> Result<UploadReceipt, ConnectorError> {
        let created = self
            .client
            .create_multipart_upload()
            .bucket(&self.config.bucket)
            .key(key)
            .content_type(&request.content_type)
            .metadata("chancela-sha256", &request.source_sha256)
            .metadata("chancela-idempotency", &request.idempotency_key)
            .metadata("chancela-purpose", "backup")
            .checksum_algorithm(ChecksumAlgorithm::Crc32)
            .checksum_type(ChecksumType::Composite)
            .send()
            .await
            .map_err(|error| {
                Self::map_code(
                    error
                        .as_service_error()
                        .and_then(ProvideErrorMetadata::code),
                    "CREATE multipart upload",
                )
            })?;
        let upload_id = created.upload_id().ok_or_else(|| {
            ConnectorError::new(
                ErrorClass::Permanent,
                "S3 multipart upload did not return an upload id",
            )
        })?;
        let part_size = Self::part_size(request.bytes);
        let mut offset = 0_u64;
        let mut part_number = 1_i32;
        let mut parts = Vec::new();
        while offset < request.bytes {
            if let Err(error) = cancellation.check() {
                self.abort(key, upload_id).await;
                return Err(error);
            }
            let length = (request.bytes - offset).min(part_size);
            let body = match ByteStream::read_from()
                .path(&request.source)
                .offset(offset)
                .length(Length::Exact(length))
                .build()
                .await
            {
                Ok(body) => body,
                Err(_) => {
                    self.abort(key, upload_id).await;
                    return Err(ConnectorError::new(
                        ErrorClass::Permanent,
                        "S3 multipart source stream creation failed",
                    ));
                }
            };
            let uploaded = match self
                .client
                .upload_part()
                .bucket(&self.config.bucket)
                .key(key)
                .upload_id(upload_id)
                .part_number(part_number)
                .content_length(length as i64)
                .checksum_algorithm(ChecksumAlgorithm::Crc32)
                .body(body)
                .send()
                .await
            {
                Ok(output) => output,
                Err(error) => {
                    let mapped = Self::map_code(
                        error
                            .as_service_error()
                            .and_then(ProvideErrorMetadata::code),
                        "UPLOAD part",
                    );
                    self.abort(key, upload_id).await;
                    return Err(mapped);
                }
            };
            let Some(etag) = uploaded.e_tag() else {
                self.abort(key, upload_id).await;
                return Err(ConnectorError::new(
                    ErrorClass::Permanent,
                    "S3 upload part returned no ETag",
                ));
            };
            let Some(checksum) = uploaded.checksum_crc32() else {
                self.abort(key, upload_id).await;
                return Err(ConnectorError::new(
                    ErrorClass::Integrity,
                    "S3 upload part returned no CRC32 confirmation",
                ));
            };
            parts.push(
                CompletedPart::builder()
                    .part_number(part_number)
                    .e_tag(etag)
                    .checksum_crc32(checksum)
                    .build(),
            );
            offset += length;
            part_number += 1;
        }
        let completed = CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();
        let output = match self
            .client
            .complete_multipart_upload()
            .bucket(&self.config.bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(completed)
            .checksum_type(ChecksumType::Composite)
            .send()
            .await
        {
            Ok(output) => output,
            Err(error) => {
                let mapped = Self::map_code(
                    error
                        .as_service_error()
                        .and_then(ProvideErrorMetadata::code),
                    "COMPLETE multipart upload",
                );
                self.abort(key, upload_id).await;
                return Err(mapped);
            }
        };
        let head = self.head_raw(key).await?;
        let remote_size = head
            .content_length()
            .and_then(|value| u64::try_from(value).ok());
        let remote_sha256 = head
            .metadata()
            .and_then(|metadata| metadata.get("chancela-sha256"));
        if remote_size != Some(request.bytes)
            || remote_sha256.map(String::as_str) != Some(request.source_sha256.as_str())
            || head.checksum_crc32().is_none()
        {
            return Err(ConnectorError::new(
                ErrorClass::Integrity,
                "S3 committed object did not preserve size and checksum evidence",
            ));
        }
        Ok(UploadReceipt {
            target_id: self.config.id.clone(),
            connector: self.kind(),
            destination: request.destination.clone(),
            provider_object_id: Some(key.to_owned()),
            provider_revision: head.version_id().map(ToOwned::to_owned),
            etag: output
                .e_tag()
                .or_else(|| head.e_tag())
                .map(ToOwned::to_owned),
            source_sha256: request.source_sha256.clone(),
            bytes: request.bytes,
            checksum_evidence: ChecksumEvidence::RemoteConfirmed,
        })
    }
}

#[async_trait]
impl Connector for S3Connector {
    fn target_id(&self) -> &str {
        &self.config.id
    }

    fn kind(&self) -> ConnectorKind {
        ConnectorKind::S3
    }

    fn capabilities(&self) -> &'static [Capability] {
        CAPABILITIES
    }

    async fn probe(&self) -> Result<ConnectorStatus, ConnectorError> {
        self.client
            .head_bucket()
            .bucket(&self.config.bucket)
            .send()
            .await
            .map_err(|error| {
                Self::map_code(
                    error
                        .as_service_error()
                        .and_then(ProvideErrorMetadata::code),
                    "HEAD bucket",
                )
            })?;
        Ok(ConnectorStatus {
            target_id: self.config.id.clone(),
            kind: self.kind(),
            state: ProbeState::Ready,
            capabilities: CAPABILITIES.to_vec(),
            detail:
                "S3-compatible bucket is reachable; requests use bounded SDK retries and checksums"
                    .to_owned(),
        })
    }

    async fn upload(
        &self,
        request: &UploadRequest,
        cancellation: &CancellationToken,
    ) -> Result<UploadReceipt, ConnectorError> {
        if request.purpose != JobPurpose::Backup {
            return Err(ConnectorError::configuration(
                "S3 is a backup-only target and cannot service sync jobs",
            ));
        }
        verify_source(
            &request.source,
            &request.source_sha256,
            request.bytes,
            cancellation,
        )
        .await?;
        let key = self.key(&request.destination)?;
        match self.head_raw(&key).await {
            Ok(existing) => {
                let same_size = existing
                    .content_length()
                    .and_then(|value| u64::try_from(value).ok())
                    == Some(request.bytes);
                let same_sha256 = existing
                    .metadata()
                    .and_then(|metadata| metadata.get("chancela-sha256"))
                    .map(String::as_str)
                    == Some(request.source_sha256.as_str());
                if !same_size || !same_sha256 {
                    return Err(ConnectorError::new(
                        ErrorClass::Conflict,
                        "S3 destination already exists with different content",
                    ));
                }
                return Ok(UploadReceipt {
                    target_id: self.config.id.clone(),
                    connector: self.kind(),
                    destination: request.destination.clone(),
                    provider_object_id: Some(key),
                    provider_revision: existing.version_id().map(ToOwned::to_owned),
                    etag: existing.e_tag().map(ToOwned::to_owned),
                    source_sha256: request.source_sha256.clone(),
                    bytes: request.bytes,
                    checksum_evidence: ChecksumEvidence::RemoteConfirmed,
                });
            }
            Err(error) if error.class == ErrorClass::NotFound => {}
            Err(error) => return Err(error),
        }
        if request.bytes == 0 {
            let empty_sha256 = base64::engine::general_purpose::STANDARD.encode(Sha256::digest([]));
            let output = self
                .client
                .put_object()
                .bucket(&self.config.bucket)
                .key(&key)
                .content_type(&request.content_type)
                .metadata("chancela-sha256", &request.source_sha256)
                .metadata("chancela-idempotency", &request.idempotency_key)
                .metadata("chancela-purpose", "backup")
                .checksum_sha256(&empty_sha256)
                .body(ByteStream::from(Vec::<u8>::new()))
                .send()
                .await
                .map_err(|error| {
                    Self::map_code(
                        error
                            .as_service_error()
                            .and_then(ProvideErrorMetadata::code),
                        "PUT empty object",
                    )
                })?;
            let head = self.head_raw(&key).await?;
            let remote_size = head
                .content_length()
                .and_then(|value| u64::try_from(value).ok());
            let remote_sha256 = head
                .metadata()
                .and_then(|metadata| metadata.get("chancela-sha256"));
            if remote_size != Some(0)
                || remote_sha256.map(String::as_str) != Some(request.source_sha256.as_str())
                || head.checksum_sha256() != Some(empty_sha256.as_str())
            {
                return Err(ConnectorError::new(
                    ErrorClass::Integrity,
                    "S3 empty object did not preserve size and SHA-256 evidence",
                ));
            }
            return Ok(UploadReceipt {
                target_id: self.config.id.clone(),
                connector: self.kind(),
                destination: request.destination.clone(),
                provider_object_id: Some(key),
                provider_revision: head
                    .version_id()
                    .or_else(|| output.version_id())
                    .map(ToOwned::to_owned),
                etag: head
                    .e_tag()
                    .or_else(|| output.e_tag())
                    .map(ToOwned::to_owned),
                source_sha256: request.source_sha256.clone(),
                bytes: 0,
                checksum_evidence: ChecksumEvidence::RemoteConfirmed,
            });
        }
        self.multipart_upload(request, &key, cancellation).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_size_never_exceeds_the_s3_part_count() {
        let size = 5_u64 * 1024 * 1024 * 1024 * 1024;
        assert!(size.div_ceil(S3Connector::part_size(size)) <= MAX_PARTS);
        assert!(S3Connector::part_size(1) >= MIN_PART_SIZE);
    }
}
