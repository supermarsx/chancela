use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use suppaftp::tokio::{AsyncRustlsConnector, AsyncRustlsFtpStream};
use suppaftp::tokio_rustls::TlsConnector;
use suppaftp::tokio_rustls::rustls::{ClientConfig, RootCertStore};
use suppaftp::types::FileType;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::http::{temporary_destination, validate_relative_path, verify_source};
use crate::{
    CancellationToken, Capability, ChecksumEvidence, Connector, ConnectorError, ConnectorKind,
    ConnectorStatus, ErrorClass, FtpsTarget, ProbeState, SecretProvider, UploadReceipt,
    UploadRequest,
};

const CAPABILITIES: &[Capability] = &[
    Capability::Upload,
    Capability::CreateFolder,
    Capability::SourceChecksum,
];

pub struct FtpsConnector {
    config: FtpsTarget,
    secrets: Arc<dyn SecretProvider>,
}

impl std::fmt::Debug for FtpsConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FtpsConnector")
            .field("target_id", &self.config.id)
            .finish_non_exhaustive()
    }
}

impl FtpsConnector {
    pub fn new(
        config: FtpsTarget,
        secrets: Arc<dyn SecretProvider>,
    ) -> Result<Self, ConnectorError> {
        config.validate()?;
        if config.host.trim().is_empty() {
            return Err(ConnectorError::configuration("FTPS host is empty"));
        }
        Ok(Self { config, secrets })
    }

    fn tls_connector(&self) -> Result<AsyncRustlsConnector, ConnectorError> {
        let native = rustls_native_certs::load_native_certs();
        let mut roots = RootCertStore::empty();
        for certificate in native.certs {
            roots.add(certificate).map_err(|_| {
                ConnectorError::configuration("invalid native TLS root certificate")
            })?;
        }
        if roots.is_empty() {
            return Err(ConnectorError::configuration(
                "no native TLS root certificates are available for FTPS",
            ));
        }
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(AsyncRustlsConnector::from(TlsConnector::from(Arc::new(
            config,
        ))))
    }

    async fn connect(&self) -> Result<AsyncRustlsFtpStream, ConnectorError> {
        let password = self.secrets.resolve(&self.config.password_ref)?;
        let timeout = Duration::from_secs(self.config.timeout_seconds);
        let address = (self.config.host.as_str(), self.config.port);
        let plain = tokio::time::timeout(timeout, AsyncRustlsFtpStream::connect(address))
            .await
            .map_err(|_| ConnectorError::transient("FTPS connection timed out"))?
            .map_err(|_| ConnectorError::transient("FTPS connection failed"))?;
        let mut ftp = tokio::time::timeout(
            timeout,
            plain.into_secure(self.tls_connector()?, &self.config.host),
        )
        .await
        .map_err(|_| ConnectorError::transient("FTPS TLS negotiation timed out"))?
        .map_err(|_| {
            ConnectorError::new(ErrorClass::Authentication, "FTPS TLS verification failed")
        })?;
        ftp.login(self.config.username.as_str(), password.expose())
            .await
            .map_err(|_| {
                ConnectorError::new(ErrorClass::Authentication, "FTPS authentication failed")
            })?;
        ftp.transfer_type(FileType::Binary)
            .await
            .map_err(|_| ConnectorError::transient("FTPS binary-mode negotiation failed"))?;
        if !self.config.root.trim().is_empty() {
            ftp.cwd(&self.config.root).await.map_err(|_| {
                ConnectorError::new(ErrorClass::NotFound, "FTPS root is unavailable")
            })?;
        }
        Ok(ftp)
    }

    async fn enter_parent(
        &self,
        ftp: &mut AsyncRustlsFtpStream,
        destination: &str,
    ) -> Result<String, ConnectorError> {
        validate_relative_path(destination)?;
        let mut components = destination.split('/').collect::<Vec<_>>();
        let filename = components
            .pop()
            .ok_or_else(|| ConnectorError::configuration("FTPS destination has no file name"))?
            .to_owned();
        for directory in components {
            if ftp.cwd(directory).await.is_err() {
                ftp.mkdir(directory).await.map_err(|_| {
                    ConnectorError::new(ErrorClass::Permanent, "FTPS directory creation failed")
                })?;
                ftp.cwd(directory).await.map_err(|_| {
                    ConnectorError::new(ErrorClass::Permanent, "FTPS directory traversal failed")
                })?;
            }
        }
        Ok(filename)
    }
}

#[async_trait]
impl Connector for FtpsConnector {
    fn target_id(&self) -> &str {
        &self.config.id
    }

    fn kind(&self) -> ConnectorKind {
        ConnectorKind::Ftps
    }

    fn capabilities(&self) -> &'static [Capability] {
        CAPABILITIES
    }

    async fn probe(&self) -> Result<ConnectorStatus, ConnectorError> {
        let mut ftp = self.connect().await?;
        ftp.pwd()
            .await
            .map_err(|_| ConnectorError::transient("FTPS working-directory probe failed"))?;
        let _ = ftp.quit().await;
        Ok(ConnectorStatus {
            target_id: self.config.id.clone(),
            kind: self.kind(),
            state: ProbeState::Ready,
            capabilities: CAPABILITIES.to_vec(),
            detail:
                "explicit FTPS with private data-channel protection and WebPKI validation is ready"
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
        let mut ftp = self.connect().await?;
        let filename = self.enter_parent(&mut ftp, &request.destination).await?;
        if ftp.size(&filename).await.is_ok() {
            return Err(ConnectorError::new(
                ErrorClass::Conflict,
                "FTPS destination already exists",
            ));
        }
        let temporary = temporary_destination(&filename, &request.idempotency_key);
        let mut source = tokio::fs::File::open(&request.source)
            .await
            .map_err(|error| ConnectorError::io("open FTPS source", &error))?;
        let mut data = ftp
            .put_with_stream(&temporary)
            .await
            .map_err(|_| ConnectorError::transient("FTPS temporary upload open failed"))?;
        let mut buffer = vec![0_u8; 1024 * 1024];
        let mut transfer_error = None;
        loop {
            if let Err(error) = cancellation.check() {
                transfer_error = Some(error);
                break;
            }
            let read = source
                .read(&mut buffer)
                .await
                .map_err(|error| ConnectorError::io("read FTPS source", &error))?;
            if read == 0 {
                break;
            }
            if data.write_all(&buffer[..read]).await.is_err() {
                transfer_error = Some(ConnectorError::transient("FTPS upload write failed"));
                break;
            }
        }
        let _ = data.shutdown().await;
        if ftp.finalize_put_stream(data).await.is_err() && transfer_error.is_none() {
            transfer_error = Some(ConnectorError::transient("FTPS upload finalization failed"));
        }
        if let Some(error) = transfer_error {
            let _ = ftp.rm(&temporary).await;
            return Err(error);
        }
        ftp.rename(&temporary, &filename)
            .await
            .map_err(|_| ConnectorError::new(ErrorClass::Conflict, "FTPS atomic rename failed"))?;
        let remote_size = ftp
            .size(&filename)
            .await
            .map_err(|_| ConnectorError::transient("FTPS committed object stat failed"))?;
        if remote_size as u64 != request.bytes {
            return Err(ConnectorError::new(
                ErrorClass::Integrity,
                "FTPS committed object size does not match the source",
            ));
        }
        let _ = ftp.quit().await;
        Ok(UploadReceipt {
            target_id: self.config.id.clone(),
            connector: self.kind(),
            destination: request.destination.clone(),
            provider_object_id: None,
            provider_revision: None,
            etag: None,
            source_sha256: request.source_sha256.clone(),
            bytes: request.bytes,
            checksum_evidence: ChecksumEvidence::SourceOnly,
        })
    }
}
