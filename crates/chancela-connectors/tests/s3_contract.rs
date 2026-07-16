use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Method, Request, Response, StatusCode};
use chancela_connectors::{
    CancellationToken, ChecksumEvidence, Connector, InMemorySecretProvider, JobPurpose,
    S3Connector, S3Target, UploadRequest,
};
use sha2::{Digest, Sha256};

#[derive(Clone)]
struct S3State {
    committed: Arc<AtomicBool>,
    payload: Arc<Vec<u8>>,
    sha256: Arc<String>,
    requests: Arc<Mutex<Vec<(Method, String, HeaderMap)>>>,
}

fn xml(status: StatusCode, body: impl Into<Body>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/xml")
        .body(body.into())
        .expect("S3 mock response")
}

async fn s3_provider(State(state): State<S3State>, request: Request<Body>) -> Response<Body> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or_default().to_owned();
    let headers = request.headers().clone();
    state.requests.lock().expect("S3 request log").push((
        method.clone(),
        format!("{path}?{query}"),
        headers,
    ));
    let _body = to_bytes(request.into_body(), 32 * 1024 * 1024)
        .await
        .expect("read S3 request");

    if method == Method::HEAD && path.trim_end_matches('/') == "/archive" {
        return Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .expect("HEAD bucket");
    }
    if method == Method::HEAD && path == "/archive/tenant/object.bin" {
        if !state.committed.load(Ordering::Acquire) {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("x-amz-error-code", "NoSuchKey")
                .header("x-amz-request-id", "request-initial-head")
                .body(Body::empty())
                .expect("missing object");
        }
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-length", state.payload.len())
            .header("etag", "\"multipart-etag-2\"")
            .header("x-amz-version-id", "version-1")
            .header("x-amz-checksum-crc32", "AAAAAA==")
            .header("x-amz-meta-chancela-sha256", state.sha256.as_str())
            .body(Body::empty())
            .expect("committed HEAD object");
    }
    if method == Method::POST && path == "/archive/tenant/object.bin" && query.contains("uploads") {
        return xml(
            StatusCode::OK,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>archive</Bucket><Key>tenant/object.bin</Key><UploadId>upload-1</UploadId>
</InitiateMultipartUploadResult>"#,
        );
    }
    if method == Method::PUT
        && path == "/archive/tenant/object.bin"
        && query.contains("partNumber=1")
    {
        return Response::builder()
            .status(StatusCode::OK)
            .header("etag", "\"part-etag\"")
            .header("x-amz-checksum-crc32", "AAAAAA==")
            .body(Body::empty())
            .expect("upload part");
    }
    if method == Method::POST
        && path == "/archive/tenant/object.bin"
        && query.contains("uploadId=upload-1")
    {
        state.committed.store(true, Ordering::Release);
        return xml(
            StatusCode::OK,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Location>http://example.test/archive/tenant/object.bin</Location>
  <Bucket>archive</Bucket><Key>tenant/object.bin</Key><ETag>"multipart-etag-2"</ETag>
  <ChecksumCRC32>AAAAAA==</ChecksumCRC32>
</CompleteMultipartUploadResult>"#,
        );
    }
    if method == Method::GET
        && path.trim_end_matches('/') == "/archive"
        && query.contains("list-type=2")
    {
        return xml(
            StatusCode::OK,
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>archive</Name><Prefix>tenant</Prefix><KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>
  <Contents><Key>tenant/object.bin</Key><LastModified>2026-07-16T00:00:00.000Z</LastModified><ETag>"multipart-etag-2"</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>
</ListBucketResult>"#,
                state.payload.len()
            ),
        );
    }
    if method == Method::GET && path == "/archive/tenant/object.bin" {
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .header("content-length", state.payload.len())
            .header("etag", "\"multipart-etag-2\"")
            .header("x-amz-meta-chancela-sha256", state.sha256.as_str())
            .body(Body::from(state.payload.as_ref().clone()))
            .expect("GET object");
    }
    xml(
        StatusCode::NOT_FOUND,
        r#"<Error><Code>NoSuchKey</Code><Message>not found</Message></Error>"#,
    )
}

async fn spawn_s3(
    payload: Vec<u8>,
    sha256: String,
) -> (String, S3State, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind S3 mock");
    let address = listener.local_addr().expect("S3 mock address");
    let state = S3State {
        committed: Arc::new(AtomicBool::new(false)),
        payload: Arc::new(payload),
        sha256: Arc::new(sha256),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let app = Router::new()
        .fallback(s3_provider)
        .with_state(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve S3 mock");
    });
    (format!("http://{address}"), state, server)
}

#[tokio::test]
async fn s3_backup_uses_signed_multipart_stat_list_and_verified_atomic_download() {
    let payload = b"S3-compatible multipart backup".to_vec();
    let sha256 = format!("{:x}", Sha256::digest(&payload));
    let (endpoint, state, server) = spawn_s3(payload.clone(), sha256.clone()).await;
    let secrets = Arc::new(InMemorySecretProvider::default());
    secrets.insert("CHANCELA_CONNECTOR_SECRET_S3_ACCESS_KEY", "test-access-key");
    secrets.insert("CHANCELA_CONNECTOR_SECRET_S3_SECRET_KEY", "test-secret-key");
    let connector = S3Connector::new(
        S3Target {
            id: "s3-backup".to_owned(),
            bucket: "archive".to_owned(),
            prefix: "tenant".to_owned(),
            region: "eu-west-1".to_owned(),
            endpoint_url: Some(endpoint),
            force_path_style: true,
            access_key_ref: "CHANCELA_CONNECTOR_SECRET_S3_ACCESS_KEY".to_owned(),
            secret_key_ref: "CHANCELA_CONNECTOR_SECRET_S3_SECRET_KEY".to_owned(),
            session_token_ref: None,
            timeout_seconds: 10,
            allow_insecure_http: true,
        },
        secrets,
    )
    .expect("S3 connector");
    connector.probe().await.expect("S3 probe");

    let root = std::env::temp_dir().join(format!("chancela-s3-test-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&root).await.expect("S3 fixture");
    let source = root.join("source.bin");
    tokio::fs::write(&source, &payload)
        .await
        .expect("S3 source");
    let request = UploadRequest {
        purpose: JobPurpose::Backup,
        source,
        destination: "object.bin".to_owned(),
        source_sha256: sha256.clone(),
        bytes: payload.len() as u64,
        idempotency_key: "s3-idempotency-key".to_owned(),
        content_type: "application/octet-stream".to_owned(),
    };
    let receipt = connector
        .upload(&request, &CancellationToken::default())
        .await
        .expect("multipart S3 upload");
    assert_eq!(receipt.checksum_evidence, ChecksumEvidence::RemoteConfirmed);
    assert_eq!(receipt.provider_revision.as_deref(), Some("version-1"));
    connector
        .upload(&request, &CancellationToken::default())
        .await
        .expect("idempotent S3 replay");
    assert_eq!(
        connector.stat("object.bin").await.expect("S3 stat").size,
        Some(payload.len() as u64)
    );
    let objects = connector.list("", 10).await.expect("S3 list");
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0].name, "object.bin");

    let downloaded = root.join("downloaded.bin");
    let download = connector
        .download("object.bin", &downloaded, &CancellationToken::default())
        .await
        .expect("S3 download");
    assert_eq!(download.downloaded_sha256, sha256);
    assert_eq!(
        tokio::fs::read(downloaded).await.expect("download"),
        payload
    );

    {
        let requests = state.requests.lock().expect("S3 request log");
        assert!(requests.iter().all(|(_, _, headers)| {
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("AWS4-HMAC-SHA256 "))
        }));
        assert!(requests.iter().any(|(method, uri, _)| {
            method == Method::POST && uri.contains("uploadId=upload-1")
        }));
    }

    server.abort();
    tokio::fs::remove_dir_all(root)
        .await
        .expect("remove S3 fixture");
}
