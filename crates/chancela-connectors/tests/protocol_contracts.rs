use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Method, Request, Response, StatusCode};
use chancela_connectors::{
    CancellationToken, ChecksumEvidence, Connector, ErrorClass, GoogleDriveConnector,
    GoogleDriveTarget, GraphConnector, GraphTarget, InMemorySecretProvider, JobPurpose,
    UploadRequest, WebDavAuth, WebDavConnector, WebDavTarget,
};
use sha2::{Digest, Sha256};

static NETWORK_POLICY: Once = Once::new();

fn configure_network_policy() {
    NETWORK_POLICY.call_once(|| {
        // SAFETY: this test binary sets this single policy once, before any connector reads it.
        unsafe { std::env::set_var("CHANCELA_CONNECTOR_ALLOWED_HOSTS", "127.0.0.1/32") };
    });
}

#[derive(Clone, Debug)]
struct ObservedRequest {
    method: Method,
    path: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

#[derive(Clone, Default)]
struct ProviderState {
    requests: Arc<Mutex<Vec<ObservedRequest>>>,
}

fn response(status: StatusCode, body: impl Into<Body>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(body.into())
        .expect("mock response")
}

async fn provider(State(state): State<ProviderState>, request: Request<Body>) -> Response<Body> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or_default().to_owned();
    let headers = request.headers().clone();
    let host = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("127.0.0.1");
    let body = to_bytes(request.into_body(), 32 * 1024 * 1024)
        .await
        .expect("read mock request")
        .to_vec();
    state
        .requests
        .lock()
        .expect("request log")
        .push(ObservedRequest {
            method: method.clone(),
            path: path.clone(),
            headers: headers.clone(),
            body: body.clone(),
        });

    match (method, path.as_str()) {
        (method, "/dav") if method.as_str() == "PROPFIND" => {
            response(StatusCode::MULTI_STATUS, r#"{"multistatus":true}"#)
        }
        (Method::PUT, path) if path.starts_with("/dav/") => Response::builder()
            .status(StatusCode::CREATED)
            .header("etag", "\"webdav-etag\"")
            .body(Body::empty())
            .expect("WebDAV PUT response"),
        (method, path) if method.as_str() == "MKCOL" && path.starts_with("/dav/") => {
            Response::builder()
                .status(StatusCode::CREATED)
                .body(Body::empty())
                .expect("WebDAV MKCOL response")
        }
        (method, path) if method.as_str() == "MOVE" && path.starts_with("/dav/") => {
            Response::builder()
                .status(StatusCode::CREATED)
                .header("etag", "\"webdav-moved\"")
                .body(Body::empty())
                .expect("WebDAV MOVE response")
        }
        (Method::GET, "/graph/drives/drive") => response(StatusCode::OK, r#"{"id":"drive"}"#),
        (Method::POST, path) if path.ends_with("/createUploadSession") => response(
            StatusCode::OK,
            format!(r#"{{"uploadUrl":"http://{host}/graph-upload"}}"#),
        ),
        (Method::PUT, "/graph-upload") => {
            let sha256 = format!("{:x}", Sha256::digest(&body));
            response(
                StatusCode::CREATED,
                format!(
                    r#"{{"id":"graph-object","eTag":"graph-etag","cTag":"graph-revision","size":{},"file":{{"hashes":{{"sha256Hash":"{sha256}"}}}}}}"#,
                    body.len()
                ),
            )
        }
        (Method::PUT, path) if path.starts_with("/graph/") && path.ends_with("/content") => {
            let sha256 = format!("{:x}", Sha256::digest(&body));
            response(
                StatusCode::CREATED,
                format!(
                    r#"{{"id":"graph-empty","size":{},"file":{{"hashes":{{"sha256Hash":"{sha256}"}}}}}}"#,
                    body.len()
                ),
            )
        }
        (Method::GET, "/drive/v3/about") => response(StatusCode::OK, r#"{"user":{}}"#),
        (Method::GET, "/drive/v3/files") => response(
            StatusCode::OK,
            r#"{"files":[{"id":"file-1","name":"minute.pdf","size":"17","headRevisionId":"revision-1"}]}"#,
        ),
        (Method::POST, "/drive/v3/files") => {
            response(StatusCode::OK, r#"{"id":"folder-1","name":"archive"}"#)
        }
        (Method::GET, "/drive/v3/files/file-1/revisions") => response(
            StatusCode::OK,
            r#"{"revisions":[{"id":"revision-1","keepForever":true}]}"#,
        ),
        (Method::POST, "/upload/drive/v3/files") => Response::builder()
            .status(StatusCode::OK)
            .header("location", format!("http://{host}/drive-upload"))
            .body(Body::empty())
            .expect("Drive session response"),
        (Method::PUT, "/drive-upload") => response(
            StatusCode::OK,
            format!(
                r#"{{"id":"drive-object","name":"object.bin","size":"{}","headRevisionId":"drive-revision"}}"#,
                body.len()
            ),
        ),
        _ => response(
            StatusCode::NOT_FOUND,
            format!(r#"{{"path":"{path}","query":"{query}"}}"#),
        ),
    }
}

async fn spawn_provider() -> (String, ProviderState, tokio::task::JoinHandle<()>) {
    configure_network_policy();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock provider");
    let address = listener.local_addr().expect("mock provider address");
    let state = ProviderState::default();
    let app = Router::new().fallback(provider).with_state(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("serve mock provider");
    });
    (format!("http://{address}"), state, server)
}

fn secrets() -> Arc<InMemorySecretProvider> {
    let secrets = Arc::new(InMemorySecretProvider::default());
    secrets.insert("CHANCELA_CONNECTOR_SECRET_TEST_TOKEN", "provider-token");
    secrets.insert("CHANCELA_CONNECTOR_SECRET_DAV_PASSWORD", "webdav-password");
    secrets
}

async fn source(label: &str, bytes: &[u8]) -> (PathBuf, PathBuf, String) {
    let root = std::env::temp_dir().join(format!(
        "chancela-connectors-{label}-{}",
        uuid::Uuid::new_v4()
    ));
    tokio::fs::create_dir_all(&root)
        .await
        .expect("create source fixture");
    let path = root.join("source.bin");
    tokio::fs::write(&path, bytes)
        .await
        .expect("write source fixture");
    (root, path, format!("{:x}", Sha256::digest(bytes)))
}

fn upload_request(path: &Path, bytes: &[u8], sha256: &str, destination: &str) -> UploadRequest {
    UploadRequest {
        purpose: JobPurpose::Backup,
        source: path.to_owned(),
        destination: destination.to_owned(),
        source_sha256: sha256.to_owned(),
        bytes: bytes.len() as u64,
        idempotency_key: format!("key-{}", uuid::Uuid::new_v4()),
        content_type: "application/octet-stream".to_owned(),
    }
}

fn header<'a>(request: &'a ObservedRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
}

#[tokio::test]
async fn webdav_probe_and_atomic_upload_send_checksum_and_authenticated_move() {
    let (base, state, server) = spawn_provider().await;
    let payload = b"WebDAV protocol payload";
    let (root, path, sha256) = source("webdav", payload).await;
    let connector = WebDavConnector::new(
        WebDavTarget {
            id: "dav".to_owned(),
            base_url: format!("{base}/dav"),
            auth: WebDavAuth::Basic {
                username: "operator".to_owned(),
                password_ref: "CHANCELA_CONNECTOR_SECRET_DAV_PASSWORD".to_owned(),
            },
            timeout_seconds: 10,
            allow_insecure_http: true,
        },
        secrets(),
    )
    .expect("WebDAV connector");
    connector.probe().await.expect("WebDAV probe");
    let receipt = connector
        .upload(
            &upload_request(&path, payload, &sha256, "records/minute.bin"),
            &CancellationToken::default(),
        )
        .await
        .expect("WebDAV upload");
    assert_eq!(receipt.etag.as_deref(), Some("\"webdav-moved\""));
    assert_eq!(receipt.checksum_evidence, ChecksumEvidence::SentToProvider);

    let requests = state.requests.lock().expect("request log").clone();
    let propfind = requests
        .iter()
        .find(|request| request.method.as_str() == "PROPFIND")
        .expect("PROPFIND request");
    assert_eq!(header(propfind, "depth"), Some("0"));
    let put = requests
        .iter()
        .find(|request| request.method == Method::PUT)
        .expect("PUT request");
    assert_eq!(put.body, payload);
    assert_eq!(
        header(put, "oc-checksum"),
        Some(format!("SHA256:{sha256}").as_str())
    );
    assert_eq!(header(put, "oc-total-length"), Some("23"));
    assert!(header(put, "authorization").is_some_and(|value| value.starts_with("Basic ")));
    assert!(
        requests.iter().any(|request| {
            request.method.as_str() == "MKCOL" && request.path == "/dav/records"
        })
    );
    let moved = requests
        .iter()
        .find(|request| request.method.as_str() == "MOVE")
        .expect("MOVE request");
    assert_eq!(header(moved, "overwrite"), Some("T"));
    assert!(
        header(moved, "destination").is_some_and(|value| value.ends_with("/records/minute.bin"))
    );

    server.abort();
    tokio::fs::remove_dir_all(root)
        .await
        .expect("remove fixture");
}

#[tokio::test]
async fn graph_resumable_and_empty_uploads_verify_remote_size_and_sha256() {
    let (base, state, server) = spawn_provider().await;
    let connector = GraphConnector::new(
        GraphTarget {
            id: "graph".to_owned(),
            drive_id: "drive".to_owned(),
            parent_item_id: "parent".to_owned(),
            token_ref: "CHANCELA_CONNECTOR_SECRET_TEST_TOKEN".to_owned(),
            api_base_url: format!("{base}/graph"),
            timeout_seconds: 10,
            allow_insecure_http: true,
        },
        secrets(),
    )
    .expect("Graph connector");
    connector.probe().await.expect("Graph probe");

    let payload = b"Graph resumable payload";
    let (root, path, sha256) = source("graph", payload).await;
    let receipt = connector
        .upload(
            &upload_request(&path, payload, &sha256, "minutes/object.bin"),
            &CancellationToken::default(),
        )
        .await
        .expect("Graph resumable upload");
    assert_eq!(receipt.provider_object_id.as_deref(), Some("graph-object"));
    assert_eq!(receipt.checksum_evidence, ChecksumEvidence::RemoteConfirmed);

    let empty: &[u8] = b"";
    let empty_path = root.join("empty.bin");
    tokio::fs::write(&empty_path, empty)
        .await
        .expect("empty source");
    let empty_sha256 = format!("{:x}", Sha256::digest(empty));
    let empty_receipt = connector
        .upload(
            &upload_request(&empty_path, empty, &empty_sha256, "minutes/empty.bin"),
            &CancellationToken::default(),
        )
        .await
        .expect("Graph empty upload");
    assert_eq!(
        empty_receipt.provider_object_id.as_deref(),
        Some("graph-empty")
    );
    assert_eq!(
        empty_receipt.checksum_evidence,
        ChecksumEvidence::RemoteConfirmed
    );

    let requests = state.requests.lock().expect("request log").clone();
    let chunk = requests
        .iter()
        .find(|request| request.path == "/graph-upload")
        .expect("Graph chunk request");
    assert_eq!(header(chunk, "content-range"), Some("bytes 0-22/23"));
    assert_eq!(chunk.body, payload);
    assert!(header(chunk, "authorization").is_none());
    assert!(requests.iter().any(|request| {
        request.path.ends_with("/empty.bin:/content")
            && request.method == Method::PUT
            && request.body.is_empty()
    }));

    server.abort();
    tokio::fs::remove_dir_all(root)
        .await
        .expect("remove fixture");
}

#[tokio::test]
async fn drive_supports_probe_search_folder_revisions_and_resumable_uploads() {
    let (base, state, server) = spawn_provider().await;
    let connector = GoogleDriveConnector::new(
        GoogleDriveTarget {
            id: "drive".to_owned(),
            parent_folder_id: "parent-folder".to_owned(),
            token_ref: "CHANCELA_CONNECTOR_SECRET_TEST_TOKEN".to_owned(),
            api_base_url: base.clone(),
            timeout_seconds: 10,
            allow_insecure_http: true,
        },
        secrets(),
    )
    .expect("Drive connector");
    connector.probe().await.expect("Drive probe");
    let found = connector
        .search("name = 'minute.pdf'")
        .await
        .expect("Drive search");
    assert_eq!(found[0].revision.as_deref(), Some("revision-1"));
    let folder = connector
        .create_folder("archive", None)
        .await
        .expect("Drive create folder");
    assert_eq!(folder.id, "folder-1");
    let revisions = connector
        .revisions("file-1")
        .await
        .expect("Drive revisions");
    assert!(revisions[0].keep_forever);

    let payload = b"Drive resumable payload";
    let (root, path, sha256) = source("drive", payload).await;
    let receipt = connector
        .upload(
            &upload_request(&path, payload, &sha256, "nested/object.bin"),
            &CancellationToken::default(),
        )
        .await
        .expect("Drive upload");
    assert_eq!(receipt.provider_object_id.as_deref(), Some("drive-object"));
    assert_eq!(receipt.provider_revision.as_deref(), Some("drive-revision"));

    let empty_path = root.join("empty.bin");
    tokio::fs::write(&empty_path, b"")
        .await
        .expect("empty source");
    let empty_sha256 = format!("{:x}", Sha256::digest([]));
    connector
        .upload(
            &upload_request(&empty_path, b"", &empty_sha256, "empty.bin"),
            &CancellationToken::default(),
        )
        .await
        .expect("Drive empty upload");

    let requests = state.requests.lock().expect("request log").clone();
    let chunks: Vec<_> = requests
        .iter()
        .filter(|request| request.path == "/drive-upload")
        .collect();
    assert_eq!(chunks.len(), 2);
    assert_eq!(header(chunks[0], "content-range"), Some("bytes 0-22/23"));
    assert_eq!(chunks[0].body, payload);
    assert!(chunks[1].body.is_empty());
    assert!(header(chunks[1], "content-range").is_none());
    assert!(
        requests
            .iter()
            .filter(|request| {
                request.path.starts_with("/drive/") || request.path.starts_with("/upload/drive/")
            })
            .all(|request| header(request, "authorization") == Some("Bearer provider-token"))
    );

    server.abort();
    tokio::fs::remove_dir_all(root)
        .await
        .expect("remove fixture");
}

#[test]
fn network_connectors_reject_cleartext_by_default_and_configs_contain_only_secret_refs() {
    let target = WebDavTarget {
        id: "dav".to_owned(),
        base_url: "http://example.test/dav".to_owned(),
        auth: WebDavAuth::Bearer {
            token_ref: "CHANCELA_CONNECTOR_SECRET_TEST_TOKEN".to_owned(),
        },
        timeout_seconds: 10,
        allow_insecure_http: false,
    };
    let error = WebDavConnector::new(target.clone(), secrets()).expect_err("reject cleartext");
    assert_eq!(error.class, ErrorClass::Configuration);

    let encoded = serde_json::to_string(&target).expect("serialize target");
    assert!(encoded.contains("TEST_TOKEN"));
    assert!(!encoded.contains("provider-token"));
    let parsed: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&encoded).expect("parse serialized config");
    assert_eq!(parsed["allow_insecure_http"], false);
}
