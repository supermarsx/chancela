use std::sync::Arc;

use chancela_api::{AppState, router};
use chancela_authz::RoleCatalog;
use chancela_mcp::bridge::ReqwestTransport;
use chancela_mcp::{EnabledTools, McpConfig, McpServer, Secret};
use serde_json::{Value, json};
use tokio::sync::RwLock;

struct LiveApi {
    base_url: String,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for LiveApi {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_bearer_key_calls_live_api_v1_and_fails_closed() {
    let api = spawn_api().await;
    let client = reqwest::Client::new();
    let session = bootstrap_owner_session(&client, &api.base_url).await;

    let ledger_key = create_api_key(
        &client,
        &api.base_url,
        &session,
        "mcp-ledger",
        "ledger.read",
    )
    .await;
    let entity_key = create_api_key(
        &client,
        &api.base_url,
        &session,
        "mcp-entity",
        "entity.read",
    )
    .await;

    let ok = mcp_tool_call(
        &api.base_url,
        &ledger_key.secret,
        "verify_ledger",
        json!({}),
    )
    .await;
    assert_tool_success_json(&ok, |body| {
        assert_eq!(body["valid"], json!(true), "ledger verify succeeds: {body}");
    });

    let denied = mcp_tool_call(
        &api.base_url,
        &entity_key.secret,
        "verify_ledger",
        json!({}),
    )
    .await;
    assert_tool_error_contains(&denied, "403");
    assert_tool_error_does_not_leak(&denied, &entity_key.secret);

    revoke_api_key(&client, &api.base_url, &session, &ledger_key.id).await;
    let revoked = mcp_tool_call(
        &api.base_url,
        &ledger_key.secret,
        "verify_ledger",
        json!({}),
    )
    .await;
    assert_tool_error_contains(&revoked, "401");
    assert_tool_error_does_not_leak(&revoked, &ledger_key.secret);

    let invalid = mcp_tool_call(
        &api.base_url,
        &format!("{}x", ledger_key.secret),
        "verify_ledger",
        json!({}),
    )
    .await;
    assert_tool_error_contains(&invalid, "401");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_draft_minutes_returns_provenance_and_unsealed_api_draft() {
    let api = spawn_api().await;
    let client = reqwest::Client::new();
    let session = bootstrap_owner_session(&client, &api.base_url).await;
    let (_entity_id, book_id) = create_entity_and_book(&client, &api.base_url, &session).await;
    let draft_key =
        create_api_key(&client, &api.base_url, &session, "mcp-draft", "act.draft").await;

    let drafted = mcp_tool_call(
        &api.base_url,
        &draft_key.secret,
        "draft_minutes",
        json!({
            "book_id": book_id,
            "title": "Ata da Assembleia Geral Anual",
            "channel": "Physical",
            "actor": "mcp-ai"
        }),
    )
    .await;

    let act_id = assert_tool_success_json(&drafted, |body| {
        assert_eq!(body["kind"], json!("ai_draft"), "draft wrapper: {body}");
        assert_eq!(body["status"], json!("draft"), "draft wrapper: {body}");
        assert_eq!(
            body["non_authoritative"],
            json!(true),
            "draft wrapper: {body}"
        );
        assert_eq!(
            body["human_verification_required"],
            json!(true),
            "draft wrapper: {body}"
        );
        let verification_status_values = json!([
            "pending_human_verification",
            "accepted_by_human",
            "rejected_by_human"
        ]);
        assert_eq!(
            body["verification"]["checkpoint_status"],
            json!("pending_human_verification"),
            "draft wrapper: {body}"
        );
        assert_eq!(
            body["verification"]["checkpoint_allowed_statuses"], verification_status_values,
            "draft wrapper: {body}"
        );
        assert_eq!(
            body["verification"]["accepted_as_legal_text"],
            json!(false),
            "draft wrapper: {body}"
        );
        assert_eq!(
            body["verification"]["legal_validity_claimed"],
            json!(false),
            "draft wrapper: {body}"
        );
        assert_eq!(
            body["verification"]["checkpoint"]["accepted_by_human"],
            json!(false),
            "draft wrapper: {body}"
        );
        assert_eq!(
            body["verification"]["checkpoint"]["rejected_by_human"],
            json!(false),
            "draft wrapper: {body}"
        );
        assert_eq!(
            body["verification"]["checkpoint"]["acceptance_claim"],
            json!("human_review_only_not_legal_certification"),
            "draft wrapper: {body}"
        );
        assert_eq!(
            body["source_provenance"]["status"],
            json!("pending_human_verification"),
            "draft wrapper: {body}"
        );
        assert_eq!(
            body["source_provenance"]["status_values"], verification_status_values,
            "draft wrapper: {body}"
        );
        assert_eq!(
            body["source_provenance"]["human_verification_required"],
            json!(true),
            "draft wrapper: {body}"
        );
        assert_eq!(
            body["source_provenance"]["accepted_as_legal_text"],
            json!(false),
            "draft wrapper: {body}"
        );
        assert_eq!(
            body["source_provenance"]["legal_validity_claimed"],
            json!(false),
            "draft wrapper: {body}"
        );
        assert_eq!(
            body["source_provenance"]["human_verification"]["allowed_statuses"],
            verification_status_values,
            "draft wrapper: {body}"
        );
        assert_eq!(
            body["source_provenance"]["source"]["tool"],
            json!("draft_minutes"),
            "draft wrapper: {body}"
        );
        let statement_sources = body["source_provenance"]["statement_sources"]
            .as_array()
            .expect("statement source provenance entries");
        assert!(
            statement_sources
                .iter()
                .any(|source| source["path"] == json!("/draft/title")
                    && source["source_type"] == json!("caller_supplied")
                    && source["human_verified"] == json!(false)
                    && source["human_verification_status"] == json!("pending_human_verification")
                    && source["human_verification_status_values"] == verification_status_values
                    && source["legal_validity_claimed"] == json!(false)),
            "draft wrapper source provenance: {body}"
        );
        assert_eq!(
            body["provenance"]["source"]["tool"],
            json!("draft_minutes"),
            "draft wrapper: {body}"
        );
        assert_eq!(
            body["provenance"]["source"]["endpoint"],
            json!("POST /acts"),
            "draft wrapper: {body}"
        );
        assert_eq!(body["provenance"]["actor"], json!("mcp-ai"));
        assert_eq!(body["provenance"]["model"], Value::Null);
        assert_eq!(body["provenance"]["provider"], Value::Null);
        assert_eq!(
            body["draft"]["state"],
            json!("Draft"),
            "draft wrapper: {body}"
        );
        assert!(
            body["draft"]["ata_number"].is_null(),
            "draft wrapper: {body}"
        );
        assert!(
            body["draft"]["payload_digest"].is_null(),
            "draft wrapper: {body}"
        );
        assert!(
            body["draft"]["seal_event_seq"].is_null(),
            "draft wrapper: {body}"
        );
        body["draft"]["id"].as_str().expect("draft id").to_owned()
    });

    let (status, api_act) = get_json(
        &client,
        &api.base_url,
        &format!("/api/v1/acts/{act_id}"),
        Some(&session),
    )
    .await;
    assert_eq!(status, 200, "API act read: {api_act}");
    assert_eq!(api_act["state"], json!("Draft"), "API act remains draft");
    assert!(
        api_act["ata_number"].is_null(),
        "API act is not sealed: {api_act}"
    );
    assert!(
        api_act["payload_digest"].is_null(),
        "API act is not legal/sealed text: {api_act}"
    );

    let rejected = mcp_tool_call(
        &api.base_url,
        &draft_key.secret,
        "seal_act",
        json!({ "id": act_id }),
    )
    .await;
    assert_tool_error_contains(&rejected, "403");
    assert_tool_error_does_not_leak(&rejected, &draft_key.secret);
}

async fn spawn_api() -> LiveApi {
    let state = AppState {
        roles: Arc::new(RwLock::new(RoleCatalog::seeded_defaults())),
        ..AppState::default()
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind live API listener");
    let addr = listener.local_addr().expect("listener addr");
    let app = router(state);
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    LiveApi {
        base_url: format!("http://{addr}"),
        handle,
    }
}

async fn bootstrap_owner_session(client: &reqwest::Client, base_url: &str) -> String {
    let (status, user) = post_json(
        client,
        base_url,
        "/api/v1/users",
        None,
        json!({ "username": "owner", "display_name": "Owner" }),
    )
    .await;
    assert_eq!(status, 201, "owner bootstraps: {user}");
    let user_id = user["id"].as_str().expect("created user id");

    let (status, session) = post_json(
        client,
        base_url,
        "/api/v1/session",
        None,
        json!({ "user_id": user_id }),
    )
    .await;
    assert_eq!(status, 200, "session opens: {session}");
    session["token"].as_str().expect("session token").to_owned()
}

async fn create_entity_and_book(
    client: &reqwest::Client,
    base_url: &str,
    session: &str,
) -> (String, String) {
    let (status, entity) = post_json(
        client,
        base_url,
        "/api/v1/entities",
        Some(session),
        json!({
            "name": "Encosto Estratégico, S.A.",
            "nipc": "503004642",
            "seat": "Lisboa",
            "kind": "SociedadeAnonima"
        }),
    )
    .await;
    assert_eq!(status, 201, "entity created: {entity}");
    let entity_id = entity["id"].as_str().expect("entity id").to_owned();

    let (status, book) = post_json(
        client,
        base_url,
        "/api/v1/books",
        Some(session),
        json!({
            "entity_id": entity_id,
            "kind": "AssembleiaGeral",
            "purpose": "livro de atas da assembleia geral",
            "opening_date": "2026-01-15",
            "required_signatories": ["Administrador"]
        }),
    )
    .await;
    assert_eq!(status, 201, "book opened: {book}");
    let book_id = book["id"].as_str().expect("book id").to_owned();
    (entity_id, book_id)
}

struct CreatedKey {
    id: String,
    secret: String,
}

async fn create_api_key(
    client: &reqwest::Client,
    base_url: &str,
    session: &str,
    name: &str,
    permission: &str,
) -> CreatedKey {
    let (status, created) = post_json(
        client,
        base_url,
        "/api/v1/api-keys",
        Some(session),
        json!({
            "name": name,
            "grant": {
                "kind": "permissions",
                "permissions": [permission],
                "scope": { "kind": "global" }
            }
        }),
    )
    .await;
    assert_eq!(status, 201, "API key created: {created}");
    CreatedKey {
        id: created["id"].as_str().expect("key id").to_owned(),
        secret: created["secret"].as_str().expect("key secret").to_owned(),
    }
}

async fn revoke_api_key(client: &reqwest::Client, base_url: &str, session: &str, id: &str) {
    let resp = client
        .delete(format!("{base_url}/api/v1/api-keys/{id}"))
        .header("x-chancela-session", session)
        .send()
        .await
        .expect("revoke API key response");
    let status = resp.status().as_u16();
    let body = response_json(resp).await;
    assert_eq!(status, 200, "API key revoked: {body}");
    assert_eq!(body["revoked"], json!(true), "revoked key view: {body}");
}

async fn post_json(
    client: &reqwest::Client,
    base_url: &str,
    path: &str,
    session: Option<&str>,
    body: Value,
) -> (u16, Value) {
    let mut req = client.post(format!("{base_url}{path}")).json(&body);
    if let Some(session) = session {
        req = req.header("x-chancela-session", session);
    }
    let resp = req.send().await.expect("API response");
    let status = resp.status().as_u16();
    (status, response_json(resp).await)
}

async fn get_json(
    client: &reqwest::Client,
    base_url: &str,
    path: &str,
    session: Option<&str>,
) -> (u16, Value) {
    let mut req = client.get(format!("{base_url}{path}"));
    if let Some(session) = session {
        req = req.header("x-chancela-session", session);
    }
    let resp = req.send().await.expect("API response");
    let status = resp.status().as_u16();
    (status, response_json(resp).await)
}

async fn response_json(resp: reqwest::Response) -> Value {
    let text = resp.text().await.expect("response body");
    if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("response is JSON ({e}): {text}"))
    }
}

async fn mcp_tool_call(base_url: &str, api_key: &str, name: &str, arguments: Value) -> Value {
    let base_url = base_url.to_owned();
    let api_key = api_key.to_owned();
    let name = name.to_owned();
    tokio::task::spawn_blocking(move || {
        let config = McpConfig {
            enabled: true,
            tenant_ai_enabled: true,
            base_url,
            base_path: "/api/v1".to_owned(),
            api_key: Secret::new(api_key),
            enabled_tools: EnabledTools::List(vec![name.clone()]),
            ..McpConfig::default()
        };
        let transport = ReqwestTransport::new().expect("reqwest transport");
        let server = McpServer::from_config(&config, transport).expect("MCP server");
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        });
        let input = format!("{request}\n");
        let mut output = Vec::new();
        server
            .run(std::io::Cursor::new(input.into_bytes()), &mut output)
            .expect("MCP stdio call");
        let response: Value = serde_json::from_slice(&output).expect("MCP response JSON");
        assert!(
            response.get("error").is_none(),
            "tools/call returns a tool result, not JSON-RPC error: {response}"
        );
        response["result"].clone()
    })
    .await
    .expect("blocking MCP call")
}

fn assert_tool_success_json<R>(result: &Value, assert_body: impl FnOnce(Value) -> R) -> R {
    assert_eq!(
        result["isError"],
        json!(false),
        "expected successful MCP tool result: {result}"
    );
    let text = tool_text(result);
    let body: Value =
        serde_json::from_str(text).unwrap_or_else(|e| panic!("tool text is JSON ({e}): {text}"));
    assert_body(body)
}

fn assert_tool_error_contains(result: &Value, needle: &str) {
    assert_eq!(
        result["isError"],
        json!(true),
        "expected MCP tool error: {result}"
    );
    let text = tool_text(result);
    assert!(
        text.contains(needle),
        "expected tool error to contain {needle:?}: {text}"
    );
}

fn assert_tool_error_does_not_leak(result: &Value, secret: &str) {
    let text = tool_text(result);
    assert!(
        !text.contains(secret),
        "tool error leaked key secret: {text}"
    );
}

fn tool_text(result: &Value) -> &str {
    result["content"][0]["text"]
        .as_str()
        .expect("MCP text content")
}
