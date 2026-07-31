//! Shared bounded collection-page contract for the large directory endpoints.
//!
//! Legacy collection routes keep returning their historical bare arrays. New `/page` routes use
//! this contract so clients can opt into a bounded response without breaking older callers.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization as _;
use unicode_normalization::char::is_combining_mark;

use crate::error::ApiError;

pub(crate) const DEFAULT_PAGE_LIMIT: usize = 50;
pub(crate) const MAX_PAGE_LIMIT: usize = 200;
const CURSOR_VERSION: u8 = 1;
const MAX_CURSOR_BYTES: usize = 2_048;

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct CollectionPageQuery {
    /// Case-insensitive free-text filter interpreted by the owning collection.
    pub q: Option<String>,
    /// Zero-based offset within the caller-visible, filtered collection.
    #[serde(default)]
    pub offset: usize,
    /// Opaque keyset cursor returned by a previous response. Mutually exclusive with a non-zero
    /// offset; the legacy offset path remains available for older clients.
    pub cursor: Option<String>,
    /// Requested page size. Values above the server ceiling are capped.
    pub limit: Option<usize>,
    /// Collection-specific sort key.
    pub sort: Option<String>,
    /// `asc` (default) or `desc`.
    pub order: Option<String>,
}

impl CollectionPageQuery {
    pub(crate) fn limit(&self) -> usize {
        self.limit
            .unwrap_or(DEFAULT_PAGE_LIMIT)
            .clamp(1, MAX_PAGE_LIMIT)
    }

    pub(crate) fn descending(&self) -> Result<bool, ApiError> {
        match self.order.as_deref().unwrap_or("asc") {
            "asc" => Ok(false),
            "desc" => Ok(true),
            other => Err(ApiError::Unprocessable(format!(
                "unknown order {other:?}: expected \"asc\" or \"desc\""
            ))),
        }
    }

    pub(crate) fn normalized_search(&self) -> Option<String> {
        self.q
            .as_deref()
            .map(str::trim)
            .filter(|q| !q.is_empty())
            .map(fold_search)
    }

    pub(crate) fn cursor(
        &self,
        collection: &str,
        fingerprint: &str,
    ) -> Result<Option<CursorPosition>, ApiError> {
        if self.cursor.is_some() && self.offset != 0 {
            return Err(ApiError::Unprocessable(
                "cursor and a non-zero offset are mutually exclusive".to_owned(),
            ));
        }
        self.cursor
            .as_deref()
            .map(|cursor| decode_cursor(cursor, collection, fingerprint))
            .transpose()
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct CollectionPage<T> {
    pub items: Vec<T>,
    pub offset: usize,
    pub limit: usize,
    pub has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl<T> CollectionPage<T> {
    #[cfg(test)]
    pub(crate) fn from_sorted(items: Vec<T>, offset: usize, limit: usize) -> Self {
        let mut page_items: Vec<T> = items.into_iter().skip(offset).take(limit + 1).collect();
        let has_more = page_items.len() > limit;
        if has_more {
            page_items.pop();
        }
        let next_offset = has_more.then_some(offset.saturating_add(page_items.len()));
        Self {
            items: page_items,
            offset,
            limit,
            has_more,
            next_offset,
            next_cursor: None,
        }
    }

    /// Build a page after the owning collection has sorted, filtered and (when present) applied the
    /// decoded keyset marker. Offset callers retain the historical `next_offset`; cursor callers
    /// receive only an opaque `next_cursor`, because reporting a synthetic absolute offset would
    /// be unstable under concurrent inserts/deletes.
    pub(crate) fn from_keyset_sorted(
        mut items: Vec<T>,
        offset: usize,
        limit: usize,
        cursor_mode: bool,
        collection: &str,
        fingerprint: &str,
        position: impl Fn(&T) -> CursorPosition,
    ) -> Self {
        if !cursor_mode && offset != 0 {
            items = items.into_iter().skip(offset).collect();
        }
        items.truncate(limit + 1);
        let has_more = items.len() > limit;
        if has_more {
            items.pop();
        }
        let next_cursor = has_more
            .then(|| items.last().map(&position))
            .flatten()
            .map(|position| encode_cursor(collection, fingerprint, &position));
        let next_offset = (!cursor_mode && has_more).then_some(offset.saturating_add(items.len()));
        Self {
            items,
            offset,
            limit,
            has_more,
            next_offset,
            next_cursor,
        }
    }

    pub(crate) fn map<U>(self, mut f: impl FnMut(T) -> U) -> CollectionPage<U> {
        CollectionPage {
            items: self.items.into_iter().map(&mut f).collect(),
            offset: self.offset,
            limit: self.limit,
            has_more: self.has_more,
            next_offset: self.next_offset,
            next_cursor: self.next_cursor,
        }
    }
}

/// Match the web roster's accent-insensitive search semantics: canonical decomposition, removal of
/// combining marks, then Unicode lowercase. Keeping it shared prevents entity/book/user paging
/// from disagreeing on Portuguese names such as "João" and an unaccented `joao` query.
pub(crate) fn fold_search(value: &str) -> String {
    value
        .nfd()
        .filter(|character| !is_combining_mark(*character))
        .flat_map(char::to_lowercase)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct CursorPosition {
    pub key: String,
    pub id: String,
}

impl CursorPosition {
    pub(crate) fn new(key: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            id: id.into(),
        }
    }
}

/// Drop rows at-or-before the cursor in the requested ordering. Comparing the complete
/// `(sort-key, id)` tuple is what prevents duplicates when the primary sort key is not unique.
pub(crate) fn apply_keyset<T>(
    items: &mut Vec<T>,
    cursor: Option<&CursorPosition>,
    descending: bool,
    position: impl Fn(&T) -> CursorPosition,
) {
    let Some(cursor) = cursor else {
        return;
    };
    items.retain(|item| {
        let item = position(item);
        if descending {
            item < *cursor
        } else {
            item > *cursor
        }
    });
}

/// Fingerprint every effective query dimension that defines one ordered result set. A cursor is
/// rejected if any search/filter/sort input changes, rather than silently resuming in a different
/// collection. Values are length-prefixed to avoid delimiter ambiguity.
pub(crate) fn query_fingerprint<'a>(fields: impl IntoIterator<Item = (&'a str, String)>) -> String {
    let mut fields: Vec<_> = fields.into_iter().collect();
    fields.sort_by(|left, right| left.0.cmp(right.0));
    let mut digest = Sha256::new();
    for (name, value) in fields {
        digest.update(name.len().to_be_bytes());
        digest.update(name.as_bytes());
        digest.update(value.len().to_be_bytes());
        digest.update(value.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorEnvelope {
    version: u8,
    collection: String,
    fingerprint: String,
    position: CursorPosition,
    /// Unkeyed corruption detector only. This is deliberately not an authorization or
    /// cryptographic tamper-resistance boundary: every resumed row is re-authorized and
    /// re-filtered, and a caller-chosen position can reveal no hidden total or row.
    integrity: String,
}

fn cursor_integrity(
    version: u8,
    collection: &str,
    fingerprint: &str,
    position: &CursorPosition,
) -> String {
    query_fingerprint([
        ("version", version.to_string()),
        ("collection", collection.to_owned()),
        ("fingerprint", fingerprint.to_owned()),
        ("key", position.key.clone()),
        ("id", position.id.clone()),
    ])
}

fn encode_cursor(collection: &str, fingerprint: &str, position: &CursorPosition) -> String {
    let envelope = CursorEnvelope {
        version: CURSOR_VERSION,
        collection: collection.to_owned(),
        fingerprint: fingerprint.to_owned(),
        position: position.clone(),
        integrity: cursor_integrity(CURSOR_VERSION, collection, fingerprint, position),
    };
    // Every field above is a string/number and therefore infallibly serializable.
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&envelope).expect("serialize collection cursor"))
}

fn decode_cursor(
    encoded: &str,
    expected_collection: &str,
    expected_fingerprint: &str,
) -> Result<CursorPosition, ApiError> {
    if encoded.is_empty() || encoded.len() > MAX_CURSOR_BYTES {
        return Err(invalid_cursor());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| invalid_cursor())?;
    let envelope: CursorEnvelope = serde_json::from_slice(&bytes).map_err(|_| invalid_cursor())?;
    if envelope.version != CURSOR_VERSION
        || envelope.collection != expected_collection
        || envelope.fingerprint != expected_fingerprint
        || envelope.integrity
            != cursor_integrity(
                envelope.version,
                &envelope.collection,
                &envelope.fingerprint,
                &envelope.position,
            )
    {
        return Err(invalid_cursor());
    }
    Ok(envelope.position)
}

fn invalid_cursor() -> ApiError {
    ApiError::Unprocessable(
        "invalid or mismatched collection cursor; restart pagination from the first page"
            .to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog, Scope};
    use chancela_core::{Book, BookKind, BookState, EntityId};
    use serde_json::Value;
    use std::collections::BTreeSet;
    use std::ops::Bound::{Excluded, Unbounded};
    use std::time::Instant;
    use time::OffsetDateTime;
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::AppState;
    use crate::session::SessionEntry;
    use crate::users::{SecretSource, User, UserId};

    #[test]
    fn page_is_bounded_and_exposes_only_the_next_offset() {
        let page = CollectionPage::from_sorted((0..10).collect::<Vec<_>>(), 3, 4);
        assert_eq!(page.items, vec![3, 4, 5, 6]);
        assert!(page.has_more);
        assert_eq!(page.next_offset, Some(7));

        let tail = CollectionPage::from_sorted((0..10).collect::<Vec<_>>(), 8, 4);
        assert_eq!(tail.items, vec![8, 9]);
        assert!(!tail.has_more);
        assert_eq!(tail.next_offset, None);
    }

    #[test]
    fn page_limit_has_a_hard_server_ceiling() {
        let query = CollectionPageQuery {
            limit: Some(usize::MAX),
            ..CollectionPageQuery::default()
        };
        assert_eq!(query.limit(), MAX_PAGE_LIMIT);

        let zero = CollectionPageQuery {
            limit: Some(0),
            ..CollectionPageQuery::default()
        };
        assert_eq!(zero.limit(), 1);
    }

    #[test]
    fn keyset_cursor_is_strictly_bound_and_rejects_corruption() {
        let fingerprint = query_fingerprint([
            ("q", "joao".to_owned()),
            ("sort", "username".to_owned()),
            ("order", "asc".to_owned()),
        ]);
        let position = CursorPosition::new("joao", Uuid::nil().to_string());
        let encoded = encode_cursor("users", &fingerprint, &position);
        assert_eq!(
            decode_cursor(&encoded, "users", &fingerprint).unwrap(),
            position
        );
        assert!(decode_cursor(&encoded, "books", &fingerprint).is_err());
        let other = query_fingerprint([
            ("q", "maria".to_owned()),
            ("sort", "username".to_owned()),
            ("order", "asc".to_owned()),
        ]);
        assert!(decode_cursor(&encoded, "users", &other).is_err());

        let mut corrupted = encoded.into_bytes();
        let last = corrupted.last_mut().expect("non-empty cursor");
        *last = if *last == b'A' { b'B' } else { b'A' };
        assert!(
            decode_cursor(
                std::str::from_utf8(&corrupted).unwrap(),
                "users",
                &fingerprint
            )
            .is_err()
        );
    }

    #[test]
    fn keyset_uses_the_id_tiebreaker_in_both_orders() {
        let mut ascending = vec![
            CursorPosition::new("same", "1"),
            CursorPosition::new("same", "2"),
            CursorPosition::new("same", "3"),
        ];
        apply_keyset(
            &mut ascending,
            Some(&CursorPosition::new("same", "1")),
            false,
            Clone::clone,
        );
        assert_eq!(
            ascending,
            vec![
                CursorPosition::new("same", "2"),
                CursorPosition::new("same", "3")
            ]
        );

        let mut descending = vec![
            CursorPosition::new("same", "3"),
            CursorPosition::new("same", "2"),
            CursorPosition::new("same", "1"),
        ];
        apply_keyset(
            &mut descending,
            Some(&CursorPosition::new("same", "3")),
            true,
            Clone::clone,
        );
        assert_eq!(
            descending,
            vec![
                CursorPosition::new("same", "2"),
                CursorPosition::new("same", "1")
            ]
        );
    }

    #[test]
    fn cursor_and_nonzero_offset_are_rejected() {
        let query = CollectionPageQuery {
            cursor: Some("opaque".to_owned()),
            offset: 1,
            ..CollectionPageQuery::default()
        };
        assert!(query.cursor("users", "fingerprint").is_err());
    }

    /// Manual capacity probe for the read-index shape deliberately *not* wired into `AppState`
    /// yet. A production index would keep one `BTreeSet<CursorPosition>` per common collection
    /// sort plus an id-to-positions map, hydrate it after startup load, and update it in the same
    /// centralized mutation boundary as the owning HashMap. Today many modules write those maps
    /// directly, so adding a cache before centralizing every path would permit stale/ghost rows.
    ///
    /// This ignored probe pins the desired 50k lookup operation: a range seek and `limit + 1`
    /// iteration, with no request-time full sort. It intentionally has no wall-clock assertion;
    /// timing thresholds belong in the capacity harness on controlled CI hardware.
    #[test]
    #[ignore = "manual 50k read-index capacity probe"]
    fn btree_read_index_pages_fifty_thousand_without_request_sorting() {
        let started = Instant::now();
        let index: BTreeSet<_> = (0_u32..50_000)
            .map(|number| CursorPosition::new(format!("{number:08}"), format!("{number:08}")))
            .collect();
        let built_in = started.elapsed();
        let marker = CursorPosition::new("00024999", "00024999");
        let seek_started = Instant::now();
        let page: Vec<_> = index
            .range((Excluded(marker), Unbounded))
            .take(DEFAULT_PAGE_LIMIT + 1)
            .cloned()
            .collect();
        let seek_in = seek_started.elapsed();
        assert_eq!(page.len(), DEFAULT_PAGE_LIMIT + 1);
        assert_eq!(page[0].key, "00025000");
        eprintln!("50k index build={built_in:?}, 51-row range seek={seek_in:?}");
    }

    fn user(username: &str, created_at: &str, active: bool) -> User {
        User {
            passkeys: Vec::new(),
            id: UserId(Uuid::new_v4()),
            username: username.to_owned(),
            display_name: username.to_owned(),
            email: None,
            created_at: created_at.to_owned(),
            active,
            password_hash: None,
            attestation_key: None,
            retired_attestation_keys: Vec::new(),
            totp: None,
            two_factor_required: false,
            force_password_change: false,
            secret_source: SecretSource::default(),
            recovery_hash: None,
            role_assignments: Vec::new(),
            language: Default::default(),
        }
    }

    async fn owner_session(state: &AppState) -> String {
        *state.roles.write().await = RoleCatalog::seeded_defaults();
        let mut owner = user("paging.owner", "2026-01-01T00:00:00Z", true);
        owner.role_assignments = vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)];
        let owner_id = owner.id;
        state.users.write().await.insert(owner_id, owner);
        let token = Uuid::new_v4().to_string();
        state.sessions.write().await.insert(
            token.clone(),
            SessionEntry {
                user_id: owner_id,
                unlocked_key: None,
                expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            },
        );
        token
    }

    async fn get_json(state: AppState, uri: &str, token: &str) -> (StatusCode, Value) {
        let request = Request::builder()
            .uri(uri)
            .header("x-chancela-session", token)
            .body(Body::empty())
            .unwrap();
        let response = crate::router(state).oneshot(request).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json = serde_json::from_slice(&body).unwrap_or_else(|error| {
            panic!(
                "expected JSON ({error}); raw={:?}",
                String::from_utf8_lossy(&body)
            )
        });
        (status, json)
    }

    #[tokio::test]
    async fn books_page_applies_enum_filters_before_offset_and_is_bounded() {
        let state = AppState::default();
        let token = owner_session(&state).await;
        let entity_id = EntityId(Uuid::new_v4());
        let mut matching = [
            Book::new(entity_id, BookKind::AssembleiaGeral),
            Book::new(entity_id, BookKind::AssembleiaGeral),
        ];
        matching.sort_by_key(|book| book.id.0);
        let mut excluded = Book::new(entity_id, BookKind::ConselhoFiscal);
        excluded.state = BookState::Open;
        state.books.write().await.extend(
            matching
                .iter()
                .cloned()
                .chain(std::iter::once(excluded))
                .map(|book| (book.id, book)),
        );

        let (status, body) = get_json(
            state.clone(),
            "/v1/books/page?kind=AssembleiaGeral&state=Created&sort=id&offset=1&limit=1",
            &token,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
        assert_eq!(body["items"][0]["id"], matching[1].id.to_string());
        assert_eq!(body["has_more"], false);
        assert!(body.get("total").is_none());

        let (status, body) = get_json(
            state.clone(),
            "/v1/books/page?q=assembleia%20geral&limit=10",
            &token,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["items"].as_array().unwrap().len(), 2);

        let (status, body) = get_json(state, "/v1/books/page?q=aberto&limit=10", &token).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
        assert_eq!(body["items"][0]["state"], "Open");
    }

    #[tokio::test]
    async fn users_page_filters_before_offset_and_sorts_created_at_descending() {
        let state = AppState::default();
        let token = owner_session(&state).await;
        let older = user("active.older", "2026-02-01T00:00:00Z", true);
        let newer = user("active.newer", "2026-03-01T00:00:00Z", true);
        let inactive = user("inactive.latest", "2026-04-01T00:00:00Z", false);
        state
            .users
            .write()
            .await
            .extend([older, newer.clone(), inactive].map(|user| (user.id, user)));

        let (status, body) = get_json(
            state,
            "/v1/users/page?active=true&sort=created_at&order=desc&offset=0&limit=1",
            &token,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
        assert_eq!(body["items"][0]["id"], newer.id.to_string());
        assert_eq!(body["has_more"], true);
        assert_eq!(body["next_offset"], 1);
        assert!(body.get("total").is_none());
    }

    #[tokio::test]
    async fn users_cursor_survives_an_insert_before_the_marker_without_duplicates() {
        let state = AppState::default();
        let token = owner_session(&state).await;
        for username in ["alpha", "bravo", "charlie"] {
            let user = user(username, "2026-02-01T00:00:00Z", true);
            state.users.write().await.insert(user.id, user);
        }
        let (status, first) = get_json(
            state.clone(),
            "/v1/users/page?sort=username&limit=1",
            &token,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["items"][0]["username"], "alpha");
        let cursor = first["next_cursor"].as_str().expect("next cursor");

        let inserted = user("aardvark", "2026-02-01T00:00:00Z", true);
        state.users.write().await.insert(inserted.id, inserted);
        let (status, second) = get_json(
            state,
            &format!("/v1/users/page?sort=username&limit=1&cursor={cursor}"),
            &token,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second["items"][0]["username"], "bravo");
        assert_ne!(second["items"][0]["id"], first["items"][0]["id"]);
        assert!(second.get("next_offset").is_none());
    }

    #[tokio::test]
    async fn cursor_rejects_filter_changes_and_search_folds_accents() {
        let state = AppState::default();
        let token = owner_session(&state).await;
        let mut accented = user("joao", "2026-02-01T00:00:00Z", true);
        accented.display_name = "João da Silva".to_owned();
        state
            .users
            .write()
            .await
            .insert(accented.id, accented.clone());

        let (status, search) =
            get_json(state.clone(), "/v1/users/page?q=joao&limit=10", &token).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            search["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["id"] == accented.id.to_string())
        );

        let (_, first) =
            get_json(state.clone(), "/v1/users/page?active=true&limit=1", &token).await;
        let cursor = first["next_cursor"].as_str().expect("next cursor");
        let (status, _) = get_json(
            state,
            &format!("/v1/users/page?active=false&limit=1&cursor={cursor}"),
            &token,
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }
}
