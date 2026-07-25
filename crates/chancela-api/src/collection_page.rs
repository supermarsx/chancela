//! Shared bounded collection-page contract for the large directory endpoints.
//!
//! Legacy collection routes keep returning their historical bare arrays. New `/page` routes use
//! this contract so clients can opt into a bounded response without breaking older callers.

use serde::{Deserialize, Serialize};

use crate::error::ApiError;

pub(crate) const DEFAULT_PAGE_LIMIT: usize = 50;
pub(crate) const MAX_PAGE_LIMIT: usize = 200;

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct CollectionPageQuery {
    /// Case-insensitive free-text filter interpreted by the owning collection.
    pub q: Option<String>,
    /// Zero-based offset within the caller-visible, filtered collection.
    #[serde(default)]
    pub offset: usize,
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
            .map(str::to_lowercase)
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
}

impl<T> CollectionPage<T> {
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
        }
    }

    pub(crate) fn map<U>(self, mut f: impl FnMut(T) -> U) -> CollectionPage<U> {
        CollectionPage {
            items: self.items.into_iter().map(&mut f).collect(),
            offset: self.offset,
            limit: self.limit,
            has_more: self.has_more,
            next_offset: self.next_offset,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog, Scope};
    use chancela_core::{Book, BookKind, BookState, EntityId};
    use serde_json::Value;
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

    fn user(username: &str, created_at: &str, active: bool) -> User {
        User {
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
            state,
            "/v1/books/page?kind=AssembleiaGeral&state=Created&sort=id&offset=1&limit=1",
            &token,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
        assert_eq!(body["items"][0]["id"], matching[1].id.to_string());
        assert_eq!(body["has_more"], false);
        assert!(body.get("total").is_none());
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
}
