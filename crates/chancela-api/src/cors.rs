//! Explicit cross-origin policy for remote companion clients.
//!
//! Same-origin remains the default: when [`CORS_ALLOWED_ORIGINS_ENV`] is unset or blank, the API
//! emits no CORS headers. Enabling the policy requires a comma-separated list of exact HTTP(S)
//! origins. Wildcards, opaque origins, credentials in URLs, paths, queries, and fragments are
//! rejected at startup instead of broadening access accidentally.

use std::collections::HashSet;
use std::fmt;
use std::time::Duration;

use axum::http::Method;
use axum::http::header::{
    ACCEPT, AUTHORIZATION, CONTENT_DISPOSITION, CONTENT_TYPE, HeaderName, HeaderValue,
};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::actor::SESSION_HEADER;

/// Comma-separated exact companion origins allowed to call the API cross-origin.
pub const CORS_ALLOWED_ORIGINS_ENV: &str = "CHANCELA_CORS_ALLOWED_ORIGINS";

const MAX_ORIGINS: usize = 32;
const MAX_CONFIG_BYTES: usize = 8 * 1024;

/// A validated, exact-origin CORS allowlist. Empty means same-origin only.
#[derive(Clone, Debug, Default)]
pub struct CorsConfig {
    origins: Vec<HeaderValue>,
}

impl CorsConfig {
    pub(crate) fn from_env() -> Result<Self, CorsConfigError> {
        match std::env::var_os(CORS_ALLOWED_ORIGINS_ENV) {
            None => Ok(Self::default()),
            Some(raw) => {
                let raw = raw.into_string().map_err(|_| CorsConfigError::NonUnicode)?;
                Self::parse(&raw)
            }
        }
    }

    pub(crate) fn parse(raw: &str) -> Result<Self, CorsConfigError> {
        if raw.len() > MAX_CONFIG_BYTES {
            return Err(CorsConfigError::TooLong);
        }
        if raw.trim().is_empty() {
            return Ok(Self::default());
        }

        let candidates: Vec<&str> = raw.split(',').collect();
        if candidates.len() > MAX_ORIGINS {
            return Err(CorsConfigError::TooManyOrigins);
        }

        let mut seen = HashSet::new();
        let mut origins = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let candidate = candidate.trim();
            if candidate.is_empty() {
                return Err(CorsConfigError::EmptyOrigin);
            }
            if candidate == "*" || candidate.eq_ignore_ascii_case("null") {
                return Err(CorsConfigError::UnsafeOrigin(candidate.to_owned()));
            }

            let parsed = reqwest::Url::parse(candidate)
                .map_err(|_| CorsConfigError::MalformedOrigin(candidate.to_owned()))?;
            if !matches!(parsed.scheme(), "http" | "https")
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.path() != "/"
                || parsed.query().is_some()
                || parsed.fragment().is_some()
            {
                return Err(CorsConfigError::MalformedOrigin(candidate.to_owned()));
            }

            // Serialize only the origin tuple. This canonicalizes host casing/default ports and
            // deliberately strips the URL parser's synthetic root slash.
            let canonical = parsed.origin().ascii_serialization();
            if !seen.insert(canonical.clone()) {
                continue;
            }
            origins.push(
                HeaderValue::from_str(&canonical)
                    .map_err(|_| CorsConfigError::MalformedOrigin(candidate.to_owned()))?,
            );
        }
        Ok(Self { origins })
    }

    pub(crate) fn layer(&self) -> Option<CorsLayer> {
        if self.origins.is_empty() {
            return None;
        }

        let session_header = HeaderName::from_static(SESSION_HEADER);
        Some(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(self.origins.clone()))
                .allow_methods([
                    Method::GET,
                    Method::HEAD,
                    Method::POST,
                    Method::PUT,
                    Method::PATCH,
                    Method::DELETE,
                    Method::OPTIONS,
                ])
                .allow_headers([ACCEPT, AUTHORIZATION, CONTENT_TYPE, session_header])
                .expose_headers([
                    CONTENT_DISPOSITION,
                    HeaderName::from_static("x-request-id"),
                    HeaderName::from_static("x-chancela-bundle-digest"),
                    HeaderName::from_static("x-chancela-export-path"),
                    HeaderName::from_static("x-content-sha256"),
                ])
                .max_age(Duration::from_secs(10 * 60)),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CorsConfigError {
    NonUnicode,
    TooLong,
    TooManyOrigins,
    EmptyOrigin,
    UnsafeOrigin(String),
    MalformedOrigin(String),
}

impl fmt::Display for CorsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonUnicode => write!(f, "contains non-Unicode data"),
            Self::TooLong => write!(f, "exceeds {MAX_CONFIG_BYTES} bytes"),
            Self::TooManyOrigins => write!(f, "contains more than {MAX_ORIGINS} origins"),
            Self::EmptyOrigin => write!(f, "contains an empty origin entry"),
            Self::UnsafeOrigin(origin) => {
                write!(
                    f,
                    "contains forbidden origin {origin:?}; wildcards and null are not allowed"
                )
            }
            Self::MalformedOrigin(origin) => write!(
                f,
                "contains invalid origin {origin:?}; use an exact http(s) origin without credentials, path, query, or fragment"
            ),
        }
    }
}

impl std::error::Error for CorsConfigError {}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::header::{
        ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
        ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_REQUEST_HEADERS,
        ACCESS_CONTROL_REQUEST_METHOD, ORIGIN,
    };
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::*;

    #[test]
    fn parser_is_exact_bounded_and_fail_closed() {
        let config = CorsConfig::parse(
            "http://tauri.localhost, https://Companion.Example:443,https://companion.example",
        )
        .expect("valid exact origins");
        assert_eq!(config.origins.len(), 2, "canonical duplicates collapse");

        for invalid in [
            "*",
            "null",
            "https://example.com/path",
            "https://user@example.com",
            "https://example.com?wide=open",
            "tauri://localhost",
            "https://example.com,",
        ] {
            assert!(
                CorsConfig::parse(invalid).is_err(),
                "must reject {invalid:?}"
            );
        }
    }

    #[tokio::test]
    async fn configured_origin_gets_bounded_preflight_and_disallowed_origin_does_not() {
        let state = crate::AppState {
            cors: CorsConfig::parse("http://tauri.localhost").unwrap(),
            ..Default::default()
        };
        let app = crate::router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/v1/session")
                    .header(ORIGIN, "http://tauri.localhost")
                    .header(ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .header(
                        ACCESS_CONTROL_REQUEST_HEADERS,
                        "content-type,x-chancela-session",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "http://tauri.localhost"
        );
        assert!(
            response
                .headers()
                .get(ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none(),
            "session headers do not require credentialed-cookie CORS"
        );
        let methods = response
            .headers()
            .get(ACCESS_CONTROL_ALLOW_METHODS)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(methods.split(',').any(|method| method.trim() == "POST"));
        let headers = response
            .headers()
            .get(ACCESS_CONTROL_ALLOW_HEADERS)
            .unwrap()
            .to_str()
            .unwrap()
            .to_ascii_lowercase();
        assert!(headers.contains("x-chancela-session"));
        assert!(headers.contains("content-type"));

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/v1/session")
                    .header(ORIGIN, "https://attacker.example")
                    .header(ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(denied.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none());

        for (method, headers, forbidden) in [
            ("TRACE", "content-type", "trace"),
            ("POST", "x-unbounded-header", "x-unbounded-header"),
        ] {
            let rejected = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::OPTIONS)
                        .uri("/v1/session")
                        .header(ORIGIN, "http://tauri.localhost")
                        .header(ACCESS_CONTROL_REQUEST_METHOD, method)
                        .header(ACCESS_CONTROL_REQUEST_HEADERS, headers)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let granted = [ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_HEADERS]
                .iter()
                .filter_map(|header| rejected.headers().get(header))
                .filter_map(|value| value.to_str().ok())
                .collect::<Vec<_>>()
                .join(",")
                .to_ascii_lowercase();
            assert!(
                !granted.contains(forbidden),
                "unsupported method/header must not appear in its preflight grant: {granted}"
            );
        }

        let auth_error = app
            .oneshot(
                Request::builder()
                    .uri("/v1/session/permissions")
                    .header(ORIGIN, "http://tauri.localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(auth_error.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            auth_error
                .headers()
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "http://tauri.localhost"
        );
    }

    #[tokio::test]
    async fn same_origin_default_emits_no_cross_origin_grant() {
        let response = crate::router(crate::AppState::default())
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header(ORIGIN, "https://companion.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            response
                .headers()
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
    }
}
