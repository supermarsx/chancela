//! Offline [`MockRegistryTransport`] returning canned certidão HTML fixtures.

use std::sync::Mutex;

use crate::code::AccessCode;
use crate::error::RegistryError;
use crate::transport::{RegistryDocument, RegistryTransport, now_rfc3339};

/// Sociedade por quotas specimen (fictional firm "Encosto Estratégico, Lda").
pub const FIXTURE_SPQ: &str = include_str!("../fixtures/spq_certidao.html");
/// Sociedade anónima specimen (fictional firm "Encosto Estratégico, S.A.").
pub const FIXTURE_SA: &str = include_str!("../fixtures/sa_certidao.html");
/// Foundation specimen (LEG-21; fictional "Fundação Encosto Estratégico").
pub const FIXTURE_FUNDACAO: &str = include_str!("../fixtures/fundacao_certidao.html");
/// Fullest-constitution specimen (deep inscription parsing; minimal matrícula block so the
/// constitution body backfills the identity — fictional "Encosto Estratégico, Lda").
pub const FIXTURE_CONSTITUICAO: &str = include_str!("../fixtures/constituicao_certidao.html");
/// An error/expired consultation page (no Matrícula block → `Unrecognized`).
pub const FIXTURE_EXPIRED: &str = include_str!("../fixtures/expired_error.html");

/// Offline transport returning a canned certidão document; records (masked) the codes it was asked
/// for. Mirrors `MockScmdTransport` / `FileTslSource`. Used by the crate tests and injected into
/// `chancela-api` tests so the whole import flow runs with zero network.
#[derive(Debug, Default)]
pub struct MockRegistryTransport {
    html: Option<String>,
    recorded: Mutex<Vec<String>>,
}

impl MockRegistryTransport {
    /// An empty mock (no canned document — `fetch` yields [`RegistryError::Upstream`]).
    pub fn empty() -> Self {
        Self::default()
    }

    /// A mock returning a single canned certidão document.
    pub fn with_html(mut self, html: impl Into<String>) -> Self {
        self.html = Some(html.into());
        self
    }

    /// Sociedade por quotas specimen (fixture).
    pub fn from_fixture_spq() -> Self {
        Self::empty().with_html(FIXTURE_SPQ)
    }

    /// Sociedade anónima specimen (fixture).
    pub fn from_fixture_sa() -> Self {
        Self::empty().with_html(FIXTURE_SA)
    }

    /// LEG-21 foundation specimen (fixture).
    pub fn from_fixture_fundacao() -> Self {
        Self::empty().with_html(FIXTURE_FUNDACAO)
    }

    /// Fullest-constitution specimen (fixture) — deep inscription parsing + identity backfill.
    pub fn from_fixture_constituicao() -> Self {
        Self::empty().with_html(FIXTURE_CONSTITUICAO)
    }

    /// The masked codes this mock has been asked to consult, in order (never the full digits).
    pub fn recorded(&self) -> Vec<String> {
        self.recorded.lock().expect("recorded mutex").clone()
    }
}

impl RegistryTransport for MockRegistryTransport {
    fn fetch(
        &self,
        code: &AccessCode,
        _email: Option<&str>,
    ) -> Result<RegistryDocument, RegistryError> {
        // Record only the MASKED code — the mock, like the real transport, never retains the secret.
        self.recorded
            .lock()
            .expect("recorded mutex")
            .push(code.masked());

        let html = self.html.clone().ok_or_else(|| {
            RegistryError::Upstream("mock registry has no canned document".to_owned())
        })?;

        Ok(RegistryDocument {
            html,
            source_url: "mock://registry/certidao".to_owned(),
            retrieved_at: now_rfc3339(),
        })
    }
}
