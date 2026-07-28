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
/// The consultation page's *code rejected* notice — "o código de acesso introduzido não é válido ou
/// a certidão já expirou". The service conflates invalid and expired, so this maps to
/// [`RegistryError::CodeRejected`], which carries that disjunction rather than resolving it.
pub const FIXTURE_EXPIRED: &str = include_str!("../fixtures/expired_error.html");
/// The consultation page's *no such certidão* notice — "não existe qualquer certidão com esse
/// número". A **different** real page from [`FIXTURE_EXPIRED`], and a definite answer from a working
/// service, so it maps to [`RegistryError::CertidaoNotFound`].
pub const FIXTURE_NOT_FOUND: &str = include_str!("../fixtures/not_found_error.html");
/// **The live consultation page's real layout**, captured from a genuine `consultaCertidao.aspx`
/// response and then anonymised (fictional "Encosto Estratégico - LDA" and "Amélia Marques";
/// fabricated NIPC/NIF, addresses, postal codes and access code). Markup is otherwise untouched, so
/// it keeps the quirks the hand-written fixtures lack: the full ASP.NET page chrome, `</br>` used as
/// a line break, `<td>Insc.N</td><td>AP. …</td>` splitting the entry across two cells, `Nome:` in
/// the Matrícula organ block, and stray unopened `</font>` tags.
pub const FIXTURE_LIVE_SPQ: &str = include_str!("../fixtures/live_spq_certidao.html");

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

    /// The registry's "código de acesso inválido ou certidão expirada" notice (fixture).
    pub fn from_fixture_code_rejected() -> Self {
        Self::empty().with_html(FIXTURE_EXPIRED)
    }

    /// The registry's "não existe qualquer certidão com esse número" notice (fixture).
    pub fn from_fixture_not_found() -> Self {
        Self::empty().with_html(FIXTURE_NOT_FOUND)
    }

    /// Anonymised capture of the **live** consultation page's layout (fixture).
    pub fn from_fixture_live_spq() -> Self {
        Self::empty().with_html(FIXTURE_LIVE_SPQ)
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
