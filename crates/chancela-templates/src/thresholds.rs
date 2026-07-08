//! # Legal-threshold placeholder registry (t53 / E3)
//!
//! Portugal's convening, quorum and majority rules are scattered across the CSC, the Código Civil,
//! the Código Cooperativo and sundry statutes, and the exact numbers for this catalog are **not yet
//! legally verified**. Rather than let an author guess a day-count or a majority into template
//! prose (a compliance hazard — WFL-31 keeps compliance in the rule pack, never the template), the
//! ~78 catalog templates reference these values through **one central registry** of
//! [`LegalThreshold`]s and a minijinja `threshold("<id>")` function.
//!
//! ## The contract
//!
//! - Every threshold ships `value: None` — **unresolved**. `threshold("id")` then renders a loud,
//!   unmistakable placeholder `[a definir: {label_pt} ({article_ref})]` — **never a number**.
//! - When the lawyer resolves a value, they set the one `value:` field in
//!   [`LEGAL_THRESHOLDS`] below (this file, one edit) to `Some(...)`. `threshold("id")` then renders
//!   the value: [`ThresholdValue::Days`] → `"N dias"`, [`ThresholdValue::Fraction`] → `"n/d"`,
//!   [`ThresholdValue::Clause`] → the authored clause text.
//! - An **unknown id is a render error** (not a blank), so a typo in a template asset fails the
//!   asset-lint test / the render, it never silently vanishes.
//!
//! `Clause`, `label_pt` and `article_ref` are `&'static str` so the whole registry is a `static`
//! and a resolved value is const-constructible in place — filling one in stays a single-file edit.

use minijinja::{Error as JinjaError, ErrorKind};

/// A resolved legal-threshold value. Compound legal areas (majority *sets*, governance *regimes*)
/// are a [`Clause`](ThresholdValue::Clause) so a lawyer fills one authored sentence; a single
/// day-count is [`Days`](ThresholdValue::Days); a bare ratio is a [`Fraction`](ThresholdValue::Fraction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdValue {
    /// A notice/impugnation period in days — renders as `"{n} dias"`.
    Days(u16),
    /// A bare ratio majority — renders as `"{numerator}/{denominator}"`.
    Fraction {
        /// The numerator (e.g. `2` in `2/3`).
        numerator: u32,
        /// The denominator (e.g. `3` in `2/3`).
        denominator: u32,
    },
    /// A compound rule set / governance regime / policy text — renders verbatim.
    Clause(&'static str),
}

impl ThresholdValue {
    /// Render a resolved value to its PT surface form.
    fn render(&self) -> String {
        match self {
            ThresholdValue::Days(n) => format!("{n} dias"),
            ThresholdValue::Fraction {
                numerator,
                denominator,
            } => format!("{numerator}/{denominator}"),
            ThresholdValue::Clause(text) => (*text).to_string(),
        }
    }
}

/// One legal threshold. `id` is the stable key templates reference via `threshold("<id>")`;
/// `label_pt` + `article_ref` compose the human-readable unresolved marker; `value` is `None` until
/// the lawyer resolves it (the **only** edit needed to fill one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegalThreshold {
    /// Stable key, e.g. `"csc.sa.convocatoria.antecedencia_dias"`.
    pub id: &'static str,
    /// Human PT label for the placeholder, e.g. `"prazo de convocatória (sociedade anónima)"`.
    pub label_pt: &'static str,
    /// The governing article citation, e.g. `"CSC art. 377.º/4"`.
    pub article_ref: &'static str,
    /// The resolved value, or `None` while unresolved. **Fill this in to resolve the threshold.**
    pub value: Option<ThresholdValue>,
}

impl LegalThreshold {
    /// The rendered surface form: the resolved value, or the unresolved
    /// `[a definir: {label_pt} ({article_ref})]` marker.
    ///
    /// The marker is deliberately loud (bracketed, prefixed `a definir:`) so it cannot be mistaken
    /// for finished text, and — crucially — it is **never a number**: the only digits it can carry
    /// live inside the `(article_ref)` citation, never in the value position.
    pub fn render(&self) -> String {
        match &self.value {
            Some(v) => v.render(),
            None => format!("[a definir: {} ({})]", self.label_pt, self.article_ref),
        }
    }
}

/// The **entire** legal-threshold registry: the 11 unresolved thresholds this catalog needs.
///
/// Every entry ships `value: None`. Resolving one = changing its `value:` to `Some(...)` here —
/// one file, one line. Ids must stay unique (guaranteed by test); authors bind them verbatim.
pub static LEGAL_THRESHOLDS: &[LegalThreshold] = &[
    LegalThreshold {
        id: "csc.sa.convocatoria.antecedencia_dias",
        label_pt: "prazo de convocatória da assembleia geral de sociedade anónima",
        article_ref: "CSC art. 377.º/4",
        value: None,
    },
    LegalThreshold {
        id: "csc.quotas.convocatoria.antecedencia_dias",
        label_pt: "prazo de convocatória da assembleia geral de sociedade por quotas",
        article_ref: "CSC art. 248.º/3",
        value: None,
    },
    LegalThreshold {
        id: "csc.deliberacao.maioria_qualificada",
        label_pt: "maioria qualificada exigida para a deliberação",
        article_ref: "CSC arts. 250.º, 265.º e 386.º",
        value: None,
    },
    LegalThreshold {
        id: "condominio.convocatoria.antecedencia_dias",
        label_pt: "prazo de convocatória da assembleia de condóminos",
        article_ref: "CC art. 1432.º",
        value: None,
    },
    LegalThreshold {
        id: "condominio.deliberacao.maioria_permilagem",
        label_pt: "maioria por permilagem exigida para a deliberação em condomínio",
        article_ref: "CC art. 1432.º",
        value: None,
    },
    LegalThreshold {
        id: "condominio.ausentes.prazo_impugnacao_dias",
        label_pt: "prazo de impugnação das deliberações pelos condóminos ausentes",
        article_ref: "CC arts. 1432.º/6 e 1433.º",
        value: None,
    },
    LegalThreshold {
        id: "assoc.convocatoria_maioria",
        label_pt: "regime de convocatória e maioria da assembleia geral de associados",
        article_ref: "CC arts. 173.º e 175.º",
        value: None,
    },
    LegalThreshold {
        id: "fundacao.orgao.regime_convocatoria",
        label_pt: "regime de convocatória do órgão de administração da fundação",
        article_ref: "Lei n.º 24/2012",
        value: None,
    },
    LegalThreshold {
        id: "cooperativa.convocatoria.antecedencia_dias",
        label_pt: "prazo de convocatória da assembleia geral da cooperativa",
        article_ref: "Código Cooperativo arts. 33.º, 34.º e 41.º",
        value: None,
    },
    LegalThreshold {
        id: "certidao.autoridade_certificacao",
        label_pt: "autoridade de certificação da certidão",
        article_ref: "TPL-40",
        value: None,
    },
    LegalThreshold {
        id: "termo.conjunto_signatarios",
        label_pt: "conjunto de signatários exigido para o termo",
        article_ref: "DL 76-A/2006",
        value: None,
    },
];

/// Look a threshold up by its stable id.
pub fn find_threshold(id: &str) -> Option<&'static LegalThreshold> {
    LEGAL_THRESHOLDS.iter().find(|t| t.id == id)
}

/// The minijinja `threshold("<id>")` function. Registered on the render environment by the engine.
///
/// - unknown id ⇒ a render **error** (typo-safe; the asset-lint test catches it earlier).
/// - known id ⇒ [`LegalThreshold::render`] (the unresolved marker, or the resolved value).
pub(crate) fn threshold_function(id: &str) -> Result<String, JinjaError> {
    match find_threshold(id) {
        Some(t) => Ok(t.render()),
        None => Err(JinjaError::new(
            ErrorKind::InvalidOperation,
            format!("unknown legal threshold id: {id:?}"),
        )),
    }
}

/// Scan a template source string for every `threshold("<id>")` / `threshold('<id>')` reference and
/// return the referenced ids, in order of appearance (duplicates kept).
///
/// This is the reusable core of the **asset-lint** guarantee: catalog CI can scan every authored
/// asset and assert each referenced id resolves via [`find_threshold`], so a typo in an asset fails
/// a fast string test rather than only surfacing at render time.
pub fn scan_threshold_references(src: &str) -> Vec<String> {
    const NEEDLE: &str = "threshold";
    let mut ids = Vec::new();
    let mut i = 0usize;
    while let Some(pos) = src[i..].find(NEEDLE) {
        let after = i + pos + NEEDLE.len();
        i = after; // advance past this match regardless of what follows
        let rest = src[after..].trim_start();
        let Some(rest) = rest.strip_prefix('(') else {
            continue;
        };
        let rest = rest.trim_start();
        let quote = match rest.chars().next() {
            Some(q @ ('"' | '\'')) => q,
            _ => continue,
        };
        let inner = &rest[quote.len_utf8()..];
        if let Some(end) = inner.find(quote) {
            ids.push(inner[..end].to_string());
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact 11 ids the plan froze — the authoring contract for E5–E9.
    const EXPECTED_IDS: [&str; 11] = [
        "csc.sa.convocatoria.antecedencia_dias",
        "csc.quotas.convocatoria.antecedencia_dias",
        "csc.deliberacao.maioria_qualificada",
        "condominio.convocatoria.antecedencia_dias",
        "condominio.deliberacao.maioria_permilagem",
        "condominio.ausentes.prazo_impugnacao_dias",
        "assoc.convocatoria_maioria",
        "fundacao.orgao.regime_convocatoria",
        "cooperativa.convocatoria.antecedencia_dias",
        "certidao.autoridade_certificacao",
        "termo.conjunto_signatarios",
    ];

    #[test]
    fn all_eleven_thresholds_present_with_unique_ids() {
        assert_eq!(
            LEGAL_THRESHOLDS.len(),
            11,
            "registry must hold exactly the 11 planned thresholds"
        );
        // Every expected id is present and resolvable.
        for id in EXPECTED_IDS {
            assert!(find_threshold(id).is_some(), "missing threshold id: {id}");
        }
        // No duplicate ids.
        let mut seen = std::collections::BTreeSet::new();
        for t in LEGAL_THRESHOLDS {
            assert!(seen.insert(t.id), "duplicate threshold id: {}", t.id);
        }
        assert_eq!(seen.len(), 11);
    }

    #[test]
    fn every_threshold_ships_unresolved() {
        // The whole point: nothing is ever shipped as a guessed number.
        for t in LEGAL_THRESHOLDS {
            assert!(
                t.value.is_none(),
                "threshold {} must ship value: None (never a guessed number)",
                t.id
            );
        }
    }

    #[test]
    fn unresolved_render_is_the_marker_and_never_a_number() {
        for t in LEGAL_THRESHOLDS {
            let out = t.render();
            // Loud, unmistakable placeholder.
            assert!(
                out.starts_with("[a definir: ") && out.ends_with(']'),
                "{} did not render the marker: {out:?}",
                t.id
            );
            assert!(out.contains(t.label_pt));
            assert!(out.contains(t.article_ref));
            // The label must carry no digits, so once the (article_ref) citation is removed the
            // marker holds NO digit that could be mistaken for the legal value.
            let without_ref = out.replacen(t.article_ref, "", 1);
            assert!(
                !without_ref.chars().any(|c| c.is_ascii_digit()),
                "{} marker leaks a stray digit outside the article ref: {out:?}",
                t.id
            );
        }
    }

    #[test]
    fn resolved_values_render_to_their_surface_form() {
        // Locks the render contract the lawyer relies on when filling a value.
        assert_eq!(ThresholdValue::Days(15).render(), "15 dias");
        assert_eq!(
            ThresholdValue::Fraction {
                numerator: 2,
                denominator: 3,
            }
            .render(),
            "2/3"
        );
        assert_eq!(
            ThresholdValue::Clause("maioria de dois terços dos votos").render(),
            "maioria de dois terços dos votos"
        );
    }

    #[test]
    fn threshold_function_errors_on_unknown_id() {
        assert!(threshold_function("csc.sa.convocatoria.antecedencia_dias").is_ok());
        assert!(threshold_function("nao.existe.este.id").is_err());
    }

    #[test]
    fn scan_finds_ids_across_quote_styles_and_ignores_bare_word() {
        let src = r#"Prazo: {{ threshold("csc.sa.convocatoria.antecedencia_dias") }} e
                     {{ threshold( 'termo.conjunto_signatarios' ) }}; o threshold legal aplica-se."#;
        let ids = scan_threshold_references(src);
        assert_eq!(
            ids,
            vec![
                "csc.sa.convocatoria.antecedencia_dias".to_string(),
                "termo.conjunto_signatarios".to_string(),
            ]
        );
    }

    /// **Asset-lint** — the reusable guarantee E5–E9's CI benefits from: every `threshold("...")`
    /// reference in every embedded catalog asset must resolve to a known registry id.
    #[test]
    fn every_asset_threshold_reference_resolves() {
        for (name, json) in crate::ASSET_FILES {
            for id in scan_threshold_references(json) {
                assert!(
                    find_threshold(&id).is_some(),
                    "asset {name}.json references unknown threshold id {id:?} \
                     — typo, or the registry is missing it"
                );
            }
        }
    }
}
