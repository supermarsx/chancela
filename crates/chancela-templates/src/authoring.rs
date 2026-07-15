//! # Authoring guard — validate + parse a *user-authored* template
//!
//! The built-in catalog is trusted data drops (`assets/*.json`, loaded by `load_registry`). This
//! module adds the **public entrypoint for untrusted input**: templates a user writes, stores,
//! or imports. They travel as the same [`crate::TemplateSpec`] JSON shape the registry uses, but
//! must be re-checked before we ever keep or render them.
//!
//! [`validate_user_template`] is the single "legally-malformed template" guard. It runs a fixed,
//! ordered sequence of checks and, on success, hands back a ready [`TemplateSpec`]; on the first
//! failure it returns a [`TemplateValidationError`] carrying a stable [`code`](TemplateValidationError::code)
//! and optional [`field`](TemplateValidationError::field) so the API layer can render an HTTP 422
//! `{code, field?, message}` body without matching on Rust variants.
//!
//! ## Order of checks (first failure wins)
//!
//! 1. byte size ≤ [`MAX_TEMPLATE_BYTES`] → [`TemplateValidationError::TooLarge`]
//! 2. strict serde parse (the registry DTO is `deny_unknown_fields`) →
//!    [`TemplateValidationError::Malformed`]
//! 3. `id` non-empty, ≤ 128 bytes, matching `^user-[a-z0-9-]+/v[0-9]+$` (the reserved `user-`
//!    namespace means a user template can never shadow a built-in id) →
//!    [`TemplateValidationError::InvalidId`]
//! 4. blocks non-empty and ≤ [`MAX_BLOCKS`]; every template string ≤
//!    [`MAX_TEMPLATE_STRING_BYTES`] → [`TemplateValidationError::NoBlocks`] /
//!    [`TemplateValidationError::TooLarge`]
//! 5. every template string compiles under the author environment →
//!    [`TemplateValidationError::BadTemplate`]
//! 6. every `threshold("<id>")` reference resolves in the threshold registry →
//!    [`TemplateValidationError::UnknownThreshold`]
//! 7. `locale` non-empty and in the allow-list → [`TemplateValidationError::UnsupportedLocale`]
//!
//! Messages are neutral and technical: this guard checks *shape*, not legal validity, and makes no
//! claim about the evidentiary weight of any document a template might produce.

use std::fmt;

use crate::{
    BlockSpec, TemplateSpec, compile_template_str, find_threshold, scan_threshold_references,
};

/// Maximum size, in bytes, of the whole authored template JSON.
pub const MAX_TEMPLATE_BYTES: usize = 64 * 1024;
/// Maximum number of blocks a single template may declare.
pub const MAX_BLOCKS: usize = 200;
/// Maximum size, in bytes, of any single minijinja template string inside a block.
pub const MAX_TEMPLATE_STRING_BYTES: usize = 8 * 1024;

/// Maximum length, in bytes, of a template `id`.
const MAX_ID_BYTES: usize = 128;
/// Locales an authored template may declare (v1: pt-PT only, UX-21).
const ALLOWED_LOCALES: &[&str] = &["pt-PT"];

/// Why an authored template was rejected. Each variant maps to a stable
/// [`code`](Self::code)/[`field`](Self::field) pair for a `{code, field?, message}` API body.
///
/// Human-facing text is intentionally neutral and technical — no claim about legal validity or the
/// evidentiary value of a produced document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateValidationError {
    /// A size limit was exceeded (the whole payload, the block count, or one template string).
    TooLarge {
        /// The limit that was exceeded, in the same unit as `actual`.
        limit: usize,
        /// The observed size.
        actual: usize,
    },
    /// The JSON did not parse against the strict template schema (missing/unknown field, bad enum
    /// value, wrong type). `field` names the offending field when it can be determined.
    Malformed {
        /// The offending field, when known.
        field: Option<String>,
        /// The underlying parser message.
        msg: String,
    },
    /// The `id` is empty, too long, or does not match the reserved `user-<slug>/v<n>` pattern.
    InvalidId {
        /// What was wrong with the id.
        msg: String,
    },
    /// The template declared no blocks.
    NoBlocks,
    /// A block's template string failed to compile under the author environment.
    BadTemplate {
        /// Index of the offending block within `blocks`.
        block_index: usize,
        /// The minijinja compile error.
        msg: String,
    },
    /// A `threshold("<id>")` reference did not resolve in the threshold registry.
    UnknownThreshold {
        /// The unresolved threshold id.
        id: String,
    },
    /// The declared `locale` is empty or not in the supported allow-list.
    UnsupportedLocale {
        /// The rejected locale.
        locale: String,
    },
}

impl TemplateValidationError {
    /// A stable, machine-readable error code for the API `{code, ...}` body. Never changes for a
    /// given variant, so clients may branch on it.
    pub fn code(&self) -> &'static str {
        match self {
            TemplateValidationError::TooLarge { .. } => "too_large",
            TemplateValidationError::Malformed { .. } => "malformed",
            TemplateValidationError::InvalidId { .. } => "invalid_id",
            TemplateValidationError::NoBlocks => "no_blocks",
            TemplateValidationError::BadTemplate { .. } => "bad_template",
            TemplateValidationError::UnknownThreshold { .. } => "unknown_threshold",
            TemplateValidationError::UnsupportedLocale { .. } => "unsupported_locale",
        }
    }

    /// The offending field path for the API `{..., field?, ...}` body, when one applies.
    pub fn field(&self) -> Option<String> {
        match self {
            TemplateValidationError::TooLarge { .. } => None,
            TemplateValidationError::Malformed { field, .. } => field.clone(),
            TemplateValidationError::InvalidId { .. } => Some("id".to_string()),
            TemplateValidationError::NoBlocks => Some("blocks".to_string()),
            TemplateValidationError::BadTemplate { block_index, .. } => {
                Some(format!("blocks[{block_index}]"))
            }
            TemplateValidationError::UnknownThreshold { .. } => None,
            TemplateValidationError::UnsupportedLocale { .. } => Some("locale".to_string()),
        }
    }
}

impl fmt::Display for TemplateValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TemplateValidationError::TooLarge { limit, actual } => {
                write!(
                    f,
                    "template exceeds the size limit: {actual} > {limit} bytes"
                )
            }
            TemplateValidationError::Malformed { field, msg } => match field {
                Some(field) => write!(f, "malformed template at field `{field}`: {msg}"),
                None => write!(f, "malformed template: {msg}"),
            },
            TemplateValidationError::InvalidId { msg } => write!(f, "invalid template id: {msg}"),
            TemplateValidationError::NoBlocks => {
                write!(f, "template must declare at least one block")
            }
            TemplateValidationError::BadTemplate { block_index, msg } => {
                write!(f, "block {block_index} has an uncompilable template: {msg}")
            }
            TemplateValidationError::UnknownThreshold { id } => {
                write!(f, "unknown legal threshold reference: {id:?}")
            }
            TemplateValidationError::UnsupportedLocale { locale } => {
                write!(f, "unsupported locale: {locale:?}")
            }
        }
    }
}

impl std::error::Error for TemplateValidationError {}

/// Validate and parse a user-authored template.
///
/// Runs the ordered checks documented on the [module](self) and, on success, returns the parsed
/// [`TemplateSpec`] (with its server-derived `law_references` populated by the DTO conversion — the
/// author neither supplies nor is trusted for those). On the first failure returns a
/// [`TemplateValidationError`]. See [`TemplateValidationError::code`]/[`field`](TemplateValidationError::field)
/// for mapping to an HTTP 422 body.
pub fn validate_user_template(json: &str) -> Result<TemplateSpec, TemplateValidationError> {
    // 1. Overall size — cheap gate before we hand untrusted bytes to serde.
    if json.len() > MAX_TEMPLATE_BYTES {
        return Err(TemplateValidationError::TooLarge {
            limit: MAX_TEMPLATE_BYTES,
            actual: json.len(),
        });
    }

    // 2. Strict parse. The registry DTO is `deny_unknown_fields`, so serde already rejects unknown
    //    keys, missing required fields, and bad enum values for family/stage/channels/signature.
    let dto: crate::TemplateSpecDto =
        serde_json::from_str(json).map_err(|e| TemplateValidationError::Malformed {
            field: None,
            msg: e.to_string(),
        })?;
    let spec: TemplateSpec = dto.into();

    // 3. Id: non-empty, bounded, reserved `user-` namespace pattern.
    if spec.id.is_empty() {
        return Err(TemplateValidationError::InvalidId {
            msg: "id must not be empty".to_string(),
        });
    }
    if spec.id.len() > MAX_ID_BYTES {
        return Err(TemplateValidationError::InvalidId {
            msg: format!("id exceeds {MAX_ID_BYTES} bytes"),
        });
    }
    if !is_reserved_user_id(&spec.id) {
        return Err(TemplateValidationError::InvalidId {
            msg: "id must match the reserved user pattern `user-<slug>/v<n>` \
                  (slug: lowercase letters, digits, hyphens)"
                .to_string(),
        });
    }

    // 4. Blocks present, bounded, and every template string within the per-string byte limit.
    if spec.blocks.is_empty() {
        return Err(TemplateValidationError::NoBlocks);
    }
    if spec.blocks.len() > MAX_BLOCKS {
        return Err(TemplateValidationError::TooLarge {
            limit: MAX_BLOCKS,
            actual: spec.blocks.len(),
        });
    }
    for block in &spec.blocks {
        for s in block_template_strings(block) {
            if s.len() > MAX_TEMPLATE_STRING_BYTES {
                return Err(TemplateValidationError::TooLarge {
                    limit: MAX_TEMPLATE_STRING_BYTES,
                    actual: s.len(),
                });
            }
        }
    }

    // 5. Every template string compiles under the author environment (syntax gate). Compilation
    //    does not evaluate, so `threshold(...)` ids are checked separately in step 6.
    for (block_index, block) in spec.blocks.iter().enumerate() {
        for s in block_template_strings(block) {
            if let Err(msg) = compile_template_str(s) {
                return Err(TemplateValidationError::BadTemplate { block_index, msg });
            }
        }
    }

    // 6. Every threshold reference resolves in the registry (typo-safe).
    for block in &spec.blocks {
        for s in block_template_strings(block) {
            for id in scan_threshold_references(s) {
                if find_threshold(&id).is_none() {
                    return Err(TemplateValidationError::UnknownThreshold { id });
                }
            }
        }
    }

    // 7. Locale allow-list.
    if !ALLOWED_LOCALES.contains(&spec.locale.as_str()) {
        return Err(TemplateValidationError::UnsupportedLocale {
            locale: spec.locale.clone(),
        });
    }

    Ok(spec)
}

/// Every minijinja template string carried by a block, in a stable order. Covers *only* the
/// template-string-bearing fields — dotted context paths (`items`/`source`/`vote_field`) are not
/// minijinja and are not checked here.
fn block_template_strings(block: &BlockSpec) -> Vec<&str> {
    match block {
        BlockSpec::Heading { template, .. } | BlockSpec::Paragraph { template, .. } => {
            vec![template.as_str()]
        }
        BlockSpec::KeyValue { rows, .. } => {
            let mut out = Vec::with_capacity(rows.len() * 2);
            for row in rows {
                out.push(row.key.as_str());
                out.push(row.value.as_str());
            }
            out
        }
        BlockSpec::VoteTable {
            label,
            unanimous_total,
            ..
        } => {
            let mut out = vec![label.as_str()];
            if let Some(total) = unanimous_total {
                out.push(total.as_str());
            }
            out
        }
        BlockSpec::SignatureBlock { role, name, .. } => vec![role.as_str(), name.as_str()],
        BlockSpec::PageBreak | BlockSpec::Rule => Vec::new(),
    }
}

/// Match `^user-[a-z0-9-]+/v[0-9]+$` by hand (the crate has no regex dependency). The `user-`
/// prefix is reserved so an authored id can never collide with a built-in catalog id.
fn is_reserved_user_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("user-") else {
        return false;
    };
    // The slug is `[a-z0-9-]+` (never a slash), so the first '/' separates slug from version.
    let Some(slash) = rest.find('/') else {
        return false;
    };
    let (slug, version) = rest.split_at(slash);
    if slug.is_empty()
        || !slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return false;
    }
    let Some(digits) = version.strip_prefix("/v") else {
        return false;
    };
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal, valid user template touching every template-string-bearing block kind.
    fn valid_json() -> String {
        r#"{
            "id": "user-encosto-ata/v1",
            "family": "CommercialCompany",
            "stage": "Ata",
            "channels": ["Physical"],
            "signature_policy": "QualifiedPreferred",
            "rule_pack_id": "csc-art63/v2",
            "locale": "pt-PT",
            "blocks": [
                { "kind": "Heading", "level": 1, "template": "Ata n.º {{ ata_number }}" },
                { "kind": "Paragraph", "template": "Reunida a assembleia em {{ meeting_date | long_date }}." },
                { "kind": "KeyValue", "rows": [ { "key": "Canal", "value": "{{ channel | channel_label }}" } ] },
                { "kind": "VoteTable", "items": "deliberation_items", "label": "{{ text }}", "unanimous_total": "{{ members_present }}" },
                { "kind": "SignatureBlock", "source": "signatories", "role": "{{ capacity | role_label }}", "name": "{{ name }}" }
            ]
        }"#
        .to_string()
    }

    #[test]
    fn valid_minimal_user_template_passes() {
        let spec = validate_user_template(&valid_json()).expect("valid template");
        assert_eq!(spec.id, "user-encosto-ata/v1");
        assert_eq!(spec.locale, "pt-PT");
        assert_eq!(spec.blocks.len(), 5);
    }

    #[test]
    fn oversize_payload_is_too_large() {
        // A well-formed body padded past the byte limit with whitespace inside a string.
        let filler = " ".repeat(MAX_TEMPLATE_BYTES + 1);
        let json = format!(
            r#"{{"id":"user-x/v1","family":"Association","stage":"Ata","channels":[],
               "signature_policy":"ManualAttested","rule_pack_id":"assoc-cc/v1","locale":"pt-PT",
               "blocks":[{{"kind":"Paragraph","template":"{filler}"}}]}}"#
        );
        let err = validate_user_template(&json).unwrap_err();
        assert_eq!(err.code(), "too_large");
        assert!(matches!(err, TemplateValidationError::TooLarge { .. }));
    }

    #[test]
    fn unknown_field_is_malformed() {
        let json = r#"{"id":"user-x/v1","family":"Association","stage":"Ata","channels":[],
            "signature_policy":"ManualAttested","rule_pack_id":"assoc-cc/v1","locale":"pt-PT",
            "surprise":true,"blocks":[{"kind":"Paragraph","template":"Olá."}]}"#;
        let err = validate_user_template(json).unwrap_err();
        assert_eq!(err.code(), "malformed");
        assert!(matches!(err, TemplateValidationError::Malformed { .. }));
    }

    #[test]
    fn non_user_namespace_id_is_invalid() {
        // Well-formed but tries to shadow a built-in id (no `user-` prefix).
        let json = r#"{"id":"csc-ata-ag/v1","family":"CommercialCompany","stage":"Ata",
            "channels":["Physical"],"signature_policy":"QualifiedPreferred","rule_pack_id":"csc-art63/v2",
            "locale":"pt-PT","blocks":[{"kind":"Paragraph","template":"Olá."}]}"#;
        let err = validate_user_template(json).unwrap_err();
        assert_eq!(err.code(), "invalid_id");
        assert_eq!(err.field().as_deref(), Some("id"));
    }

    #[test]
    fn bad_id_characters_are_invalid() {
        // Reserved prefix but the slug carries an uppercase letter and the version is malformed.
        let json = r#"{"id":"user-Encosto/v","family":"CommercialCompany","stage":"Ata",
            "channels":["Physical"],"signature_policy":"QualifiedPreferred","rule_pack_id":"csc-art63/v2",
            "locale":"pt-PT","blocks":[{"kind":"Paragraph","template":"Olá."}]}"#;
        let err = validate_user_template(json).unwrap_err();
        assert_eq!(err.code(), "invalid_id");
    }

    #[test]
    fn empty_blocks_is_no_blocks() {
        let json = r#"{"id":"user-x/v1","family":"Association","stage":"Ata","channels":[],
            "signature_policy":"ManualAttested","rule_pack_id":"assoc-cc/v1","locale":"pt-PT","blocks":[]}"#;
        let err = validate_user_template(json).unwrap_err();
        assert_eq!(err.code(), "no_blocks");
        assert_eq!(err.field().as_deref(), Some("blocks"));
    }

    #[test]
    fn bad_minijinja_syntax_is_bad_template() {
        // Unterminated `{{` expression → compile failure in block index 0.
        let json = r#"{"id":"user-x/v1","family":"Association","stage":"Ata","channels":[],
            "signature_policy":"ManualAttested","rule_pack_id":"assoc-cc/v1","locale":"pt-PT",
            "blocks":[{"kind":"Paragraph","template":"Olá {{ quebrado"}]}"#;
        let err = validate_user_template(json).unwrap_err();
        assert_eq!(err.code(), "bad_template");
        assert!(matches!(
            err,
            TemplateValidationError::BadTemplate { block_index: 0, .. }
        ));
        assert_eq!(err.field().as_deref(), Some("blocks[0]"));
    }

    #[test]
    fn unknown_threshold_reference_is_rejected() {
        let json = r#"{"id":"user-x/v1","family":"Association","stage":"Ata","channels":[],
            "signature_policy":"ManualAttested","rule_pack_id":"assoc-cc/v1","locale":"pt-PT",
            "blocks":[{"kind":"Paragraph","template":"Maioria: {{ threshold(\"nao.existe\") }}."}]}"#;
        let err = validate_user_template(json).unwrap_err();
        assert_eq!(err.code(), "unknown_threshold");
        assert!(matches!(
            err,
            TemplateValidationError::UnknownThreshold { id } if id == "nao.existe"
        ));
    }

    #[test]
    fn unsupported_locale_is_rejected() {
        let json = r#"{"id":"user-x/v1","family":"Association","stage":"Ata","channels":[],
            "signature_policy":"ManualAttested","rule_pack_id":"assoc-cc/v1","locale":"en-US",
            "blocks":[{"kind":"Paragraph","template":"Hello."}]}"#;
        let err = validate_user_template(json).unwrap_err();
        assert_eq!(err.code(), "unsupported_locale");
        assert_eq!(err.field().as_deref(), Some("locale"));
        assert!(matches!(
            err,
            TemplateValidationError::UnsupportedLocale { locale } if locale == "en-US"
        ));
    }
}
