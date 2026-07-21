//! # Rendering an operator-authored ata body: placeholders, then markdown (t74 §4, §5)
//!
//! [`markdown::compile_markdown`](crate::markdown) turns markdown into the frozen [`Block`] set.
//! This module is the layer *above* it: an ata body may also carry minijinja placeholders
//! (`{{ entity.name }}`, `{% if … %}`), and something has to decide what happens when a
//! placeholder's **value** contains markdown punctuation.
//!
//! ## The order is fixed: minijinja first, then markdown
//!
//! `{% if %}` blocks must resolve before block structure is determined — a conditional that
//! disappears changes paragraph boundaries, so markdown cannot run first. The cost of that ordering
//! is the whole reason this module exists:
//!
//! ```text
//! source ──[minijinja render]──► rendered text ──[compile_markdown]──► Vec<Block>
//!               ^^^^^^^^^^^^^^
//!        values land here, BEFORE the parser sees them
//! ```
//!
//! ## Structure must never come from data
//!
//! An entity named `# Encosto` interpolated at the start of a line would otherwise become an actual
//! **heading** in a sealed document. The document's structure would then be partly authored by
//! whoever chose the company name, not by the operator who approved the text. So every interpolated
//! value is markdown-escaped at the moment it is written, by a custom minijinja *formatter*
//! ([`render_markdown_body`]).
//!
//! Escaping at interpolation time is the only correct place for it. Escaping the *context* before
//! rendering would miss values produced by filters (`{{ d | long_date }}`) and by
//! `threshold("…")` — exactly the values most likely to carry unexpected punctuation. Escaping the
//! *rendered output* would escape the operator's own markdown, defeating the feature.
//!
//! **`|safe` does not bypass this.** The formatter escapes unconditionally, including values marked
//! safe, because "safe" in minijinja means *safe HTML*, which is a different question from *may
//! this value invent document structure*. There is deliberately no escape hatch: a body that needs
//! a heading spells the heading out in the source, where the operator can see it.
//!
//! ## Two entry points, one compiler
//!
//! - [`check_markdown_body`] — the **save-time** gate. Syntax-checks the placeholders without
//!   evaluating them and structurally checks the markdown, so a malformed `{{` or an unsupported
//!   construct is a 422 while the operator is still editing, not a surprise at the seal gate.
//! - [`render_markdown_body`] — the **freeze-time and preview** path. The editor's preview and the
//!   seal call the same function, so what the operator previews is what gets sealed.

use serde_json::Value;

use chancela_core::Block;

use crate::markdown::{self, MarkdownError};

/// Why an ata body was rejected.
///
/// Split from [`MarkdownError`] because the two failures have different audiences: a placeholder
/// mistake points at minijinja syntax the operator typed, a markdown mistake points at a construct
/// the block set cannot represent. Both carry a stable `code` for the API's `{code, offset?}` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyRenderError {
    /// The placeholder syntax does not compile, or evaluating it failed (an unknown
    /// `threshold("…")` id, a filter applied to the wrong type). Never a silent blank.
    Template {
        /// minijinja's message, already formatted with its source context.
        message: String,
        /// Byte offset into the source of the offending expression, when minijinja reports one.
        offset: Option<usize>,
    },
    /// The markdown itself is not representable in the frozen [`Block`] set.
    Markdown(MarkdownError),
}

impl BodyRenderError {
    /// A stable, machine-readable code for the API `{code, …}` body.
    pub fn code(&self) -> &'static str {
        match self {
            BodyRenderError::Template { .. } => "invalid_placeholder",
            BodyRenderError::Markdown(e) => e.code(),
        }
    }

    /// Byte offset into the source of the offending construct, when one applies.
    pub fn offset(&self) -> Option<usize> {
        match self {
            BodyRenderError::Template { offset, .. } => *offset,
            BodyRenderError::Markdown(e) => e.offset(),
        }
    }
}

impl std::fmt::Display for BodyRenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyRenderError::Template { message, .. } => write!(f, "invalid placeholder: {message}"),
            BodyRenderError::Markdown(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BodyRenderError {}

impl From<MarkdownError> for BodyRenderError {
    fn from(e: MarkdownError) -> Self {
        BodyRenderError::Markdown(e)
    }
}

/// Turn a minijinja error into [`BodyRenderError::Template`], keeping the byte offset when the
/// error carries a source span so the editor can underline the expression in place.
fn template_error(e: &minijinja::Error) -> BodyRenderError {
    BodyRenderError::Template {
        message: format!("{e:#}"),
        offset: e.range().map(|r: std::ops::Range<usize>| r.start),
    }
}

/// Escape `value` so that it can be interpolated into a markdown body as **literal text** and can
/// never contribute document structure (t74 §4).
///
/// This is the single markdown escaper in the workspace. It is used in two directions and both need
/// exactly this guarantee:
///
/// - interpolating a record value into an ata body before the parser runs ([`render_markdown_body`]);
/// - emitting a structured `Block` back out as a markdown working copy
///   (`chancela_api::documents::working_copy_markdown`).
///
/// Deliberately not two functions: they would drift, and the one at the security boundary is the
/// one that would be missed.
///
/// ## Why some characters are escaped everywhere and others only at the start of a line
///
/// `*`, `_`, `` ` ``, `[`, `]`, `<`, `|`, `#` and `\` can begin inline markup (or, for `<`, raw
/// HTML) anywhere they appear, so they are escaped unconditionally. `-`, `+`, `>`, `=` and an
/// ordered-list marker (`1.` / `1)`) are only meaningful as *block* markers, which CommonMark only
/// recognises at the start of a line. Escaping those unconditionally would turn every ordinary date
/// into `2026\-07\-19` in the working copy for no gain; escaping them at line start closes the
/// injection without the noise.
///
/// `=` is included for the same reason as `-`: a line of `===` under a paragraph is a setext
/// heading, so an unescaped value on its own line could promote the line above it into a heading.
///
/// Leading spaces and tabs do not clear "start of line" — CommonMark allows up to three spaces of
/// indent before a block marker, so `  - x` is still a list.
pub fn escape_markdown_text(value: &str) -> String {
    // Escaping only ever grows the string; most values need few escapes.
    let mut out = String::with_capacity(value.len() + value.len() / 8);
    let mut at_line_start = true;
    let mut chars = value.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\n' => {
                out.push('\n');
                at_line_start = true;
                continue;
            }
            // Indent does not end the block-marker position.
            ' ' | '\t' => {
                out.push(ch);
                continue;
            }
            '\\' => out.push_str("\\\\"),
            '`' => out.push_str("\\`"),
            '*' => out.push_str("\\*"),
            '_' => out.push_str("\\_"),
            '[' => out.push_str("\\["),
            ']' => out.push_str("\\]"),
            '#' => out.push_str("\\#"),
            '<' => out.push_str("\\<"),
            '|' => out.push_str("\\|"),
            // Block markers: only meaningful in leading position.
            '-' | '+' | '>' | '=' if at_line_start => {
                out.push('\\');
                out.push(ch);
            }
            // An ordered-list marker is one or more digits followed by `.` or `)`. Escape the
            // delimiter, not the digits, so `2026` stays `2026` but `1.` becomes `1\.`.
            '0'..='9' if at_line_start => {
                out.push(ch);
                while let Some(d) = chars.peek().copied().filter(char::is_ascii_digit) {
                    out.push(d);
                    chars.next();
                }
                if matches!(chars.peek(), Some('.' | ')')) {
                    let delimiter = chars.next().expect("peeked");
                    out.push('\\');
                    out.push(delimiter);
                }
            }
            _ => out.push(ch),
        }
        at_line_start = false;
    }

    out
}

/// The save-time gate for an ata body (t74 §5).
///
/// Checks, in order: the byte cap, that the placeholders *compile* (without evaluating them, so no
/// record context is needed and no `threshold("…")` is resolved), and that the markdown structure is
/// representable.
///
/// Checking the **unrendered** source for markdown structure is sound precisely because
/// [`render_markdown_body`] escapes every interpolated value: no value can add or remove a block, so
/// the structure of the rendered text is exactly the structure of the source. `{% if %}` branches
/// are the one asymmetry, and in the conservative direction — this validates the union of all
/// branches, so anything that passes here passes at freeze whichever way the conditionals fall.
pub fn check_markdown_body(src: &str) -> Result<(), BodyRenderError> {
    if src.len() > markdown::MAX_BODY_BYTES {
        return Err(MarkdownError::TooLarge {
            limit: markdown::MAX_BODY_BYTES,
            actual: src.len(),
        }
        .into());
    }
    crate::compile_template_str(src).map_err(|message| BodyRenderError::Template {
        message,
        offset: None,
    })?;
    markdown::compile_markdown(src)?;
    Ok(())
}

/// Render an ata body's placeholders against `ctx` and compile the result into the frozen
/// [`Block`] set.
///
/// **This is the single function that produces an ata body's blocks.** The seal calls it at content
/// freeze and the editor's preview endpoint calls it on every keystroke-debounce, so the operator
/// previews exactly the blocks that will be sealed. Two callers, one compiler, no second
/// implementation to drift — and nothing markdown-shaped is ever compiled by a client.
///
/// Every interpolated value is markdown-escaped as it is written (see the module docs). Undefined
/// values keep minijinja's default *Lenient* behaviour — they render as the empty string, which is
/// load-bearing existing behaviour for the catalog templates and is not changed here.
pub fn render_markdown_body(src: &str, ctx: &Value) -> Result<Vec<Block>, BodyRenderError> {
    if src.len() > markdown::MAX_BODY_BYTES {
        return Err(MarkdownError::TooLarge {
            limit: markdown::MAX_BODY_BYTES,
            actual: src.len(),
        }
        .into());
    }

    let mut env = crate::build_env();
    // The whole mitigation, in one hook: every `{{ … }}` write is escaped, whatever produced it —
    // a context field, a filter, or `threshold()`. Values marked `|safe` are escaped too; see the
    // module docs for why there is no opt-out.
    env.set_formatter(|out, _state, value| {
        // `Display` for an undefined value is the empty string, which preserves Lenient semantics.
        let rendered = value.to_string();
        out.write_str(&escape_markdown_text(&rendered))
            .map_err(|e| minijinja::Error::new(minijinja::ErrorKind::WriteFailure, e.to_string()))
    });

    let template = env
        .template_from_str(src)
        .map_err(|e| template_error(&e))?;
    let rendered = template.render(ctx).map_err(|e| template_error(&e))?;

    // The cap is applied again to the *rendered* text: placeholders expand, so a body that fit
    // before interpolation need not fit after it.
    Ok(markdown::compile_markdown(&rendered)?)
}

/// The canonical JSON serialization of compiled blocks — the exact bytes whose SHA-256 becomes
/// `ActBody::compiled_digest`.
///
/// Mirrors [`crate::canonical_spec_json`]: this crate defines *which bytes are hashed* and the API
/// takes the digest, so the crate stays free of a hashing dependency and there is exactly one
/// definition of the preimage.
pub fn canonical_blocks_json(blocks: &[Block]) -> Result<String, serde_json::Error> {
    serde_json::to_string(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body(src: &str, ctx: &Value) -> Vec<Block> {
        render_markdown_body(src, ctx).expect("body should render")
    }

    // --- the security-critical property: structure never comes from data ---------------------

    #[test]
    fn a_company_name_containing_markdown_structure_stays_literal_text() {
        // The named hazard from t74 §4: `#` would be a heading and `**` bold, both authored by
        // whoever chose the company name rather than by the operator who approved the text.
        let ctx = json!({ "entity": { "name": "# Encosto **Estratégico** Lda" } });
        let blocks = body("{{ entity.name }}", &ctx);

        // One paragraph, not a heading: the `#` did not become structure.
        assert_eq!(blocks.len(), 1, "expected exactly one block: {blocks:?}");
        let Block::Paragraph { runs } = &blocks[0] else {
            panic!("value with a leading `#` produced {:?}, not a paragraph", blocks[0]);
        };
        // A single unstyled run: the `**` did not become emphasis.
        assert_eq!(runs.len(), 1, "expected one unstyled run, got {runs:?}");
        assert!(!runs[0].bold, "`**` in a value must not produce bold");
        assert!(!runs[0].italic, "`**` in a value must not produce italic");
        // And the text is the name exactly as it was given, punctuation intact.
        assert_eq!(runs[0].text, "# Encosto **Estratégico** Lda");
    }

    #[test]
    fn the_operators_own_markdown_still_works_alongside_an_escaped_value() {
        // The other half of the property: escaping must not disarm the feature. The heading and the
        // bold here are in the *source*, where the operator wrote and approved them.
        let ctx = json!({ "entity": { "name": "**Encosto** Lda" } });
        let blocks = body("# Ata\n\nPresente: **{{ entity.name }}**.", &ctx);

        assert!(
            matches!(&blocks[0], Block::Heading { level: 1, text } if text == "Ata"),
            "the source's own heading must survive: {:?}",
            blocks[0]
        );
        let Block::Paragraph { runs } = &blocks[1] else {
            panic!("expected a paragraph, got {:?}", blocks[1]);
        };
        // The operator's `**` around the placeholder is real emphasis...
        let bolded: String = runs.iter().filter(|r| r.bold).map(|r| r.text.as_str()).collect();
        // ...and the value's own `**` is inside it as literal characters.
        assert_eq!(bolded, "**Encosto** Lda");
    }

    #[test]
    fn a_value_cannot_inject_a_list_a_quote_or_a_rule() {
        // These are *rejected* constructs, so an unescaped value would not merely restructure the
        // document — it would make the act unsealable. Each must survive as literal text.
        for injected in ["- item", "> quote", "1. item", "--- ", "=== ", "+ item"] {
            let ctx = json!({ "v": injected });
            let blocks = render_markdown_body("{{ v }}", &ctx)
                .unwrap_or_else(|e| panic!("value {injected:?} must not be structure, got {e}"));
            assert_eq!(blocks.len(), 1, "value {injected:?} produced {blocks:?}");
            let Block::Paragraph { runs } = &blocks[0] else {
                panic!("value {injected:?} produced {:?}, not a paragraph", blocks[0]);
            };
            assert_eq!(runs[0].text.trim(), injected.trim());
        }
    }

    #[test]
    fn a_value_cannot_inject_raw_html_or_a_link() {
        // `<` and `[` are escaped unconditionally, so neither reaches the parser as markup. Raw HTML
        // and links are rejected constructs, so failing to escape would be a hard error, not a
        // silent injection — but the operator would see a 422 they could not explain.
        let ctx = json!({ "v": "<script>alert(1)</script> [link](https://example.test)" });
        let blocks = body("{{ v }}", &ctx);
        let Block::Paragraph { runs } = &blocks[0] else {
            panic!("expected a paragraph, got {:?}", blocks[0]);
        };
        assert_eq!(
            runs[0].text,
            "<script>alert(1)</script> [link](https://example.test)"
        );
    }

    #[test]
    fn a_value_marked_safe_is_still_escaped() {
        // `|safe` means "safe HTML", which is a different question from "may this invent document
        // structure". There is no opt-out by design.
        let ctx = json!({ "v": "# not a heading" });
        let blocks = body("{{ v | safe }}", &ctx);
        assert!(
            matches!(&blocks[0], Block::Paragraph { .. }),
            "`|safe` must not bypass markdown escaping: {:?}",
            blocks[0]
        );
    }

    #[test]
    fn filter_output_is_escaped_too() {
        // The reason escaping is a formatter hook rather than a pre-pass over the context: a
        // pre-pass never sees what a filter produced.
        let ctx = json!({ "v": "# x" });
        let blocks = body("{{ v | upper }}", &ctx);
        let Block::Paragraph { runs } = &blocks[0] else {
            panic!("filter output was not escaped: {:?}", blocks[0]);
        };
        assert_eq!(runs[0].text, "# X");
    }

    // --- escaper unit properties ---------------------------------------------------------------

    #[test]
    fn ordinary_text_is_left_alone() {
        // The counterweight to the tests above: over-escaping would make every working copy
        // unreadable. A date must not become `2026\-07\-19`.
        assert_eq!(escape_markdown_text("2026-07-19"), "2026-07-19");
        assert_eq!(escape_markdown_text("Encosto Estratégico Lda"), "Encosto Estratégico Lda");
        assert_eq!(escape_markdown_text("a - b"), "a - b");
    }

    #[test]
    fn block_markers_are_escaped_only_in_leading_position() {
        assert_eq!(escape_markdown_text("- item"), "\\- item");
        assert_eq!(escape_markdown_text("  - indented"), "  \\- indented");
        assert_eq!(escape_markdown_text("1. item"), "1\\. item");
        assert_eq!(escape_markdown_text("a\n- item"), "a\n\\- item");
        // ...but the same characters mid-line are ordinary punctuation.
        assert_eq!(escape_markdown_text("x 1. y"), "x 1. y");
    }

    #[test]
    fn inline_markup_is_escaped_everywhere() {
        assert_eq!(escape_markdown_text("a *b* c"), "a \\*b\\* c");
        assert_eq!(escape_markdown_text("a | b"), "a \\| b");
        // `<` is escaped everywhere (it can open raw HTML inline); the closing `>` needs no escape
        // mid-line, because `>` is only a block-quote marker in leading position.
        assert_eq!(escape_markdown_text("a <b> c"), "a \\<b> c");
        // The backslash must be escaped first, or the escapes themselves become injectable.
        assert_eq!(escape_markdown_text("a\\*b"), "a\\\\\\*b");
    }

    #[test]
    fn escaping_is_idempotent_in_effect() {
        // Escaping twice must not corrupt the text — it round-trips through the parser to the same
        // literal either way. This is what makes it safe that `escape_markdown_table_cell` composes
        // on top of this function.
        let once = escape_markdown_text("# a *b* - c");
        let blocks = markdown::compile_markdown(&once).expect("escaped text must compile");
        let Block::Paragraph { runs } = &blocks[0] else {
            panic!("expected a paragraph");
        };
        assert_eq!(runs[0].text, "# a *b* - c");
    }

    // --- the save-time gate --------------------------------------------------------------------

    #[test]
    fn a_malformed_placeholder_is_rejected_at_save_time() {
        let err = check_markdown_body("Ata n.º {{ unclosed").expect_err("must reject");
        assert_eq!(err.code(), "invalid_placeholder");
    }

    #[test]
    fn an_unsupported_construct_is_rejected_at_save_time() {
        let err = check_markdown_body("- a list").expect_err("must reject");
        assert_eq!(err.code(), "unsupported_markdown");
        assert!(err.offset().is_some(), "the editor needs an offset to underline");
    }

    #[test]
    fn a_body_over_the_byte_cap_is_rejected_at_save_time() {
        let src = "a".repeat(markdown::MAX_BODY_BYTES + 1);
        let err = check_markdown_body(&src).expect_err("must reject");
        assert_eq!(err.code(), "body_too_large");
    }

    #[test]
    fn placeholders_do_not_confuse_the_save_time_structure_check() {
        // The source is checked unrendered, so `{{ … }}` and `{% … %}` must read as ordinary text
        // to the markdown parser rather than as constructs to reject.
        check_markdown_body("# Ata {{ ata_number }}\n\n{% if x %}Presente.{% endif %}")
            .expect("placeholders must not trip the structure check");
    }

    #[test]
    fn what_passes_save_time_still_renders_at_freeze() {
        // The contract between the two entry points: the save-time gate must not admit a body that
        // fails at the seal, because that is precisely the surprise it exists to prevent.
        let src = "# Ata {{ n }}\n\nPresente: **{{ who }}**.";
        check_markdown_body(src).expect("save-time gate");
        let blocks = render_markdown_body(src, &json!({ "n": "1/2026", "who": "# * Lda" }))
            .expect("freeze-time render");
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn an_undefined_placeholder_renders_empty_rather_than_failing() {
        // Lenient undefined is load-bearing existing behaviour for the catalog and is not changed.
        let blocks = body("Presente: {{ missing }}.", &json!({}));
        let Block::Paragraph { runs } = &blocks[0] else {
            panic!("expected a paragraph");
        };
        assert_eq!(runs[0].text, "Presente: .");
    }

    #[test]
    fn rendering_is_deterministic() {
        let ctx = json!({ "entity": { "name": "# Encosto **Lda**" } });
        let src = "# Ata\n\n{{ entity.name }}";
        assert_eq!(body(src, &ctx), body(src, &ctx));
    }

    #[test]
    fn compiled_blocks_serialize_canonically_and_stably() {
        let blocks = body("# Ata\n\nTexto.", &json!({}));
        let once = canonical_blocks_json(&blocks).expect("serialize");
        let twice = canonical_blocks_json(&blocks).expect("serialize");
        assert_eq!(once, twice, "the digest preimage must be stable");
    }
}
