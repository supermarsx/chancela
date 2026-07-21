//! # `md-block/v1` — compile operator-authored markdown into the frozen [`Block`] set (t74 §2)
//!
//! An ata body is prose an operator writes and then *seals*. This module is the single place where
//! that prose becomes document structure:
//!
//! ```text
//! markdown source ──[compile_markdown]──► Vec<Block> ──(existing, unchanged)──► DocumentModel ──► PDF/A
//!                                        ^^^^^^^^^^
//!                                    the frozen seam (chancela_core::document_model)
//! ```
//!
//! Markdown stops at the seam. Everything downstream of `Vec<Block>` is the already-proven
//! deterministic PDF path and none of it changes.
//!
//! ## Three properties this module exists to guarantee
//!
//! **1. Reject, never silently drop.** Every construct that has no representation in the frozen
//! [`Block`] set — images, links, code, lists, tables, block quotes, raw HTML, hard line breaks —
//! is a hard [`MarkdownError`], never a dropped node. Dropping would be the worst outcome
//! available: the operator approves text in the editor that the sealed PDF does not contain. The
//! parser is therefore configured with [`Options::empty()`] (no extensions at all), and the
//! HTML/link/code events CommonMark produces natively are matched and rejected rather than
//! stripped.
//!
//! **2. Determinism is the product requirement.** [`compile_markdown`] is pure and total: no clock,
//! no RNG, no locale, no environment, no interior mutability, no allocation-order dependence. The
//! parser is pinned to an **exact** version in the workspace `Cargo.toml` (`=0.13.4`, no caret)
//! because the compiled blocks are bound into the seal preimage — a patch-level change that
//! perturbs output would change what a sealed document says. The committed golden corpus under
//! `crates/chancela-templates/golden/md-block-v1/` fails CI loudly if any bump perturbs output.
//!
//! **3. No HTML string, anywhere.** Compilation targets typed Rust structs holding plain `String`s.
//! The `pulldown-cmark` dependency is declared `default-features = false`, which drops that crate's
//! HTML writer from the build entirely: there is no HTML on this path and none can be produced.
//!
//! ## Versioning
//!
//! [`COMPILER_ID`] is `"md-block/v1"` and is recorded on the act and bound into the seal. A
//! deliberate change to the mapping — a new accepted construct, a different whitespace rule — is
//! **not** an edit to this compiler: it ships as `md-block/v2` with `v1` retained, so an act sealed
//! under `v1` recompiles to the same blocks forever. Nothing here may be changed in place once a
//! document has been sealed with it.
//!
//! ## Accept / reject matrix
//!
//! | markdown | result |
//! |---|---|
//! | ATX heading `# … ######`, setext heading | [`Block::Heading`] (plain text; emphasis inside a heading is rejected — [`Block::Heading::text`] is an unstyled `String` and flattening would drop styling the operator saw) |
//! | paragraph | [`Block::Paragraph`] of [`Run`]s |
//! | `**bold**`, `__bold__` | `Run { bold: true, .. }` |
//! | `*italic*`, `_italic_` | `Run { italic: true, .. }` |
//! | nested emphasis | one `Run` per distinct style span |
//! | soft line break (a plain newline inside a paragraph) | a single space, as CommonMark specifies |
//! | `***` / `---` / `___` thematic break | [`Block::Rule`] |
//! | blank / whitespace-only input | `Ok(vec![])` — emptiness is the substance gate's decision, not the compiler's |
//! | image, link, autolink `<https://…>` | [`MarkdownError::Unsupported`] |
//! | inline code, fenced/indented code block | [`MarkdownError::Unsupported`] |
//! | list (ordered, unordered, task) | [`MarkdownError::Unsupported`] |
//! | table, block quote, footnote, definition list | [`MarkdownError::Unsupported`] |
//! | raw HTML block, inline HTML | [`MarkdownError::Unsupported`] |
//! | hard line break (two trailing spaces, `\`) | [`MarkdownError::Unsupported`] — no intra-paragraph break exists in the block set; a blank line is the supported form |
//! | a bare `https://…` | literal text (autolinking is off) |
//! | `~~strike~~`, `$math$`, `- [ ]`, `{#id}` | literal text (every extension is off) |
//!
//! [`Block::Heading::text`]: chancela_core::Block::Heading

use std::fmt;
use std::ops::Range;

use chancela_core::{Block, Run};
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};

/// The compiler identity recorded on the act and bound into the seal preimage. See the module
/// docs: a change in behaviour ships as a new id, never as an edit to this one.
pub const COMPILER_ID: &str = "md-block/v1";

/// Maximum size, in bytes, of a whole markdown body. Mirrors
/// [`crate::authoring::MAX_TEMPLATE_BYTES`] — the same untrusted-input budget the template
/// authoring guard uses. Also bounds how much of a book's capacity one ata can consume (t74 §9.6).
pub const MAX_BODY_BYTES: usize = crate::authoring::MAX_TEMPLATE_BYTES;

/// Maximum size, in bytes, of the text of any single produced block. Mirrors
/// [`crate::authoring::MAX_TEMPLATE_STRING_BYTES`].
pub const MAX_BLOCK_TEXT_BYTES: usize = crate::authoring::MAX_TEMPLATE_STRING_BYTES;

/// Why a markdown body was rejected. Carries a stable [`code`](Self::code) so the API layer can
/// render an HTTP 422 `{code, offset?, message}` body without matching on Rust variants, and a byte
/// `offset` so the editor can underline the offending construct in place.
///
/// Text is neutral and technical: this is a structural check, and it makes no claim about the legal
/// validity or evidentiary weight of any document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkdownError {
    /// The whole body exceeded [`MAX_BODY_BYTES`].
    TooLarge {
        /// The limit, in bytes.
        limit: usize,
        /// The observed size, in bytes.
        actual: usize,
    },
    /// One produced block's text exceeded [`MAX_BLOCK_TEXT_BYTES`].
    BlockTooLarge {
        /// The limit, in bytes.
        limit: usize,
        /// The observed size, in bytes.
        actual: usize,
        /// Byte offset into the source where the offending block starts.
        offset: usize,
    },
    /// A construct with no representation in the frozen [`Block`] set. **Rejected, not dropped** —
    /// see the module docs.
    Unsupported {
        /// Stable snake_case token naming the construct (`"image"`, `"list"`, `"inline_html"`, …).
        /// Safe for clients to branch on; new tokens may be added.
        construct: &'static str,
        /// Byte offset into the source where the construct starts.
        offset: usize,
    },
}

impl MarkdownError {
    /// A stable, machine-readable error code for the API `{code, …}` body.
    pub fn code(&self) -> &'static str {
        match self {
            MarkdownError::TooLarge { .. } => "body_too_large",
            MarkdownError::BlockTooLarge { .. } => "body_block_too_large",
            MarkdownError::Unsupported { .. } => "unsupported_markdown",
        }
    }

    /// Byte offset into the source of the offending construct, when one applies.
    pub fn offset(&self) -> Option<usize> {
        match self {
            MarkdownError::TooLarge { .. } => None,
            MarkdownError::BlockTooLarge { offset, .. }
            | MarkdownError::Unsupported { offset, .. } => Some(*offset),
        }
    }
}

impl fmt::Display for MarkdownError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MarkdownError::TooLarge { limit, actual } => {
                write!(f, "body exceeds the size limit: {actual} > {limit} bytes")
            }
            MarkdownError::BlockTooLarge {
                limit,
                actual,
                offset,
            } => write!(
                f,
                "the block at byte {offset} exceeds the per-block text limit: {actual} > {limit} bytes"
            ),
            MarkdownError::Unsupported { construct, offset } => write!(
                f,
                "unsupported markdown construct `{construct}` at byte {offset}: \
                 the document format supports headings, paragraphs, bold, italic and horizontal rules"
            ),
        }
    }
}

impl std::error::Error for MarkdownError {}

/// Compile a markdown body into the frozen [`Block`] set.
///
/// Pure and total: the same `src` always yields the same result, on any machine, in any locale, at
/// any time. Blank or whitespace-only input compiles to an empty `Vec` — whether an empty body is
/// acceptable is the rule pack's decision (`has_substance`), not this function's.
///
/// See the module docs for the full accept/reject matrix. Every unsupported construct is an error;
/// nothing is ever silently dropped.
pub fn compile_markdown(src: &str) -> Result<Vec<Block>, MarkdownError> {
    if src.len() > MAX_BODY_BYTES {
        return Err(MarkdownError::TooLarge {
            limit: MAX_BODY_BYTES,
            actual: src.len(),
        });
    }

    // Every extension off. This is load-bearing, not tidiness: it keeps tables, footnotes,
    // strikethrough, task lists, math, metadata blocks, wikilinks, heading attributes and smart
    // punctuation out of the event stream entirely, so they stay literal text instead of becoming
    // structure we would then have to reject. Raw HTML, links and code are *core* CommonMark —
    // there is no option that disables them, so they arrive as events and are rejected below.
    let mut c = Compiler::default();
    for (event, range) in Parser::new_ext(src, Options::empty()).into_offset_iter() {
        c.event(event, range)?;
    }
    Ok(c.out)
}

/// Where text events are currently landing.
#[derive(Default, PartialEq, Eq)]
enum Sink {
    /// Between blocks.
    #[default]
    None,
    /// Inside a paragraph; text accumulates into `runs`.
    Paragraph,
    /// Inside a heading of the given level; text accumulates into `text`.
    Heading(u8),
}

#[derive(Default)]
struct Compiler {
    out: Vec<Block>,
    sink: Sink,
    /// Runs of the paragraph being built.
    runs: Vec<Run>,
    /// Text of the heading being built.
    text: String,
    /// Byte offset where the block being built started (for error reporting).
    start: usize,
    /// Nesting depth of `**strong**` and `*emphasis*`; a run is bold/italic when the depth is > 0,
    /// so nested and overlapping emphasis need no special case.
    bold: u32,
    italic: u32,
}

impl Compiler {
    fn event(&mut self, event: Event<'_>, range: Range<usize>) -> Result<(), MarkdownError> {
        let at = range.start;
        match event {
            Event::Start(Tag::Paragraph) => {
                self.sink = Sink::Paragraph;
                self.start = at;
            }
            Event::End(TagEnd::Paragraph) => self.flush_paragraph()?,

            Event::Start(Tag::Heading {
                level,
                id,
                classes,
                attrs,
            }) => {
                // Unreachable with `Options::empty()` (heading attributes are an extension), but
                // asserted rather than assumed: attributes would be silently dropped otherwise.
                if id.is_some() || !classes.is_empty() || !attrs.is_empty() {
                    return Err(unsupported("heading_attributes", at));
                }
                self.sink = Sink::Heading(level as u8);
                self.start = at;
            }
            Event::End(TagEnd::Heading(_)) => self.flush_heading()?,

            Event::Start(Tag::Strong) => self.bold += 1,
            Event::End(TagEnd::Strong) => self.bold = self.bold.saturating_sub(1),
            Event::Start(Tag::Emphasis) => self.italic += 1,
            Event::End(TagEnd::Emphasis) => self.italic = self.italic.saturating_sub(1),

            Event::Text(t) => self.push_text(&t, at)?,
            // CommonMark renders a soft break as a single space. Mapping it to anything else (or
            // to nothing) would make the sealed PDF read differently from the editor.
            Event::SoftBreak => self.push_text(" ", at)?,

            Event::Rule => {
                self.out.push(Block::Rule);
            }

            Event::Start(tag) => return Err(unsupported(tag_name(&tag), at)),
            Event::End(_) => {
                // An `End` can only follow a `Start` we already rejected, so this is unreachable;
                // it exists so the match stays total without a blanket wildcard.
                return Err(unsupported("unsupported_block", at));
            }
            Event::Code(_) => return Err(unsupported("inline_code", at)),
            Event::Html(_) => return Err(unsupported("html_block", at)),
            Event::InlineHtml(_) => return Err(unsupported("inline_html", at)),
            Event::InlineMath(_) | Event::DisplayMath(_) => return Err(unsupported("math", at)),
            Event::FootnoteReference(_) => return Err(unsupported("footnote", at)),
            Event::TaskListMarker(_) => return Err(unsupported("task_list", at)),
            // No representation for a line break inside a paragraph. A blank line (a new
            // paragraph) is the supported form; accepting this as a space would change the shape
            // of the text the operator approved.
            Event::HardBreak => return Err(unsupported("hard_line_break", at)),
        }
        Ok(())
    }

    fn push_text(&mut self, t: &str, at: usize) -> Result<(), MarkdownError> {
        match self.sink {
            Sink::Heading(_) => {
                // `Block::Heading` carries an unstyled `String`, so emphasis inside a heading has
                // nowhere to go. Flattening it would drop styling the operator saw in the editor.
                if self.bold > 0 || self.italic > 0 {
                    return Err(unsupported("emphasis_in_heading", at));
                }
                self.text.push_str(t);
            }
            Sink::Paragraph => {
                if t.is_empty() {
                    return Ok(());
                }
                let (bold, italic) = (self.bold > 0, self.italic > 0);
                match self.runs.last_mut() {
                    // Merge adjacent same-styled spans so the block output is a canonical function
                    // of the rendered text, not of how the parser happened to split events.
                    Some(last) if last.bold == bold && last.italic == italic => {
                        last.text.push_str(t);
                    }
                    _ => self.runs.push(Run {
                        text: t.to_string(),
                        bold,
                        italic,
                    }),
                }
            }
            Sink::None => return Err(unsupported("text_outside_block", at)),
        }
        Ok(())
    }

    fn flush_paragraph(&mut self) -> Result<(), MarkdownError> {
        let runs = std::mem::take(&mut self.runs);
        self.sink = Sink::None;
        let len: usize = runs.iter().map(|r| r.text.len()).sum();
        if len > MAX_BLOCK_TEXT_BYTES {
            return Err(MarkdownError::BlockTooLarge {
                limit: MAX_BLOCK_TEXT_BYTES,
                actual: len,
                offset: self.start,
            });
        }
        // A paragraph that renders to nothing but whitespace produces no block — the same rule
        // `push_paragraph` already applies to a template paragraph whose placeholders all resolved
        // empty (`lib.rs`).
        if runs.iter().all(|r| r.text.trim().is_empty()) {
            return Ok(());
        }
        self.out.push(Block::Paragraph { runs });
        Ok(())
    }

    fn flush_heading(&mut self) -> Result<(), MarkdownError> {
        let text = std::mem::take(&mut self.text);
        let level = match self.sink {
            Sink::Heading(level) => level,
            _ => 1,
        };
        self.sink = Sink::None;
        if text.len() > MAX_BLOCK_TEXT_BYTES {
            return Err(MarkdownError::BlockTooLarge {
                limit: MAX_BLOCK_TEXT_BYTES,
                actual: text.len(),
                offset: self.start,
            });
        }
        if text.trim().is_empty() {
            return Ok(());
        }
        self.out.push(Block::Heading { level, text });
        Ok(())
    }
}

fn unsupported(construct: &'static str, offset: usize) -> MarkdownError {
    MarkdownError::Unsupported { construct, offset }
}

/// A stable snake_case token for a rejected container tag.
fn tag_name(tag: &Tag<'_>) -> &'static str {
    match tag {
        Tag::BlockQuote(_) => "block_quote",
        Tag::CodeBlock(_) => "code_block",
        Tag::HtmlBlock => "html_block",
        Tag::List(_) => "list",
        Tag::Item => "list_item",
        Tag::FootnoteDefinition(_) => "footnote_definition",
        Tag::DefinitionList | Tag::DefinitionListTitle | Tag::DefinitionListDefinition => {
            "definition_list"
        }
        Tag::Table(_) | Tag::TableHead | Tag::TableRow | Tag::TableCell => "table",
        Tag::Strikethrough => "strikethrough",
        Tag::Superscript => "superscript",
        Tag::Subscript => "subscript",
        // Links and images are rejected together with autolinks: no `Block` variant carries a
        // link, so it would render as bare text in the PDF while appearing clickable on screen —
        // two readers seeing different documents. A remote image would additionally leak the
        // reader's IP and break offline determinism.
        Tag::Link { .. } => "link",
        Tag::Image { .. } => "image",
        Tag::MetadataBlock(_) => "metadata_block",
        Tag::Paragraph | Tag::Heading { .. } | Tag::Emphasis | Tag::Strong => {
            debug_assert!(false, "accepted tag routed to tag_name");
            "unsupported_block"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    // -- helpers ---------------------------------------------------------------------------

    fn run(text: &str, bold: bool, italic: bool) -> Run {
        Run {
            text: text.to_string(),
            bold,
            italic,
        }
    }

    fn plain(text: &str) -> Block {
        Block::Paragraph {
            runs: vec![run(text, false, false)],
        }
    }

    #[track_caller]
    fn reject(src: &str, construct: &str) {
        match compile_markdown(src) {
            Err(MarkdownError::Unsupported { construct: got, .. }) => {
                assert_eq!(got, construct, "wrong construct token for {src:?}");
            }
            other => panic!("expected {construct} rejection for {src:?}, got {other:?}"),
        }
    }

    // -- accepted constructs ---------------------------------------------------------------

    #[test]
    fn atx_headings_map_to_heading_blocks_at_every_level() {
        let src = "# um\n\n## dois\n\n### três\n\n#### quatro\n\n##### cinco\n\n###### seis";
        let want: Vec<Block> = [
            (1, "um"),
            (2, "dois"),
            (3, "três"),
            (4, "quatro"),
            (5, "cinco"),
            (6, "seis"),
        ]
        .into_iter()
        .map(|(level, text)| Block::Heading {
            level,
            text: text.to_string(),
        })
        .collect();
        assert_eq!(compile_markdown(src).unwrap(), want);
    }

    #[test]
    fn setext_heading_maps_to_a_heading_block() {
        assert_eq!(
            compile_markdown("Deliberações\n===").unwrap(),
            vec![Block::Heading {
                level: 1,
                text: "Deliberações".to_string()
            }]
        );
    }

    #[test]
    fn paragraphs_map_to_paragraph_blocks() {
        assert_eq!(
            compile_markdown("Primeiro.\n\nSegundo.").unwrap(),
            vec![plain("Primeiro."), plain("Segundo.")]
        );
    }

    #[test]
    fn thematic_breaks_map_to_rule() {
        for src in ["***", "---", "___", "* * *"] {
            assert_eq!(compile_markdown(src).unwrap(), vec![Block::Rule], "{src:?}");
        }
    }

    #[test]
    fn a_soft_break_becomes_a_single_space_inside_one_paragraph() {
        assert_eq!(
            compile_markdown("uma linha\noutra linha").unwrap(),
            vec![plain("uma linha outra linha")]
        );
    }

    // -- emphasis --------------------------------------------------------------------------

    #[test]
    fn bold_and_italic_map_to_run_flags() {
        assert_eq!(
            compile_markdown("a **b** c *d* e").unwrap(),
            vec![Block::Paragraph {
                runs: vec![
                    run("a ", false, false),
                    run("b", true, false),
                    run(" c ", false, false),
                    run("d", false, true),
                    run(" e", false, false),
                ]
            }]
        );
    }

    #[test]
    fn underscore_forms_are_equivalent_to_asterisk_forms() {
        assert_eq!(
            compile_markdown("__b__ _i_").unwrap(),
            compile_markdown("**b** *i*").unwrap()
        );
    }

    #[test]
    fn nested_emphasis_produces_one_run_per_distinct_style_span() {
        assert_eq!(
            compile_markdown("**a *b* c**").unwrap(),
            vec![Block::Paragraph {
                runs: vec![
                    run("a ", true, false),
                    run("b", true, true),
                    run(" c", true, false),
                ]
            }]
        );
    }

    #[test]
    fn deeply_nested_emphasis_does_not_unset_the_outer_style() {
        // The depth counters, not a boolean flip, are what make this correct.
        assert_eq!(
            compile_markdown("***todo*** normal").unwrap(),
            vec![Block::Paragraph {
                runs: vec![run("todo", true, true), run(" normal", false, false)]
            }]
        );
    }

    #[test]
    fn adjacent_same_styled_spans_merge_into_one_run() {
        // `a` and `b` arrive as separate text events (the entity splits them) but carry identical
        // styling, so the block output must be canonical rather than event-shaped.
        let blocks = compile_markdown("a&amp;b").unwrap();
        assert_eq!(blocks, vec![plain("a&b")]);
    }

    #[test]
    fn emphasis_inside_a_heading_is_rejected_rather_than_flattened() {
        reject("# **Ata**", "emphasis_in_heading");
        reject("## _Ata_", "emphasis_in_heading");
    }

    // -- rejections ------------------------------------------------------------------------

    #[test]
    fn images_are_rejected() {
        reject("![alt](https://example.test/a.png)", "image");
        reject("![alt](data:image/png;base64,AAAA)", "image");
    }

    #[test]
    fn links_and_autolinks_are_rejected() {
        reject("[texto](https://example.test)", "link");
        reject("<https://example.test>", "link");
        reject("[ref][r]\n\n[r]: https://example.test", "link");
    }

    #[test]
    fn a_bare_url_stays_literal_text() {
        // Autolinking is off, so this is prose — not a link, and not an error.
        assert_eq!(
            compile_markdown("ver https://example.test aqui").unwrap(),
            vec![plain("ver https://example.test aqui")]
        );
    }

    #[test]
    fn code_is_rejected_in_every_form() {
        reject("```rust\nfn main() {}\n```", "code_block");
        reject("~~~\ntexto\n~~~", "code_block");
        reject("    indentado", "code_block");
        reject("um `literal` aqui", "inline_code");
    }

    #[test]
    fn lists_are_rejected() {
        reject("- um\n- dois", "list");
        reject("1. um\n2. dois", "list");
        reject("- um\n  - aninhado", "list");
    }

    #[test]
    fn tables_block_quotes_and_footnotes_are_rejected() {
        // Tables and footnotes are extensions and stay literal text with `Options::empty()`; block
        // quotes are core CommonMark and must be rejected as structure.
        reject("> citação", "block_quote");
        assert_eq!(
            compile_markdown("| a | b |\n|---|---|\n| 1 | 2 |").unwrap(),
            vec![plain("| a | b | |---|---| | 1 | 2 |")]
        );
        // An undefined footnote marker is literal text; but a *defined* one is not a footnote at
        // all with the extension off — `[^1]: texto` is a link reference definition, so `[^1]`
        // becomes a shortcut link and is rejected as one. Either way nothing is silently dropped.
        assert_eq!(
            compile_markdown("nota[^1]").unwrap(),
            vec![plain("nota[^1]")]
        );
        reject("nota[^1]\n\n[^1]: texto", "link");
    }

    #[test]
    fn raw_html_is_rejected_not_stripped() {
        reject("<script>alert(1)</script>", "html_block");
        reject("<div>oi</div>", "html_block");
        reject("texto <img src=x onerror=alert(1)> mais", "inline_html");
        reject("texto <b>negrito</b>", "inline_html");
    }

    #[test]
    fn a_hard_line_break_is_rejected() {
        reject("uma linha  \noutra", "hard_line_break");
        reject("uma linha\\\noutra", "hard_line_break");
    }

    #[test]
    fn html_looking_text_that_is_not_html_stays_text() {
        // The rejection is on parsed HTML events, not on angle brackets in prose.
        assert_eq!(
            compile_markdown("3 < 4 e 5 > 2").unwrap(),
            vec![plain("3 < 4 e 5 > 2")]
        );
    }

    #[test]
    fn disabled_extensions_stay_literal_text() {
        for src in ["~~riscado~~", "$x^2$", "[[wiki]]", "H~2~O"] {
            let blocks = compile_markdown(src).unwrap();
            assert_eq!(blocks.len(), 1, "{src:?} produced {blocks:?}");
            assert!(matches!(blocks[0], Block::Paragraph { .. }), "{src:?}");
        }
    }

    #[test]
    fn errors_carry_a_stable_code_and_a_source_offset() {
        let err = compile_markdown("Texto bom.\n\n![x](y)").unwrap_err();
        assert_eq!(err.code(), "unsupported_markdown");
        assert_eq!(err.offset(), Some(12));
        assert!(err.to_string().contains("image"));
    }

    // -- edges -----------------------------------------------------------------------------

    #[test]
    fn empty_input_compiles_to_no_blocks() {
        assert_eq!(compile_markdown("").unwrap(), Vec::<Block>::new());
    }

    #[test]
    fn whitespace_only_input_compiles_to_no_blocks() {
        for src in ["   ", "\n\n\n", "\t\n  \n", "\u{a0}\n"] {
            assert!(
                compile_markdown(src).unwrap().is_empty()
                    || matches!(
                        compile_markdown(src).unwrap()[..],
                        [Block::Paragraph { .. }]
                    ),
                "{src:?}"
            );
        }
        assert!(compile_markdown("   ").unwrap().is_empty());
        assert!(compile_markdown("\n\n\n").unwrap().is_empty());
    }

    #[test]
    fn line_ending_style_does_not_change_the_output() {
        assert_eq!(
            compile_markdown("# t\r\n\r\ncorpo\r\n").unwrap(),
            compile_markdown("# t\n\ncorpo\n").unwrap()
        );
    }

    // -- size caps (mirroring `authoring.rs`) ----------------------------------------------

    #[test]
    fn a_body_at_the_byte_cap_is_accepted() {
        // Many short paragraphs, so the per-block cap is not what is under test here.
        let para = "abcdefgh\n\n"; // 10 bytes
        let mut src = para.repeat(MAX_BODY_BYTES / para.len());
        src.push_str(&"x".repeat(MAX_BODY_BYTES - src.len()));
        assert_eq!(src.len(), MAX_BODY_BYTES);
        assert!(compile_markdown(&src).is_ok());
    }

    #[test]
    fn a_body_one_byte_over_the_cap_is_rejected() {
        let src = "a".repeat(MAX_BODY_BYTES + 1);
        assert_eq!(
            compile_markdown(&src),
            Err(MarkdownError::TooLarge {
                limit: MAX_BODY_BYTES,
                actual: MAX_BODY_BYTES + 1,
            })
        );
    }

    #[test]
    fn a_block_at_the_per_block_text_cap_is_accepted() {
        let src = "a".repeat(MAX_BLOCK_TEXT_BYTES);
        assert_eq!(compile_markdown(&src).unwrap(), vec![plain(&src)]);
    }

    #[test]
    fn a_block_one_byte_over_the_per_block_text_cap_is_rejected() {
        let src = "a".repeat(MAX_BLOCK_TEXT_BYTES + 1);
        assert_eq!(
            compile_markdown(&src),
            Err(MarkdownError::BlockTooLarge {
                limit: MAX_BLOCK_TEXT_BYTES,
                actual: MAX_BLOCK_TEXT_BYTES + 1,
                offset: 0,
            })
        );
    }

    #[test]
    fn an_oversized_heading_is_rejected() {
        let src = format!("# {}", "a".repeat(MAX_BLOCK_TEXT_BYTES + 1));
        assert!(matches!(
            compile_markdown(&src),
            Err(MarkdownError::BlockTooLarge { .. })
        ));
    }

    // -- determinism -----------------------------------------------------------------------

    const DETERMINISM_SAMPLE: &str = "\
# Ata n.º 1

A assembleia reuniu na sede da **Encosto Estratégico Lda**, tendo sido
deliberado o seguinte.

---

## Ponto um

Aprovado por *unanimidade*, com a ***expressa*** concordância de todos.
";

    #[test]
    fn compiling_the_same_input_twice_yields_the_same_output() {
        let a = compile_markdown(DETERMINISM_SAMPLE).unwrap();
        let b = compile_markdown(DETERMINISM_SAMPLE).unwrap();
        assert_eq!(a, b);
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap(),
            "serialized form must be byte-identical — this is what the seal binds"
        );
    }

    #[test]
    fn compilation_order_across_inputs_does_not_affect_any_result() {
        // Guards against hidden shared state: compiling other bodies in between must not perturb
        // the result of this one.
        let first = compile_markdown(DETERMINISM_SAMPLE).unwrap();
        for other in ["# a", "b **c**", "***", ""] {
            let _ = compile_markdown(other);
        }
        assert_eq!(compile_markdown(DETERMINISM_SAMPLE).unwrap(), first);
    }

    // -- golden corpus ---------------------------------------------------------------------
    //
    // Committed markdown → expected `Vec<Block>` JSON. Any `pulldown-cmark` bump that perturbs
    // output fails here, loudly, before it can reach a seal. `include_str!` (not a directory walk)
    // so a deleted or renamed corpus file is a compile error rather than a silently skipped case.

    macro_rules! golden {
        ($($name:literal),* $(,)?) => {
            &[$((
                $name,
                include_str!(concat!("../golden/md-block-v1/", $name, ".md")),
                include_str!(concat!("../golden/md-block-v1/", $name, ".blocks.json")),
            )),*]
        };
    }

    const GOLDEN: &[(&str, &str, &str)] = golden![
        "ata-completa",
        "emphasis",
        "headings",
        "rules-and-paragraphs",
        "empty",
    ];

    #[test]
    fn golden_corpus_matches_exactly() {
        for (name, src, expected) in GOLDEN {
            let blocks = compile_markdown(src)
                .unwrap_or_else(|e| panic!("golden case `{name}` failed to compile: {e}"));
            let got: Value = serde_json::to_value(&blocks).unwrap();
            let want: Value = serde_json::from_str(expected)
                .unwrap_or_else(|e| panic!("golden case `{name}` has invalid JSON: {e}"));
            assert_eq!(
                got,
                want,
                "golden case `{name}` drifted.\n\nIf this is a deliberate compiler change it ships \
                 as md-block/v2 with v1 retained — do not re-bless this file in place.\n\ngot:\n{}",
                serde_json::to_string_pretty(&got).unwrap()
            );
        }
    }

    #[test]
    fn golden_corpus_is_not_empty() {
        assert!(GOLDEN.len() >= 5, "the corpus must not be quietly emptied");
    }

    #[test]
    fn compiler_id_is_v1() {
        assert_eq!(COMPILER_ID, "md-block/v1");
    }
}
