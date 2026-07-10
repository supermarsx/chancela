//! Bounded, purpose-built layout engine: lowers a [`DocumentModel`] into one or more A4 page
//! content streams plus the set of glyphs actually used (for `/ToUnicode` and `/W`).
//!
//! This is not a general typesetter — it handles exactly the conservative block set (UX-04):
//! headings, paragraphs with bold/italic runs, 2-column key/value, a favor/against/abstain vote
//! table, a signature block, horizontal rules and explicit page breaks. Line-breaking wraps within
//! the text column; page-breaking flows overflowing content onto new pages. All coordinates are
//! emitted at fixed precision so the same model reproduces byte-identical content.

use std::collections::BTreeMap;

use chancela_core::{Block, DocumentModel, Run};

use crate::font::Font;

// A4 in PostScript points.
const PAGE_W: f32 = 595.28;
const PAGE_H: f32 = 841.89;
const MARGIN: f32 = 56.0;

const BODY: f32 = 11.0;
/// Text-matrix shear for synthesized italics (~12°).
const ITALIC_SHEAR: f32 = 0.2126;

/// One styled word (the atom of line breaking).
struct Word {
    text: String,
    bold: bool,
    italic: bool,
}

/// The laid-out document: per-page content streams, glyphs used across all pages, and the
/// page-local marked-content references needed for the PDF structure tree.
pub struct Laid {
    /// Uncompressed content-stream bytes, one entry per page (never empty).
    pub pages: Vec<Vec<u8>>,
    /// glyph id → a representative Unicode scalar (for the `/ToUnicode` CMap and `/W` widths).
    pub used: BTreeMap<u16, u32>,
    /// Semantic structure elements in reading order.
    pub structure_elements: Vec<TaggedElement>,
}

/// A semantic structure element backed by one or more page-local marked-content sequences.
pub struct TaggedElement {
    /// The writer's bounded semantic role for this element.
    pub role: StructureRole,
    /// Marked-content references belonging to this structure element.
    pub marked_content: Vec<MarkedContentRef>,
}

/// One marked-content sequence in one page content stream.
pub struct MarkedContentRef {
    /// Zero-based index into [`Laid::pages`].
    pub page_index: usize,
    /// Page-local `/MCID` value.
    pub mcid: i64,
}

/// Bounded roles emitted by the current deterministic writer.
#[derive(Clone, Copy)]
pub enum StructureRole {
    DocumentTitle,
    HeaderMetadata,
    Heading(u8),
    Paragraph,
    KeyValue,
    VoteTable,
    SignatureBlock,
}

struct Layouter<'f> {
    font: &'f Font,
    pages: Vec<Vec<u8>>,
    cur: Vec<u8>,
    /// Top of the remaining free area on the current page.
    y: f32,
    used: BTreeMap<u16, u32>,
    structure_elements: Vec<TaggedElement>,
    current_element: Option<usize>,
    next_mcids: Vec<i64>,
}

/// Format a coordinate deterministically (fixed 2 decimals, no negative zero).
fn num(x: f32) -> String {
    let x = if x.abs() < 0.005 { 0.0 } else { x };
    format!("{x:.2}")
}

impl<'f> Layouter<'f> {
    fn new(font: &'f Font) -> Self {
        Layouter {
            font,
            pages: Vec::new(),
            cur: Vec::new(),
            y: PAGE_H - MARGIN,
            used: BTreeMap::new(),
            structure_elements: Vec::new(),
            current_element: None,
            next_mcids: Vec::new(),
        }
    }

    fn content_x0(&self) -> f32 {
        MARGIN
    }
    fn content_x1(&self) -> f32 {
        PAGE_W - MARGIN
    }

    fn new_page(&mut self) {
        let done = std::mem::take(&mut self.cur);
        self.pages.push(done);
        self.y = PAGE_H - MARGIN;
    }

    fn current_page_index(&self) -> usize {
        self.pages.len()
    }

    fn next_mcid(&mut self) -> i64 {
        let page_index = self.current_page_index();
        if self.next_mcids.len() <= page_index {
            self.next_mcids.resize(page_index + 1, 0);
        }
        let mcid = self.next_mcids[page_index];
        self.next_mcids[page_index] += 1;
        mcid
    }

    fn tagged_element(&mut self, role: StructureRole, render: impl FnOnce(&mut Self)) {
        let index = self.structure_elements.len();
        self.structure_elements.push(TaggedElement {
            role,
            marked_content: Vec::new(),
        });
        let previous = self.current_element.replace(index);
        render(self);
        self.current_element = previous;
        if self.structure_elements[index].marked_content.is_empty() {
            self.structure_elements.remove(index);
        }
    }

    /// Reserve vertical space `h`; break the page if it would not fit.
    fn ensure(&mut self, h: f32) {
        if self.y - h < MARGIN {
            self.new_page();
        }
    }

    /// Take one text line of the given font size: reserve space and return the baseline y.
    fn take_line(&mut self, size: f32) -> f32 {
        let gap = size * 1.4;
        self.ensure(gap);
        let baseline = self.y - size;
        self.y -= gap;
        baseline
    }

    fn gap(&mut self, h: f32) {
        self.y -= h;
    }

    fn text_w(&self, s: &str, size: f32) -> f32 {
        s.chars().map(|c| self.font.char_width_1000(c)).sum::<f32>() * size / 1000.0
    }

    fn space_w(&self, size: f32) -> f32 {
        self.text_w(" ", size)
    }

    /// Emit one positioned text fragment (its own `BT…ET`), recording used glyphs.
    fn frag(&mut self, x: f32, baseline: f32, size: f32, bold: bool, italic: bool, s: &str) {
        if s.is_empty() {
            return;
        }
        let mut hex = String::with_capacity(s.len() * 4);
        for c in s.chars() {
            let gid = self.font.glyph_id(c);
            self.used.entry(gid).or_insert(c as u32);
            hex.push_str(&format!("{gid:04X}"));
        }
        let marked = if let Some(element_index) = self.current_element {
            let role = self.structure_elements[element_index].role;
            let page_index = self.current_page_index();
            let mcid = self.next_mcid();
            self.structure_elements[element_index]
                .marked_content
                .push(MarkedContentRef { page_index, mcid });
            Some((marked_content_tag(role), mcid))
        } else {
            None
        };
        let close_marked = marked.is_some();
        if let Some((tag, mcid)) = marked {
            self.cur
                .extend_from_slice(format!("/{tag} << /MCID {mcid} >> BDC\n").as_bytes());
        }
        self.cur.extend_from_slice(b"BT\n");
        self.cur
            .extend_from_slice(format!("/F1 {} Tf\n", num(size)).as_bytes());
        self.cur.extend_from_slice(b"0 g\n");
        if bold {
            let lw = size * 0.03;
            self.cur
                .extend_from_slice(format!("0 G\n{} w\n2 Tr\n", num(lw)).as_bytes());
        } else {
            self.cur.extend_from_slice(b"0 Tr\n");
        }
        if italic {
            self.cur.extend_from_slice(
                format!(
                    "1 0 {} 1 {} {} Tm\n",
                    num(ITALIC_SHEAR),
                    num(x),
                    num(baseline)
                )
                .as_bytes(),
            );
        } else {
            self.cur
                .extend_from_slice(format!("{} {} Td\n", num(x), num(baseline)).as_bytes());
        }
        self.cur
            .extend_from_slice(format!("<{hex}> Tj\nET\n").as_bytes());
        if close_marked {
            self.cur.extend_from_slice(b"EMC\n");
        }
    }

    /// Draw a horizontal rule at height `y` from `x0` to `x1`.
    fn rule_at(&mut self, x0: f32, x1: f32, y: f32, width: f32) {
        self.cur.extend_from_slice(b"/Artifact BMC\n");
        self.cur.extend_from_slice(
            format!(
                "{} w\n{} {} m\n{} {} l\nS\n",
                num(width),
                num(x0),
                num(y),
                num(x1),
                num(y)
            )
            .as_bytes(),
        );
        self.cur.extend_from_slice(b"EMC\n");
    }

    /// Greedy word-wrap `words` into the column `[x0, x1]` at `size`, drawing each line and paging
    /// as needed.
    fn flow(&mut self, words: &[Word], size: f32, x0: f32, x1: f32) {
        let col_w = x1 - x0;
        let space = self.space_w(size);
        let mut line: Vec<(f32, &Word)> = Vec::new();
        let mut width = 0.0f32;
        for w in words {
            let ww = self.text_w(&w.text, size);
            let add = if line.is_empty() {
                ww
            } else {
                width + space + ww
            };
            if !line.is_empty() && add > col_w {
                self.flush_line(&line, size, x0);
                line.clear();
                width = 0.0;
            }
            let xoff = if line.is_empty() { 0.0 } else { width + space };
            line.push((xoff, w));
            width = if line.len() == 1 {
                ww
            } else {
                width + space + ww
            };
        }
        if !line.is_empty() {
            self.flush_line(&line, size, x0);
        }
    }

    fn flush_line(&mut self, line: &[(f32, &Word)], size: f32, x0: f32) {
        let baseline = self.take_line(size);
        let space = self.space_w(size);
        for (index, (xoff, w)) in line.iter().enumerate() {
            if index > 0 {
                self.frag(x0 + xoff - space, baseline, size, false, false, " ");
            }
            self.frag(x0 + xoff, baseline, size, w.bold, w.italic, &w.text);
        }
    }

    // --- Block renderers -------------------------------------------------------------------------

    fn heading(&mut self, level: u8, text: &str) {
        let size = match level {
            1 => 17.0,
            2 => 14.0,
            3 => 12.0,
            _ => BODY,
        };
        self.tagged_element(StructureRole::Heading(level), |l| {
            l.gap(size * 0.5);
            let words = split_words(text, true, false);
            l.flow(&words, size, l.content_x0(), l.content_x1());
            l.gap(size * 0.25);
        });
    }

    fn paragraph(&mut self, runs: &[Run]) {
        let mut words = Vec::new();
        for r in runs {
            words.extend(split_words(&r.text, r.bold, r.italic));
        }
        if words.is_empty() {
            return;
        }
        self.tagged_element(StructureRole::Paragraph, |l| {
            l.flow(&words, BODY, l.content_x0(), l.content_x1());
            l.gap(BODY * 0.5);
        });
    }

    fn key_value(&mut self, rows: &[(String, String)]) {
        self.tagged_element(StructureRole::KeyValue, |l| {
            let x0 = l.content_x0();
            let val_x = x0 + 150.0;
            let val_x1 = l.content_x1();
            for (k, v) in rows {
                l.draw_kv_row(k, v, x0, val_x, val_x1);
            }
            l.gap(BODY * 0.3);
        });
    }

    fn draw_kv_row(&mut self, k: &str, v: &str, x0: f32, val_x: f32, val_x1: f32) {
        let baseline = self.take_line(BODY);
        self.frag(x0, baseline, BODY, true, false, k);
        // value wrapped within [val_x, val_x1]; first line shares the key's baseline.
        let vwords = split_words(v, false, false);
        let col_w = val_x1 - val_x;
        let space = self.space_w(BODY);
        let mut cur_base = baseline;
        let mut line_w = 0.0f32;
        let mut line_started = false;
        for w in &vwords {
            let ww = self.text_w(&w.text, BODY);
            let add = if line_started {
                line_w + space + ww
            } else {
                ww
            };
            if line_started && add > col_w {
                cur_base = self.take_line(BODY);
                line_w = 0.0;
                line_started = false;
            }
            if line_started {
                self.frag(val_x + line_w, cur_base, BODY, false, false, " ");
                line_w += space;
            }
            self.frag(val_x + line_w, cur_base, BODY, false, false, &w.text);
            line_w += ww;
            line_started = true;
        }
    }

    fn vote_table(&mut self, rows: &[chancela_core::VoteRow]) {
        self.tagged_element(StructureRole::VoteTable, |l| {
            let x0 = l.content_x0();
            let x1 = l.content_x1();
            let num_w = 72.0f32;
            let c3_r = x1;
            let c2_r = x1 - num_w;
            let c1_r = x1 - 2.0 * num_w;
            let label_x1 = x1 - 3.0 * num_w;

            l.gap(4.0);
            // Header row.
            let base = l.take_line(BODY);
            l.frag(x0, base, BODY, true, false, "Deliberação");
            l.right(c1_r, base, BODY, true, "A favor");
            l.right(c2_r, base, BODY, true, "Contra");
            l.right(c3_r, base, BODY, true, "Abstenção");
            l.rule_at(x0, x1, base - 3.0, 0.6);
            l.gap(3.0);
            for r in rows {
                // Each row is atomic; `take_line` page-breaks if it will not fit.
                let base = l.take_line(BODY);
                // wrap-free label (truncation avoided by column width being generous)
                l.frag_clip(x0, base, BODY, &r.label, label_x1 - x0);
                l.right(c1_r, base, BODY, false, &r.favor.to_string());
                l.right(c2_r, base, BODY, false, &r.against.to_string());
                l.right(c3_r, base, BODY, false, &r.abstain.to_string());
            }
            let end_y = l.y - 1.0;
            l.rule_at(x0, x1, end_y, 0.6);
            l.gap(6.0);
        });
    }

    /// Draw right-aligned text ending at `x_right`.
    fn right(&mut self, x_right: f32, baseline: f32, size: f32, bold: bool, s: &str) {
        let x = x_right - self.text_w(s, size);
        self.frag(x, baseline, size, bold, false, s);
    }

    /// Draw plain (non-bold, non-italic) text, dropping trailing characters that would exceed
    /// `max_w` (simple clip for table labels).
    fn frag_clip(&mut self, x: f32, baseline: f32, size: f32, s: &str, max_w: f32) {
        if self.text_w(s, size) <= max_w {
            self.frag(x, baseline, size, false, false, s);
            return;
        }
        let mut acc = String::new();
        for c in s.chars() {
            let trial = format!("{acc}{c}…");
            if self.text_w(&trial, size) > max_w {
                break;
            }
            acc.push(c);
        }
        acc.push('…');
        self.frag(x, baseline, size, false, false, &acc);
    }

    fn signature_block(&mut self, slots: &[chancela_core::SignatureSlot]) {
        self.tagged_element(StructureRole::SignatureBlock, |l| {
            let x0 = l.content_x0();
            let line_w = 220.0f32;
            l.gap(10.0);
            for slot in slots {
                // Reserve the whole slot (signature gap + rule + two text lines) as a unit.
                l.ensure(60.0);
                l.gap(26.0); // blank space for the ink signature
                let rule_y = l.y;
                l.rule_at(x0, x0 + line_w, rule_y, 0.6);
                l.gap(2.0);
                let b1 = l.take_line(BODY);
                l.frag(x0, b1, BODY, true, false, &slot.role);
                let b2 = l.take_line(BODY);
                l.frag(x0, b2, BODY, false, false, &slot.name);
                l.gap(8.0);
            }
        });
    }

    fn horizontal_rule(&mut self) {
        self.gap(4.0);
        self.ensure(4.0);
        let y = self.y;
        self.rule_at(self.content_x0(), self.content_x1(), y, 0.6);
        self.gap(6.0);
    }

    fn header_prologue(&mut self, doc: &DocumentModel) {
        // Title.
        self.tagged_element(StructureRole::DocumentTitle, |l| {
            let title_words = split_words(&doc.title, true, false);
            l.flow(&title_words, 17.0, l.content_x0(), l.content_x1());
            l.gap(3.0);
        });
        // Entity line.
        let entity = match &doc.entity_nipc {
            Some(n) if !n.is_empty() => format!("{} — NIPC {}", doc.entity_name, n),
            _ => doc.entity_name.clone(),
        };
        self.tagged_element(StructureRole::HeaderMetadata, |l| {
            let ewords = split_words(&entity, false, false);
            l.flow(&ewords, BODY, l.content_x0(), l.content_x1());
        });
        // Subject.
        if !doc.subject.is_empty() {
            self.tagged_element(StructureRole::HeaderMetadata, |l| {
                l.gap(2.0);
                let swords = split_words(&doc.subject, false, true);
                l.flow(&swords, 12.0, l.content_x0(), l.content_x1());
            });
        }
        self.horizontal_rule();
    }
}

fn marked_content_tag(role: StructureRole) -> &'static str {
    match role {
        StructureRole::DocumentTitle => "H1",
        StructureRole::HeaderMetadata => "P",
        StructureRole::Heading(1) => "H1",
        StructureRole::Heading(2) => "H2",
        StructureRole::Heading(3) => "H3",
        StructureRole::Heading(_) => "H",
        StructureRole::Paragraph => "P",
        StructureRole::KeyValue => "Div",
        StructureRole::VoteTable => "Div",
        StructureRole::SignatureBlock => "Div",
    }
}

/// Split text into styled words on ASCII/Unicode whitespace.
fn split_words(text: &str, bold: bool, italic: bool) -> Vec<Word> {
    text.split_whitespace()
        .map(|w| Word {
            text: w.to_string(),
            bold,
            italic,
        })
        .collect()
}

/// Lay a whole document out into page content streams.
pub fn lay_out(doc: &DocumentModel, font: &Font) -> Laid {
    let mut l = Layouter::new(font);
    l.header_prologue(doc);
    for block in &doc.blocks {
        match block {
            Block::Heading { level, text } => l.heading(*level, text),
            Block::Paragraph { runs } => l.paragraph(runs),
            Block::KeyValue { rows } => {
                let rows: Vec<(String, String)> = rows
                    .iter()
                    .map(|r| (r.key.clone(), r.value.clone()))
                    .collect();
                l.key_value(&rows);
            }
            Block::VoteTable { rows } => l.vote_table(rows),
            Block::SignatureBlock { slots } => l.signature_block(slots),
            Block::PageBreak => l.new_page(),
            Block::Rule => l.horizontal_rule(),
        }
    }
    // Flush the last page.
    l.pages.push(std::mem::take(&mut l.cur));
    // Guarantee at least one page and at least the .notdef/space glyph presence.
    if l.pages.is_empty() {
        l.pages.push(Vec::new());
    }
    Laid {
        pages: l.pages,
        used: l.used,
        structure_elements: l.structure_elements,
    }
}
