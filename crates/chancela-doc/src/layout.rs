//! Bounded, purpose-built layout engine: lowers a [`DocumentModel`] into one or more A4 page
//! content streams plus the set of glyphs actually used (for `/ToUnicode` and `/W`).
//!
//! This is not a general typesetter — it handles exactly the conservative block set (UX-04):
//! headings, paragraphs with bold/italic runs, 2-column key/value, a favor/against/abstain vote
//! table, a signature block, horizontal rules and explicit page breaks. Line-breaking wraps within
//! the text column; page-breaking flows overflowing content onto new pages. All coordinates are
//! emitted at fixed precision so the same model reproduces byte-identical content.

use std::collections::BTreeMap;

use chancela_core::{
    Block, DocumentFurnitureAlignment, DocumentLayoutPolicy, DocumentModel, DocumentOrientation,
    DocumentPageSize, DocumentSideTextEdge, FurnitureFacts, Run,
};

use crate::DocError;
use crate::font::Font;

const PT_PER_MM: f32 = 72.0 / 25.4;
/// Text-matrix shear for synthesized italics (~12°).
const ITALIC_SHEAR: f32 = 0.2126;
/// Vertical clearance between a header/footer furniture line (or its rule) and the text column.
const FURNITURE_BODY_GAP: f32 = 4.0;
/// Horizontal clearance between marginal side text and the text column.
const FURNITURE_SIDE_GAP: f32 = 4.0;
/// Width of the marginal band, as a multiple of the furniture font size, before the side gap.
const FURNITURE_SIDE_BAND: f32 = 1.5;

#[derive(Clone, Copy)]
enum FontSlot {
    Body,
    Header,
    /// The face used for page furniture (`typography.footer_font_*`).
    Footer,
}

#[derive(Clone, Copy)]
enum FontEmphasis {
    Normal,
    Bold,
    Italic,
    BoldItalic,
}

impl FontEmphasis {
    fn from_flags(bold: bool, italic: bool) -> Self {
        match (bold, italic) {
            (false, false) => Self::Normal,
            (true, false) => Self::Bold,
            (false, true) => Self::Italic,
            (true, true) => Self::BoldItalic,
        }
    }

    fn bold(self) -> bool {
        matches!(self, Self::Bold | Self::BoldItalic)
    }

    fn italic(self) -> bool {
        matches!(self, Self::Italic | Self::BoldItalic)
    }
}

/// Approved fonts needed by a concrete policy. Equal body/header families share one object.
pub struct FontCatalog {
    pub fonts: Vec<Font>,
    body_index: usize,
    header_index: usize,
    footer_index: usize,
}

impl FontCatalog {
    pub fn load(policy: &DocumentLayoutPolicy) -> Result<Self, DocError> {
        policy
            .validate()
            .map_err(|error| DocError::Layout(error.to_string()))?;
        let body_family = policy.typography.body_font_family;
        let header_family = policy.typography.header_font_family;
        let footer_family = policy.typography.footer_font_family;
        let mut fonts = vec![Font::load_family(body_family)?];
        let mut families = vec![body_family];
        // Equal families share one object. A slot whose face is never used emits no font object at
        // all (`pdfa::write` skips an empty glyph set), so loading the footer face here cannot move
        // the bytes of a document that draws no furniture.
        let intern =
            |fonts: &mut Vec<Font>, families: &mut Vec<_>, family| -> Result<usize, DocError> {
                if let Some(index) = families.iter().position(|known| *known == family) {
                    return Ok(index);
                }
                fonts.push(Font::load_family(family)?);
                families.push(family);
                Ok(fonts.len() - 1)
            };
        let header_index = intern(&mut fonts, &mut families, header_family)?;
        let footer_index = intern(&mut fonts, &mut families, footer_family)?;
        Ok(Self {
            fonts,
            body_index: 0,
            header_index,
            footer_index,
        })
    }

    fn index(&self, slot: FontSlot) -> usize {
        match slot {
            FontSlot::Body => self.body_index,
            FontSlot::Header => self.header_index,
            FontSlot::Footer => self.footer_index,
        }
    }

    fn get(&self, slot: FontSlot) -> &Font {
        &self.fonts[self.index(slot)]
    }
}

#[derive(Clone, Copy)]
struct Metrics {
    page_w: f32,
    page_h: f32,
    margin_top: f32,
    margin_right: f32,
    margin_bottom: f32,
    margin_left: f32,
    body_size: f32,
    header_size: f32,
    line_spacing: f32,
    paragraph_spacing: f32,
    heading_scale: f32,
    header_gap: f32,
    footer_gap: f32,
    /// Font size for every piece of page furniture.
    furniture_size: f32,
    /// Vertical space taken out of the top of the text column for the running header.
    header_reserve: f32,
    /// Vertical space taken out of the bottom of the text column for the running footer.
    footer_reserve: f32,
    /// Horizontal space taken out of one side of the text column for the marginal text.
    side_reserve: f32,
    /// Which side `side_reserve` comes out of.
    side_edge: DocumentSideTextEdge,
}

impl Metrics {
    fn from_policy(policy: &DocumentLayoutPolicy) -> Self {
        let (portrait_w, portrait_h) = match policy.page.size {
            DocumentPageSize::A4 => (595.28, 841.89),
            DocumentPageSize::A5 => (419.53, 595.28),
            DocumentPageSize::Letter => (612.0, 792.0),
            DocumentPageSize::Legal => (612.0, 1008.0),
        };
        let (page_w, page_h) = match policy.page.orientation {
            DocumentOrientation::Portrait => (portrait_w, portrait_h),
            DocumentOrientation::Landscape => (portrait_h, portrait_w),
        };
        // Furniture reserves space out of the text column rather than sitting free in the margin,
        // so a body that fills the page reflows around it instead of overprinting it. Every
        // reserve is a pure function of the policy — never of the text a given page resolves to —
        // so an omitted or short furniture line cannot move body content.
        let line_spacing = f32::from(policy.typography.line_spacing_percent) / 100.0;
        let furniture_size = f32::from(policy.typography.footer_font_size_pt);
        let furniture_line = furniture_size * line_spacing;
        let furniture = &policy.furniture;
        let header_reserve = if furniture.header_draws() {
            furniture_line + FURNITURE_BODY_GAP
        } else {
            0.0
        };
        let footer_reserve = if furniture.footer_draws() {
            furniture_line + FURNITURE_BODY_GAP
        } else {
            0.0
        };
        let side_reserve = if furniture.side_text_draws() {
            furniture_size * FURNITURE_SIDE_BAND + FURNITURE_SIDE_GAP
        } else {
            0.0
        };
        Self {
            page_w,
            page_h,
            margin_top: f32::from(policy.page.margins_mm.top) * PT_PER_MM,
            margin_right: f32::from(policy.page.margins_mm.right) * PT_PER_MM,
            margin_bottom: f32::from(policy.page.margins_mm.bottom) * PT_PER_MM,
            margin_left: f32::from(policy.page.margins_mm.left) * PT_PER_MM,
            body_size: f32::from(policy.typography.body_font_size_pt),
            header_size: f32::from(policy.typography.header_font_size_pt),
            line_spacing,
            paragraph_spacing: f32::from(policy.typography.paragraph_spacing_pt),
            heading_scale: f32::from(policy.typography.heading_scale_percent) / 100.0,
            header_gap: f32::from(policy.regions.header_gap_mm) * PT_PER_MM,
            footer_gap: f32::from(policy.regions.footer_gap_mm) * PT_PER_MM,
            furniture_size,
            header_reserve,
            footer_reserve,
            side_reserve,
            side_edge: policy.furniture.side_text.edge,
        }
    }

    /// Top of the text column: the top margin, less anything the running header reserved.
    fn content_top(&self) -> f32 {
        self.page_h - self.margin_top - self.header_reserve
    }

    /// Baseline of the footer band — where the text column stops if no footer is drawn.
    fn footer_band_y(&self) -> f32 {
        self.margin_bottom + self.footer_gap
    }
}

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
    pub used: Vec<BTreeMap<u16, u32>>,
    /// Physical page width in PostScript points.
    pub page_width: f32,
    /// Physical page height in PostScript points.
    pub page_height: f32,
    /// Semantic structure elements in reading order.
    pub structure_elements: Vec<TaggedElement>,
}

/// A semantic structure element backed by one or more page-local marked-content sequences.
pub struct TaggedElement {
    /// The writer's bounded semantic role for this element.
    pub role: StructureRole,
    /// Parent structure element index, or `None` for children of the document root.
    pub parent: Option<usize>,
    /// Child structure element indices in reading order.
    pub children: Vec<usize>,
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

/// Table header scope emitted for the writer's bounded table profile.
#[derive(Clone, Copy)]
pub enum TableHeaderScope {
    Row,
    Column,
}

/// Bounded roles emitted by the current deterministic writer.
#[derive(Clone, Copy)]
pub enum StructureRole {
    DocumentTitle,
    HeaderMetadata,
    Heading(u8),
    Paragraph,
    KeyValueTable,
    VoteTable,
    TableRow,
    TableHeaderCell(TableHeaderScope),
    TableDataCell,
    SignatureBlock,
}

struct Layouter<'f> {
    fonts: &'f FontCatalog,
    metrics: Metrics,
    pages: Vec<Vec<u8>>,
    cur: Vec<u8>,
    /// Top of the remaining free area on the current page.
    y: f32,
    used: Vec<BTreeMap<u16, u32>>,
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
    fn new(fonts: &'f FontCatalog, policy: &DocumentLayoutPolicy) -> Self {
        let metrics = Metrics::from_policy(policy);
        Layouter {
            fonts,
            metrics,
            pages: Vec::new(),
            cur: Vec::new(),
            y: metrics.content_top(),
            used: (0..fonts.fonts.len()).map(|_| BTreeMap::new()).collect(),
            structure_elements: Vec::new(),
            current_element: None,
            next_mcids: Vec::new(),
        }
    }

    fn content_x0(&self) -> f32 {
        self.metrics.margin_left
            + match self.metrics.side_edge {
                DocumentSideTextEdge::Left => self.metrics.side_reserve,
                DocumentSideTextEdge::Right => 0.0,
            }
    }
    fn content_x1(&self) -> f32 {
        self.metrics.page_w
            - self.metrics.margin_right
            - match self.metrics.side_edge {
                DocumentSideTextEdge::Left => 0.0,
                DocumentSideTextEdge::Right => self.metrics.side_reserve,
            }
    }
    fn body_size(&self) -> f32 {
        self.metrics.body_size
    }
    fn bottom_y(&self) -> f32 {
        self.metrics.footer_band_y() + self.metrics.footer_reserve
    }

    fn new_page(&mut self) {
        let done = std::mem::take(&mut self.cur);
        self.pages.push(done);
        self.y = self.metrics.content_top();
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
        let parent = self.current_element;
        let index = self.structure_elements.len();
        self.structure_elements.push(TaggedElement {
            role,
            parent,
            children: Vec::new(),
            marked_content: Vec::new(),
        });
        if let Some(parent_index) = parent {
            self.structure_elements[parent_index].children.push(index);
        }
        let previous = self.current_element.replace(index);
        render(self);
        self.current_element = previous;
        if self.structure_elements[index].marked_content.is_empty()
            && self.structure_elements[index].children.is_empty()
        {
            self.structure_elements.pop();
            if let Some(parent_index) = parent {
                let removed = self.structure_elements[parent_index].children.pop();
                debug_assert_eq!(removed, Some(index));
            }
        }
    }

    /// Reserve vertical space `h`; break the page if it would not fit.
    fn ensure(&mut self, h: f32) {
        if self.y - h < self.bottom_y() {
            self.new_page();
        }
    }

    /// Take one text line of the given font size: reserve space and return the baseline y.
    fn take_line(&mut self, size: f32) -> f32 {
        let gap = size * self.metrics.line_spacing;
        self.ensure(gap);
        let baseline = self.y - size;
        self.y -= gap;
        baseline
    }

    fn gap(&mut self, h: f32) {
        self.y -= h;
    }

    fn text_w(&self, font: FontSlot, s: &str, size: f32) -> f32 {
        s.chars()
            .map(|c| self.fonts.get(font).char_width_1000(c))
            .sum::<f32>()
            * size
            / 1000.0
    }

    fn space_w(&self, font: FontSlot, size: f32) -> f32 {
        self.text_w(font, " ", size)
    }

    /// Emit one positioned text fragment (its own `BT…ET`), recording used glyphs.
    fn frag(
        &mut self,
        font_slot: FontSlot,
        x: f32,
        baseline: f32,
        size: f32,
        emphasis: FontEmphasis,
        s: &str,
    ) {
        if s.is_empty() {
            return;
        }
        let mut hex = String::with_capacity(s.len() * 4);
        let font_index = self.fonts.index(font_slot);
        for c in s.chars() {
            let gid = self.fonts.fonts[font_index].glyph_id(c);
            self.used[font_index].entry(gid).or_insert(c as u32);
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
            .extend_from_slice(format!("/F{} {} Tf\n", font_index + 1, num(size)).as_bytes());
        self.cur.extend_from_slice(b"0 g\n");
        if emphasis.bold() {
            let lw = size * 0.03;
            self.cur
                .extend_from_slice(format!("0 G\n{} w\n2 Tr\n", num(lw)).as_bytes());
        } else {
            self.cur.extend_from_slice(b"0 Tr\n");
        }
        if emphasis.italic() {
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
    fn flow(&mut self, font: FontSlot, words: &[Word], size: f32, x0: f32, x1: f32) {
        let col_w = x1 - x0;
        let space = self.space_w(font, size);
        let mut line: Vec<(f32, &Word)> = Vec::new();
        let mut width = 0.0f32;
        for w in words {
            let ww = self.text_w(font, &w.text, size);
            let add = if line.is_empty() {
                ww
            } else {
                width + space + ww
            };
            if !line.is_empty() && add > col_w {
                self.flush_line(font, &line, size, x0);
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
            self.flush_line(font, &line, size, x0);
        }
    }

    fn flush_line(&mut self, font: FontSlot, line: &[(f32, &Word)], size: f32, x0: f32) {
        let baseline = self.take_line(size);
        let space = self.space_w(font, size);
        for (index, (xoff, w)) in line.iter().enumerate() {
            if index > 0 {
                self.frag(
                    font,
                    x0 + xoff - space,
                    baseline,
                    size,
                    FontEmphasis::Normal,
                    " ",
                );
            }
            self.frag(
                font,
                x0 + xoff,
                baseline,
                size,
                FontEmphasis::from_flags(w.bold, w.italic),
                &w.text,
            );
        }
    }

    // --- Block renderers -------------------------------------------------------------------------

    fn heading(&mut self, level: u8, text: &str) {
        let ratio = match level {
            1 => 17.0 / 11.0,
            2 => 14.0 / 11.0,
            3 => 12.0 / 11.0,
            _ => 1.0,
        };
        let size = self.body_size() * ratio * self.metrics.heading_scale;
        self.tagged_element(StructureRole::Heading(level), |l| {
            l.gap(size * 0.5);
            let words = split_words(text, true, false);
            l.flow(
                FontSlot::Header,
                &words,
                size,
                l.content_x0(),
                l.content_x1(),
            );
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
        let body_size = self.body_size();
        let paragraph_spacing = self.metrics.paragraph_spacing;
        self.tagged_element(StructureRole::Paragraph, |l| {
            l.flow(
                FontSlot::Body,
                &words,
                body_size,
                l.content_x0(),
                l.content_x1(),
            );
            l.gap(paragraph_spacing);
        });
    }

    fn key_value(&mut self, rows: &[(String, String)]) {
        self.tagged_element(StructureRole::KeyValueTable, |l| {
            let x0 = l.content_x0();
            let val_x1 = l.content_x1();
            let content_width = val_x1 - x0;
            let val_x = x0 + (content_width * 0.36).clamp(80.0, 150.0);
            for (k, v) in rows {
                l.draw_kv_row(k, v, x0, val_x, val_x1);
            }
            l.gap(l.body_size() * 0.3);
        });
    }

    fn draw_kv_row(&mut self, k: &str, v: &str, x0: f32, val_x: f32, val_x1: f32) {
        self.tagged_element(StructureRole::TableRow, |l| {
            let body_size = l.body_size();
            let baseline = l.take_line(body_size);
            l.tagged_element(StructureRole::TableHeaderCell(TableHeaderScope::Row), |l| {
                l.frag(
                    FontSlot::Body,
                    x0,
                    baseline,
                    body_size,
                    FontEmphasis::Bold,
                    k,
                );
            });
            l.tagged_element(StructureRole::TableDataCell, |l| {
                // value wrapped within [val_x, val_x1]; first line shares the key's baseline.
                let vwords = split_words(v, false, false);
                let col_w = val_x1 - val_x;
                let space = l.space_w(FontSlot::Body, body_size);
                let mut cur_base = baseline;
                let mut line_w = 0.0f32;
                let mut line_started = false;
                for w in &vwords {
                    let ww = l.text_w(FontSlot::Body, &w.text, body_size);
                    let add = if line_started {
                        line_w + space + ww
                    } else {
                        ww
                    };
                    if line_started && add > col_w {
                        cur_base = l.take_line(body_size);
                        line_w = 0.0;
                        line_started = false;
                    }
                    if line_started {
                        l.frag(
                            FontSlot::Body,
                            val_x + line_w,
                            cur_base,
                            body_size,
                            FontEmphasis::Normal,
                            " ",
                        );
                        line_w += space;
                    }
                    l.frag(
                        FontSlot::Body,
                        val_x + line_w,
                        cur_base,
                        body_size,
                        FontEmphasis::Normal,
                        &w.text,
                    );
                    line_w += ww;
                    line_started = true;
                }
            });
        });
    }

    fn vote_table(&mut self, rows: &[chancela_core::VoteRow]) {
        self.tagged_element(StructureRole::VoteTable, |l| {
            let x0 = l.content_x0();
            let x1 = l.content_x1();
            let body_size = l.body_size();
            let content_width = x1 - x0;
            let num_w = 72.0f32.min(content_width * 0.17);
            let c3_r = x1;
            let c2_r = x1 - num_w;
            let c1_r = x1 - 2.0 * num_w;
            let label_x1 = x1 - 3.0 * num_w;

            l.gap(4.0);
            // Header row.
            let base = l.take_line(body_size);
            l.tagged_element(StructureRole::TableRow, |l| {
                l.tagged_element(
                    StructureRole::TableHeaderCell(TableHeaderScope::Column),
                    |l| {
                        l.frag(
                            FontSlot::Body,
                            x0,
                            base,
                            body_size,
                            FontEmphasis::Bold,
                            "Deliberação",
                        );
                    },
                );
                l.tagged_element(
                    StructureRole::TableHeaderCell(TableHeaderScope::Column),
                    |l| {
                        l.right(FontSlot::Body, c1_r, base, body_size, true, "A favor");
                    },
                );
                l.tagged_element(
                    StructureRole::TableHeaderCell(TableHeaderScope::Column),
                    |l| {
                        l.right(FontSlot::Body, c2_r, base, body_size, true, "Contra");
                    },
                );
                l.tagged_element(
                    StructureRole::TableHeaderCell(TableHeaderScope::Column),
                    |l| {
                        l.right(FontSlot::Body, c3_r, base, body_size, true, "Abstenção");
                    },
                );
            });
            l.rule_at(x0, x1, base - 3.0, 0.6);
            l.gap(3.0);
            for r in rows {
                // Each row is atomic; `take_line` page-breaks if it will not fit.
                let base = l.take_line(body_size);
                l.tagged_element(StructureRole::TableRow, |l| {
                    l.tagged_element(StructureRole::TableHeaderCell(TableHeaderScope::Row), |l| {
                        // wrap-free label (truncation avoided by column width being generous)
                        l.frag_clip(FontSlot::Body, x0, base, body_size, &r.label, label_x1 - x0);
                    });
                    l.tagged_element(StructureRole::TableDataCell, |l| {
                        l.right(
                            FontSlot::Body,
                            c1_r,
                            base,
                            body_size,
                            false,
                            &r.favor.to_string(),
                        );
                    });
                    l.tagged_element(StructureRole::TableDataCell, |l| {
                        l.right(
                            FontSlot::Body,
                            c2_r,
                            base,
                            body_size,
                            false,
                            &r.against.to_string(),
                        );
                    });
                    l.tagged_element(StructureRole::TableDataCell, |l| {
                        l.right(
                            FontSlot::Body,
                            c3_r,
                            base,
                            body_size,
                            false,
                            &r.abstain.to_string(),
                        );
                    });
                });
            }
            let end_y = l.y - 1.0;
            l.rule_at(x0, x1, end_y, 0.6);
            l.gap(6.0);
        });
    }

    /// Draw right-aligned text ending at `x_right`.
    fn right(
        &mut self,
        font: FontSlot,
        x_right: f32,
        baseline: f32,
        size: f32,
        bold: bool,
        s: &str,
    ) {
        let x = x_right - self.text_w(font, s, size);
        self.frag(
            font,
            x,
            baseline,
            size,
            if bold {
                FontEmphasis::Bold
            } else {
                FontEmphasis::Normal
            },
            s,
        );
    }

    /// The longest prefix of `s` that fits `max_w`, ellipsised when it had to be cut.
    fn clip_to_width(&self, font: FontSlot, s: &str, size: f32, max_w: f32) -> String {
        if self.text_w(font, s, size) <= max_w {
            return s.to_string();
        }
        let mut acc = String::new();
        for c in s.chars() {
            let trial = format!("{acc}{c}…");
            if self.text_w(font, &trial, size) > max_w {
                break;
            }
            acc.push(c);
        }
        acc.push('…');
        acc
    }

    /// Draw plain (non-bold, non-italic) text, dropping trailing characters that would exceed
    /// `max_w` (simple clip for table labels).
    fn frag_clip(&mut self, font: FontSlot, x: f32, baseline: f32, size: f32, s: &str, max_w: f32) {
        let text = self.clip_to_width(font, s, size, max_w);
        self.frag(font, x, baseline, size, FontEmphasis::Normal, &text);
    }

    /// Emit one rotated text fragment (its own `BT…ET`), recording used glyphs.
    ///
    /// The rotation is a **text-matrix** rotation, not a page `/Rotate` and not a form XObject: the
    /// glyphs stay in the page's own coordinate space, so page-breaking, the enclosing artifact
    /// scope, and the PAdES byte shape all stay exactly as they are for upright text. `clockwise`
    /// reads top-to-bottom (the fore-edge convention); otherwise bottom-to-top (the binding edge).
    fn frag_rotated(
        &mut self,
        font_slot: FontSlot,
        x: f32,
        y: f32,
        size: f32,
        clockwise: bool,
        s: &str,
    ) {
        if s.is_empty() {
            return;
        }
        let font_index = self.fonts.index(font_slot);
        let mut hex = String::with_capacity(s.len() * 4);
        for c in s.chars() {
            let gid = self.fonts.fonts[font_index].glyph_id(c);
            self.used[font_index].entry(gid).or_insert(c as u32);
            hex.push_str(&format!("{gid:04X}"));
        }
        let (b, c) = if clockwise { (-1.0, 1.0) } else { (1.0, -1.0) };
        self.cur.extend_from_slice(b"BT\n");
        self.cur
            .extend_from_slice(format!("/F{} {} Tf\n", font_index + 1, num(size)).as_bytes());
        self.cur.extend_from_slice(b"0 g\n0 Tr\n");
        self.cur.extend_from_slice(
            format!("0 {} {} 0 {} {} Tm\n", num(b), num(c), num(x), num(y)).as_bytes(),
        );
        self.cur
            .extend_from_slice(format!("<{hex}> Tj\nET\n").as_bytes());
    }

    fn signature_block(&mut self, slots: &[chancela_core::SignatureSlot]) {
        self.tagged_element(StructureRole::SignatureBlock, |l| {
            let x0 = l.content_x0();
            let line_w = 220.0f32.min(l.content_x1() - x0);
            let body_size = l.body_size();
            l.gap(10.0);
            for slot in slots {
                // Reserve the whole slot (signature gap + rule + two text lines) as a unit.
                l.ensure(60.0);
                l.gap(26.0); // blank space for the ink signature
                let rule_y = l.y;
                l.rule_at(x0, x0 + line_w, rule_y, 0.6);
                l.gap(2.0);
                let b1 = l.take_line(body_size);
                l.frag(
                    FontSlot::Body,
                    x0,
                    b1,
                    body_size,
                    FontEmphasis::Bold,
                    &slot.role,
                );
                let b2 = l.take_line(body_size);
                l.frag(
                    FontSlot::Body,
                    x0,
                    b2,
                    body_size,
                    FontEmphasis::Normal,
                    &slot.name,
                );
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
        let header_size = self.metrics.header_size;
        // Title.
        self.tagged_element(StructureRole::DocumentTitle, |l| {
            let title_words = split_words(&doc.title, true, false);
            l.flow(
                FontSlot::Header,
                &title_words,
                header_size * (17.0 / 11.0),
                l.content_x0(),
                l.content_x1(),
            );
            l.gap(3.0);
        });
        // Entity line.
        let entity = match &doc.entity_nipc {
            Some(n) if !n.is_empty() => format!("{} — NIPC {}", doc.entity_name, n),
            _ => doc.entity_name.clone(),
        };
        self.tagged_element(StructureRole::HeaderMetadata, |l| {
            let ewords = split_words(&entity, false, false);
            l.flow(
                FontSlot::Header,
                &ewords,
                header_size,
                l.content_x0(),
                l.content_x1(),
            );
        });
        // Subject.
        if !doc.subject.is_empty() {
            self.tagged_element(StructureRole::HeaderMetadata, |l| {
                l.gap(2.0);
                let swords = split_words(&doc.subject, false, true);
                l.flow(
                    FontSlot::Header,
                    &swords,
                    header_size * (12.0 / 11.0),
                    l.content_x0(),
                    l.content_x1(),
                );
            });
        }
        self.gap(4.0);
        self.ensure(4.0);
        let y = self.y;
        self.rule_at(self.content_x0(), self.content_x1(), y, 0.6);
        self.gap(self.metrics.header_gap);
    }

    // --- Page furniture --------------------------------------------------------------------------

    /// Append the running header, running footer and marginal side text to every page.
    ///
    /// Runs **after** the body has been laid out, because `{{ page_count }}` is not knowable until
    /// then. That ordering is safe precisely because furniture never participates in the flow: the
    /// space it occupies was already taken out of the text column by [`Metrics::from_policy`], and
    /// that reserve depends only on the policy, so no furniture text — long, short, or omitted —
    /// can move a single body glyph.
    ///
    /// Every piece is emitted inside an `/Artifact` scope and carries no `/MCID`, so none of it
    /// enters the structure tree. That is the correct classification, not a convenience: each line
    /// is a pure function of the policy, the page index and metadata the document already states in
    /// its tagged content, so exposing it as content would make a screen reader re-read the same
    /// facts between every paragraph — the exact defect ISO 14289-1 §7.8 exists to prevent.
    fn draw_page_furniture(&mut self, doc: &DocumentModel) -> Result<(), DocError> {
        let furniture = &doc.document_layout.furniture;
        if !furniture.draws_anything() {
            return Ok(());
        }
        // True by construction here — every `tagged_element` scope has closed — but pinned rather
        // than asserted: if furniture ever emitted inside a structure element, `frag` would open an
        // `/MCID` sequence *inside* an `/Artifact` scope, which is content marked as decoration and
        // a PDF/UA failure that only the external gate would catch.
        self.current_element = None;
        let parse = |text: &str| {
            chancela_core::parse_furniture_template(text)
                .map_err(|error| DocError::Layout(format!("page furniture: {error}")))
        };
        let header = furniture
            .header_draws()
            .then(|| parse(&furniture.header.text))
            .transpose()?;
        let footer = furniture
            .footer_draws()
            .then(|| parse(&furniture.footer.text))
            .transpose()?;
        let side_text = furniture
            .side_text_draws()
            .then(|| parse(&furniture.side_text.text))
            .transpose()?;

        let page_count = u32::try_from(self.pages.len()).ok();
        for page_index in 0..self.pages.len() {
            let facts = FurnitureFacts {
                page: u32::try_from(page_index + 1).ok(),
                page_count,
                page_capacity: doc.page_capacity,
                entity_name: Some(doc.entity_name.as_str()),
                entity_nipc: doc
                    .entity_nipc
                    .as_deref()
                    .filter(|nipc| !nipc.trim().is_empty()),
                title: Some(doc.title.as_str()),
                subject: Some(doc.subject.as_str()),
                date: doc.created_at.as_deref(),
            };
            debug_assert!(self.cur.is_empty());
            if let Some(segments) = &header
                && let Some(text) = chancela_core::resolve_furniture_segments(segments, &facts)
            {
                self.draw_furniture_line(
                    &text,
                    furniture.header.alignment,
                    true,
                    furniture.header.rule,
                );
            }
            if let Some(segments) = &footer
                && let Some(text) = chancela_core::resolve_furniture_segments(segments, &facts)
            {
                self.draw_furniture_line(
                    &text,
                    furniture.footer.alignment,
                    false,
                    furniture.footer.rule,
                );
            }
            if let Some(segments) = &side_text
                && let Some(text) = chancela_core::resolve_furniture_segments(segments, &facts)
            {
                self.draw_furniture_side_text(&text);
            }
            let drawn = std::mem::take(&mut self.cur);
            self.pages[page_index].extend_from_slice(&drawn);
        }
        Ok(())
    }

    /// Draw one horizontal furniture line inside the band its reserve created.
    fn draw_furniture_line(
        &mut self,
        text: &str,
        alignment: DocumentFurnitureAlignment,
        is_header: bool,
        rule: bool,
    ) {
        let size = self.metrics.furniture_size;
        let x0 = self.content_x0();
        let x1 = self.content_x1();
        let column = x1 - x0;
        if column <= 0.0 {
            return;
        }
        let clipped = self.clip_to_width(FontSlot::Footer, text.trim(), size, column);
        if clipped.is_empty() {
            return;
        }
        let width = self.text_w(FontSlot::Footer, &clipped, size);
        let x = match alignment {
            DocumentFurnitureAlignment::Left => x0,
            DocumentFurnitureAlignment::Center => x0 + (column - width) / 2.0,
            DocumentFurnitureAlignment::Right => x1 - width,
        }
        .max(x0);
        let line = size * self.metrics.line_spacing;
        let (baseline, rule_y) = if is_header {
            let band_top = self.metrics.page_h - self.metrics.margin_top;
            (band_top - size, band_top - line)
        } else {
            let band = self.metrics.footer_band_y();
            (band + size * 0.3, band + line)
        };
        self.cur.extend_from_slice(b"/Artifact BMC\n");
        self.frag(
            FontSlot::Footer,
            x,
            baseline,
            size,
            FontEmphasis::Normal,
            &clipped,
        );
        self.cur.extend_from_slice(b"EMC\n");
        if rule {
            self.rule_at(x0, x1, rule_y, 0.4);
        }
    }

    /// Draw the marginal side text, rotated 90°, centred on the text column's height.
    fn draw_furniture_side_text(&mut self, text: &str) {
        let size = self.metrics.furniture_size;
        let top = self.metrics.content_top();
        let bottom = self.bottom_y();
        let available = top - bottom;
        if available <= 0.0 {
            return;
        }
        let clipped = self.clip_to_width(FontSlot::Footer, text.trim(), size, available);
        if clipped.is_empty() {
            return;
        }
        let width = self.text_w(FontSlot::Footer, &clipped, size);
        let centre = (top + bottom) / 2.0;
        // The baseline sits one font size inside the reserved band, which leaves the ascenders room
        // to lean out towards the paper edge and keeps the descenders clear of the text column.
        let (x, y, clockwise) = match self.metrics.side_edge {
            DocumentSideTextEdge::Left => {
                (self.metrics.margin_left + size, centre - width / 2.0, false)
            }
            DocumentSideTextEdge::Right => (
                self.metrics.page_w - self.metrics.margin_right - size,
                centre + width / 2.0,
                true,
            ),
        };
        self.cur.extend_from_slice(b"/Artifact BMC\n");
        self.frag_rotated(FontSlot::Footer, x, y, size, clockwise, &clipped);
        self.cur.extend_from_slice(b"EMC\n");
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
        StructureRole::KeyValueTable => "Table",
        StructureRole::VoteTable => "Table",
        StructureRole::TableRow => "TR",
        StructureRole::TableHeaderCell(_) => "TH",
        StructureRole::TableDataCell => "TD",
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
pub fn lay_out(doc: &DocumentModel, fonts: &FontCatalog) -> Result<Laid, DocError> {
    doc.document_layout
        .validate()
        .map_err(|error| DocError::Layout(error.to_string()))?;
    let mut l = Layouter::new(fonts, &doc.document_layout);
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
    // Last, once the page count exists: repeated page apparatus, as artifacts.
    l.draw_page_furniture(doc)?;
    Ok(Laid {
        pages: l.pages,
        used: l.used,
        structure_elements: l.structure_elements,
        page_width: l.metrics.page_w,
        page_height: l.metrics.page_h,
    })
}
