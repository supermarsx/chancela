//! The PDF parser (plan t23 §2.2): a faithful port of `data/source/gen_cae.py` — reconstruct
//! positioned "words" from the Diário da República diploma PDFs, derive each node's level from its
//! code shape and its parent structurally, including the Rev.3 group-843 reconstruction. Pure Rust
//! over `lopdf`; no native library.
//!
//! `gen_cae.py` uses pymupdf's `get_text("words")` (per-word bounding boxes). lopdf hands us the raw
//! content-stream operators instead, so this module runs a small **text-showing interpreter** (the
//! text-positioning subset of the PDF imaging model: `Tm`/`Td`/`TD`/`T*`/`Tj`/`TJ` plus font glyph
//! widths and `ToUnicode` decoding) to recover the same positioned words, then applies the exact
//! `logical_rows`/`build` logic. The result is cross-checked against the embedded dataset (generated
//! by the Python) by the crate's tests, and gated on the exact official per-level counts.

use std::collections::HashMap;

use lopdf::{Dictionary, Document, Object, ObjectId};

use crate::model::{CaeEntry, CaeLevel};
use crate::{CaeError, CaeRevision};

/// Per-revision extraction geometry, in PDF points, mirroring `gen_cae.py`'s `LAYOUT`. The `x`
/// thresholds are page-x (matching pymupdf); `y_max` is the lower bound of the table band in this
/// module's **top-down baseline** convention (`page_height - baseline_y`, y increasing downward), so
/// it excludes the running footer. The header row's y is found dynamically (the "Designação" word).
struct Layout {
    /// A code cell sits left of this x.
    code_x: f64,
    /// A designation word sits at/right of this x.
    desig_x: f64,
    /// Words at/right of this x are the rotated running-header / page margin — dropped.
    margin_x: f64,
    /// A lone secção letter must sit left of this x (guards against prose one-letter words).
    sec_x: f64,
    /// Table rows sit above this top-down y (drops the footer band).
    y_max: f64,
}

fn layout(revision: CaeRevision) -> Layout {
    match revision {
        CaeRevision::Rev3 => Layout {
            code_x: 255.0,
            desig_x: 255.0,
            margin_x: 560.0,
            sec_x: 78.0,
            y_max: 800.0,
        },
        CaeRevision::Rev4 => Layout {
            code_x: 236.0,
            desig_x: 236.0,
            margin_x: 530.0,
            sec_x: 95.0,
            y_max: 805.0,
        },
    }
}

/// A positioned word: `x` is the page-x of its first glyph's origin, `y` its top-down baseline y.
struct Word {
    x: f64,
    y: f64,
    text: String,
}

/// Parse one revision's diploma PDF bytes into its classification entries. Ported from the proven
/// offline generator so the counts land on the fidelity totals; the caller runs the result through
/// the integrity + fidelity gates before it may supersede anything.
pub(crate) fn parse_revision_pdf(
    bytes: &[u8],
    revision: CaeRevision,
) -> Result<Vec<CaeEntry>, CaeError> {
    let doc = Document::load_mem(bytes)
        .map_err(|e| CaeError::Parse(format!("{revision:?} PDF load: {e}")))?;
    let lay = layout(revision);

    // Reproduce `logical_rows`: (codes, designation) rows in page/reading order, merging wraps.
    let mut raw: Vec<(Vec<String>, String)> = Vec::new();
    for (_, page_id) in doc.get_pages() {
        let Some(page_h) = page_height(&doc, page_id) else {
            continue;
        };
        let words = extract_words(&doc, page_id, page_h, revision);

        // Only real table pages carry the "Designação" column header (in the designation column)
        // AND a "Subclasse" header; its y bounds the table band from above.
        let header_y = words
            .iter()
            .filter(|w| w.text == "Designação" && w.x > lay.desig_x)
            .map(|w| w.y)
            .fold(f64::INFINITY, f64::min);
        let has_subclasse = words.iter().any(|w| w.text == "Subclasse");
        if !header_y.is_finite() || !has_subclasse {
            continue;
        }

        // Group into visual lines by rounded baseline y (a BTreeMap keeps them top-to-bottom).
        let mut lines: std::collections::BTreeMap<i64, Vec<&Word>> =
            std::collections::BTreeMap::new();
        for w in &words {
            if !(header_y < w.y && w.y < lay.y_max) {
                continue;
            }
            if w.x >= lay.margin_x {
                continue;
            }
            lines.entry(w.y.round() as i64).or_default().push(w);
        }
        for (_, mut ws) in lines {
            ws.sort_by(|a, b| a.x.partial_cmp(&b.x).unwrap_or(std::cmp::Ordering::Equal));
            let codes: Vec<String> = ws
                .iter()
                .filter(|w| is_code(w, &lay))
                .map(|w| w.text.clone())
                .collect();
            let desig: String = ws
                .iter()
                .filter(|w| w.x >= lay.desig_x)
                .map(|w| w.text.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            if codes.is_empty() && desig.is_empty() {
                continue;
            }
            raw.push((codes, desig));
        }
    }

    let merged = merge_continuations(raw);
    let entries = build(merged, revision);
    if entries.is_empty() {
        return Err(CaeError::Parse(format!(
            "{revision:?} PDF yielded no classification entries (unexpected layout?)"
        )));
    }
    Ok(entries)
}

/// A word is a code cell iff it sits in a code column and matches the code shape; a lone letter must
/// additionally sit in the Secção column (guards against prose one-letter words). Ports `is_code`.
fn is_code(w: &Word, lay: &Layout) -> bool {
    if w.x >= lay.code_x || !is_code_shape(&w.text) {
        return false;
    }
    if is_single_upper(&w.text) && w.x >= lay.sec_x {
        return false;
    }
    true
}

/// `^([A-Z]|\d{2,5})$` — a single uppercase letter or a run of 2–5 digits.
fn is_code_shape(t: &str) -> bool {
    is_single_upper(t) || (t.len() >= 2 && t.len() <= 5 && t.bytes().all(|b| b.is_ascii_digit()))
}

fn is_single_upper(t: &str) -> bool {
    t.len() == 1 && t.as_bytes()[0].is_ascii_uppercase()
}

/// Merge wrapped continuation lines (ports the `logical_rows` tail): a no-code line is a wrap of the
/// previous designation only while that designation is still incomplete (does not end in a period).
fn merge_continuations(raw: Vec<(Vec<String>, String)>) -> Vec<(Vec<String>, String)> {
    let mut merged: Vec<(Vec<String>, String)> = Vec::new();
    for (codes, desig) in raw {
        if !codes.is_empty() {
            merged.push((codes, desig));
        } else if let Some(prev) = merged.last_mut()
            && !prev.1.trim_end().ends_with('.')
        {
            if let Some(stripped) = prev.1.strip_suffix('-') {
                prev.1 = format!("{stripped}{desig}");
            } else {
                prev.1 = format!("{} {}", prev.1, desig).trim().to_string();
            }
        }
    }
    merged
}

/// Assign each code its level (from shape) and parent (structural), preserving first-seen order.
/// Ports `build`, including the Rev.3 group-843 reconstruction (DL 381/2007 omits its header row).
fn build(rows: Vec<(Vec<String>, String)>, revision: CaeRevision) -> Vec<CaeEntry> {
    let mut map: HashMap<String, CaeEntry> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut cur_section: Option<String> = None;

    for (codes, desig) in rows {
        for c in codes {
            let Some(level) = CaeLevel::from_code(&c) else {
                continue;
            };
            let parent = match level {
                CaeLevel::Seccao => {
                    cur_section = Some(c.clone());
                    None
                }
                CaeLevel::Divisao => cur_section.clone(),
                _ => Some(c[..c.len() - 1].to_string()),
            };
            if !map.contains_key(&c) {
                map.insert(
                    c.clone(),
                    CaeEntry {
                        code: c.clone(),
                        designation: desig.clone(),
                        level,
                        revision,
                        parent,
                    },
                );
                order.push(c);
            }
        }
    }

    if revision == CaeRevision::Rev3
        && !map.contains_key("843")
        && let Some(child) = map.get("8430")
    {
        let entry = CaeEntry {
            code: "843".to_string(),
            designation: child.designation.clone(),
            level: CaeLevel::Grupo,
            revision,
            parent: Some("84".to_string()),
        };
        let pos = order
            .iter()
            .position(|c| c == "8430")
            .unwrap_or(order.len());
        order.insert(pos, "843".to_string());
        map.insert("843".to_string(), entry);
    }

    order.into_iter().filter_map(|c| map.remove(&c)).collect()
}

// ---------------------------------------------------------------------------------------------
// Text-showing interpreter: recover positioned words from a page's content stream.
// ---------------------------------------------------------------------------------------------

/// The MediaBox height of a page (following the `Parent` chain for the inheritable attribute).
fn page_height(doc: &Document, page_id: ObjectId) -> Option<f64> {
    let mut id = page_id;
    for _ in 0..32 {
        let dict = doc.get_object(id).ok()?.as_dict().ok()?;
        if let Ok(mb) = dict.get(b"MediaBox")
            && let Object::Array(a) = resolve(doc, mb)
            && a.len() == 4
        {
            let y0 = as_f64(&a[1]);
            let y1 = as_f64(&a[3]);
            return Some((y1 - y0).abs());
        }
        match dict.get(b"Parent") {
            Ok(Object::Reference(pid)) => id = *pid,
            _ => break,
        }
    }
    None
}

/// A single font's glyph-decoding + width model.
struct FontInfo {
    /// Type0 (Identity-H) uses 2-byte codes; simple fonts use 1-byte codes.
    two_byte: bool,
    /// code → Unicode string, from the font's `ToUnicode` CMap.
    to_unicode: HashMap<u32, String>,
    /// Glyph widths, in 1000-unit glyph space.
    widths: WidthModel,
}

enum WidthModel {
    Simple {
        first_char: i64,
        widths: Vec<f64>,
        missing: f64,
    },
    Type0 {
        cid_widths: HashMap<u32, f64>,
        default: f64,
    },
}

impl FontInfo {
    /// Glyph width as an em fraction (glyph-space width / 1000).
    fn width_em(&self, code: u32) -> f64 {
        match &self.widths {
            WidthModel::Simple {
                first_char,
                widths,
                missing,
            } => {
                let idx = code as i64 - first_char;
                let w = usize::try_from(idx)
                    .ok()
                    .and_then(|i| widths.get(i).copied())
                    .unwrap_or(*missing);
                w / 1000.0
            }
            WidthModel::Type0 {
                cid_widths,
                default,
            } => cid_widths.get(&code).copied().unwrap_or(*default) / 1000.0,
        }
    }

    /// Decode one glyph code to its Unicode text (empty string if unmapped and non-printable).
    fn decode(&self, code: u32) -> String {
        if let Some(s) = self.to_unicode.get(&code) {
            return s.chars().map(fixup_cp1252).collect();
        }
        // Fallback for simple fonts without a mapping entry: treat the byte as Windows-1252
        // (WinAnsi), the encoding these diploma fonts declare.
        if !self.two_byte
            && let Some(c) = char::from_u32(code)
        {
            return fixup_cp1252(c).to_string();
        }
        String::new()
    }
}

/// Map a codepoint in the C1 control range (0x80–0x9F) to its Windows-1252 (WinAnsi) meaning. These
/// diploma fonts declare `WinAnsiEncoding` but their `ToUnicode` CMaps emit the raw byte for the
/// upper range (e.g. `0x97` → U+0097 instead of U+2014 EM DASH), which pymupdf resolves via the
/// encoding. No CAE designation contains a genuine C1 control, so the remap is unambiguous.
fn fixup_cp1252(c: char) -> char {
    match c as u32 {
        0x80 => '\u{20AC}',
        0x82 => '\u{201A}',
        0x83 => '\u{0192}',
        0x84 => '\u{201E}',
        0x85 => '\u{2026}',
        0x86 => '\u{2020}',
        0x87 => '\u{2021}',
        0x88 => '\u{02C6}',
        0x89 => '\u{2030}',
        0x8A => '\u{0160}',
        0x8B => '\u{2039}',
        0x8C => '\u{0152}',
        0x8E => '\u{017D}',
        0x91 => '\u{2018}',
        0x92 => '\u{2019}',
        0x93 => '\u{201C}',
        0x94 => '\u{201D}',
        0x95 => '\u{2022}',
        0x96 => '\u{2013}',
        0x97 => '\u{2014}',
        0x98 => '\u{02DC}',
        0x99 => '\u{2122}',
        0x9A => '\u{0161}',
        0x9B => '\u{203A}',
        0x9C => '\u{0153}',
        0x9E => '\u{017E}',
        0x9F => '\u{0178}',
        _ => c,
    }
}

type Mat = [f64; 6];

/// Row-vector matrix product `a · b` for 2-D affine matrices `[a b c d e f]`.
fn mat_mul(a: Mat, b: Mat) -> Mat {
    [
        a[0] * b[0] + a[1] * b[2],
        a[0] * b[1] + a[1] * b[3],
        a[2] * b[0] + a[3] * b[2],
        a[2] * b[1] + a[3] * b[3],
        a[4] * b[0] + a[5] * b[2] + b[4],
        a[4] * b[1] + a[5] * b[3] + b[5],
    ]
}

const IDENTITY: Mat = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0];

/// Per-page decompression ceiling for official CAE PDF content streams. Source downloads are
/// already capped at 50 MiB; bounding each decoded page as well prevents a compressed stream from
/// expanding without limit during catalog refresh.
const MAX_DECOMPRESSED_PAGE_BYTES: usize = 64 * 1024 * 1024;

/// Extract positioned words from one page by interpreting its text-showing operators.
fn extract_words(
    doc: &Document,
    page_id: ObjectId,
    page_h: f64,
    revision: CaeRevision,
) -> Vec<Word> {
    let fonts = build_fonts(doc, page_id);
    let content = match doc.get_page_content_with_limit(page_id, MAX_DECOMPRESSED_PAGE_BYTES) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let ops = match lopdf::content::Content::decode(&content) {
        Ok(c) => c.operations,
        Err(_) => return Vec::new(),
    };

    let mut words: Vec<Word> = Vec::new();
    let mut wb = WordBuilder::default();

    // Graphics + text state.
    let mut ctm: Mat = IDENTITY;
    let mut ctm_stack: Vec<Mat> = Vec::new();
    let mut tm: Mat = IDENTITY;
    let mut tlm: Mat = IDENTITY;
    let mut leading = 0.0;
    let mut font_size = 0.0;
    let mut char_spacing = 0.0;
    let mut word_spacing = 0.0;
    let mut h_scale = 1.0;
    let mut cur_font: Option<&FontInfo> = None;

    for op in &ops {
        match op.operator.as_str() {
            "q" => ctm_stack.push(ctm),
            "Q" => {
                if let Some(m) = ctm_stack.pop() {
                    ctm = m;
                }
            }
            "cm" => {
                if let Some(m) = read_mat(&op.operands) {
                    ctm = mat_mul(m, ctm);
                }
            }
            "BT" => {
                tm = IDENTITY;
                tlm = IDENTITY;
                wb.flush(&mut words);
            }
            "ET" => wb.flush(&mut words),
            // Note: Tm/Td/TD/T* only reposition the text matrix; they do NOT force a word break.
            // Word boundaries are decided geometrically in `show_string` (space glyph, line change,
            // or a wide horizontal gap) — mirroring pymupdf, so an end-of-line hyphen positioned a
            // hair after its word (a tiny/negative gap) stays attached ("pro-", not "pro" + "-").
            "Tf" => {
                if let Some(Object::Name(n)) = op.operands.first() {
                    cur_font = fonts.get(n.as_slice());
                }
                if let Some(sz) = op.operands.get(1) {
                    font_size = as_f64(sz);
                }
            }
            "Tc" => char_spacing = op.operands.first().map(as_f64).unwrap_or(0.0),
            "Tw" => word_spacing = op.operands.first().map(as_f64).unwrap_or(0.0),
            "Tz" => h_scale = op.operands.first().map(as_f64).unwrap_or(100.0) / 100.0,
            "TL" => leading = op.operands.first().map(as_f64).unwrap_or(0.0),
            "Tm" => {
                if let Some(m) = read_mat(&op.operands) {
                    tm = m;
                    tlm = m;
                }
            }
            "Td" => {
                let (tx, ty) = read_xy(&op.operands);
                tlm = mat_mul([1.0, 0.0, 0.0, 1.0, tx, ty], tlm);
                tm = tlm;
            }
            "TD" => {
                let (tx, ty) = read_xy(&op.operands);
                leading = -ty;
                tlm = mat_mul([1.0, 0.0, 0.0, 1.0, tx, ty], tlm);
                tm = tlm;
            }
            "T*" => {
                tlm = mat_mul([1.0, 0.0, 0.0, 1.0, 0.0, -leading], tlm);
                tm = tlm;
            }
            "'" | "\"" => {
                // `'`: T* then show. `"`: aw ac string → set word/char spacing, then T* + show.
                if op.operator == "\""
                    && let (Some(aw), Some(ac)) = (op.operands.first(), op.operands.get(1))
                {
                    word_spacing = as_f64(aw);
                    char_spacing = as_f64(ac);
                }
                tlm = mat_mul([1.0, 0.0, 0.0, 1.0, 0.0, -leading], tlm);
                tm = tlm;
                wb.flush(&mut words);
                if let (Some(font), Some(Object::String(s, _))) = (cur_font, op.operands.last()) {
                    show_string(
                        s,
                        font,
                        &mut tm,
                        ctm,
                        page_h,
                        font_size,
                        char_spacing,
                        word_spacing,
                        h_scale,
                        revision,
                        &mut wb,
                        &mut words,
                    );
                }
            }
            "Tj" => {
                if let (Some(font), Some(Object::String(s, _))) = (cur_font, op.operands.last()) {
                    show_string(
                        s,
                        font,
                        &mut tm,
                        ctm,
                        page_h,
                        font_size,
                        char_spacing,
                        word_spacing,
                        h_scale,
                        revision,
                        &mut wb,
                        &mut words,
                    );
                }
            }
            "TJ" => {
                if let (Some(font), Some(Object::Array(arr))) = (cur_font, op.operands.first()) {
                    for el in arr {
                        match el {
                            Object::String(s, _) => show_string(
                                s,
                                font,
                                &mut tm,
                                ctm,
                                page_h,
                                font_size,
                                char_spacing,
                                word_spacing,
                                h_scale,
                                revision,
                                &mut wb,
                                &mut words,
                            ),
                            n @ (Object::Integer(_) | Object::Real(_)) => {
                                // A positive number tightens (moves left); negative widens.
                                let adj = -as_f64(n) / 1000.0 * font_size * h_scale;
                                tm = mat_mul([1.0, 0.0, 0.0, 1.0, adj, 0.0], tm);
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }
    wb.flush(&mut words);
    words
}

/// Accumulates consecutive non-space glyphs into a word until a space or a large horizontal gap.
#[derive(Default)]
struct WordBuilder {
    text: String,
    start_x: f64,
    y: f64,
    /// Device-x where the previous glyph ended (to measure the gap to the next one).
    pen_x: f64,
}

impl WordBuilder {
    fn flush(&mut self, out: &mut Vec<Word>) {
        if !self.text.is_empty() {
            out.push(Word {
                x: self.start_x,
                y: self.y,
                text: std::mem::take(&mut self.text),
            });
        }
        self.text.clear();
    }
}

/// Show one string: walk its glyphs, advancing the text matrix, decoding to Unicode, and cutting
/// words on spaces and on gaps wider than 30% of the em (matches pymupdf's word segmentation for
/// the DR tables — intra-word kerning is sub-point; inter-column jumps are tens of points).
#[allow(clippy::too_many_arguments)]
fn show_string(
    bytes: &[u8],
    font: &FontInfo,
    tm: &mut Mat,
    ctm: Mat,
    page_h: f64,
    font_size: f64,
    char_spacing: f64,
    word_spacing: f64,
    h_scale: f64,
    _revision: CaeRevision,
    wb: &mut WordBuilder,
    out: &mut Vec<Word>,
) {
    // Thresholds in device space, scaled by the text matrix (font_size is often 1 with the size
    // carried in Tm). x-gap wider than ~0.3 em cuts a word; a y shift over ~0.5 em is a new line.
    let m0 = mat_mul(*tm, ctm);
    let scale_x = m0[0].hypot(m0[1]);
    let scale_y = m0[2].hypot(m0[3]);
    let gap_threshold = 0.3 * font_size * scale_x.max(f64::MIN_POSITIVE);
    let y_epsilon = 0.5 * font_size * scale_y.max(f64::MIN_POSITIVE);
    let codes: Vec<u32> = if font.two_byte {
        bytes
            .chunks(2)
            .map(|c| (u32::from(c[0]) << 8) | u32::from(*c.get(1).unwrap_or(&0)))
            .collect()
    } else {
        bytes.iter().map(|&b| u32::from(b)).collect()
    };

    for code in codes {
        // Device origin of this glyph = (Tm · CTM) applied to (0,0).
        let m = mat_mul(*tm, ctm);
        let x0 = m[4];
        let y0 = page_h - m[5];

        let text = font.decode(code);
        // A regular or non-breaking space is a word separator (pymupdf splits on both); the
        // designation join reinserts a single regular space between the resulting words.
        let is_space = text == " "
            || text == "\u{00A0}"
            || (text.is_empty() && !font.two_byte && code == 0x20);

        if is_space {
            wb.flush(out);
        } else if !text.is_empty() {
            if wb.text.is_empty() {
                wb.start_x = x0;
                wb.y = y0;
            } else if (y0 - wb.y).abs() > y_epsilon || x0 - wb.pen_x > gap_threshold {
                wb.flush(out);
                wb.start_x = x0;
                wb.y = y0;
            }
            wb.text.push_str(&text);
        }

        // Advance the text matrix by this glyph's displacement.
        let is_single_space = !font.two_byte && code == 0x20;
        let tw = if is_single_space { word_spacing } else { 0.0 };
        let tx = (font.width_em(code) * font_size + char_spacing + tw) * h_scale;
        *tm = mat_mul([1.0, 0.0, 0.0, 1.0, tx, 0.0], *tm);
        wb.pen_x = mat_mul(*tm, ctm)[4];
    }
}

/// Build the per-font decoding + width models for a page's resources.
fn build_fonts(doc: &Document, page_id: ObjectId) -> HashMap<Vec<u8>, FontInfo> {
    let mut out = HashMap::new();
    let fonts = match doc.get_page_fonts(page_id) {
        Ok(f) => f,
        Err(_) => return out,
    };
    for (name, dict) in fonts {
        out.insert(name.clone(), build_font(doc, dict));
    }
    out
}

fn build_font(doc: &Document, dict: &Dictionary) -> FontInfo {
    let subtype = dict.get(b"Subtype").ok().and_then(|o| o.as_name().ok());
    let two_byte = subtype == Some(b"Type0".as_ref());

    let to_unicode = dict
        .get(b"ToUnicode")
        .ok()
        .and_then(|o| match resolve(doc, o) {
            Object::Stream(s) => s.decompressed_content().ok(),
            _ => None,
        })
        .map(|c| parse_to_unicode(&c))
        .unwrap_or_default();

    let widths = if two_byte {
        build_type0_widths(doc, dict)
    } else {
        build_simple_widths(doc, dict)
    };

    FontInfo {
        two_byte,
        to_unicode,
        widths,
    }
}

fn build_simple_widths(doc: &Document, dict: &Dictionary) -> WidthModel {
    let first_char = dict.get(b"FirstChar").ok().map(as_f64).unwrap_or(0.0) as i64;
    let widths = match dict.get(b"Widths").map(|o| resolve(doc, o)) {
        Ok(Object::Array(a)) => a.iter().map(as_f64).collect(),
        _ => Vec::new(),
    };
    let missing = dict
        .get(b"FontDescriptor")
        .ok()
        .and_then(|o| match resolve(doc, o) {
            Object::Dictionary(d) => d.get(b"MissingWidth").ok().map(as_f64),
            _ => None,
        })
        .unwrap_or(0.0);
    WidthModel::Simple {
        first_char,
        widths,
        missing,
    }
}

fn build_type0_widths(doc: &Document, dict: &Dictionary) -> WidthModel {
    let mut cid_widths = HashMap::new();
    let mut default = 1000.0;
    if let Ok(Object::Array(descs)) = dict.get(b"DescendantFonts").map(|o| resolve(doc, o))
        && let Some(df) = descs.first()
        && let Object::Dictionary(dfd) = resolve(doc, df)
    {
        if let Ok(dw) = dfd.get(b"DW") {
            default = as_f64(dw);
        }
        if let Ok(Object::Array(w)) = dfd.get(b"W").map(|o| resolve(doc, o)) {
            parse_cid_widths(w, &mut cid_widths);
        }
    }
    WidthModel::Type0 {
        cid_widths,
        default,
    }
}

/// Parse a CIDFont `W` array: `c [w1 w2 …]` (consecutive CIDs from c) or `c_first c_last w` (range).
fn parse_cid_widths(w: &[Object], out: &mut HashMap<u32, f64>) {
    let mut i = 0;
    while i < w.len() {
        let c = as_f64(&w[i]) as i64;
        match w.get(i + 1) {
            Some(Object::Array(list)) => {
                for (k, obj) in list.iter().enumerate() {
                    if let Ok(cid) = u32::try_from(c + k as i64) {
                        out.insert(cid, as_f64(obj));
                    }
                }
                i += 2;
            }
            Some(obj @ (Object::Integer(_) | Object::Real(_))) => {
                let c_last = as_f64(obj) as i64;
                let width = w.get(i + 2).map(as_f64).unwrap_or(0.0);
                for cid in c..=c_last {
                    if let Ok(cid) = u32::try_from(cid) {
                        out.insert(cid, width);
                    }
                }
                i += 3;
            }
            _ => break,
        }
    }
}

/// Parse a `ToUnicode` CMap's `bfchar`/`bfrange` sections into a code→string map.
fn parse_to_unicode(cmap: &[u8]) -> HashMap<u32, String> {
    let text = String::from_utf8_lossy(cmap);
    let toks = tokenize_cmap(&text);
    let mut map = HashMap::new();
    let mut i = 0;
    while i < toks.len() {
        match toks[i].as_str() {
            "beginbfchar" => {
                i += 1;
                while i + 1 < toks.len() && toks[i] != "endbfchar" {
                    if let (Some(code), Some(dst)) = (hex_code(&toks[i]), hex_bytes(&toks[i + 1])) {
                        map.insert(code, utf16be(&dst));
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }
            "beginbfrange" => {
                i += 1;
                while i < toks.len() && toks[i] != "endbfrange" {
                    let lo = hex_code(&toks[i]);
                    let hi = toks.get(i + 1).and_then(|t| hex_code(t));
                    match (lo, hi, toks.get(i + 2).map(String::as_str)) {
                        (Some(lo), Some(hi), Some("[")) => {
                            // c_lo c_hi [ d0 d1 … ]
                            let mut j = i + 3;
                            let mut code = lo;
                            while j < toks.len() && toks[j] != "]" {
                                if let Some(dst) = hex_bytes(&toks[j]) {
                                    map.insert(code, utf16be(&dst));
                                }
                                code = code.wrapping_add(1);
                                j += 1;
                                if code > hi {
                                    break;
                                }
                            }
                            // Skip to past the closing ']'.
                            while j < toks.len() && toks[j] != "]" {
                                j += 1;
                            }
                            i = j + 1;
                        }
                        (Some(lo), Some(hi), Some(dst_tok)) => {
                            if let Some(dst) = hex_bytes(dst_tok) {
                                let base = dst.iter().fold(0u32, |a, &b| (a << 8) | u32::from(b));
                                let width = dst.len();
                                for (n, code) in (lo..=hi).enumerate() {
                                    let val = base + n as u32;
                                    let bytes: Vec<u8> =
                                        (0..width).rev().map(|k| (val >> (8 * k)) as u8).collect();
                                    map.insert(code, utf16be(&bytes));
                                }
                            }
                            i += 3;
                        }
                        _ => i += 1,
                    }
                }
            }
            _ => i += 1,
        }
    }
    map
}

/// Tokenize a CMap into `<hex>`, `[`, `]`, and bareword tokens (whitespace-separated otherwise).
fn tokenize_cmap(s: &str) -> Vec<String> {
    let mut toks = Vec::new();
    let mut chars = s.chars().peekable();
    let mut word = String::new();
    let flush = |word: &mut String, toks: &mut Vec<String>| {
        if !word.is_empty() {
            toks.push(std::mem::take(word));
        }
    };
    while let Some(&c) = chars.peek() {
        match c {
            '<' => {
                flush(&mut word, &mut toks);
                let mut hex = String::from("<");
                chars.next();
                for h in chars.by_ref() {
                    if h == '>' {
                        break;
                    }
                    hex.push(h);
                }
                hex.push('>');
                toks.push(hex);
            }
            '[' | ']' => {
                flush(&mut word, &mut toks);
                toks.push(c.to_string());
                chars.next();
            }
            c if c.is_whitespace() => {
                flush(&mut word, &mut toks);
                chars.next();
            }
            _ => {
                word.push(c);
                chars.next();
            }
        }
    }
    flush(&mut word, &mut toks);
    toks
}

/// Parse a `<…>` hex token into raw bytes.
fn hex_bytes(tok: &str) -> Option<Vec<u8>> {
    let inner = tok.strip_prefix('<')?.strip_suffix('>')?;
    let hex: String = inner.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.is_empty() {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len().div_ceil(2));
    let mut i = 0;
    while i < hex.len() {
        let end = (i + 2).min(hex.len());
        bytes.push(u8::from_str_radix(&hex[i..end], 16).ok()?);
        i += 2;
    }
    Some(bytes)
}

/// Parse a `<…>` hex token into a big-endian code point.
fn hex_code(tok: &str) -> Option<u32> {
    let bytes = hex_bytes(tok)?;
    Some(bytes.iter().fold(0u32, |a, &b| (a << 8) | u32::from(b)))
}

/// Decode UTF-16BE bytes (a `ToUnicode` destination) to a Rust string.
fn utf16be(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
        .collect();
    String::from_utf16_lossy(&units)
}

fn resolve<'a>(doc: &'a Document, obj: &'a Object) -> &'a Object {
    match obj {
        Object::Reference(id) => doc.get_object(*id).unwrap_or(obj),
        _ => obj,
    }
}

fn as_f64(obj: &Object) -> f64 {
    match obj {
        Object::Integer(i) => *i as f64,
        Object::Real(r) => *r as f64,
        _ => 0.0,
    }
}

fn read_mat(operands: &[Object]) -> Option<Mat> {
    if operands.len() < 6 {
        return None;
    }
    Some([
        as_f64(&operands[0]),
        as_f64(&operands[1]),
        as_f64(&operands[2]),
        as_f64(&operands[3]),
        as_f64(&operands[4]),
        as_f64(&operands[5]),
    ])
}

fn read_xy(operands: &[Object]) -> (f64, f64) {
    (
        operands.first().map(as_f64).unwrap_or(0.0),
        operands.get(1).map(as_f64).unwrap_or(0.0),
    )
}
