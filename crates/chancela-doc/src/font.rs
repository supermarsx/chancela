//! Minimal, dependency-free TrueType (`glyf`) parser for the one bundled serif face.
//!
//! We only read what a PDF/A composite-font embed needs: the table directory, `head`
//! (`unitsPerEm`, font bbox), `hhea`/`maxp`/`hmtx` (advance widths), `OS/2`/`post` (descriptor
//! metrics) and a format-4 Unicode `cmap` subtable (char → glyph id). The whole font program is
//! embedded verbatim as `/FontFile2` (no subsetting in v1), so we never rewrite `glyf`/`loca`.
//!
//! All values are read at load time; parsing is pure and deterministic.

use crate::DocError;

/// The bundled Noto Serif Regular program (SIL OFL 1.1; see `assets/fonts/PROVENANCE.md`).
pub const NOTO_SERIF_REGULAR: &[u8] = include_bytes!("../assets/fonts/NotoSerif-Regular.ttf");

/// A parsed TrueType face, holding just enough to lay out text and emit the PDF font objects.
pub struct Font {
    /// The raw font program (embedded as `/FontFile2`).
    pub data: &'static [u8],
    /// Font design units per em (Noto Serif = 1000, i.e. already in PDF glyph space).
    pub units_per_em: u16,
    /// Per-glyph advance widths, indexed by glyph id, in font design units.
    advances: Vec<u16>,
    /// Format-4 Unicode cmap (BMP) for char → glyph id resolution.
    cmap: Cmap4,
    /// Font bounding box in design units `[xMin yMin xMax yMax]`.
    pub bbox: [i16; 4],
    /// Typographic ascent (design units).
    pub ascent: i16,
    /// Typographic descent (design units, negative).
    pub descent: i16,
    /// Cap height (design units).
    pub cap_height: i16,
    /// Italic angle in degrees (0 for the regular face).
    pub italic_angle: f32,
}

/// A parsed `cmap` format-4 (segment mapping to delta values) subtable.
struct Cmap4 {
    seg_count: usize,
    end_codes: Vec<u16>,
    start_codes: Vec<u16>,
    id_deltas: Vec<i16>,
    id_range_offsets: Vec<u16>,
    /// Raw subtable bytes (for `idRangeOffset` glyph-array indirection).
    sub: Vec<u8>,
    /// Byte offset within `sub` of the first `idRangeOffset` entry.
    id_range_offset_pos: usize,
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}
fn be16s(b: &[u8], i: usize) -> i16 {
    i16::from_be_bytes([b[i], b[i + 1]])
}
fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

impl Font {
    /// Parse the bundled Noto Serif Regular face.
    pub fn load() -> Result<Font, DocError> {
        Self::parse(NOTO_SERIF_REGULAR)
    }

    fn err(m: &str) -> DocError {
        DocError::Font(m.to_string())
    }

    fn parse(data: &'static [u8]) -> Result<Font, DocError> {
        if data.len() < 12 {
            return Err(Self::err("font too small for an sfnt header"));
        }
        let num_tables = be16(data, 4) as usize;
        let find = |tag: &[u8; 4]| -> Option<(usize, usize)> {
            for i in 0..num_tables {
                let o = 12 + i * 16;
                if o + 16 > data.len() {
                    return None;
                }
                if &data[o..o + 4] == tag {
                    return Some((be32(data, o + 8) as usize, be32(data, o + 12) as usize));
                }
            }
            None
        };

        let (head_o, _) = find(b"head").ok_or_else(|| Self::err("missing head table"))?;
        let units_per_em = be16(data, head_o + 18);
        let bbox = [
            be16s(data, head_o + 36),
            be16s(data, head_o + 38),
            be16s(data, head_o + 40),
            be16s(data, head_o + 42),
        ];

        let (hhea_o, _) = find(b"hhea").ok_or_else(|| Self::err("missing hhea table"))?;
        let ascent = be16s(data, hhea_o + 4);
        let descent = be16s(data, hhea_o + 6);
        let num_h_metrics = be16(data, hhea_o + 34) as usize;

        let (maxp_o, _) = find(b"maxp").ok_or_else(|| Self::err("missing maxp table"))?;
        let num_glyphs = be16(data, maxp_o + 4) as usize;

        let (hmtx_o, _) = find(b"hmtx").ok_or_else(|| Self::err("missing hmtx table"))?;
        let mut advances = Vec::with_capacity(num_glyphs);
        let mut last = 0u16;
        for g in 0..num_glyphs {
            if g < num_h_metrics {
                let p = hmtx_o + g * 4;
                if p + 2 > data.len() {
                    return Err(Self::err("hmtx truncated"));
                }
                last = be16(data, p);
            }
            advances.push(last);
        }

        // Descriptor metrics from OS/2 (cap height, weight) and post (italic angle).
        let (cap_height, italic_angle) = {
            let cap = find(b"OS/2")
                .filter(|&(o, _)| be16(data, o) >= 2 && o + 90 <= data.len())
                .map(|(o, _)| be16s(data, o + 88))
                .unwrap_or((ascent as f32 * 0.7) as i16);
            let ia = find(b"post")
                .filter(|&(o, _)| o + 8 <= data.len())
                .map(|(o, _)| be32(data, o + 4) as i32 as f32 / 65536.0)
                .unwrap_or(0.0);
            (cap, ia)
        };

        let cmap = Self::parse_cmap(data, find(b"cmap"))?;

        Ok(Font {
            data,
            units_per_em,
            advances,
            cmap,
            bbox,
            ascent,
            descent,
            cap_height,
            italic_angle,
        })
    }

    fn parse_cmap(data: &[u8], loc: Option<(usize, usize)>) -> Result<Cmap4, DocError> {
        let (cmap_o, _) = loc.ok_or_else(|| Self::err("missing cmap table"))?;
        let n = be16(data, cmap_o + 2) as usize;
        // Prefer a (3,1) Unicode BMP subtable, else (0,*) Unicode.
        let mut chosen: Option<usize> = None;
        let mut fallback: Option<usize> = None;
        for i in 0..n {
            let rec = cmap_o + 4 + i * 8;
            let pid = be16(data, rec);
            let eid = be16(data, rec + 2);
            let off = be32(data, rec + 4) as usize;
            let sub = cmap_o + off;
            if sub + 2 > data.len() || be16(data, sub) != 4 {
                continue; // only format 4 supported
            }
            if pid == 3 && eid == 1 {
                chosen = Some(sub);
            } else if pid == 0 {
                fallback = Some(sub);
            }
        }
        let sub_o = chosen
            .or(fallback)
            .ok_or_else(|| Self::err("no supported (format-4) cmap subtable"))?;

        let length = be16(data, sub_o + 2) as usize;
        if sub_o + length > data.len() {
            return Err(Self::err("cmap subtable truncated"));
        }
        let sub = data[sub_o..sub_o + length].to_vec();
        let seg_x2 = be16(&sub, 6) as usize;
        let seg_count = seg_x2 / 2;
        let mut end_codes = Vec::with_capacity(seg_count);
        let mut start_codes = Vec::with_capacity(seg_count);
        let mut id_deltas = Vec::with_capacity(seg_count);
        let mut id_range_offsets = Vec::with_capacity(seg_count);
        let end_pos = 14;
        let start_pos = end_pos + seg_x2 + 2; // +2 reservedPad
        let delta_pos = start_pos + seg_x2;
        let range_pos = delta_pos + seg_x2;
        if range_pos + seg_x2 > sub.len() {
            return Err(Self::err("cmap format-4 arrays out of bounds"));
        }
        for i in 0..seg_count {
            end_codes.push(be16(&sub, end_pos + i * 2));
            start_codes.push(be16(&sub, start_pos + i * 2));
            id_deltas.push(be16s(&sub, delta_pos + i * 2));
            id_range_offsets.push(be16(&sub, range_pos + i * 2));
        }
        Ok(Cmap4 {
            seg_count,
            end_codes,
            start_codes,
            id_deltas,
            id_range_offsets,
            sub,
            id_range_offset_pos: range_pos,
        })
    }

    /// Map a Unicode scalar to a glyph id (0 = `.notdef` when absent / non-BMP).
    pub fn glyph_id(&self, ch: char) -> u16 {
        let code = ch as u32;
        if code > 0xFFFF {
            return 0;
        }
        let code = code as u16;
        let c = &self.cmap;
        for i in 0..c.seg_count {
            if c.end_codes[i] >= code && c.start_codes[i] <= code {
                let ro = c.id_range_offsets[i];
                if ro == 0 {
                    return (code as i32 + c.id_deltas[i] as i32) as u16;
                }
                // glyphIndexAddress = &idRangeOffset[i] + idRangeOffset[i] + 2*(code - startCode[i])
                let addr = c.id_range_offset_pos
                    + i * 2
                    + ro as usize
                    + 2 * (code - c.start_codes[i]) as usize;
                if addr + 2 > c.sub.len() {
                    return 0;
                }
                let g = be16(&c.sub, addr);
                if g == 0 {
                    return 0;
                }
                return (g as i32 + c.id_deltas[i] as i32) as u16;
            }
        }
        0
    }

    /// Advance width of a glyph, in font design units.
    pub fn advance(&self, gid: u16) -> u16 {
        self.advances.get(gid as usize).copied().unwrap_or(0)
    }

    /// Width of `ch` scaled to PDF glyph space (1000 units/em).
    pub fn char_width_1000(&self, ch: char) -> f32 {
        let a = self.advance(self.glyph_id(ch)) as f32;
        a * 1000.0 / self.units_per_em as f32
    }

    /// Advance width of a glyph scaled to PDF glyph space (1000 units/em), rounded to an integer
    /// (for the `/W` array).
    pub fn glyph_width_1000(&self, gid: u16) -> i64 {
        (self.advance(gid) as f32 * 1000.0 / self.units_per_em as f32).round() as i64
    }

    /// A metric scaled from design units to PDF glyph space (1000/em).
    pub fn scale_1000(&self, v: i16) -> i64 {
        (v as f32 * 1000.0 / self.units_per_em as f32).round() as i64
    }
}
