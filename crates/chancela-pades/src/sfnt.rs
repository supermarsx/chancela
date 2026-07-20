//! Minimal TrueType (`sfnt`) reader for the font program a document already embeds.
//!
//! A visible text seal must be drawn with an embedded face carrying a `/ToUnicode` CMap, or the
//! signed file stops being PDF/A conformant (ISO 19005-2 §6.2.11). Rather than bundle a second copy
//! of a font programme in this crate — which would add it to every signed file, and would say
//! nothing about the face the document itself uses — the seal is drawn with the **font programme
//! the input PDF already embeds**, referenced by object id. Nothing is copied; the seal simply
//! shares the `/FontFile2` stream that is already there.
//!
//! To do that this module must answer three questions about that programme: which glyph a character
//! maps to (`cmap`), how wide that glyph is (`hmtx`), and what design grid the widths are on
//! (`head`). That is all it reads.
//!
//! This is deliberately a separate reader from `chancela-doc`'s. `chancela-pades` does not depend on
//! `chancela-doc` — the dependency runs the other way in that crate's dev-dependencies — and the
//! layering is worth more than the ~120 lines saved. It also means the seal path works on any input
//! PDF with an embedded TrueType face, not only on ones this workspace wrote.

use crate::error::PadesError;

/// Tables a `CIDFontType2` programme must carry for a seal to be drawn from it and extracted again.
const REQUIRED_TABLES: [&[u8; 4]; 5] = [b"head", b"hhea", b"maxp", b"hmtx", b"cmap"];

/// A parsed TrueType table directory over borrowed programme bytes.
pub(crate) struct Sfnt<'a> {
    data: &'a [u8],
    tables: Vec<([u8; 4], usize, usize)>,
}

fn malformed(message: impl Into<String>) -> PadesError {
    PadesError::MalformedStructure(message.into())
}

fn be16(bytes: &[u8], at: usize) -> Result<u16, PadesError> {
    bytes
        .get(at..at + 2)
        .map(|w| u16::from_be_bytes([w[0], w[1]]))
        .ok_or_else(|| malformed(format!("embedded font programme truncated at offset {at}")))
}

fn be32(bytes: &[u8], at: usize) -> Result<u32, PadesError> {
    bytes
        .get(at..at + 4)
        .map(|w| u32::from_be_bytes([w[0], w[1], w[2], w[3]]))
        .ok_or_else(|| malformed(format!("embedded font programme truncated at offset {at}")))
}

impl<'a> Sfnt<'a> {
    /// Parse the table directory, bounds-checking every entry against the programme length.
    pub(crate) fn parse(data: &'a [u8]) -> Result<Self, PadesError> {
        let version = be32(data, 0)?;
        if !matches!(version, 0x0001_0000 | 0x7472_7565) {
            return Err(malformed(format!(
                "the document's embedded font programme has sfnt version {version:#010x}, not a \
                 TrueType outline font, so a text seal cannot be drawn from it"
            )));
        }
        let num_tables = be16(data, 4)? as usize;
        let mut tables = Vec::with_capacity(num_tables);
        for index in 0..num_tables {
            let entry = 12 + index * 16;
            let tag = data
                .get(entry..entry + 4)
                .ok_or_else(|| malformed("embedded font table directory is truncated"))?;
            let offset = be32(data, entry + 8)? as usize;
            let length = be32(data, entry + 12)? as usize;
            let end = offset
                .checked_add(length)
                .ok_or_else(|| malformed("embedded font table extent overflows"))?;
            if end > data.len() {
                return Err(malformed(format!(
                    "embedded font table `{}` spans {offset}..{end}, past the {}-byte programme",
                    String::from_utf8_lossy(tag),
                    data.len()
                )));
            }
            tables.push(([tag[0], tag[1], tag[2], tag[3]], offset, length));
        }
        let sfnt = Sfnt { data, tables };
        for required in REQUIRED_TABLES {
            sfnt.table(required)?;
        }
        Ok(sfnt)
    }

    fn table(&self, tag: &[u8; 4]) -> Result<(usize, usize), PadesError> {
        self.tables
            .iter()
            .find(|(candidate, _, _)| candidate == tag)
            .map(|&(_, offset, length)| (offset, length))
            .ok_or_else(|| {
                malformed(format!(
                    "the document's embedded font programme has no `{}` table",
                    String::from_utf8_lossy(tag)
                ))
            })
    }

    /// Design units per em — the grid `hmtx` advances are on.
    pub(crate) fn units_per_em(&self) -> Result<u16, PadesError> {
        let (offset, _) = self.table(b"head")?;
        match be16(self.data, offset + 18)? {
            0 => Err(malformed("embedded font programme declares unitsPerEm 0")),
            units => Ok(units),
        }
    }

    /// Advance width of `gid` scaled to PDF glyph space (1000 units/em), as `/W` records it.
    pub(crate) fn width_1000(&self, gid: u16) -> Result<i64, PadesError> {
        let (hhea, _) = self.table(b"hhea")?;
        let num_metrics = be16(self.data, hhea + 34)? as usize;
        if num_metrics == 0 {
            return Err(malformed(
                "embedded font programme declares numberOfHMetrics 0",
            ));
        }
        let (hmtx, _) = self.table(b"hmtx")?;
        // Glyphs past the last full metric all share its advance (the monospaced tail).
        let index = (gid as usize).min(num_metrics - 1);
        let advance = be16(self.data, hmtx + index * 4)? as f32;
        Ok((advance * 1000.0 / self.units_per_em()? as f32).round() as i64)
    }

    /// Map a Unicode scalar to a glyph id through the programme's format-4 Unicode `cmap`.
    ///
    /// Returns `0` (`.notdef`) when the character is absent — the caller must treat that as a hard
    /// error rather than drawing it, because a `.notdef` renders as a blank box and its
    /// `/ToUnicode` entry would then describe whichever character reached `.notdef` first.
    pub(crate) fn glyph_id(&self, ch: char) -> Result<u16, PadesError> {
        let code = ch as u32;
        if code > 0xFFFF {
            return Ok(0);
        }
        let code = code as u16;
        let subtable = self.unicode_subtable()?;

        let seg_x2 = be16(self.data, subtable + 6)? as usize;
        if seg_x2 == 0 || !seg_x2.is_multiple_of(2) {
            return Err(malformed(
                "embedded cmap format-4 has an invalid segCountX2",
            ));
        }
        let seg_count = seg_x2 / 2;
        let end_codes = subtable + 14;
        let start_codes = end_codes + seg_x2 + 2; // + reservedPad
        let deltas = start_codes + seg_x2;
        let range_offsets = deltas + seg_x2;

        for segment in 0..seg_count {
            let end = be16(self.data, end_codes + segment * 2)?;
            if end < code {
                continue;
            }
            let start = be16(self.data, start_codes + segment * 2)?;
            if start > code {
                return Ok(0);
            }
            let delta = be16(self.data, deltas + segment * 2)? as i32;
            let range_offset = be16(self.data, range_offsets + segment * 2)? as usize;
            if range_offset == 0 {
                return Ok(((code as i32 + delta) & 0xFFFF) as u16);
            }
            let address = range_offsets + segment * 2 + range_offset + 2 * (code - start) as usize;
            let raw = be16(self.data, address)?;
            if raw == 0 {
                return Ok(0);
            }
            return Ok(((raw as i32 + delta) & 0xFFFF) as u16);
        }
        Ok(0)
    }

    /// Offset of the preferred format-4 Unicode `cmap` subtable: (3,1) Windows BMP, else any (0,\*).
    fn unicode_subtable(&self) -> Result<usize, PadesError> {
        let (cmap, _) = self.table(b"cmap")?;
        let count = be16(self.data, cmap + 2)? as usize;
        let mut best = None;
        let mut fallback = None;
        for index in 0..count {
            let record = cmap + 4 + index * 8;
            let platform = be16(self.data, record)?;
            let encoding = be16(self.data, record + 2)?;
            let subtable = cmap + be32(self.data, record + 4)? as usize;
            if be16(self.data, subtable)? != 4 {
                continue; // only format 4 is read
            }
            if platform == 3 && encoding == 1 {
                best = Some(subtable);
            } else if platform == 0 {
                fallback = Some(subtable);
            }
        }
        best.or(fallback).ok_or_else(|| {
            malformed(
                "the document's embedded font programme has no format-4 Unicode cmap subtable, so \
                 seal characters cannot be resolved to glyphs",
            )
        })
    }
}
